# WiFiShare API

The server behind [WiFiShare](https://github.com/WiFiShare): anonymous ingest of
Wi-Fi observations, area lookups, reports, opt-out and venue claims.

Django 5 on Python 3.12. The contract it implements is the
[spec](https://github.com/WiFiShare/spec) repository — the data model, the
JSON Schemas, the privacy rules R1–R12 and P1–P10, and `openapi.yaml`. **If this
repository and `spec` disagree, `spec` is right**, and the disagreement is a bug
here.

## What it does, in one paragraph

A phone filters its scan results on the device, seals a batch of at most 200 of
them with HPKE, and posts it. The server decrypts the envelope, runs the same
filter rules again, and stores the observations against nothing but a rate-limit
bucket — an HMAC of the caller's address under a salt that is thrown away within
a day. A scheduled job turns those observations into published networks, blurring
each community-found one to the centre of a 150 m cell and dropping its BSSID
entirely. Clients read a whole 4.9 km area at a time, so a lookup is never a
position report. There is no endpoint that resolves a BSSID to a place.

## Running it

Python 3.12 comes from [uv](https://docs.astral.sh/uv/). Every command below is
prefixed with `env -u PYTHONPATH` so that a system `PYTHONPATH` cannot leak
broken packages into the environment.

```sh
env -u PYTHONPATH uv sync --python 3.12

alias wf='env -u PYTHONPATH uv run --python 3.12 python manage.py'

wf migrate
wf issue_ingest_key          # one HPKE key pair, served at GET /v1/keys
wf seed_demo                 # a few fictional networks to look at
wf createsuperuser           # for /admin/
DEBUG=on wf runserver        # DEBUG on only so runserver serves the admin's CSS
```

No configuration is needed for this: `ALLOWED_HOSTS` defaults to localhost, and
the development signing key is accepted only while that is true. The moment
`ALLOWED_HOSTS` names a real host, the service refuses to start without a
`SECRET_KEY` from the environment. Copy `.env.example` to `.env` when you want
to set anything.

`seed_demo` writes a handful of obviously fictional networks in two areas
(Bologna and Lisbon) so that a website or an app has something to render. Every
one of them has `Demo` in its name and a BSSID from the documentation range.
`seed_demo --clear` takes them out again.

### Tests

```sh
env -u PYTHONPATH uv run --python 3.12 python manage.py test
```

SQLite, no network, no external service. The suite includes the two tests this
repository exists to pass:

- `tests/test_filter_fixtures.py` runs **every** case in
  `spec/privacy/fixtures/filter-cases.json` — each observation case for its
  keep/drop decision, the rule id that decided it and the exact normalised
  output, and each batch case for R12. The fixture file's own `now` is the
  clock, never the wall clock. The fixtures are read from the spec repo itself,
  found at `../spec` or at `$WIFISHARE_SPEC_DIR`.
- `tests/test_hpke_vectors.py` checks `ingest/hpke.py` against the RFC 9180
  Appendix A.2.1 test vectors, in both directions, for the exact ciphersuite the
  envelope schema names.

### Scheduled jobs

Two of the privacy rules are jobs, not code paths:

```sh
manage.py aggregate                 # P1–P6: raw observations -> published networks
manage.py export_dump --out DIR     # areas/<gh2>/<gh3>/<gh5>.geojson plus index.json
manage.py purge                     # P7: retention
```

Run `aggregate` and `export_dump` daily and `purge` hourly. `docker-compose.yml`
wires all three up.

## Endpoints

All of them are version 1, defined in `spec/openapi.yaml`. Errors are RFC 9457
problem documents served as `application/problem+json`, carrying `type`,
`title`, `status`, and where they apply `detail` and `rule`.

| Method and path | What it does |
| --- | --- |
| `GET /v1/keys` | The active HPKE ingest public keys, newest first. Clients pin one and refresh here |
| `POST /v1/batches` | One sealed envelope of observations. `202` with `{accepted, rejected, rules}`; `400` with the rule id when an observation breaks one; `409` when the key id is retired; `429` when the bucket is over its limit |
| `GET /v1/areas/{geohash5}` | Every published network in one 4.9 km cell, as GeoJSON, with an `ETag` and `Cache-Control`. `304` on a matching `If-None-Match`, `404` when the area is empty. Byte-identical to the file in the public dump |
| `POST /v1/networks/{id}/reports` | An anonymous verdict: `works`, `fails`, `not_free`, `private` or `gone` |
| `POST /v1/optout` | Remove a network and keep it out. Accepted whether or not the network was known, so the response never confirms that a BSSID is in the database |
| `POST /v1/claims` | A venue claims its network. Returns a challenge code to append to the SSID |
| `POST /v1/claims/{claim_id}/verify` | Confirms the code was seen on air and publishes the venue at full precision |

`/admin/` is Django's admin, for moderating claims and reports.

## The privacy properties, and where they live in the code

| Property | Where |
| --- | --- |
| R1–R12 re-checked on arrival, batch rejected whole when one breaks | `ingest/filters.py`, `ingest/views.py` |
| Envelopes are HPKE base mode, X25519 + HKDF-SHA256 + ChaCha20-Poly1305, `info` = `wifishare.batch/1`, key id as AAD | `ingest/hpke.py` |
| No IP address is stored or logged. The rate-limit bucket is `HMAC(address, salt-of-the-day)`; the salt is random per UTC day and deleted within 24 h | `ingest/ratelimit.py`, `LOGGING` in `config/settings.py` |
| A community network's BSSID is never published: it is not reachable from the function that builds the published representation | `networks/publish.py:published_properties` |
| A community network's position is the centre of its geohash-7 cell, not a measurement | `networks/publish.py:_apply_position` |
| A network whose sightings span more than 1 km is marked mobile and excluded at any precision | `networks/publish.py`, P4 |
| The opt-out list holds `HMAC-SHA256(BSSID)` under a server pepper, never the BSSID | `networks/publish.py:optout_hmac` |
| Raw observations die within 24 hours of the run that consumed them, and that run waits 8 days for their UTC day to close; buckets and salts die after 24 hours too | `networks/publish.py:purge`, `manage.py purge` |
| P1's evidence outlives them as a count and never as a bucket value: one row per network per closed UTC day, holding only the day, the distinct-bucket count and the observation count | `networks/models.py:NetworkDayTally`, `networks/publish.py:_record_day`, P9 |
| Rows older than 90 days collapse into one, so the record of which days a network was seen on does not accumulate; P1 reads sums, so its verdict is unchanged | `networks/publish.py:compact_tallies`, P10 |
| Public ids are random, carry no derivation from BSSID, SSID or position, and are not reused | `networks/models.py:new_public_id` |
| There is no BSSID lookup endpoint | `config/urls.py` — and `tests/test_read_api.py` asserts it |

Two things worth stating plainly, because they are the point:

- **The dump cannot be used to find a specific router.** Community-found BSSIDs
  never leave the database, and no endpoint takes a BSSID as a query.
- **An owner who verifies a network is choosing to be precisely located.** The
  claim flow must say that in those words before the owner confirms; the API
  cannot enforce that, the client must.

`Django server` access logging, which is the only stock logger that prints a
client address, is sent to a null handler and not allowed to propagate.
`tests/test_no_ip_logging.py` pins that, and also exercises real requests with
the root logger captured.

## Layout

```
config/          settings, URLs, WSGI/ASGI, the DATABASE_URL parser
core/            geohash, JSON Schema validation, RFC 9457 problem documents
ingest/          keys, envelopes, filter rules R1-R12, rate limiting
networks/        published networks, reports, opt-outs, claims, publish rules P1-P10
dump/            the public dump exporter
schemas/         a verbatim copy of spec/schemas, so the service is self-contained
tests/           the suite, including the two acceptance tests above
```

`schemas/` is a copy rather than a submodule so the container needs nothing
beside it. `tests/test_spec_sync.py` fails if the copy ever drifts from the spec
repo; when the spec changes, copy the files across again in the same commit.
Generated area files are validated against `area.schema.json` and `index.json`
against `index.schema.json` in `tests/test_export_dump.py`, so the dump cannot
drift from the contract either.

## Dependencies, and why each one is here

| Package | Why |
| --- | --- |
| `django` | The framework. Views are plain Django views; there is no DRF, because JSON Schema from the spec is a better contract than a second set of serialisers |
| `jsonschema` | Validates every request body and every generated area file against the spec's own schemas, so the spec stays the single source of truth |
| `pyhpke` | RFC 9180 HPKE. Maintained, its only dependency is `cryptography`, and `tests/test_hpke_vectors.py` proves it matches the RFC for our suite |
| `cryptography` | X25519 key generation and the primitives the vector test drives directly |
| `psycopg[binary]` | Optional, `--extra postgres`. Only for a Postgres deployment; tests run on SQLite |
| `gunicorn` | Optional, `--extra server`. Only the container image uses it |

Geohash, the DATABASE_URL parser and the rate limiter are a few dozen lines each
and are implemented here rather than pulled in, because their exact behaviour is
part of the privacy contract and we want it pinned by our own tests.

## Self-hosting

`docker-compose.yml` runs the API, Postgres, and the aggregate/export and purge
loops:

```sh
cp .env.example .env     # fill in SECRET_KEY, OPTOUT_PEPPER, POSTGRES_PASSWORD
docker compose up --build
```

Put TLS in front of it (the API binds to `127.0.0.1:8000`) and set
`BEHIND_TLS_PROXY=on`. Set `TRUST_X_FORWARDED_FOR=on` **only** if the proxy is
yours: otherwise a caller can pick their own rate-limit bucket.

Settings read from the environment: `DATABASE_URL`, `SECRET_KEY`,
`ALLOWED_HOSTS`, `DEBUG` (off unless set), `OPTOUT_PEPPER`, `KEY_GRACE_DAYS`,
`RATE_LIMIT_*`, `AREA_CACHE_SECONDS`, `LOG_LEVEL`. See `.env.example`, which
holds placeholders and no real values.

`OPTOUT_PEPPER` is effectively permanent: changing it makes every existing
opt-out stop matching. Back it up with the database, and never commit it.

Ingest keys rotate quarterly. `manage.py issue_ingest_key` generates one; the
private half never leaves the server and is never shown by the admin or by
`/v1/keys`. A retired key keeps decrypting envelopes already in flight for
`KEY_GRACE_DAYS` (30 by default), after which `/v1/batches` answers `409`.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

The spec is Apache-2.0 and the published data is ODbL-1.0; those live in their
own repositories.
