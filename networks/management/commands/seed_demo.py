"""Fictional networks so a local website has something to render.

Everything this writes is invented. Every SSID carries the word "Demo", the
BSSIDs are in the IANA documentation-style block `00:00:5e:00:53:xx`, and the
venue names are made up, so nothing here can be mistaken for a real network or
a real place.

Two modes:

* the default writes published `Network` rows directly, which is what a local
  website or app needs to have something on the map straight away;
* `--observations` writes raw observations instead and leaves them for
  `manage.py aggregate` to turn into networks, which is the only way to watch
  the real pipeline work. Their dates are 9 and 10 days back, because P9 will
  not consume a UTC day until it is closed, 8 days after it ends.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

from django.core.management.base import BaseCommand, CommandParser
from django.db import transaction

from core import geohash
from ingest.models import RawObservation
from networks.models import Network, NetworkBssid, Report
from networks.publish import COMMUNITY_CELL_LENGTH, VERIFIED_DECIMALS

# The three fictional contributors of `--observations`. A bucket is an HMAC in
# production; these are labels, because nothing reads them but the P9 tally and
# an operator reading the table should see at once that they are invented.
DEMO_BUCKETS = ("demo-contributor-1", "demo-contributor-2", "demo-contributor-3")

# P9 closes a UTC day 8 days after it ends, so anything seeded more recently
# than that would sit in the table until the following week and an operator
# running `aggregate` would see nothing happen. 9 and 10 days back are closed
# whenever this runs, and are two distinct days, which is what P1 asks for.
DEMO_OBSERVATION_DAYS_AGO = (10, 9)

# Two areas: Piazza Maggiore in Bologna (srbj4) and Lisbon's Baixa (eycs5).
SEEDS: list[dict] = [
    {
        "ssid": "Demo Biblioteca Sala Borsa",
        "bssid": "00:00:5e:00:53:01",
        "lat": 44.4938,
        "lon": 11.3426,
        "security": "open",
        "captive_portal": "none",
        "verification": Network.COMMUNITY,
        "reports": {"works": 7, "fails": 1},
    },
    {
        "ssid": "Demo Portico WiFi",
        "bssid": "00:00:5e:00:53:02",
        "lat": 44.4952,
        "lon": 11.3458,
        "security": "owe",
        "captive_portal": "unknown",
        "verification": Network.COMMUNITY,
        "reports": {"works": 3, "fails": 0},
    },
    {
        "ssid": "Demo Parco Libero",
        "bssid": "00:00:5e:00:53:03",
        "lat": 44.4901,
        "lon": 11.3390,
        "security": "open",
        "captive_portal": "detected",
        "verification": Network.COMMUNITY,
        "reports": {"works": 2, "fails": 2},
    },
    {
        "ssid": "Demo Caffe Centrale",
        "bssid": "00:00:5e:00:53:04",
        "lat": 44.49417,
        "lon": 11.34290,
        "security": "shared",
        "captive_portal": "none",
        "verification": Network.OWNER_VERIFIED,
        "venue": {"name": "Demo Caffè Centrale (fictional)", "kind": "cafe"},
        "credential": {
            "type": "wpa2-psk",
            "secret": "demo-not-a-real-password",
            "note": "Ask at the bar",
        },
        "extra_bssids": ["00:00:5e:00:53:05"],
        "reports": {"works": 11, "fails": 0},
    },
    {
        "ssid": "Demo Praca WiFi",
        "bssid": "00:00:5e:00:53:06",
        "lat": 38.7100,
        "lon": -9.1400,
        "security": "open",
        "captive_portal": "unknown",
        "verification": Network.COMMUNITY,
        "reports": {"works": 4, "fails": 1},
    },
    {
        "ssid": "Demo Livraria Aberta",
        "bssid": "00:00:5e:00:53:07",
        "lat": 38.7123,
        "lon": -9.1365,
        "security": "open",
        "captive_portal": "none",
        "verification": Network.COMMUNITY,
        "reports": {"works": 5, "fails": 0},
    },
]


class Command(BaseCommand):
    help = "Create a handful of clearly fictional networks, or the observations behind them."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--clear", action="store_true", help="Delete the demo networks instead of adding them."
        )
        parser.add_argument(
            "--observations",
            action="store_true",
            help=(
                "Seed raw observations instead of published networks, dated 9 and 10 days "
                "back so their UTC days are closed (P9) and `manage.py aggregate` can "
                "consume them. Use it to watch the real pipeline publish something."
            ),
        )

    @transaction.atomic
    def handle(self, *args: object, **options: object) -> None:
        demo_bssids = [seed["bssid"] for seed in SEEDS] + [
            bssid for seed in SEEDS for bssid in seed.get("extra_bssids", [])
        ]

        if options["clear"]:
            deleted = Network.objects.filter(bssids__bssid__in=demo_bssids).distinct().delete()
            observations, _ = RawObservation.objects.filter(bssid__in=demo_bssids).delete()
            self.stdout.write(f"removed demo networks ({deleted[0]} rows)")
            self.stdout.write(f"removed {observations} demo observations")
            return

        if options["observations"]:
            self._seed_observations(demo_bssids)
            return

        today = date.today()
        for seed in SEEDS:
            network = self._upsert(seed, today)
            self.stdout.write(f"{network.public_id}  {network.ssid}  {network.cell}")

        self.stdout.write(f"seeded {len(SEEDS)} fictional networks")

    def _seed_observations(self, demo_bssids: list[str]) -> None:
        """Enough sightings of each community seed to satisfy P1, on closed days.

        Three observations from three distinct buckets across two UTC days, per
        network: exactly the threshold, so `aggregate` publishes every one of
        them and an operator can see the whole sequence work.
        """
        # Only anything not yet consumed: re-seeding before an aggregation run
        # replaces the batch rather than doubling it.
        RawObservation.objects.filter(bssid__in=demo_bssids, consumed_at__isnull=True).delete()

        today = datetime.now(timezone.utc).date()
        day_one, day_two = (today - timedelta(days=ago) for ago in DEMO_OBSERVATION_DAYS_AGO)
        # One contributor on the earlier day, two on the later one.
        sightings = (
            (day_one, 9, DEMO_BUCKETS[0], -58),
            (day_two, 11, DEMO_BUCKETS[1], -63),
            (day_two, 17, DEMO_BUCKETS[2], -55),
        )

        rows = []
        for seed in SEEDS:
            if seed["verification"] != Network.COMMUNITY:
                # An owner-verified network is published by its claim, not by
                # being seen, so there is nothing to observe it into being.
                continue
            for day, hour, bucket, rssi in sightings:
                rows.append(
                    RawObservation(
                        ssid=seed["ssid"],
                        bssid=seed["bssid"],
                        security=seed["security"],
                        captive_portal=seed["captive_portal"],
                        lat=round(seed["lat"], 4),  # R10
                        lon=round(seed["lon"], 4),
                        accuracy_m=12.0,
                        rssi=rssi,
                        observed_at=datetime.combine(day, time(hour), tzinfo=timezone.utc),
                        source="scan",
                        bucket=bucket,
                    )
                )
        RawObservation.objects.bulk_create(rows)

        networks = len({row.bssid for row in rows})
        self.stdout.write(
            f"seeded {len(rows)} fictional observations of {networks} networks, "
            f"on {day_one.isoformat()} and {day_two.isoformat()}"
        )
        self.stdout.write(
            "both days are closed (P9 consumes a day 8 days after it ends), so "
            "`manage.py aggregate` will publish them now"
        )

    def _upsert(self, seed: dict, today: date) -> Network:
        link = NetworkBssid.objects.filter(bssid=seed["bssid"]).select_related("network").first()
        network = link.network if link else Network()

        verified = seed["verification"] == Network.OWNER_VERIFIED
        cell = geohash.encode(seed["lat"], seed["lon"], COMMUNITY_CELL_LENGTH)
        if verified:
            lat, lon = round(seed["lat"], VERIFIED_DECIMALS), round(seed["lon"], VERIFIED_DECIMALS)
        else:
            lat, lon = geohash.centre(cell)

        network.ssid = seed["ssid"]
        network.security = seed["security"]
        network.captive_portal = seed["captive_portal"]
        network.verification = seed["verification"]
        network.lat, network.lon, network.cell = lat, lon, cell
        network.first_seen = today - timedelta(days=40)
        network.last_seen = today - timedelta(days=1)
        network.observation_count = 12
        network.is_published = True
        network.unpublished_reason = ""
        if verified:
            network.venue_name = seed["venue"]["name"]
            network.venue_kind = seed["venue"].get("kind", "")
            network.publish_credential = True
            network.credential_type = seed["credential"]["type"]
            network.credential_secret = seed["credential"]["secret"]
            network.credential_note = seed["credential"].get("note", "")
        network.save()

        for bssid in [seed["bssid"], *seed.get("extra_bssids", [])]:
            NetworkBssid.objects.update_or_create(bssid=bssid, defaults={"network": network})

        network.reports.all().delete()
        Report.objects.bulk_create(
            Report(network=network, kind=kind)
            for kind, count in seed["reports"].items()
            for _ in range(count)
        )
        return network
