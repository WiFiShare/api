"""Publish rules P1-P10.

spec/privacy/publish-rules.md fixes both the rules and the order in which the
aggregation job applies them:

    consume a closed UTC day -> tally it (P9) -> opt-out (P5) -> mobile (P4)
      -> threshold (P1) -> precision (P2/P3) -> write

P9 is what lets P1 outlive P7. A UTC day is *closed* 8 days on, past the
7-day window R7 lets a client upload within, so once a day is closed no
observation belonging to it can still arrive. Aggregation consumes only closed
days, and records on the network one row per day: the day, how many distinct
rate-limit buckets were seen in it, and how many observations. The bucket
values are not kept and are never compared across days -- the daily salt behind
them is deleted within 24 hours, so a bucket is already day-scoped and
"distinct buckets" has only ever meant distinct contributor-days. Summing the
per-day counts therefore gives the same number as counting distinct buckets
over the whole history, while keeping none of them. P1 reads that tally rather
than the raw rows, so a network whose third contributor arrives months after
the first two is still published, long after P7 has deleted the observations
that proved the first two.

Waiting for a day to close is what makes "tally it once" true rather than
hopeful: a closed day is tallied once and is never revised, because there is
nothing left that could revise it. The cost is latency, and the spec states it:
a network first seen today is publishable nine days later at the earliest,
eight for its first day to close and one more for P1's second day.

P10 then compacts: tally rows older than 90 days collapse into one row holding
the summed counts and the number of days. P1 reads sums, so its verdict does
not change, and the record of *which* days a network was seen on goes.

Two implementation choices the spec leaves open, recorded here because they
are visible in the output:

* **Weighting.** The observation schema says RSSI is "used to weight the
  position estimate". A stronger signal means the observer was nearer the
  access point, so each observation is weighted `rssi + 101` (1 at -100 dBm,
  101 at 0 dBm), which is monotonic and never zero.
* **Span.** P4 asks whether a network's observations span more than 1 km.
  Raw observations are deleted within a day of being consumed (P7), so the span
  is kept as a cumulative bounding box on the network row and measured across
  its diagonal. That is never smaller than the true maximum pairwise distance,
  so the check errs towards not publishing.
"""

from __future__ import annotations

import hmac
import math
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from hashlib import sha256
from typing import Any, Iterable

from django.conf import settings
from django.db import transaction
from django.db.models import Min, Sum

from core import geohash
from ingest.models import RawObservation
from networks.models import Network, NetworkBssid, NetworkDayTally, OptOut, RetiredPublicId

EARTH_RADIUS_M = 6_371_000.0

# P4: a network seen more than this far apart is a vehicle or a travel router.
MOBILE_THRESHOLD_M = 1_000.0

# P1: three observations, three buckets, two days, counted over the P9 tally.
MIN_OBSERVATIONS = 3
MIN_BUCKETS = 3
MIN_DAYS = 2

# P6: unpublish after twelve months without a sighting, or three of these.
STALE_AFTER = timedelta(days=365)
UNPUBLISH_REPORTS = 3

# P7: raw observations live one day past the run that consumed them, and so
# does every piece of rate-limit state.
OBSERVATION_RETENTION = timedelta(hours=24)
BUCKET_RETENTION = timedelta(hours=24)

# P9: a UTC day is closed, and only then consumable, this long after its own
# date. R7 lets a client upload an observation up to 7 days old, so by day 8
# nothing belonging to that day can still arrive.
CLOSED_AFTER = timedelta(days=8)

# P10: tally rows older than this are compacted into one row per network.
TALLY_COMPACT_AFTER = timedelta(days=90)

COMMUNITY_CELL_LENGTH = 7
AREA_CELL_LENGTH = 5
VERIFIED_DECIMALS = 5


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


def optout_hmac(bssid: str) -> str:
    """P5: the opt-out list holds HMAC-SHA256(BSSID) under a server pepper."""
    return hmac.new(settings.OPTOUT_PEPPER, bssid.lower().encode("ascii"), sha256).hexdigest()


def weight_for(rssi: int) -> float:
    return float(rssi + 101)


@dataclass
class AggregationResult:
    observations_consumed: int = 0
    networks_touched: int = 0
    published: int = 0
    unpublished: int = 0
    blocked_by_optout: int = 0
    mobile: int = 0
    below_threshold: int = 0
    reasons: dict[str, int] = field(default_factory=dict)

    def note(self, reason: str) -> None:
        self.reasons[reason] = self.reasons.get(reason, 0) + 1


def is_opted_out(network: Network) -> bool:
    """P5, for either form of opt-out: by BSSID, or by SSID plus area."""
    hashes = [optout_hmac(row.bssid) for row in network.bssids.all()]
    if hashes and OptOut.objects.filter(bssid_hmac__in=hashes).exists():
        return True
    if network.cell:
        return OptOut.objects.filter(
            ssid=network.ssid, cell=network.cell[:AREA_CELL_LENGTH]
        ).exists()
    return False


def _span_m(network: Network) -> float:
    if network.span_min_lat is None:
        return 0.0
    return haversine_m(
        network.span_min_lat, network.span_min_lon, network.span_max_lat, network.span_max_lon
    )


def _evidence(network: Network) -> tuple[int, int, int]:
    """P1's evidence, read from the P9 day tally and not from the raw rows.

    Returns (observations, distinct buckets, distinct UTC days). The counts
    come from `NetworkDayTally`, which survives the purge of the observations
    that produced it, so the threshold is cumulative over the network's whole
    life: a third contributor arriving months after the first two still
    publishes the network.

    "Distinct buckets" is the sum of the per-day distinct-bucket counts. That
    is the same number as counting distinct bucket values across the history,
    because the daily salt makes the same contributor produce an unrelated
    value on each day; and it needs none of the values to be kept.

    Every figure is a sum, and days come from `day_count` rather than a row
    count, so a P10-compacted row answers exactly as the rows it replaced did.
    """
    totals = network.day_tallies.aggregate(
        observations=Sum("observation_count"),
        buckets=Sum("bucket_count"),
        days=Sum("day_count"),
    )
    return (totals["observations"] or 0, totals["buckets"] or 0, totals["days"] or 0)


def _accumulate(network: Network, observations: Iterable[RawObservation]) -> None:
    """Fold new observations into the network's running totals."""
    for observation in observations:
        weight = weight_for(observation.rssi)
        network.weight_sum += weight
        network.weighted_lat_sum += weight * observation.lat
        network.weighted_lon_sum += weight * observation.lon
        network.observation_count += 1

        day = observation.observed_at.astimezone(timezone.utc).date()
        network.first_seen = day if network.first_seen is None else min(network.first_seen, day)
        network.last_seen = day if network.last_seen is None else max(network.last_seen, day)

        if network.span_min_lat is None:
            network.span_min_lat = network.span_max_lat = observation.lat
            network.span_min_lon = network.span_max_lon = observation.lon
        else:
            network.span_min_lat = min(network.span_min_lat, observation.lat)
            network.span_max_lat = max(network.span_max_lat, observation.lat)
            network.span_min_lon = min(network.span_min_lon, observation.lon)
            network.span_max_lon = max(network.span_max_lon, observation.lon)

        # The freshest sighting wins for the mutable descriptive fields.
        network.ssid = observation.ssid
        network.security = observation.security
        if observation.captive_portal != "unknown":
            network.captive_portal = observation.captive_portal


def centroid(network: Network) -> tuple[float, float] | None:
    if network.weight_sum <= 0:
        return None
    return (
        network.weighted_lat_sum / network.weight_sum,
        network.weighted_lon_sum / network.weight_sum,
    )


def _apply_position(network: Network, claim_position: tuple[float, float] | None) -> bool:
    """P2/P3: set the published position at the precision the rules allow."""
    if network.is_verified:
        position = claim_position or centroid(network)
        if position is None:
            return False
        lat, lon = round(position[0], VERIFIED_DECIMALS), round(position[1], VERIFIED_DECIMALS)
        network.lat, network.lon = lat, lon
        network.cell = geohash.encode(lat, lon, COMMUNITY_CELL_LENGTH)
        return True

    position = centroid(network)
    if position is None:
        return False
    cell = geohash.encode(position[0], position[1], COMMUNITY_CELL_LENGTH)
    network.cell = cell
    network.lat, network.lon = geohash.centre(cell)
    return True


def evaluate_network(network: Network, *, now: datetime, result: AggregationResult) -> None:
    """Run P5, P4, P1, P6 and P2/P3 over one network and save the verdict."""
    was_published = network.is_published

    if is_opted_out(network):  # P5
        network.is_published = False
        network.unpublished_reason = "opt-out"
        # P5 takes the tally with everything else: an opted-out network keeps
        # no evidence, so if it were ever allowed back it would start over.
        network.day_tallies.all().delete()
        result.blocked_by_optout += 1
        result.note("P5")
    elif _span_m(network) > MOBILE_THRESHOLD_M:  # P4
        network.is_mobile = True
        network.is_published = False
        network.unpublished_reason = "mobile"
        result.mobile += 1
        result.note("P4")
    else:
        network.is_mobile = False
        unpublishing_reports = network.unpublishing_report_count()
        stale = network.last_seen is not None and (now.date() - network.last_seen) > STALE_AFTER
        if unpublishing_reports >= UNPUBLISH_REPORTS:  # P6
            network.is_published = False
            network.unpublished_reason = "reports"
            result.note("P6")
        elif stale:  # P6
            network.is_published = False
            network.unpublished_reason = "stale"
            result.note("P6")
        else:
            claim_position = _claim_position(network)
            has_position = _apply_position(network, claim_position)  # P2/P3
            if not has_position:
                network.is_published = False
                network.unpublished_reason = "no-position"
            elif network.is_verified:  # P3 does not wait for P1
                network.is_published = True
                network.unpublished_reason = ""
            elif network.is_published:
                # P1 is an entry gate only: once a network is over the
                # threshold no later run re-tests it, and only P5 or P6 take it
                # out again. The spec does not say so either way; this is the
                # reading, written down because it is a choice.
                network.unpublished_reason = ""
            else:
                observations, buckets, days = _evidence(network)  # P1, over the P9 tally
                if observations >= MIN_OBSERVATIONS and buckets >= MIN_BUCKETS and days >= MIN_DAYS:
                    network.is_published = True
                    network.unpublished_reason = ""
                else:
                    result.below_threshold += 1
                    network.unpublished_reason = "threshold"
                    result.note("P1")

    network.last_aggregated_at = now
    network.save()

    if was_published and not network.is_published:
        result.unpublished += 1
        RetiredPublicId.objects.get_or_create(public_id=network.public_id)  # P8
    elif not was_published and network.is_published:
        result.published += 1


def _claim_position(network: Network) -> tuple[float, float] | None:
    claim = network.claims.filter(status="verified").order_by("-verified_at").first()
    if claim is None or claim.venue_lat is None or claim.venue_lon is None:
        return None
    return claim.venue_lat, claim.venue_lon


def last_closed_day(now: datetime) -> date:
    """P9: the newest UTC day that is closed, and so consumable, at `now`."""
    return now.astimezone(timezone.utc).date() - CLOSED_AFTER


def _closed_days_end(now: datetime) -> datetime:
    """P9: the first instant aggregation must not reach.

    Everything strictly earlier than this belongs to a day that is closed: at
    least 8 days on from its own date, so past the 7 days R7 gives a client to
    upload. Nothing belonging to such a day can still arrive, which is what
    lets a day be tallied once and never revised.
    """
    return datetime.combine(
        last_closed_day(now) + timedelta(days=1), time.min, tzinfo=timezone.utc
    )


def _record_day(network_id: int, day: date, buckets: int, observations: int) -> None:
    """P9: record one closed UTC day on a network. Never the bucket values.

    A closed day is tallied once and never revised. Finding a row already there
    therefore means the day was recorded by an earlier run and there is nothing
    to add: no observation for it can have arrived since.
    """
    NetworkDayTally.objects.get_or_create(
        network_id=network_id,
        day=day,
        defaults={"bucket_count": buckets, "observation_count": observations, "day_count": 1},
    )


@transaction.atomic
def aggregate(now: datetime | None = None) -> AggregationResult:
    """One aggregation run: consume completed UTC days, then re-decide publication."""
    now = now or datetime.now(timezone.utc)
    result = AggregationResult()

    pending = list(
        RawObservation.objects.filter(
            consumed_at__isnull=True, observed_at__lt=_closed_days_end(now)
        ).order_by("bssid", "observed_at")
    )
    touched: set[int] = set()

    by_bssid: dict[str, list[RawObservation]] = {}
    for observation in pending:
        by_bssid.setdefault(observation.bssid, []).append(observation)

    # P9, per network and per closed day: the distinct buckets seen in that day
    # and how many observations they carried. The bucket values live here only
    # for as long as the run, and are counted before being discarded.
    days_seen: dict[int, dict[date, tuple[set[str], int]]] = {}

    for bssid, observations in by_bssid.items():
        # P5 runs here, before anything is stored. That is earlier than the
        # rule order puts it, and publish-rules.md says the difference is
        # deliberate: an opted-out BSSID never reaches a network row at all.
        if OptOut.objects.filter(bssid_hmac=optout_hmac(bssid)).exists():
            RawObservation.objects.filter(id__in=[o.id for o in observations]).delete()
            result.blocked_by_optout += 1
            continue

        network = _network_for(bssid, observations[-1])
        _accumulate(network, observations)
        network.save()
        touched.add(network.pk)
        result.observations_consumed += len(observations)

        by_day = days_seen.setdefault(network.pk, {})
        for observation in observations:
            day = observation.observed_at.astimezone(timezone.utc).date()
            buckets, count = by_day.get(day, (set(), 0))
            buckets.add(observation.bucket)
            by_day[day] = (buckets, count + 1)

    for network_id, by_day in days_seen.items():
        for day, (buckets, count) in by_day.items():
            _record_day(network_id, day, len(buckets), count)

    RawObservation.objects.filter(id__in=[o.id for o in pending], consumed_at__isnull=True).update(
        consumed_at=now
    )

    # P6 has to be able to unpublish a network nobody reported this run, so
    # every network is re-evaluated, not only the ones that were touched.
    for network in Network.objects.prefetch_related("bssids"):
        evaluate_network(network, now=now, result=result)

    result.networks_touched = len(touched)
    return result


def _network_for(bssid: str, sample: RawObservation) -> Network:
    link = NetworkBssid.objects.filter(bssid=bssid).select_related("network").first()
    if link is not None:
        return link.network
    network = Network.objects.create(
        ssid=sample.ssid,
        security=sample.security,
        captive_portal=sample.captive_portal,
        verification=Network.COMMUNITY,
    )
    NetworkBssid.objects.create(network=network, bssid=bssid)
    return network


@transaction.atomic
def compact_tallies(now: datetime | None = None) -> int:
    """P10: collapse tally rows older than 90 days into one row per network.

    Atomic on purpose: the old rows are deleted before the summary that
    replaces them is written, and half of that would lose P1's evidence.

    The survivor carries the summed observation count, the summed bucket count
    and the number of days it stands for, so P1's three figures are unchanged
    to the unit. What goes is the day-by-day record of when a network was seen:
    afterwards the row names only the earliest day it covers.

    Returns how many rows were removed. A network already down to a single old
    row is left alone, which makes running this twice a no-op.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now.astimezone(timezone.utc).date() - TALLY_COMPACT_AFTER
    removed = 0

    network_ids = list(
        NetworkDayTally.objects.filter(day__lt=cutoff)
        .values_list("network_id", flat=True)
        .distinct()
    )
    for network_id in network_ids:
        rows = NetworkDayTally.objects.filter(network_id=network_id, day__lt=cutoff)
        if rows.count() < 2:
            continue
        totals = rows.aggregate(
            observations=Sum("observation_count"),
            buckets=Sum("bucket_count"),
            days=Sum("day_count"),
            earliest=Min("day"),
        )
        deleted, _ = rows.delete()
        NetworkDayTally.objects.create(
            network_id=network_id,
            day=totals["earliest"],
            observation_count=totals["observations"],
            bucket_count=totals["buckets"],
            day_count=totals["days"],
        )
        removed += deleted - 1

    return removed


def purge(now: datetime | None = None) -> dict[str, int]:
    """P7 and P10: delete what is spent, compact what is old.

    P7 takes consumed observations within 24 hours of the run that consumed
    them, and the rate-limit counters and daily salt within 24 hours too. A raw
    observation's whole life is therefore about nine days: eight waiting for
    its UTC day to close under P9, and one after being consumed.

    The P9 day tally is not raw data and is not deleted here, only compacted by
    P10. It holds no bucket value, no position and no timestamp finer than a
    date -- only "this many distinct contributors on this day" -- and P1 needs
    it to keep meaning something once the observations behind it are gone.
    """
    from ingest.models import RateLimitBucket, RateLimitSalt

    now = now or datetime.now(timezone.utc)
    observations, _ = RawObservation.objects.filter(
        consumed_at__isnull=False, consumed_at__lt=now - OBSERVATION_RETENTION
    ).delete()
    buckets, _ = RateLimitBucket.objects.filter(window_start__lt=now - BUCKET_RETENTION).delete()
    salts, _ = RateLimitSalt.objects.filter(day__lt=now.date()).delete()
    compacted = compact_tallies(now)  # P10
    return {
        "observations": observations,
        "buckets": buckets,
        "salts": salts,
        "tally_rows": compacted,
    }


# --- Published representation ---------------------------------------------


def published_properties(network: Network) -> dict[str, Any]:
    """The network as the outside world sees it.

    P2 is enforced here and nowhere else: a community-found network's BSSIDs,
    venue and credential are simply not reachable from this function.
    """
    properties: dict[str, Any] = {
        "id": network.public_id,
        "ssid": network.ssid,
        "security": network.security,
        "captive_portal": network.captive_portal or "unknown",
        "verification": network.verification,
        "lat": network.lat,
        "lon": network.lon,
        "precision_m": network.precision_m,
        "cell": network.cell,
        "first_seen": network.first_seen.isoformat() if network.first_seen else None,
        "last_seen": network.last_seen.isoformat() if network.last_seen else None,
        "reports": network.report_counts(),
    }

    if network.is_verified:  # P3
        bssids = sorted(network.bssids.values_list("bssid", flat=True))
        if bssids:
            properties["bssids"] = bssids
        if network.venue_name:
            venue = {"name": network.venue_name}
            if network.venue_kind:
                venue["kind"] = network.venue_kind
            properties["venue"] = venue
        if network.publish_credential and network.credential_type:
            credential = {"type": network.credential_type}
            if network.credential_secret:
                credential["secret"] = network.credential_secret
            if network.credential_note:
                credential["note"] = network.credential_note
            properties["credential"] = credential

    return properties


def published_feature(network: Network) -> dict[str, Any]:
    return {
        "type": "Feature",
        "id": network.public_id,
        "geometry": {"type": "Point", "coordinates": [network.lon, network.lat]},
        "properties": published_properties(network),
    }


def published_in_area(cell5: str) -> list[Network]:
    return list(
        Network.objects.filter(is_published=True, cell__startswith=cell5)
        .prefetch_related("bssids", "reports")
        .order_by("public_id")
    )


def area_document(cell5: str, networks: list[Network], generated: date) -> dict[str, Any]:
    """The GeoJSON document served by the API and written into the dump."""
    return {
        "type": "FeatureCollection",
        "schema": "wifishare.area/1",
        "cell": cell5,
        "generated": generated.isoformat(),
        "license": "ODbL-1.0",
        "attribution": "WiFiShare contributors",
        "features": [published_feature(network) for network in networks],
    }


def unpublish_for_reports(network: Network) -> bool:
    """P6: three private or gone reports take a network out immediately."""
    if network.unpublishing_report_count() >= UNPUBLISH_REPORTS and network.is_published:
        network.unpublish("reports")
        RetiredPublicId.objects.get_or_create(public_id=network.public_id)
        return True
    return False
