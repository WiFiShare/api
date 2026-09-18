"""Filter rules R1-R12, re-applied server side.

The rules live in spec/privacy/filter-rules.md and their acceptance test
vectors in spec/privacy/fixtures/filter-cases.json. Clients run these on the
device before anything is encrypted; the server runs them again on arrival
because a client cannot be trusted to be a current version.

Two things the spec insists on and this module implements literally:

* the drop rules are evaluated in numeric order and the *first* one that
  matches is the one reported;
* R7 is evaluated against a caller-supplied `now`, never the wall clock, so
  the fixtures do not rot.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from core.schemas import schema_properties

# Fields the observation schema defines, plus the one raw platform field the
# rules themselves consume: `hidden` is what R1 tests, and every fixture input
# carries it, so it cannot be an R8 violation.
RAW_ONLY_FIELDS = frozenset({"hidden"})

MAX_ACCURACY_M = 50.0
MAX_AGE = timedelta(days=7)
MAX_OBSERVATIONS_PER_BATCH = 200
OPT_OUT_SUFFIXES = ("_nomap", "_optout")
ALLOWED_SECURITY = frozenset({"open", "owe"})

# Verbatim from privacy/filter-rules.md. Each is matched against the whole
# SSID, case-insensitively: the anchoring is the point, an unanchored `iphone`
# would also drop `iPhone Repair Shop WiFi`, which is a place and not a person.
HOTSPOT_PATTERNS: tuple[str, ...] = (
    r"^(iphone|ipad)([-_ ]?[0-9]{1,4})?$",
    r"^(iphone|ipad|galaxy|pixel) (di|de|van|von) .+",
    r".+['`’]s (iphone|ipad|phone|galaxy|hotspot)$",
    r"^androidap[0-9]*$",
    r"^galaxy[-_ ]?[a-z]?[0-9]{1,3}([-_ ].*)?$",
    r"^(mifi|myhotspot|personal ?hotspot)([-_ 0-9].*)?$",
)
_HOTSPOT_RES = tuple(re.compile(p, re.IGNORECASE) for p in HOTSPOT_PATTERNS)

_BSSID_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")


@dataclass(frozen=True)
class Decision:
    """The outcome of running R1-R11 over one raw scan result."""

    action: str  # "keep" or "drop"
    rule: str | None = None  # the first drop rule that matched
    normalized: dict[str, Any] | None = None
    detail: str | None = None  # set when the input was not a usable observation

    @property
    def kept(self) -> bool:
        return self.action == "keep"


@dataclass
class BatchDecision:
    """The outcome of running R12 over one batch."""

    action: str  # "accept" or "reject"
    rule: str | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)
    removed: int = 0
    detail: str | None = None


def _allowed_input_fields() -> frozenset[str]:
    return frozenset(schema_properties("observation")) | RAW_ONLY_FIELDS


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _round_coordinate(value: float) -> float:
    """R10: four decimal places, about 11 m."""
    return round(value, 4)


def normalize_bssid(value: str) -> str:
    """R9: lowercase hexadecimal with colons."""
    return value.lower().replace("-", ":")


def truncate_to_hour(moment: datetime) -> str:
    """R11: down to the hour, in UTC."""
    utc = moment.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    return utc.strftime("%Y-%m-%dT%H:00:00Z")


def evaluate(raw: dict[str, Any], now: datetime) -> Decision:
    """Apply R1-R11 to one raw platform scan result.

    Returns a keep decision carrying the normalised observation, or a drop
    decision naming the first rule that matched.
    """
    if not isinstance(raw, dict):
        return Decision("drop", detail="observation is not an object")

    ssid = raw.get("ssid")

    # R1: absent, empty, or hidden.
    if raw.get("hidden") is True or not isinstance(ssid, str) or ssid == "":
        return Decision("drop", "R1")

    # R2: the standard opt-out suffix. Only the suffix counts.
    lowered = ssid.lower()
    if lowered.endswith(OPT_OUT_SUFFIXES):
        return Decision("drop", "R2")

    # R3: locally administered BSSID, bit 0x02 of the first octet.
    bssid = raw.get("bssid")
    if not isinstance(bssid, str) or not _BSSID_RE.match(bssid):
        return Decision("drop", detail="bssid is missing or malformed")
    if int(normalize_bssid(bssid)[0:2], 16) & 0x02:
        return Decision("drop", "R3")

    # R4: personal-hotspot patterns.
    if any(pattern.fullmatch(ssid) for pattern in _HOTSPOT_RES):
        return Decision("drop", "R4")

    # R5: phase 1 collects only networks anyone may join.
    if raw.get("security") not in ALLOWED_SECURITY:
        return Decision("drop", "R5")

    # R6: no location fix, or a fix we cannot trust.
    lat, lon, accuracy = raw.get("lat"), raw.get("lon"), raw.get("accuracy_m")
    if not _is_number(lat) or not _is_number(lon) or not _is_number(accuracy):
        return Decision("drop", "R6")
    if accuracy <= 0 or accuracy > MAX_ACCURACY_M:
        return Decision("drop", "R6")
    if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
        return Decision("drop", detail="position out of range")

    # R7: stale in the queue. Measured against the caller's clock, not ours.
    observed_at = _parse_timestamp(raw.get("observed_at"))
    if observed_at is None:
        return Decision("drop", detail="observed_at is missing or not RFC 3339")
    if now - observed_at > MAX_AGE:
        return Decision("drop", "R7")

    # R8: belt and braces against a future contributor adding a device id.
    unknown = set(raw) - _allowed_input_fields()
    if unknown:
        return Decision("drop", "R8")

    # Not rules, but an observation without these is not an observation. The
    # ingest path has already validated the batch against batch.schema.json, so
    # this only bites callers of `evaluate` that skipped that step.
    rssi = raw.get("rssi")
    if not isinstance(rssi, int) or isinstance(rssi, bool) or not (-100 <= rssi <= 0):
        return Decision("drop", detail="rssi is missing or out of range")
    if raw.get("source") not in ("scan", "connected"):
        return Decision("drop", detail="source is missing or unknown")

    normalized: dict[str, Any] = {
        "ssid": ssid,
        "bssid": normalize_bssid(bssid),  # R9
        "security": raw["security"],
    }
    if "captive_portal" in raw:
        normalized["captive_portal"] = raw["captive_portal"]
    normalized["lat"] = _round_coordinate(lat)  # R10
    normalized["lon"] = _round_coordinate(lon)  # R10
    normalized["accuracy_m"] = accuracy
    normalized["rssi"] = rssi
    if "frequency_mhz" in raw:
        normalized["frequency_mhz"] = raw["frequency_mhz"]
    normalized["observed_at"] = truncate_to_hour(observed_at)  # R11
    normalized["source"] = raw["source"]

    return Decision("keep", normalized=normalized)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def dedupe_key(observation: dict[str, Any]) -> tuple[str, float, float, str]:
    """R12's identity: one observation per (BSSID, rounded position, hour)."""
    return (
        observation["bssid"],
        observation["lat"],
        observation["lon"],
        observation["observed_at"],
    )


def apply_r12(observations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Dedupe by (BSSID, position, hour) keeping the strongest RSSI, then cap.

    Returns the surviving observations in input order and how many were
    removed. Shuffling is the sender's job; the server keeps the received
    order, which a sender has already shuffled.
    """
    best: dict[tuple[str, float, float, str], dict[str, Any]] = {}
    order: list[tuple[str, float, float, str]] = []
    for observation in observations:
        key = dedupe_key(observation)
        current = best.get(key)
        if current is None:
            best[key] = observation
            order.append(key)
        elif observation["rssi"] > current["rssi"]:
            best[key] = observation

    kept = [best[key] for key in order][:MAX_OBSERVATIONS_PER_BATCH]
    return kept, len(observations) - len(kept)


#: Keys a batch may carry. Anything else is a linkage field and R12 refuses it.
BATCH_FIELDS = frozenset({"schema", "client", "observations"})


def check_batch_linkage(batch: dict[str, Any]) -> BatchDecision | None:
    """R12: no batch id, sequence number, session id or timestamp of its own."""
    if not isinstance(batch, dict):
        return BatchDecision("reject", "R12", detail="batch is not an object")
    extra = set(batch) - BATCH_FIELDS
    if extra:
        return BatchDecision("reject", "R12", detail="batch carries a linkage field")
    return None


def filter_batch(batch: dict[str, Any], now: datetime) -> BatchDecision:
    """Run R1-R12 over a whole batch, the way the server does on arrival.

    A batch whose observations all survive the drop rules is accepted with the
    deduplicated, capped observation list. A batch that breaks a rule is
    rejected whole, naming the rule, as filter-rules.md requires.
    """
    refusal = check_batch_linkage(batch)
    if refusal is not None:
        return refusal

    raw_observations = batch.get("observations")
    if not isinstance(raw_observations, list) or not raw_observations:
        return BatchDecision("reject", detail="batch carries no observations")

    kept: list[dict[str, Any]] = []
    for raw in raw_observations:
        decision = evaluate(raw, now)
        if not decision.kept:
            return BatchDecision(
                "reject",
                decision.rule,
                detail=decision.detail or "observation dropped by a filter rule",
            )
        assert decision.normalized is not None
        kept.append(decision.normalized)

    observations, removed = apply_r12(kept)
    return BatchDecision("accept", observations=observations, removed=removed)
