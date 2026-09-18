"""Shared building blocks for the tests: an ingest key, a sealed envelope."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any

from ingest import hpke
from ingest.models import IngestKey, RawObservation
from networks.models import Network, NetworkBssid

KEY_ID = "2026q4"


def make_key(key_id: str = KEY_ID, *, not_after: date | None = None) -> IngestKey:
    pair = hpke.generate_keypair()
    return IngestKey.objects.create(
        key_id=key_id,
        suite=hpke.SUITE_NAME,
        public_key=pair.public_key_b64,
        private_key=pair.private_key,
        not_after=not_after or (date.today() + timedelta(days=60)),
    )


def seal_envelope(key: IngestKey, batch: dict[str, Any]) -> dict[str, Any]:
    enc, ciphertext = hpke.seal(
        hpke.b64url_decode(key.public_key),
        json.dumps(batch).encode("utf-8"),
        aad=key.key_id.encode("ascii"),
    )
    return {
        "schema": "wifishare.envelope/1",
        "key_id": key.key_id,
        "suite": key.suite,
        "enc": hpke.b64url_encode(enc),
        "ct": hpke.b64url_encode(ciphertext),
    }


def observation(**overrides: Any) -> dict[str, Any]:
    base = {
        "ssid": "Test Open Net",
        "bssid": "b8:27:eb:11:22:33",
        "security": "open",
        "captive_portal": "none",
        "lat": 44.4938,
        "lon": 11.3427,
        "accuracy_m": 12.0,
        "rssi": -60,
        "observed_at": "2026-09-17T14:00:00Z",
        "source": "scan",
    }
    base.update(overrides)
    return base


def batch(*observations: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "wifishare.batch/1",
        "client": {"platform": "android", "version": "1.0"},
        "observations": list(observations) or [observation()],
    }


def store_observation(
    *,
    bssid: str = "b8:27:eb:11:22:33",
    ssid: str = "Test Open Net",
    lat: float = 44.4938,
    lon: float = 11.3427,
    rssi: int = -60,
    bucket: str = "bucket-a",
    observed_at: datetime | None = None,
    security: str = "open",
    captive_portal: str = "none",
) -> RawObservation:
    return RawObservation.objects.create(
        ssid=ssid,
        bssid=bssid,
        security=security,
        captive_portal=captive_portal,
        lat=lat,
        lon=lon,
        accuracy_m=12.0,
        rssi=rssi,
        observed_at=observed_at or datetime(2026, 9, 17, 14, tzinfo=timezone.utc),
        source="scan",
        bucket=bucket,
    )


def publishable(bssid: str = "b8:27:eb:11:22:33", **kwargs: Any) -> list[RawObservation]:
    """Three observations, three buckets, two days: exactly what P1 asks for."""
    day_one = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
    day_two = datetime(2026, 9, 17, 14, tzinfo=timezone.utc)
    return [
        store_observation(bssid=bssid, bucket="bucket-a", observed_at=day_one, **kwargs),
        store_observation(bssid=bssid, bucket="bucket-b", observed_at=day_two, **kwargs),
        store_observation(bssid=bssid, bucket="bucket-c", observed_at=day_two, **kwargs),
    ]


def network_with_bssid(bssid: str = "b8:27:eb:11:22:33", **kwargs: Any) -> Network:
    network = Network.objects.create(**kwargs)
    NetworkBssid.objects.create(network=network, bssid=bssid)
    return network
