"""GET /v1/keys and POST /v1/batches."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from core.problems import problem
from core.schemas import SchemaError, validate
from ingest import hpke, ratelimit
from ingest.filters import filter_batch
from ingest.models import IngestKey, RawObservation


@require_http_methods(["GET"])
def keys(request: HttpRequest) -> HttpResponse:
    """The active ingest keys, newest first."""
    today = date.today()
    active = IngestKey.objects.filter(not_after__gte=today)
    return JsonResponse(
        {
            "keys": [
                {
                    "key_id": key.key_id,
                    "suite": key.suite,
                    "public_key": key.public_key,
                    "not_after": key.not_after.isoformat(),
                }
                for key in active
            ]
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def batches(request: HttpRequest) -> HttpResponse:
    """Accept one HPKE envelope of observations.

    The envelope is decrypted, every observation is re-checked against the
    filter rules, and the whole batch is refused if any of them breaks a rule
    (filter-rules.md). Nothing about the caller is written down except the
    rate-limit bucket.
    """
    bucket = ratelimit.bucket_for(request)
    try:
        ratelimit.check(bucket, "batches")
    except ratelimit.RateLimited as limited:
        return problem(
            "rate-limited", 429, headers={"Retry-After": str(limited.retry_after)}
        )

    try:
        envelope = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return problem("invalid-json", 400, detail="body is not valid JSON")

    try:
        validate("envelope", envelope)
    except SchemaError as error:
        return problem("schema-violation", 400, detail=error.detail)

    key = IngestKey.objects.filter(key_id=envelope["key_id"]).first()
    if key is None:
        return problem("unknown-key", 400, detail="no such ingest key")
    if key.suite != envelope["suite"]:
        return problem("schema-violation", 400, detail="suite does not match the key")

    grace = timedelta(days=settings.KEY_GRACE_DAYS)
    if date.today() > key.not_after + grace:
        return problem("retired-key", 409, detail="fetch /v1/keys and resend")

    try:
        plaintext = hpke.open_envelope(
            bytes(key.private_key),
            hpke.b64url_decode(envelope["enc"]),
            hpke.b64url_decode(envelope["ct"]),
            aad=key.key_id.encode("ascii"),
        )
        batch = json.loads(plaintext.decode("utf-8"))
    except hpke.DecryptionError:
        return problem("undecryptable", 400, detail="envelope did not open under this key")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return problem("invalid-json", 400, detail="sealed batch is not valid JSON")

    try:
        validate("batch", batch)
    except SchemaError as error:
        return problem("schema-violation", 400, detail=error.detail)

    decision = filter_batch(batch, datetime.now(timezone.utc))
    if decision.action != "accept":
        return problem(
            "filter-rule",
            400,
            detail=decision.detail or "batch refused",
            rule=decision.rule,
        )

    _store(decision.observations, bucket)

    body: dict[str, Any] = {
        "accepted": len(decision.observations),
        "rejected": decision.removed,
    }
    if decision.removed:
        body["rules"] = ["R12"]
    return JsonResponse(body, status=202)


def _store(observations: list[dict[str, Any]], bucket: str) -> None:
    RawObservation.objects.bulk_create(
        RawObservation(
            ssid=observation["ssid"],
            bssid=observation["bssid"],
            security=observation["security"],
            captive_portal=observation.get("captive_portal", "unknown"),
            lat=observation["lat"],
            lon=observation["lon"],
            accuracy_m=observation["accuracy_m"],
            rssi=observation["rssi"],
            frequency_mhz=observation.get("frequency_mhz"),
            observed_at=datetime.strptime(
                observation["observed_at"], "%Y-%m-%dT%H:00:00Z"
            ).replace(tzinfo=timezone.utc),
            source=observation["source"],
            bucket=bucket,
        )
        for observation in observations
    )
