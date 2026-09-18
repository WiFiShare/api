"""Read and feedback endpoints: areas, reports, opt-out and claims."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from core import geohash
from core.problems import problem
from core.schemas import SchemaError, validate
from ingest import ratelimit
from networks import publish
from networks.models import Claim, Network, NetworkBssid, OptOut, Report, RetiredPublicId

GEOHASH5_RE = re.compile(r"^[0-9b-hjkmnp-z]{5}$")
PUBLIC_ID_RE = re.compile(r"^[a-z2-7]{12}$")
BSSID_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

CHALLENGE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
CHALLENGE_TTL = timedelta(days=7)


def _json_body(request: HttpRequest) -> dict[str, Any]:
    return json.loads(request.body.decode("utf-8"))


def _limited(request: HttpRequest, scope: str) -> HttpResponse | None:
    try:
        ratelimit.check(ratelimit.bucket_for(request), scope)
    except ratelimit.RateLimited as limited:
        return problem("rate-limited", 429, headers={"Retry-After": str(limited.retry_after)})
    return None


@require_http_methods(["GET"])
def area(request: HttpRequest, geohash5: str) -> HttpResponse:
    """The same GeoJSON document the dump holds for this cell."""
    if not GEOHASH5_RE.match(geohash5):
        return problem("not-found", 404, detail="not a geohash-5 cell")

    networks = publish.published_in_area(geohash5)
    if not networks:
        return problem("not-found", 404, detail="no published networks in this area yet")

    document = publish.area_document(geohash5, networks, date.today())
    payload = json.dumps(document, separators=(",", ":"), sort_keys=True)
    etag = '"%s"' % hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]

    if request.headers.get("If-None-Match") == etag:
        response = HttpResponse(status=304)
    else:
        response = HttpResponse(payload, content_type="application/geo+json")
    response["ETag"] = etag
    response["Cache-Control"] = f"public, max-age={settings.AREA_CACHE_SECONDS}"
    return response


@csrf_exempt
@require_http_methods(["POST"])
def reports(request: HttpRequest, network_id: str) -> HttpResponse:
    """Record one anonymous verdict on a published network."""
    limited = _limited(request, "reports")
    if limited is not None:
        return limited

    if not PUBLIC_ID_RE.match(network_id):
        return problem("unknown-network", 404, detail="no such network")

    network = Network.objects.filter(public_id=network_id).first()
    if network is None:
        return problem("unknown-network", 404, detail="no such network")

    try:
        body = _json_body(request)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return problem("invalid-json", 400, detail="body is not valid JSON")

    try:
        validate("report", body)
    except SchemaError as error:
        return problem("schema-violation", 400, detail=error.detail)

    Report.objects.create(
        network=network,
        kind=body["kind"],
        note=body.get("note", ""),
        bucket=ratelimit.bucket_for(request),
    )
    publish.unpublish_for_reports(network)  # P6
    return JsonResponse({}, status=202)


@csrf_exempt
@require_http_methods(["POST"])
def optout(request: HttpRequest) -> HttpResponse:
    """Remove a network and keep it out (P5).

    Accepted whether or not the network was known, so that the response never
    tells the caller whether a BSSID is in the database.
    """
    limited = _limited(request, "optout")
    if limited is not None:
        return limited

    try:
        body = _json_body(request)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return problem("invalid-json", 400, detail="body is not valid JSON")

    try:
        validate("optout", body)
    except SchemaError as error:
        return problem("schema-violation", 400, detail=error.detail)

    bssid = body.get("bssid")
    reason = body.get("reason", "")

    if bssid:
        OptOut.objects.get_or_create(
            bssid_hmac=publish.optout_hmac(bssid), defaults={"reason": reason}
        )
        link = NetworkBssid.objects.filter(bssid=bssid).select_related("network").first()
        if link is not None:
            _withdraw(link.network)
    else:
        OptOut.objects.get_or_create(
            ssid=body["ssid"], cell=body["cell"], defaults={"reason": reason}
        )
        for network in Network.objects.filter(ssid=body["ssid"], cell__startswith=body["cell"]):
            _withdraw(network)

    return JsonResponse({}, status=202)


def _withdraw(network: Network) -> None:
    """P6: the owner withdrew it. Unpublish now, do not wait for aggregation."""
    if network.is_published:
        RetiredPublicId.objects.get_or_create(public_id=network.public_id)  # P8
    network.unpublish("opt-out")


@csrf_exempt
@require_http_methods(["POST"])
def claims(request: HttpRequest) -> HttpResponse:
    """Start the SSID challenge for a venue claiming its own network."""
    limited = _limited(request, "claims")
    if limited is not None:
        return limited

    try:
        body = _json_body(request)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return problem("invalid-json", 400, detail="body is not valid JSON")

    try:
        validate("claim", body)
    except SchemaError as error:
        return problem("schema-violation", 400, detail=error.detail)

    venue = body["venue"]
    share = body["share"]
    credential = share.get("credential", {})
    code = "ws-" + "".join(secrets.choice(CHALLENGE_ALPHABET) for _ in range(6))
    expires_at = datetime.now(timezone.utc) + CHALLENGE_TTL

    claim = Claim.objects.create(
        ssid=body["ssid"],
        bssids=body.get("bssids", []),
        venue_name=venue["name"],
        venue_kind=venue.get("kind", ""),
        venue_lat=venue.get("lat"),
        venue_lon=venue.get("lon"),
        publish_credential=share["publish_credential"],
        credential_type=credential.get("type", ""),
        credential_secret=credential.get("secret", ""),
        credential_note=credential.get("note", ""),
        contact_email=body.get("contact", {}).get("email", ""),
        challenge_code=code,
        expires_at=expires_at,
    )

    return JsonResponse(
        {
            "claim_id": str(claim.id),
            "challenge_code": code,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        },
        status=201,
    )


@csrf_exempt
@require_http_methods(["POST"])
def verify_claim(request: HttpRequest, claim_id: str) -> HttpResponse:
    """Confirm the challenge code is visible on air, and publish the venue."""
    claim = Claim.objects.filter(id=claim_id).first() if _is_uuid(claim_id) else None
    if claim is None:
        return problem("claim-not-verified", 409, detail="no such claim")

    try:
        body = _json_body(request)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return problem("invalid-json", 400, detail="body is not valid JSON")

    observed_ssid = body.get("observed_ssid")
    bssid = body.get("bssid")
    if not isinstance(observed_ssid, str) or not isinstance(bssid, str):
        return problem("schema-violation", 400, detail="observed_ssid and bssid are required")
    if len(observed_ssid) > 40 or not BSSID_RE.match(bssid):
        return problem("schema-violation", 400, detail="observed_ssid or bssid is malformed")

    if claim.status == Claim.VERIFIED and claim.network is not None:
        return JsonResponse({"network_id": claim.network.public_id})

    if claim.status != Claim.PENDING:
        return problem("claim-not-verified", 409, detail="claim is not open")
    if claim.expires_at <= datetime.now(timezone.utc):
        claim.status = Claim.EXPIRED
        claim.save(update_fields=["status"])
        return problem("claim-not-verified", 409, detail="challenge expired")

    if claim.challenge_code not in observed_ssid.lower():
        return problem("claim-not-verified", 409, detail="code not seen on that network")
    if claim.bssids and bssid not in claim.bssids:
        return problem("claim-not-verified", 409, detail="code not seen on that network")

    network = _promote(claim, bssid)
    claim.status = Claim.VERIFIED
    claim.verified_at = datetime.now(timezone.utc)
    claim.network = network
    claim.save(update_fields=["status", "verified_at", "network"])

    return JsonResponse({"network_id": network.public_id})


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _promote(claim: Claim, bssid: str) -> Network:
    """Turn the claimed access points into one owner-verified network (P3)."""
    bssids = list(dict.fromkeys([bssid, *claim.bssids]))

    link = NetworkBssid.objects.filter(bssid__in=bssids).select_related("network").first()
    network = link.network if link is not None else Network.objects.create(ssid=claim.ssid)

    # Linked before the opt-out check below, which asks the network which
    # access points it stands for.
    for address in bssids:
        NetworkBssid.objects.update_or_create(bssid=address, defaults={"network": network})

    network.ssid = claim.ssid
    network.verification = Network.OWNER_VERIFIED
    network.venue_name = claim.venue_name
    network.venue_kind = claim.venue_kind
    network.publish_credential = claim.publish_credential
    network.credential_type = claim.credential_type
    network.credential_secret = claim.credential_secret if claim.publish_credential else ""
    network.credential_note = claim.credential_note
    if claim.credential_type in ("wpa2-psk", "wpa3-psk") and claim.publish_credential:
        network.security = "shared"

    position = (
        (claim.venue_lat, claim.venue_lon)
        if claim.venue_lat is not None and claim.venue_lon is not None
        else publish.centroid(network)
    )
    if position is not None:
        network.lat = round(position[0], publish.VERIFIED_DECIMALS)
        network.lon = round(position[1], publish.VERIFIED_DECIMALS)
        network.cell = geohash.encode(network.lat, network.lon, publish.COMMUNITY_CELL_LENGTH)
        today = date.today()
        network.first_seen = network.first_seen or today
        network.last_seen = max(network.last_seen or today, today)
        network.is_published = not publish.is_opted_out(network)  # P5 still refuses
        network.unpublished_reason = "" if network.is_published else "opt-out"
    network.save()
    return network
