"""Rate limiting that never sees, stores or logs an IP address.

The address is turned into a bucket with HMAC-SHA256 under a salt that is
random per UTC day and deleted within 24 hours by `manage.py purge` (P7). Only
the bucket is written down. Once the salt is gone the bucket cannot be linked
back to an address, not even by us.
"""

from __future__ import annotations

import hmac
import secrets
from datetime import date, datetime, timedelta, timezone
from hashlib import sha256

from django.conf import settings
from django.db import transaction
from django.http import HttpRequest

from ingest.models import RateLimitBucket, RateLimitSalt

SALT_BYTES = 32


def _salt_for(day: date) -> bytes:
    """Fetch or create the salt of the day, without racing another worker."""
    row = RateLimitSalt.objects.filter(day=day).first()
    if row is None:
        row, _ = RateLimitSalt.objects.get_or_create(
            day=day, defaults={"salt": secrets.token_bytes(SALT_BYTES)}
        )
    return bytes(row.salt)


def client_address(request: HttpRequest) -> str:
    """The caller's address, used immediately and never returned to a caller."""
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def bucket_for(request: HttpRequest, *, now: datetime | None = None) -> str:
    """HMAC(address, salt-of-the-day), hex. The only identifier we keep."""
    now = now or datetime.now(timezone.utc)
    salt = _salt_for(now.date())
    return hmac.new(salt, client_address(request).encode("utf-8"), sha256).hexdigest()


class RateLimited(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


def check(bucket: str, scope: str, *, now: datetime | None = None) -> None:
    """Count this request against `bucket`, raising RateLimited when over."""
    limit, window_seconds = settings.RATE_LIMITS[scope]
    now = now or datetime.now(timezone.utc)
    window = timedelta(seconds=window_seconds)
    window_start = datetime.fromtimestamp(
        (now.timestamp() // window_seconds) * window_seconds, tz=timezone.utc
    )

    with transaction.atomic():
        row, _ = RateLimitBucket.objects.select_for_update().get_or_create(
            bucket=bucket, scope=scope, window_start=window_start
        )
        if row.count >= limit:
            raise RateLimited(int((window_start + window - now).total_seconds()) + 1)
        row.count += 1
        row.save(update_fields=["count"])
