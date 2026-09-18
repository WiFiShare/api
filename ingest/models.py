"""Ingest-side storage: keys, raw observations, rate-limit buckets.

None of these rows holds an IP address. A contributor is represented only by a
`bucket` value, which is an HMAC of their address under a salt that is thrown
away within 24 hours (P7), so a bucket stops meaning anything the day after it
was written.
"""

from __future__ import annotations

from django.db import models


class IngestKey(models.Model):
    """An HPKE recipient key pair. Public half is served at GET /v1/keys."""

    SUITE = "x25519-sha256-chacha20poly1305"

    key_id = models.CharField(max_length=8, unique=True)  # e.g. 2026q4
    suite = models.CharField(max_length=40, default=SUITE)
    public_key = models.CharField(max_length=64, help_text="32 bytes, base64url, unpadded")
    private_key = models.BinaryField(help_text="32 raw bytes. Never leaves the server.")
    not_after = models.DateField(help_text="Last day clients should encrypt to this key.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-not_after", "-key_id"]

    def __str__(self) -> str:
        return f"{self.key_id} (until {self.not_after})"


class RateLimitSalt(models.Model):
    """The salt of the day. Rotated daily and deleted by `manage.py purge`.

    Rotating and then deleting the salt is what makes an old bucket value
    unlinkable to an address even by us.
    """

    day = models.DateField(unique=True)
    salt = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"salt for {self.day}"


class RateLimitBucket(models.Model):
    """A counter keyed on HMAC(address, salt-of-the-day), never the address."""

    bucket = models.CharField(max_length=64, db_index=True)
    scope = models.CharField(max_length=16)
    window_start = models.DateTimeField()
    count = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["bucket", "scope", "window_start"], name="unique_bucket_window"
            )
        ]
        indexes = [models.Index(fields=["window_start"])]

    def __str__(self) -> str:
        return f"{self.scope} {self.bucket[:8]}… x{self.count}"


class RawObservation(models.Model):
    """One observation out of a decrypted batch, pending aggregation.

    Deleted within 24 hours of the aggregation run that consumed it (P7),
    and that run comes only once its UTC day is closed, 8 days on (P9). The
    `bucket` column is what P9 counts, once per completed UTC day, into
    `NetworkDayTally`; the value itself is never copied onto the network, and
    P1 reads that tally rather than these rows, so the threshold outlives them.
    """

    ssid = models.CharField(max_length=32)
    bssid = models.CharField(max_length=17, db_index=True)
    security = models.CharField(max_length=8)
    captive_portal = models.CharField(max_length=8, default="unknown")
    lat = models.FloatField()
    lon = models.FloatField()
    accuracy_m = models.FloatField()
    rssi = models.IntegerField()
    frequency_mhz = models.IntegerField(null=True, blank=True)
    observed_at = models.DateTimeField()
    source = models.CharField(max_length=10)
    bucket = models.CharField(max_length=64)
    received_at = models.DateTimeField(auto_now_add=True)
    consumed_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        indexes = [models.Index(fields=["bssid", "observed_at"])]

    def __str__(self) -> str:
        return f"{self.ssid} @ {self.observed_at:%Y-%m-%d %H:00}"
