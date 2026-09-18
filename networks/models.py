"""Published networks, reports, opt-outs and claims.

A `Network` row is the aggregate of every observation of one access point. Its
BSSIDs live in `NetworkBssid` and are *never* published for a community-found
network (P2); the published representation is built by `networks.publish`.
"""

from __future__ import annotations

import secrets
import uuid

from django.db import models

BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
PUBLIC_ID_LENGTH = 12


def new_public_id() -> str:
    """P8: a random id with no derivation from BSSID, SSID or position."""
    while True:
        candidate = "".join(secrets.choice(BASE32_ALPHABET) for _ in range(PUBLIC_ID_LENGTH))
        taken = (
            Network.objects.filter(public_id=candidate).exists()
            or RetiredPublicId.objects.filter(public_id=candidate).exists()
        )
        if not taken:
            return candidate


class RetiredPublicId(models.Model):
    """Ids are not reused after P6, so retired ones are remembered."""

    public_id = models.CharField(max_length=PUBLIC_ID_LENGTH, unique=True)
    retired_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.public_id


class Network(models.Model):
    COMMUNITY = "community"
    OWNER_VERIFIED = "owner-verified"
    VERIFICATION_CHOICES = [(COMMUNITY, "community"), (OWNER_VERIFIED, "owner-verified")]

    PRECISION_M = {COMMUNITY: 150, OWNER_VERIFIED: 10}

    public_id = models.CharField(max_length=PUBLIC_ID_LENGTH, unique=True, default=new_public_id)
    ssid = models.CharField(max_length=32)
    security = models.CharField(max_length=8, default="open")
    captive_portal = models.CharField(max_length=8, default="unknown")
    verification = models.CharField(max_length=16, choices=VERIFICATION_CHOICES, default=COMMUNITY)

    # Aggregated position. Null until the first aggregation run sees it.
    lat = models.FloatField(null=True, blank=True)
    lon = models.FloatField(null=True, blank=True)
    cell = models.CharField(max_length=7, blank=True, db_index=True)

    first_seen = models.DateField(null=True, blank=True)
    last_seen = models.DateField(null=True, blank=True)

    # Running totals, so that purging raw observations does not move a network.
    observation_count = models.PositiveIntegerField(default=0)
    weight_sum = models.FloatField(default=0.0)
    weighted_lat_sum = models.FloatField(default=0.0)
    weighted_lon_sum = models.FloatField(default=0.0)

    # Cumulative bounding box of every observation ever aggregated, for P4.
    span_min_lat = models.FloatField(null=True, blank=True)
    span_max_lat = models.FloatField(null=True, blank=True)
    span_min_lon = models.FloatField(null=True, blank=True)
    span_max_lon = models.FloatField(null=True, blank=True)
    is_mobile = models.BooleanField(default=False)

    is_published = models.BooleanField(default=False, db_index=True)
    unpublished_reason = models.CharField(max_length=32, blank=True)
    last_aggregated_at = models.DateTimeField(null=True, blank=True)

    # Owner-verified extras (P3).
    venue_name = models.CharField(max_length=120, blank=True)
    venue_kind = models.CharField(max_length=40, blank=True)
    publish_credential = models.BooleanField(default=False)
    credential_type = models.CharField(max_length=16, blank=True)
    credential_secret = models.CharField(max_length=128, blank=True)
    credential_note = models.CharField(max_length=200, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ssid"]

    def __str__(self) -> str:
        return f"{self.ssid} [{self.public_id}]"

    @property
    def precision_m(self) -> int:
        return self.PRECISION_M[self.verification]

    @property
    def is_verified(self) -> bool:
        return self.verification == self.OWNER_VERIFIED

    def report_counts(self) -> dict[str, int]:
        """The two counts that are published (P2)."""
        counts = {"works": 0, "fails": 0}
        for row in self.reports.values("kind").annotate(n=models.Count("id")):
            if row["kind"] in counts:
                counts[row["kind"]] = row["n"]
        return counts

    def unpublishing_report_count(self) -> int:
        """P6 counts `private` and `gone` reports together."""
        return self.reports.filter(kind__in=Report.UNPUBLISH_KINDS).count()

    def unpublish(self, reason: str) -> None:
        self.is_published = False
        self.unpublished_reason = reason
        self.save(update_fields=["is_published", "unpublished_reason", "updated_at"])


class NetworkBssid(models.Model):
    """Which access points a network row stands for. Internal only for P2."""

    network = models.ForeignKey(Network, on_delete=models.CASCADE, related_name="bssids")
    bssid = models.CharField(max_length=17, unique=True)

    def __str__(self) -> str:
        return self.bssid


class Report(models.Model):
    KINDS = [(k, k) for k in ("works", "fails", "not_free", "private", "gone")]
    UNPUBLISH_KINDS = ("private", "gone")

    network = models.ForeignKey(Network, on_delete=models.CASCADE, related_name="reports")
    kind = models.CharField(max_length=10, choices=KINDS)
    note = models.CharField(max_length=200, blank=True)
    bucket = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    moderated = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.kind} on {self.network_id}"


class OptOut(models.Model):
    """P5. A BSSID opt-out is stored only as an HMAC under a server pepper."""

    REASONS = [(r, r) for r in ("mine", "private", "wrong", "other")]

    bssid_hmac = models.CharField(max_length=64, blank=True, db_index=True)
    ssid = models.CharField(max_length=32, blank=True)
    cell = models.CharField(max_length=5, blank=True)
    reason = models.CharField(max_length=8, blank=True, choices=REASONS)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["ssid", "cell"])]

    def __str__(self) -> str:
        if self.bssid_hmac:
            return f"opt-out {self.bssid_hmac[:8]}…"
        return f"opt-out {self.ssid} in {self.cell}"


class Claim(models.Model):
    PENDING, VERIFIED, REJECTED, EXPIRED = "pending", "verified", "rejected", "expired"
    STATUSES = [(s, s) for s in (PENDING, VERIFIED, REJECTED, EXPIRED)]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ssid = models.CharField(max_length=32)
    bssids = models.JSONField(default=list, blank=True)
    venue_name = models.CharField(max_length=120)
    venue_kind = models.CharField(max_length=40, blank=True)
    venue_lat = models.FloatField(null=True, blank=True)
    venue_lon = models.FloatField(null=True, blank=True)
    publish_credential = models.BooleanField(default=False)
    credential_type = models.CharField(max_length=16, blank=True)
    credential_secret = models.CharField(max_length=128, blank=True)
    credential_note = models.CharField(max_length=200, blank=True)
    contact_email = models.EmailField(blank=True, help_text="Never published.")

    challenge_code = models.CharField(max_length=16)
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=10, choices=STATUSES, default=PENDING)
    verified_at = models.DateTimeField(null=True, blank=True)
    moderator_note = models.CharField(max_length=200, blank=True)
    network = models.ForeignKey(
        Network, null=True, blank=True, on_delete=models.SET_NULL, related_name="claims"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.venue_name} / {self.ssid} ({self.status})"
