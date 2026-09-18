"""Moderation for claims and reports.

Moderators see what they need to judge a claim or a report and nothing more.
There is no view here that lists a BSSID next to a position for a
community-found network, and no view that shows a contributor: the rate-limit
bucket is not exposed, because it is the nearest thing to one that exists.
"""

from __future__ import annotations

from datetime import datetime, timezone

from django.contrib import admin, messages
from django.db.models import QuerySet
from django.http import HttpRequest

from networks.models import Claim, Network, NetworkBssid, OptOut, Report, RetiredPublicId


class NetworkBssidInline(admin.TabularInline):
    model = NetworkBssid
    extra = 0
    fields = ["bssid"]


@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = [
        "public_id",
        "ssid",
        "verification",
        "cell",
        "is_published",
        "is_mobile",
        "unpublished_reason",
        "last_seen",
    ]
    list_filter = ["verification", "is_published", "is_mobile", "security"]
    search_fields = ["public_id", "ssid", "cell"]
    readonly_fields = [
        "public_id",
        "observation_count",
        "weight_sum",
        "weighted_lat_sum",
        "weighted_lon_sum",
        "span_min_lat",
        "span_max_lat",
        "span_min_lon",
        "span_max_lon",
        "last_aggregated_at",
        "created_at",
        "updated_at",
    ]
    inlines = [NetworkBssidInline]
    actions = ["unpublish_selected"]

    def get_inlines(self, request: HttpRequest, obj: Network | None = None) -> list[type]:
        # A community network's BSSIDs are never published (P2), and there is
        # no reason for a moderator to read them either. An owner-verified
        # network publishes them, so showing them costs nothing.
        return [NetworkBssidInline] if obj is not None and obj.is_verified else []

    @admin.action(description="Unpublish (P6: moderator withdrawal)")
    def unpublish_selected(self, request: HttpRequest, queryset: QuerySet[Network]) -> None:
        count = 0
        for network in queryset.filter(is_published=True):
            RetiredPublicId.objects.get_or_create(public_id=network.public_id)
            network.unpublish("moderator")
            count += 1
        self.message_user(request, f"unpublished {count} networks", messages.SUCCESS)


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["created_at", "kind", "network", "moderated", "short_note"]
    list_filter = ["kind", "moderated"]
    search_fields = ["network__public_id", "network__ssid", "note"]
    readonly_fields = ["network", "kind", "note", "created_at"]
    actions = ["mark_moderated", "unpublish_network"]

    def get_fields(self, request: HttpRequest, obj: Report | None = None) -> list[str]:
        return ["network", "kind", "note", "created_at", "moderated"]

    @admin.display(description="note")
    def short_note(self, obj: Report) -> str:
        return (obj.note[:60] + "…") if len(obj.note) > 60 else obj.note

    @admin.action(description="Mark as moderated")
    def mark_moderated(self, request: HttpRequest, queryset: QuerySet[Report]) -> None:
        updated = queryset.update(moderated=True)
        self.message_user(request, f"marked {updated} reports", messages.SUCCESS)

    @admin.action(description="Unpublish the reported network (P6)")
    def unpublish_network(self, request: HttpRequest, queryset: QuerySet[Report]) -> None:
        networks = {report.network for report in queryset.select_related("network")}
        for network in networks:
            if network.is_published:
                RetiredPublicId.objects.get_or_create(public_id=network.public_id)
                network.unpublish("moderator")
        self.message_user(request, f"unpublished {len(networks)} networks", messages.SUCCESS)


@admin.register(Claim)
class ClaimAdmin(admin.ModelAdmin):
    list_display = ["created_at", "venue_name", "ssid", "status", "network", "expires_at"]
    list_filter = ["status", "publish_credential"]
    search_fields = ["venue_name", "ssid", "contact_email"]
    readonly_fields = ["id", "challenge_code", "created_at", "verified_at", "network"]
    actions = ["approve", "reject"]

    @admin.action(description="Approve: publish as owner-verified (P3)")
    def approve(self, request: HttpRequest, queryset: QuerySet[Claim]) -> None:
        from networks.views import _promote

        approved = 0
        for claim in queryset.exclude(status=Claim.VERIFIED):
            bssid = (claim.bssids or [None])[0]
            if not bssid:
                self.message_user(
                    request,
                    f"{claim} carries no BSSID; it can only be verified through the app",
                    messages.WARNING,
                )
                continue
            claim.network = _promote(claim, bssid)
            claim.status = Claim.VERIFIED
            claim.verified_at = datetime.now(timezone.utc)
            claim.save(update_fields=["network", "status", "verified_at"])
            approved += 1
        self.message_user(request, f"approved {approved} claims", messages.SUCCESS)

    @admin.action(description="Reject")
    def reject(self, request: HttpRequest, queryset: QuerySet[Claim]) -> None:
        updated = queryset.exclude(status=Claim.VERIFIED).update(status=Claim.REJECTED)
        self.message_user(request, f"rejected {updated} claims", messages.SUCCESS)


@admin.register(OptOut)
class OptOutAdmin(admin.ModelAdmin):
    list_display = ["created_at", "identifier", "reason"]
    list_filter = ["reason"]
    readonly_fields = ["bssid_hmac", "created_at"]

    @admin.display(description="identifies")
    def identifier(self, obj: OptOut) -> str:
        # The BSSID itself is not stored: only its HMAC under the server pepper (P5).
        if obj.bssid_hmac:
            return f"bssid hmac {obj.bssid_hmac[:12]}…"
        return f"{obj.ssid} in {obj.cell}"


@admin.register(RetiredPublicId)
class RetiredPublicIdAdmin(admin.ModelAdmin):
    list_display = ["public_id", "retired_at"]
    readonly_fields = ["public_id", "retired_at"]


admin.site.site_header = "WiFiShare moderation"
admin.site.site_title = "WiFiShare"
admin.site.index_title = "Claims, reports and published networks"