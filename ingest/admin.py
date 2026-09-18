"""Admin for ingest keys only.

Raw observations, rate-limit buckets and salts are deliberately not registered:
they are short-lived privacy-sensitive rows, and browsing them is not part of
moderating anything.
"""

from django.contrib import admin

from ingest.models import IngestKey


@admin.register(IngestKey)
class IngestKeyAdmin(admin.ModelAdmin):
    list_display = ["key_id", "suite", "not_after", "created_at"]
    readonly_fields = ["key_id", "suite", "public_key", "not_after", "created_at"]
    exclude = ["private_key"]

    def has_add_permission(self, request) -> bool:
        # Keys are issued by `manage.py issue_ingest_key`, which never shows
        # the private half to anyone.
        return False
