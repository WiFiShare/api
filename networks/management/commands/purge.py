from __future__ import annotations

from django.core.management.base import BaseCommand

from networks.publish import purge


class Command(BaseCommand):
    help = (
        "Retention (P7) and compaction (P10): delete raw observations, "
        "rate-limit buckets and salts 24 hours on, and collapse tally rows "
        "older than 90 days into one row per network."
    )

    def handle(self, *args: object, **options: object) -> None:
        deleted = purge()
        self.stdout.write(
            f"deleted {deleted['observations']} observations, "
            f"{deleted['buckets']} rate-limit buckets, {deleted['salts']} salts"
        )
        self.stdout.write(f"compacted away {deleted['tally_rows']} tally rows")
