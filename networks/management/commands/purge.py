from __future__ import annotations

from django.core.management.base import BaseCommand

from networks.publish import purge


class Command(BaseCommand):
    help = (
        "Retention (P7): delete raw observations 7 days after the aggregation "
        "that consumed them, and rate-limit buckets and salts after 24 hours."
    )

    def handle(self, *args: object, **options: object) -> None:
        deleted = purge()
        self.stdout.write(
            f"deleted {deleted['observations']} observations, "
            f"{deleted['buckets']} rate-limit buckets, {deleted['salts']} salts"
        )
