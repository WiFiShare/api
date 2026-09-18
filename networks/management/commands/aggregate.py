from __future__ import annotations

from django.core.management.base import BaseCommand

from networks.publish import aggregate


class Command(BaseCommand):
    help = "Turn raw observations into published networks, applying P1-P8."

    def handle(self, *args: object, **options: object) -> None:
        result = aggregate()
        self.stdout.write(
            f"consumed {result.observations_consumed} observations "
            f"across {result.networks_touched} networks"
        )
        self.stdout.write(
            f"published {result.published}, unpublished {result.unpublished}, "
            f"mobile {result.mobile}, blocked by opt-out {result.blocked_by_optout}, "
            f"below threshold {result.below_threshold}"
        )
