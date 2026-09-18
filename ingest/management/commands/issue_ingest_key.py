from __future__ import annotations

from datetime import date

from django.core.management.base import BaseCommand, CommandError, CommandParser

from ingest import hpke
from ingest.models import IngestKey

QUARTER_END = {1: (3, 31), 2: (6, 30), 3: (9, 30), 4: (12, 31)}


def quarter_id(today: date) -> str:
    return f"{today.year}q{(today.month - 1) // 3 + 1}"


class Command(BaseCommand):
    help = "Generate an HPKE ingest key pair and publish its public half at /v1/keys."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--key-id", default=None, help="Defaults to the current quarter.")
        parser.add_argument(
            "--not-after", default=None, help="YYYY-MM-DD. Defaults to the quarter end."
        )

    def handle(self, *args: object, **options: object) -> None:
        today = date.today()
        key_id = str(options["key_id"] or quarter_id(today))
        if IngestKey.objects.filter(key_id=key_id).exists():
            raise CommandError(f"key {key_id} already exists")

        if options["not_after"]:
            not_after = date.fromisoformat(str(options["not_after"]))
        else:
            year, quarter = int(key_id[:4]), int(key_id[5])
            month, day = QUARTER_END[quarter]
            not_after = date(year, month, day)

        pair = hpke.generate_keypair()
        IngestKey.objects.create(
            key_id=key_id,
            suite=hpke.SUITE_NAME,
            public_key=pair.public_key_b64,
            private_key=pair.private_key,
            not_after=not_after,
        )
        self.stdout.write(f"issued {key_id}, public key {pair.public_key_b64}, until {not_after}")
