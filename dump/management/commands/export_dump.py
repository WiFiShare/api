from __future__ import annotations

from datetime import date
from pathlib import Path

from django.core.management.base import BaseCommand, CommandParser

from dump.export import export


class Command(BaseCommand):
    help = "Write the public dump: areas/<gh2>/<gh3>/<gh5>.geojson plus index.json."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--out", required=True, help="Directory to write the dump into.")
        parser.add_argument(
            "--generated",
            default=None,
            help="Override the generation date (YYYY-MM-DD), for reproducible output.",
        )

    def handle(self, *args: object, **options: object) -> None:
        generated = (
            date.fromisoformat(str(options["generated"])) if options["generated"] else None
        )
        result = export(Path(str(options["out"])), generated=generated)
        self.stdout.write(
            f"wrote {result.network_count} networks in {result.area_count} areas "
            f"to {result.out_dir}"
        )
