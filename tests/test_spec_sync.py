"""The vendored schemas must stay byte-identical to the spec repo.

`schemas/` is a copy so the service runs in a container without the spec repo
checked out next to it. A copy that drifts is worse than no copy, so this test
compares the two whenever the spec repo is present.
"""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from core.schemas import SCHEMA_DIR

SPEC_SCHEMAS = Path(settings.SPEC_DIR) / "schemas"


class SpecSyncTest(SimpleTestCase):
    def setUp(self) -> None:
        if not SPEC_SCHEMAS.is_dir():
            self.skipTest(f"spec repo not checked out at {settings.SPEC_DIR}")

    def test_every_spec_schema_is_vendored(self) -> None:
        spec_names = {path.name for path in SPEC_SCHEMAS.glob("*.schema.json")}
        local_names = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}
        self.assertEqual(spec_names, local_names)

    def test_the_copies_are_identical(self) -> None:
        for path in sorted(SPEC_SCHEMAS.glob("*.schema.json")):
            with self.subTest(schema=path.name):
                self.assertEqual(
                    (SCHEMA_DIR / path.name).read_bytes(),
                    path.read_bytes(),
                    f"{path.name} has drifted from the spec repo; copy it across again",
                )
