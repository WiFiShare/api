"""The acceptance test for R1-R12.

Runs every case in spec/privacy/fixtures/filter-cases.json: each observation
case is checked for the keep/drop decision, the rule id that decided it, and —
for kept cases — the exact normalised output; each batch case is checked for
the surviving count and, where the fixture pins it, which observation survived.

`now` comes from the fixture file, never the wall clock, as filter-rules.md
requires. The fixtures are read from the spec repo itself (settings.SPEC_DIR),
not from a copy, so a change there shows up here.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from django.conf import settings
from django.test import SimpleTestCase

from ingest.filters import evaluate, filter_batch

FIXTURES_PATH = Path(settings.SPEC_DIR) / "privacy" / "fixtures" / "filter-cases.json"

# R10 says implementations must agree to within 1e-9; everything else is exact.
COORDINATE_TOLERANCE = 1e-9


def load_fixtures() -> dict[str, Any]:
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


def parse_now(fixtures: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(fixtures["now"].replace("Z", "+00:00")).astimezone(timezone.utc)


def expand_batch(case: dict[str, Any]) -> dict[str, Any]:
    """Build the batch a case describes, including the `generate` form."""
    raw = case["input"]
    if "generate" not in raw:
        return raw

    recipe = raw["generate"]
    template = dict(recipe["template"])
    prefix = template.pop("bssid_prefix")
    observations = []
    for index in range(recipe["count"]):
        observation = dict(template)
        tail = f"{index // 65536 % 256:02x}:{index // 256 % 256:02x}:{index % 256:02x}"
        observation["bssid"] = f"{prefix}:{tail}"
        observations.append(observation)
    return {**{k: v for k, v in raw.items() if k != "generate"}, "observations": observations}


class FilterFixturesTest(SimpleTestCase):
    """spec/privacy/fixtures/filter-cases.json, in full."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.fixtures = load_fixtures()
        cls.now = parse_now(cls.fixtures)

    def test_fixture_file_is_the_one_we_expect(self) -> None:
        self.assertTrue(FIXTURES_PATH.is_file(), f"fixtures not found at {FIXTURES_PATH}")
        self.assertEqual(self.fixtures["schema"], "wifishare.fixtures/1")
        self.assertTrue(self.fixtures["observation_cases"])
        self.assertTrue(self.fixtures["batch_cases"])

    def test_observation_cases(self) -> None:
        cases = self.fixtures["observation_cases"]
        for case in cases:
            with self.subTest(case=case["id"]):
                expected = case["expect"]
                decision = evaluate(case["input"], self.now)

                self.assertEqual(decision.action, expected["action"])
                if expected["action"] == "drop":
                    self.assertEqual(
                        decision.rule,
                        expected["rule"],
                        f"{case['id']} was dropped by {decision.rule}, "
                        f"fixture says {expected['rule']}",
                    )
                    self.assertIsNone(decision.normalized)
                else:
                    self.assertIsNone(decision.rule)
                    self._assert_normalized(case["id"], decision.normalized, expected["normalized"])

    def _assert_normalized(
        self, case_id: str, actual: dict[str, Any] | None, expected: dict[str, Any]
    ) -> None:
        self.assertIsNotNone(actual)
        assert actual is not None
        self.assertEqual(
            set(actual), set(expected), f"{case_id}: normalised fields differ from the fixture"
        )
        for field, value in expected.items():
            if field in ("lat", "lon"):
                self.assertAlmostEqual(
                    actual[field], value, delta=COORDINATE_TOLERANCE, msg=f"{case_id}.{field}"
                )
            else:
                self.assertEqual(actual[field], value, f"{case_id}.{field}")

    def test_batch_cases(self) -> None:
        for case in self.fixtures["batch_cases"]:
            with self.subTest(case=case["id"]):
                expected = case["expect"]
                decision = filter_batch(expand_batch(case), self.now)

                if expected.get("action") == "reject":
                    self.assertEqual(decision.action, "reject", case["id"])
                    self.assertEqual(decision.rule, expected["rule"], case["id"])
                    continue

                self.assertEqual(decision.action, "accept", f"{case['id']}: {decision.detail}")
                self.assertEqual(len(decision.observations), expected["count"], case["id"])
                if "kept_rssi" in expected:
                    self.assertEqual(
                        sorted(o["rssi"] for o in decision.observations),
                        sorted(expected["kept_rssi"]),
                        case["id"],
                    )

    def test_every_case_in_the_file_was_exercised(self) -> None:
        """A guard against a future fixture being silently skipped."""
        observation_ids = [case["id"] for case in self.fixtures["observation_cases"]]
        batch_ids = [case["id"] for case in self.fixtures["batch_cases"]]
        self.assertEqual(len(observation_ids), len(set(observation_ids)))
        self.assertEqual(len(batch_ids), len(set(batch_ids)))

        ran = 0
        for case in self.fixtures["observation_cases"]:
            evaluate(case["input"], self.now)
            ran += 1
        for case in self.fixtures["batch_cases"]:
            filter_batch(expand_batch(case), self.now)
            ran += 1
        self.assertEqual(ran, len(observation_ids) + len(batch_ids))
