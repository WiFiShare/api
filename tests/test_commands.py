"""The management commands, end to end."""

from __future__ import annotations

import json
from datetime import datetime, time, timedelta, timezone
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from core.schemas import validate
from ingest.models import IngestKey, RawObservation
from networks.models import Network
from networks.publish import _evidence, aggregate, published_properties
from tests.helpers import batch, observation, seal_envelope, store_observation


class IssueIngestKeyTest(TestCase):
    def test_issues_a_usable_key(self) -> None:
        out = StringIO()
        call_command("issue_ingest_key", "--key-id", "2026q4", stdout=out)

        key = IngestKey.objects.get()
        self.assertEqual(key.key_id, "2026q4")
        self.assertEqual(key.not_after.isoformat(), "2026-12-31")
        self.assertEqual(len(bytes(key.private_key)), 32)
        self.assertIn(key.public_key, out.getvalue())
        self.assertNotIn(bytes(key.private_key).hex(), out.getvalue())

        response = self.client.post(
            "/v1/batches",
            data=json.dumps(seal_envelope(key, batch())),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)

    def test_refuses_to_overwrite_an_existing_key(self) -> None:
        from django.core.management.base import CommandError

        call_command("issue_ingest_key", "--key-id", "2026q4", stdout=StringIO())
        with self.assertRaises(CommandError):
            call_command("issue_ingest_key", "--key-id", "2026q4", stdout=StringIO())


class AggregateCommandTest(TestCase):
    def test_reports_what_it_did(self) -> None:
        # The command reads the wall clock, so the fixture is dated against it:
        # a UTC day is only consumable 8 days on (P9), so these are 9 and 10.
        today = datetime.now(timezone.utc).date()
        day_one = datetime.combine(today - timedelta(days=10), time(9), tzinfo=timezone.utc)
        day_two = datetime.combine(today - timedelta(days=9), time(14), tzinfo=timezone.utc)
        store_observation(bucket="bucket-a", observed_at=day_one)
        store_observation(bucket="bucket-b", observed_at=day_two)
        store_observation(bucket="bucket-c", observed_at=day_two)
        out = StringIO()

        call_command("aggregate", stdout=out)

        text = out.getvalue()
        self.assertIn("consumed 3 observations", text)
        self.assertIn("published 1", text)
        self.assertTrue(Network.objects.get().is_published)
        self.assertIsNotNone(RawObservation.objects.first().consumed_at)

    def test_it_leaves_a_day_that_has_not_closed_alone(self) -> None:
        today = datetime.now(timezone.utc).date()
        store_observation(
            bucket="bucket-a",
            observed_at=datetime.combine(today - timedelta(days=2), time(9), tzinfo=timezone.utc),
        )
        out = StringIO()

        call_command("aggregate", stdout=out)

        self.assertIn("consumed 0 observations", out.getvalue())
        self.assertIsNone(RawObservation.objects.get().consumed_at)


class SeedDemoTest(TestCase):
    def test_creates_clearly_fictional_published_networks(self) -> None:
        call_command("seed_demo", stdout=StringIO())

        networks = list(Network.objects.all())
        self.assertGreaterEqual(len(networks), 5)
        for network in networks:
            with self.subTest(ssid=network.ssid):
                self.assertIn("Demo", network.ssid)
                self.assertTrue(network.is_published)
                validate("network", published_properties(network))

    def test_lands_in_two_areas(self) -> None:
        call_command("seed_demo", stdout=StringIO())
        cells = {network.cell[:5] for network in Network.objects.all()}
        self.assertEqual(len(cells), 2)

    def test_is_idempotent(self) -> None:
        call_command("seed_demo", stdout=StringIO())
        first = Network.objects.count()
        call_command("seed_demo", stdout=StringIO())
        self.assertEqual(Network.objects.count(), first)

    def test_clear_removes_them(self) -> None:
        call_command("seed_demo", stdout=StringIO())
        call_command("seed_demo", "--clear", stdout=StringIO())
        self.assertEqual(Network.objects.count(), 0)

    def test_the_demo_area_renders_through_the_api(self) -> None:
        call_command("seed_demo", stdout=StringIO())
        cell5 = Network.objects.filter(ssid__contains="Biblioteca").get().cell[:5]

        response = self.client.get(f"/v1/areas/{cell5}")

        self.assertEqual(response.status_code, 200)
        validate("area", json.loads(response.content))


class SeedObservationsEndToEndTest(TestCase):
    """seed_demo --observations, aggregate, export_dump: the whole pipeline.

    Every other test drives one stage with a clock of its own choosing. This
    one runs the three commands an operator runs, on the wall clock, and
    asserts a network reaches the dump by being *aggregated* into existence
    rather than written there. It is the only test that fails if the storage,
    the P9 close window, the P1 threshold and the exporter stop agreeing.
    """

    def test_seeded_observations_reach_the_dump_through_aggregation(self) -> None:
        import tempfile
        from pathlib import Path

        call_command("seed_demo", "--observations", stdout=StringIO())

        # The seed writes observations and nothing else: no network exists yet.
        self.assertEqual(Network.objects.count(), 0)
        self.assertEqual(RawObservation.objects.count(), 15)
        self.assertTrue(all(row.consumed_at is None for row in RawObservation.objects.all()))

        call_command("aggregate", stdout=StringIO())

        networks = list(Network.objects.all())
        self.assertEqual(len(networks), 5)
        for network in networks:
            with self.subTest(ssid=network.ssid):
                self.assertIn("Demo", network.ssid)
                self.assertTrue(network.is_published)
                self.assertEqual(network.verification, Network.COMMUNITY)
                # P9 tallied two closed days, which is exactly P1's threshold.
                self.assertEqual(_evidence(network), (3, 3, 2))
                self.assertEqual(network.day_tallies.count(), 2)

        with tempfile.TemporaryDirectory() as tmp:
            call_command("export_dump", "--out", tmp, stdout=StringIO())

            index = json.loads((Path(tmp) / "index.json").read_text())
            validate("index", index)
            self.assertEqual(index["network_count"], 5)
            for cell5 in index["areas"]:
                path = Path(tmp) / "areas" / cell5[:2] / cell5[:3] / f"{cell5}.geojson"
                validate("area", json.loads(path.read_text()))
            for path in Path(tmp).rglob("*.geojson"):
                # P2, all the way through: no demo BSSID reaches the dump.
                self.assertNotIn("00:00:5e:00:53", path.read_text())

    def test_the_seeded_days_are_closed_whenever_this_runs(self) -> None:
        """The seed is useless if its dates are not consumable today."""
        call_command("seed_demo", "--observations", stdout=StringIO())

        today = datetime.now(timezone.utc).date()
        days = {
            row.observed_at.astimezone(timezone.utc).date()
            for row in RawObservation.objects.all()
        }

        self.assertEqual(len(days), 2)
        for day in days:
            self.assertGreaterEqual((today - day).days, 8)

    def test_re_seeding_before_aggregation_replaces_rather_than_doubles(self) -> None:
        call_command("seed_demo", "--observations", stdout=StringIO())
        call_command("seed_demo", "--observations", stdout=StringIO())

        self.assertEqual(RawObservation.objects.count(), 15)

    def test_clear_takes_the_observations_too(self) -> None:
        call_command("seed_demo", "--observations", stdout=StringIO())

        call_command("seed_demo", "--clear", stdout=StringIO())

        self.assertEqual(RawObservation.objects.count(), 0)

    def test_the_default_mode_still_writes_networks_directly(self) -> None:
        """The new mode is opt-in; nothing that depended on the old one moved."""
        call_command("seed_demo", stdout=StringIO())

        self.assertGreaterEqual(Network.objects.count(), 5)
        self.assertEqual(RawObservation.objects.count(), 0)


class EndToEndTest(TestCase):
    """A batch in, an area file out."""

    def test_ingest_aggregate_export(self) -> None:
        import tempfile
        from pathlib import Path

        call_command("issue_ingest_key", "--key-id", "2026q4", stdout=StringIO())
        key = IngestKey.objects.get()

        # Three contributors, two days: exactly what P1 asks for. The dates are
        # relative to the wall clock because R7 refuses anything over 7 days
        # old on the way in.
        now = datetime.now(timezone.utc)
        for index, (address, days_ago, hour) in enumerate(
            [("203.0.113.1", 2, 9), ("198.51.100.2", 1, 11), ("192.0.2.3", 1, 15)]
        ):
            observed = datetime.combine(
                (now - timedelta(days=days_ago)).date(), time(hour), tzinfo=timezone.utc
            )
            payload = batch(
                observation(
                    observed_at=observed.strftime("%Y-%m-%dT%H:00:00Z"), rssi=-55 - index
                )
            )
            response = self.client.post(
                "/v1/batches",
                data=json.dumps(seal_envelope(key, payload)),
                content_type="application/json",
                REMOTE_ADDR=address,
            )
            self.assertEqual(response.status_code, 202)

        # R7 lets a client upload for 7 days and P9 waits 8 for the day to
        # close, so nothing just ingested is ever consumable now. The command
        # takes no clock, so this step calls what the command calls.
        aggregate(now + timedelta(days=10))

        with tempfile.TemporaryDirectory() as tmp:
            call_command("export_dump", "--out", tmp, stdout=StringIO())
            index = json.loads((Path(tmp) / "index.json").read_text())
            self.assertEqual(index["network_count"], 1)
            validate("index", index)
            cell5 = next(iter(index["areas"]))
            area_file = Path(tmp) / "areas" / cell5[:2] / cell5[:3] / f"{cell5}.geojson"
            document = json.loads(area_file.read_text())
            validate("area", document)
            self.assertNotIn("b8:27:eb:11:22:33", json.dumps(document))
