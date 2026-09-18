"""The management commands, end to end."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from core.schemas import validate
from ingest.models import IngestKey, RawObservation
from networks.models import Network
from networks.publish import published_properties
from tests.helpers import batch, observation, publishable, seal_envelope

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)


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
        publishable()
        out = StringIO()

        call_command("aggregate", stdout=out)

        text = out.getvalue()
        self.assertIn("consumed 3 observations", text)
        self.assertIn("published 1", text)
        self.assertTrue(Network.objects.get().is_published)
        self.assertIsNotNone(RawObservation.objects.first().consumed_at)


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


class EndToEndTest(TestCase):
    """A batch in, an area file out."""

    def test_ingest_aggregate_export(self) -> None:
        import tempfile
        from pathlib import Path

        call_command("issue_ingest_key", "--key-id", "2026q4", stdout=StringIO())
        key = IngestKey.objects.get()

        # Three contributors, two days: exactly what P1 asks for.
        for index, (address, day, hour) in enumerate(
            [("203.0.113.1", 16, 9), ("198.51.100.2", 17, 11), ("192.0.2.3", 17, 15)]
        ):
            payload = batch(
                observation(observed_at=f"2026-09-{day}T{hour:02d}:00:00Z", rssi=-55 - index)
            )
            response = self.client.post(
                "/v1/batches",
                data=json.dumps(seal_envelope(key, payload)),
                content_type="application/json",
                REMOTE_ADDR=address,
            )
            self.assertEqual(response.status_code, 202)

        call_command("aggregate", stdout=StringIO())

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
