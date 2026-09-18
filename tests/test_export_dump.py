"""`manage.py export_dump --out DIR`: the public dump's layout and shape."""

from __future__ import annotations

import json
import tempfile
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase

from core.schemas import validate
from dump.export import EMPTY_INDEX, export
from networks.models import Network, NetworkBssid
from networks.publish import aggregate
from tests.helpers import publishable, store_observation

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
BSSID = "b8:27:eb:11:22:33"


class ExportTest(TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _seed_two_areas(self) -> None:
        # Bologna.
        publishable(bssid=BSSID)
        # Lisbon, a different geohash-2 prefix.
        for bucket, day in (("a", 16), ("b", 17), ("c", 17)):
            store_observation(
                bssid="b8:27:eb:44:55:66",
                ssid="Praca WiFi",
                lat=38.7100,
                lon=-9.1400,
                bucket=bucket,
                observed_at=datetime(2026, 9, day, 10, tzinfo=timezone.utc),
            )
        aggregate(NOW)

    def test_writes_areas_under_gh2_gh3_gh5(self) -> None:
        self._seed_two_areas()

        result = export(self.out, generated=date(2026, 9, 18))

        self.assertEqual(result.area_count, 2)
        self.assertEqual(result.network_count, 2)
        for path in result.files:
            relative = path.relative_to(self.out)
            parts = relative.parts
            self.assertEqual(parts[0], "areas")
            gh2, gh3, filename = parts[1], parts[2], parts[3]
            cell5 = filename.removesuffix(".geojson")
            self.assertEqual(len(gh2), 2)
            self.assertEqual(len(gh3), 3)
            self.assertEqual(len(cell5), 5)
            self.assertTrue(cell5.startswith(gh3))
            self.assertTrue(gh3.startswith(gh2))

    def test_bologna_lands_on_the_documented_path(self) -> None:
        publishable(bssid=BSSID)
        aggregate(NOW)
        export(self.out)
        self.assertTrue((self.out / "areas" / "sr" / "srb" / "srbj4.geojson").is_file())

    def test_every_file_validates_against_the_area_schema(self) -> None:
        self._seed_two_areas()
        result = export(self.out, generated=date(2026, 9, 18))

        self.assertTrue(result.files)
        for path in result.files:
            with self.subTest(path=str(path)):
                document = json.loads(path.read_text(encoding="utf-8"))
                validate("area", document)
                self.assertEqual(document["schema"], "wifishare.area/1")
                self.assertEqual(document["generated"], "2026-09-18")

    def test_index_validates_against_the_index_schema(self) -> None:
        self._seed_two_areas()
        export(self.out, generated=date(2026, 9, 18))

        index = json.loads((self.out / "index.json").read_text(encoding="utf-8"))

        validate("index", index)
        self.assertEqual(set(index), set(EMPTY_INDEX))
        self.assertEqual(index["schema"], "wifishare.index/1")
        self.assertEqual(index["generated"], "2026-09-18")
        self.assertEqual(index["area_count"], 2)
        self.assertEqual(index["network_count"], 2)

    def test_every_indexed_area_has_the_file_its_geohash_implies(self) -> None:
        self._seed_two_areas()
        export(self.out, generated=date(2026, 9, 18))

        index = json.loads((self.out / "index.json").read_text(encoding="utf-8"))

        self.assertEqual(len(index["areas"]), 2)
        for cell5, entry in index["areas"].items():
            with self.subTest(cell=cell5):
                self.assertRegex(cell5, r"^[0-9b-hjkmnp-z]{5}$")
                path = self.out / "areas" / cell5[:2] / cell5[:3] / f"{cell5}.geojson"
                self.assertTrue(path.is_file())
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(entry["network_count"], len(document["features"]))
                self.assertEqual(entry["updated"], "2026-09-18")

    def test_an_empty_dump_matches_the_documented_empty_index(self) -> None:
        export(self.out)
        index = json.loads((self.out / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index, EMPTY_INDEX)
        validate("index", index)

    def test_unpublished_networks_are_not_exported(self) -> None:
        publishable(bssid=BSSID)
        aggregate(NOW)
        Network.objects.get().unpublish("moderator")

        result = export(self.out)

        self.assertEqual(result.network_count, 0)
        self.assertEqual(result.files, [])

    def test_no_community_bssid_appears_anywhere_in_the_dump(self) -> None:
        self._seed_two_areas()
        export(self.out)
        for path in self.out.rglob("*.geojson"):
            body = path.read_text(encoding="utf-8")
            self.assertNotIn(BSSID, body)
            self.assertNotIn("bssid", body)

    def test_the_api_and_the_dump_agree(self) -> None:
        publishable(bssid=BSSID)
        aggregate(NOW)
        network = Network.objects.get()
        export(self.out, generated=date.today())

        from_file = json.loads(
            (self.out / "areas" / "sr" / "srb" / f"{network.cell[:5]}.geojson").read_text()
        )
        from_api = json.loads(self.client.get(f"/v1/areas/{network.cell[:5]}").content)

        self.assertEqual(from_file, from_api)

    def test_management_command(self) -> None:
        publishable(bssid=BSSID)
        aggregate(NOW)
        out = StringIO()

        call_command("export_dump", "--out", str(self.out), "--generated", "2026-09-18", stdout=out)

        self.assertIn("1 networks in 1 areas", out.getvalue())
        self.assertTrue((self.out / "index.json").is_file())

    def test_owner_verified_network_is_exported_with_its_bssids(self) -> None:
        network = Network.objects.create(
            ssid="Bar Centrale",
            security="shared",
            verification=Network.OWNER_VERIFIED,
            lat=44.49381,
            lon=11.34268,
            cell="srbj45g",
            first_seen=date(2026, 9, 1),
            last_seen=date(2026, 9, 17),
            venue_name="Bar Centrale",
            publish_credential=True,
            credential_type="wpa2-psk",
            credential_secret="ospiti2026",
            is_published=True,
        )
        NetworkBssid.objects.create(network=network, bssid=BSSID)

        export(self.out, generated=date(2026, 9, 18))

        document = json.loads((self.out / "areas" / "sr" / "srb" / "srbj4.geojson").read_text())
        validate("area", document)
        properties = document["features"][0]["properties"]
        self.assertEqual(properties["bssids"], [BSSID])
        self.assertEqual(properties["precision_m"], 10)
