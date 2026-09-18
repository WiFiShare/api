"""GET /v1/areas/{geohash5}."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from django.test import TestCase

from core.schemas import validate
from networks.models import Network
from networks.publish import aggregate
from tests.helpers import publishable

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
BSSID = "b8:27:eb:11:22:33"


class AreaTest(TestCase):
    def setUp(self) -> None:
        publishable()
        aggregate(NOW)
        self.network = Network.objects.get()
        self.cell5 = self.network.cell[:5]

    def test_returns_geojson_matching_the_area_schema(self) -> None:
        response = self.client.get(f"/v1/areas/{self.cell5}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/geo+json")
        document = json.loads(response.content)
        validate("area", document)
        self.assertEqual(document["type"], "FeatureCollection")
        self.assertEqual(document["cell"], self.cell5)
        self.assertEqual(document["license"], "ODbL-1.0")
        self.assertEqual(document["attribution"], "WiFiShare contributors")
        self.assertEqual(len(document["features"]), 1)

    def test_geometry_is_lon_lat(self) -> None:
        document = json.loads(self.client.get(f"/v1/areas/{self.cell5}").content)
        coordinates = document["features"][0]["geometry"]["coordinates"]
        self.assertAlmostEqual(coordinates[0], self.network.lon)
        self.assertAlmostEqual(coordinates[1], self.network.lat)

    def test_no_bssid_anywhere_in_the_response(self) -> None:
        body = self.client.get(f"/v1/areas/{self.cell5}").content.decode()
        self.assertNotIn(BSSID, body)
        self.assertNotIn("bssid", body)

    def test_etag_and_cache_control(self) -> None:
        response = self.client.get(f"/v1/areas/{self.cell5}")
        etag = response["ETag"]
        self.assertTrue(etag.startswith('"'))
        self.assertIn("max-age=", response["Cache-Control"])

        repeat = self.client.get(f"/v1/areas/{self.cell5}", headers={"if-none-match": etag})
        self.assertEqual(repeat.status_code, 304)
        self.assertEqual(repeat["ETag"], etag)

    def test_empty_area_is_404(self) -> None:
        self.assertEqual(self.client.get("/v1/areas/u0nzs").status_code, 404)

    def test_unpublished_network_is_not_returned(self) -> None:
        self.network.unpublish("moderator")
        self.assertEqual(self.client.get(f"/v1/areas/{self.cell5}").status_code, 404)

    def test_malformed_cell_is_404(self) -> None:
        # `a`, `i`, `l` and `o` are not geohash characters.
        self.assertEqual(self.client.get("/v1/areas/aaaaa").status_code, 404)
        self.assertEqual(self.client.get("/v1/areas/srbj").status_code, 404)

    def test_there_is_no_endpoint_that_resolves_a_bssid(self) -> None:
        for path in (
            f"/v1/networks/{BSSID}",
            f"/v1/bssids/{BSSID}",
            f"/v1/networks/{self.network.public_id}",
        ):
            self.assertIn(self.client.get(path).status_code, (404, 405))
