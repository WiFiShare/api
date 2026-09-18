"""The geohash helpers, against the worked examples in spec/docs/geohash.md."""

from __future__ import annotations

import math

from django.test import SimpleTestCase

from core import geohash


class GeohashTest(SimpleTestCase):
    def test_piazza_maggiore_worked_example(self) -> None:
        lat, lon = 44.4938, 11.3426
        self.assertEqual(geohash.encode(lat, lon, 7), "srbj45g")
        self.assertEqual(geohash.encode(lat, lon, 5), "srbj4")
        self.assertEqual(geohash.encode(lat, lon, 3), "srb")
        self.assertEqual(geohash.encode(lat, lon, 2), "sr")

    def test_prefixes_nest(self) -> None:
        cell = geohash.encode(-33.8688, 151.2093, 7)
        for length in range(1, 7):
            self.assertTrue(cell.startswith(geohash.encode(-33.8688, 151.2093, length)))

    def test_a_geohash7_cell_is_about_153_by_109_metres_in_bologna(self) -> None:
        lat_lo, lat_hi, lon_lo, lon_hi = geohash.bounds("srbj45g")
        height = (lat_hi - lat_lo) * 111_320
        width = (lon_hi - lon_lo) * 111_320 * math.cos(math.radians(44.49))
        self.assertAlmostEqual(height, 153, delta=2)
        self.assertAlmostEqual(width, 109, delta=2)

    def test_centre_falls_inside_its_own_cell(self) -> None:
        for lat, lon in ((44.4938, 11.3426), (-22.9068, -43.1729), (0.0, 0.0), (89.9, 179.9)):
            cell = geohash.encode(lat, lon, 7)
            centre_lat, centre_lon = geohash.centre(cell)
            self.assertEqual(geohash.encode(centre_lat, centre_lon, 7), cell)

    def test_the_alphabet_excludes_a_i_l_and_o(self) -> None:
        for letter in "ailo":
            self.assertNotIn(letter, geohash.ALPHABET)

    def test_neighbours_are_eight_distinct_cells(self) -> None:
        around = geohash.neighbours("srbj4")
        self.assertEqual(len(around), 8)
        self.assertEqual(len(set(around)), 8)
        self.assertNotIn("srbj4", around)

    def test_a_bad_character_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            geohash.bounds("srbja")
