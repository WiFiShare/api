"""Publish rules P1-P10, one test class per rule."""

from __future__ import annotations

import json
from datetime import date, datetime, time, timedelta, timezone

from django.test import TestCase

from core import geohash
from ingest.models import RawObservation
from networks.models import (
    Claim,
    Network,
    NetworkBssid,
    NetworkDayTally,
    OptOut,
    Report,
    RetiredPublicId,
)
from networks.publish import (
    MOBILE_THRESHOLD_M,
    _evidence,
    aggregate,
    compact_tallies,
    optout_hmac,
    published_feature,
    published_properties,
    purge,
)
from tests.helpers import publishable, store_observation

NOW = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)
BSSID = "b8:27:eb:11:22:33"


class P1ThresholdTest(TestCase):
    def test_three_observations_three_buckets_two_days_publish(self) -> None:
        publishable()
        aggregate(NOW)
        network = Network.objects.get()
        self.assertTrue(network.is_published)
        self.assertEqual(network.verification, Network.COMMUNITY)

    def test_one_contributor_walking_past_three_times_is_not_enough(self) -> None:
        for hour, day in ((9, 16), (14, 17), (15, 17)):
            store_observation(
                bucket="same-bucket",
                observed_at=datetime(2026, 9, day, hour, tzinfo=timezone.utc),
            )
        aggregate(NOW)
        network = Network.objects.get()
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "threshold")

    def test_three_buckets_on_a_single_day_is_not_enough(self) -> None:
        for bucket in ("a", "b", "c"):
            store_observation(
                bucket=bucket, observed_at=datetime(2026, 9, 17, 14, tzinfo=timezone.utc)
            )
        aggregate(NOW)
        self.assertFalse(Network.objects.get().is_published)

    def test_two_observations_are_not_enough(self) -> None:
        store_observation(bucket="a", observed_at=datetime(2026, 9, 16, 9, tzinfo=timezone.utc))
        store_observation(bucket="b", observed_at=datetime(2026, 9, 17, 9, tzinfo=timezone.utc))
        aggregate(NOW)
        self.assertFalse(Network.objects.get().is_published)


class P2CommunityPrecisionTest(TestCase):
    def setUp(self) -> None:
        publishable()
        aggregate(NOW)
        self.network = Network.objects.get()

    def test_position_is_the_centre_of_a_geohash7_cell(self) -> None:
        self.assertEqual(len(self.network.cell), 7)
        centre_lat, centre_lon = geohash.centre(self.network.cell)
        self.assertAlmostEqual(self.network.lat, centre_lat, places=9)
        self.assertAlmostEqual(self.network.lon, centre_lon, places=9)

    def test_precision_is_150_m(self) -> None:
        self.assertEqual(published_properties(self.network)["precision_m"], 150)

    def test_dates_are_day_precision(self) -> None:
        properties = published_properties(self.network)
        self.assertEqual(properties["first_seen"], "2026-09-16")
        self.assertEqual(properties["last_seen"], "2026-09-17")

    def test_report_counts_are_published(self) -> None:
        Report.objects.create(network=self.network, kind="works")
        Report.objects.create(network=self.network, kind="works")
        Report.objects.create(network=self.network, kind="fails")
        Report.objects.create(network=self.network, kind="not_free")
        self.assertEqual(
            published_properties(self.network)["reports"], {"works": 2, "fails": 1}
        )

    def test_a_community_bssid_never_reaches_the_published_representation(self) -> None:
        """The negative test P2 exists for."""
        self.assertEqual(self.network.bssids.get().bssid, BSSID)

        properties = published_properties(self.network)
        feature = published_feature(self.network)
        serialised = json.dumps(feature)

        self.assertNotIn("bssids", properties)
        self.assertNotIn("bssid", properties)
        self.assertNotIn(BSSID, serialised)
        self.assertNotIn(BSSID.replace(":", ""), serialised)
        self.assertNotIn("venue", properties)
        self.assertNotIn("credential", properties)

    def test_published_position_is_not_the_measured_position(self) -> None:
        # Every observation was at 44.4938, 11.3427; the published point is the
        # cell centre, which is a different number.
        self.assertNotEqual(self.network.lat, 44.4938)
        self.assertNotEqual(self.network.lon, 11.3427)


class P3OwnerVerifiedTest(TestCase):
    def setUp(self) -> None:
        publishable()
        aggregate(NOW)
        self.network = Network.objects.get()
        self.network.verification = Network.OWNER_VERIFIED
        self.network.venue_name = "Bar Centrale"
        self.network.venue_kind = "cafe"
        self.network.publish_credential = True
        self.network.credential_type = "wpa2-psk"
        self.network.credential_secret = "hunter2"
        self.network.security = "shared"
        self.network.lat, self.network.lon = 44.49381, 11.34268
        self.network.save()
        Claim.objects.create(
            ssid=self.network.ssid,
            venue_name="Bar Centrale",
            venue_lat=44.49381,
            venue_lon=11.34268,
            challenge_code="ws-abc123",
            expires_at=NOW + timedelta(days=1),
            status=Claim.VERIFIED,
            verified_at=NOW,
            network=self.network,
        )

    def test_bssids_venue_and_credential_are_published(self) -> None:
        properties = published_properties(self.network)
        self.assertEqual(properties["bssids"], [BSSID])
        self.assertEqual(properties["venue"], {"name": "Bar Centrale", "kind": "cafe"})
        self.assertEqual(properties["credential"]["type"], "wpa2-psk")
        self.assertEqual(properties["credential"]["secret"], "hunter2")
        self.assertEqual(properties["precision_m"], 10)

    def test_credential_stays_unpublished_when_the_owner_said_so(self) -> None:
        self.network.publish_credential = False
        self.network.save()
        self.assertNotIn("credential", published_properties(self.network))

    def test_position_is_kept_at_five_decimals_by_aggregation(self) -> None:
        aggregate(NOW + timedelta(hours=1))
        network = Network.objects.get()
        self.assertAlmostEqual(network.lat, 44.49381, places=9)
        self.assertAlmostEqual(network.lon, 11.34268, places=9)
        self.assertTrue(network.is_published)


class P4MobileTest(TestCase):
    def test_a_network_spanning_more_than_a_kilometre_is_excluded(self) -> None:
        day_one = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
        day_two = datetime(2026, 9, 17, 14, tzinfo=timezone.utc)
        store_observation(bucket="a", observed_at=day_one, lat=44.4938, lon=11.3427)
        store_observation(bucket="b", observed_at=day_two, lat=44.4938, lon=11.3427)
        # About 2.2 km north.
        store_observation(bucket="c", observed_at=day_two, lat=44.5138, lon=11.3427)

        aggregate(NOW)

        network = Network.objects.get()
        self.assertTrue(network.is_mobile)
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "mobile")

    def test_a_stationary_network_is_not_mobile(self) -> None:
        publishable()
        aggregate(NOW)
        network = Network.objects.get()
        self.assertFalse(network.is_mobile)
        self.assertTrue(network.is_published)

    def test_the_threshold_is_one_kilometre(self) -> None:
        self.assertEqual(MOBILE_THRESHOLD_M, 1_000.0)

    def test_mobile_is_checked_before_the_threshold(self) -> None:
        """P4 comes before P1, so a mobile network is never merely 'pending'."""
        store_observation(bucket="a", lat=44.4938, lon=11.3427)
        store_observation(bucket="b", lat=44.6000, lon=11.3427)
        aggregate(NOW)
        self.assertEqual(Network.objects.get().unpublished_reason, "mobile")


class P5OptOutTest(TestCase):
    def test_an_opted_out_bssid_is_never_published(self) -> None:
        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        publishable()

        aggregate(NOW)

        self.assertEqual(Network.objects.count(), 0)
        self.assertEqual(RawObservation.objects.count(), 0)

    def test_the_list_holds_an_hmac_and_not_the_bssid(self) -> None:
        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        row = OptOut.objects.get()
        self.assertNotIn(BSSID, str(list(OptOut.objects.values())))
        self.assertEqual(len(row.bssid_hmac), 64)
        self.assertNotEqual(row.bssid_hmac, BSSID)

    def test_an_already_published_network_is_withdrawn(self) -> None:
        publishable()
        aggregate(NOW)
        self.assertTrue(Network.objects.get().is_published)

        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        aggregate(NOW + timedelta(hours=1))

        network = Network.objects.get()
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "opt-out")

    def test_ssid_plus_cell_opt_out_also_blocks(self) -> None:
        publishable()
        aggregate(NOW)
        network = Network.objects.get()
        OptOut.objects.create(ssid=network.ssid, cell=network.cell[:5])

        aggregate(NOW + timedelta(hours=1))

        self.assertFalse(Network.objects.get().is_published)


class P6UnpublishTest(TestCase):
    def _published(self) -> Network:
        publishable()
        aggregate(NOW)
        return Network.objects.get()

    def test_twelve_months_without_a_sighting(self) -> None:
        network = self._published()
        aggregate(NOW + timedelta(days=366))
        network.refresh_from_db()
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "stale")

    def test_eleven_months_is_still_published(self) -> None:
        network = self._published()
        aggregate(NOW + timedelta(days=330))
        network.refresh_from_db()
        self.assertTrue(network.is_published)

    def test_three_private_or_gone_reports(self) -> None:
        network = self._published()
        Report.objects.create(network=network, kind="private")
        Report.objects.create(network=network, kind="gone")
        Report.objects.create(network=network, kind="gone")

        aggregate(NOW + timedelta(hours=1))

        network.refresh_from_db()
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "reports")

    def test_two_reports_do_not_unpublish(self) -> None:
        network = self._published()
        Report.objects.create(network=network, kind="private")
        Report.objects.create(network=network, kind="gone")
        aggregate(NOW + timedelta(hours=1))
        network.refresh_from_db()
        self.assertTrue(network.is_published)

    def test_works_and_fails_reports_never_unpublish(self) -> None:
        network = self._published()
        for _ in range(5):
            Report.objects.create(network=network, kind="fails")
        aggregate(NOW + timedelta(hours=1))
        network.refresh_from_db()
        self.assertTrue(network.is_published)


class P8PublicIdTest(TestCase):
    def test_id_is_twelve_base32_characters(self) -> None:
        publishable()
        aggregate(NOW)
        self.assertRegex(Network.objects.get().public_id, r"^[a-z2-7]{12}$")

    def test_id_is_not_derived_from_the_bssid_ssid_or_position(self) -> None:
        ids = set()
        for index in range(8):
            RawObservation.objects.all().delete()
            Network.objects.all().delete()
            publishable(bssid=f"b8:27:eb:11:22:{index:02x}")
            aggregate(NOW)
            ids.add(Network.objects.get().public_id)
        # Identical SSID and position every time; the ids must still differ.
        self.assertEqual(len(ids), 8)

    def test_a_retired_id_is_remembered_and_not_reused(self) -> None:
        publishable()
        aggregate(NOW)
        network = Network.objects.get()
        retired = network.public_id

        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        aggregate(NOW + timedelta(hours=1))

        self.assertTrue(RetiredPublicId.objects.filter(public_id=retired).exists())
        from networks.models import new_public_id

        self.assertNotEqual(new_public_id(), retired)


class P9DayTallyTest(TestCase):
    """P9: aggregation tallies closed UTC days, and P1 reads the tally.

    A day is closed 8 days on, past the window R7 gives a client to upload, so
    nothing belonging to it can still arrive and it is tallied once and never
    revised. The tally holds a day, a count of distinct rate-limit buckets seen
    in it and a count of observations. Never a bucket value, and never a
    comparison of buckets across days: the daily salt is deleted within 24
    hours, so a bucket is day-scoped by construction.

    NOW is 2026-09-25, which is the first day the fixture's 09-16 and 09-17 are
    both closed.
    """

    def _tally(self) -> list[tuple[date, int, int]]:
        return [
            (row.day, row.bucket_count, row.observation_count)
            for row in NetworkDayTally.objects.order_by("day")
        ]

    def test_a_third_contributor_months_later_still_publishes(self) -> None:
        """The bug P9 fixes: the evidence must outlive the observations.

        Two contributors on two days, then P7 deletes the raw rows, then a
        third contributor turns up three months on. Counting over the raw rows
        this network could never be published, because the first two sightings
        are gone by then. Counting over the tally, it is.
        """
        store_observation(
            bucket="bucket-a", observed_at=datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
        )
        store_observation(
            bucket="bucket-b", observed_at=datetime(2026, 9, 17, 14, tzinfo=timezone.utc)
        )
        aggregate(NOW)
        network = Network.objects.get()
        self.assertFalse(network.is_published)

        purge(NOW + timedelta(days=2))  # P7, a day after the run that consumed them
        self.assertEqual(RawObservation.objects.count(), 0)
        self.assertEqual(NetworkDayTally.objects.count(), 2)

        store_observation(
            bucket="bucket-c", observed_at=datetime(2026, 12, 16, 18, tzinfo=timezone.utc)
        )
        aggregate(datetime(2026, 12, 24, 12, tzinfo=timezone.utc))  # 12-16 closes on 12-24

        network.refresh_from_db()
        self.assertTrue(network.is_published)
        self.assertEqual(network.unpublished_reason, "")
        self.assertEqual(
            self._tally(),
            [
                (date(2026, 9, 16), 1, 1),
                (date(2026, 9, 17), 1, 1),
                (date(2026, 12, 16), 1, 1),
            ],
        )

    def test_a_day_is_counted_once_however_often_aggregation_runs(self) -> None:
        publishable()
        aggregate(NOW)
        first = self._tally()
        self.assertEqual(first, [(date(2026, 9, 16), 1, 1), (date(2026, 9, 17), 2, 2)])

        for hours in (1, 2, 6, 24, 240):
            aggregate(NOW + timedelta(hours=hours))

        self.assertEqual(self._tally(), first)
        self.assertEqual(NetworkDayTally.objects.count(), 2)
        self.assertEqual(Network.objects.get().observation_count, 3)

    def test_a_day_is_consumed_eight_days_on_and_not_a_moment_sooner(self) -> None:
        """P9's boundary. R7 gives a client 7 days to upload; day 8 is safe."""
        store_observation(
            bucket="bucket-a", observed_at=datetime(2026, 9, 17, 9, tzinfo=timezone.utc)
        )

        aggregate(datetime(2026, 9, 24, 23, 59, tzinfo=timezone.utc))  # D+7, still open

        self.assertEqual(NetworkDayTally.objects.count(), 0)
        self.assertEqual(Network.objects.count(), 0)
        self.assertIsNone(RawObservation.objects.get().consumed_at)

        aggregate(datetime(2026, 9, 25, 0, 0, tzinfo=timezone.utc))  # D+8, closed

        self.assertEqual(self._tally(), [(date(2026, 9, 17), 1, 1)])
        self.assertIsNotNone(RawObservation.objects.get().consumed_at)

    def test_a_day_still_open_cannot_complete_the_threshold(self) -> None:
        store_observation(
            bucket="bucket-a", observed_at=datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
        )
        store_observation(
            bucket="bucket-b", observed_at=datetime(2026, 9, 17, 14, tzinfo=timezone.utc)
        )
        store_observation(
            bucket="bucket-c", observed_at=datetime(2026, 9, 18, 10, tzinfo=timezone.utc)
        )

        aggregate(NOW)  # 09-18 does not close until 09-26
        self.assertFalse(Network.objects.get().is_published)

        aggregate(datetime(2026, 9, 26, 0, 30, tzinfo=timezone.utc))
        self.assertTrue(Network.objects.get().is_published)

    def test_an_opt_out_takes_the_tally_with_everything_else(self) -> None:
        """P5: an opted-out network keeps no evidence either."""
        publishable()
        aggregate(NOW)
        self.assertEqual(NetworkDayTally.objects.count(), 2)

        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        aggregate(NOW + timedelta(hours=1))

        network = Network.objects.get()
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "opt-out")
        self.assertEqual(NetworkDayTally.objects.count(), 0)

    def test_one_contributor_walking_past_never_reaches_three_buckets(self) -> None:
        """Three sightings, two days, one bucket per day: two contributor-days."""
        for day, hour in ((16, 9), (17, 11), (17, 15)):
            store_observation(
                bucket="same-bucket", observed_at=datetime(2026, 9, day, hour, tzinfo=timezone.utc)
            )

        aggregate(NOW)

        network = Network.objects.get()
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "threshold")
        self.assertEqual(self._tally(), [(date(2026, 9, 16), 1, 1), (date(2026, 9, 17), 1, 2)])

    def test_a_contributor_day_is_the_finest_thing_the_tally_knows(self) -> None:
        """Pinned because it looks like a hole and is in fact the design.

        The salt rotates every UTC day and is deleted within 24 hours, so one
        person seen on three days produces three unrelated bucket values. No
        part of this system can tell that from three people, and P9 does not
        try: publish-rules.md says "distinct buckets has only ever meant
        distinct contributor-days". Three sightings on three days are three
        contributor-days, whoever made them, and they publish.
        """
        for day in (15, 16, 17):
            store_observation(
                bucket=f"salt-of-{day}-then-thrown-away",
                observed_at=datetime(2026, 9, day, 9, tzinfo=timezone.utc),
            )

        aggregate(NOW)

        self.assertEqual(
            self._tally(),
            [(date(2026, 9, 15), 1, 1), (date(2026, 9, 16), 1, 1), (date(2026, 9, 17), 1, 1)],
        )
        self.assertTrue(Network.objects.get().is_published)

    def test_the_tally_keeps_no_bucket_value(self) -> None:
        """The negative test P9 exists for, in the shape of P2's."""
        publishable()
        aggregate(NOW)

        stored = str(list(NetworkDayTally.objects.values()))

        for bucket in ("bucket-a", "bucket-b", "bucket-c"):
            self.assertNotIn(bucket, stored)
        self.assertEqual(
            sorted(NetworkDayTally.objects.values()[0]),
            [
                "bucket_count",
                "created_at",
                "day",
                "day_count",
                "id",
                "network_id",
                "observation_count",
            ],
        )

    def test_two_bssids_of_one_network_share_its_days(self) -> None:
        network = Network.objects.create(ssid="Test Open Net")
        NetworkBssid.objects.create(network=network, bssid=BSSID)
        NetworkBssid.objects.create(network=network, bssid="b8:27:eb:44:55:66")
        store_observation(
            bssid=BSSID,
            bucket="bucket-a",
            observed_at=datetime(2026, 9, 17, 9, tzinfo=timezone.utc),
        )
        store_observation(
            bssid="b8:27:eb:44:55:66",
            bucket="bucket-b",
            observed_at=datetime(2026, 9, 17, 11, tzinfo=timezone.utc),
        )

        aggregate(NOW)

        self.assertEqual(self._tally(), [(date(2026, 9, 17), 2, 2)])


class P10CompactionTest(TestCase):
    """P10: rows older than 90 days collapse, and P1 cannot tell the difference.

    NOW is 2026-09-25, so the cutoff is 2026-06-27: the March days below are
    well past it, and 09-16 is well inside it.
    """

    def _seen(self, day: date, buckets: list[str]) -> None:
        for index, bucket in enumerate(buckets):
            store_observation(
                bucket=bucket,
                observed_at=datetime.combine(day, time(9 + index), tzinfo=timezone.utc),
            )

    def test_p1_reads_the_same_three_figures_after_compaction(self) -> None:
        self._seen(date(2026, 3, 1), ["bucket-a", "bucket-b"])
        self._seen(date(2026, 3, 2), ["bucket-c"])
        aggregate(NOW)
        network = Network.objects.get()
        self.assertTrue(network.is_published)
        before = _evidence(network)
        self.assertEqual(before, (3, 3, 2))

        removed = compact_tallies(NOW)

        self.assertEqual(removed, 1)
        network.refresh_from_db()
        self.assertEqual(_evidence(network), before)
        row = NetworkDayTally.objects.get()
        self.assertEqual(
            (row.day, row.day_count, row.bucket_count, row.observation_count),
            (date(2026, 3, 1), 2, 3, 3),
        )
        self.assertTrue(row.is_compacted)

    def test_the_threshold_can_be_crossed_on_a_compacted_row_alone(self) -> None:
        """The verdict, not just the figures: the gate opens on the summary."""
        self._seen(date(2026, 3, 1), ["bucket-a", "bucket-b"])
        self._seen(date(2026, 3, 2), ["bucket-c"])
        aggregate(NOW)
        compact_tallies(NOW)
        self.assertEqual(NetworkDayTally.objects.count(), 1)

        # Put the network back at the entry gate. One compacted row is all the
        # evidence left, and it has to be enough.
        network = Network.objects.get()
        network.is_published = False
        network.unpublished_reason = "threshold"
        network.save()

        aggregate(NOW + timedelta(hours=1))

        self.assertTrue(Network.objects.get().is_published)

    def test_a_network_still_short_of_the_threshold_stays_short_of_it(self) -> None:
        self._seen(date(2026, 3, 1), ["bucket-a"])
        self._seen(date(2026, 3, 2), ["bucket-b"])
        aggregate(NOW)
        network = Network.objects.get()
        before = _evidence(network)
        self.assertEqual(before, (2, 2, 2))

        compact_tallies(NOW)

        network.refresh_from_db()
        self.assertEqual(_evidence(network), before)
        self.assertFalse(network.is_published)
        self.assertEqual(network.unpublished_reason, "threshold")

    def test_only_rows_older_than_ninety_days_are_compacted(self) -> None:
        self._seen(date(2026, 3, 1), ["bucket-a"])
        self._seen(date(2026, 3, 2), ["bucket-b"])
        self._seen(date(2026, 9, 16), ["bucket-c"])
        aggregate(NOW)
        self.assertEqual(NetworkDayTally.objects.count(), 3)

        self.assertEqual(compact_tallies(NOW), 1)

        self.assertEqual(
            [(row.day, row.day_count) for row in NetworkDayTally.objects.order_by("day")],
            [(date(2026, 3, 1), 2), (date(2026, 9, 16), 1)],
        )
        self.assertEqual(compact_tallies(NOW), 0)  # nothing left to collapse

    def test_which_days_a_network_was_seen_on_is_what_goes(self) -> None:
        for day in (date(2026, 3, 1), date(2026, 3, 5), date(2026, 3, 9)):
            self._seen(day, [f"bucket-{day.isoformat()}"])
        aggregate(NOW)

        compact_tallies(NOW)

        row = NetworkDayTally.objects.get()
        self.assertEqual((row.day, row.day_count), (date(2026, 3, 1), 3))
        self.assertFalse(NetworkDayTally.objects.filter(day=date(2026, 3, 5)).exists())
        self.assertFalse(NetworkDayTally.objects.filter(day=date(2026, 3, 9)).exists())

    def test_a_later_compaction_folds_in_the_rows_that_have_since_aged(self) -> None:
        self._seen(date(2026, 3, 1), ["bucket-a"])
        self._seen(date(2026, 3, 2), ["bucket-b"])
        self._seen(date(2026, 9, 16), ["bucket-c"])
        aggregate(NOW)
        compact_tallies(NOW)

        # Three months on, 09-16 is older than 90 days too.
        self.assertEqual(compact_tallies(NOW + timedelta(days=100)), 1)

        row = NetworkDayTally.objects.get()
        self.assertEqual(
            (row.day, row.day_count, row.bucket_count, row.observation_count),
            (date(2026, 3, 1), 3, 3, 3),
        )
        self.assertEqual(_evidence(Network.objects.get()), (3, 3, 3))


class OrderingTest(TestCase):
    """publish-rules.md: opt-out, then mobile, then threshold, then precision."""

    def test_opt_out_beats_a_mobile_network(self) -> None:
        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        store_observation(bucket="a", lat=44.4938, lon=11.3427)
        store_observation(bucket="b", lat=44.6000, lon=11.3427)

        aggregate(NOW)

        self.assertEqual(Network.objects.count(), 0)

    def test_mobile_beats_the_threshold(self) -> None:
        store_observation(bucket="a", lat=44.4938, lon=11.3427)
        aggregate(NOW)
        self.assertEqual(Network.objects.get().unpublished_reason, "threshold")

        store_observation(bucket="b", lat=44.6000, lon=11.3427)
        aggregate(NOW + timedelta(hours=1))
        self.assertEqual(Network.objects.get().unpublished_reason, "mobile")


class WeightedCentroidTest(TestCase):
    def test_the_stronger_signal_pulls_the_centroid(self) -> None:
        day_one = datetime(2026, 9, 16, 9, tzinfo=timezone.utc)
        day_two = datetime(2026, 9, 17, 14, tzinfo=timezone.utc)
        store_observation(bucket="a", observed_at=day_one, lat=44.4900, lon=11.3400, rssi=-90)
        store_observation(bucket="b", observed_at=day_two, lat=44.4900, lon=11.3400, rssi=-90)
        store_observation(bucket="c", observed_at=day_two, lat=44.5000, lon=11.3400, rssi=-30)

        aggregate(NOW)
        network = Network.objects.get()

        from networks.publish import centroid

        latitude, _ = centroid(network)
        unweighted_mean = (44.4900 + 44.4900 + 44.5000) / 3
        self.assertGreater(latitude, unweighted_mean)
        self.assertLess(latitude, 44.5000)


class AggregationIdempotenceTest(TestCase):
    def test_running_twice_does_not_move_the_network(self) -> None:
        publishable()
        aggregate(NOW)
        first = Network.objects.get()
        position = (first.lat, first.lon, first.observation_count)

        aggregate(NOW + timedelta(hours=1))

        second = Network.objects.get()
        self.assertEqual((second.lat, second.lon, second.observation_count), position)

    def test_a_purge_does_not_unpublish_an_established_network(self) -> None:
        publishable()
        aggregate(NOW)
        RawObservation.objects.all().delete()

        aggregate(NOW + timedelta(days=8))

        self.assertTrue(Network.objects.get().is_published)


class NetworkSchemaTest(TestCase):
    """Every published network validates against spec/schemas/network.schema.json."""

    def test_community_network_validates(self) -> None:
        from core.schemas import validate

        publishable()
        aggregate(NOW)
        validate("network", published_properties(Network.objects.get()))

    def test_owner_verified_network_validates(self) -> None:
        from core.schemas import validate

        network = Network.objects.create(
            ssid="Bar Centrale",
            security="shared",
            captive_portal="none",
            verification=Network.OWNER_VERIFIED,
            lat=44.49381,
            lon=11.34268,
            cell=geohash.encode(44.49381, 11.34268, 7),
            first_seen=date(2026, 9, 1),
            last_seen=date(2026, 9, 17),
            venue_name="Bar Centrale",
            venue_kind="cafe",
            publish_credential=True,
            credential_type="wpa2-psk",
            credential_secret="hunter2",
            is_published=True,
        )
        NetworkBssid.objects.create(network=network, bssid=BSSID)
        validate("network", published_properties(network))
