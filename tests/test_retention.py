"""P7 and P10: `manage.py purge` deletes what is spent and compacts what is old."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from ingest.models import RateLimitBucket, RateLimitSalt, RawObservation
from networks.publish import aggregate, purge
from tests.helpers import publishable, store_observation

NOW = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)


class ObservationRetentionTest(TestCase):
    def test_observations_go_twenty_four_hours_after_the_run_that_consumed_them(self) -> None:
        """P7's window, tightened to a day now that P9 waits for a closed day."""
        publishable()
        aggregate(NOW)
        self.assertEqual(RawObservation.objects.count(), 3)

        purge(NOW + timedelta(hours=23))
        self.assertEqual(RawObservation.objects.count(), 3)

        purge(NOW + timedelta(hours=25))
        self.assertEqual(RawObservation.objects.count(), 0)

    def test_a_raw_observation_lives_about_nine_days_in_all(self) -> None:
        """Eight waiting for its UTC day to close under P9, one after the run."""
        observed = datetime(2026, 9, 17, 9, tzinfo=timezone.utc)
        store_observation(observed_at=observed)

        purge(observed + timedelta(days=8))  # nothing has consumed it yet
        self.assertEqual(RawObservation.objects.count(), 1)

        aggregate(observed + timedelta(days=8))  # the day closed at 09-25
        purge(observed + timedelta(days=9, hours=1))

        self.assertEqual(RawObservation.objects.count(), 0)

    def test_unconsumed_observations_survive(self) -> None:
        store_observation()
        purge(NOW + timedelta(days=30))
        self.assertEqual(RawObservation.objects.count(), 1)

    def test_purging_does_not_unpublish(self) -> None:
        from networks.models import Network

        publishable()
        aggregate(NOW)
        purge(NOW + timedelta(days=8))
        self.assertTrue(Network.objects.get().is_published)

    def test_the_day_tally_is_not_raw_data_and_is_not_purged(self) -> None:
        """P9 outlives P7 on purpose: it is a count, not an observation."""
        from networks.models import NetworkDayTally

        publishable()
        aggregate(NOW)

        purge(NOW + timedelta(days=2))

        self.assertEqual(RawObservation.objects.count(), 0)
        self.assertEqual(NetworkDayTally.objects.count(), 2)

    def test_purge_is_where_p10_compaction_runs(self) -> None:
        from networks.models import NetworkDayTally

        publishable()
        aggregate(NOW)

        deleted = purge(NOW + timedelta(days=120))

        self.assertEqual(deleted["tally_rows"], 1)
        self.assertEqual(NetworkDayTally.objects.get().day_count, 2)


class RateLimitRetentionTest(TestCase):
    def test_buckets_go_after_twenty_four_hours(self) -> None:
        RateLimitBucket.objects.create(
            bucket="deadbeef", scope="batches", window_start=NOW - timedelta(hours=25), count=3
        )
        RateLimitBucket.objects.create(
            bucket="deadbeef", scope="batches", window_start=NOW - timedelta(hours=2), count=1
        )

        deleted = purge(NOW)

        self.assertEqual(deleted["buckets"], 1)
        self.assertEqual(RateLimitBucket.objects.count(), 1)

    def test_yesterdays_salt_goes(self) -> None:
        RateLimitSalt.objects.create(day=NOW.date() - timedelta(days=1), salt=b"x" * 32)
        RateLimitSalt.objects.create(day=NOW.date(), salt=b"y" * 32)

        deleted = purge(NOW)

        self.assertEqual(deleted["salts"], 1)
        self.assertEqual(RateLimitSalt.objects.get().day, NOW.date())

    def test_management_command_reports_what_it_deleted(self) -> None:
        # The command reads the wall clock, so the fixture has to as well.
        RateLimitBucket.objects.create(
            bucket="deadbeef",
            scope="batches",
            window_start=datetime.now(timezone.utc) - timedelta(days=3),
        )
        out = StringIO()

        call_command("purge", stdout=out)

        self.assertIn("1 rate-limit buckets", out.getvalue())
        self.assertIn("0 tally rows", out.getvalue())
        self.assertEqual(RateLimitBucket.objects.count(), 0)
