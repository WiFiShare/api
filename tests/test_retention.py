"""P7: `manage.py purge` deletes raw observations and rate-limit state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from ingest.models import RateLimitBucket, RateLimitSalt, RawObservation
from networks.publish import aggregate, purge
from tests.helpers import publishable, store_observation

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)


class ObservationRetentionTest(TestCase):
    def test_observations_go_seven_days_after_the_run_that_consumed_them(self) -> None:
        publishable()
        aggregate(NOW)
        self.assertEqual(RawObservation.objects.count(), 3)

        purge(NOW + timedelta(days=6, hours=23))
        self.assertEqual(RawObservation.objects.count(), 3)

        purge(NOW + timedelta(days=7, hours=1))
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
        RateLimitBucket.objects.create(
            bucket="deadbeef", scope="batches", window_start=NOW - timedelta(days=3)
        )
        out = StringIO()

        call_command("purge", stdout=out)

        self.assertIn("1 rate-limit buckets", out.getvalue())
        self.assertEqual(RateLimitBucket.objects.count(), 0)
