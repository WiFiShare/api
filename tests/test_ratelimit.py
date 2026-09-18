"""Rate limiting, and the promise that no address is ever written down."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import TestCase, override_settings

from ingest import ratelimit
from ingest.models import RateLimitBucket, RateLimitSalt, RawObservation
from networks.models import Network, Report
from networks.publish import aggregate
from tests.helpers import batch, make_key, publishable, seal_envelope

ADDRESS = "203.0.113.47"
NOW = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)


class BucketTest(TestCase):
    def test_bucket_is_an_hmac_and_not_the_address(self) -> None:
        request = _request(ADDRESS)
        bucket = ratelimit.bucket_for(request, now=NOW)

        self.assertEqual(len(bucket), 64)
        self.assertNotIn(ADDRESS, bucket)
        self.assertNotEqual(bucket, ADDRESS)

    def test_the_same_address_gets_the_same_bucket_on_the_same_day(self) -> None:
        first = ratelimit.bucket_for(_request(ADDRESS), now=NOW)
        second = ratelimit.bucket_for(_request(ADDRESS), now=NOW + timedelta(hours=3))
        self.assertEqual(first, second)

    def test_two_addresses_get_different_buckets(self) -> None:
        self.assertNotEqual(
            ratelimit.bucket_for(_request(ADDRESS), now=NOW),
            ratelimit.bucket_for(_request("198.51.100.9"), now=NOW),
        )

    def test_the_salt_rotates_daily_so_the_bucket_changes(self) -> None:
        today = ratelimit.bucket_for(_request(ADDRESS), now=NOW)
        tomorrow = ratelimit.bucket_for(_request(ADDRESS), now=NOW + timedelta(days=1))

        self.assertNotEqual(today, tomorrow)
        self.assertEqual(RateLimitSalt.objects.count(), 2)
        salts = {bytes(row.salt) for row in RateLimitSalt.objects.all()}
        self.assertEqual(len(salts), 2)

    def test_nothing_stored_contains_the_address(self) -> None:
        key = make_key()
        self.client.post(
            "/v1/batches",
            data=json.dumps(seal_envelope(key, batch())),
            content_type="application/json",
            REMOTE_ADDR=ADDRESS,
        )

        rows = str(list(RateLimitBucket.objects.values())) + str(
            list(RawObservation.objects.values())
        )
        self.assertNotIn(ADDRESS, rows)
        self.assertEqual(RawObservation.objects.count(), 1)

    def test_x_forwarded_for_is_ignored_unless_it_is_trusted(self) -> None:
        request = _request(ADDRESS, forwarded="198.51.100.9")
        self.assertEqual(ratelimit.client_address(request), ADDRESS)

    @override_settings(TRUST_X_FORWARDED_FOR=True)
    def test_x_forwarded_for_is_used_when_configured(self) -> None:
        request = _request(ADDRESS, forwarded="198.51.100.9, 203.0.113.1")
        self.assertEqual(ratelimit.client_address(request), "198.51.100.9")


LIMITS = {scope: (2, 3600) for scope in ("batches", "reports", "optout", "claims")}


@override_settings(RATE_LIMITS=LIMITS)
class LimitTest(TestCase):
    def test_batches_are_limited(self) -> None:
        key = make_key()
        for _ in range(2):
            response = self._post_batch(key)
            self.assertEqual(response.status_code, 202)

        blocked = self._post_batch(key)

        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked["Content-Type"], "application/problem+json")
        self.assertGreater(int(blocked["Retry-After"]), 0)
        self.assertEqual(blocked.json()["status"], 429)

    def test_a_different_bucket_is_not_blocked(self) -> None:
        key = make_key()
        for _ in range(3):
            self._post_batch(key)

        other = self._post_batch(key, address="198.51.100.9")

        self.assertEqual(other.status_code, 202)

    def test_reports_are_limited(self) -> None:
        publishable()
        aggregate(NOW)
        network = Network.objects.get()
        body = {"schema": "wifishare.report/1", "kind": "works"}

        for _ in range(2):
            self._post_report(network.public_id, body)
        blocked = self._post_report(network.public_id, body)

        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(Report.objects.count(), 2)

    def _post_batch(self, key, address: str = ADDRESS):
        return self.client.post(
            "/v1/batches",
            data=json.dumps(seal_envelope(key, batch())),
            content_type="application/json",
            REMOTE_ADDR=address,
        )

    def _post_report(self, public_id: str, body: dict):
        return self.client.post(
            f"/v1/networks/{public_id}/reports",
            data=json.dumps(body),
            content_type="application/json",
            REMOTE_ADDR=ADDRESS,
        )


def _request(address: str, forwarded: str | None = None):
    from django.test import RequestFactory

    extra = {"REMOTE_ADDR": address}
    if forwarded:
        extra["HTTP_X_FORWARDED_FOR"] = forwarded
    return RequestFactory().get("/", **extra)
