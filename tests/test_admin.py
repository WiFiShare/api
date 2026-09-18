"""The moderation admin: it loads, it moderates, and it leaks nothing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from networks.models import Claim, Network, Report
from networks.publish import aggregate
from tests.helpers import publishable

NOW = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)
BSSID = "b8:27:eb:11:22:33"


class AdminTest(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_superuser("mod", "mod@example.org", "not-a-real-password")
        self.client.force_login(self.user)
        publishable()
        aggregate(NOW)
        self.network = Network.objects.get()

    def test_index_lists_the_moderation_models(self) -> None:
        response = self.client.get(reverse("admin:index"))
        body = response.content.decode()
        for model in ("Claims", "Reports", "Networks", "Opt outs", "Ingest keys"):
            self.assertIn(model, body)

    def test_network_list_does_not_show_a_community_bssid(self) -> None:
        response = self.client.get(reverse("admin:networks_network_changelist"))
        self.assertNotIn(BSSID, response.content.decode())

    def test_network_detail_hides_a_community_bssid(self) -> None:
        url = reverse("admin:networks_network_change", args=[self.network.pk])
        self.assertNotIn(BSSID, self.client.get(url).content.decode())

    def test_network_detail_shows_a_verified_bssid(self) -> None:
        self.network.verification = Network.OWNER_VERIFIED
        self.network.save()
        url = reverse("admin:networks_network_change", args=[self.network.pk])
        self.assertIn(BSSID, self.client.get(url).content.decode())

    def test_unpublish_action(self) -> None:
        self.client.post(
            reverse("admin:networks_network_changelist"),
            {"action": "unpublish_selected", "_selected_action": [str(self.network.pk)]},
            follow=True,
        )
        self.network.refresh_from_db()
        self.assertFalse(self.network.is_published)
        self.assertEqual(self.network.unpublished_reason, "moderator")

    def test_report_moderation(self) -> None:
        report = Report.objects.create(network=self.network, kind="fails", note="asked for money")

        self.client.post(
            reverse("admin:networks_report_changelist"),
            {"action": "mark_moderated", "_selected_action": [str(report.pk)]},
            follow=True,
        )

        report.refresh_from_db()
        self.assertTrue(report.moderated)

    def test_report_action_can_unpublish_the_network(self) -> None:
        report = Report.objects.create(network=self.network, kind="private")

        self.client.post(
            reverse("admin:networks_report_changelist"),
            {"action": "unpublish_network", "_selected_action": [str(report.pk)]},
            follow=True,
        )

        self.network.refresh_from_db()
        self.assertFalse(self.network.is_published)

    def test_claim_approval_publishes_an_owner_verified_network(self) -> None:
        claim = Claim.objects.create(
            ssid="Bar Centrale",
            bssids=["b8:27:eb:99:88:77"],
            venue_name="Bar Centrale",
            venue_lat=44.49381,
            venue_lon=11.34268,
            challenge_code="ws-abc123",
            expires_at=NOW + timedelta(days=1),
        )

        self.client.post(
            reverse("admin:networks_claim_changelist"),
            {"action": "approve", "_selected_action": [str(claim.pk)]},
            follow=True,
        )

        claim.refresh_from_db()
        self.assertEqual(claim.status, Claim.VERIFIED)
        self.assertIsNotNone(claim.network)
        self.assertEqual(claim.network.verification, Network.OWNER_VERIFIED)
        self.assertTrue(claim.network.is_published)

    def test_claim_rejection(self) -> None:
        claim = Claim.objects.create(
            ssid="Bar Centrale",
            venue_name="Bar Centrale",
            challenge_code="ws-abc123",
            expires_at=NOW + timedelta(days=1),
        )

        self.client.post(
            reverse("admin:networks_claim_changelist"),
            {"action": "reject", "_selected_action": [str(claim.pk)]},
            follow=True,
        )

        claim.refresh_from_db()
        self.assertEqual(claim.status, Claim.REJECTED)

    def test_ingest_key_admin_never_shows_the_private_half(self) -> None:
        from tests.helpers import make_key

        key = make_key()
        url = reverse("admin:ingest_ingestkey_change", args=[key.pk])
        body = self.client.get(url).content.decode()
        self.assertIn(key.public_key, body)
        self.assertNotIn(bytes(key.private_key).hex(), body)

    def test_raw_observations_are_not_browsable(self) -> None:
        from django.urls import NoReverseMatch

        with self.assertRaises(NoReverseMatch):
            reverse("admin:ingest_rawobservation_changelist")
        with self.assertRaises(NoReverseMatch):
            reverse("admin:ingest_ratelimitbucket_changelist")
