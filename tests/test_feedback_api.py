"""POST /v1/networks/{id}/reports, /v1/optout, /v1/claims and the verify step."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from django.test import TestCase

from networks.models import Claim, Network, NetworkBssid, OptOut, Report
from networks.publish import aggregate, optout_hmac
from tests.helpers import publishable

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
BSSID = "b8:27:eb:11:22:33"


def post(client, path: str, body: dict):
    return client.post(path, data=json.dumps(body), content_type="application/json")


class ReportTest(TestCase):
    def setUp(self) -> None:
        publishable()
        aggregate(NOW)
        self.network = Network.objects.get()

    def test_records_a_report(self) -> None:
        response = post(
            self.client,
            f"/v1/networks/{self.network.public_id}/reports",
            {"schema": "wifishare.report/1", "kind": "works"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(Report.objects.get().kind, "works")

    def test_unknown_network_is_404(self) -> None:
        response = post(
            self.client,
            "/v1/networks/aaaaaaaaaaaa/reports",
            {"schema": "wifishare.report/1", "kind": "works"},
        )
        self.assertEqual(response.status_code, 404)

    def test_malformed_id_is_404(self) -> None:
        response = post(
            self.client,
            "/v1/networks/NOT-AN-ID/reports",
            {"schema": "wifishare.report/1", "kind": "works"},
        )
        self.assertEqual(response.status_code, 404)

    def test_unknown_kind_is_a_problem_document(self) -> None:
        response = post(
            self.client,
            f"/v1/networks/{self.network.public_id}/reports",
            {"schema": "wifishare.report/1", "kind": "brilliant"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "application/problem+json")

    def test_three_private_or_gone_reports_unpublish_immediately(self) -> None:
        for kind in ("private", "gone", "gone"):
            post(
                self.client,
                f"/v1/networks/{self.network.public_id}/reports",
                {"schema": "wifishare.report/1", "kind": kind},
            )
        self.network.refresh_from_db()
        self.assertFalse(self.network.is_published)

    def test_the_note_is_stored_but_never_published(self) -> None:
        post(
            self.client,
            f"/v1/networks/{self.network.public_id}/reports",
            {"schema": "wifishare.report/1", "kind": "fails", "note": "moved upstairs"},
        )
        self.assertEqual(Report.objects.get().note, "moved upstairs")
        area = self.client.get(f"/v1/areas/{self.network.cell[:5]}").content.decode()
        self.assertNotIn("moved upstairs", area)


class OptOutTest(TestCase):
    def setUp(self) -> None:
        publishable()
        aggregate(NOW)
        self.network = Network.objects.get()

    def test_bssid_opt_out_unpublishes_immediately(self) -> None:
        response = post(
            self.client, "/v1/optout", {"schema": "wifishare.optout/1", "bssid": BSSID}
        )
        self.assertEqual(response.status_code, 202)
        self.network.refresh_from_db()
        self.assertFalse(self.network.is_published)
        self.assertEqual(OptOut.objects.get().bssid_hmac, optout_hmac(BSSID))

    def test_the_bssid_is_not_stored_in_the_clear(self) -> None:
        post(self.client, "/v1/optout", {"schema": "wifishare.optout/1", "bssid": BSSID})
        self.assertNotIn(BSSID, str(list(OptOut.objects.values())))

    def test_unknown_bssid_is_still_accepted(self) -> None:
        response = post(
            self.client,
            "/v1/optout",
            {"schema": "wifishare.optout/1", "bssid": "aa:bb:cc:dd:ee:ff"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.content, b"{}")

    def test_ssid_plus_cell_opt_out(self) -> None:
        response = post(
            self.client,
            "/v1/optout",
            {
                "schema": "wifishare.optout/1",
                "ssid": self.network.ssid,
                "cell": self.network.cell[:5],
            },
        )
        self.assertEqual(response.status_code, 202)
        self.network.refresh_from_db()
        self.assertFalse(self.network.is_published)

    def test_neither_form_is_a_problem_document(self) -> None:
        response = post(self.client, "/v1/optout", {"schema": "wifishare.optout/1"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "application/problem+json")


CLAIM = {
    "schema": "wifishare.claim/1",
    "ssid": "Bar Centrale",
    "bssids": [BSSID],
    "venue": {"name": "Bar Centrale", "kind": "cafe", "lat": 44.49381, "lon": 11.34268},
    "share": {
        "publish_credential": True,
        "credential": {"type": "wpa2-psk", "secret": "ospiti2026", "note": "Ask at the bar"},
    },
    "contact": {"email": "owner@example.org"},
}


class ClaimTest(TestCase):
    def test_issues_a_challenge(self) -> None:
        response = post(self.client, "/v1/claims", CLAIM)

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertRegex(body["challenge_code"], r"^ws-[a-z0-9]{6}$")
        self.assertIn("claim_id", body)
        self.assertIn("expires_at", body)
        self.assertEqual(Claim.objects.get().status, Claim.PENDING)

    def test_malformed_claim_is_a_problem_document(self) -> None:
        response = post(self.client, "/v1/claims", {"schema": "wifishare.claim/1"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], "application/problem+json")

    def test_verify_publishes_the_network_at_full_precision(self) -> None:
        created = post(self.client, "/v1/claims", CLAIM).json()
        code = created["challenge_code"]

        response = post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {"observed_ssid": f"Bar Centrale {code}", "bssid": BSSID},
        )

        self.assertEqual(response.status_code, 200)
        network = Network.objects.get(public_id=response.json()["network_id"])
        self.assertEqual(network.verification, Network.OWNER_VERIFIED)
        self.assertTrue(network.is_published)
        self.assertAlmostEqual(network.lat, 44.49381, places=9)
        self.assertEqual(network.precision_m, 10)
        self.assertEqual(Claim.objects.get().status, Claim.VERIFIED)

    def test_verify_then_the_area_carries_the_bssid_and_credential(self) -> None:
        created = post(self.client, "/v1/claims", CLAIM).json()
        post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {"observed_ssid": f"Bar Centrale {created['challenge_code']}", "bssid": BSSID},
        )
        network = Network.objects.get()

        body = self.client.get(f"/v1/areas/{network.cell[:5]}").content.decode()

        self.assertIn(BSSID, body)
        self.assertIn("ospiti2026", body)

    def test_wrong_code_is_409(self) -> None:
        created = post(self.client, "/v1/claims", CLAIM).json()
        response = post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {"observed_ssid": "Bar Centrale ws-000000", "bssid": BSSID},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(Claim.objects.get().status, Claim.PENDING)

    def test_wrong_bssid_is_409(self) -> None:
        created = post(self.client, "/v1/claims", CLAIM).json()
        response = post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {
                "observed_ssid": f"Bar Centrale {created['challenge_code']}",
                "bssid": "aa:bb:cc:dd:ee:ff",
            },
        )
        self.assertEqual(response.status_code, 409)

    def test_expired_challenge_is_409(self) -> None:
        created = post(self.client, "/v1/claims", CLAIM).json()
        claim = Claim.objects.get()
        claim.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        claim.save(update_fields=["expires_at"])

        response = post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {"observed_ssid": f"Bar Centrale {created['challenge_code']}", "bssid": BSSID},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(Claim.objects.get().status, Claim.EXPIRED)

    def test_unknown_claim_is_409(self) -> None:
        response = post(
            self.client,
            "/v1/claims/0f4c1c9a-7b2e-4a1a-9c2a-1d2e3f4a5b6c/verify",
            {"observed_ssid": "Bar Centrale ws-abc123", "bssid": BSSID},
        )
        self.assertEqual(response.status_code, 409)

    def test_verifying_an_existing_community_network_upgrades_it(self) -> None:
        publishable()
        aggregate(NOW)
        existing = Network.objects.get()
        self.assertEqual(existing.verification, Network.COMMUNITY)

        created = post(self.client, "/v1/claims", CLAIM).json()
        response = post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {"observed_ssid": f"Bar Centrale {created['challenge_code']}", "bssid": BSSID},
        )

        self.assertEqual(response.json()["network_id"], existing.public_id)
        existing.refresh_from_db()
        self.assertEqual(existing.verification, Network.OWNER_VERIFIED)
        self.assertEqual(NetworkBssid.objects.filter(bssid=BSSID).count(), 1)

    def test_an_opted_out_network_is_not_republished_by_a_claim(self) -> None:
        OptOut.objects.create(bssid_hmac=optout_hmac(BSSID))
        created = post(self.client, "/v1/claims", CLAIM).json()
        post(
            self.client,
            f"/v1/claims/{created['claim_id']}/verify",
            {"observed_ssid": f"Bar Centrale {created['challenge_code']}", "bssid": BSSID},
        )
        self.assertFalse(Network.objects.get().is_published)
