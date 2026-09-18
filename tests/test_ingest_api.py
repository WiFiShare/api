"""GET /v1/keys and POST /v1/batches, against spec/openapi.yaml."""

from __future__ import annotations

import json
from datetime import date, timedelta

from django.test import TestCase

from ingest import hpke
from ingest.models import RawObservation
from tests.helpers import batch, make_key, observation, seal_envelope

PROBLEM_TYPE = "application/problem+json"


class KeysTest(TestCase):
    def test_lists_active_keys_newest_first(self) -> None:
        make_key("2026q3", not_after=date.today() + timedelta(days=5))
        make_key("2026q4", not_after=date.today() + timedelta(days=95))

        response = self.client.get("/v1/keys")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual([key["key_id"] for key in body["keys"]], ["2026q4", "2026q3"])
        for key in body["keys"]:
            self.assertEqual(key["suite"], "x25519-sha256-chacha20poly1305")
            self.assertEqual(len(hpke.b64url_decode(key["public_key"])), 32)
            self.assertRegex(key["not_after"], r"^\d{4}-\d{2}-\d{2}$")

    def test_retired_keys_are_not_advertised(self) -> None:
        make_key("2026q1", not_after=date.today() - timedelta(days=1))
        self.assertEqual(self.client.get("/v1/keys").json()["keys"], [])

    def test_no_private_key_is_ever_served(self) -> None:
        key = make_key()
        body = self.client.get("/v1/keys").content.decode()
        self.assertNotIn(hpke.b64url_encode(bytes(key.private_key)), body)


class BatchesTest(TestCase):
    def post(self, envelope: dict) -> object:
        return self.client.post(
            "/v1/batches", data=json.dumps(envelope), content_type="application/json"
        )

    def test_accepts_a_sealed_batch_and_stores_the_observations(self) -> None:
        key = make_key()
        response = self.post(seal_envelope(key, batch()))

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"accepted": 1, "rejected": 0})
        self.assertEqual(RawObservation.objects.count(), 1)
        stored = RawObservation.objects.get()
        self.assertEqual(stored.bssid, "b8:27:eb:11:22:33")
        self.assertNotEqual(stored.bucket, "")

    def test_reports_r12_dedupe_without_naming_a_network(self) -> None:
        key = make_key()
        duplicate = observation(rssi=-40)
        response = self.post(seal_envelope(key, batch(observation(), duplicate)))

        body = response.json()
        self.assertEqual(response.status_code, 202)
        self.assertEqual(body["accepted"], 1)
        self.assertEqual(body["rejected"], 1)
        self.assertEqual(body["rules"], ["R12"])
        self.assertEqual(RawObservation.objects.get().rssi, -40)
        self.assertNotIn("b8:27:eb", response.content.decode())

    def test_rejects_the_whole_batch_when_an_observation_breaks_a_rule(self) -> None:
        key = make_key()
        # A locally administered BSSID: R3 on the device, R3 again here.
        envelope = seal_envelope(key, batch(observation(bssid="02:1a:2b:3c:4d:5e")))

        response = self.post(envelope)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], PROBLEM_TYPE)
        problem = response.json()
        self.assertEqual(problem["rule"], "R3")
        self.assertEqual(problem["status"], 400)
        self.assertIn("type", problem)
        self.assertIn("title", problem)
        self.assertEqual(RawObservation.objects.count(), 0)

    def test_rejects_a_batch_carrying_a_linkage_field(self) -> None:
        key = make_key()
        payload = batch()
        payload["batch_id"] = "0f4c1c9a-7b2e-4a1a-9c2a-1d2e3f4a5b6c"

        response = self.post(seal_envelope(key, payload))

        # batch.schema.json forbids extra properties, so the schema catches it
        # first; either way the batch never reaches storage.
        self.assertEqual(response.status_code, 400)
        self.assertEqual(RawObservation.objects.count(), 0)

    def test_unknown_key_is_refused(self) -> None:
        key = make_key()
        envelope = seal_envelope(key, batch())
        envelope["key_id"] = "2025q1"
        self.assertEqual(self.post(envelope).status_code, 400)

    def test_retired_key_gets_409(self) -> None:
        key = make_key(not_after=date.today() - timedelta(days=40))
        response = self.post(seal_envelope(key, batch()))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response["Content-Type"], PROBLEM_TYPE)

    def test_key_inside_the_grace_period_still_decrypts(self) -> None:
        key = make_key(not_after=date.today() - timedelta(days=5))
        self.assertEqual(self.post(seal_envelope(key, batch())).status_code, 202)

    def test_envelope_sealed_to_another_key_does_not_open(self) -> None:
        key = make_key()
        other = make_key("2026q3")
        envelope = seal_envelope(other, batch())
        envelope["key_id"] = key.key_id
        response = self.post(envelope)
        self.assertEqual(response.status_code, 400)
        self.assertIn("undecryptable", response.json()["type"])

    def test_malformed_envelope_is_a_problem_document(self) -> None:
        response = self.client.post(
            "/v1/batches", data='{"schema": "nope"}', content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response["Content-Type"], PROBLEM_TYPE)
        self.assertEqual(response.json()["status"], 400)

    def test_body_that_is_not_json(self) -> None:
        response = self.client.post("/v1/batches", data="not json", content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_get_is_not_allowed(self) -> None:
        self.assertEqual(self.client.get("/v1/batches").status_code, 405)
