"""RFC 9180 interop for the suite the envelope schema names.

tests/data/rfc9180-a2-1.json is Appendix A.2.1 of RFC 9180 — base mode,
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, which is exactly
KEM 0x0020 / KDF 0x0001 / AEAD 0x0003 from spec/schemas/envelope.schema.json.
The values were taken from the CFRG test-vector JSON and byte-checked against
the RFC's own text.

`ingest.hpke` is exercised through its public seal/open functions, so this is a
test of what the server actually runs and not of the library underneath it.
"""

from __future__ import annotations

import json
from binascii import unhexlify
from pathlib import Path

from django.test import SimpleTestCase

from ingest import hpke

VECTOR_PATH = Path(__file__).resolve().parent / "data" / "rfc9180-a2-1.json"


def load_vector() -> dict:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


class Rfc9180VectorTest(SimpleTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.vector = load_vector()

    def test_vector_is_the_suite_the_spec_names(self) -> None:
        self.assertEqual(self.vector["mode"], 0, "base mode")
        self.assertEqual(self.vector["kem_id"], 0x0020)
        self.assertEqual(self.vector["kdf_id"], 0x0001)
        self.assertEqual(self.vector["aead_id"], 0x0003)

    def test_recipient_opens_every_vector_ciphertext(self) -> None:
        """Decapsulation, key schedule and AEAD, against the RFC's own values."""
        vector = self.vector
        private_key = unhexlify(vector["skRm"])
        enc = unhexlify(vector["enc"])
        info = unhexlify(vector["info"])

        # `open_envelope` builds a fresh context, which is at sequence 0: that
        # is the case a WiFiShare envelope always is.
        first = vector["encryptions"][0]
        self.assertEqual(first["sequence_number"], 0)
        self.assertEqual(
            hpke.open_envelope(
                private_key,
                enc,
                unhexlify(first["ct"]),
                aad=unhexlify(first["aad"]),
                info=info,
            ),
            unhexlify(first["pt"]),
        )

        # The later vectors depend on the nonce sequence, so replay them
        # through one recipient context. A sender context on the same key
        # supplies throwaway ciphertexts for the sequence numbers the RFC does
        # not print, so the recipient's counter stays in step.
        recipient = hpke.suite().create_recipient_context(enc, _private_key(private_key), info=info)
        _, filler = hpke.suite().create_sender_context(
            _recipient_key(unhexlify(vector["pkRm"])),
            info=info,
            eks=_ephemeral_pair(unhexlify(vector["skEm"])),
        )
        wanted = {item["sequence_number"]: item for item in vector["encryptions"]}
        for sequence in range(max(wanted) + 1):
            item = wanted.get(sequence)
            if item is None:
                recipient.open(filler.seal(b"", aad=b""), aad=b"")
                continue
            filler.seal(b"", aad=b"")  # keep the two counters together
            with self.subTest(sequence_number=sequence):
                self.assertEqual(
                    recipient.open(unhexlify(item["ct"]), aad=unhexlify(item["aad"])),
                    unhexlify(item["pt"]),
                )

    def test_sender_reproduces_every_vector_ciphertext(self) -> None:
        """With the vector's ephemeral key, our seal must be byte-identical.

        This covers the encapsulation and the nonce sequence too, which the
        recipient test above cannot reach on its own.
        """
        vector = self.vector
        enc, _ = hpke.seal(
            unhexlify(vector["pkRm"]),
            b"",
            aad=b"",
            info=unhexlify(vector["info"]),
            ephemeral=unhexlify(vector["skEm"]),
        )
        self.assertEqual(enc.hex(), vector["pkEm"], "encapsulated key")
        self.assertEqual(enc.hex(), vector["enc"])

        # Replay the full sequence through one sender context so that the
        # ciphertexts at sequence 1, 2, 4, 255 and 256 are checked as well.
        context_enc, context = hpke.suite().create_sender_context(
            _recipient_key(unhexlify(vector["pkRm"])),
            info=unhexlify(vector["info"]),
            eks=_ephemeral_pair(unhexlify(vector["skEm"])),
        )
        self.assertEqual(context_enc, unhexlify(vector["enc"]))

        wanted = {item["sequence_number"]: item for item in vector["encryptions"]}
        plaintext = unhexlify(vector["encryptions"][0]["pt"])
        for sequence in range(max(wanted) + 1):
            item = wanted.get(sequence)
            aad = unhexlify(item["aad"]) if item else b"skip"
            ciphertext = context.seal(plaintext, aad=aad)
            if item is not None:
                with self.subTest(sequence_number=sequence):
                    self.assertEqual(ciphertext.hex(), item["ct"])

    def test_round_trip_with_the_project_defaults(self) -> None:
        """A generated key, `info` = the batch schema id, key id as AAD."""
        pair = hpke.generate_keypair()
        message = b'{"schema":"wifishare.batch/1"}'
        enc, ciphertext = hpke.seal(pair.public_key, message, aad=b"2026q4")
        self.assertEqual(hpke.INFO, b"wifishare.batch/1")
        self.assertEqual(
            hpke.open_envelope(pair.private_key, enc, ciphertext, aad=b"2026q4"), message
        )

    def test_wrong_aad_does_not_open(self) -> None:
        pair = hpke.generate_keypair()
        enc, ciphertext = hpke.seal(pair.public_key, b"hello", aad=b"2026q4")
        with self.assertRaises(hpke.DecryptionError):
            hpke.open_envelope(pair.private_key, enc, ciphertext, aad=b"2026q3")

    def test_wrong_key_does_not_open(self) -> None:
        pair = hpke.generate_keypair()
        other = hpke.generate_keypair()
        enc, ciphertext = hpke.seal(pair.public_key, b"hello", aad=b"2026q4")
        with self.assertRaises(hpke.DecryptionError):
            hpke.open_envelope(other.private_key, enc, ciphertext, aad=b"2026q4")


def _recipient_key(public_key: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from pyhpke import KEMKey

    return KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(public_key))


def _ephemeral_pair(private_key: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from pyhpke import KEMKey, KEMKeyPair

    key = X25519PrivateKey.from_private_bytes(private_key)
    return KEMKeyPair(
        KEMKey.from_pyca_cryptography_key(key),
        KEMKey.from_pyca_cryptography_key(key.public_key()),
    )


def _private_key(private_key: bytes):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from pyhpke import KEMKey

    return KEMKey.from_pyca_cryptography_key(X25519PrivateKey.from_private_bytes(private_key))
