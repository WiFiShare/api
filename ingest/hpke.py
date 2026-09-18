"""HPKE envelope sealing and opening.

RFC 9180 base mode, suite X25519-SHA256-ChaCha20Poly1305 (KEM 0x0020,
KDF 0x0001, AEAD 0x0003), with `info` set to the batch schema id and the key id
passed as additional authenticated data, exactly as spec/docs/data-model.md
says.

The primitives come from `pyhpke`; `tests/test_hpke_vectors.py` checks that
this module's own seal/open pair reproduces the RFC 9180 Appendix A.2.1 test
vectors in both directions, so the interop claim is tested and not assumed.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, KEMKeyPair

SUITE_NAME = "x25519-sha256-chacha20poly1305"
BATCH_SCHEMA_ID = "wifishare.batch/1"

#: RFC 9180 `info` for every WiFiShare envelope: the batch schema id.
INFO = BATCH_SCHEMA_ID.encode("ascii")


def suite() -> CipherSuite:
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
    )


class DecryptionError(Exception):
    """The envelope did not open under this key."""


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


@dataclass(frozen=True)
class KeyPair:
    private_key: bytes  # 32 raw bytes
    public_key: bytes  # 32 raw bytes

    @property
    def public_key_b64(self) -> str:
        return b64url_encode(self.public_key)


def generate_keypair() -> KeyPair:
    private = X25519PrivateKey.generate()
    return KeyPair(
        private_key=private.private_bytes_raw(),
        public_key=private.public_key().public_bytes_raw(),
    )


def seal(
    public_key: bytes,
    plaintext: bytes,
    *,
    aad: bytes,
    info: bytes = INFO,
    ephemeral: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt to `public_key`, returning (enc, ct).

    `ephemeral` forces the sender's ephemeral private key; it exists so the
    RFC 9180 vectors can be reproduced exactly and is never used in production.
    """
    recipient = KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(public_key))
    eks = None
    if ephemeral is not None:
        sk = X25519PrivateKey.from_private_bytes(ephemeral)
        eks = KEMKeyPair(
            KEMKey.from_pyca_cryptography_key(sk),
            KEMKey.from_pyca_cryptography_key(sk.public_key()),
        )
    enc, context = suite().create_sender_context(recipient, info=info, eks=eks)
    return enc, context.seal(plaintext, aad=aad)


def open_envelope(
    private_key: bytes,
    enc: bytes,
    ciphertext: bytes,
    *,
    aad: bytes,
    info: bytes = INFO,
) -> bytes:
    """Decrypt one sealed batch. Raises DecryptionError on any failure."""
    try:
        recipient = KEMKey.from_pyca_cryptography_key(
            X25519PrivateKey.from_private_bytes(private_key)
        )
        context = suite().create_recipient_context(enc, recipient, info=info)
        return context.open(ciphertext, aad=aad)
    except Exception as exc:  # pyhpke raises several unrelated types
        raise DecryptionError(str(exc)) from exc
