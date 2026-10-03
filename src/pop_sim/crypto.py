"""Cryptographic primitives used by the simulation.

The manuscript's transactions "contain the timestamp and the key pairs of the
sender and receiver PMs along with the data encrypted with the receiver public
key and signed by the sender/source private key" (Section IV-D).  This module
provides exactly those operations on NIST P-256:

* ``generate_keypair``        -> (sk, pk)
* ``sign`` / ``verify``       -> ECDSA over SHA-256
* ``encrypt`` / ``decrypt``   -> ECIES-style: ephemeral ECDH + HKDF + AES-256-GCM
* ``sha256_hex``              -> hash used for block linking and PoW puzzles
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()


@dataclass(frozen=True)
class KeyPair:
    """A public/secret key pair ``(pk_i, sk_i)`` in the notation of Table 1."""

    sk: ec.EllipticCurvePrivateKey
    pk: ec.EllipticCurvePublicKey

    @property
    def pk_hex(self) -> str:
        return pk_to_hex(self.pk)


def generate_keypair() -> KeyPair:
    sk = ec.generate_private_key(CURVE)
    return KeyPair(sk=sk, pk=sk.public_key())


def pk_to_bytes(pk: ec.EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def pk_to_hex(pk: ec.EllipticCurvePublicKey) -> str:
    return pk_to_bytes(pk).hex()


def pk_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)


def pk_from_hex(data: str) -> ec.EllipticCurvePublicKey:
    return pk_from_bytes(bytes.fromhex(data))


def sign(sk: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return sk.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pk: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pk.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def _derive_key(shared: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"pop-sim-ecies"
    ).derive(shared)


def encrypt(recipient_pk: ec.EllipticCurvePublicKey, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` so that only the holder of the matching secret key
    can read it.  Output layout: ``eph_pk(33) || nonce(12) || ciphertext``."""
    eph = ec.generate_private_key(CURVE)
    shared = eph.exchange(ec.ECDH(), recipient_pk)
    nonce = os.urandom(12)
    key = _derive_key(shared, nonce)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return pk_to_bytes(eph.public_key()) + nonce + ct


def decrypt(recipient_sk: ec.EllipticCurvePrivateKey, blob: bytes) -> bytes:
    eph_pk = pk_from_bytes(blob[:33])
    nonce = blob[33:45]
    ct = blob[45:]
    shared = recipient_sk.exchange(ec.ECDH(), eph_pk)
    key = _derive_key(shared, nonce)
    return AESGCM(key).decrypt(nonce, ct, None)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()
