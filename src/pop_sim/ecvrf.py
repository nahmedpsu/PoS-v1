"""ECVRF (RFC 9381, Section 5) over secp256k1 with SHA-256 and the
try-and-increment hash-to-curve, on top of libsecp256k1 (``coincurve``).

The construction is the one of ECVRF-P256-SHA256-TAI with the curve swapped
for secp256k1, because that is the curve the fast library exposes point
operations for.  The output ``beta`` depends only on ``Gamma = x * H``, so
it is unique per (key, input): the prover cannot grind it through the nonce.

Costs on this machine: prove about 0.15 ms, verify about 0.25 ms, against
7 ms / 0.2 ms for the pure-Python RSA-FDH-VRF.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

try:
    from coincurve import PublicKey
    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only where coincurve is missing
    AVAILABLE = False

SUITE = b"\xfe"              # private-use suite byte: ECVRF-SECP256K1-SHA256-TAI
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
C_LEN = 16
PT_LEN = 33
Q_LEN = 32


def _i2osp(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(frozen=True)
class ECVRFPublicKey:
    point: bytes                      # compressed, 33 bytes

    def to_hex(self) -> str:
        return "ec:" + self.point.hex()

    @classmethod
    def from_hex(cls, s: str) -> "ECVRFPublicKey":
        if s.startswith("ec:"):
            s = s[3:]
        return cls(bytes.fromhex(s))


@dataclass(frozen=True)
class ECVRFKeyPair:
    secret: bytes                     # 32 bytes

    @property
    def public(self) -> ECVRFPublicKey:
        return ECVRFPublicKey(PublicKey.from_secret(self.secret).format(compressed=True))


def generate_keypair() -> ECVRFKeyPair:
    while True:
        s = os.urandom(32)
        if 0 < _os2ip(s) < ORDER:
            return ECVRFKeyPair(s)


def _hash_to_curve(pk: bytes, alpha: bytes) -> PublicKey:
    """Try-and-increment: the first ctr whose SHA-256 is a valid x coordinate."""
    ctr = 0
    while True:
        h = hashlib.sha256(SUITE + b"\x01" + pk + alpha + bytes([ctr]) + b"\x00").digest()
        try:
            return PublicKey(b"\x02" + h)
        except ValueError:
            ctr += 1
            if ctr > 255:
                raise RuntimeError("hash_to_curve failed")


def _challenge(*points: bytes) -> int:
    h = hashlib.sha256(SUITE + b"\x02" + b"".join(points) + b"\x00").digest()
    return _os2ip(h[:C_LEN])


def _mul(p: PublicKey, k: int) -> PublicKey:
    return p.multiply(_i2osp(k % ORDER, Q_LEN))


def _neg(p: PublicKey) -> PublicKey:
    return p.multiply(_i2osp(ORDER - 1, Q_LEN))


def _add(p: PublicKey, q: PublicKey) -> PublicKey:
    return PublicKey.combine_keys([p, q])


def prove(sk: ECVRFKeyPair, alpha: bytes) -> bytes:
    x = _os2ip(sk.secret)
    y_point = PublicKey.from_secret(sk.secret)
    y = y_point.format(compressed=True)
    h_pt = _hash_to_curve(y, alpha)
    h = h_pt.format(compressed=True)
    gamma = _mul(h_pt, x)
    # deterministic nonce from the secret and the input (RFC 9381 allows any
    # unpredictable k; the output does not depend on it)
    k = _os2ip(hashlib.sha256(b"nonce" + sk.secret + h).digest()) % ORDER or 1
    u = PublicKey.from_secret(_i2osp(k, Q_LEN)).format(compressed=True)
    v = _mul(h_pt, k).format(compressed=True)
    g = gamma.format(compressed=True)
    c = _challenge(y, h, g, u, v)
    s = (k + c * x) % ORDER
    return g + _i2osp(c, C_LEN) + _i2osp(s, Q_LEN)


def proof_to_hash(pi: bytes) -> bytes:
    gamma = pi[:PT_LEN]
    return hashlib.sha256(SUITE + b"\x03" + gamma + b"\x00").digest()


def verify(pk: ECVRFPublicKey, alpha: bytes, pi: bytes) -> bytes | None:
    if len(pi) != PT_LEN + C_LEN + Q_LEN:
        return None
    try:
        gamma = PublicKey(pi[:PT_LEN])
        c = _os2ip(pi[PT_LEN:PT_LEN + C_LEN])
        s = _os2ip(pi[PT_LEN + C_LEN:])
        if not 0 < s < ORDER or c == 0:
            return None
        y_pt = PublicKey(pk.point)
        h_pt = _hash_to_curve(pk.point, alpha)
        s_b = PublicKey.from_secret(_i2osp(s, Q_LEN))
        u = _add(s_b, _neg(_mul(y_pt, c)))
        v = _add(_mul(h_pt, s), _neg(_mul(gamma, c)))
        c2 = _challenge(pk.point, h_pt.format(compressed=True), gamma.format(compressed=True),
                        u.format(compressed=True), v.format(compressed=True))
    except ValueError:
        return None
    return proof_to_hash(pi) if c2 == c else None
