"""RSA-FDH-VRF (RFC 9381, Section 4) with the RSA-FDH-VRF-SHA256 ciphersuite.

A Verifiable Random Function lets a node derive a pseudo-random value
``beta`` from an input ``alpha`` with its secret key, together with a proof
``pi`` that anyone holding the public key can check.  Because the RSA
full-domain-hash signature is *unique* for a given key and input, the node
cannot choose or grind ``beta``: it gets exactly one value per input.

This is the primitive PoP v2 uses to replace both the trusted election
server and the self-reported "random short time" of Algorithm 6.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa

SUITE_STRING = b"\x01"          # RSA-FDH-VRF-SHA256
_ONE = b"\x01"
_TWO = b"\x02"


def i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def mgf1(seed: bytes, mask_len: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < mask_len:
        out += hashlib.sha256(seed + i2osp(counter, 4)).digest()
        counter += 1
    return out[:mask_len]


@dataclass(frozen=True)
class VRFPublicKey:
    n: int
    e: int

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def to_hex(self) -> str:
        return f"{self.e:x}:{self.n:x}"

    @classmethod
    def from_hex(cls, s: str) -> "VRFPublicKey":
        e, n = s.split(":")
        return cls(int(n, 16), int(e, 16))


@dataclass(frozen=True)
class VRFKeyPair:
    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0
    dmp1: int = 0
    dmq1: int = 0
    iqmp: int = 0

    @property
    def public(self) -> VRFPublicKey:
        return VRFPublicKey(self.n, self.e)

    def rsasp1(self, m: int) -> int:
        """RSA signature primitive, with the CRT when the factors are known."""
        if not self.p:
            return pow(m, self.d, self.n)
        m1 = pow(m % self.p, self.dmp1, self.p)
        m2 = pow(m % self.q, self.dmq1, self.q)
        h = (self.iqmp * (m1 - m2)) % self.p
        return m2 + h * self.q


def generate_vrf_keypair(bits: int = 2048) -> VRFKeyPair:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv = key.private_numbers()
    pub = priv.public_numbers
    return VRFKeyPair(pub.n, pub.e, priv.d, priv.p, priv.q, priv.dmp1, priv.dmq1, priv.iqmp)


def _encode(pk: VRFPublicKey, alpha: bytes) -> int:
    k = pk.k
    em = mgf1(SUITE_STRING + _ONE + i2osp(k, 4) + i2osp(pk.n, k) + alpha, k - 1)
    return os2ip(em)


def vrf_prove(sk: VRFKeyPair, alpha: bytes) -> bytes:
    """Return the proof ``pi`` (an RSA-FDH signature over ``alpha``)."""
    m = _encode(sk.public, alpha)
    s = sk.rsasp1(m)
    return i2osp(s, sk.public.k)


def vrf_proof_to_hash(pi: bytes) -> bytes:
    """``beta = SHA-256(suite || 0x02 || pi)``, the VRF output."""
    return hashlib.sha256(SUITE_STRING + _TWO + pi).digest()


def vrf_verify(pk: VRFPublicKey, alpha: bytes, pi: bytes) -> bytes | None:
    """Return ``beta`` if ``pi`` is a valid proof for ``alpha`` under ``pk``, else ``None``."""
    if len(pi) != pk.k:
        return None
    s = os2ip(pi)
    if s >= pk.n:
        return None
    m = pow(s, pk.e, pk.n)
    if m != _encode(pk, alpha):
        return None
    return vrf_proof_to_hash(pi)


def beta_to_unit(beta: bytes) -> float:
    """Map a 256-bit VRF output to a number in [0, 1)."""
    return os2ip(beta) / 2 ** 256
