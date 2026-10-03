"""Algorithm 2 - Proof_of_Work_2 consensus.

"Algorithm 2 takes a hash of data, timestamp, and nonce. We set a difficulty
i.e. leading zeros over this hash and we start the guessing and monitor the
time it hashes with different difficulty levels."  Inputs: ``h`` (hash of the
data), ``d`` (difficulty), ``n0`` (nonce).  The puzzle is solved when
``sha256(h || timestamp || nonce)`` starts with ``d`` zero hex digits.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass


@dataclass
class PoW2Result:
    data_hash: str
    difficulty: int
    nonce: int
    block_hash: str
    hashes: int
    seconds: float


def pow2_hash(data_hash: str, timestamp: float, nonce: int) -> str:
    return hashlib.sha256(f"{data_hash}{timestamp}{nonce}".encode()).hexdigest()


def mine_pow2(data_hash: str, difficulty: int, timestamp: float | None = None, start_nonce: int = 0) -> PoW2Result:
    """Find a nonce so that the hash has ``difficulty`` leading zeros."""
    if difficulty < 0:
        raise ValueError("difficulty must be >= 0")
    ts = time.time() if timestamp is None else timestamp
    target = "0" * difficulty
    prefix = f"{data_hash}{ts}".encode()
    nonce = start_nonce
    hashes = 0
    t0 = time.perf_counter()
    while True:
        h = hashlib.sha256(prefix + str(nonce).encode()).hexdigest()
        hashes += 1
        if h.startswith(target):
            return PoW2Result(data_hash, difficulty, nonce, h, hashes, time.perf_counter() - t0)
        nonce += 1


def verify_pow2(data_hash: str, timestamp: float, nonce: int, difficulty: int) -> bool:
    return pow2_hash(data_hash, timestamp, nonce).startswith("0" * difficulty)
