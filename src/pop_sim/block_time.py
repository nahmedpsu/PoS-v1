"""Block time model used in Section V:

    tB = nT * tV + 2 * tP + tprep + tM * N        (after Bao et al. [31])

* ``nT``    number of transactions in the block
* ``tV``    verification time of one transaction
* ``tP``    network propagation time (counted twice: request and block)
* ``tprep`` block preparation time
* ``tM``    average mining time of the consensus (PoW 2 or Proof of Pseudonym)
* ``N``     number of mining nodes taking part
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import crypto
from .blockchain import Transaction


@dataclass
class BlockTimeParams:
    tV: float
    tP: float
    tprep: float
    tM: float
    N: int

    def to_dict(self) -> dict:
        return {"tV": self.tV, "tP": self.tP, "tprep": self.tprep, "tM": self.tM, "N": self.N}


def block_time(nT: int, p: BlockTimeParams) -> float:
    return nT * p.tV + 2 * p.tP + p.tprep + p.tM * p.N


def measure_tv(samples: int = 100) -> float:
    """Mean ECDSA verification time of one signed, encrypted transaction."""
    sender = crypto.generate_keypair()
    receiver = crypto.generate_keypair()
    txs = [Transaction.create("bench", sender, receiver.pk, {"i": i}) for i in range(samples)]
    t0 = time.perf_counter()
    for tx in txs:
        assert tx.verify_signature()
    return (time.perf_counter() - t0) / samples


def measure_tprep(nT: int, repeats: int = 3) -> float:
    """Time to hash ``nT`` transactions into a block header (block preparation)."""
    sender = crypto.generate_keypair()
    receiver = crypto.generate_keypair()
    tx = Transaction.create("bench", sender, receiver.pk, {"i": 0})
    hashes = [tx.hash()] * nT
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        crypto.sha256_hex("".join(hashes))
        best = min(best, time.perf_counter() - t0)
    return best
