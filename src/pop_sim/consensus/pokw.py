"""Proof of Kernel Work (Section III-B).

PoKW "eliminates some of the network nodes for the mining race and randomly
chooses nodes (the kernel) for participating in mining".  The kernel members
then compete with ordinary proof of work; the fastest solver wins.  The
simulation runs PoW2 for every kernel member and takes the one that solved
its puzzle in the fewest hashes (the one that would have finished first on
equal hardware).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from .pow2 import PoW2Result, mine_pow2


@dataclass
class PoKWResult:
    nodes: int
    kernel: list[str]
    winner: str
    difficulty: int
    per_node: dict[str, PoW2Result] = field(default_factory=dict)
    seconds: float = 0.0

    @property
    def winner_hashes(self) -> int:
        return self.per_node[self.winner].hashes


def pokw_mine(node_ids: list[str], data_hash: str, difficulty: int, kernel_size: int | None = None,
              rng: random.Random | None = None) -> PoKWResult:
    rng = rng or random.Random()
    k = kernel_size or max(1, len(node_ids) // 2)
    kernel = rng.sample(node_ids, k)
    t0 = time.perf_counter()
    ts = time.time()
    per_node = {}
    for nid in kernel:
        # Each miner hashes its own candidate block header (data || its id).
        per_node[nid] = mine_pow2(f"{data_hash}{nid}", difficulty, timestamp=ts)
    winner = min(per_node, key=lambda n: per_node[n].hashes)
    return PoKWResult(len(node_ids), kernel, winner, difficulty, per_node, time.perf_counter() - t0)
