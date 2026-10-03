"""Algorithm 3 - Proof_of_Elapsed_Time consensus.

"The client nodes generate random time ``ts`` without any threshold value and
the node's time is compared with each other. The node with the smallest time
is the winner of the block."  Every node of the network takes part, so the
election cost grows with the number of nodes (Section V: "the CPU time in
PoET is directly proportional to the number of nodes").
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field


@dataclass
class PoETResult:
    nodes: int
    winner: str
    winner_time: float
    times: dict[str, float] = field(default_factory=dict)
    cpu_seconds: float = 0.0


def poet_elect(node_ids: list[str], max_wait: float = 0.25, rng: random.Random | None = None,
               real_wait: bool = False) -> PoETResult:
    """Run one PoET election among all ``node_ids``.

    Each node draws a random timer in ``(0, max_wait]``; the smallest timer
    wins.  With ``real_wait=True`` the winner actually sleeps for its timer
    (the trusted-code wait of SGX-based PoET); otherwise only the election
    itself is timed.
    """
    rng = rng or random.Random()
    t0 = time.perf_counter()
    times = {nid: round(rng.uniform(0.01, max_wait), 2) for nid in node_ids}
    winner = node_ids[0]
    smallest = times[winner]
    for nid in node_ids[1:]:          # Step 3 of Algorithm 3: linear comparison
        if times[nid] < smallest:
            smallest, winner = times[nid], nid
    if real_wait:
        time.sleep(smallest)
    return PoETResult(len(node_ids), winner, smallest, times, time.perf_counter() - t0)
