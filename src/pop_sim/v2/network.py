"""A latency/loss model for the PM network and what it does to consensus.

The v1 simulation runs every node in one process and takes propagation as
the constant ``tP``.  This module samples per-link one-way delays from a
log-normal distribution with optional loss, and uses them for three things:

* **fork analysis of timer-based consensus** (PoP v1, PoP v2, PoET): a node
  whose timer fires before the winner's block *reaches* it also publishes,
  so the fork probability depends on the ratio of network latency to the
  time limit, which the manuscript never discusses;
* **consensus latency models** for PoW 2, PoET, PoP v1, PoP v2, PBFT and
  Raft on the same network, with the cryptographic costs measured rather
  than assumed;
* the ``tP`` term of the block-time formula, drawn instead of fixed.
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass


@dataclass
class NetworkModel:
    mean_latency: float = 0.020       # one-way, seconds
    jitter_sigma: float = 0.5         # log-normal sigma (0 = deterministic)
    loss_rate: float = 0.0
    rng: random.Random | None = None

    def __post_init__(self):
        self.rng = self.rng or random.Random(0)

    def delay(self) -> float | None:
        """One-way delay of one message, or ``None`` if the message is lost."""
        if self.loss_rate and self.rng.random() < self.loss_rate:
            return None
        if self.jitter_sigma <= 0:
            return self.mean_latency
        mu = math.log(self.mean_latency) - self.jitter_sigma ** 2 / 2   # keeps the mean
        return self.rng.lognormvariate(mu, self.jitter_sigma)

    def broadcast_delays(self, n: int) -> list[float | None]:
        return [self.delay() for _ in range(n)]


# ---------------------------------------------------------------- forks
@dataclass
class ForkRound:
    publishers: list[str]
    winner: str
    wasted_blocks: int


def simulate_timer_forks(n_nodes: int, time_limit: float, net: NetworkModel, rounds: int = 200,
                         rng: random.Random | None = None, participation: float = 0.5,
                         timer: str = "uniform") -> dict:
    """Timer-based election under real propagation.

    Each participating node ``i`` draws a timer ``t_i`` (uniform in (0,
    time_limit] for PoP v1 / PoET; ``value * time_limit`` for PoP v2, where
    ``value`` is uniform in [0,1) as a VRF output is).  Node ``i`` publishes
    at ``t_i`` unless a block from an earlier publisher ``j`` reached it by
    then (``t_j + delay_ji <= t_i``).  More than one publisher is a fork; the
    fork rule keeps the smallest timer, the others are wasted blocks.
    """
    rng = rng or random.Random(1)
    forks = 0
    wasted = []
    publishers_per_round = []
    for _ in range(rounds):
        ids = [f"N{i}" for i in range(n_nodes)]
        miners = [i for i in ids if rng.random() < participation] or ids[:1]
        if timer == "uniform":
            timers = {i: rng.uniform(0.0, time_limit) for i in miners}
        else:
            timers = {i: rng.random() * time_limit for i in miners}
        order = sorted(miners, key=timers.get)
        published: list[tuple[str, float]] = []
        for i in order:
            suppressed = False
            for p, tp in published:
                d = net.delay()
                if d is not None and tp + d <= timers[i]:
                    suppressed = True
                    break
            if not suppressed:
                published.append((i, timers[i]))
        if len(published) > 1:
            forks += 1
        wasted.append(len(published) - 1)
        publishers_per_round.append(len(published))
    return {"nodes": n_nodes, "time_limit": time_limit, "mean_latency": net.mean_latency,
            "latency_ratio": net.mean_latency / time_limit, "rounds": rounds,
            "fork_probability": forks / rounds, "mean_publishers": statistics.mean(publishers_per_round),
            "wasted_blocks_per_round": statistics.mean(wasted)}


# ------------------------------------------------- consensus latency models
@dataclass
class CryptoCosts:
    """Measured per-operation costs (seconds) handed to the latency models."""
    ecdsa_sign: float
    ecdsa_verify: float
    vrf_prove: float
    vrf_verify: float
    pow2_puzzle: float          # one puzzle at the chosen difficulty


def _kth_smallest(values: list[float], k: int) -> float:
    return sorted(values)[min(k, len(values)) - 1]


def _delays(net: NetworkModel, n: int, retransmit: float = 0.2) -> list[float]:
    """Delays of ``n`` messages; a lost message costs a retransmission timeout."""
    out = []
    for _ in range(n):
        d = net.delay()
        while d is None:
            d = retransmit + (net.delay() or retransmit)
        out.append(d)
    return out


def latency_pow2(n: int, net: NetworkModel, c: CryptoCosts, rng: random.Random) -> float:
    """Every node mines; the first solver's block must reach everyone."""
    first = min(rng.expovariate(1.0 / c.pow2_puzzle) for _ in range(n))
    return first + max(_delays(net, n - 1)) + c.ecdsa_verify


def latency_poet(n: int, net: NetworkModel, c: CryptoCosts, rng: random.Random, time_limit: float) -> float:
    """All nodes draw a timer; the smallest publishes; its block must reach everyone."""
    wait = min(rng.uniform(0.0, time_limit) for _ in range(n))
    return wait + max(_delays(net, n - 1)) + c.ecdsa_verify


def latency_pop_v1(n: int, net: NetworkModel, c: CryptoCosts, rng: random.Random, time_limit: float,
                   participation: float = 0.5) -> float:
    """Handshake with the server (round trip), selection notice, the winner's
    timer, the signed election record, and the block broadcast."""
    handshake = max(_delays(net, n)) + max(_delays(net, n))
    notice = max(_delays(net, max(1, int(n * participation))))
    m = max(1, int(n * participation))
    wait = min(rng.uniform(0.0, time_limit) for _ in range(m))
    return handshake + notice + wait + c.ecdsa_sign + max(_delays(net, n - 1)) + 2 * c.ecdsa_verify


def latency_pop_v2(n: int, net: NetworkModel, c: CryptoCosts, rng: random.Random, time_limit: float,
                   participation: float = 0.5) -> float:
    """Each node proves its own VRF value (in parallel), the smallest value
    waits ``value * time_limit`` and publishes; receivers verify one proof."""
    m = max(1, int(n * participation))
    wait = min(rng.random() for _ in range(m)) * time_limit
    return c.vrf_prove + wait + max(_delays(net, n - 1)) + c.vrf_verify + c.ecdsa_verify


def latency_pbft(n: int, net: NetworkModel, c: CryptoCosts, rng: random.Random) -> float:
    """PBFT (Castro and Liskov): pre-prepare, prepare, commit, each phase
    waiting for a quorum of 2f+1 signed messages, f = (n-1)//3."""
    f = (n - 1) // 3
    quorum = 2 * f + 1
    pre_prepare = max(_delays(net, n - 1)) + c.ecdsa_sign + c.ecdsa_verify
    prepare = _kth_smallest(_delays(net, n - 1), quorum) + c.ecdsa_sign + quorum * c.ecdsa_verify
    commit = _kth_smallest(_delays(net, n - 1), quorum) + c.ecdsa_sign + quorum * c.ecdsa_verify
    return pre_prepare + prepare + commit


def latency_raft(n: int, net: NetworkModel, c: CryptoCosts, rng: random.Random) -> float:
    """Raft: leader appends, waits for a majority of acknowledgements, then
    the commit index propagates with the next append."""
    majority = n // 2 + 1
    append = _kth_smallest([a + b for a, b in zip(_delays(net, n - 1), _delays(net, n - 1))], majority - 1)
    return c.ecdsa_sign + append + (majority - 1) * c.ecdsa_verify + max(_delays(net, n - 1))


LATENCY_MODELS = {
    "pow2": lambda n, net, c, rng, tl: latency_pow2(n, net, c, rng),
    "poet": latency_poet,
    "pop_v1": latency_pop_v1,
    "pop_v2": latency_pop_v2,
    "pbft": lambda n, net, c, rng, tl: latency_pbft(n, net, c, rng),
    "raft": lambda n, net, c, rng, tl: latency_raft(n, net, c, rng),
}


def message_counts(n: int) -> dict[str, int]:
    """Messages per block for each algorithm (order of magnitude check)."""
    m = max(1, n // 2)
    return {"pow2": n - 1, "poet": n - 1, "pop_v1": 3 * n + m, "pop_v2": n - 1,
            "pbft": (n - 1) + 2 * n * (n - 1), "raft": 2 * (n - 1) + (n - 1)}
