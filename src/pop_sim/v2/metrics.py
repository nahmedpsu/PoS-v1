"""Metrics of the pseudonym recycling study, defined once.

Every experiment computes the same quantities through these functions:

* ``forged_acceptance``      share of the former holder's forged messages accepted
* ``exposure_windows``       per recycled pseudonym, the seconds during which forgeries were accepted
* ``post_revocation``        messages of a revoked vehicle accepted after revocation
* ``cluster_metrics``        link rate, precision, identity rate and trajectory coverage of an
                             identity clustering (union-find over pseudonyms)
* ``cpu_seconds``            authority load converted with measured per-operation costs
* ``bootstrap_ci``, ``wilcoxon_signed_rank``   the statistics the paper reports
"""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass, field


# ------------------------------------------------------------------ union-find
class UnionFind:
    def __init__(self):
        self.parent: dict = {}

    def find(self, a):
        p = self.parent.setdefault(a, a)
        while p != a:
            self.parent[a] = self.parent.setdefault(p, p)
            a, p = p, self.parent[p]
        return a

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def clusters(self) -> dict:
        out: dict = {}
        for a in list(self.parent):
            out.setdefault(self.find(a), []).append(a)
        return out


# ------------------------------------------------------------- attack metrics
@dataclass
class ForgeryStats:
    sent: int = 0
    accepted_v2v: int = 0            # forged messages accepted by at least one V2V receiver
    receivers_total: int = 0         # receivers in range of forged messages
    receivers_accepting: int = 0
    accepted_rsu: int = 0
    accepted_times: dict = field(default_factory=dict)   # pid -> sorted list of times a forgery was accepted (V2V)
    victims_blamed: int = 0          # misbehaviour reports that name the innocent holder

    def to_dict(self) -> dict:
        return {"sent": self.sent, "accepted_v2v": self.accepted_v2v, "receivers_total": self.receivers_total,
                "receivers_accepting": self.receivers_accepting, "accepted_rsu": self.accepted_rsu,
                "victims_blamed": self.victims_blamed, "pids_with_accepted_forgeries": len(self.accepted_times)}


def forged_acceptance(stats: ForgeryStats) -> dict:
    return {
        "v2v_message_rate": stats.accepted_v2v / stats.sent if stats.sent else 0.0,
        "v2v_receiver_rate": stats.receivers_accepting / stats.receivers_total if stats.receivers_total else 0.0,
        "rsu_rate": stats.accepted_rsu / stats.sent if stats.sent else 0.0,
    }


def exposure_windows(accepted_times: dict, gap: float = 2.0) -> dict:
    """Seconds during which forgeries under each pseudonym were accepted: the
    span from first to last accepted time, counting only stretches with no
    gap above ``gap`` seconds.  Returns mean and 95th percentile."""
    windows = []
    for pid, times in accepted_times.items():
        ts = sorted(times)
        if not ts:
            continue
        total = 0.0
        start = prev = ts[0]
        for t in ts[1:]:
            if t - prev > gap:
                total += prev - start + 1.0
                start = t
            prev = t
        total += prev - start + 1.0
        windows.append(total)
    if not windows:
        return {"mean": 0.0, "p95": 0.0, "n": 0}
    windows.sort()
    return {"mean": statistics.mean(windows), "p95": windows[min(len(windows) - 1, int(0.95 * len(windows)))],
            "n": len(windows)}


def post_revocation(accepted_after: list[float], revoked_at: float | None) -> dict:
    if revoked_at is None:
        return {"accepted": 0, "seconds_to_last": 0.0}
    later = [t for t in accepted_after if t >= revoked_at]
    return {"accepted": len(later), "seconds_to_last": (max(later) - revoked_at) if later else 0.0}


# ----------------------------------------------------------- linking metrics
def cluster_metrics(uf: UnionFind, histories: dict[str, list[str]], truth_of_pid: dict[str, str],
                    pid_seconds: dict[str, float]) -> dict:
    """``histories``: vehicle -> pseudonyms in the order used.  Permanent ids
    are nodes of the union-find too (prefix ``VEH-``)."""
    changes = correct = 0
    for vid, pids in histories.items():
        for a, b in zip(pids, pids[1:]):
            changes += 1
            if uf.find(a) == uf.find(b):
                correct += 1
    pairs = wrong = 0
    clusters = uf.clusters()
    identified = set()
    for members in clusters.values():
        pids = [m for m in members if m in truth_of_pid]
        vids = [m for m in members if m not in truth_of_pid]
        n = len(pids)
        pairs += n * (n - 1) // 2
        by_truth: dict[str, int] = {}
        for m in pids:
            by_truth[truth_of_pid[m]] = by_truth.get(truth_of_pid[m], 0) + 1
        same = sum(c * (c - 1) // 2 for c in by_truth.values())
        wrong += n * (n - 1) // 2 - same
        if vids:
            for v in vids:
                if any(truth_of_pid[m] == v for m in pids):
                    identified.add(v)
    # trajectory coverage: seconds of a vehicle's beacons that fall in its largest cluster
    coverage = []
    for vid, pids in histories.items():
        total = sum(pid_seconds.get(p, 0.0) for p in pids)
        if total <= 0:
            continue
        by_cluster: dict = {}
        for p in pids:
            by_cluster[uf.find(p)] = by_cluster.get(uf.find(p), 0.0) + pid_seconds.get(p, 0.0)
        coverage.append(max(by_cluster.values()) / total)
    return {
        "link_rate": correct / changes if changes else 0.0,
        "precision": 1 - wrong / pairs if pairs else 1.0,
        "identity_rate": len(identified) / len(histories) if histories else 0.0,
        "trajectory_coverage": statistics.mean(coverage) if coverage else 0.0,
        "changes": changes, "pairs": pairs,
    }


# ------------------------------------------------------------ authority load
@dataclass
class OpCosts:
    sign: float = 5e-5          # seconds, ECDSA P-256 (measured in experiments_v2.measure_crypto_costs)
    verify: float = 2e-4
    keygen: float = 1e-4


def cpu_seconds(load: dict, costs: OpCosts) -> float:
    return load.get("signatures", 0) * costs.sign + load.get("keygens", 0) * costs.keygen + \
        load.get("verifications", 0) * costs.verify


def per_1000_vehicles_per_hour(cpu: float, vehicles: int, sim_seconds: float) -> float:
    if vehicles <= 0 or sim_seconds <= 0:
        return 0.0
    return cpu / vehicles * 1000.0 / sim_seconds * 3600.0


# ----------------------------------------------------------------- statistics
def bootstrap_ci(values: list[float], resamples: int = 1000, seed: int = 0, level: float = 0.95) -> dict:
    vals = [float(v) for v in values]
    if not vals:
        return {"mean": 0.0, "lo": 0.0, "hi": 0.0, "n": 0}
    if len(vals) == 1:
        return {"mean": vals[0], "lo": vals[0], "hi": vals[0], "n": 1}
    rng = random.Random(seed)
    means = sorted(statistics.mean(rng.choices(vals, k=len(vals))) for _ in range(resamples))
    lo = means[int((1 - level) / 2 * resamples)]
    hi = means[min(resamples - 1, int((1 + level) / 2 * resamples))]
    return {"mean": statistics.mean(vals), "lo": lo, "hi": hi, "n": len(vals)}


def _exact_signed_rank_p(ranks: list[float], w_obs: float) -> float:
    """Exact two-sided p-value of the Wilcoxon signed-rank statistic: the
    probability, under the null that every sign is equally likely, that the
    smaller of W+ and W- is at most ``w_obs``.  Ranks may be half-integers
    (mid-ranks of ties), so the distribution is built on doubled ranks."""
    doubled = [int(round(2 * r)) for r in ranks]
    total = sum(doubled)
    dist = [1] + [0] * total                      # dist[k] = number of sign patterns with 2*W+ == k
    for d in doubled:
        for k in range(total, d - 1, -1):
            dist[k] += dist[k - d]
    w2 = int(round(2 * w_obs))
    n_patterns = 2 ** len(ranks)
    lower = sum(dist[: w2 + 1]) / n_patterns     # P(W+ <= w_obs)
    return min(1.0, 2 * lower)


def wilcoxon_signed_rank(a: list[float], b: list[float], exact_max_n: int = 25) -> dict:
    """Paired Wilcoxon signed-rank test and the matched-pairs rank-biserial
    effect size.  Up to ``exact_max_n`` non-zero differences the two-sided
    p-value is exact (enumeration of the 2^n sign patterns, ties mid-ranked);
    beyond that the normal approximation is used.  With ten pairs all in the
    same direction the exact p is 2/1024 = 0.002."""
    diffs = [float(x) - float(y) for x, y in zip(a, b) if float(x) != float(y)]
    n = len(diffs)
    if n == 0:
        return {"n": 0, "w_plus": 0.0, "w_minus": 0.0, "z": 0.0, "p": 1.0, "effect_size": 0.0, "method": "none"}
    order = sorted(range(n), key=lambda i: abs(diffs[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(diffs[order[j + 1]]) == abs(diffs[order[i]]):
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = r
        i = j + 1
    w_plus = sum(r for d, r in zip(diffs, ranks) if d > 0)
    w_minus = sum(r for d, r in zip(diffs, ranks) if d < 0)
    total = n * (n + 1) / 2
    mean = total / 2
    var = n * (n + 1) * (2 * n + 1) / 24
    z = (min(w_plus, w_minus) - mean) / math.sqrt(var) if var > 0 else 0.0
    if n <= exact_max_n:
        p = _exact_signed_rank_p(ranks, min(w_plus, w_minus))
        method = "exact"
    else:
        p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
        method = "normal"
    return {"n": n, "w_plus": w_plus, "w_minus": w_minus, "z": z, "p": min(1.0, p),
            "effect_size": (w_plus - w_minus) / total, "method": method}
