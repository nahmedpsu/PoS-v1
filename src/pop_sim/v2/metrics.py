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
    victims_blamed: int = 0          # misbehaviour reports that name the innocent holder (reports, not vehicles)
    victims_blamed_ids: set = field(default_factory=set)   # distinct innocent vehicles named at least once

    def to_dict(self) -> dict:
        return {"sent": self.sent, "accepted_v2v": self.accepted_v2v, "receivers_total": self.receivers_total,
                "receivers_accepting": self.receivers_accepting, "accepted_rsu": self.accepted_rsu,
                "victims_blamed": self.victims_blamed, "pids_with_accepted_forgeries": len(self.accepted_times)}


def forged_acceptance(stats: ForgeryStats) -> dict:
    """Rates with their denominators; a rate with a zero denominator is None
    (not tested), never 0 (review R02, R16)."""
    return {
        "v2v_message_rate": stats.accepted_v2v / stats.sent if stats.sent else None,
        "v2v_receiver_rate": stats.receivers_accepting / stats.receivers_total if stats.receivers_total else None,
        "rsu_rate": stats.accepted_rsu / stats.sent if stats.sent else None,
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
        return {"mean": None, "p95": None, "n": 0, "windows": []}
    windows.sort()
    return {"mean": statistics.mean(windows), "p95": pooled_percentile(windows, 0.95),
            "n": len(windows), "windows": windows}


def pooled_percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile of the pooled values (used across seeds too, so
    that a reported p95 is the p95 of all windows, not a mean of per-seed p95s)."""
    vals = sorted(values)
    if not vals:
        return None
    return vals[min(len(vals) - 1, max(0, int(math.ceil(q * len(vals))) - 1))]


def post_revocation(accepted_after: list[float], revoked_at: float | None) -> dict:
    if revoked_at is None:
        return {"accepted": 0, "seconds_to_last": 0.0}
    later = [t for t in accepted_after if t >= revoked_at]
    return {"accepted": len(later), "seconds_to_last": (max(later) - revoked_at) if later else 0.0}


# ----------------------------------------------------------- linking metrics
def cluster_metrics(uf: UnionFind, histories: dict[str, list[str]], truth_of_pid: dict[str, str],
                    pid_seconds: dict[str, float]) -> dict:
    """``histories``: vehicle -> pseudonym holdings in the order used.  Permanent
    ids are nodes of the union-find too (prefix ``VEH-``); any other node (a
    forged-message node, say) is neither a holding nor an identity.

    Besides link rate, pairwise precision, identity rate and largest-cluster
    coverage, reports what coverage alone cannot (review R15):

    * ``purity``: beacon-seconds in each cluster that belong to its majority
      vehicle, over all beacon-seconds;
    * ``pair_recall``: same-vehicle holding pairs that share a cluster;
    * ``correct_identity_seconds``: beacon-seconds whose cluster carries exactly
      one permanent identity and it is the true one; ``wrong_identity_seconds``
      one identity but another vehicle's; ``ambiguous_identity_seconds`` two or
      more identities; the rest carries none.  All as shares of beacon-seconds."""
    changes = correct = 0
    for vid, pids in histories.items():
        for a, b in zip(pids, pids[1:]):
            changes += 1
            if uf.find(a) == uf.find(b):
                correct += 1
    pairs = wrong = 0
    clusters = uf.clusters()
    identified = set()
    total_s = sum(pid_seconds.get(p, 0.0) for p in truth_of_pid)
    pure_s = correct_s = wrong_s = ambiguous_s = 0.0
    same_vehicle_pairs_in_cluster = 0
    for members in clusters.values():
        pids = [m for m in members if m in truth_of_pid]
        vids = [m for m in members if isinstance(m, str) and m.startswith("VEH-") and m not in truth_of_pid]
        n = len(pids)
        pairs += n * (n - 1) // 2
        by_truth: dict[str, int] = {}
        secs_by_truth: dict[str, float] = {}
        for m in pids:
            t = truth_of_pid[m]
            by_truth[t] = by_truth.get(t, 0) + 1
            secs_by_truth[t] = secs_by_truth.get(t, 0.0) + pid_seconds.get(m, 0.0)
        same = sum(c * (c - 1) // 2 for c in by_truth.values())
        same_vehicle_pairs_in_cluster += same
        wrong += n * (n - 1) // 2 - same
        if secs_by_truth:
            pure_s += max(secs_by_truth.values())
        for v in vids:
            if any(truth_of_pid[m] == v for m in pids):
                identified.add(v)
        cluster_s = sum(secs_by_truth.values())
        if len(vids) == 1:
            correct_s += secs_by_truth.get(vids[0], 0.0)
            wrong_s += cluster_s - secs_by_truth.get(vids[0], 0.0)
        elif len(vids) > 1:
            ambiguous_s += cluster_s
    all_same_vehicle_pairs = 0
    holdings_by_vehicle: dict[str, int] = {}
    for p, v in truth_of_pid.items():
        holdings_by_vehicle[v] = holdings_by_vehicle.get(v, 0) + 1
    all_same_vehicle_pairs = sum(c * (c - 1) // 2 for c in holdings_by_vehicle.values())
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
    share = (lambda x: x / total_s) if total_s > 0 else (lambda x: None)
    return {
        "link_rate": correct / changes if changes else None,
        "precision": 1 - wrong / pairs if pairs else None,
        "pair_recall": same_vehicle_pairs_in_cluster / all_same_vehicle_pairs if all_same_vehicle_pairs else None,
        "purity": share(pure_s),
        "identity_rate": len(identified) / len(histories) if histories else None,
        "correct_identity_seconds": share(correct_s),
        "wrong_identity_seconds": share(wrong_s),
        "ambiguous_identity_seconds": share(ambiguous_s),
        "trajectory_coverage": statistics.mean(coverage) if coverage else None,
        "changes": changes, "pairs": pairs, "beacon_seconds": total_s,
    }


# ------------------------------------------------------------ authority load
@dataclass
class OpCosts:
    """Per-operation CPU seconds.  The defaults are assumed coefficients;
    ``calibrate_op_costs`` measures them on the running machine (review R17).
    A CPU figure is (counted operations) x (coefficient): a modelled cost of
    the cryptography only, not a measured deployment cost (no database,
    replication, network service or queueing)."""
    sign: float = 5e-5
    verify: float = 2e-4
    keygen: float = 1e-4
    encrypt: float = 3e-4
    decrypt: float = 3e-4
    source: str = "assumed"


def calibrate_op_costs(samples: int = 200) -> tuple[OpCosts, dict]:
    """Time ECDSA P-256 sign / verify / keygen and ECIES encrypt / decrypt on
    this machine; returns the coefficients and the environment they hold for."""
    import platform
    import time as _t

    import cryptography

    from .. import crypto

    k = crypto.generate_keypair()
    msg = b"x" * 120
    t0 = _t.perf_counter()
    for _ in range(samples):
        crypto.generate_keypair()
    keygen = (_t.perf_counter() - t0) / samples
    t0 = _t.perf_counter()
    for _ in range(samples):
        sig = crypto.sign(k.sk, msg)
    sign = (_t.perf_counter() - t0) / samples
    t0 = _t.perf_counter()
    for _ in range(samples):
        crypto.verify(k.pk, msg, sig)
    verify = (_t.perf_counter() - t0) / samples
    t0 = _t.perf_counter()
    for _ in range(samples):
        ct = crypto.encrypt(k.pk, msg)
    enc = (_t.perf_counter() - t0) / samples
    t0 = _t.perf_counter()
    for _ in range(samples):
        crypto.decrypt(k.sk, ct)
    dec = (_t.perf_counter() - t0) / samples
    env = {"machine": platform.machine(), "processor": platform.processor(), "python": platform.python_version(),
           "system": platform.platform(), "cryptography": cryptography.__version__, "samples": samples}
    return OpCosts(sign, verify, keygen, enc, dec, "measured"), env


def cpu_seconds(load: dict, costs: OpCosts) -> float:
    return (load.get("signatures", 0) * costs.sign + load.get("keygens", 0) * costs.keygen
            + load.get("verifications", 0) * costs.verify + load.get("encryptions", 0) * costs.encrypt
            + load.get("decryptions", 0) * costs.decrypt)


def per_1000_vehicles_per_hour(cpu: float, vehicles: int, sim_seconds: float) -> float:
    if vehicles <= 0 or sim_seconds <= 0:
        return 0.0
    return cpu / vehicles * 1000.0 / sim_seconds * 3600.0


# ----------------------------------------------------------------- statistics
def bootstrap_ci(values: list[float], resamples: int = 1000, seed: int = 0, level: float = 0.95) -> dict:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return {"mean": None, "lo": None, "hi": None, "n": 0}     # nothing measured: not applicable, not zero
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


def _signed_rank_ranks(x: list[float]) -> list[tuple[float, float]]:
    """(value, mid-rank of |value|) for the non-zero values."""
    xs = [v for v in x if v != 0]
    order = sorted(range(len(xs)), key=lambda i: abs(xs[i]))
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(xs):
        j = i
        while j + 1 < len(xs) and abs(xs[order[j + 1]]) == abs(xs[order[i]]):
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return list(zip(xs, ranks))


def _one_sided_greater_p(x: list[float]) -> float:
    """Exact one-sided Wilcoxon signed-rank p for H1: the median of ``x`` is
    above zero (P(W+ >= observed) under symmetric signs)."""
    pairs = _signed_rank_ranks(x)
    if not pairs:
        return 1.0
    doubled = [int(round(2 * r)) for _, r in pairs]
    total = sum(doubled)
    dist = [1] + [0] * total
    for d in doubled:
        for k in range(total, d - 1, -1):
            dist[k] += dist[k - d]
    w_obs = int(round(2 * sum(r for v, r in pairs if v > 0)))
    return sum(dist[w_obs:]) / 2 ** len(pairs)


def paired_equivalence(a: list, b: list, margin: float, resamples: int = 2000, seed: int = 0) -> dict:
    """Paired comparison of a against b for an equivalence claim (review R12).

    Only pairs where both values exist are used (``n_valid``).  Reports the
    mean paired difference a - b with a 95 % bootstrap interval, and two
    one-sided exact signed-rank tests (TOST): equivalence within +/- margin is
    concluded when both one-sided p-values are below 0.05, which coincides
    with the difference lying inside the margin with 90 % confidence."""
    d = [float(x) - float(y) for x, y in zip(a, b) if x is not None and y is not None]
    n = len(d)
    if n == 0:
        return {"n_valid": 0, "margin": margin, "mean_diff": None, "ci95": None, "p_lower": None, "p_upper": None,
                "p_tost": None, "equivalent": None}
    rng = random.Random(seed)
    boots = sorted(statistics.mean(rng.choices(d, k=n)) for _ in range(resamples))
    ci = (boots[int(0.025 * resamples)], boots[min(resamples - 1, int(0.975 * resamples))])
    p_lower = _one_sided_greater_p([x + margin for x in d])     # H1: diff > -margin
    p_upper = _one_sided_greater_p([margin - x for x in d])     # H1: diff < +margin
    p = max(p_lower, p_upper)
    return {"n_valid": n, "margin": margin, "mean_diff": statistics.mean(d), "ci95": ci,
            "p_lower": p_lower, "p_upper": p_upper, "p_tost": p, "equivalent": p < 0.05}
