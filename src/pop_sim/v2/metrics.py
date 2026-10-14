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
    accepted_times: dict = field(default_factory=dict)   # (pid, holder or None) -> times a forgery was accepted (V2V)
    # denominators, from the widest to the narrowest (review G08, H01):
    # key_checks = held_by_self + retired_skips + expired_key_seconds + valid_key_seconds,
    # eligible <= valid_key_seconds, sent <= eligible
    key_checks: int = 0              # every retained key examined, every second
    held_by_self: int = 0            # ... that the attacker currently holds itself
    retired_skips: int = 0           # ... retired labels (fresh modes: the label is never used again)
    expired_key_seconds: int = 0     # ... whose retained certificate has expired: never sent
    valid_key_seconds: int = 0       # ... unexpired and not held by the attacker
    eligible: int = 0                # ... and the strategy's condition held (S1/S2: another vehicle transmitting
                                     #     under the pseudonym; S3: nobody holding it)

    def to_dict(self) -> dict:
        return {"sent": self.sent, "accepted_v2v": self.accepted_v2v, "receivers_total": self.receivers_total,
                "receivers_accepting": self.receivers_accepting, "accepted_rsu": self.accepted_rsu,
                "key_checks": self.key_checks, "held_by_self": self.held_by_self,
                "retired_skips": self.retired_skips, "expired_key_seconds": self.expired_key_seconds,
                "valid_key_seconds": self.valid_key_seconds,
                "eligible": self.eligible, "holdings_with_accepted_forgeries": len(self.accepted_times)}


def forged_acceptance(stats: ForgeryStats) -> dict:
    """Rates with their denominators; a rate with a zero denominator is None
    (not tested), never 0 (review R02, R16)."""
    return {
        "v2v_message_rate": stats.accepted_v2v / stats.sent if stats.sent else None,
        "v2v_receiver_rate": stats.receivers_accepting / stats.receivers_total if stats.receivers_total else None,
        "rsu_rate": stats.accepted_rsu / stats.sent if stats.sent else None,
    }


def exposure_windows(accepted_times: dict, gap: float = 2.0, horizon_end: float | None = None) -> dict:
    """Exposure to accepted forgeries, per holding (review G03, H03).

    ``accepted_times`` maps a holding (pseudonym, holder) to the times a forged
    message under it was accepted by at least one receiver.  A *window* is a
    run of accepted seconds in which no two consecutive acceptances are more
    than ``gap`` seconds apart; a holding may have several.  Two durations are
    kept per window: ``span_s``, first to last accepted second inclusive, which
    counts tolerated gaps of up to ``gap`` seconds, and ``accepted_s``, the
    number of distinct seconds with an accepted forgery.  A window whose last
    acceptance is within ``gap`` of ``horizon_end`` is ``truncated``: the run
    ended, not the exposure, so its span is a lower bound on its natural
    duration.  The *cumulative* exposure of a holding sums its windows."""
    segments, cumulative = [], []
    for key, times in accepted_times.items():
        ts = sorted(set(times))
        if not ts:
            continue
        pid, holder = key if isinstance(key, tuple) else (key, None)
        span_total = acc_total = 0.0
        start = prev = ts[0]
        n = 1
        for t in ts[1:] + [None]:
            if t is None or t - prev > gap:
                truncated = horizon_end is not None and prev >= horizon_end - gap
                segments.append({"pid": pid, "holder": holder, "start": start, "end": prev,
                                 "span_s": prev - start + 1.0, "accepted_s": float(n), "truncated": truncated})
                span_total += prev - start + 1.0
                acc_total += n
                if t is None:
                    break
                start, n = t, 0
            n += 1
            prev = t
        cumulative.append({"pid": pid, "holder": holder, "span_s": span_total, "accepted_s": acc_total})

    def _summ(vals):
        return {"mean": statistics.mean(vals) if vals else None, "p95": pooled_percentile(vals, 0.95),
                "n": len(vals)}

    spans = [x["span_s"] for x in segments]
    return {"contiguous": {**_summ(spans), "truncated": sum(x["truncated"] for x in segments)},
            "contiguous_accepted_s": _summ([x["accepted_s"] for x in segments]),
            "contiguous_complete": _summ([x["span_s"] for x in segments if not x["truncated"]]),
            "cumulative_per_holding": _summ([c["span_s"] for c in cumulative]),
            "segments": segments, "holdings": cumulative}


def clustered_bootstrap_mean(groups: list[list[float]], resamples: int = 2000, seed: int = 0) -> dict:
    """Mean of all values pooled over groups (each value weighs the same), with
    a 95 % bootstrap interval that resamples whole groups (seeds), since values
    from one seed share its traffic (review H03)."""
    groups = [list(g) for g in groups if g is not None]
    pooled = [v for g in groups for v in g]
    if not pooled:
        return {"mean": None, "lo": None, "hi": None, "n": 0, "clusters": len(groups), "weighting": "per window"}
    rng = random.Random(seed)
    means = []
    for _ in range(resamples):
        pick = [v for g in rng.choices(groups, k=len(groups)) for v in g]
        if pick:
            means.append(statistics.mean(pick))
    means.sort()
    return {"mean": statistics.mean(pooled), "lo": means[int(0.025 * len(means))],
            "hi": means[min(len(means) - 1, int(0.975 * len(means)))], "n": len(pooled),
            "clusters": len(groups), "weighting": "per window, bootstrap over seeds"}


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
                    pid_seconds: dict[str, float], driven_seconds: float | None = None) -> dict:
    """``histories``: vehicle -> pseudonym holdings in the order used.  Permanent
    ids are nodes of the union-find too (prefix ``VEH-``); any other node (a
    forged-message node, say) is neither a holding nor an identity.

    Besides link rate, pairwise precision, identity rate and largest-cluster
    coverage, reports what coverage alone cannot (review R15):

    * ``purity``: beacon-seconds in each cluster that belong to its majority
      vehicle, over all beacon-seconds;
    * ``pair_recall``: same-vehicle holding pairs that share a cluster;
    * ``correct_identity_beacon_share``: share of observed beacon-seconds whose
      cluster carries exactly one permanent identity and it is the true one;
      ``wrong_identity_beacon_share`` one identity but another vehicle's;
      ``ambiguous_identity_beacon_share`` two or
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
        # shares of observed beacon-seconds (all vehicles' beacon-seconds pooled; review G07)
        "correct_identity_beacon_share": share(correct_s),
        "wrong_identity_beacon_share": share(wrong_s),
        "ambiguous_identity_beacon_share": share(ambiguous_s),
        # shares of driven time: every vehicle-second on the road, silent and
        # unserved seconds included (they carry no observation, so no attribution)
        "correct_identity_driven_share": correct_s / driven_seconds if driven_seconds else None,
        "trajectory_coverage": statistics.mean(coverage) if coverage else None,
        "changes": changes, "pairs": pairs, "beacon_seconds": total_s, "driven_seconds": driven_seconds,
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
    encrypt: float = 3e-4            # fixed cost of one ECIES encryption (key agreement, KDF)
    decrypt: float = 3e-4
    source: str = "assumed"
    encrypt_per_byte: float = 0.0    # plus this per plaintext byte (review G10: packages are large)
    decrypt_per_byte: float = 0.0


def calibrate_op_costs(samples: int = 200) -> tuple[OpCosts, dict]:
    """Time ECDSA P-256 sign / verify / keygen and ECIES encrypt / decrypt on
    this machine; returns the coefficients and the environment they hold for."""
    import platform
    import time as _t

    import cryptography

    from .. import crypto

    k = crypto.generate_keypair()
    msg = b"x" * 120
    big = b"x" * 65536                # about a PKI package of 150 pseudonyms with their keys
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

    def _time_ecies(payload: bytes) -> tuple[float, float]:
        t1 = _t.perf_counter()
        for _ in range(samples):
            ct = crypto.encrypt(k.pk, payload)
        e = (_t.perf_counter() - t1) / samples
        t1 = _t.perf_counter()
        for _ in range(samples):
            crypto.decrypt(k.sk, ct)
        return e, (_t.perf_counter() - t1) / samples

    enc_s, dec_s = _time_ecies(msg)
    enc_b, dec_b = _time_ecies(big)
    span = len(big) - len(msg)
    enc_pb, dec_pb = max(0.0, (enc_b - enc_s) / span), max(0.0, (dec_b - dec_s) / span)
    enc, dec = max(0.0, enc_s - enc_pb * len(msg)), max(0.0, dec_s - dec_pb * len(msg))
    env = {"machine": platform.machine(), "processor": platform.processor(), "python": platform.python_version(),
           "system": platform.platform(), "cryptography": cryptography.__version__, "samples": samples,
           "ecies_payload_sizes": [len(msg), len(big)]}
    return OpCosts(sign, verify, keygen, enc, dec, "measured", enc_pb, dec_pb), env


def cpu_breakdown(load: dict, costs: OpCosts) -> dict:
    """Modelled CPU seconds per operation (review G10)."""
    return {"sign": load.get("signatures", 0) * costs.sign,
            "verify": load.get("verifications", 0) * costs.verify,
            "keygen": load.get("keygens", 0) * costs.keygen,
            "encrypt": load.get("encryptions", 0) * costs.encrypt
            + load.get("encrypted_bytes", 0) * costs.encrypt_per_byte,
            "decrypt": load.get("decryptions", 0) * costs.decrypt
            + load.get("decrypted_bytes", 0) * costs.decrypt_per_byte}


def cpu_seconds(load: dict, costs: OpCosts) -> float:
    return sum(cpu_breakdown(load, costs).values())


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


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the regularized incomplete beta (Lentz)."""
    tiny, qab, qap, qam = 1e-300, a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c if abs(1.0 + aa / c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c if abs(1.0 + aa / c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return h


def _betainc(a: float, b: float, x: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbt = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x)
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbt) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbt) * _betacf(b, a, 1.0 - x) / b


def t_cdf(t: float, df: float) -> float:
    """Student-t distribution function."""
    x = df / (df + t * t)
    tail = 0.5 * _betainc(df / 2.0, 0.5, x)
    return 1.0 - tail if t > 0 else tail


def t_ppf(q: float, df: float) -> float:
    """Student-t quantile by bisection on ``t_cdf``."""
    lo, hi = -1e3, 1e3
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if t_cdf(mid, df) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def paired_equivalence(a: list, b: list, margin: float, alpha: float = 0.05) -> dict:
    """Mean equivalence of paired values a and b within +/- margin (review R12, G06).

    Estimand: the mean paired difference a - b.  Test: two one-sided paired
    t-tests (TOST) of H0: mean <= -margin and H0: mean >= +margin; equivalence
    is concluded when both are rejected at ``alpha``, which is the same as the
    (1 - 2 alpha) t confidence interval for the mean lying inside the margin
    (reported as ``ci90``).  Assumes the paired differences are roughly normal
    (or n large enough for the mean); ``ci95`` is the t interval for the same
    mean.  Only pairs where both values exist are used (``n_valid``)."""
    d = [float(x) - float(y) for x, y in zip(a, b) if x is not None and y is not None]
    n = len(d)
    base = {"n_valid": n, "margin": margin, "estimand": "mean paired difference", "test": "paired t TOST"}
    if n < 2:
        return {**base, "mean_diff": statistics.mean(d) if d else None, "sd_diff": None, "ci90": None, "ci95": None,
                "p_lower": None, "p_upper": None, "p_tost": None, "equivalent": None}
    m = statistics.mean(d)
    sd = statistics.stdev(d)
    df = n - 1
    se = sd / math.sqrt(n)
    if se == 0.0:
        inside = -margin < m < margin
        p_lower = p_upper = 0.0 if inside else 1.0
        ci90 = ci95 = (m, m)
    else:
        p_lower = 1.0 - t_cdf((m + margin) / se, df)      # H1: mean > -margin
        p_upper = t_cdf((m - margin) / se, df)            # H1: mean < +margin
        q90, q95 = t_ppf(1.0 - alpha, df), t_ppf(0.975, df)
        ci90 = (m - q90 * se, m + q90 * se)
        ci95 = (m - q95 * se, m + q95 * se)
    p = max(p_lower, p_upper)
    return {**base, "mean_diff": m, "sd_diff": sd, "ci90": ci90, "ci95": ci95,
            "p_lower": p_lower, "p_upper": p_upper, "p_tost": p, "equivalent": p < alpha}
