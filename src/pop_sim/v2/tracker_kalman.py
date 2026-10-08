"""A stronger tracking adversary: per-track Kalman filter with global
nearest-neighbour assignment (Hungarian algorithm).

The baseline tracker in ``adversary.py`` predicts with the last velocity
and matches greedily within a fixed gate.  This one keeps a constant-
velocity Kalman filter per track (state x, v; process noise on
acceleration), gates on the Mahalanobis distance so the gate grows with
the filter's uncertainty during silence, and solves the assignment of all
tracks to all beacons at once, which removes the greedy tracker's order
dependence.  It is the standard GNN tracker of the tracking literature and
gives a more conservative privacy bound.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .adversary import TrackingReport
from .mobility import Beacon


# ------------------------------------------------------------------ Hungarian
def hungarian(cost: list[list[float]]) -> list[tuple[int, int]]:
    """Minimum-cost assignment for a rectangular matrix (rows <= cols after
    padding).  Returns (row, col) pairs for real rows/cols only.
    O(n^3) implementation of the Kuhn-Munkres algorithm."""
    if not cost or not cost[0]:
        return []
    n_rows, n_cols = len(cost), len(cost[0])
    n = max(n_rows, n_cols)
    big = 1e9
    a = [[cost[i][j] if i < n_rows and j < n_cols else big for j in range(n)] for i in range(n)]
    u = [0.0] * (n + 1)
    v = [0.0] * (n + 1)
    p = [0] * (n + 1)
    way = [0] * (n + 1)
    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [math.inf] * (n + 1)
        used = [False] * (n + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = math.inf
            j1 = 0
            for j in range(1, n + 1):
                if not used[j]:
                    cur = a[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j] = cur
                        way[j] = j0
                    if minv[j] < delta:
                        delta = minv[j]
                        j1 = j
            for j in range(n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    out = []
    for j in range(1, n + 1):
        i = p[j]
        if 0 < i <= n_rows and j <= n_cols and a[i - 1][j - 1] < big / 2:
            out.append((i - 1, j - 1))
    return out


# -------------------------------------------------------------------- Kalman
@dataclass
class KTrack:
    track_id: int
    x: float                  # position estimate
    v: float                  # velocity estimate
    P: list[list[float]]      # 2x2 covariance
    direction: int
    last: Beacon
    pids: list[str]
    truth: list[int]
    length: int = 1
    gap: float = 0.0


class KalmanTrackingAdversary:
    """Same interface as ``TrackingAdversary``: ``observe(beacons)`` per
    time step and ``report(true_changes)`` at the end."""

    def __init__(self, length_m: float, dt: float = 1.0, max_gap: float = 20.0, gate_sigma: float = 3.5,
                 accel_sd: float = 1.0, pos_noise_sd: float = 3.0, vel_noise_sd: float = 1.0):
        self.length_m = length_m
        self.dt = dt
        self.max_gap = max_gap
        self.gate2 = gate_sigma ** 2
        self.q = accel_sd ** 2
        self.r_pos = pos_noise_sd ** 2
        self.r_vel = vel_noise_sd ** 2
        self.tracks: dict[int, KTrack] = {}
        self.closed: list[KTrack] = []
        self._next = 0
        self.changes = self.correct = self.wrong = self.lost = self.beacons = 0
        self.vehicles: set[int] = set()
        self.linked_pairs: list[tuple[str, str]] = []     # (old pid, new pid) the tracker decided to link

    # -- geometry on a ring
    def _wrap(self, d: float) -> float:
        d = (d + self.length_m / 2) % self.length_m - self.length_m / 2
        return d

    # -- Kalman steps for state (x, v), F = [[1, dt], [0, 1]]
    def _predict(self, t: KTrack, dt: float) -> tuple[float, float, list[list[float]]]:
        x = (t.x + t.direction * t.v * dt) % self.length_m
        v = t.v
        p = t.P
        q = self.q
        # Q for a piecewise-constant white acceleration model
        Q = [[q * dt ** 4 / 4, q * dt ** 3 / 2], [q * dt ** 3 / 2, q * dt ** 2]]
        P = [[p[0][0] + dt * (p[1][0] + p[0][1]) + dt * dt * p[1][1] + Q[0][0], p[0][1] + dt * p[1][1] + Q[0][1]],
             [p[1][0] + dt * p[1][1] + Q[1][0], p[1][1] + Q[1][1]]]
        return x, v, P

    def _mahalanobis2(self, t: KTrack, b: Beacon, pred) -> float:
        x, v, P = pred
        dx = self._wrap(b.x - x)
        dv = b.v - v
        s00, s11 = P[0][0] + self.r_pos, P[1][1] + self.r_vel
        s01 = P[0][1]
        det = s00 * s11 - s01 * s01
        if det <= 0:
            return math.inf
        return (s11 * dx * dx - 2 * s01 * dx * dv + s00 * dv * dv) / det

    def _update(self, t: KTrack, b: Beacon, pred) -> None:
        x, v, P = pred
        dx = self._wrap(b.x - x)
        dv = b.v - v
        s00, s11, s01 = P[0][0] + self.r_pos, P[1][1] + self.r_vel, P[0][1]
        det = s00 * s11 - s01 * s01
        inv = [[s11 / det, -s01 / det], [-s01 / det, s00 / det]]
        K = [[P[0][0] * inv[0][0] + P[0][1] * inv[1][0], P[0][0] * inv[0][1] + P[0][1] * inv[1][1]],
             [P[1][0] * inv[0][0] + P[1][1] * inv[1][0], P[1][0] * inv[0][1] + P[1][1] * inv[1][1]]]
        t.x = (x + K[0][0] * dx + K[0][1] * dv) % self.length_m
        t.v = v + K[1][0] * dx + K[1][1] * dv
        I_K = [[1 - K[0][0], -K[0][1]], [-K[1][0], 1 - K[1][1]]]
        t.P = [[I_K[0][0] * P[0][0] + I_K[0][1] * P[1][0], I_K[0][0] * P[0][1] + I_K[0][1] * P[1][1]],
               [I_K[1][0] * P[0][0] + I_K[1][1] * P[1][0], I_K[1][0] * P[0][1] + I_K[1][1] * P[1][1]]]

    # -- main step
    def observe(self, beacons: list[Beacon]) -> None:
        self.beacons += len(beacons)
        self.vehicles.update(b.truth_vid for b in beacons)
        tracks = list(self.tracks.values())
        preds = {t.track_id: self._predict(t, t.gap + self.dt) for t in tracks}
        matched_t: set[int] = set()
        used_b: set[int] = set()

        # 1. same pseudonym: continuation, unless the beacon is nowhere near the
        #    track's prediction (a recycled pseudonym reappearing on another
        #    vehicle); then it is a new track
        by_pid = {t.last.pid: t for t in tracks}
        for i, b in enumerate(beacons):
            t = by_pid.get(b.pid)
            if t is not None and t.track_id not in matched_t:
                if self._mahalanobis2(t, b, preds[t.track_id]) > 16 * self.gate2 or b.direction != t.direction:
                    continue
                self._extend(t, b, preds[t.track_id])
                matched_t.add(t.track_id)
                used_b.add(i)

        # 2. pseudonym changed: global assignment on Mahalanobis distance within the gate
        rows = [t for t in tracks if t.track_id not in matched_t]
        cols = [i for i in range(len(beacons)) if i not in used_b]
        if rows and cols:
            for comp_rows, comp_cols, cost in self._components(rows, cols, beacons, preds):
                for r, c in hungarian(cost):
                    if cost[r][c] >= 1e9:
                        continue
                    t, b = comp_rows[r], beacons[comp_cols[c]]
                    self.changes += 1
                    self.linked_pairs.append((t.last.node or t.last.pid, b.node or b.pid))
                    if b.truth_vid == t.truth[-1]:
                        self.correct += 1
                    else:
                        self.wrong += 1
                    self._extend(t, b, preds[t.track_id])
                    matched_t.add(t.track_id)
                    used_b.add(comp_cols[c])

        # 3. coast or close unmatched tracks; start tracks for unmatched beacons
        for t in rows:
            if t.track_id not in matched_t:
                t.gap += self.dt
                if t.gap > self.max_gap:
                    self.closed.append(self.tracks.pop(t.track_id))
        for i, b in enumerate(beacons):
            if i not in used_b:
                self._start(b)

    def _components(self, rows, cols, beacons, preds):
        """Gated candidate pairs split into connected components, so that
        the assignment is solved on many small matrices instead of one
        n x n matrix (the gate makes the problem sparse: only vehicles
        near a track's prediction can be its continuation)."""
        # coarse spatial bucketing of beacons for the candidate search
        bucket = max(50.0, 4 * math.sqrt(self.gate2 * (self.r_pos + 50.0)))
        by_cell: dict[int, list[int]] = {}
        for i in cols:
            by_cell.setdefault(int(beacons[i].x // bucket), []).append(i)
        n_cells = int(self.length_m // bucket) + 1
        pairs: dict[int, dict[int, float]] = {}
        for ri, t in enumerate(rows):
            x_pred = preds[t.track_id][0]
            cell = int(x_pred // bucket)
            cand = []
            for dc in (-1, 0, 1):
                cand.extend(by_cell.get((cell + dc) % n_cells, []))
                cand.extend(by_cell.get(cell + dc, []))
            for i in set(cand):
                b = beacons[i]
                if b.direction != t.direction:
                    continue
                d2 = self._mahalanobis2(t, b, preds[t.track_id])
                if d2 <= self.gate2:
                    pairs.setdefault(ri, {})[i] = d2
        # union-find over rows and columns
        parent: dict[tuple[str, int], tuple[str, int]] = {}

        def find(a):
            while parent.setdefault(a, a) != a:
                parent[a] = parent[parent[a]]
                a = parent[a]
            return a

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for ri, cands in pairs.items():
            for i in cands:
                union(("r", ri), ("c", i))
        groups: dict[tuple[str, int], tuple[list[int], list[int]]] = {}
        for ri in pairs:
            groups.setdefault(find(("r", ri)), ([], []))[0].append(ri)
        for ri, cands in pairs.items():
            g = groups[find(("r", ri))]
            for i in cands:
                if i not in g[1]:
                    g[1].append(i)
        for r_idx, c_idx in groups.values():
            cost = [[pairs[ri].get(i, 1e9) for i in c_idx] for ri in r_idx]
            yield [rows[ri] for ri in r_idx], c_idx, cost

    def _extend(self, t: KTrack, b: Beacon, pred) -> None:
        self._update(t, b, pred)
        if b.pid != t.last.pid:
            t.pids.append(b.pid)
        t.last = b
        t.truth.append(b.truth_vid)
        t.length += 1
        t.gap = 0.0

    def _start(self, b: Beacon) -> None:
        self.tracks[self._next] = KTrack(self._next, b.x, b.v, [[self.r_pos, 0.0], [0.0, self.r_vel]],
                                         b.direction, b, [b.pid], [b.truth_vid])
        self._next += 1

    def report(self, true_changes: int | None = None) -> TrackingReport:
        tracks = list(self.tracks.values()) + self.closed
        if true_changes is not None:
            self.lost = max(0, true_changes - self.correct - self.wrong)
        runs = []
        for t in tracks:
            run = best = 1
            for a, b in zip(t.truth, t.truth[1:]):
                run = run + 1 if a == b else 1
                best = max(best, run)
            runs.append(best)
        return TrackingReport(
            beacons=self.beacons, pseudonym_changes=self.changes + self.lost,
            changes_linked_correctly=self.correct, changes_linked_wrongly=self.wrong, changes_lost=self.lost,
            mean_track_length=sum(t.length for t in tracks) / max(1, len(tracks)),
            longest_correct_run=sum(runs) / max(1, len(runs)), vehicles=len(self.vehicles))


def make_tracker(kind: str, length_m: float, gate_m: float = 8.0, dt: float = 1.0, max_gap: float = 20.0):
    """Factory shared by the experiments: ``"nn"`` (baseline) or ``"kalman"``."""
    if kind == "kalman":
        return KalmanTrackingAdversary(length_m, dt, max_gap)
    from .adversary import TrackingAdversary
    return TrackingAdversary(length_m, gate_m, dt, max_gap)
