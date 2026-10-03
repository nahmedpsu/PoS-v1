"""A Global Passive Adversary that tracks vehicles through pseudonym changes.

The manuscript's unlinkability argument is that pseudonyms change.  A real
eavesdropper does not only read the pseudonym: it also sees position, speed
and heading, and can continue a trajectory across a pseudonym change by
predicting where the vehicle will be next.  This adversary does exactly
that (constant-velocity prediction, nearest-neighbour gating), so that
unlinkability becomes a measured number: the fraction of pseudonym changes
the adversary links correctly, and how long it can follow a vehicle.
"""

from __future__ import annotations

from dataclasses import dataclass

from .mobility import Beacon


@dataclass
class Track:
    track_id: int
    last: Beacon
    pids: list[str]
    truth: list[int]              # ground truth of every beacon on the track
    length: int = 1
    gap: float = 0.0              # seconds since the last beacon (dead reckoning)


@dataclass
class TrackingReport:
    beacons: int
    pseudonym_changes: int
    changes_linked_correctly: int
    changes_linked_wrongly: int
    changes_lost: int
    mean_track_length: float
    longest_correct_run: float
    vehicles: int

    @property
    def linking_success(self) -> float:
        return self.changes_linked_correctly / self.pseudonym_changes if self.pseudonym_changes else 0.0

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["linking_success"] = self.linking_success
        return d


class TrackingAdversary:
    def __init__(self, length_m: float, gate_m: float = 8.0, dt: float = 1.0, max_gap: float = 20.0,
                 gate_growth_m_per_s: float = 1.5):
        """``max_gap``: how long a track is kept alive by dead reckoning when
        its vehicle is silent; the matching gate widens by
        ``gate_growth_m_per_s`` for every silent second (speed uncertainty)."""
        self.length_m = length_m
        self.gate = gate_m
        self.dt = dt
        self.max_gap = max_gap
        self.gate_growth = gate_growth_m_per_s
        self.tracks: dict[int, Track] = {}
        self._next = 0
        self.closed: list[Track] = []
        self.changes = 0
        self.correct = 0
        self.wrong = 0
        self.lost = 0
        self.beacons = 0
        self.vehicles: set[int] = set()

    def _dist(self, a: float, b: float) -> float:
        d = abs(a - b) % self.length_m
        return min(d, self.length_m - d)

    def observe(self, beacons: list[Beacon]) -> None:
        """Assign this instant's beacons to tracks."""
        self.beacons += len(beacons)
        self.vehicles.update(b.truth_vid for b in beacons)
        unassigned = list(beacons)
        matched_tracks: set[int] = set()

        # 1. Same pseudonym -> trivially the same track.
        by_pid = {t.last.pid: t for t in self.tracks.values()}
        rest = []
        for b in unassigned:
            t = by_pid.get(b.pid)
            if t is not None and t.track_id not in matched_tracks:
                self._extend(t, b)
                matched_tracks.add(t.track_id)
            else:
                rest.append(b)

        # 2. Pseudonym changed: predict every unmatched track's position and
        #    take the closest unmatched beacon in the same direction within the gate.
        candidates = [t for t in self.tracks.values() if t.track_id not in matched_tracks]
        pairs = []
        for t in candidates:
            elapsed = t.gap + self.dt
            pred = (t.last.x + t.last.direction * t.last.v * elapsed) % self.length_m
            gate = self.gate + self.gate_growth * t.gap
            for b in rest:
                if b.direction != t.last.direction:
                    continue
                d = self._dist(pred, b.x)
                if d <= gate:
                    pairs.append((d, t.track_id, id(b), t, b))
        pairs.sort(key=lambda p: p[0])
        used_b: set[int] = set()
        for d, tid, bid, t, b in pairs:
            if tid in matched_tracks or bid in used_b:
                continue
            matched_tracks.add(tid)
            used_b.add(bid)
            self.changes += 1
            if b.truth_vid == t.truth[-1]:
                self.correct += 1
            else:
                self.wrong += 1
            self._extend(t, b)

        # 3. Tracks that got nothing coast by dead reckoning until ``max_gap``;
        #    beacons that matched nothing start new tracks.
        for t in candidates:
            if t.track_id not in matched_tracks:
                t.gap += self.dt
                if t.gap > self.max_gap:
                    self.closed.append(self.tracks.pop(t.track_id))
        for b in rest:
            if id(b) not in used_b:
                self._start(b)

    def _extend(self, t: Track, b: Beacon) -> None:
        if b.pid != t.last.pid:
            t.pids.append(b.pid)
        t.last = b
        t.truth.append(b.truth_vid)
        t.length += 1
        t.gap = 0.0

    def _start(self, b: Beacon) -> None:
        self.tracks[self._next] = Track(self._next, b, [b.pid], [b.truth_vid])
        self._next += 1

    def count_lost_changes(self, true_changes: int) -> None:
        """Pseudonym changes that produced no link at all (track ended)."""
        self.lost = max(0, true_changes - self.correct - self.wrong)

    def report(self, true_changes: int | None = None) -> TrackingReport:
        tracks = list(self.tracks.values()) + self.closed
        if true_changes is not None:
            self.count_lost_changes(true_changes)
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
