"""SUMO floating-car-data (FCD) import: drive the simulation with a recorded
trace instead of the synthetic ring road.

``sumo --fcd-output trace.xml`` writes one ``<timestep time="..">`` element
per second with ``<vehicle id= x= y= lane= pos= speed= angle= .../>``
children.  The simulator's road model is one-dimensional (position along a
corridor), so this importer maps each vehicle to a corridor coordinate:

* ``corridor="lane"``: the lane's ``pos`` attribute, offset by the cumulative
  length of the preceding edges in ``edge_order`` (a straight road or a
  ring described by its edge sequence);
* ``corridor="xy"``: the projection of (x, y) on the axis between two
  reference points (a highway section without junctions).

Direction is +1 when the corridor coordinate increases between consecutive
timesteps, -1 otherwise.  Vehicles present in the trace but not in the
chosen corridor are ignored.  ``TraceRoad`` has the ``Road`` interface the
protocol uses (``vehicles``, ``step``, ``rsu_of``, ``beacons``, ``cfg``), so
``ITSConfig(road=...)`` cannot take it directly; use ``ITSSimulation.with_road``
or set ``sim.road`` before running.  Only synthetic traces are exercised by the
tests here; a real SUMO scenario is a file the user supplies.
"""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .mobility import Beacon, MobileVehicle, RoadConfig


@dataclass
class FcdFrame:
    time: float
    vehicles: dict[str, tuple[float, float, str, float, float]]   # id -> (x, y, lane, pos, speed)


def parse_fcd(path: str) -> list[FcdFrame]:
    """Parse an FCD file into frames (streaming; large files are fine)."""
    frames: list[FcdFrame] = []
    for _, el in ET.iterparse(path, events=("end",)):
        if el.tag == "timestep":
            vs = {}
            for v in el.findall("vehicle"):
                vs[v.get("id")] = (float(v.get("x", 0.0)), float(v.get("y", 0.0)), v.get("lane", ""),
                                   float(v.get("pos", 0.0)), float(v.get("speed", 0.0)))
            frames.append(FcdFrame(float(el.get("time")), vs))
            el.clear()
    return frames


@dataclass
class Corridor:
    mode: str = "lane"                       # "lane" | "xy"
    edge_order: list[str] = field(default_factory=list)      # lane mode: edge ids in corridor order
    edge_lengths: dict[str, float] = field(default_factory=dict)
    axis: tuple[tuple[float, float], tuple[float, float]] | None = None   # xy mode: two reference points
    ring: bool = False

    def length(self) -> float:
        if self.mode == "lane":
            return sum(self.edge_lengths.get(e, 0.0) for e in self.edge_order)
        (x0, y0), (x1, y1) = self.axis
        return math.hypot(x1 - x0, y1 - y0)

    def coordinate(self, x: float, y: float, lane: str, pos: float) -> float | None:
        if self.mode == "lane":
            edge = lane.rsplit("_", 1)[0] if lane else ""
            if edge not in self.edge_order:
                return None
            offset = sum(self.edge_lengths.get(e, 0.0) for e in self.edge_order[: self.edge_order.index(edge)])
            return offset + pos
        (x0, y0), (x1, y1) = self.axis
        dx, dy = x1 - x0, y1 - y0
        L = math.hypot(dx, dy)
        if L <= 0:
            return None
        t = ((x - x0) * dx + (y - y0) * dy) / L
        return t if 0 <= t <= L else None


class TraceRoad:
    """``Road`` replacement fed by FCD frames."""

    def __init__(self, frames: list[FcdFrame], corridor: Corridor, n_rsu: int = 6, seed: int = 1):
        if not frames:
            raise ValueError("empty trace")
        self.frames = frames
        self.corridor = corridor
        length = corridor.length()
        self.cfg = RoadConfig(length_m=length, n_rsu=n_rsu, seed=seed)
        self.seg = length / n_rsu
        self.t = frames[0].time
        self._i = 0
        self._ids: dict[str, int] = {}
        self._prev_x: dict[int, float] = {}
        self.vehicles: list[MobileVehicle] = []
        # every vehicle that ever enters the corridor, at its first position: the
        # protocol provisions all of them at build time, so that one entering the
        # corridor mid-run is allotted pseudonyms at the next round
        self.all_vehicles: list[MobileVehicle] = []
        for f in frames:
            for sid, (x, y, lane, pos, speed) in f.vehicles.items():
                c = corridor.coordinate(x, y, lane, pos)
                if c is None or sid in self._ids:
                    continue
                self.all_vehicles.append(MobileVehicle(self._vid(sid), c, speed, +1))
        self._load_frame(0)

    def _vid(self, sumo_id: str) -> int:
        if sumo_id not in self._ids:
            self._ids[sumo_id] = len(self._ids)
        return self._ids[sumo_id]

    def rsu_of(self, x: float) -> int:
        return int(x // self.seg) % self.cfg.n_rsu

    def _load_frame(self, i: int) -> None:
        f = self.frames[i]
        self.t = f.time
        present: dict[int, MobileVehicle] = {v.vid: v for v in self.vehicles}
        new: list[MobileVehicle] = []
        for sid, (x, y, lane, pos, speed) in f.vehicles.items():
            c = self.corridor.coordinate(x, y, lane, pos)
            if c is None:
                continue
            vid = self._vid(sid)
            prev = self._prev_x.get(vid)
            direction = +1 if prev is None or c >= prev else -1
            v = present.get(vid) or MobileVehicle(vid, c, speed, direction)
            v.x, v.v, v.direction = c, speed, direction
            v.rsu = self.rsu_of(c)
            self._prev_x[vid] = c
            new.append(v)
        self.vehicles = new

    @property
    def is_ring(self) -> bool:
        return self.corridor.ring

    @property
    def all_vehicle_ids(self) -> list[int]:
        return [v.vid for v in self.all_vehicles]

    @property
    def present_share(self) -> float:
        """Share of the trace's vehicles present in the current frame."""
        return len(self.vehicles) / max(1, len(self.all_vehicles))

    def step(self, dt: float = 1.0) -> None:
        if self._i + 1 < len(self.frames):
            self._i += 1
            self._load_frame(self._i)
        else:
            self.t += dt                     # trace exhausted: freeze positions

    def vehicles_in_rsu(self, rsu: int) -> list[MobileVehicle]:
        return [v for v in self.vehicles if v.rsu == rsu]

    def beacons(self, pid_of: dict[int, str]) -> list[Beacon]:
        out = []
        for v in self.vehicles:
            pid = pid_of.get(v.vid)
            if pid is not None:
                out.append(Beacon(self.t, pid, v.x, v.v, v.direction, v.rsu, v.vid))
        return out

    @classmethod
    def from_file(cls, path: str, corridor: Corridor, n_rsu: int = 6, seed: int = 1) -> "TraceRoad":
        return cls(parse_fcd(path), corridor, n_rsu, seed)


def synthetic_fcd(path: str, vehicles: int = 20, seconds: int = 60, edge_len: float = 1000.0,
                  edges=("e0", "e1", "e2"), seed: int = 1) -> dict[str, float]:
    """Write a small FCD file (for tests and examples). Returns the edge lengths."""
    import random

    rng = random.Random(seed)
    L = edge_len * len(edges)
    state = {f"veh{i}": [rng.uniform(0, L), rng.uniform(8, 20)] for i in range(vehicles)}
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<fcd-export>"]
    for t in range(seconds):
        lines.append(f'    <timestep time="{t:.2f}">')
        for sid, (x, v) in state.items():
            e = min(int(x // edge_len), len(edges) - 1)
            pos = x - e * edge_len
            lines.append(f'        <vehicle id="{sid}" x="{x:.2f}" y="0.00" angle="90.00" type="car" speed="{v:.2f}" '
                         f'pos="{pos:.2f}" lane="{edges[e]}_0" slope="0.00"/>')
            state[sid][0] = (x + v) % L
        lines.append("    </timestep>")
    lines.append("</fcd-export>")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    return {e: edge_len for e in edges}
