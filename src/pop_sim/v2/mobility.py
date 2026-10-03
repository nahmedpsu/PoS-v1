"""A mobility model: vehicles on a two-direction ring road covered by RSUs.

The manuscript says shuffling happens "at zones where there is maximum
traffic" but never moves a vehicle.  Here vehicles drive, cross RSU
coverage areas, and beacon their state at a fixed interval (the Cooperative
Awareness Message of Section IV).  Traffic density is a Poisson parameter
so the same experiment can be run on an empty road at night and on a
congested one.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


@dataclass
class RoadConfig:
    length_m: float = 5000.0          # ring road length
    n_rsu: int = 6                    # equal coverage segments
    density_per_km: float = 6.0       # vehicles per km per direction
    speed_mean: float = 14.0          # m/s (about 50 km/h)
    speed_sd: float = 3.0
    accel_sd: float = 0.5             # random speed change per second
    beacon_interval: float = 1.0      # s
    seed: int = 1


@dataclass
class MobileVehicle:
    vid: int
    x: float
    v: float
    direction: int                    # +1 or -1
    rsu: int = 0


@dataclass
class Beacon:
    """What a Cooperative Awareness Message exposes to an eavesdropper."""
    t: float
    pid: str
    x: float
    v: float
    direction: int
    rsu: int
    truth_vid: int = field(repr=False, default=-1)   # hidden ground truth, scoring only


class Road:
    def __init__(self, cfg: RoadConfig):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.t = 0.0
        self.vehicles: list[MobileVehicle] = []
        self.seg = cfg.length_m / cfg.n_rsu
        n = max(1, int(round(self.rng.gauss(0, 0) + cfg.density_per_km * cfg.length_m / 1000)))
        for d in (+1, -1):
            k = self._poisson(n)
            for _ in range(k):
                self.add_vehicle(d)

    def _poisson(self, lam: float) -> int:
        # Knuth's method is fine for the sizes used here.
        L, k, p = math.exp(-lam), 0, 1.0
        while p > L:
            k += 1
            p *= self.rng.random()
        return k - 1

    def add_vehicle(self, direction: int) -> MobileVehicle:
        v = MobileVehicle(len(self.vehicles), self.rng.uniform(0, self.cfg.length_m),
                          max(3.0, self.rng.gauss(self.cfg.speed_mean, self.cfg.speed_sd)), direction)
        v.rsu = self.rsu_of(v.x)
        self.vehicles.append(v)
        return v

    def rsu_of(self, x: float) -> int:
        return int(x // self.seg) % self.cfg.n_rsu

    def step(self, dt: float) -> None:
        c = self.cfg
        for v in self.vehicles:
            v.v = min(max(3.0, v.v + self.rng.gauss(0, c.accel_sd * dt)), c.speed_mean + 3 * c.speed_sd)
            v.x = (v.x + v.direction * v.v * dt) % c.length_m
            v.rsu = self.rsu_of(v.x)
        self.t += dt

    def vehicles_in_rsu(self, rsu: int) -> list[MobileVehicle]:
        return [v for v in self.vehicles if v.rsu == rsu]

    def beacons(self, pid_of: dict[int, str]) -> list[Beacon]:
        """One beacon per vehicle that currently holds a pseudonym."""
        out = []
        for v in self.vehicles:
            pid = pid_of.get(v.vid)
            if pid is None:
                continue
            out.append(Beacon(self.t, pid, v.x, v.v, v.direction, v.rsu, v.vid))
        return out
