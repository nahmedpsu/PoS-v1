"""E1 and E4 of the recycling study on a SUMO trace instead of the synthetic ring.

The trace fixes the traffic; the seeds vary the protocol's randomness (keys,
which vehicles are former holders, GPS noise).  A corridor JSON file maps the
trace onto the simulator's one-dimensional road::

    {"mode": "lane", "edge_order": ["e0", "e1"], "edge_lengths": {"e0": 1000, "e1": 900}, "ring": false}
    {"mode": "xy", "axis": [[0, 0], [6000, 0]], "ring": false}
"""

from __future__ import annotations

import json
import statistics
import time

from .experiments_recycling import _agg, _attackers, _base
from .shuffle import ISSUANCE_MODES, ITSSimulation
from .v2.metrics import wilcoxon_signed_rank
from .v2.mobility_sumo import Corridor, FcdFrame, TraceRoad, parse_fcd


def load_corridor(path: str) -> Corridor:
    d = json.loads(open(path).read())
    if d.get("mode", "lane") == "xy":
        (x0, y0), (x1, y1) = d["axis"]
        return Corridor("xy", axis=((float(x0), float(y0)), (float(x1), float(y1))), ring=bool(d.get("ring", False)))
    return Corridor("lane", list(d["edge_order"]), {k: float(v) for k, v in d["edge_lengths"].items()},
                    ring=bool(d.get("ring", False)))


def trace_info(frames: list[FcdFrame], corridor: Corridor, run_seconds: int | None = None) -> dict:
    """What the corridor sees: vehicles per frame, density, speed, horizon; the
    same for the first ``run_seconds`` frames (the part an experiment uses)."""
    present, speeds, ids, ids_run = [], [], set(), set()
    for k, f in enumerate(frames):
        n = 0
        for sid, (x, y, lane, pos, speed) in f.vehicles.items():
            if corridor.coordinate(x, y, lane, pos) is None:
                continue
            n += 1
            ids.add(sid)
            speeds.append(speed)
            if run_seconds is None or k < run_seconds:
                ids_run.add(sid)
        present.append(n)
    length_km = corridor.length() / 1000.0
    run = present[:run_seconds] if run_seconds else present
    return {"frames": len(frames), "seconds": frames[-1].time - frames[0].time + 1 if frames else 0,
            "t_begin": frames[0].time if frames else None, "corridor_m": corridor.length(), "ring": corridor.ring,
            "vehicles_total": len(ids), "vehicles_present_mean": statistics.mean(present) if present else 0.0,
            "vehicles_present_max": max(present) if present else 0,
            "density_per_km": (statistics.mean(present) / length_km) if present and length_km else 0.0,
            "speed_mean_mps": statistics.mean(speeds) if speeds else 0.0,
            "run_seconds": run_seconds, "vehicles_seen_in_run": len(ids_run),
            "vehicles_present_mean_in_run": statistics.mean(run) if run else 0.0}


def _run_trace(frames, corridor, seed: int, rounds: int, n_pm: int, rsus_per_pm: int, **kw) -> dict:
    road = TraceRoad(frames, corridor, n_rsu=n_pm * rsus_per_pm, seed=seed)
    cfg = _base(10, seed, n_pm=n_pm, rsus_per_pm=rsus_per_pm, **kw)
    sim = ITSSimulation(cfg, road=road)
    sim.run(rounds)
    s = sim.summary()
    r = s["recycling"]
    return {"vehicles": len(sim.vehicles), "revoked": s["linkability"]["revoked_vehicles"], "stockouts": s["stockouts"],
            "tracking": s["tracking"], "v2v": r["v2v"], "load": r["load"], "insider": r.get("insider"),
            "forgery": r.get("forgery"), "rejected_messages": sum(x["rejected_messages"] for x in s["rounds"])}


def exp_sumo(trace: str, corridor_path: str, name: str, seeds=tuple(range(1, 11)), rounds: int = 4,
             strategies=("S1", "S2", "S3"), modes=ISSUANCE_MODES, share: float = 0.05, lifetime: float = 900.0,
             n_pm: int = 2, rsus_per_pm: int = 3, e4_strategy: str = "S2") -> dict:
    """E1 (core cell: plausibility on, 5 % former holders, 900 s certificates)
    and E4 (issuance modes, paired over seeds) on one SUMO trace."""
    t0 = time.perf_counter()
    corridor = load_corridor(corridor_path)
    frames = parse_fcd(trace)
    info = trace_info(frames, corridor, run_seconds=rounds * 30)
    n_att = _attackers(info["vehicles_total"], share)
    e1 = []
    for st in strategies:
        rows = [_run_trace(frames, corridor, seed, rounds, n_pm, rsus_per_pm, issuance="recycle", former_holders=n_att,
                           former_holder_strategy=st, v2v_plausibility=True, pseudonym_lifetime=lifetime) for seed in seeds]
        e1.append({"strategy": st, "seeds": len(rows), "attackers": n_att,
                   "forged_sent": _agg(rows, ["forgery", "sent"]),
                   "v2v_receiver_rate": _agg(rows, ["forgery", "v2v_receiver_rate"]),
                   "rsu_rate": _agg(rows, ["forgery", "rsu_rate"]),
                   "exposure_mean_s": _agg(rows, ["forgery", "exposure", "mean"]),
                   "exposure_p95_s": _agg(rows, ["forgery", "exposure", "p95"]),
                   "victims_blamed": _agg(rows, ["forgery", "victims_blamed"]),
                   "honest_revoked": _agg(rows, ["revoked"]),
                   "vehicles": _agg(rows, ["vehicles"])})
    e4 = []
    paired: dict[str, dict[str, list[float]]] = {}
    for mode in modes:
        rows = [_run_trace(frames, corridor, seed, rounds, n_pm, rsus_per_pm, issuance=mode, former_holders=n_att,
                           former_holder_strategy=e4_strategy, v2v_plausibility=True, pseudonym_lifetime=lifetime)
                for seed in seeds]
        e4.append({"mode": mode, "seeds": len(rows),
                   "tracker_link_rate": _agg(rows, ["tracking", "linking_success"]),
                   "forged_v2v_accepted": _agg(rows, ["forgery", "accepted_v2v"]),
                   "victims_blamed": _agg(rows, ["forgery", "victims_blamed"]),
                   "insider_pm_link_rate": _agg(rows, ["insider", "pm", "link_rate"]),
                   "pki_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pki_cpu_s_per_1000_veh_h"]),
                   "pm_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pm_cpu_s_per_1000_veh_h"]),
                   "bytes_per_vehicle_per_round": _agg(rows, ["load", "bytes_per_vehicle_per_round"]),
                   "stockouts": _agg(rows, ["stockouts"])})
        paired.setdefault("tracker_link_rate", {})[mode] = [(r.get("tracking") or {}).get("linking_success", 0.0) for r in rows]
        paired.setdefault("forged_v2v_accepted", {})[mode] = [(r.get("forgery") or {}).get("accepted_v2v", 0) for r in rows]
        paired.setdefault("pki_cpu_s_per_1000_veh_h", {})[mode] = [r["load"]["pki_cpu_s_per_1000_veh_h"] for r in rows]
    tests = {f"{metric}: recycle vs {mode}": wilcoxon_signed_rank(by_mode["recycle"], vals)
             for metric, by_mode in paired.items() for mode, vals in by_mode.items() if mode != "recycle"}
    return {"experiment": f"SUMO_{name}", "trace": trace, "corridor": corridor_path, "trace_info": info,
            "rounds": rounds, "lifetime": lifetime, "share": share, "E1": e1, "E4": e4, "paired_tests": tests,
            "wall_seconds": time.perf_counter() - t0}
