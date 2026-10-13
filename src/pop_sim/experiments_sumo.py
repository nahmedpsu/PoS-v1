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

from .experiments_recycling import (
    EQUIVALENCE_MARGIN,
    _agg,
    _attackers,
    _base,
    _forgery_fields,
    _revocation_fields,
    seed_record,
)
from .shuffle import ISSUANCE_MODES, ITSSimulation
from .v2.metrics import paired_equivalence, wilcoxon_signed_rank
from .v2.mobility_sumo import Corridor, FcdFrame, TraceRoad, parse_fcd


def load_corridor(path: str) -> Corridor:
    d = json.loads(open(path).read())
    if d.get("mode", "lane") == "xy":
        (x0, y0), (x1, y1) = d["axis"]
        return Corridor("xy", axis=((float(x0), float(y0)), (float(x1), float(y1))), ring=bool(d.get("ring", False)))
    return Corridor("lane", list(d["edge_order"]), {k: float(v) for k, v in d["edge_lengths"].items()},
                    ring=bool(d.get("ring", False)))


def trace_info(frames: list[FcdFrame], corridor: Corridor, run_seconds: int | None = None) -> dict:
    """Corridor statistics under distinct names (review R22): ``full_*`` over
    the whole trace, ``window_*`` over the first ``run_seconds`` frames, the
    part an experiment evaluates."""
    def stats(fs):
        present, speeds, ids = [], [], set()
        for f in fs:
            n = 0
            for sid, (x, y, lane, pos, speed) in f.vehicles.items():
                if corridor.coordinate(x, y, lane, pos) is None:
                    continue
                n += 1
                ids.add(sid)
                speeds.append(speed)
            present.append(n)
        length_km = corridor.length() / 1000.0
        return {"seconds": len(fs), "vehicles_seen": len(ids),
                "vehicles_present_mean": statistics.mean(present) if present else 0.0,
                "vehicles_present_max": max(present) if present else 0,
                "density_per_km": (statistics.mean(present) / length_km) if present and length_km else 0.0,
                "speed_mean_mps": statistics.mean(speeds) if speeds else 0.0}

    full = stats(frames)
    win = stats(frames[:run_seconds] if run_seconds else frames)
    out = {"frames": len(frames), "t_begin": frames[0].time if frames else None, "corridor_m": corridor.length(),
           "ring": corridor.ring, "run_seconds": run_seconds}
    out.update({f"full_{k}": v for k, v in full.items()})
    out.update({f"window_{k}": v for k, v in win.items()})
    return out


def _window_ids(road: TraceRoad, run_seconds: int) -> set[int]:
    ids = set()
    for f in road.frames[:run_seconds]:
        for sid, (x, y, lane, pos, speed) in f.vehicles.items():
            if road.corridor.coordinate(x, y, lane, pos) is not None and sid in road._ids:
                ids.add(road._ids[sid])
    return ids


def _run_trace(frames, corridor, seed: int, rounds: int, n_pm: int, rsus_per_pm: int, **kw) -> dict:
    road = TraceRoad(frames, corridor, n_rsu=n_pm * rsus_per_pm, seed=seed)
    road.window_ids = _window_ids(road, rounds * 30)          # attackers are drawn from the evaluated window (R22)
    cfg = _base(10, seed, n_pm=n_pm, rsus_per_pm=rsus_per_pm, **kw)
    sim = ITSSimulation(cfg, road=road)
    sim.run(rounds)
    s = sim.summary()
    r = s["recycling"]
    full = dict(s["linkability"]["population"])
    attackers = {v.vehicle_id for v in sim.vehicles if v.former_holder or v.malicious}
    in_window = [v for v in sim.vehicles if v.index in road.window_ids]
    honest_win = sum(1 for v in in_window if v.vehicle_id not in attackers)
    # Only vehicles that drive inside the evaluated window can be revoked; the
    # share is over them.  The whole trace's counts keep their own names (R22).
    pop = {"vehicles": len(in_window), "honest": honest_win, "attackers": full["attackers"],
           "vehicles_in_trace": full["vehicles"], "honest_in_trace": full["honest"],
           "revoked_total": full["revoked_total"], "revoked_honest": full["revoked_honest"],
           "revoked_attackers": full["revoked_attackers"],
           "revoked_honest_share": full["revoked_honest"] / honest_win if honest_win else None,
           "revoked_honest_share_of_trace": full["revoked_honest"] / full["honest"] if full["honest"] else None}
    return {"seed": seed, "vehicles": len(sim.vehicles), "population": pop, "stockouts": s["stockouts"],
            "departed_returns": s["departed_returns"], "departed_lost": s["departed_lost"],
            "attacker_vehicle_seconds": s["attacker_vehicle_seconds"], "vehicle_seconds": s["vehicle_seconds"],
            "achieved_attack_share": s["achieved_attack_share"],
            "tracking": s["tracking"], "v2v": r["v2v"], "load": r["load"], "insider": r.get("insider"),
            "forgery": r.get("forgery"), "retained_valid": r.get("retained_valid"),
            "reports": r.get("reports"), "retention": r.get("retention"),
            "rejected_messages": sum(x["rejected_messages"] for x in s["rounds"])}


def _window_fields(rows: list[dict]) -> dict:
    return {"achieved_attack_share": _agg(rows, ["achieved_attack_share"]),
            "attacker_vehicle_seconds": _agg(rows, ["attacker_vehicle_seconds"]),
            "vehicle_seconds": _agg(rows, ["vehicle_seconds"])}


def _pairs_and_tests(paired: dict, margin: float) -> tuple[dict, dict]:
    tests, eq = {}, {}
    for metric, by_mode in paired.items():
        for mode, vals in by_mode.items():
            if mode == "recycle":
                continue
            a = by_mode["recycle"]
            valid = [(x, y) for x, y in zip(a, vals) if x is not None and y is not None]
            name = f"{metric}: recycle vs {mode}"
            if not valid:
                tests[name] = {"n_valid": 0, "result": "not applicable: no attempts in at least one mode"}
                continue
            tests[name] = {**wilcoxon_signed_rank([x for x, _ in valid], [y for _, y in valid]), "n_valid": len(valid)}
            if metric.endswith("tracker_link_rate"):
                eq[name] = paired_equivalence(a, vals, margin)
    return tests, eq


def exp_sumo(trace: str, corridor_path: str, name: str, seeds=tuple(range(1, 11)), rounds: int = 4,
             strategies=("S1", "S2", "S3"), modes=ISSUANCE_MODES, share: float = 0.05, lifetime: float = 900.0,
             n_pm: int = 2, rsus_per_pm: int = 3, e4_strategy: str = "S2", margin: float = EQUIVALENCE_MARGIN) -> dict:
    """E1 (core cell: plausibility on, former holders are ``share`` of the
    vehicles seen in the evaluated window, 900 s certificates) and E4 (issuance
    modes, attack-free and joint, paired over seeds) on one SUMO trace.

    What varies across seeds (review R21): keys, which window vehicles are
    former holders, GPS noise and the protocol's own randomness.  The traffic is
    the trace's and is the same at every seed; seeds are not independent
    mobility realizations (see ``exp_sumo_realizations``)."""
    t0 = time.perf_counter()
    corridor = load_corridor(corridor_path)
    frames = parse_fcd(trace)
    info = trace_info(frames, corridor, run_seconds=rounds * 30)
    n_att = _attackers(info["window_vehicles_seen"], share)
    e1 = []
    for st in strategies:
        rows = [_run_trace(frames, corridor, seed, rounds, n_pm, rsus_per_pm, issuance="recycle", former_holders=n_att,
                           former_holder_strategy=st, v2v_plausibility=True, pseudonym_lifetime=lifetime) for seed in seeds]
        e1.append({"strategy": st, "seeds": len(rows), "attackers_selected": n_att, **_window_fields(rows),
                   **_forgery_fields(rows), **_revocation_fields(rows), "vehicles": _agg(rows, ["vehicles"]),
                   "per_seed": [seed_record(r) for r in rows]})
    e4, af = [], []
    paired: dict[str, dict[str, list]] = {}
    for mode in modes:
        free = [_run_trace(frames, corridor, seed, rounds, n_pm, rsus_per_pm, issuance=mode, v2v_plausibility=True,
                           pseudonym_lifetime=lifetime) for seed in seeds]
        af.append({"mode": mode, "seeds": len(free), "tracker_link_rate": _agg(free, ["tracking", "linking_success"]),
                   "true_changes": _agg(free, ["tracking", "true_changes"]), "stockouts": _agg(free, ["stockouts"]),
                   "per_seed": [seed_record(r) for r in free]})
        paired.setdefault("attack_free/tracker_link_rate", {})[mode] = [(r.get("tracking") or {}).get("linking_success") for r in free]
        rows = [_run_trace(frames, corridor, seed, rounds, n_pm, rsus_per_pm, issuance=mode, former_holders=n_att,
                           former_holder_strategy=e4_strategy, v2v_plausibility=True, pseudonym_lifetime=lifetime)
                for seed in seeds]
        e4.append({"mode": mode, "seeds": len(rows),
                   "tracker_link_rate": _agg(rows, ["tracking", "linking_success"]),
                   "true_changes": _agg(rows, ["tracking", "true_changes"]),
                   "tracker_relabel_captures": _agg(rows, ["tracking", "relabel_captures"]),
                   "forged_accepted_v2v": _agg(rows, ["forgery", "accepted_v2v"]),
                   **_forgery_fields(rows), **_revocation_fields(rows),
                   "insider_pm_link_rate": _agg(rows, ["insider", "pm", "link_rate"]),
                   "pki_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pki_cpu_s_per_1000_veh_h"]),
                   "pm_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pm_cpu_s_per_1000_veh_h"]),
                   "bytes_per_vehicle_per_round": _agg(rows, ["load", "bytes_per_vehicle_per_round"]),
                   "stockouts": _agg(rows, ["stockouts"]), "per_seed": [seed_record(r) for r in rows]})
        paired.setdefault("joint/tracker_link_rate", {})[mode] = [(r.get("tracking") or {}).get("linking_success") for r in rows]
        paired.setdefault("forged_accepted_v2v", {})[mode] = [
            (r.get("forgery") or {}).get("accepted_v2v") if (r.get("forgery") or {}).get("sent") else None for r in rows]
        paired.setdefault("pki_cpu_s_per_1000_veh_h", {})[mode] = [r["load"]["pki_cpu_s_per_1000_veh_h"] for r in rows]
    tests, eq = _pairs_and_tests(paired, margin)
    return {"experiment": f"SUMO_{name}", "trace": trace, "corridor": corridor_path, "trace_info": info,
            "rounds": rounds, "lifetime": lifetime, "share": share, "equivalence_margin": margin,
            "E1": e1, "E4": e4, "E4_attack_free": af, "paired_tests": tests, "equivalence": eq,
            "wall_seconds": time.perf_counter() - t0}


def exp_sumo_returns(trace: str, corridor_path: str, name: str, seeds=tuple(range(1, 6)), rounds: int = 4,
                     policies=((1.0, 0), (1.0, 2), (0.5, 0), (0.0, 0)), modes=("recycle", "fresh_vgk")) -> dict:
    """Review R21: the open-corridor return assumption.  Departing vehicles
    return their pseudonyms with probability p, d rounds late.  Reports
    stock-outs, lost pseudonyms and the attack-free link rate per policy."""
    corridor = load_corridor(corridor_path)
    frames = parse_fcd(trace)
    cells = []
    for p, d in policies:
        for mode in modes:
            rows = [_run_trace(frames, corridor, seed, rounds, 2, 3, issuance=mode, v2v_plausibility=True,
                               pseudonym_lifetime=900.0, departed_return_prob=p, departed_return_delay_rounds=d)
                    for seed in seeds]
            cells.append({"return_prob": p, "return_delay_rounds": d, "mode": mode, "seeds": len(rows),
                          "stockouts": _agg(rows, ["stockouts"]), "departed_lost": _agg(rows, ["departed_lost"]),
                          "departed_returns": _agg(rows, ["departed_returns"]),
                          "tracker_link_rate": _agg(rows, ["tracking", "linking_success"]),
                          "per_seed": [{"seed": r["seed"], "stockouts": r["stockouts"], "departed_lost": r["departed_lost"],
                                        "link": (r.get("tracking") or {}).get("linking_success")} for r in rows]})
    return {"experiment": f"SUMO_returns_{name}", "trace": trace, "rounds": rounds, "cells": cells}


def exp_sumo_realizations(traces: list[str], corridor_path: str, name: str, seeds=(1, 2), rounds: int = 4,
                          share: float = 0.05, modes=("recycle", "fresh", "fresh_vgk", "rekey")) -> dict:
    """Review R21: several independent traffic realizations (SUMO runs with
    different ``--seed``), a few protocol seeds each.  E1 S2 outcome and the
    attack-free link rate per mode, with the spread across realizations."""
    corridor = load_corridor(corridor_path)
    per_trace = []
    for tr in traces:
        frames = parse_fcd(tr)
        info = trace_info(frames, corridor, run_seconds=rounds * 30)
        n_att = _attackers(info["window_vehicles_seen"], share)
        e1 = [_run_trace(frames, corridor, sd, rounds, 2, 3, issuance="recycle", former_holders=n_att,
                         former_holder_strategy="S2", v2v_plausibility=True, pseudonym_lifetime=900.0) for sd in seeds]
        link = {m: [(_run_trace(frames, corridor, sd, rounds, 2, 3, issuance=m, v2v_plausibility=True,
                                pseudonym_lifetime=900.0).get("tracking") or {}).get("linking_success") for sd in seeds]
                for m in modes}
        per_trace.append({"trace": tr, "trace_info": info, "attackers_selected": n_att,
                          "e1_s2": {**_forgery_fields(e1), **_revocation_fields(e1)},
                          "attack_free_link_rate": {m: sum(v) / len(v) for m, v in link.items()}})
    agg = {m: _agg([{"x": t["attack_free_link_rate"][m]} for t in per_trace], ["x"]) for m in modes}
    return {"experiment": f"SUMO_realizations_{name}", "traces": traces, "seeds_per_trace": list(seeds),
            "per_trace": per_trace, "attack_free_link_rate_across_realizations": agg,
            "s2_receiver_rate_across_realizations": _agg([t["e1_s2"]["v2v_receiver_rate"] for t in per_trace], ["mean"]),
            "s2_honest_revoked_across_realizations": _agg([t["e1_s2"]["honest_revoked"] for t in per_trace], ["mean"])}
