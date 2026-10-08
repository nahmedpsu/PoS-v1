"""Experiments E1 to E6 of the pseudonym recycling study.

Every cell is run over several seeds; seeded runs are byte-identical and the
traffic is the same in every issuance mode for a given seed, so comparisons
across modes are paired.  Each experiment writes one JSON file.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import asdict

from .shuffle import ISSUANCE_MODES, ITSConfig, ITSSimulation
from .v2 import attacks as atk
from .v2.metrics import bootstrap_ci, wilcoxon_signed_rank
from .v2.mobility import RoadConfig

DEFAULT_SEEDS = tuple(range(1, 11))


def _base(density: float, seed: int, **kw) -> ITSConfig:
    cfg = dict(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=density, seed=seed),
               round_seconds=30, pseudonyms_per_vehicle=3, safety_stock=0.25, seed=seed, silent_period=3,
               position_noise_m=3, attribution="ledger", v2v=True)
    cfg.update(kw)
    return ITSConfig(**cfg)


def _run(cfg: ITSConfig, rounds: int) -> dict:
    sim = ITSSimulation(cfg)
    sim.run(rounds)
    s = sim.summary()
    r = s["recycling"]
    out = {"vehicles": len(sim.vehicles), "revoked": s["linkability"]["revoked_vehicles"], "stockouts": s["stockouts"],
           "tracking": s["tracking"], "v2v": r["v2v"], "load": r["load"], "insider": r.get("insider"),
           "forgery": r.get("forgery"), "revoked_persistence": r.get("revoked_persistence"),
           "rejected_messages": sum(x["rejected_messages"] for x in s["rounds"])}
    return out


def _agg(rows: list[dict], path: list[str]) -> dict:
    vals = []
    for r in rows:
        v = r
        for k in path:
            v = v.get(k) if isinstance(v, dict) and v is not None else None
            if v is None:
                break
        if isinstance(v, (int, float)):
            vals.append(float(v))
    return bootstrap_ci(vals)


def _attackers(n_vehicles_est: int, share: float) -> int:
    return max(1, round(n_vehicles_est * share))


# ------------------------------------------------------------------ E1
def exp_e1_impersonation(seeds=DEFAULT_SEEDS, rounds: int = 4, strategies=("S1", "S2", "S3"),
                         plausibility=(False, True), lifetimes=(300, 900, 3600), densities=(10,),
                         attacker_shares=(0.05,), extra_density_sweep=(2, 10, 40, 80),
                         extra_share_sweep=(0.01, 0.05, 0.10)) -> dict:
    """RQ1: how long and how often can a former holder sign messages that
    other vehicles accept?  Core factorial: strategy x plausibility x
    lifetime; plus a density sweep and an attacker-share sweep at the
    middle lifetime."""
    cells = []
    for st in strategies:
        for pl in plausibility:
            for lt in lifetimes:
                for d in densities:
                    for sh in attacker_shares:
                        cells.append({"strategy": st, "plausibility": pl, "lifetime": lt, "density": d, "share": sh, "sweep": "core"})
    for d in extra_density_sweep:
        for st in strategies:
            cells.append({"strategy": st, "plausibility": True, "lifetime": 900, "density": d, "share": 0.05, "sweep": "density"})
    for sh in extra_share_sweep:
        for st in strategies:
            cells.append({"strategy": st, "plausibility": True, "lifetime": 900, "density": 10, "share": sh, "sweep": "share"})
    results = []
    for c in cells:
        rows = []
        for seed in seeds:
            est = int(2 * c["density"] * 5)      # two directions on 5 km
            cfg = _base(c["density"], seed, issuance="recycle", former_holders=_attackers(est, c["share"]),
                        former_holder_strategy=c["strategy"], v2v_plausibility=c["plausibility"],
                        pseudonym_lifetime=float(c["lifetime"]))
            rows.append(_run(cfg, rounds))
        results.append({**c, "seeds": len(rows),
                        "forged_sent": _agg(rows, ["forgery", "sent"]),
                        "v2v_message_rate": _agg(rows, ["forgery", "v2v_message_rate"]),
                        "v2v_receiver_rate": _agg(rows, ["forgery", "v2v_receiver_rate"]),
                        "rsu_rate": _agg(rows, ["forgery", "rsu_rate"]),
                        "exposure_mean_s": _agg(rows, ["forgery", "exposure", "mean"]),
                        "exposure_p95_s": _agg(rows, ["forgery", "exposure", "p95"]),
                        "victims_blamed": _agg(rows, ["forgery", "victims_blamed"]),
                        "honest_revoked": _agg(rows, ["revoked"])})
    return {"experiment": "E1_impersonation", "rounds": rounds, "cells": results}


# ------------------------------------------------------------------ E2
def exp_e2_revocation(seeds=DEFAULT_SEEDS, rounds: int = 4, lifetimes=(300, 900, 3600), density: float = 10) -> dict:
    """RQ2: does revoking a vehicle stop its messages from being accepted by
    other vehicles?  One misbehaving vehicle, caught by the RSU, keeps
    transmitting; V2V receivers never see the ledger."""
    results = []
    for lt in lifetimes:
        rows = []
        for seed in seeds:
            cfg = _base(density, seed, issuance="recycle", malicious_vehicles=1, revoked_keep_transmitting=True,
                        pseudonym_lifetime=float(lt), attribution="oracle")
            r = _run(cfg, rounds)
            rp = r["revoked_persistence"] or {}
            acc = [v["accepted_after"] for v in rp.values()]
            last = [v["seconds_to_last"] for v in rp.values()]
            rows.append({"revoked": len(rp), "accepted_after": statistics.mean(acc) if acc else 0.0,
                         "seconds_to_last": statistics.mean(last) if last else 0.0})
        results.append({"lifetime": lt, "seeds": len(rows),
                        "revoked_vehicles": _agg(rows, ["revoked"]),
                        "post_revocation_accepted": _agg(rows, ["accepted_after"]),
                        "seconds_to_last_accepted": _agg(rows, ["seconds_to_last"])})
    return {"experiment": "E2_revocation", "rounds": rounds, "cells": results}


# ------------------------------------------------------------------ E3
def exp_e3_insider(seeds=DEFAULT_SEEDS, rounds: int = 4, densities=(10, 40), orders=("kept", "shuffled")) -> dict:
    """RQ3: what can each insider link, alone and with the outside tracker."""
    results = []
    for d in densities:
        for order in orders:
            rows = []
            for seed in seeds:
                cfg = _base(d, seed, issuance="recycle", shuffle_before_upload=(order == "shuffled"))
                rows.append(_run(cfg, rounds))
            table = {}
            for entity in rows[0]["insider"]:
                table[entity] = {m: _agg(rows, ["insider", entity, m])
                                 for m in ("link_rate", "precision", "identity_rate", "trajectory_coverage")}
            results.append({"density": d, "cloud_order": order, "seeds": len(rows), "table": table})
    return {"experiment": "E3_insider", "rounds": rounds, "cells": results}


# ------------------------------------------------------------------ E4
def exp_e4_modes(seeds=DEFAULT_SEEDS, rounds: int = 4, densities=(10, 40), modes=ISSUANCE_MODES,
                 strategy: str = "S2") -> dict:
    """RQ4: modes against axes.  Same seed = same traffic, so paired."""
    results = []
    paired: dict[str, dict[str, list[float]]] = {}
    for d in densities:
        for mode in modes:
            rows = []
            for seed in seeds:
                est = int(2 * d * 5)
                cfg = _base(d, seed, issuance=mode, former_holders=_attackers(est, 0.05), former_holder_strategy=strategy,
                            v2v_plausibility=True, pseudonym_lifetime=900.0)
                rows.append(_run(cfg, rounds))
            cell = {"density": d, "mode": mode, "seeds": len(rows),
                    "tracker_link_rate": _agg(rows, ["tracking", "linking_success"]),
                    "forged_sent": _agg(rows, ["forgery", "sent"]),
                    "forged_v2v_accepted": _agg(rows, ["forgery", "accepted_v2v"]),
                    "victims_blamed": _agg(rows, ["forgery", "victims_blamed"]),
                    "insider_pm_link_rate": _agg(rows, ["insider", "pm", "link_rate"]),
                    "insider_cloud_link_rate": _agg(rows, ["insider", "cloud", "link_rate"]),
                    "pki_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pki_cpu_s_per_1000_veh_h"]),
                    "pm_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pm_cpu_s_per_1000_veh_h"]),
                    "pki_signatures": _agg(rows, ["load", "steady_state", "pki", "signatures"]),
                    "pm_signatures": _agg(rows, ["load", "steady_state", "pm", "signatures"]),
                    "vehicle_keygens_per_vehicle_per_round": _agg(rows, ["load", "vehicle_keygens_per_vehicle_per_round"]),
                    "bytes_per_vehicle_per_round": _agg(rows, ["load", "bytes_per_vehicle_per_round"]),
                    "stockouts": _agg(rows, ["stockouts"])}
            results.append(cell)
            for metric in ("tracker_link_rate", "pki_cpu_s_per_1000_veh_h", "forged_v2v_accepted"):
                paired.setdefault(f"{d}/{metric}", {})[mode] = [
                    (r.get("tracking") or {}).get("linking_success", 0.0) if metric == "tracker_link_rate" else
                    r["load"]["pki_cpu_s_per_1000_veh_h"] if metric == "pki_cpu_s_per_1000_veh_h" else
                    (r.get("forgery") or {}).get("accepted_v2v", 0) for r in rows]
    tests = {}
    for key, by_mode in paired.items():
        if "recycle" in by_mode:
            for mode, vals in by_mode.items():
                if mode != "recycle":
                    tests[f"{key}: recycle vs {mode}"] = wilcoxon_signed_rank(by_mode["recycle"], vals)
    return {"experiment": "E4_modes", "rounds": rounds, "strategy": strategy, "cells": results, "paired_tests": tests}


# ------------------------------------------------------------------ E5
def exp_e5_fix(seeds=DEFAULT_SEEDS, rounds: int = 4, density: float = 10, variants=("window", "rekey", "fresh_vgk"),
               strategies=("S1", "S2", "S3")) -> dict:
    results = []
    for var in variants:
        for st in strategies:
            rows = []
            for seed in seeds:
                est = int(2 * density * 5)
                cfg = _base(density, seed, issuance=var, former_holders=_attackers(est, 0.05), former_holder_strategy=st,
                            v2v_plausibility=False, pseudonym_lifetime=900.0)
                rows.append(_run(cfg, rounds))
            results.append({"variant": var, "strategy": st, "seeds": len(rows),
                            "forged_sent": _agg(rows, ["forgery", "sent"]),
                            "forged_v2v_accepted": _agg(rows, ["forgery", "accepted_v2v"]),
                            "v2v_message_rate": _agg(rows, ["forgery", "v2v_message_rate"]),
                            "victims_blamed": _agg(rows, ["forgery", "victims_blamed"]),
                            "pm_signatures": _agg(rows, ["load", "steady_state", "pm", "signatures"]),
                            "pki_signatures": _agg(rows, ["load", "steady_state", "pki", "signatures"]),
                            "vehicle_keygens_per_vehicle_per_round": _agg(rows, ["load", "vehicle_keygens_per_vehicle_per_round"]),
                            "bytes_per_vehicle_per_round": _agg(rows, ["load", "bytes_per_vehicle_per_round"])})
    return {"experiment": "E5_fix", "rounds": rounds, "cells": results}


# ------------------------------------------------------------------ E6
def exp_e6_bench_recheck(quick: bool = False) -> dict:
    """The existing 18-attack bench under oracle and ledger attribution."""
    out = {}
    for attribution in ("oracle", "ledger"):
        res = atk.run_all(quick=quick, attribution=attribution)
        out[attribution] = {r["name"]: r["outcome"] for r in res["results"]}
        out[f"{attribution}_summary"] = res["summary"]
    changes = {k: (out["oracle"][k], out["ledger"][k]) for k in out["oracle"] if out["oracle"][k] != out["ledger"][k]}
    return {"experiment": "E6_bench_recheck", "outcomes": out, "changed": changes}


def run_all(quick: bool = False, seeds=None) -> dict:
    seeds = tuple(seeds) if seeds else ((1, 2) if quick else DEFAULT_SEEDS)
    rounds = 2 if quick else 4
    t0 = time.perf_counter()
    out = {}
    if quick:
        out["E1"] = exp_e1_impersonation(seeds, rounds, lifetimes=(300, 3600), extra_density_sweep=(2, 40), extra_share_sweep=(0.05,))
        out["E2"] = exp_e2_revocation(seeds, rounds, lifetimes=(300, 3600))
        out["E3"] = exp_e3_insider(seeds, rounds, densities=(10,))
        out["E4"] = exp_e4_modes(seeds, rounds, densities=(10,))
        out["E5"] = exp_e5_fix(seeds, rounds, strategies=("S2", "S3"))
    else:
        out["E1"] = exp_e1_impersonation(seeds, rounds)
        out["E2"] = exp_e2_revocation(seeds, rounds)
        out["E3"] = exp_e3_insider(seeds, rounds)
        out["E4"] = exp_e4_modes(seeds, rounds)
        out["E5"] = exp_e5_fix(seeds, rounds)
    out["E6"] = exp_e6_bench_recheck(quick=quick)
    out["config"] = {"seeds": list(seeds), "rounds": rounds, "quick": quick, "base": asdict(_base(10, 1))}
    out["wall_seconds"] = time.perf_counter() - t0
    return out


# ------------------------------------------------------- longer horizon (E1x, E2x)
def exp_e1_lifetime_long(seeds=DEFAULT_SEEDS, rounds: int = 20, lifetimes=(300, 900, 3600), strategies=("S1", "S2", "S3"),
                         density: float = 10, share: float = 0.05) -> dict:
    """E1 over a horizon longer than the shortest certificate lifetime
    (20 rounds of 30 s = 600 s), so that expiry and PKI renewal actually
    happen.  Plausibility on, ledger attribution."""
    results = []
    for st in strategies:
        for lt in lifetimes:
            rows = []
            for seed in seeds:
                est = int(2 * density * 5)
                cfg = _base(density, seed, issuance="recycle", former_holders=_attackers(est, share),
                            former_holder_strategy=st, v2v_plausibility=True, pseudonym_lifetime=float(lt))
                rows.append(_run(cfg, rounds))
            results.append({"strategy": st, "lifetime": lt, "seeds": len(rows), "sim_seconds": rounds * 30,
                            "forged_sent": _agg(rows, ["forgery", "sent"]),
                            "v2v_receiver_rate": _agg(rows, ["forgery", "v2v_receiver_rate"]),
                            "rsu_rate": _agg(rows, ["forgery", "rsu_rate"]),
                            "exposure_mean_s": _agg(rows, ["forgery", "exposure", "mean"]),
                            "exposure_p95_s": _agg(rows, ["forgery", "exposure", "p95"]),
                            "victims_blamed": _agg(rows, ["forgery", "victims_blamed"]),
                            "honest_revoked": _agg(rows, ["revoked"]),
                            "pki_renewals": _agg(rows, ["load", "steady_state", "pki", "signatures"]),
                            "v2v_expired_rejections": _agg(rows, ["v2v", "rejected", "certificate-expired"])})
    return {"experiment": "E1x_lifetime_long", "rounds": rounds, "cells": results}


def exp_e2_long(seeds=DEFAULT_SEEDS, rounds: int = 20, lifetimes=(300, 900, 3600), density: float = 10) -> dict:
    """E2 over 600 s: how long a revoked vehicle keeps being believed when its
    certificates can expire inside the horizon."""
    results = []
    for lt in lifetimes:
        rows = []
        for seed in seeds:
            cfg = _base(density, seed, issuance="recycle", malicious_vehicles=1, revoked_keep_transmitting=True,
                        pseudonym_lifetime=float(lt), attribution="oracle")
            r = _run(cfg, rounds)
            rp = r["revoked_persistence"] or {}
            acc = [v["accepted_after"] for v in rp.values()]
            last = [v["seconds_to_last"] for v in rp.values()]
            rows.append({"revoked": len(rp), "accepted_after": statistics.mean(acc) if acc else 0.0,
                         "seconds_to_last": statistics.mean(last) if last else 0.0})
        results.append({"lifetime": lt, "seeds": len(rows), "sim_seconds": rounds * 30,
                        "revoked_vehicles": _agg(rows, ["revoked"]),
                        "post_revocation_accepted": _agg(rows, ["accepted_after"]),
                        "seconds_to_last_accepted": _agg(rows, ["seconds_to_last"])})
    return {"experiment": "E2x_long", "rounds": rounds, "cells": results}
