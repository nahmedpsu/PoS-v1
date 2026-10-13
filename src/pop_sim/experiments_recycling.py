"""Experiments E1 to E6 of the pseudonym recycling study.

Every cell is run over several seeds; seeded runs are byte-identical and the
traffic is the same in every issuance mode for a given seed, so comparisons
across modes are paired.  Each experiment writes one JSON file.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import asdict

from . import clock
from .shuffle import ISSUANCE_MODES, ITSConfig, ITSSimulation
from .v2 import attacks as atk
from .v2.metrics import bootstrap_ci, paired_equivalence, pooled_percentile, wilcoxon_signed_rank
from .v2.mobility import RoadConfig

DEFAULT_SEEDS = tuple(range(1, 11))
_CALIBRATION: dict = {}


def calibrate(samples: int = 500) -> dict:
    """Measure the per-operation CPU coefficients once per process and make the
    simulator use them (review R17); returns them with the environment."""
    if not _CALIBRATION:
        from .shuffle import set_op_costs
        from .v2.metrics import calibrate_op_costs
        costs, env = calibrate_op_costs(samples)
        set_op_costs(costs)
        _CALIBRATION.update({"op_costs_s": {k: getattr(costs, k) for k in ("sign", "verify", "keygen", "encrypt", "decrypt",
                                                                    "encrypt_per_byte", "decrypt_per_byte")},
                             "source": costs.source, "environment": env})
    return dict(_CALIBRATION)
# (clone reports needed, distinct RSUs needed) before the PM asks the PKI to revoke a vehicle
REVOCATION_RULES = ((1, 1), (2, 1), (3, 1), (5, 1), (2, 2), (3, 2), (3, 3))


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
    pop = s["linkability"]["population"]
    assert pop["revoked_total"] == pop["revoked_honest"] + pop["revoked_attackers"]
    assert pop["vehicles"] == pop["honest"] + pop["attackers"]
    pop = {**pop, "revoked_honest_share": pop["revoked_honest"] / pop["honest"] if pop["honest"] else None}
    out = {"seed": cfg.seed, "vehicles": len(sim.vehicles), "population": pop, "stockouts": s["stockouts"],
           "tracking": s["tracking"], "v2v": r["v2v"], "load": r["load"], "insider": r.get("insider"),
           "forgery": r.get("forgery"), "revoked_persistence": r.get("revoked_persistence"),
           "retained_valid": r.get("retained_valid"), "reports": r.get("reports"), "retention": r.get("retention"),
           "rejected_messages": sum(x["rejected_messages"] for x in s["rounds"])}
    return out


def seed_record(r: dict) -> dict:
    """The per-seed numerators and denominators behind every aggregate (review
    R16): population and revocations, forgery counts with their opportunities,
    exposure windows, tracker counts."""
    f = r.get("forgery") or {}
    t = r.get("tracking") or {}
    rec = {"seed": r.get("seed"), "population": r.get("population"), "stockouts": r.get("stockouts")}
    if f:
        rec["forgery"] = {k: f.get(k) for k in ("key_checks", "valid_key_seconds", "eligible", "sent",
                                                 "accepted_v2v", "receivers_total", "receivers_accepting",
                                                 "accepted_rsu")}
        ex = f.get("exposure") or {}
        rec["forgery"]["exposure_segments"] = ex.get("segments", [])
        rec["forgery"]["exposure_cumulative_per_holding_s"] = (ex.get("cumulative_per_holding") or {}).get("values", [])
    rv = r.get("retained_valid") or []
    rec["retained_valid_end"] = rv[-1] if rv else None
    rec["retention"] = r.get("retention")
    rec["reports"] = r.get("reports")
    load = r.get("load") or {}
    if load:
        rec["load"] = {"steady_state": load.get("steady_state"),
                       "cpu_by_operation_per_1000_veh_h": load.get("cpu_by_operation_per_1000_veh_h")}
    if t:
        rec["tracking"] = {k: t.get(k) for k in ("true_changes", "pseudonym_changes", "changes_linked_correctly",
                                                  "changes_linked_wrongly", "changes_lost", "relabel_captures")}
    return rec


def _revocation_fields(rows: list[dict]) -> dict:
    """Disjoint revocation counts (review R01): honest, attackers and total,
    with the honest denominator, never a total labelled honest."""
    return {"population_honest": _agg(rows, ["population", "honest"]),
            "population_attackers": _agg(rows, ["population", "attackers"]),
            "honest_revoked": _agg(rows, ["population", "revoked_honest"]),
            "honest_revoked_share": _agg(rows, ["population", "revoked_honest_share"]),
            "attackers_revoked": _agg(rows, ["population", "revoked_attackers"]),
            "total_revoked": _agg(rows, ["population", "revoked_total"])}


def _forgery_fields(rows: list[dict]) -> dict:
    """Forgery outcomes with denominators (review R02, R16, G03, G08).  Rates
    are None where nothing was attempted.  Opportunities come in three tiers:
    raw key checks, valid-key seconds, eligible seconds (valid key and the
    strategy's condition).  Exposure is given per contiguous window and per
    holding (cumulative); both p95s are pooled over all seeds."""
    seg = [x["seconds"] for r in rows
           for x in (((r.get("forgery") or {}).get("exposure") or {}).get("segments") or [])]
    cens = sum(x["censored"] for r in rows
               for x in (((r.get("forgery") or {}).get("exposure") or {}).get("segments") or []))
    cum = [x for r in rows
           for x in ((((r.get("forgery") or {}).get("exposure") or {}).get("cumulative_per_holding") or {})
                     .get("values") or [])]
    return {"key_checks": _agg(rows, ["forgery", "key_checks"]),
            "valid_key_seconds": _agg(rows, ["forgery", "valid_key_seconds"]),
            "eligible": _agg(rows, ["forgery", "eligible"]),
            "forged_sent": _agg(rows, ["forgery", "sent"]),
            "v2v_message_rate": _agg(rows, ["forgery", "v2v_message_rate"]),
            "v2v_receiver_rate": _agg(rows, ["forgery", "v2v_receiver_rate"]),
            "rsu_rate": _agg(rows, ["forgery", "rsu_rate"]),
            "exposure_contiguous_mean_s": _agg(rows, ["forgery", "exposure", "contiguous", "mean"]),
            "exposure_contiguous_p95_s_pooled": pooled_percentile(seg, 0.95),
            "exposure_contiguous_n": len(seg),
            "exposure_contiguous_censored": cens,
            "exposure_cumulative_mean_s": _agg(rows, ["forgery", "exposure", "cumulative_per_holding", "mean"]),
            "exposure_cumulative_p95_s_pooled": pooled_percentile(cum, 0.95),
            "exposure_holdings_n": len(cum),
            **_report_fields(rows), **_retention_fields(rows)}


def _report_fields(rows: list[dict]) -> dict:
    """Misbehaviour reports through the central path (review G01): those
    raised by forged messages, those raised by vehicles' own beacons after a
    forgery, and their union, each naming honest vehicles only."""
    def route(r, name, key):
        return ((r.get("reports") or {}).get("by_route") or {}).get(name, {}).get(key, 0)
    for r in rows:
        rep = r.get("reports") or {}
        r["_rep"] = {"forgery_honest": route(r, "forgery", "naming_honest"),
                     "forgery_distinct_honest": route(r, "forgery", "distinct_honest"),
                     "beacon_honest": route(r, "beacon", "naming_honest"),
                     "beacon_distinct_honest": route(r, "beacon", "distinct_honest"),
                     "all_honest": rep.get("reports_naming_honest", 0),
                     "distinct_honest": rep.get("distinct_honest_reported", 0)}
    return {"reports_forgery_naming_honest": _agg(rows, ["_rep", "forgery_honest"]),
            "honest_named_by_forgery_reports": _agg(rows, ["_rep", "forgery_distinct_honest"]),
            "reports_beacon_naming_honest": _agg(rows, ["_rep", "beacon_honest"]),
            "honest_named_by_beacon_reports": _agg(rows, ["_rep", "beacon_distinct_honest"]),
            "reports_naming_honest": _agg(rows, ["_rep", "all_honest"]),
            "honest_reported": _agg(rows, ["_rep", "distinct_honest"])}


def _retention_fields(rows: list[dict]) -> dict:
    """Distinct credentials the attackers held and kept (review G02)."""
    return {"attacker_credentials_held": _agg(rows, ["retention", "held_distinct"]),
            "attacker_credentials_retained": _agg(rows, ["retention", "retained_distinct"])}


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
        results.append({**c, "seeds": len(rows), **_forgery_fields(rows), **_revocation_fields(rows),
                        "per_seed": [seed_record(r) for r in rows]})
    return {"experiment": "E1_impersonation", "rounds": rounds, "cells": results}


# ------------------------------------------------------------------ E2
E2_MODES = ("recycle", "fresh", "fresh_vgk", "rekey")


def exp_e2_revocation(seeds=DEFAULT_SEEDS, rounds: int = 4, lifetimes=(300, 900, 3600), density: float = 10,
                      modes=E2_MODES) -> dict:
    """RQ2: does revoking a vehicle stop its messages from being accepted by
    other vehicles?  One misbehaving vehicle, caught by the RSU, keeps
    transmitting with the credentials it kept; V2V receivers never see the
    ledger.  Run under every issuance mode (review follow-up): the reuse of a
    vehicle's own retired credentials is measured, not inferred, in fresh
    modes too."""
    results = []
    for mode in modes:
        for lt in lifetimes:
            rows = []
            for seed in seeds:
                cfg = _base(density, seed, issuance=mode, malicious_vehicles=1, revoked_keep_transmitting=True,
                            pseudonym_lifetime=float(lt), attribution="oracle")
                rows.append(_e2_row(_run(cfg, rounds)))
            results.append({"mode": mode, "lifetime": lt, "seeds": len(rows), **_e2_fields(rows)})
    return {"experiment": "E2_revocation", "rounds": rounds, "cells": results}


def _e2_row(r: dict) -> dict:
    """One E2 run: the misbehaving vehicle's revocation, the messages other
    vehicles accepted from it afterwards, and its retained credentials still
    unexpired at the end (review R04: retained copies no longer follow renewals)."""
    rp = r["revoked_persistence"] or {}
    acc = [v["accepted_after"] for v in rp.values()]
    last = [v["seconds_to_last"] for v in rp.values()]
    rv = r.get("retained_valid") or []
    return {"seed": r.get("seed"), "population": r["population"], "misbehaver_revoked": len(rp),
            "accepted_after": statistics.mean(acc) if acc else None,
            "seconds_to_last": statistics.mean(last) if last else None,
            "retained_valid_end": rv[-1] if rv else None}


def _e2_fields(rows: list[dict]) -> dict:
    return {"misbehaver_revoked": _agg(rows, ["misbehaver_revoked"]),
            "honest_revoked": _agg(rows, ["population", "revoked_honest"]),
            "post_revocation_accepted": _agg(rows, ["accepted_after"]),
            "seconds_to_last_accepted": _agg(rows, ["seconds_to_last"]),
            "per_seed": rows}


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
                                 for m in ("link_rate", "precision", "pair_recall", "purity", "identity_rate",
                                           "correct_identity_beacon_share", "wrong_identity_beacon_share",
                                           "ambiguous_identity_beacon_share", "correct_identity_driven_share",
                                           "trajectory_coverage")}
            results.append({"density": d, "cloud_order": order, "seeds": len(rows), "table": table,
                            "per_seed": [{"seed": r["seed"], "population": r["population"], "insider": r["insider"]}
                                         for r in rows]})
    return {"experiment": "E3_insider", "rounds": rounds, "cells": results}


# ------------------------------------------------------------------ E3b
INSIDER_ENTITIES = ("pki", "pm", "rsu", "cloud")


def exp_e3b_insider_forgery(seeds=DEFAULT_SEEDS, rounds: int = 4, density: float = 10, modes=ISSUANCE_MODES,
                            strategies=("offset", "near", "silent"), forgeries_per_round: int = 10) -> dict:
    """RQ3, with a key: private keys pass through the PKI, the PMs, the RSUs
    and the cloud in software.  Per issuance mode, entity and forging
    strategy: the share of pseudonyms in use whose current signing key the
    entity holds, and for its forgeries (``forgeries_per_round`` per entity per
    round, on behalf of the pseudonym's current holder) the share of receivers
    in range that accept, the share of forgeries at least one receiver
    accepts, the share the RSU accepts, and the share after which the RSU
    reports the innocent holder.  Strategies: ``offset`` claims a position
    40 m from the holder, ``near`` 10 m (inside the 25 m same-second
    tolerance), ``silent`` forges at the holder's position while it is in its
    post-change silent period.  Plausibility on, ledger attribution."""
    results = []
    for mode in modes:
        for strat in strategies:
            rows = []
            for seed in seeds:
                cfg = _base(density, seed, issuance=mode, v2v_plausibility=True, pseudonym_lifetime=900.0, insider_forgery=True,
                            insider_strategy=strat, insider_forgeries_per_round=forgeries_per_round)
                sim = ITSSimulation(cfg)
                sim.run(rounds)
                rows.append({**sim.summary()["recycling"]["insider_forgery"], "_seed": seed})
            for ent in INSIDER_ENTITIES:
                per = [r[ent] for r in rows]
                results.append({"mode": mode, "strategy": strat, "entity": ent, "seeds": len(per),
                                "key_share": bootstrap_ci([x["key_share"] for x in per]),
                                "forgeries_sent": bootstrap_ci([float(x["sent"]) for x in per]),
                                "receiver_rate": bootstrap_ci([x["receiver_rate"] for x in per if x["sent"]]),
                                "message_rate": bootstrap_ci([x["message_rate"] for x in per if x["sent"]]),
                                "rsu_rate": bootstrap_ci([x["rsu_rate"] for x in per if x["sent"]]),
                                "blame_rate": bootstrap_ci([x["blame_rate"] for x in per if x["sent"]]),
                                "per_seed": [{"seed": r["_seed"], **r[ent]} for r in rows]})
    return {"experiment": "E3b_insider_forgery", "rounds": rounds, "density": density,
            "forgeries_per_round": forgeries_per_round, "strategies": list(strategies), "cells": results}


# ------------------------------------------------------------------ E4
EQUIVALENCE_MARGIN = 0.01   # tracker link rate: one point, set in 3.5.0 after the earlier results (review R12)


def exp_e4_modes(seeds=DEFAULT_SEEDS, rounds: int = 4, densities=(10, 40), modes=ISSUANCE_MODES,
                 strategy: str = "S2", margin: float = EQUIVALENCE_MARGIN) -> dict:
    """RQ4: modes against axes.  Same seed = same mobility, so paired.

    Two privacy comparisons (review R13): ``privacy_attack_free`` runs every
    mode with no attacker, so each mode emits the same beacons and has the same
    pseudonym changes; the joint cells run the S2 attack, whose forgeries and
    revocations change the emitted traffic.  Link-rate equality is tested as
    equivalence within ``margin`` (TOST), with the paired difference and its
    interval, on the valid pairs only.  Forgery comparisons are reported only
    where both modes had attempts; a mode with none is not applicable."""
    results, attack_free = [], []
    paired: dict[str, dict[str, list]] = {}
    for d in densities:
        for mode in modes:
            # attack-free privacy (matched emission opportunities)
            af = [_run(_base(d, seed, issuance=mode, v2v_plausibility=True, pseudonym_lifetime=900.0), rounds)
                  for seed in seeds]
            attack_free.append({"density": d, "mode": mode, "seeds": len(af),
                                "tracker_link_rate": _agg(af, ["tracking", "linking_success"]),
                                "true_changes": _agg(af, ["tracking", "true_changes"]),
                                "tracker_relabel_captures": _agg(af, ["tracking", "relabel_captures"]),
                                "per_seed": [seed_record(r) for r in af]})
            paired.setdefault(f"{d}/attack_free/tracker_link_rate", {})[mode] = [
                (r.get("tracking") or {}).get("linking_success") for r in af]
            rows = []
            for seed in seeds:
                est = int(2 * d * 5)
                cfg = _base(d, seed, issuance=mode, former_holders=_attackers(est, 0.05), former_holder_strategy=strategy,
                            v2v_plausibility=True, pseudonym_lifetime=900.0)
                rows.append(_run(cfg, rounds))
            cell = {"density": d, "mode": mode, "seeds": len(rows),
                    "tracker_link_rate": _agg(rows, ["tracking", "linking_success"]),
                    "true_changes": _agg(rows, ["tracking", "true_changes"]),
                    "tracker_relabel_captures": _agg(rows, ["tracking", "relabel_captures"]),
                    "forged_accepted_v2v": _agg(rows, ["forgery", "accepted_v2v"]),
                    **_forgery_fields(rows), **_revocation_fields(rows),
                    "insider_pm_link_rate": _agg(rows, ["insider", "pm", "link_rate"]),
                    # fresh modes never upload to the cloud: that channel does not exist there (review R23)
                    "insider_cloud_link_rate": (_agg(rows, ["insider", "cloud", "link_rate"])
                                                if mode not in ("fresh", "fresh_vgk") else _agg([], [])),
                    "insider_cloud_channel": "absent" if mode in ("fresh", "fresh_vgk") else "uploads",
                    "pki_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pki_cpu_s_per_1000_veh_h"]),
                    "pm_cpu_s_per_1000_veh_h": _agg(rows, ["load", "pm_cpu_s_per_1000_veh_h"]),
                    # where the CPU goes, per entity and operation (review G10)
                    "cpu_by_operation_per_1000_veh_h": {
                        ent: {op: _agg(rows, ["load", "cpu_by_operation_per_1000_veh_h", ent, op])
                              for op in ("sign", "verify", "keygen", "encrypt", "decrypt")}
                        for ent in ("pki", "pm", "rsu")},
                    "pki_signatures": _agg(rows, ["load", "steady_state", "pki", "signatures"]),
                    "pm_signatures": _agg(rows, ["load", "steady_state", "pm", "signatures"]),
                    "vehicle_keygens_per_vehicle_per_round": _agg(rows, ["load", "vehicle_keygens_per_vehicle_per_round"]),
                    "bytes_per_vehicle_per_round": _agg(rows, ["load", "bytes_per_vehicle_per_round"]),
                    "stockouts": _agg(rows, ["stockouts"]),
                    "per_seed": [seed_record(r) for r in rows]}
            results.append(cell)
            paired.setdefault(f"{d}/joint/tracker_link_rate", {})[mode] = [
                (r.get("tracking") or {}).get("linking_success") for r in rows]
            paired.setdefault(f"{d}/pki_cpu_s_per_1000_veh_h", {})[mode] = [
                r["load"]["pki_cpu_s_per_1000_veh_h"] for r in rows]
            paired.setdefault(f"{d}/forged_accepted_v2v", {})[mode] = [
                (r.get("forgery") or {}).get("accepted_v2v") if (r.get("forgery") or {}).get("sent") else None
                for r in rows]
    tests, equivalence = {}, {}
    for key, by_mode in paired.items():
        if "recycle" not in by_mode:
            continue
        for mode, vals in by_mode.items():
            if mode == "recycle":
                continue
            a, b = by_mode["recycle"], vals
            valid = [(x, y) for x, y in zip(a, b) if x is not None and y is not None]
            name = f"{key}: recycle vs {mode}"
            if not valid:
                tests[name] = {"n_valid": 0, "result": "not applicable: no attempts in at least one mode"}
                continue
            t = wilcoxon_signed_rank([x for x, _ in valid], [y for _, y in valid])
            tests[name] = {**t, "n_valid": len(valid)}
            if key.endswith("tracker_link_rate"):
                equivalence[name] = paired_equivalence(a, b, margin)
    from .v2.sizes import size_table
    return {"experiment": "E4_modes", "rounds": rounds, "strategy": strategy, "equivalence_margin": margin,
            "cells": results, "privacy_attack_free": attack_free, "paired_tests": tests, "equivalence": equivalence,
            "size_estimate_standard": size_table()}


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
            results.append({"variant": var, "strategy": st, "seeds": len(rows), **_forgery_fields(rows),
                            "forged_v2v_accepted": _agg(rows, ["forgery", "accepted_v2v"]),
                            **_revocation_fields(rows), "per_seed": [seed_record(r) for r in rows],
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
                            **_forgery_fields(rows), **_revocation_fields(rows),
                            "per_seed": [seed_record(r) for r in rows],
                            "pki_renewals": _agg(rows, ["load", "steady_state", "pki", "signatures"]),
                            "v2v_expired_rejections": _agg(rows, ["v2v", "rejected", "certificate-expired"])})
    return {"experiment": "E1x_lifetime_long", "rounds": rounds, "cells": results}


def exp_e2_long(seeds=DEFAULT_SEEDS, rounds: int = 20, lifetimes=(300, 900, 3600), density: float = 10,
                modes=E2_MODES) -> dict:
    """E2 over 600 s: how long a revoked vehicle keeps being believed when its
    certificates can expire inside the horizon, under every issuance mode."""
    results = []
    for mode in modes:
        for lt in lifetimes:
            rows = []
            for seed in seeds:
                cfg = _base(density, seed, issuance=mode, malicious_vehicles=1, revoked_keep_transmitting=True,
                            pseudonym_lifetime=float(lt), attribution="oracle")
                rows.append(_e2_row(_run(cfg, rounds)))
            results.append({"mode": mode, "lifetime": lt, "seeds": len(rows), "sim_seconds": rounds * 30,
                            **_e2_fields(rows)})
    return {"experiment": "E2x_long", "rounds": rounds, "cells": results}


# ------------------------------------------------ E1r: the revocation rule
def exp_e1_revocation_rule(seeds=DEFAULT_SEEDS, rounds: int = 4, long_rounds: int = 20, rules=REVOCATION_RULES,
                           strategies=("S1", "S2"), density: float = 10, share: float = 0.05,
                           lifetime: float = 900.0) -> dict:
    """Sensitivity of the E1 accountability result to the revocation rule.
    E1 revokes a vehicle on its first clone report.  Here the PM waits for
    ``k`` reports from at least ``m`` distinct RSUs, for every (k, m) in
    ``rules``, and three things are measured per rule: how many honest
    vehicles the former holders still get revoked (120 s and 600 s
    horizons, ledger attribution), how many wrongful reports are filed, and
    the price of the stricter rule on a genuine misbehaver (the E2 setting:
    one vehicle replaying its pseudonyms under oracle attribution): the time
    until it is revoked and how many of its messages RSUs accept meanwhile."""
    results = []
    for k, m in rules:
        cell = {"reports": k, "distinct_rsus": m, "rule": f"{k} report{'s' if k > 1 else ''} / {m} RSU{'s' if m > 1 else ''}"}
        for st in strategies:
            for label, n_rounds in (("short", rounds), ("long", long_rounds)):
                rows = []
                for seed in seeds:
                    est = int(2 * density * 5)
                    cfg = _base(density, seed, issuance="recycle", former_holders=_attackers(est, share),
                                former_holder_strategy=st, v2v_plausibility=True, pseudonym_lifetime=lifetime,
                                revocation_reports=k, revocation_distinct_rsus=m)
                    rows.append(_run(cfg, n_rounds))
                cell[f"{st}_{label}"] = {"sim_seconds": n_rounds * 30, "seeds": len(rows),
                                         "vehicles": _agg(rows, ["vehicles"]), **_revocation_fields(rows),
                                         **_report_fields(rows),
                                         "v2v_receiver_rate": _agg(rows, ["forgery", "v2v_receiver_rate"]),
                                         "per_seed": [seed_record(r) for r in rows]}
        # the genuine misbehaver: how long the stricter rule lets it run
        rows = []
        for seed in seeds:
            cfg = _base(density, seed, issuance="recycle", malicious_vehicles=1, revoked_keep_transmitting=True,
                        pseudonym_lifetime=lifetime, attribution="oracle", revocation_reports=k, revocation_distinct_rsus=m)
            sim = ITSSimulation(cfg)
            t0 = clock.now()
            sim.run(long_rounds)
            bad = next(v for v in sim.vehicles if v.malicious)
            t_rev = sim.revoked_at.get(bad.vehicle_id)
            reports = len(sim.report_tally.get(bad.vehicle_id, []))
            # not revoked within the horizon: censored at the horizon (counted in revoked_within_horizon)
            rows.append({"seed": seed, "revoked": 1.0 if t_rev is not None else 0.0,
                         "seconds_to_revocation": (t_rev - t0) if t_rev is not None else float(long_rounds * 30),
                         "censored": t_rev is None, "reports_against_it": reports})
        cell["misbehaver"] = {"sim_seconds": long_rounds * 30, "seeds": len(rows), "per_seed": rows,
                              "revoked_within_horizon": _agg(rows, ["revoked"]),
                              "seconds_to_revocation": _agg(rows, ["seconds_to_revocation"]),
                              "reports_against_it": _agg(rows, ["reports_against_it"])}
        results.append(cell)
    return {"experiment": "E1r_revocation_rule", "rounds": rounds, "long_rounds": long_rounds,
            "strategies": list(strategies), "cells": results}
