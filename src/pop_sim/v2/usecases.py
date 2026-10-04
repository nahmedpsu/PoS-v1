"""Deployment scenarios for PoP v2.

Each scenario configures the protocol for a concrete ITS setting, runs it,
and reports the numbers an operator would ask for: how private the
vehicles are against a tracker, how many pseudonyms the domain must hold,
how long a shuffle round takes, and what the blockchain machinery costs.
A one-line verdict says whether the scheme fits that setting.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from .. import crypto
from ..entities import SafetyMessage
from ..shuffle import ITSConfig, ITSSimulation
from .anchoring import build_allotment_proof, proof_size_bytes, verify_allotment_proof
from .mobility import RoadConfig


@dataclass
class UseCaseResult:
    scenario: str
    description: str
    config: dict
    metrics: dict
    verdict: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _run(cfg: ITSConfig, rounds: int) -> tuple[ITSSimulation, dict]:
    sim = ITSSimulation(cfg)
    t0 = time.perf_counter()
    sim.run(rounds)
    s = sim.summary()
    wall = time.perf_counter() - t0
    tr = s["tracking"] or {}
    m = {
        "vehicles": len(sim.vehicles),
        "rounds": rounds,
        "wall_seconds_per_round": wall / rounds,
        "linking_success": tr.get("linking_success"),
        "mean_correct_track_s": tr.get("longest_correct_run"),
        "stockouts": s["stockouts"],
        "pseudonyms_issued": s["linkability"]["pids_issued"],
        "pseudonyms_per_vehicle": s["linkability"]["pids_issued"] / max(1, len(sim.vehicles)),
        "pm_election_ms": statistics.mean(r["pm_consensus_cpu"] for r in s["rounds"]) * 1e3,
        "rsu_elections_ms": statistics.mean(r["rsu_consensus_cpu"] for r in s["rounds"]) * 1e3,
        "messages_per_round": statistics.mean(r["messages"] for r in s["rounds"]),
        "rejected_messages": sum(r["rejected_messages"] for r in s["rounds"]),
        "pm_blocks": s["pm_chain_blocks"] - 1,
        "chains_valid": s["pm_chain_valid"] and s["rsu_chains_valid"],
        "revoked": s["linkability"]["revoked_vehicles"],
        "allotment_proof_bytes": s["anchoring"].get("proof_bytes"),
    }
    return sim, m


def _cfg_dict(cfg: ITSConfig) -> dict:
    d = {k: v for k, v in cfg.__dict__.items() if k != "road"}
    d["road"] = cfg.road.__dict__ if cfg.road else None
    return d


def _privacy_verdict(link: float) -> str:
    if link is None:
        return "no tracker run"
    if link < 0.35:
        return "privacy adequate"
    if link < 0.7:
        return "privacy partial"
    return "privacy insufficient"


# --------------------------------------------------------------- scenarios
def uc_urban_intersection(rounds: int = 4, seed: int = 1) -> UseCaseResult:
    """Dense, slow traffic around a signalised intersection: the setting the
    manuscript names for shuffling ("traffic signal stops, roundabouts")."""
    cfg = ITSConfig(n_pm=1, rsus_per_pm=4, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=2000, density_per_km=60, speed_mean=8, speed_sd=2, seed=seed),
                    round_seconds=20, pseudonyms_per_vehicle=2, silent_period=5, position_noise_m=3,
                    safety_stock=0.25, seed=seed)
    sim, m = _run(cfg, rounds)
    return UseCaseResult("urban_intersection", "Signalised intersection, 60 veh/km, 30 km/h, shuffle every 20 s, 5 s silence.",
                         _cfg_dict(cfg), m,
                         f"{_privacy_verdict(m['linking_success'])}; {m['stockouts']} stock-outs; "
                         f"{m['wall_seconds_per_round']:.1f} s per round for {m['vehicles']} vehicles")


def uc_highway(rounds: int = 4, seed: int = 1) -> UseCaseResult:
    cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=12000, density_per_km=4, speed_mean=30, speed_sd=4, seed=seed),
                    round_seconds=60, pseudonyms_per_vehicle=3, silent_period=3, position_noise_m=3,
                    safety_stock=0.25, seed=seed)
    sim, m = _run(cfg, rounds)
    return UseCaseResult("highway", "12 km highway, 4 veh/km, 110 km/h, shuffle every 60 s, 3 s silence.",
                         _cfg_dict(cfg), m,
                         f"{_privacy_verdict(m['linking_success'])}: at this density a tracker follows most vehicles; "
                         "shuffling must be paired with longer silence at entries/exits")


def uc_rural_night(rounds: int = 4, seed: int = 1) -> UseCaseResult:
    cfg = ITSConfig(n_pm=1, rsus_per_pm=3, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=6000, density_per_km=1, speed_mean=20, speed_sd=3, seed=seed),
                    round_seconds=60, pseudonyms_per_vehicle=2, silent_period=10, position_noise_m=3,
                    safety_stock=0.5, seed=seed)
    sim, m = _run(cfg, rounds)
    return UseCaseResult("rural_night", "Rural road at night, 1 veh/km, shuffle every 60 s, 10 s silence.",
                         _cfg_dict(cfg), m,
                         f"{_privacy_verdict(m['linking_success'])}: pseudonym change cannot hide a lone vehicle; "
                         "do not rely on shuffling here")


def uc_city_scale(rounds: int = 3, seed: int = 1, density: float = 20.0, n_pm: int = 4, rsus_per_pm: int = 5) -> UseCaseResult:
    """Capacity: a city district with 4 PMs x 5 RSUs and hundreds of vehicles."""
    cfg = ITSConfig(n_pm=n_pm, rsus_per_pm=rsus_per_pm, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=20000, density_per_km=density, speed_mean=12, speed_sd=3, seed=seed),
                    round_seconds=30, pseudonyms_per_vehicle=3, silent_period=5, position_noise_m=3,
                    safety_stock=0.25, seed=seed)
    sim, m = _run(cfg, rounds)
    m["signatures_per_round"] = m["messages_per_round"]
    return UseCaseResult("city_scale", f"{n_pm} PMs x {rsus_per_pm} RSUs, 20 km of roads, {density} veh/km.",
                         _cfg_dict(cfg), m,
                         f"{m['vehicles']} vehicles, {m['wall_seconds_per_round']:.1f} s per 30 s round on one core "
                         f"({m['messages_per_round']:.0f} signed CAMs/round); PM election {m['pm_election_ms']:.0f} ms")


def uc_cross_pm_roaming(rounds: int = 4, seed: int = 1) -> UseCaseResult:
    """Vehicles cross from one PM's area into another's and prove their
    current allotment with an anchored proof instead of re-registering."""
    cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=6000, density_per_km=8, speed_mean=20, speed_sd=3, seed=seed),
                    round_seconds=30, pseudonyms_per_vehicle=3, silent_period=3, position_noise_m=3,
                    safety_stock=0.25, seed=seed)
    sim = ITSSimulation(cfg)
    pm_of = {}
    crossings = 0
    proofs_ok = 0
    proofs_failed = 0
    sizes = []
    verify_times = []
    t0 = time.perf_counter()
    for r in range(rounds):
        sim.run_round()
        for mv in sim.road.vehicles:
            pm_idx = mv.rsu // cfg.rsus_per_pm
            prev = pm_of.get(mv.vid)
            pm_of[mv.vid] = pm_idx
            if prev is None or prev == pm_idx:
                continue
            crossings += 1
            v = next(x for x in sim.vehicles if x.index == mv.vid)
            old_pm = sim.pms[prev]
            pid = v.pseudonyms[0].pid if v.pseudonyms else (v.history[-1] if v.history else None)
            proof = build_allotment_proof(old_pm.rsu_chain, sim.pm_chain, old_pm.pm_id, pid, old_pm.keys) if pid else None
            if proof is None:
                proofs_failed += 1
                continue
            t = time.perf_counter()
            ok = verify_allotment_proof(proof, sim.pm_chain)
            verify_times.append(time.perf_counter() - t)
            sizes.append(proof_size_bytes(proof))
            proofs_ok += ok
            proofs_failed += not ok
    wall = time.perf_counter() - t0
    s = sim.summary()
    m = {"vehicles": len(sim.vehicles), "rounds": rounds, "pm_crossings": crossings, "proofs_verified": proofs_ok,
         "proofs_unavailable_or_failed": proofs_failed,
         "mean_proof_bytes": statistics.mean(sizes) if sizes else None,
         "mean_verify_us": statistics.mean(verify_times) * 1e6 if verify_times else None,
         "wall_seconds_per_round": wall / rounds, "chains_valid": s["pm_chain_valid"] and s["rsu_chains_valid"],
         "linking_success": (s["tracking"] or {}).get("linking_success")}
    return UseCaseResult("cross_pm_roaming", "Two PMs on a 6 km ring; vehicles crossing the PM boundary carry an allotment proof.",
                         _cfg_dict(cfg), m,
                         f"{crossings} crossings, {proofs_ok} proofs verified "
                         f"({(m['mean_proof_bytes'] or 0):.0f} B, {(m['mean_verify_us'] or 0):.0f} us each); "
                         f"{proofs_failed} vehicles crossed before their allotment was anchored and fall back to the ledger")


def uc_toll_service_access(rounds: int = 2, seed: int = 1) -> UseCaseResult:
    """A toll gantry (or EV charger) authenticates passing vehicles by pseudonym
    only: signature under the pseudonym key, allotment in the ledger, not
    revoked.  The permanent identity is never presented."""
    cfg = ITSConfig(n_pm=1, rsus_per_pm=3, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=4000, density_per_km=10, speed_mean=15, speed_sd=3, seed=seed),
                    round_seconds=20, pseudonyms_per_vehicle=3, silent_period=0, position_noise_m=0,
                    safety_stock=0.25, malicious_vehicles=2, seed=seed)
    sim = ITSSimulation(cfg)
    sim.run(rounds)
    accepted = rejected = 0
    reasons: dict[str, int] = {}
    times = []
    ids_seen = set()
    t = 10_000.0
    for v in sim.vehicles:
        if not v.pseudonyms:
            if v.revoked:
                rejected += 1
                reasons["revoked-no-pseudonyms"] = reasons.get("revoked-no-pseudonyms", 0) + 1
            continue
        p = v.pseudonyms[0]
        msg = SafetyMessage(p.pid, (float(sim.road.vehicles[v.index].x), 0.0), 10.0, 0.0, t)
        msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
        t0 = time.perf_counter()
        ok, reason = sim.ledger.check(p.pid, v.vehicle_id, msg)
        if ok and sim.pki.is_revoked(v.credential.cert):
            ok, reason = False, "certificate-revoked"
        times.append(time.perf_counter() - t0)
        ids_seen.add(msg.pid)
        accepted += ok
        rejected += not ok
        if not ok:
            reasons[reason] = reasons.get(reason, 0) + 1
    perm_ids = {v.vehicle_id for v in sim.vehicles}
    m = {"vehicles": len(sim.vehicles), "accepted": accepted, "rejected": rejected, "rejection_reasons": reasons,
         "mean_check_us": statistics.mean(times) * 1e6 if times else None,
         "permanent_ids_exposed": len(perm_ids & ids_seen), "revoked_vehicles": sum(v.revoked for v in sim.vehicles)}
    return UseCaseResult("toll_service_access", "Toll gantry / charging point authenticates vehicles by pseudonym and ledger only.",
                         _cfg_dict(cfg), m,
                         f"{accepted} accepted, {rejected} rejected in {(m['mean_check_us'] or 0):.0f} us each; "
                         f"{m['permanent_ids_exposed']} permanent identities exposed")


def uc_incident_revocation(rounds: int = 4, seed: int = 1) -> UseCaseResult:
    """Misbehaving vehicles are detected, reported and revoked; the
    revocation holds across PMs (PKI CRL) and the vehicle gets no new sets."""
    cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="popv2", mobility=True,
                    road=RoadConfig(length_m=6000, density_per_km=8, speed_mean=15, speed_sd=3, seed=seed),
                    round_seconds=30, pseudonyms_per_vehicle=3, silent_period=3, position_noise_m=3,
                    safety_stock=0.25, malicious_vehicles=3, seed=seed)
    sim = ITSSimulation(cfg)
    revoked_at = {}
    for r in range(1, rounds + 1):
        sim.run_round()
        for v in sim.vehicles:
            if v.revoked and v.vehicle_id not in revoked_at:
                revoked_at[v.vehicle_id] = r
    bad = [v for v in sim.vehicles if v.malicious]
    s = sim.summary()
    after = sum(1 for v in bad if v.revoked and not v.pseudonyms)
    m = {"vehicles": len(sim.vehicles), "malicious": len(bad), "revoked": sum(v.revoked for v in bad),
         "honest_revoked": sum(v.revoked for v in sim.vehicles if not v.malicious),
         "rounds_to_revocation": {k: v for k, v in revoked_at.items()},
         "mean_rounds_to_revocation": statistics.mean(revoked_at.values()) if revoked_at else None,
         "revoked_without_sets_at_end": after, "rejected_messages": sum(r["rejected_messages"] for r in s["rounds"]),
         "pki_accesses": s["linkability"]["pki_accesses"], "crl_size": len(sim.pki.crl)}
    return UseCaseResult("incident_revocation", "Three vehicles replay pseudonyms; detection, reporting and CRL propagation across two PMs.",
                         _cfg_dict(cfg), m,
                         f"{m['revoked']}/{len(bad)} revoked after {m['mean_rounds_to_revocation']} rounds on average, "
                         f"{m['honest_revoked']} honest vehicles affected")


USE_CASES = [uc_urban_intersection, uc_highway, uc_rural_night, uc_cross_pm_roaming, uc_toll_service_access,
             uc_incident_revocation, uc_city_scale]


def run_all(quick: bool = False) -> dict:
    out = []
    t0 = time.perf_counter()
    for fn in USE_CASES:
        t = time.perf_counter()
        if quick and fn is uc_city_scale:
            r = fn(rounds=1, density=6.0, n_pm=2, rsus_per_pm=3)
        elif quick:
            r = fn(rounds=2)
        else:
            r = fn()
        d = r.to_dict()
        d["seconds"] = time.perf_counter() - t
        out.append(d)
    return {"experiment": "usecases", "quick": quick, "results": out, "wall_seconds": time.perf_counter() - t0}
