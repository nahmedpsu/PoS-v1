"""Invariants added for the external repository review of v3.4.0 (R25).

Each test pins a boundary between simulator behaviour, metric definitions and
reported numbers that the review found unguarded."""

import math

import pytest

from pop_sim import clock, crypto
from pop_sim.entities import PKI, Pseudonym, SafetyMessage, Vehicle, snapshot
from pop_sim.shuffle import ITSConfig, ITSSimulation
from pop_sim.v2.metrics import (
    ForgeryStats,
    UnionFind,
    bootstrap_ci,
    cluster_metrics,
    forged_acceptance,
    paired_equivalence,
    pooled_percentile,
)
from pop_sim.v2.mobility import RoadConfig
from pop_sim.v2.v2v import V2VLayer


@pytest.fixture(autouse=True)
def _clock():
    clock.set_virtual(1_700_000_000.0)
    yield
    clock.set_virtual(None)


def _cfg(**kw):
    base = dict(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=10, seed=5),
                round_seconds=30, pseudonyms_per_vehicle=3, seed=5, silent_period=3, position_noise_m=3,
                attribution="ledger", v2v=True, v2v_plausibility=True, pseudonym_lifetime=900.0)
    base.update(kw)
    return ITSConfig(**base)


# R01 -------------------------------------------------------------------------
def test_population_counts_are_disjoint_and_honest_excludes_attackers():
    sim = ITSSimulation(_cfg(issuance="recycle", former_holders=5, former_holder_strategy="S1"))
    sim.run(3)
    pop = sim.summary()["linkability"]["population"]
    assert pop["vehicles"] == pop["honest"] + pop["attackers"] == len(sim.vehicles)
    assert pop["attackers"] == 5
    assert pop["revoked_total"] == pop["revoked_honest"] + pop["revoked_attackers"]
    assert pop["revoked_honest"] == sum(v.revoked for v in sim.vehicles if not (v.former_holder or v.malicious))


# R02 / R16 -------------------------------------------------------------------
def test_no_attempt_is_not_applicable_not_zero():
    assert forged_acceptance(ForgeryStats())["v2v_message_rate"] is None
    assert bootstrap_ci([])["mean"] is None
    assert bootstrap_ci([None, None])["n"] == 0
    sim = ITSSimulation(_cfg(issuance="fresh", former_holders=5, former_holder_strategy="S2"))
    sim.run(2)
    f = sim.summary()["recycling"]["forgery"]
    assert f["key_checks"] > 0 and f["eligible"] == 0 and f["sent"] == 0
    assert f["v2v_receiver_rate"] is None and f["rsu_rate"] is None


def test_pooled_percentile_is_not_a_mean_of_percentiles():
    a, b = [1.0] * 19 + [100.0], [1.0] * 20
    assert pooled_percentile(a + b, 0.95) == 1.0
    assert pooled_percentile([], 0.95) is None


# R03 -------------------------------------------------------------------------
def _signed_message(p: Pseudonym, t: float) -> SafetyMessage:
    msg = SafetyMessage(p.pid, (100.0, 0.0), 20.0, 1.0, t)
    msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
    msg.cred = p.cert_wire()
    return msg


def test_cached_verification_rechecks_expiry():
    pki = PKI(__import__("random").Random(1), pseudonym_lifetime=5.0)
    p = pki.generate_pseudonyms(1)[0]
    v2v = V2VLayer(pki.keys.pk, 10_000.0, freshness=1e9)
    msg = _signed_message(p, clock.now())
    assert v2v.verify(msg, clock.now()) == (True, "ok")
    assert v2v.verify(msg, clock.now() + 10.0) == (False, "certificate-expired")   # same message, cache warm


def test_certificate_substitution_is_not_served_from_cache():
    pki = PKI(__import__("random").Random(2))
    p, q = pki.generate_pseudonyms(2)
    v2v = V2VLayer(pki.keys.pk, 10_000.0)
    msg = _signed_message(p, clock.now())
    assert v2v.verify(msg, clock.now())[0]
    msg.cred = q.cert_wire()                      # a different, valid certificate on the same signed body
    assert v2v.verify(msg, clock.now()) == (False, "certificate-pid-mismatch")
    q2 = dict(p.cert_wire())
    q2["expiry"] = q2["expiry"] + 1               # tampered expiry: certificate signature no longer matches
    msg.cred = q2
    assert v2v.verify(msg, clock.now()) == (False, "certificate-invalid")


# R04 -------------------------------------------------------------------------
def test_retained_credentials_do_not_follow_renewals():
    pki = PKI(__import__("random").Random(3), pseudonym_lifetime=100.0)
    p = pki.generate_pseudonyms(1)[0]
    v = Vehicle(1, __import__("random").Random(4))
    v.former_holder = True
    v._keep(p)
    kept = v.kept_keys[0]
    before = (kept.expiry, kept.cert)
    clock.advance(50.0)
    pki.renew(p)                                  # the circulating object is renewed
    assert (kept.expiry, kept.cert) == before and kept is not p
    s = snapshot(p)
    assert s == p and s is not p


# R12 / R15 -------------------------------------------------------------------
def test_all_merged_clusters_are_not_reported_as_attribution():
    uf = UnionFind()
    nodes = ["a1", "a2", "b1", "b2", "VEH-A", "VEH-B"]
    for n in nodes[1:]:
        uf.union(nodes[0], n)
    m = cluster_metrics(uf, {"VEH-A": ["a1", "a2"], "VEH-B": ["b1", "b2"]},
                        {"a1": "VEH-A", "a2": "VEH-A", "b1": "VEH-B", "b2": "VEH-B"}, dict.fromkeys(nodes[:4], 10.0))
    assert m["trajectory_coverage"] == 1.0 and m["link_rate"] == 1.0
    assert abs(m["precision"] - 1 / 3) < 1e-12 and m["purity"] == 0.5
    assert m["correct_identity_beacon_share"] == 0.0 and m["ambiguous_identity_beacon_share"] == 1.0


def test_equivalence_uses_valid_pairs_and_the_margin():
    r = paired_equivalence([0.90, 0.91, None, 0.92], [0.90, 0.92, 0.5, None], margin=0.01)
    assert r["n_valid"] == 2
    far = paired_equivalence([0.9] * 10, [0.95] * 10, margin=0.01)
    assert far["equivalent"] is False and abs(far["mean_diff"] + 0.05) < 1e-12
    near = paired_equivalence([0.9 + i * 1e-4 for i in range(10)], [0.9] * 10, margin=0.01)
    assert near["equivalent"] is True


# R14 -------------------------------------------------------------------------
def test_tracker_hears_forged_cams():
    sim = ITSSimulation(_cfg(issuance="recycle", former_holders=5, former_holder_strategy="S1"))
    sim.run(2)
    s = sim.summary()
    honest_msgs = sum(r["messages"] for r in s["rounds"]) - s["recycling"]["forgery"]["sent"]
    assert s["tracking"]["beacons"] > honest_msgs - 1   # forged CAMs reach the eavesdropper as well


# R21 / R22 -------------------------------------------------------------------
def _trace_road():
    from pop_sim.v2.mobility_sumo import Corridor, FcdFrame, TraceRoad
    frames = [FcdFrame(float(t), {f"v{i}": (0.0, 0.0, "e0_0", 150.0 * i + 25.0 * t, 25.0)
                                  for i in range(12) if 150.0 * i + 25.0 * t < 2000.0 and (i < 6 or t > 70)})
              for t in range(120)]
    return TraceRoad(frames, Corridor("lane", ["e0"], {"e0": 2000.0}, ring=False), n_rsu=6)


def test_departed_pseudonyms_can_be_lost():
    road = _trace_road()
    sim = ITSSimulation(_cfg(departed_return_prob=0.0, v2v=False), road=road)
    sim.run(3)
    s = sim.summary()
    assert s["departed_lost"] > 0 and s["departed_returns"] == 0


def test_attackers_are_drawn_from_the_evaluated_window():
    road = _trace_road()
    road.window_ids = {mv.vid for mv in road.vehicles}          # only the vehicles present at the start
    sim = ITSSimulation(_cfg(former_holders=4, v2v=False), road=road)
    assert all(v.index in road.window_ids for v in sim.vehicles if v.former_holder)
    sim.run(2)
    share = sim.summary()["achieved_attack_share"]
    assert share is not None and 0 < share <= 1


# R17 / R18 -------------------------------------------------------------------
def test_rsu_block_transactions_are_counted():
    sim = ITSSimulation(_cfg(v2v=False))
    sim.run(2)
    rsu = sim.summary()["recycling"]["load"]["rsu"]
    assert rsu["signatures"] > 0 and rsu["encryptions"] > 0


def test_standard_size_model_ratios():
    from pop_sim.v2.sizes import cam_bytes
    assert cam_bytes("rekey", 1.0) > cam_bytes("recycle", 1.0)
    assert cam_bytes("rekey", 0.1) / cam_bytes("recycle", 0.1) < cam_bytes("rekey", 1.0) / cam_bytes("recycle", 1.0) < 2.0
    assert math.isclose(cam_bytes("fresh", 0.5), cam_bytes("recycle", 0.5))
