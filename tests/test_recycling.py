import random

import pytest

from pop_sim import clock, crypto
from pop_sim.entities import PKI, SafetyMessage
from pop_sim.shuffle import ITSConfig, ITSSimulation
from pop_sim.v2.insider import Evidence, link
from pop_sim.v2.metrics import UnionFind, bootstrap_ci, cluster_metrics, exposure_windows, wilcoxon_signed_rank
from pop_sim.v2.mobility import RoadConfig
from pop_sim.v2.v2v import V2VLayer


@pytest.fixture(autouse=True)
def _reset_clock():
    yield
    clock.set_virtual(None)


def _cfg(**kw):
    base = dict(n_pm=2, rsus_per_pm=2, consensus="pop", mobility=True, road=RoadConfig(density_per_km=6, seed=3),
                round_seconds=20, pseudonyms_per_vehicle=2, safety_stock=0.25, seed=3, silent_period=0,
                position_noise_m=0)
    base.update(kw)
    return ITSConfig(**base)


# ------------------------------------------------------------------ work item 1: V2V
def _pki_and_msg(lifetime=3600.0, t=1000.0):
    clock.set_virtual(t)                                  # certificates and messages on one time base
    rng = random.Random(1)
    pki = PKI(rng, pseudonym_lifetime=lifetime)
    p = pki.generate_pseudonyms(1)[0]
    msg = SafetyMessage(p.pid, (100.0, 0.0), 10.0, 1.0, t)
    msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
    msg.cred = p.cert_wire()
    return pki, p, msg


def test_v2v_accepts_honest_rejects_tampered_and_expired():
    pki, p, msg = _pki_and_msg()
    layer = V2VLayer(pki.keys.pk, 5000.0, range_m=300.0)
    positions = {1: 100.0, 2: 250.0, 3: 350.0, 4: 3000.0}
    acc, rx = layer.deliver(msg, 100.0, positions, now=msg.timestamp, exclude=1)
    assert (acc, rx) == (2, 2)                       # vehicles 2 and 3 are in range, 4 is not
    bad = SafetyMessage(p.pid, (100.0, 0.0), 99.0, 1.0, msg.timestamp, msg.signature, msg.cred)
    assert layer.deliver(bad, 100.0, positions, now=msg.timestamp, exclude=1)[0] == 0
    assert layer.stats.rejected.get("bad-signature") == 2
    # expired certificate
    pki2, p2, msg2 = _pki_and_msg(lifetime=1.0)
    layer2 = V2VLayer(pki2.keys.pk, 5000.0)
    late = msg2.timestamp + 5.0
    late_msg = SafetyMessage(p2.pid, (100.0, 0.0), 10.0, 1.0, late)
    late_msg.signature = crypto.sign(p2.keys.sk, late_msg.body()).hex()
    late_msg.cred = p2.cert_wire()
    assert layer2.deliver(late_msg, 100.0, positions, now=late, exclude=1)[0] == 0
    assert "certificate-expired" in layer2.stats.rejected


def test_v2v_plausibility_is_per_receiver():
    pki, p, msg = _pki_and_msg()
    layer = V2VLayer(pki.keys.pk, 5000.0, range_m=300.0, plausibility=True)
    positions = {1: 100.0, 2: 250.0, 3: 2100.0}
    assert layer.deliver(msg, 100.0, positions, now=msg.timestamp, exclude=1)[0] == 1      # receiver 2 hears it
    far = SafetyMessage(p.pid, (2100.0, 0.0), 10.0, 1.0, msg.timestamp + 1.0)
    far.signature = crypto.sign(p.keys.sk, far.body()).hex()
    far.cred = p.cert_wire()
    # receiver 3 never heard the first message: accepts; receiver 2 (if in range) would reject
    acc, rx = layer.deliver(far, 2100.0, {2: 1900.0, 3: 2150.0}, now=far.timestamp, exclude=None)
    assert rx == 2 and acc == 1
    assert layer.stats.rejected.get("implausible") == 1


# ------------------------------------------------------------- attribution (step 1)
def test_ledger_attribution_names_the_holder_not_the_sender():
    sim = ITSSimulation(_cfg(attribution="ledger"))
    sim.run(1)
    victim = next(v for v in sim.vehicles if v.pseudonyms)
    p = victim.pseudonyms[0]
    other = next(v for v in sim.vehicles if v is not victim)
    rsu = sim.rsus[0]
    m1 = SafetyMessage(p.pid, (100.0, 0.0), 5.0, 1.0, 5000.0)
    m1.signature = crypto.sign(p.keys.sk, m1.body()).hex()
    assert rsu.receive_message(other, m1)                 # the RSU cannot tell who sent it
    m2 = SafetyMessage(p.pid, (4000.0, 0.0), 5.0, 1.0, 5001.0)
    m2.signature = crypto.sign(p.keys.sk, m2.body()).hex()
    assert not rsu.receive_message(other, m2)             # clone: flagged ...
    assert rsu.pm.misbehaviour_reports[-1]["vehicle"] == victim.vehicle_id   # ... and the holder is blamed
    assert rsu.pm.misbehaviour_reports[-1]["reason"] == "pseudonym-cloned"


# --------------------------------------------------------- work item 2: former holder
@pytest.mark.parametrize("strategy", ["S1", "S2", "S3"])
def test_fresh_issuance_leaves_nothing_to_forge(strategy):
    sim = ITSSimulation(_cfg(issuance="fresh", v2v=True, former_holders=2, former_holder_strategy=strategy,
                             attribution="ledger"))
    sim.run(3)
    f = sim.recycling_report()["forgery"]
    assert f["sent"] == 0 and f["accepted_v2v"] == 0


def test_gap_filler_is_accepted_under_recycling_until_expiry():
    sim = ITSSimulation(_cfg(issuance="recycle", v2v=True, former_holders=2, former_holder_strategy="S3",
                             attribution="ledger", pseudonym_lifetime=3600.0))
    sim.run(3)
    f = sim.recycling_report()["forgery"]
    assert f["sent"] > 0 and f["accepted_v2v"] == f["sent"]        # V2V has no ledger
    assert f["accepted_rsu"] == 0                                   # the RSU's ledger says "returned"
    assert f["exposure"]["contiguous"]["mean"] > 0


def test_ghost_blames_the_victim_under_ledger_attribution():
    sim = ITSSimulation(_cfg(issuance="recycle", v2v=True, former_holders=3, former_holder_strategy="S2",
                             attribution="ledger"))
    sim.run(3)
    f = sim.recycling_report()["forgery"]
    assert f["sent"] > 0 and f["accepted_v2v"] > 0
    assert sim.recycling_report()["reports"]["by_route"]["forgery"]["naming_honest"] > 0
    assert all(not v.former_holder for v in sim.vehicles if v.revoked)     # only victims were revoked


def test_rekey_blocks_every_strategy_and_window_does_not_block_the_ghost():
    for strategy in ("S1", "S2", "S3"):
        sim = ITSSimulation(_cfg(issuance="rekey", v2v=True, former_holders=3, former_holder_strategy=strategy,
                                 attribution="ledger"))
        sim.run(3)
        f = sim.recycling_report()["forgery"]
        assert f["sent"] > 0
        assert f["accepted_v2v"] == 0, (strategy, f)
        routes = sim.recycling_report()["reports"]["by_route"]
        assert routes.get("forgery", {}).get("naming_honest", 0) == 0
    sim = ITSSimulation(_cfg(issuance="window", v2v=True, former_holders=3, former_holder_strategy="S2",
                             attribution="ledger"))
    sim.run(3)
    f = sim.recycling_report()["forgery"]
    assert f["accepted_v2v"] == f["sent"] > 0


def test_revoked_vehicle_keeps_being_accepted_by_v2v():
    sim = ITSSimulation(_cfg(issuance="recycle", v2v=True, malicious_vehicles=1, revoked_keep_transmitting=True))
    sim.run(3)
    rp = sim.recycling_report()["revoked_persistence"]
    assert rp and all(v["accepted_after"] > 0 for v in rp.values())


# -------------------------------------------------------- work item 3: issuance modes
def test_fresh_never_reallots_a_pseudonym_and_counts_pki_work():
    sim = ITSSimulation(_cfg(issuance="fresh"))
    sim.run(3)
    assert all(len(h) == 1 for h in sim.holder_history.values())
    assert sim.ledger.retired and not sim.cloud.store
    load = sim.load_report()
    assert load["pki"]["signatures"] > len(sim.vehicles) * 2 * 3        # fresh certificates every round
    rec = ITSSimulation(_cfg(issuance="recycle"))
    rec.run(3)
    assert rec.load_report()["pki"]["signatures"] < load["pki"]["signatures"]


def test_fresh_vgk_keys_are_made_by_vehicles():
    sim = ITSSimulation(_cfg(issuance="fresh_vgk"))
    sim.run(2)
    load = sim.load_report()
    assert load["vehicles"]["keygens"] >= len(sim.vehicles) * 2 * 2
    assert load["pki"]["keygens"] == len(sim.vehicles)              # only the permanent identities
    assert all(r["rejected_messages"] == 0 for r in sim.summary()["rounds"])


def test_modes_share_the_same_traffic():
    a = ITSSimulation(_cfg(issuance="recycle"))
    a.run(2)
    b = ITSSimulation(_cfg(issuance="fresh"))
    b.run(2)
    assert [(v.x, v.v) for v in a.road.vehicles] == [(v.x, v.v) for v in b.road.vehicles]
    assert a.adversary.report(a.true_changes).pseudonym_changes == b.adversary.report(b.true_changes).pseudonym_changes


# ------------------------------------------------------- work item 4: insider linker
def test_union_find_metrics_on_a_hand_built_history():
    ev = Evidence(histories={"VEH-A": ["a1", "a2", "a3"], "VEH-B": ["b1", "b2"]},
                  truth_of_pid={"a1": "VEH-A", "a2": "VEH-A", "a3": "VEH-A", "b1": "VEH-B", "b2": "VEH-B"},
                  pid_seconds={"a1": 10, "a2": 10, "a3": 10, "b1": 10, "b2": 10},
                  tracker_pairs=[("a1", "a2"), ("a3", "b2")],
                  pm_domains={"PM-1": [("a1", "VEH-A"), ("a2", "VEH-A"), ("a3", "VEH-A")]})
    t = link(ev, ["tracker"])
    assert t["link_rate"] == pytest.approx(1 / 3)
    assert t["precision"] == pytest.approx(0.5)             # {a1,a2} right, {a3,b2} wrong
    assert t["identity_rate"] == 0.0
    pm = link(ev, ["pm"])
    assert pm["link_rate"] == pytest.approx(2 / 3) and pm["identity_rate"] == 0.5 and pm["precision"] == 1.0
    both = link(ev, ["tracker", "pm"])
    assert both["identity_rate"] == 0.5 and both["trajectory_coverage"] == pytest.approx((1.0 + 0.5) / 2)
    uf = UnionFind()
    uf.union("x", "y")
    assert uf.find("x") == uf.find("y")


def test_cloud_order_leak_and_its_fix():
    kept = ITSSimulation(_cfg(issuance="recycle"))
    kept.run(3)
    fixed = ITSSimulation(_cfg(issuance="recycle", shuffle_before_upload=True))
    fixed.run(3)
    k = kept.recycling_report()["insider"]["cloud"]
    f = fixed.recycling_report()["insider"]["cloud"]
    assert k["link_rate"] > 0.5 and k["precision"] > 0.5
    assert f["link_rate"] < 0.3


# ------------------------------------------------------------------ metrics
def test_exposure_windows_and_statistics():
    e = exposure_windows({("p", "A"): [1, 2, 3, 10, 11], ("q", "B"): [5]})
    assert e["contiguous"]["n"] == 3 and e["contiguous"]["mean"] == pytest.approx((3 + 2 + 1) / 3)
    assert e["cumulative_per_holding"]["n"] == 2 and e["cumulative_per_holding"]["mean"] == pytest.approx((5 + 1) / 2)
    ci = bootstrap_ci([1, 2, 3, 4, 5], resamples=200)
    assert ci["lo"] <= ci["mean"] <= ci["hi"]
    w = wilcoxon_signed_rank([5, 6, 7, 8, 9, 10], [1, 2, 3, 4, 5, 6])
    assert w["effect_size"] == 1.0 and w["p"] < 0.05
    assert wilcoxon_signed_rank([1, 2], [1, 2])["n"] == 0
    m = cluster_metrics(UnionFind(), {}, {}, {})
    assert m["link_rate"] is None          # no pseudonym changes: not applicable, not 0 (review R16)


# ------------------------------------------------- review follow-ups (3.2.0)
def test_wilcoxon_exact_small_samples():
    from pop_sim.v2.metrics import wilcoxon_signed_rank
    r = wilcoxon_signed_rank(list(range(1, 11)), [0] * 10)
    assert r["method"] == "exact"
    assert abs(r["p"] - 2 / 1024) < 1e-12           # ten pairs, all one way: 2 of 1,024 sign patterns
    assert r["effect_size"] == 1.0
    r = wilcoxon_signed_rank([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], [0, 0, 0, 0, 0, 0, 0, 0, 0, 11])
    assert abs(r["p"] - 6 / 1024) < 1e-12           # |diffs| 1 and 1 tie at mid-rank 1.5: W- = 1.5, three sign patterns reach it
    assert wilcoxon_signed_rank(list(range(40)), [0] * 40)["method"] == "normal"
    assert wilcoxon_signed_rank([1, 1], [1, 1])["p"] == 1.0


def test_revocation_rule_delays_and_reduces_revocations():
    from pop_sim.shuffle import ITSConfig, ITSSimulation
    from pop_sim.v2.mobility import RoadConfig

    def run(**kw):
        cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=10, seed=3),
                        round_seconds=30, pseudonyms_per_vehicle=3, seed=3, attribution="ledger", v2v=True,
                        former_holders=5, former_holder_strategy="S1", pseudonym_lifetime=900.0, **kw)
        sim = ITSSimulation(cfg)
        sim.run(3)
        return sim

    first = run()
    strict = run(revocation_reports=3, revocation_distinct_rsus=2)
    assert sum(v.revoked for v in first.vehicles) > sum(v.revoked for v in strict.vehicles)
    # nobody is revoked before the rule is met
    for vid, t in strict.revoked_at.items():
        reps = strict.report_tally[vid]
        assert len(reps) >= 3 and len({r["rsu"] for r in reps}) >= 2
    import pytest
    with pytest.raises(ValueError):
        ITSConfig(revocation_reports=0)


def test_trace_road_provisions_vehicles_that_enter_later(tmp_path):
    from pop_sim.shuffle import ITSConfig, ITSSimulation
    from pop_sim.v2.mobility_sumo import Corridor, FcdFrame, TraceRoad

    frames = [FcdFrame(float(t), {f"v{i}": (0.0, 0.0, "e0_0", 100.0 * i + 20.0 * t, 20.0)
                                  for i in range(3 + (t // 10))}) for t in range(60)]
    road = TraceRoad(frames, Corridor("lane", ["e0"], {"e0": 5000.0}, ring=False), n_rsu=6)
    assert len(road.vehicles) == 3 and len(road.all_vehicles) == 8 and not road.is_ring
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=3, mobility=True, v2v=True, seed=1), road=road)
    assert len(sim.vehicles) == 8
    assert sim.wrap_m > 1e9                       # a straight corridor never wraps around
    sim.run(2)
    assert sim.summary()["rounds"][-1]["messages"] > 0


def test_departing_vehicles_return_their_pseudonyms():
    """A vehicle that leaves a trace corridor hands back what it holds through
    its last RSU, so the recycled supply does not drain out of the study area."""
    from pop_sim.shuffle import ITSConfig, ITSSimulation
    from pop_sim.v2.mobility_sumo import Corridor, FcdFrame, TraceRoad

    # ten vehicles drive off the end of a 2 km corridor one after another
    frames = [FcdFrame(float(t), {f"v{i}": (0.0, 0.0, "e0_0", 200.0 * i + 25.0 * t, 25.0)
                                  for i in range(10) if 200.0 * i + 25.0 * t < 2000.0}) for t in range(90)]
    road = TraceRoad(frames, Corridor("lane", ["e0"], {"e0": 2000.0}, ring=False), n_rsu=6)
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=3, mobility=True, v2v=True, seed=1, pseudonyms_per_vehicle=3), road=road)
    sim.run(3)
    assert sim.departed_returns > 0
    gone = {v.index for v in sim.vehicles} - {mv.vid for mv in road.vehicles}
    for v in sim.vehicles:
        if v.index in gone:
            assert v.pseudonyms == [] and v.current is None and v.used == []   # returned and collected
    assert sim.summary()["departed_returns"] == sim.departed_returns


def test_tracker_counts_only_real_pseudonym_changes():
    """A beacon that carries the pseudonym its track already has is a
    continuation: under recycling the tracker used to re-link such beacons
    and count them as changes, inflating the recycle link rate."""
    from pop_sim.shuffle import ITSConfig, ITSSimulation
    from pop_sim.v2.mobility import RoadConfig

    for tracker in ("kalman", "nearest"):
        cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=10, seed=4),
                        round_seconds=30, pseudonyms_per_vehicle=3, seed=4, silent_period=3, position_noise_m=3,
                        issuance="recycle", tracker=tracker)
        sim = ITSSimulation(cfg)
        sim.run(4)
        t = sim.summary()["tracking"]
        assert t["pseudonym_changes"] == sim.true_changes == t["true_changes"]
        assert sim.adversary.changes <= sim.true_changes             # never more links than changes
        assert sim.adversary.changes == sim.adversary.correct + sim.adversary.wrong
        for old, new in sim.adversary.linked_pairs:                  # no link joins a label to itself
            assert old.split("#")[0] != new.split("#")[0]
        assert abs(t["linking_success_true"] - sim.adversary.correct / sim.true_changes) < 1e-12


def test_insider_key_custody_and_forgery():
    """E3b: in recycle, fresh and window modes the PKI, PMs, RSUs and cloud hold
    vehicle signing keys in software and can sign as a vehicle; with
    vehicle-generated keys (fresh_vgk, rekey) no infrastructure entity ever
    holds a key in use."""
    from pop_sim.shuffle import ITSConfig, ITSSimulation
    from pop_sim.v2.mobility import RoadConfig

    def run(mode):
        cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=10, seed=2),
                        round_seconds=30, pseudonyms_per_vehicle=3, seed=2, silent_period=3, position_noise_m=3,
                        attribution="ledger", v2v=True, issuance=mode, insider_forgery=True)
        sim = ITSSimulation(cfg)
        sim.run(3)
        return sim, sim.summary()["recycling"]["insider_forgery"]

    for mode in ("fresh_vgk", "rekey"):
        sim, r = run(mode)
        assert all(x["key_share"] == 0.0 and x["sent"] == 0 for x in r.values()), mode
        in_use_pks = {v.current.keys.pk_hex for v in sim.vehicles if v.current} | {p.keys.pk_hex for v in sim.vehicles for p in v.pseudonyms}
        for ent in (sim.pki, *sim.pms, *sim.rsus, sim.cloud):
            held = {k.pk_hex for k in ent.key_custody.values() if k.sk is not None}
            assert not (held & in_use_pks), f"{mode}: an infrastructure entity holds a key in use"
    sim, r = run("recycle")
    assert r["pki"]["key_share"] == 1.0 and r["pm"]["key_share"] > 0 and r["rsu"]["key_share"] > 0 and r["cloud"]["key_share"] > 0
    assert r["pki"]["sent"] == 3 and r["pki"]["accepted"] >= 1          # receivers accept the insider's message
    assert r["pki"]["holder_blamed"] >= 1                                # and the ledger blames the holder
    sim, r = run("fresh")
    assert r["pki"]["key_share"] == 1.0 and r["cloud"]["key_share"] == 0.0   # fresh pseudonyms are never uploaded


def test_stronger_insider_forges_without_trace():
    """E3b: an insider that claims a position within the 25 m one-second
    tolerance, or forges while the holder is silent after a change, is
    accepted by every receiver and by the RSU, and nobody is blamed."""
    from pop_sim.shuffle import ITSConfig, ITSSimulation
    from pop_sim.v2.mobility import RoadConfig

    for strategy in ("near", "silent"):
        cfg = ITSConfig(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=10, seed=3),
                        round_seconds=30, pseudonyms_per_vehicle=3, seed=3, silent_period=3, position_noise_m=3,
                        attribution="ledger", v2v=True, v2v_plausibility=True, issuance="recycle", insider_forgery=True,
                        insider_strategy=strategy, insider_forgeries_per_round=5)
        sim = ITSSimulation(cfg)
        sim.run(3)
        r = sim.summary()["recycling"]["insider_forgery"]["pki"]
        assert r["sent"] >= 10, strategy
        # a receiver may still reject one that last heard the recycled label from its previous holder elsewhere
        assert r["receiver_rate"] >= 0.95 and r["rsu_rate"] == 1.0 and r["holder_blamed"] == 0, (strategy, r)
    import pytest
    with pytest.raises(ValueError):
        ITSConfig(insider_strategy="teleport")
