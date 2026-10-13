"""Invariants for the follow-up review of v3.5.0 (G01 to G10).

Each test pins one defect the follow-up review reproduced: every report route
is counted, every credential that leaves an attacker is retained, exposure is
split into contiguous episodes, no handoff instant has two valid holders, the
equivalence test matches its estimand, opportunities have honest denominators,
and the CPU model can say where the time goes."""

import random

import pytest

from pop_sim import clock, crypto
from pop_sim.entities import PKI, PMCloud, PrivacyManager, SafetyMessage
from pop_sim.experiments_sumo import _run_trace
from pop_sim.shuffle import ITSConfig, ITSSimulation
from pop_sim.v2.metrics import OpCosts, cpu_breakdown, cpu_seconds, exposure_windows, paired_equivalence, t_cdf, t_ppf
from pop_sim.v2.mobility import RoadConfig
from pop_sim.v2.mobility_sumo import Corridor, parse_fcd, synthetic_fcd
from pop_sim.v2.v2v import V2VLayer


@pytest.fixture(autouse=True)
def _clock():
    clock.set_virtual(1_700_000_000.0)
    yield
    clock.set_virtual(None)


def _cfg(**kw):
    base = dict(n_pm=2, rsus_per_pm=3, consensus="pop", mobility=True, road=RoadConfig(density_per_km=10, seed=1),
                round_seconds=30, pseudonyms_per_vehicle=3, seed=1, silent_period=3, position_noise_m=3,
                attribution="ledger", v2v=True, v2v_plausibility=True, pseudonym_lifetime=900.0)
    base.update(kw)
    return ITSConfig(**base)


# G01 -------------------------------------------------------------------------
def test_every_report_route_is_counted_and_classified():
    sim = ITSSimulation(_cfg(issuance="recycle", former_holders=5, former_holder_strategy="S1"))
    sim.run(4)
    rep = sim.recycling_report()["reports"]
    routes = rep["by_route"]
    assert routes["forgery"]["naming_honest"] > 0
    assert routes.get("beacon", {}).get("naming_honest", 0) > 0          # the holder's own beacons, after a forgery
    attackers = {v.vehicle_id for v in sim.vehicles if v.former_holder}
    honest_named = {e["vehicle"] for e in sim.report_events if e["vehicle"] not in attackers}
    assert rep["distinct_honest_reported"] == len(honest_named)
    assert rep["reports"] == len(sim.report_events) == sum(r["reports"] for r in routes.values())
    assert rep["reports_naming_honest"] == sum(r["naming_honest"] for r in routes.values())
    # first-report rule: every honest vehicle reported is revoked, and only those
    revoked_honest = {v.vehicle_id for v in sim.vehicles if v.revoked and v.vehicle_id not in attackers}
    assert revoked_honest == honest_named


# G02 -------------------------------------------------------------------------
@pytest.mark.parametrize("mode", ["recycle", "fresh_vgk"])
def test_attackers_retain_every_credential_they_held(mode):
    sim = ITSSimulation(_cfg(issuance=mode, former_holders=5, former_holder_strategy="S2"))
    sim.run(4)
    ret = sim.recycling_report()["retention"]
    assert ret["retained_distinct"] == ret["held_distinct"] > 0
    for v in sim.vehicles:
        if v.former_holder:
            assert {k.pid for k in v.kept_keys} == set(v.history)


# G03 -------------------------------------------------------------------------
def test_separated_episodes_are_separate_windows():
    e = exposure_windows({("p", "A"): [0, 1, 100, 101]})
    assert e["contiguous"]["n"] == 2 and e["contiguous"]["values"] == [2.0, 2.0]
    assert e["cumulative_per_holding"]["values"] == [4.0]
    e = exposure_windows({("p", "A"): [0, 1], ("p", "B"): [2, 3]})        # same pid, two holdings
    assert e["cumulative_per_holding"]["n"] == 2
    e = exposure_windows({("p", "A"): [117, 118, 119, 120]}, horizon_end=120)
    assert e["contiguous"]["censored"] == 1


# G04 -------------------------------------------------------------------------
def test_no_handoff_instant_has_two_valid_holders():
    rng = random.Random(4)
    pki = PKI(rng)
    pm = PrivacyManager("PM-1", PMCloud(rng), rng)
    pm.pm_cert = pki.certify_pm(pm.pm_id, pm.keys.pk_hex)
    p = pki.generate_pseudonyms(1)[0]
    old, new = crypto.generate_keypair(), crypto.generate_keypair()
    t0 = clock.now()
    hc_old = pm.sign_holder_cert(p.pid, old.pk_hex, t0, t0 + 30)           # outgoing holder: (t0, t0 + 30]
    hc_new = pm.sign_holder_cert(p.pid, new.pk_hex, t0 + 30, t0 + 60)      # incoming holder: (t0 + 30, t0 + 60]
    v2v = V2VLayer(pki.keys.pk, 10_000.0, mode="holder", pm_cert_check=pki.verify_pm_cert)

    def msg(key, hc, t):
        m = SafetyMessage(p.pid, (10.0, 0.0), 20.0, 1.0, t)
        m.signature = crypto.sign(key.sk, m.body()).hex()
        m.cred = {**p.cert_wire(), "holder": dict(hc)}
        return m

    b = t0 + 30
    assert v2v.verify(msg(old, hc_old, b), b)[0]                           # the outgoing holder's last message
    assert v2v.verify(msg(new, hc_new, b), b) == (False, "holder-window")  # the incoming holder is not yet valid
    later = b + 0.001
    assert v2v.verify(msg(old, hc_old, later), later) == (False, "holder-window")   # old key, old certificate
    assert v2v.verify(msg(old, hc_new, later), later)[0] is False           # old key, new public certificate
    assert v2v.verify(msg(new, hc_new, later), later)[0]                    # only the new holder from here on


# G06 -------------------------------------------------------------------------
def test_equivalence_tests_the_mean_it_reports():
    assert t_cdf(2.262157, 9) == pytest.approx(0.975, abs=1e-5)
    assert t_ppf(0.95, 9) == pytest.approx(1.833113, abs=1e-5)
    r = paired_equivalence([0.004] * 9 + [0.069], [0.0] * 10, margin=0.01)   # the review's counterexample
    assert r["mean_diff"] == pytest.approx(0.0105) and r["equivalent"] is False
    near = paired_equivalence([0.001, 0.002, -0.001, 0.0015, 0.003, 0.0, 0.002, 0.001, -0.0005, 0.0025],
                              [0.0] * 10, margin=0.01)
    assert near["equivalent"] is True
    for x in (r, near):                                                       # TOST <=> the 90 % interval in the margin
        lo, hi = x["ci90"]
        assert x["equivalent"] == (-0.01 < lo and hi < 0.01)


# G08 -------------------------------------------------------------------------
def test_opportunity_tiers_are_nested_and_expiry_counts():
    sim = ITSSimulation(_cfg(issuance="recycle", former_holders=5, former_holder_strategy="S3",
                             pseudonym_lifetime=60.0))
    sim.run(4)
    f = sim.recycling_report()["forgery"]
    assert f["key_checks"] >= f["valid_key_seconds"] >= f["eligible"] > 0
    assert f["valid_key_seconds"] < f["key_checks"]                         # 60 s certificates expire inside 120 s


# G10 -------------------------------------------------------------------------
def test_cpu_breakdown_names_the_operations():
    costs = OpCosts(1e-4, 2e-4, 3e-5, 1e-4, 1e-4, "test", 1e-9, 1e-9)
    load = {"signatures": 8, "verifications": 899, "encryptions": 8, "decryptions": 8,
            "encrypted_bytes": 400_000, "decrypted_bytes": 400_000}
    b = cpu_breakdown(load, costs)
    assert sum(b.values()) == pytest.approx(cpu_seconds(load, costs))
    assert b["verify"] > 10 * b["decrypt"]                                  # the review's PM case: verification dominates
    sim = ITSSimulation(_cfg(issuance="fresh"))
    sim.run(2)
    by_op = sim.load_report()["cpu_by_operation_per_1000_veh_h"]["pm"]
    assert by_op["verify"] > by_op["decrypt"]


# minor: SUMO revocation share over the vehicles in the evaluated window --------
def test_sumo_share_is_over_the_window(tmp_path):
    path = tmp_path / "trace.xml"
    lengths = synthetic_fcd(str(path), vehicles=12, seconds=70, seed=3)
    pop = _run_trace(parse_fcd(str(path)), Corridor("lane", ["e0", "e1", "e2"], lengths), seed=3, rounds=1,
                     n_pm=1, rsus_per_pm=2, issuance="recycle", former_holders=2,
                     former_holder_strategy="S1")["population"]
    assert pop["honest"] + pop["attackers"] <= pop["vehicles_in_trace"]
    if pop["honest"]:
        assert pop["revoked_honest_share"] == pytest.approx(pop["revoked_honest"] / pop["honest"])
    assert pop["revoked_honest_share_of_trace"] == pytest.approx(pop["revoked_honest"] / pop["honest_in_trace"])
