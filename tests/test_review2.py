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
    # versions (H08): label, key and expiry.  Allocation never returns a label to a vehicle that
    # held it, so here one label is one version; the test pins that, and retention by version
    assert ret["held_versions"] == ret["held_distinct"]
    assert ret["retained_versions"] == ret["held_versions"]
    for v in sim.vehicles:
        if v.former_holder:
            assert {k.pid for k in v.kept_keys} == set(v.history)


# G03 -------------------------------------------------------------------------
def test_separated_episodes_are_separate_windows():
    e = exposure_windows({("p", "A"): [0, 1, 100, 101]})
    assert e["contiguous"]["n"] == 2 and [x["span_s"] for x in e["segments"]] == [2.0, 2.0]
    assert [h["span_s"] for h in e["holdings"]] == [4.0]
    assert all(x["pid"] == "p" and x["holder"] == "A" for x in e["segments"])      # identifiers kept (H03)
    e = exposure_windows({("p", "A"): [0, 1], ("p", "B"): [2, 3]})        # same pid, two holdings
    assert e["cumulative_per_holding"]["n"] == 2
    e = exposure_windows({("p", "A"): [117, 118, 119, 120]}, horizon_end=120)
    assert e["contiguous"]["truncated"] == 1 and e["contiguous_complete"]["n"] == 0
    e = exposure_windows({("p", "A"): [0, 2]})                            # a tolerated 1 s gap
    assert e["segments"][0]["span_s"] == 3.0 and e["segments"][0]["accepted_s"] == 2.0


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


def test_real_handoff_ledger_window_and_key_agree():
    """An actual rekey transfer (review H02): at the handoff instant the ledger,
    the receivers' holder window and the verifying key all name the outgoing
    holder; from the next instant all three name the incoming one."""
    sim = ITSSimulation(_cfg(issuance="rekey"))
    held: dict = {}                                                          # pid -> [(vehicle, bound copy)]
    real_bind = sim._bind_holders

    def record(rsu, pm):
        real_bind(rsu, pm)
        for v in rsu.vehicles:
            for p in v.pseudonyms:
                held.setdefault(p.pid, []).append((v.vehicle_id, p))

    sim._bind_holders = record
    sim.run(4)
    moved = [(pid, h[i], h[i + 1]) for pid, h in held.items() for i in range(len(h) - 1)
             if h[i][0] != h[i + 1][0] and h[i + 1][1].holder_cert["t_start"] == h[i][1].holder_cert["t_end"]]
    assert moved                                                             # a label passed straight to a new holder
    pid, (vid0, p0), (vid1, p1) = moved[0]
    v0 = next(v for v in sim.vehicles if v.vehicle_id == vid0)
    v1 = next(v for v in sim.vehicles if v.vehicle_id == vid1)
    t_b = p0.holder_cert["t_end"]                                           # the windows meet at the boundary
    ledger, v2v = sim.ledger, sim.v2v

    def msg(p, t):
        m = SafetyMessage(pid, (10.0, 0.0), 20.0, 1.0, t)
        m.signature = crypto.sign(p.keys.sk, m.body()).hex()
        m.cred = p.cert_wire()
        return m

    later = t_b + 0.001
    assert ledger.owner_at(pid, t_b) == (v0.vehicle_id, p0.keys.pk_hex)      # outgoing holder owns the instant
    assert ledger.owner_at(pid, later) == (v1.vehicle_id, p1.keys.pk_hex)
    assert v2v.verify(msg(p0, t_b), t_b)[0]
    assert ledger.check(pid, v0.vehicle_id, msg(p0, t_b), {})[0]
    assert not v2v.verify(msg(p1, t_b), t_b)[0]                             # incoming holder not yet valid
    assert not ledger.check(pid, v1.vehicle_id, msg(p1, t_b), {})[0]
    assert not v2v.verify(msg(p0, later), later)[0]                          # outgoing holder no longer valid
    assert ledger.check(pid, v0.vehicle_id, msg(p0, later), {}) == (False, "pseudonym-held-by-another-vehicle")
    assert v2v.verify(msg(p1, later), later)[0]
    assert ledger.check(pid, v1.vehicle_id, msg(p1, later), {})[0]


@pytest.mark.parametrize("mode", ["recycle", "rekey", "window", "fresh_vgk"])
def test_honest_messages_pass_the_rsu_check_in_every_mode(mode):
    """Attack-free: the time-aware ledger check (H02) accepts every honest
    message, with the key bound at allotment (rekey) included."""
    sim = ITSSimulation(_cfg(issuance=mode))
    sim.run(3)
    flagged = [reason for r in sim.rsus for _, reason in r.flagged]
    assert flagged == [] and not any(v.revoked for v in sim.vehicles)


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
@pytest.mark.parametrize("mode,strategy", [("recycle", "S1"), ("recycle", "S3"), ("fresh_vgk", "S2")])
def test_opportunity_tiers_are_nested_against_sent_events(mode, strategy):
    """Every check lands in exactly one bucket and nothing is sent outside the
    eligible seconds, checked against the messages actually sent (review H01)."""
    sim = ITSSimulation(_cfg(issuance=mode, former_holders=5, former_holder_strategy=strategy,
                             pseudonym_lifetime=60.0))
    sent_expired = []
    real = sim.former.record

    def spy(fm, acc, rx, rsu_ok, now):
        sender = next(v for v in sim.vehicles if v.index == fm.attacker_vid)
        p = next(k for k in sender.kept_keys if k.pid == fm.msg.pid)
        sent_expired.append(p.expiry < now)
        return real(fm, acc, rx, rsu_ok, now)

    sim.former.record = spy
    sim.run(4)
    f = sim.recycling_report()["forgery"]
    assert f["key_checks"] == f["held_by_self"] + f["retired_skips"] + f["expired_key_seconds"] + f["valid_key_seconds"]
    assert f["valid_key_seconds"] >= f["eligible"] >= f["sent"] == len(sent_expired)
    assert not any(sent_expired)                                            # nothing sent under an expired certificate
    if mode == "recycle":
        assert f["expired_key_seconds"] > 0                                  # 60 s certificates expire inside 120 s
    else:
        assert f["retired_skips"] > 0 and f["sent"] == 0                     # fresh labels are never reused


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


# Round 3 additions -------------------------------------------------------------
def test_delegated_fresh_labels_are_pm_signed_and_checked():
    """fresh_pm (the delegated control): fresh labels for vehicle keys, signed by
    a PM whose PKI certificate rides along; receivers check that chain."""
    sim = ITSSimulation(_cfg(issuance="fresh_pm"))
    sim.run(2)
    assert sim.load_report()["steady_state"]["pki"]["signatures"] == 0
    assert sim.recycling_report()["v2v"]["honest_rejected_implausible"] == 0
    assert sim.recycling_report()["v2v"]["accepted"] == sim.recycling_report()["v2v"]["received"] > 0
    p = next(p for v in sim.vehicles for p in v.pseudonyms)
    m = SafetyMessage(p.pid, (10.0, 0.0), 20.0, 1.0, clock.now())
    m.signature = crypto.sign(p.keys.sk, m.body()).hex()
    m.cred = p.cert_wire()
    assert sim.v2v.verify(m, clock.now())[0]
    bad = dict(m.cred)
    bad["issuer_chain"] = {**bad["issuer_chain"], "pm_cert": bad["issuer_chain"]["pm_cert"][::-1]}
    m.cred = bad
    assert sim.v2v.verify(m, clock.now()) == (False, "pm-certificate-invalid")


def test_one_insider_at_a_time():
    sim = ITSSimulation(_cfg(issuance="recycle", insider_forgery=True, insider_active=("pm",)))
    sim.run(2)
    assert set(sim.recycling_report()["insider_forgery"]) == {"pm"}


def test_quarantine_withdraws_labels_and_revokes_nobody():
    sim = ITSSimulation(_cfg(issuance="recycle", former_holders=5, former_holder_strategy="S1",
                             misbehaviour_response="quarantine_pseudonym"))
    sim.run(4)
    r = sim.recycling_report()
    assert not any(v.revoked for v in sim.vehicles)
    q = r["quarantine"]
    assert q["labels"] > 0 and q["labels"] == len(sim.quarantines)
    assert all(x["pid"] in sim.ledger.retired for x in sim.quarantines)
    held = {p.pid for v in sim.vehicles for p in v.pseudonyms}
    assert not held & {x["pid"] for x in sim.quarantines if x["t"] < clock.now() - 30}   # never handed out again


def test_provenance_archives_untracked_and_dirty_source(tmp_path, monkeypatch):
    import subprocess

    from pop_sim import cli
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    for cmd in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c"]):
        subprocess.run(["git", *cmd], check=True)
    clean = cli._capture_provenance()
    assert clean["source_dirty"] is False and clean["source_snapshot"] is None
    (tmp_path / "src" / "a.py").write_text("x = 2\n")
    (tmp_path / "src" / "b.py").write_text("y = 3\n")                        # untracked source counts too
    dirty = cli._capture_provenance()
    assert dirty["source_dirty"] is True and dirty["untracked_source_files"] == ["src/b.py"]
    snap = __import__("json").loads((tmp_path / dirty["source_snapshot"]).read_text())
    assert "x = 2" in snap["diff"] and snap["untracked"]["src/b.py"] == "y = 3\n"


@pytest.mark.parametrize("history", ["shared", "local"])
def test_attack_free_runs_revoke_nobody(history):
    """No attackers, no revocations: an RSU's own clone history of a previous
    holding must not count against the label's next holder (found by the
    round-3 attack-free control under local histories)."""
    for seed in (1, 2):
        sim = ITSSimulation(_cfg(issuance="recycle", seed=seed, road=RoadConfig(density_per_km=10, seed=seed),
                                 rsu_history=history))
        sim.run(4)
        assert not any(v.revoked for v in sim.vehicles)
