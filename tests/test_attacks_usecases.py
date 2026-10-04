import pytest

from pop_sim.v2 import attacks, usecases


@pytest.mark.parametrize("fn", [
    attacks.attack_value_forgery, attacks.attack_equivocation, attacks.attack_replay_proof,
    attacks.attack_sybil_keys, attacks.attack_pseudonym_replay, attacks.attack_pseudonym_clone,
    attacks.attack_forged_pseudonym, attacks.attack_fake_vehicle_flood, attacks.attack_revoked_vehicle_persists,
    attacks.attack_tamper_rsu_chain, attacks.attack_curious_rsu, attacks.attack_server_dos,
])
def test_attack_is_defended(fn):
    r = fn()
    assert r.outcome == "defended", (r.name, r.metrics)


def test_seed_grinding_is_blocked_by_chained_seed():
    r = attacks.attack_seed_grinding(rounds=150, budgets=(1, 64))
    m = r.metrics
    assert m["worst_share_chained_seed"] < 2 * m["fair_share"]
    assert m["share"]["block_hash/budget=64"] > m["share"]["chained_vrf/budget=64"]
    assert r.outcome == "defended"


def test_withholding_keeps_liveness():
    r = attacks.attack_withholding(rounds=300)
    rows = r.metrics["by_attacker_fraction"]
    assert all(v["attacker_blocks"] == 0 for v in rows.values())
    assert rows["0.5"]["mean_block_delay"] > rows["0.0"]["mean_block_delay"]
    assert rows["0.5"]["rounds_without_block"] < 0.01


def test_fake_vehicle_flood_without_check_hurts_and_with_check_does_not():
    m = attacks.attack_fake_vehicle_flood().metrics
    assert m["without_cert_check"]["fake_vehicles_served"] > 0
    assert m["with_cert_check"]["fake_vehicles_served"] == 0
    assert m["with_cert_check"]["honest_vehicles_short"] == 0
    assert m["with_cert_check"]["rejected_uncertified"] > 0


def test_attack_bench_quick_has_no_vulnerable_entry():
    res = attacks.run_all(quick=True)
    assert res["summary"].get("vulnerable", 0) == 0
    assert len(res["results"]) == len(attacks.ATTACKS)


def test_usecases_quick_run_and_report():
    res = usecases.run_all(quick=True)
    by = {r["scenario"]: r for r in res["results"]}
    assert set(by) == {f.__name__[3:] for f in usecases.USE_CASES}
    assert all(r["metrics"].get("chains_valid", True) for r in res["results"])
    toll = by["toll_service_access"]["metrics"]
    assert toll["permanent_ids_exposed"] == 0 and toll["accepted"] > 0
    inc = by["incident_revocation"]["metrics"]
    assert inc["revoked"] == inc["malicious"] and inc["honest_revoked"] == 0
    roam = by["cross_pm_roaming"]["metrics"]
    assert roam["proofs_verified"] > 0
    # privacy ordering: the lone rural vehicle is easier to track than the intersection crowd
    assert by["rural_night"]["metrics"]["linking_success"] > by["urban_intersection"]["metrics"]["linking_success"]


def test_threshold_and_miner_count_are_not_sender_controlled():
    r = attacks.attack_threshold_tampering()
    assert r.outcome == "defended", r.metrics
    assert r.metrics["accepted"] == 0 and r.metrics["honest_block_accepted"]


def test_multi_key_seed_choice_is_bounded():
    r = attacks.attack_multi_key_seed_choice(rounds=120, k_values=(1, 3))
    by = r.metrics["by_k"]
    for k, v in by.items():
        assert v["strategic_share"] < v["fair_share"] + 0.12
    assert r.metrics["max_gain_over_naive"] < 0.1
