import random

import pytest

from pop_sim import crypto
from pop_sim.block_time import BlockTimeParams, block_time
from pop_sim.entities import PKI, PMCloud, PrivacyManager
from pop_sim.experiments import exp_security
from pop_sim.shuffle import CONSENSUS_KINDS, ITSConfig, ITSSimulation


def test_block_time_formula():
    p = BlockTimeParams(tV=0.001, tP=0.01, tprep=0.05, tM=0.2, N=4)
    assert block_time(100, p) == pytest.approx(100 * 0.001 + 2 * 0.01 + 0.05 + 0.2 * 4)


def test_pki_package_is_encrypted_for_pm_and_signed():
    rng = random.Random(0)
    pki = PKI(rng)
    pm = PrivacyManager("PM-1", PMCloud(rng), rng)
    ps = pki.generate_pseudonyms(4)
    ct, sig = pki.package_for_pm(pm.keys.pk, ps)
    assert b"PID-" not in ct
    assert pm.receive_from_pki(ct, sig, pki.keys.pk) == 4
    assert all(p.verify(pki.keys.pk) for p in pm.pool)
    with pytest.raises(ValueError):
        pm.receive_from_pki(ct, crypto.sign(crypto.generate_keypair().sk, ct), pki.keys.pk)


@pytest.mark.parametrize("kind", CONSENSUS_KINDS)
def test_shuffle_rounds_keep_chains_valid_and_pseudonyms_conserved(kind):
    cfg = ITSConfig(n_pm=2, rsus_per_pm=2, vehicles_per_rsu=3, pseudonyms_per_vehicle=2,
                    consensus=kind, pow_difficulty=1, seed=3)
    sim = ITSSimulation(cfg)
    total = len(sim.pki.issued_pids)
    assert total == 2 * 2 * 3 * 2
    sim.run(3)
    s = sim.summary()
    assert s["pm_chain_valid"] and s["rsu_chains_valid"]
    assert s["pm_chain_blocks"] == 1 + 3
    for r in s["rounds"]:
        assert r["rejected_messages"] == 0
        assert r["shuffled"] == total                      # every used pseudonym comes back
        assert r["messages"] == total
    # after each round every vehicle holds a full fresh set
    assert all(len(v.pseudonyms) == 2 for v in sim.vehicles)
    # no pseudonym is held by two vehicles at the same time
    holders = [p.pid for v in sim.vehicles for p in v.pseudonyms]
    assert len(holders) == len(set(holders))


def test_pseudonyms_never_return_to_previous_holder_when_pool_allows():
    cfg = ITSConfig(n_pm=2, rsus_per_pm=3, vehicles_per_rsu=5, pseudonyms_per_vehicle=3, seed=11)
    sim = ITSSimulation(cfg)
    sim.run(4)
    assert sum(r.reassigned_to_previous_holder for r in sim.rounds) == 0
    assert sim.linkability_report()["pid_reused_by_same_vehicle"] == 0


def test_pop_block_proof_names_elected_pm():
    sim = ITSSimulation(ITSConfig(n_pm=3, rsus_per_pm=1, vehicles_per_rsu=2, seed=4))
    sim.run(2)
    for b in sim.pm_chain.chain[1:]:
        assert b.miner == b.proof["winner"] and b.miner in b.proof["mining_list"]
        assert b.proof["threshold_percent"] >= 50


def test_malicious_reuse_is_detected_and_revoked():
    sim = ITSSimulation(ITSConfig(n_pm=2, rsus_per_pm=2, vehicles_per_rsu=4, seed=7, malicious_vehicles=1))
    sim.run(3)
    rep = sim.linkability_report()
    assert rep["revoked_vehicles"] == 1
    bad = next(v for v in sim.vehicles if v.malicious)
    assert bad.revoked and sim.pki.is_revoked(bad.credential.cert)
    assert all(r["vehicle"] == bad.vehicle_id for r in sim.revocations)


def test_security_scenarios_all_hold():
    res = exp_security()["results"]
    for key, val in res.items():
        if isinstance(val, bool):
            assert val, key
    assert res["unlinkability"]["linkable_fraction"] == 0
