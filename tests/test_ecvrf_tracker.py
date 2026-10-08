import random

import pytest

from pop_sim import ecvrf, vrf
from pop_sim.consensus.popv2 import V2Node, popv2_elect, verify_popv2_proof
from pop_sim.v2.mobility import Beacon, Road, RoadConfig
from pop_sim.v2.tracker_kalman import KalmanTrackingAdversary, hungarian, make_tracker

pytestmark = pytest.mark.skipif(not ecvrf.AVAILABLE, reason="coincurve not installed")


def test_ecvrf_unique_verifiable_and_bound_to_input_and_key():
    k = ecvrf.generate_keypair()
    pi = ecvrf.prove(k, b"alpha")
    assert ecvrf.prove(k, b"alpha") == pi
    beta = ecvrf.verify(k.public, b"alpha", pi)
    assert beta == ecvrf.proof_to_hash(pi) and len(beta) == 32
    assert ecvrf.verify(k.public, b"beta", pi) is None
    assert ecvrf.verify(ecvrf.generate_keypair().public, b"alpha", pi) is None
    for pos in (0, 40, 70):
        bad = pi[:pos] + bytes([pi[pos] ^ 1]) + pi[pos + 1:]
        assert ecvrf.verify(k.public, b"alpha", bad) is None
    assert ecvrf.verify(k.public, b"alpha", pi[:-1]) is None


def test_ecvrf_output_does_not_depend_on_nonce():
    """Two valid proofs with different nonces give the same beta (Gamma is fixed)."""
    k = ecvrf.generate_keypair()
    pi1 = ecvrf.prove(k, b"x")
    # re-prove with a different nonce by patching the nonce derivation input
    import hashlib
    x = ecvrf._os2ip(k.secret)
    y = ecvrf.PublicKey.from_secret(k.secret).format(compressed=True)
    h_pt = ecvrf._hash_to_curve(y, b"x")
    h = h_pt.format(compressed=True)
    gamma = ecvrf._mul(h_pt, x)
    k2 = ecvrf._os2ip(hashlib.sha256(b"other-nonce").digest()) % ecvrf.ORDER
    u = ecvrf.PublicKey.from_secret(ecvrf._i2osp(k2, 32)).format(compressed=True)
    v = ecvrf._mul(h_pt, k2).format(compressed=True)
    g = gamma.format(compressed=True)
    c = ecvrf._challenge(y, h, g, u, v)
    s = (k2 + c * x) % ecvrf.ORDER
    pi2 = g + ecvrf._i2osp(c, 16) + ecvrf._i2osp(s, 32)
    assert pi2 != pi1
    assert ecvrf.verify(k.public, b"x", pi2) == ecvrf.verify(k.public, b"x", pi1)


def test_vrf_dispatch_and_hex_roundtrip():
    for scheme in ("ecvrf", "rsa-fdh"):
        k = vrf.generate_vrf_keypair(1024, scheme)
        pi = vrf.vrf_prove(k, b"seed")
        pk = vrf.VRFPublicKey.from_hex(k.public.to_hex())
        assert vrf.vrf_verify(pk, b"seed", pi) == vrf.vrf_proof_to_hash(pi)
        assert vrf.vrf_verify(pk, b"seeds", pi) is None


def test_popv2_runs_on_ecvrf_and_rejects_forgeries():
    rng = random.Random(7)                                   # deterministic keys: no flaky no-miner rounds
    nodes = [V2Node(f"N{i}", vrf.generate_vrf_keypair(scheme="ecvrf", rng=rng)) for i in range(8)]
    certs = {n.node_id: n.pk.to_hex() for n in nodes}
    res, pi = popv2_elect(nodes, "11" * 32, 2)
    w = next(n for n in nodes if n.node_id == res.winner)
    proof = res.proof(w, pi)
    # with the certified key set the proof verifies whether or not anyone was below the threshold
    assert verify_popv2_proof(proof, "11" * 32, 2, res.winner, certified_pk=w.pk.to_hex(), certified_pks=certs)
    assert not verify_popv2_proof({**proof, "value": 0.0}, "11" * 32, 2, res.winner, certified_pks=certs)
    assert not verify_popv2_proof(proof, "11" * 32, 3, res.winner, certified_pks=certs)
    assert res.prove_seconds_mean < 0.005


def test_hungarian_small_cases():
    assert sorted(hungarian([[4, 1, 3], [2, 0, 5], [3, 2, 2]])) == [(0, 1), (1, 0), (2, 2)]
    assert sorted(hungarian([[1, 5], [5, 1], [9, 9]])) == [(0, 0), (1, 1)]
    assert hungarian([]) == []


def _run_tracker(kind: str, density: float, silent: int, seed: int = 1) -> float:
    cfg = RoadConfig(density_per_km=density, seed=seed)
    road = Road(cfg)
    rng = random.Random(seed)
    adv = make_tracker(kind, cfg.length_m)
    pid = {v.vid: f"P{v.vid}-0" for v in road.vehicles}
    silent_until = {v.vid: 0 for v in road.vehicles}
    changes = 0
    for t in range(1, 121):
        road.step(1.0)
        beacons = []
        for v in road.vehicles:
            if t % 30 == 0:
                pid[v.vid] = f"P{v.vid}-{t}"
                changes += 1
                silent_until[v.vid] = t + silent
            if t < silent_until[v.vid]:
                continue
            beacons.append(Beacon(float(t), pid[v.vid], (v.x + rng.gauss(0, 3)) % cfg.length_m, v.v, v.direction, v.rsu, v.vid))
        adv.observe(beacons)
    return adv.report(changes).linking_success


def test_kalman_tracker_is_at_least_as_strong_as_baseline_in_dense_traffic():
    assert isinstance(make_tracker("kalman", 5000.0), KalmanTrackingAdversary)
    k = _run_tracker("kalman", 40, 0)
    nn = _run_tracker("nn", 40, 0)
    assert k >= nn - 0.02
    assert k > 0.9
    # silence still lowers the Kalman tracker's success in dense traffic
    assert _run_tracker("kalman", 40, 10) < k
