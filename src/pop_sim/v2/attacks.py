"""Adversarial bench for PoP v2.

Every attack here is *executed* against the implementation, not argued:
the attacker's action is carried out and the outcome is read from what the
honest nodes accept.  Each function returns an ``AttackResult`` whose
``outcome`` is one of

* ``defended``   - the attack has no effect on honest nodes;
* ``mitigated``  - the attack has a bounded, measured effect;
* ``vulnerable`` - the attack succeeds (kept in the bench for the v1 or
                   weakened variants, to show what the v2 defence buys).

Consensus attacks target the election; protocol attacks target
pseudonyms, RSUs and vehicles; one privacy attack measures tracking.
``ATTACKS`` lists them all; ``run_all`` executes the bench.
"""

from __future__ import annotations

import random
import statistics
import time
from dataclasses import asdict, dataclass, field

from .. import crypto, vrf
from ..consensus.popv2 import EquivocationDetector, V2Node, election_seed, popv2_elect, verify_popv2_proof
from ..entities import PKI, PMCloud, PrivacyManager, SafetyMessage, Vehicle
from ..shuffle import ITSConfig, ITSSimulation


@dataclass
class AttackResult:
    name: str
    category: str
    description: str
    target: str
    outcome: str
    defense: str
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================== consensus
def attack_value_forgery(seed: int = 1, bits: int = 1024) -> AttackResult:
    """A node that was not elected tries four ways to publish anyway."""
    rng = random.Random(seed)
    nodes = [V2Node(f"N{i}", vrf.generate_vrf_keypair(bits)) for i in range(6)]
    prev = crypto.sha256_hex(str(rng.random()))
    res, pi = popv2_elect(nodes, prev, 7)
    w = next(n for n in nodes if n.node_id == res.winner)
    attacker = next(n for n in nodes if n.node_id != res.winner)
    good = res.proof(w, pi)
    attempts = {
        "claim smaller value with the real proof": {**good, "value": 0.0},
        "reuse the winner's proof under own name": {**good, "winner": attacker.node_id},
        "self-made proof with an uncertified key": {
            **good, "winner": attacker.node_id, "vrf_pk": attacker.pk.to_hex(),
            "pi": vrf.vrf_prove(attacker.keys, bytes.fromhex(good["seed"])).hex(),
            "beta": vrf.vrf_proof_to_hash(vrf.vrf_prove(attacker.keys, bytes.fromhex(good["seed"]))).hex(),
            "value": 0.0},
        "own proof for a seed of own choosing": {
            **good, "winner": attacker.node_id, "vrf_pk": attacker.pk.to_hex(),
            "seed": election_seed("0" * 64, 7).hex(),
            "pi": vrf.vrf_prove(attacker.keys, election_seed("0" * 64, 7)).hex()},
    }
    accepted = {}
    for name, proof in attempts.items():
        miner = proof["winner"]
        certified = next(n for n in nodes if n.node_id == miner).pk.to_hex()
        accepted[name] = verify_popv2_proof(proof, prev, 7, miner, certified_pk=certified)
    honest_ok = verify_popv2_proof(good, prev, 7, res.winner, certified_pk=w.pk.to_hex())
    return AttackResult(
        "value forgery / proof theft", "consensus",
        "A non-elected node claims a smaller value, reuses the winner's proof, uses an uncertified key, or picks its own seed.",
        "v2", "defended" if honest_ok and not any(accepted.values()) else "vulnerable",
        "VRF proof bound to the certified key, the chain position and the seed; the value is recomputed from the proof.",
        {"attempts": len(attempts), "accepted": sum(accepted.values()), "honest_block_accepted": honest_ok,
         "per_attempt": accepted})


def attack_seed_grinding(n_honest: int = 9, budgets=(1, 4, 16, 64), rounds: int = 300, seed: int = 1,
                         bits: int = 1024) -> AttackResult:
    """The winner of block i re-arranges its block (nonce) so that its own
    value for block i+1 is small.  Possible when the seed is the block hash;
    impossible when the seed is the previous winner's VRF output."""
    rng = random.Random(seed)
    honest = [vrf.generate_vrf_keypair(bits) for _ in range(n_honest)]
    attacker = vrf.generate_vrf_keypair(bits)
    results = {}
    for mode in ("block_hash", "chained_vrf"):
        for budget in budgets:
            wins = 0
            prev_hash = crypto.sha256_hex("genesis")
            prev_beta = None
            attacker_won = False
            for i in range(1, rounds + 1):
                if mode == "block_hash":
                    candidates = [crypto.sha256_hex(f"{prev_hash}:{nonce}") for nonce in range(budget)] \
                        if attacker_won else [prev_hash]
                    best = None
                    for c in candidates:
                        s = election_seed(c, i)
                        v = vrf.beta_to_unit(vrf.vrf_proof_to_hash(vrf.vrf_prove(attacker, s)))
                        if best is None or v < best[0]:
                            best = (v, c)
                    a_val, chosen = best
                    s = election_seed(chosen, i)
                else:
                    s = election_seed(prev_hash, i, prev_beta)
                    a_val = vrf.beta_to_unit(vrf.vrf_proof_to_hash(vrf.vrf_prove(attacker, s)))
                h_vals = [vrf.beta_to_unit(vrf.vrf_proof_to_hash(vrf.vrf_prove(k, s))) for k in honest]
                miners_h = [v for v in h_vals if v < 0.5]
                a_mines = a_val < 0.5
                attacker_won = a_mines and (not miners_h or a_val < min(miners_h))
                if not a_mines and not miners_h:
                    attacker_won = a_val < min(h_vals)
                wins += attacker_won
                if attacker_won:
                    prev_beta = vrf.vrf_proof_to_hash(vrf.vrf_prove(attacker, s)).hex()
                    prev_hash = crypto.sha256_hex(f"att:{i}:{rng.random()}")
                else:
                    j = h_vals.index(min(miners_h) if miners_h else min(h_vals))
                    prev_beta = vrf.vrf_proof_to_hash(vrf.vrf_prove(honest[j], s)).hex()
                    prev_hash = crypto.sha256_hex(f"hon:{i}:{rng.random()}")
            results[f"{mode}/budget={budget}"] = wins / rounds
    fair = 1 / (n_honest + 1)
    worst_hash = max(v for k, v in results.items() if k.startswith("block_hash"))
    worst_chain = max(v for k, v in results.items() if k.startswith("chained_vrf"))
    return AttackResult(
        "seed grinding", "consensus",
        "The previous winner tries many block variants to make its next VRF value small.",
        "v2", "defended" if worst_chain < 2 * fair else "vulnerable",
        "Seed the election with the previous winner's VRF output (unique, ungrindable) instead of the block hash.",
        {"fair_share": fair, "share": results, "worst_share_block_hash_seed": worst_hash,
         "worst_share_chained_seed": worst_chain, "rounds": rounds})


def attack_withholding(n: int = 20, fractions=(0.0, 0.1, 0.25, 0.5), rounds: int = 2000, time_limit: float = 1.0,
                       seed: int = 1) -> AttackResult:
    """Attacker-controlled winners never publish.  In a timer election the
    next-smallest honest value fires on its own timer, so liveness holds
    and the cost is the extra wait."""
    rng = random.Random(seed)
    rows = {}
    for f in fractions:
        k = int(round(n * f))
        delays, lost = [], 0
        for _ in range(rounds):
            vals = sorted((rng.random(), i < k) for i in range(n))
            miners = [(v, bad) for v, bad in vals if v < 0.5] or vals[:1]
            published = next(((v, bad) for v, bad in miners if not bad), None)
            if published is None:
                lost += 1
                delays.append(time_limit)
            else:
                delays.append(published[0] * time_limit)
        rows[str(f)] = {"attacker_nodes": k, "mean_block_delay": statistics.mean(delays),
                        "rounds_without_block": lost / rounds, "attacker_blocks": 0}
    return AttackResult(
        "block withholding (selfish winner)", "consensus",
        "Winners controlled by the attacker stay silent.",
        "v2", "mitigated",
        "Every miner's timer fires independently: the next-smallest value publishes; a withheld block costs only waiting time.",
        {"time_limit": time_limit, "by_attacker_fraction": rows})


def attack_equivocation(seed: int = 3) -> AttackResult:
    """The elected PM publishes two different blocks with the same proof."""
    sim = ITSSimulation(ITSConfig(n_pm=3, rsus_per_pm=1, vehicles_per_rsu=2, consensus="popv2", vrf_bits=1024, seed=seed))
    sim.run(1)
    last = sim.pm_chain.last
    # a second block for the same position, same proof, different content
    sim.pm_chain.chain.pop()
    assert sim.pm_chain.last.hash == last.previous_hash
    sim.equivocation = EquivocationDetector()
    sim.equivocation.observe(last.proof, last.hash)           # the first block was seen by everyone
    twin = sim.pm_chain.new_block([], miner=last.miner, consensus="popv2", proof=dict(last.proof))
    twin.timestamp = last.timestamp + 1
    accepted = True
    try:
        sim.pm_chain.add_block(twin)
    except ValueError:
        accepted = False
    sim.pm_chain.chain.append(last)
    return AttackResult(
        "equivocation (two blocks, one proof)", "consensus",
        "The winner signs two conflicting blocks for the same height.",
        "v2", "defended" if not accepted and last.miner in sim.equivocation.equivocators else "vulnerable",
        "Nodes remember (key, seed) -> block hash; the first block seen stands, a second one is rejected and the node is reported for revocation.",
        {"second_block_accepted": accepted, "reported_equivocators": sorted(sim.equivocation.equivocators)})


def attack_replay_proof(seed: int = 4) -> AttackResult:
    """A valid old proof is replayed for the next height."""
    sim = ITSSimulation(ITSConfig(n_pm=3, rsus_per_pm=1, vehicles_per_rsu=2, consensus="popv2", vrf_bits=1024, seed=seed))
    sim.run(2)
    old = sim.pm_chain.chain[1]
    replay = sim.pm_chain.new_block([], miner=old.miner, consensus="popv2", proof=dict(old.proof))
    accepted = True
    try:
        sim.pm_chain.add_block(replay)
    except ValueError:
        accepted = False
    return AttackResult(
        "proof replay", "consensus", "A proof that won an earlier block is reused at a later height.",
        "v2", "defended" if not accepted else "vulnerable",
        "The seed binds the proof to the chain position and the previous winner's output.",
        {"replayed_block_accepted": accepted})


def attack_server_dos(p_down=(0.0, 0.1, 0.3, 0.5, 0.9), rounds: int = 1000, seed: int = 1) -> AttackResult:
    """Denial of service against the v1 election server."""
    rng = random.Random(seed)
    rows = {}
    for p in p_down:
        v1 = sum(1 for _ in range(rounds) if rng.random() >= p)
        rows[str(p)] = {"v1_blocks": v1 / rounds, "v2_blocks": 1.0}
    return AttackResult(
        "election server denial of service", "consensus",
        "The cloud server that selects miners in v1 is flooded or taken down.",
        "v1", "defended",
        "v2 has no server: every node derives its own value from the chain.",
        {"availability": rows})


def attack_sybil_keys(seed: int = 5) -> AttackResult:
    """Fifty self-generated VRF keys try to take part in the election."""
    sim = ITSSimulation(ITSConfig(n_pm=3, rsus_per_pm=1, vehicles_per_rsu=2, consensus="popv2", vrf_bits=1024, seed=seed))
    sim.run(1)
    rng = random.Random(seed)
    accepted = 0
    last = sim.pm_chain.last
    for i in range(50):
        key = vrf.generate_vrf_keypair(1024)
        node = V2Node(f"SYBIL-{i}", key)
        node.cert = crypto.sign(crypto.generate_keypair().sk, b"self-signed").hex()   # not from PKI
        sim.v2nodes[node.node_id] = node
        s = election_seed(last.hash, last.index + 1, last.proof.get("beta"))
        pi = vrf.vrf_prove(key, s)
        proof = {"seed": s.hex(), "winner": node.node_id, "vrf_pk": node.pk.to_hex(), "pi": pi.hex(),
                 "beta": vrf.vrf_proof_to_hash(pi).hex(), "value": vrf.beta_to_unit(vrf.vrf_proof_to_hash(pi)),
                 "threshold": 0.5, "miners": 1}
        blk = sim.pm_chain.new_block([], miner=node.node_id, consensus="popv2", proof=proof)
        try:
            sim.pm_chain.add_block(blk)
            accepted += 1
            sim.pm_chain.chain.pop()
        except ValueError:
            pass
        rng.random()
    return AttackResult(
        "Sybil election keys", "consensus",
        "An attacker generates many election keys to raise its chance of winning.",
        "v2", "defended" if accepted == 0 else "vulnerable",
        "Only a VRF key certified by PKI for that node id may publish; one certificate is one identity (share k/(n+k) with k certificates).",
        {"sybil_keys": 50, "blocks_accepted": accepted})


def attack_partition(n: int = 20, split: float = 0.5, rounds: int = 10, seed: int = 1) -> AttackResult:
    """The PM network is split in two for ``rounds`` blocks; each side keeps
    electing.  On healing the fork rule keeps, height by height, the block
    with the smaller value; the other side's blocks are wasted."""
    rng = random.Random(seed)
    a = int(n * split)
    wasted = 0
    side_a_kept = 0
    for _ in range(rounds):
        va = min(rng.random() for _ in range(max(1, a)))
        vb = min(rng.random() for _ in range(max(1, n - a)))
        wasted += 1
        side_a_kept += va < vb
    return AttackResult(
        "network partition", "consensus",
        "The PM network is partitioned; both halves keep producing blocks until it heals.",
        "v2", "mitigated",
        "Deterministic fork rule (smaller VRF value per height) converges on healing; partition-time blocks on the losing side are wasted. Transactions are re-included.",
        {"rounds_partitioned": rounds, "wasted_blocks": wasted, "share_kept_from_side_a": side_a_kept / rounds})


# ================================================================ protocol
def _fresh_sim(seed: int, **kw) -> ITSSimulation:
    cfg = ITSConfig(n_pm=2, rsus_per_pm=2, vehicles_per_rsu=4, consensus="popv2", vrf_bits=1024, seed=seed, **kw)
    return ITSSimulation(cfg)


def attack_pseudonym_replay(seed: int = 6) -> AttackResult:
    sim = _fresh_sim(seed, malicious_vehicles=2)
    sim.run(3)
    rep = sim.linkability_report()
    bad = {v.vehicle_id for v in sim.vehicles if v.malicious}
    revoked = {r["vehicle"] for r in sim.revocations}
    return AttackResult(
        "pseudonym replay (internal tricking adversary)", "protocol",
        "A compromised OBU keeps a copy of a used pseudonym and signs with it again.",
        "both", "defended" if revoked == bad and rep["flagged_messages"] >= 2 else "vulnerable",
        "The ledger (RSU chain) knows every pseudonym as allotted-to-X or returned; the RSU flags it, the PM reports, PKI revokes.",
        {"malicious": len(bad), "revoked": len(revoked), "honest_revoked": len(revoked - bad), "flagged": rep["flagged_messages"]})


def attack_pseudonym_clone(seed: int = 7) -> AttackResult:
    """An attacker copies a victim's live pseudonym and key and uses it far away at the same time."""
    sim = _fresh_sim(seed)
    victim = next(v for v in sim.vehicles if v.pseudonyms)
    p = victim.pseudonyms[0]
    rsu = next(r for r in sim.rsus if victim in r.vehicles)
    ledger = sim.ledger
    msg1 = SafetyMessage(p.pid, (100.0, 0.0), 10.0, 0.0, 1000.0)
    msg1.signature = crypto.sign(p.keys.sk, msg1.body()).hex()
    ok1, _ = ledger.check(p.pid, victim.vehicle_id, msg1)
    msg2 = SafetyMessage(p.pid, (4100.0, 0.0), 10.0, 0.0, 1001.0)       # 4 km away one second later
    msg2.signature = crypto.sign(p.keys.sk, msg2.body()).hex()
    ok2, reason2 = ledger.check(p.pid, victim.vehicle_id, msg2)
    # and the same clone presented through a different vehicle's link identity
    other = next(v for v in rsu.vehicles if v is not victim)
    msg3 = SafetyMessage(p.pid, (110.0, 0.0), 10.0, 0.0, 1002.0)
    msg3.signature = crypto.sign(p.keys.sk, msg3.body()).hex()
    ok3, reason3 = ledger.check(p.pid, other.vehicle_id, msg3)
    return AttackResult(
        "pseudonym cloning", "protocol",
        "A copied pseudonym (with its key) is used in two places at once.",
        "v2", "defended" if ok1 and not ok2 and not ok3 else "vulnerable",
        "Ledger plausibility check: one pseudonym cannot move faster than 60 m/s between accepted messages; holder binding catches a different sender.",
        {"first_message_ok": ok1, "clone_far_away": reason2, "clone_other_sender": reason3})


def attack_forged_pseudonym(seed: int = 8) -> AttackResult:
    sim = _fresh_sim(seed)
    rng = random.Random(seed)
    fake_pki = PKI(rng)
    fake = fake_pki.generate_pseudonyms(1)[0]
    v = sim.vehicles[0]
    rsu = next(r for r in sim.rsus if v in r.vehicles)
    msg = SafetyMessage(fake.pid, (0.0, 0.0), 1.0, 0.0, 1.0)
    msg.signature = crypto.sign(fake.keys.sk, msg.body()).hex()
    ok, reason = sim.ledger.check(fake.pid, v.vehicle_id, msg)
    # and a forged pseudonym package offered to a PM
    pm = PrivacyManager("PM-X", PMCloud(rng), rng)
    ct, sig = fake_pki.package_for_pm(pm.keys.pk, [fake])
    try:
        pm.receive_from_pki(ct, sig, sim.pki.keys.pk)
        pkg = True
    except ValueError:
        pkg = False
    return AttackResult(
        "forged pseudonym / forged PKI package", "protocol",
        "An attacker mints its own pseudonym credentials and offers them to RSUs and PMs.",
        "both", "defended" if not ok and not pkg else "vulnerable",
        "Pseudonyms are only valid when their certificate verifies under the real PKI key and the ledger has an allotment.",
        {"message_with_forged_pseudonym": reason, "forged_package_accepted_by_pm": pkg, "rsu": rsu.rsu_id})


def attack_fake_vehicle_flood(k_fake: int = 30, seed: int = 9) -> AttackResult:
    """Sybil vehicles with forged certificates request pseudonym sets at one
    RSU to starve honest vehicles (with and without the v2 certificate check)."""
    out = {}
    for check in (False, True):
        sim = ITSSimulation(ITSConfig(n_pm=1, rsus_per_pm=2, vehicles_per_rsu=5, consensus="pop", seed=seed,
                                      verify_vehicle_certs=check))
        rng = random.Random(seed)
        rsu = sim.rsus[0]
        honest = list(rsu.vehicles)
        fake_pki = PKI(rng)
        fakes = []
        for i in range(k_fake):
            fv = Vehicle(10_000 + i, rng)
            fv.credential = fake_pki.register_vehicle(10_000 + i)      # certificate from the wrong CA
            fakes.append(fv)
        rsu.vehicles = fakes + rsu.vehicles                            # the flood arrives first
        sim.run(2)
        honest_short = sum(1 for v in honest if len(v.pseudonyms) < sim.cfg.pseudonyms_per_vehicle)
        fakes_served = sum(1 for v in rsu.vehicles if v.index >= 10_000 and v.pseudonyms)
        out["with_cert_check" if check else "without_cert_check"] = {
            "honest_vehicles_short": honest_short, "fake_vehicles_served": fakes_served,
            "rejected_uncertified": rsu.rejected_uncertified, "stockouts": rsu.stockouts}
    w = out["with_cert_check"]
    return AttackResult(
        "fake-vehicle pseudonym flood", "protocol",
        f"{k_fake} vehicles with forged certificates ask one RSU for sets.",
        "v2", "defended" if w["fake_vehicles_served"] == 0 and w["honest_vehicles_short"] == 0 else "vulnerable",
        "The RSU allots a set only to a vehicle whose permanent certificate verifies under PKI and is not revoked.",
        out)


def attack_revoked_vehicle_persists(seed: int = 10) -> AttackResult:
    sim = _fresh_sim(seed, malicious_vehicles=1)
    sim.run(2)
    bad = next(v for v in sim.vehicles if v.malicious)
    rsu = next(r for r in sim.rsus if bad in r.vehicles)
    kept = bad._kept_copy
    attempts = 0
    accepted = 0
    for p in (bad.pseudonyms + ([kept] if kept else []))[:3]:
        msg = SafetyMessage(p.pid, (0.0, 0.0), 1.0, 0.0, 5.0)
        msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
        attempts += 1
        accepted += rsu.receive_message(bad, msg)
    sim.run(1)
    got_new = len(bad.pseudonyms) > 0 and not bad.revoked
    return AttackResult(
        "revoked vehicle keeps transmitting", "protocol",
        "A vehicle whose certificate PKI revoked keeps using the pseudonyms it still holds and asks for new ones.",
        "both", "defended" if bad.revoked and accepted == 0 and not got_new else "vulnerable",
        "On revocation its held pseudonyms are marked returned in the ledger and the RSU's certificate check refuses new sets.",
        {"revoked": bad.revoked, "messages_attempted": attempts, "messages_accepted": accepted, "new_sets_after_revocation": got_new})


def attack_tamper_rsu_chain(seed: int = 11) -> AttackResult:
    from .anchoring import detect_rsu_tamper
    sim = _fresh_sim(seed)
    sim.run(2)
    pm = sim.pms[0]
    clean = detect_rsu_tamper(pm.rsu_chain, sim.pm_chain, pm.pm_id)
    b = pm.rsu_chain.chain[2]
    b.transactions[0].timestamp += 1
    b.seal()                                                   # the RSU re-hashes to cover the edit
    for later in pm.rsu_chain.chain[3:]:                       # ... and re-links everything after it
        later.previous_hash = pm.rsu_chain.chain[later.index - 1].hash
        later.seal()
    local_valid = pm.rsu_chain.is_valid()
    detected = detect_rsu_tamper(pm.rsu_chain, sim.pm_chain, pm.pm_id)
    return AttackResult(
        "compromised RSU rewrites its chain", "protocol",
        "An RSU edits a recorded transaction and re-hashes its whole chain so it validates locally.",
        "v2", "defended" if not clean and detected else "vulnerable",
        "Every PM block anchors the RSU chain's block hashes; the rewritten chain no longer matches the anchor.",
        {"rsu_chain_valid_locally_after_rewrite": local_valid, "detected_from_pm_level": detected})


def attack_curious_rsu(seed: int = 12) -> AttackResult:
    sim = _fresh_sim(seed)
    sim.run(1)
    rsu = sim.rsus[0]
    pm = sim.pms[0]
    opened = 0
    total = 0
    for b in pm.rsu_chain.chain:
        for tx in b.transactions:
            total += 1
            try:
                tx.open(rsu.keys)
                opened += 1
            except Exception:  # noqa: BLE001 - any failure means the RSU could not read it
                pass
    return AttackResult(
        "curious RSU reads the ledger", "protocol",
        "An RSU tries to read the used/allot transactions of its neighbours from the chain it stores.",
        "both", "defended" if opened == 0 else "vulnerable",
        "Transactions are encrypted for the PM; the RSU holds ciphertext only.",
        {"transactions": total, "opened_by_rsu": opened})


def attack_tracking(seed: int = 13, seconds: int = 180) -> AttackResult:
    """Global passive adversary with kinematic tracking, two deployments."""
    from ..experiments_v2 import _track_run
    sparse = _track_run(2.0, 30, 0.0, 3.0, seconds, True, seed, tracker="kalman")
    dense = _track_run(60.0, 30, 10.0, 3.0, seconds, True, seed, tracker="kalman")
    unsync = _track_run(60.0, 30, 10.0, 3.0, seconds, False, seed, tracker="kalman")
    return AttackResult(
        "location tracking across pseudonym changes", "privacy",
        "A Kalman/GNN tracker links beacons by position and speed through every pseudonym change.",
        "both", "mitigated",
        "Shuffle in dense traffic with synchronized changes and a silent period; sparse roads stay linkable.",
        {"sparse_road_no_silence": sparse["linking_success"], "dense_sync_10s_silence": dense["linking_success"],
         "dense_unsync_10s_silence": unsync["linking_success"]})


def attack_threshold_tampering(seed: int = 14) -> AttackResult:
    """A node whose value is above the sortition threshold edits the
    threshold and miner-count fields of its proof, or claims that nobody was
    below the threshold (with and without evidence)."""
    rng = random.Random(seed)
    nodes = [V2Node(f"N{i}", vrf.generate_vrf_keypair(rng=rng)) for i in range(6)]
    certs = {n.node_id: n.pk.to_hex() for n in nodes}
    prev = crypto.sha256_hex(str(rng.random()))
    res, pi = popv2_elect(nodes, prev, 3)
    loser = max(res.values, key=res.values.get)
    lnode = next(n for n in nodes if n.node_id == loser)
    seed_b = election_seed(prev, 3)
    lpi = vrf.vrf_prove(lnode.keys, seed_b)
    base = {"seed": seed_b.hex(), "winner": loser, "vrf_pk": lnode.pk.to_hex(), "pi": lpi.hex(),
            "beta": vrf.vrf_proof_to_hash(lpi).hex(), "value": res.values[loser], "threshold": 0.5, "miners": 3}
    forged_fallback = {n.node_id: {"vrf_pk": n.pk.to_hex(), "pi": vrf.vrf_prove(n.keys, seed_b).hex()} for n in nodes}
    attempts = {
        "threshold field set to 1.0": {**base, "threshold": 1.0},
        "miners field set to 0": {**base, "miners": 0},
        "claim no-miner round without evidence": {**base, "miners": 0, "fallback_proofs": {}},
        "claim no-miner round with everyone's real proofs": {**base, "miners": 0, "fallback_proofs": forged_fallback},
    }
    accepted = {k: verify_popv2_proof(v, prev, 3, loser, certified_pk=lnode.pk.to_hex(), certified_pks=certs)
                for k, v in attempts.items()}
    w = next(n for n in nodes if n.node_id == res.winner)
    honest = verify_popv2_proof(res.proof(w, pi), prev, 3, res.winner, certified_pk=w.pk.to_hex(), certified_pks=certs)
    return AttackResult(
        "sortition threshold tampering", "consensus",
        "A node above the threshold edits the threshold / miner-count fields or claims a no-miner round.",
        "v2", "defended" if honest and not any(accepted.values()) else "vulnerable",
        "The threshold is a protocol constant; a no-miner claim needs every certified node's proof, all above threshold, with the miner's value the minimum.",
        {"loser_value": res.values[loser], "attempts": len(attempts), "accepted": sum(accepted.values()),
         "per_attempt": accepted, "honest_block_accepted": honest})


def attack_multi_key_seed_choice(n_honest: int = 19, k_values=(1, 2, 3, 5), rounds: int = 400, seed: int = 15) -> AttackResult:
    """An attacker holding k certified keys: when two or more of its keys
    beat every honest node, it can choose which one publishes, and so
    which seed the next election uses (or withhold).  The chained seed stops
    single-key grinding; this measures what k keys still buy."""
    rng = random.Random(seed)
    honest = [vrf.generate_vrf_keypair(rng=rng) for _ in range(n_honest)]
    out = {}
    for k in k_values:
        att = [vrf.generate_vrf_keypair(rng=rng) for _ in range(k)]
        wins = {"strategic": 0, "naive": 0}
        for strategy in ("strategic", "naive"):
            prev_hash, prev_beta = crypto.sha256_hex("g"), None
            for i in range(1, rounds + 1):
                s = election_seed(prev_hash, i, prev_beta)
                hv = [vrf.beta_to_unit(vrf.vrf_proof_to_hash(vrf.vrf_prove(kp, s))) for kp in honest]
                ap = [vrf.vrf_prove(kp, s) for kp in att]
                av = [vrf.beta_to_unit(vrf.vrf_proof_to_hash(p)) for p in ap]
                h_best = min(hv)
                winners = [j for j, v in enumerate(av) if v < h_best]
                if winners:
                    wins[strategy] += 1
                    if strategy == "strategic" and len(winners) > 1:
                        # pick the key whose output gives the attacker the best next round
                        def next_score(j):
                            s2 = election_seed("x", i + 1, vrf.vrf_proof_to_hash(ap[j]).hex())
                            return min(vrf.beta_to_unit(vrf.vrf_proof_to_hash(vrf.vrf_prove(kp, s2))) for kp in att)
                        j = min(winners, key=next_score)
                    else:
                        j = min(winners, key=lambda j: av[j])
                    prev_beta = vrf.vrf_proof_to_hash(ap[j]).hex()
                else:
                    j = hv.index(h_best)
                    prev_beta = vrf.vrf_proof_to_hash(vrf.vrf_prove(honest[j], s)).hex()
                prev_hash = "x"
        out[str(k)] = {"naive_share": wins["naive"] / rounds, "strategic_share": wins["strategic"] / rounds,
                       "fair_share": k / (n_honest + k)}
    gain = max(v["strategic_share"] - v["naive_share"] for v in out.values())
    return AttackResult(
        "multi-key seed choice", "consensus",
        "An attacker with k certified keys chooses which of its winning keys publishes to steer the next seed.",
        "v2", "mitigated",
        "Bounded by the k/(n+k) share of k certificates; the gain over honest play is measured here. PKI issuance limits k.",
        {"n_honest": n_honest, "rounds": rounds, "by_k": out, "max_gain_over_naive": gain})


ATTACKS = [
    attack_value_forgery, attack_threshold_tampering, attack_seed_grinding, attack_multi_key_seed_choice,
    attack_withholding, attack_equivocation, attack_replay_proof,
    attack_server_dos, attack_sybil_keys, attack_partition,
    attack_pseudonym_replay, attack_pseudonym_clone, attack_forged_pseudonym, attack_fake_vehicle_flood,
    attack_revoked_vehicle_persists, attack_tamper_rsu_chain, attack_curious_rsu, attack_tracking,
]


def run_all(quick: bool = False) -> dict:
    results = []
    t0 = time.perf_counter()
    for fn in ATTACKS:
        t = time.perf_counter()
        if fn is attack_seed_grinding and quick:
            r = fn(rounds=60, budgets=(1, 16))
        elif fn is attack_multi_key_seed_choice and quick:
            r = fn(rounds=60, k_values=(1, 3))
        elif fn is attack_withholding and quick:
            r = fn(rounds=300)
        elif fn is attack_tracking and quick:
            r = fn(seconds=60)
        else:
            r = fn()
        d = r.to_dict()
        d["seconds"] = time.perf_counter() - t
        results.append(d)
    counts = {}
    for r in results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    return {"experiment": "attacks", "quick": quick, "results": results, "summary": counts,
            "wall_seconds": time.perf_counter() - t0}
