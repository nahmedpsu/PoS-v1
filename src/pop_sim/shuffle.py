"""End-to-end simulation of the pseudonym shuffling scheme.

Implements Algorithm 4 (pseudonym shuffling over the PM cloud, mined on the
PM-level blockchain) and Algorithm 5 (pseudonym distribution by RSUs with the
RSU-level blockchain of each PM), with a pluggable consensus so that the same
run can be repeated under PoW 2, PoET, PoKW or Proof of Pseudonym.
"""

from __future__ import annotations

import random
import time
from dataclasses import asdict, dataclass, field

from . import crypto
from .blockchain import Blockchain, Transaction
from .consensus.poet import poet_elect
from .consensus.pokw import pokw_mine
from .consensus.pop import PoPServer, verify_election
from .consensus.popv2 import V2Node, popv2_elect, verify_popv2_proof
from .consensus.pow2 import mine_pow2
from .entities import PKI, RSU, Manufacturer, PMCloud, PrivacyManager, Pseudonym, PseudonymLedger, Vehicle
from .v2.adversary import TrackingAdversary
from .v2.anchoring import (
    anchors_to_proof,
    build_allotment_proof,
    detect_rsu_tamper,
    make_anchor,
    proof_size_bytes,
    time_verify,
)
from .v2.mobility import Beacon, Road, RoadConfig
from .vrf import generate_vrf_keypair

CONSENSUS_KINDS = ("pop", "poet", "pow2", "pokw", "popv2")


@dataclass
class ITSConfig:
    n_pm: int = 2
    rsus_per_pm: int = 3
    vehicles_per_rsu: int = 5
    pseudonyms_per_vehicle: int = 3
    consensus: str = "pop"
    pow_difficulty: int = 3
    seed: int = 1
    malicious_vehicles: int = 0
    avoid_previous_holder: bool = True   # RSU never hands a pseudonym back to a vehicle that used it
    # ---- PoP v2 options ----
    anchoring: bool = True               # commit RSU-chain block hashes into every PM block
    vrf_bits: int = 2048                 # RSA-FDH-VRF key size for consensus "popv2"
    mobility: bool = False               # vehicles drive on a ring road and beacon every second
    road: RoadConfig | None = None       # mobility parameters (n_rsu is forced to n_pm * rsus_per_pm)
    round_seconds: int = 30              # simulated seconds per shuffle round in mobility mode
    silent_period: float = 0.0           # seconds without beacons after a pseudonym change
    position_noise_m: float = 0.0        # GPS error added to what the eavesdropper sees
    forecast_alpha: float = 0.5          # EMA weight of the RSU demand forecast
    safety_stock: float = 0.0            # extra fraction of sets an RSU asks for above its forecast
    adversary_gate_m: float = 8.0        # tracking adversary's matching gate

    def __post_init__(self):
        if self.consensus not in CONSENSUS_KINDS:
            raise ValueError(f"consensus must be one of {CONSENSUS_KINDS}")


@dataclass
class ConsensusOutcome:
    kind: str
    winner: str
    nodes: int
    miners: int
    cpu_seconds: float
    proof: dict = field(default_factory=dict)


def run_consensus(kind: str, node_ids: list[str], data_hash: str, rng: random.Random,
                  difficulty: int = 3, server: PoPServer | None = None) -> ConsensusOutcome:
    """Elect the publisher of the next block among ``node_ids``."""
    if kind == "pop":
        server = server or PoPServer(rng=rng)
        server.disconnect_all()
        for nid in node_ids:
            server.connect(nid)
        r = server.elect()
        return ConsensusOutcome(kind, r.winner, r.nodes, r.miners, r.cpu_seconds + r.winner_time, r.proof())
    if kind == "poet":
        r = poet_elect(node_ids, rng=rng)
        return ConsensusOutcome(kind, r.winner, r.nodes, r.nodes, r.cpu_seconds + r.winner_time,
                                {"winner_time": r.winner_time})
    if kind == "pokw":
        r = pokw_mine(node_ids, data_hash, difficulty, rng=rng)
        w = r.per_node[r.winner]
        return ConsensusOutcome(kind, r.winner, r.nodes, len(r.kernel), r.seconds,
                                {"kernel": r.kernel, "nonce": w.nonce, "difficulty": difficulty})
    if kind == "pow2":
        t0 = time.perf_counter()
        ts = time.time()
        results = {nid: mine_pow2(f"{data_hash}{nid}", difficulty, timestamp=ts) for nid in node_ids}
        winner = min(results, key=lambda n: results[n].hashes)
        return ConsensusOutcome(kind, winner, len(node_ids), len(node_ids), time.perf_counter() - t0,
                                {"nonce": results[winner].nonce, "difficulty": difficulty})
    raise ValueError(kind)


@dataclass
class RoundStats:
    round: int
    messages: int
    rejected_messages: int
    used_collected: int
    shuffled: int
    rsu_blocks: int
    rsu_txs: int
    pm_block_txs: int
    pm_consensus_cpu: float
    rsu_consensus_cpu: float
    pm_winner: str
    pm_miners: int
    reassigned_to_previous_holder: int
    wall_seconds: float


class ITSSimulation:
    """One ITS domain: a PKI, ``n_pm`` privacy managers, their RSUs and vehicles."""

    def __init__(self, cfg: ITSConfig):
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        self.pki = PKI(self.rng)
        self.manufacturer = Manufacturer(self.pki)
        self.cloud = PMCloud(self.rng)
        self.ledger = PseudonymLedger()                      # shared blockchain view
        self.pms: list[PrivacyManager] = []
        self.rsus: list[RSU] = []
        self.vehicles: list[Vehicle] = []
        self.pop_server = PoPServer(rng=self.rng)
        self.pm_chain = Blockchain("pm-chain", validator=self.validate_block)   # blockchain over PMs (Fig. 4)
        self.rounds: list[RoundStats] = []
        self.holder_history: dict[str, set[str]] = {}       # pid -> vehicles that held it
        self.revocations: list[dict] = []
        self.v2nodes: dict[str, V2Node] = {}                # PoP v2 election keys, PKI-certified
        self.road: Road | None = None
        self.adversary: TrackingAdversary | None = None
        self.true_changes = 0
        self.sim_time = 0.0
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        cfg = self.cfg
        vidx = 0
        for i in range(cfg.n_pm):
            pm = PrivacyManager(f"PM-{i+1}", self.cloud, self.rng, self.ledger)
            pm.rsu_chain.validator = self.validate_block
            pm.anchored_upto = 0
            self.pms.append(pm)
            for j in range(cfg.rsus_per_pm):
                rsu = RSU(f"RSU-{i+1}.{j+1}", pm, self.rng)
                pm.rsus.append(rsu)
                self.rsus.append(rsu)
                if not cfg.mobility:
                    for _ in range(cfg.vehicles_per_rsu):
                        vidx += 1
                        v = Vehicle(vidx, self.rng)
                        self.manufacturer.provision(v)            # Alg. 4 steps 1-3
                        rsu.vehicles.append(v)
                        self.vehicles.append(v)
        if cfg.mobility:
            road_cfg = cfg.road or RoadConfig(seed=cfg.seed)
            road_cfg.n_rsu = cfg.n_pm * cfg.rsus_per_pm
            self.road = Road(road_cfg)
            self.adversary = TrackingAdversary(road_cfg.length_m, cfg.adversary_gate_m, 1.0)
            for mv in self.road.vehicles:
                v = Vehicle(mv.vid, self.rng)
                self.manufacturer.provision(v)
                self.vehicles.append(v)
            self._place_vehicles()
            for rsu in self.rsus:
                rsu.update_forecast(cfg.forecast_alpha, cfg.safety_stock)
        if cfg.consensus == "popv2":
            for node_id in [pm.pm_id for pm in self.pms] + [r.rsu_id for r in self.rsus]:
                node = V2Node(node_id, generate_vrf_keypair(cfg.vrf_bits))
                node.cert = self.pki.certify_vrf_key(node_id, node.pk.to_hex())
                self.v2nodes[node_id] = node
        for v in self.rng.sample(self.vehicles, cfg.malicious_vehicles):
            v.malicious = True

        # Alg. 4 steps 4-6: PKI generates the pseudonym sets and broadcasts them
        # to the PMs, encrypted with the PM's public key and signed by PKI.
        for pm in self.pms:
            ps = self.pki.generate_pseudonyms(pm.demand(cfg.pseudonyms_per_vehicle))
            ct, sig = self.pki.package_for_pm(pm.keys.pk, ps)
            pm.receive_from_pki(ct, sig, self.pki.keys.pk)
        # Alg. 4 steps 8-9 and Alg. 5 lines 1-6: PM -> RSU -> vehicles.
        self._allot_and_distribute(initial=True)

    # ------------------------------------------------------------------
    def validate_block(self, block) -> bool:
        """Nodes accept a block only from the node the consensus elected.  Under
        PoP the election record is signed by the server, so a spoofed PM that
        was not selected cannot publish (Section VI-B-3)."""
        if block.consensus == "pop":
            return verify_election(block.proof, self.pop_server.keys.pk_hex) and \
                block.miner == block.proof.get("winner")
        if block.consensus == "popv2":
            node = self.v2nodes.get(block.miner)
            if node is None or not self.pki.verify_vrf_cert(node.node_id, node.pk.to_hex(), node.cert):
                return False
            return verify_popv2_proof(block.proof, block.previous_hash, block.index, block.miner,
                                      certified_pk=node.pk.to_hex())
        return True

    def _place_vehicles(self) -> None:
        """Mobility mode: RSU membership follows the vehicles' positions."""
        for rsu in self.rsus:
            rsu.vehicles = []
        by_vid = {v.index: v for v in self.vehicles}
        for mv in self.road.vehicles:
            self.rsus[mv.rsu].vehicles.append(by_vid[mv.vid])

    def _node_ids(self, nodes) -> list[str]:
        return [getattr(n, "pm_id", None) or n.rsu_id for n in nodes]

    def _mine(self, chain: Blockchain, nodes, txs: list[Transaction],
              extra_proof: dict | None = None) -> tuple[ConsensusOutcome, int]:
        """Elect a publisher among ``nodes`` and append a block of ``txs``."""
        ids = self._node_ids(nodes)
        data_hash = crypto.sha256_hex("".join(t.hash() for t in txs) + chain.last.hash)
        if self.cfg.consensus == "popv2":
            v2 = [self.v2nodes[i] for i in ids]
            res, pi = popv2_elect(v2, chain.last.hash, len(chain.chain))
            wnode = self.v2nodes[res.winner]
            outcome = ConsensusOutcome("popv2", res.winner, res.nodes, len(res.miners),
                                       res.prove_seconds_mean + res.race_seconds + res.verify_seconds,
                                       res.proof(wnode, pi))
        else:
            outcome = run_consensus(self.cfg.consensus, ids, data_hash, self.rng,
                                    self.cfg.pow_difficulty, self.pop_server)
        proof = {**outcome.proof, "miners": outcome.miners}
        if extra_proof:
            proof.update(extra_proof)
        block = chain.new_block(txs, miner=outcome.winner, consensus=outcome.kind, proof=proof)
        chain.add_block(block)
        return outcome, len(txs)

    def _allot_and_distribute(self, initial: bool = False) -> tuple[float, int, int]:
        """Algorithm 5 lines 1-6 for every PM: RSUs request sets, record the
        allotment as a transaction, mine the RSU chain and distribute."""
        per_vehicle = self.cfg.pseudonyms_per_vehicle
        cpu = 0.0
        blocks = 0
        txs_total = 0
        reassigned = 0
        if self.cfg.mobility and not initial:
            self._place_vehicles()
            for rsu in self.rsus:
                rsu.update_forecast(self.cfg.forecast_alpha, self.cfg.safety_stock)
        for pm in self.pms:
            pm.serve_rsus(per_vehicle)
            txs = []
            for rsu in pm.rsus:
                payload = {"rsu": rsu.rsu_id, "pids": [p.pid for p in rsu.shuffled_sets]}
                txs.append(Transaction.create("allot", rsu.keys, pm.keys.pk, payload))
            outcome, n = self._mine(pm.rsu_chain, pm.rsus, txs)
            cpu += outcome.cpu_seconds
            blocks += 1
            txs_total += n
            for rsu in pm.rsus:
                rsu.distribute(per_vehicle, avoid_previous=self.cfg.avoid_previous_holder)
                for v in rsu.vehicles:
                    for p in v.pseudonyms:
                        holders = self.holder_history.setdefault(p.pid, set())
                        if not initial and v.vehicle_id in holders:
                            reassigned += 1
                        holders.add(v.vehicle_id)
        return cpu, blocks, txs_total, reassigned

    # ------------------------------------------------------------------
    def run_round(self) -> RoundStats:
        r = len(self.rounds) + 1
        t0 = time.perf_counter()
        per_vehicle = self.cfg.pseudonyms_per_vehicle

        # 1. Vehicles broadcast safety messages signed with pseudonyms.
        messages = rejected = 0
        if self.cfg.mobility:
            messages, rejected = self._drive_round()
        for rsu in (self.rsus if not self.cfg.mobility else []):
            for v in rsu.vehicles:
                if v.revoked:
                    continue
                for _ in range(per_vehicle):
                    msg = v.broadcast()
                    if msg is None:
                        break
                    messages += 1
                    if not rsu.receive_message(v, msg):
                        rejected += 1
                if v.malicious:
                    msg = v.replay_used()           # Internal Tricking Adversary
                    if msg is not None:
                        messages += 1
                        if not rsu.receive_message(v, msg):
                            rejected += 1
        self._process_reports()

        # 2. Algorithm 5 lines 7-9: RSUs collect used sets, record them as
        #    transactions, mine the RSU chain and send them to the PM.
        used_total = 0
        rsu_cpu = 0.0
        rsu_blocks = rsu_txs = 0
        for pm in self.pms:
            txs = []
            for rsu in pm.rsus:
                used_total += rsu.collect_used()
                payload = {"rsu": rsu.rsu_id,
                           "used": [{"pid": p.pid, "status": s} for p, s in rsu.used]}
                txs.append(Transaction.create("used", rsu.keys, pm.keys.pk, payload))
            outcome, n = self._mine(pm.rsu_chain, pm.rsus, txs)
            rsu_cpu += outcome.cpu_seconds
            rsu_blocks += 1
            rsu_txs += n

        # 3. Algorithm 4 lines 11-16: PMs collect, package and upload to the
        #    cloud; the cloud shuffles and relocates to destination PMs.
        for pm in self.pms:
            pm.collect_from_rsus()
            pm.upload_to_cloud()
        demands = {pm.pm_id: pm.net_demand(per_vehicle) for pm in self.pms}
        relocated = self.cloud.shuffle_and_relocate(demands, seed=self.rng.getrandbits(64))
        shuffled = sum(len(v) for v in relocated.values())

        # 4. Algorithm 4 lines 18-19: shuffle results become transactions of the
        #    PM-level blockchain; the PMs mine with the configured consensus.
        pm_by_id = {pm.pm_id: pm for pm in self.pms}
        txs = []
        for dst_id, ps in relocated.items():
            by_origin: dict[str, list[Pseudonym]] = {}
            for origin, p in ps:
                by_origin.setdefault(origin, []).append(p)
            for origin, group in by_origin.items():
                src = pm_by_id[origin]
                txs.append(src.make_tx("shuffle", pm_by_id[dst_id].keys.pk,
                                       {"from": origin, "to": dst_id, "pids": [p.pid for p in group]}))
        extra = None
        if self.cfg.anchoring:
            anchors = []
            for pm in self.pms:
                anchors.append(make_anchor(pm.rsu_chain, pm.pm_id, pm.anchored_upto))
                pm.anchored_upto = len(pm.rsu_chain.chain)
            extra = anchors_to_proof(anchors)
        outcome, pm_txs = self._mine(self.pm_chain, self.pms, txs, extra_proof=extra)

        # 5. Algorithm 4 line 21: PMs retrieve the new sets; Algorithm 5 again.
        for dst_id, ps in relocated.items():
            pm_by_id[dst_id].pool.extend(p for _, p in ps)
        cpu2, blocks2, txs2, reassigned = self._allot_and_distribute()

        stats = RoundStats(
            round=r, messages=messages, rejected_messages=rejected, used_collected=used_total,
            shuffled=shuffled, rsu_blocks=rsu_blocks + blocks2, rsu_txs=rsu_txs + txs2,
            pm_block_txs=pm_txs, pm_consensus_cpu=outcome.cpu_seconds,
            rsu_consensus_cpu=rsu_cpu + cpu2, pm_winner=outcome.winner, pm_miners=outcome.miners,
            reassigned_to_previous_holder=reassigned, wall_seconds=time.perf_counter() - t0,
        )
        self.rounds.append(stats)
        return stats

    def _drive_round(self) -> tuple[int, int]:
        """Mobility mode: ``round_seconds`` seconds of driving.  Vehicles switch
        pseudonym ``pseudonyms_per_vehicle`` times per round, keep silent for
        ``silent_period`` seconds after each switch, beacon once a second
        otherwise, and the eavesdropper sees every beacon (with GPS noise)."""
        cfg = self.cfg
        road = self.road
        by_vid = {v.index: v for v in self.vehicles}
        period = max(1, cfg.round_seconds // cfg.pseudonyms_per_vehicle)
        silent_until: dict[int, float] = {}
        messages = rejected = 0
        for step in range(cfg.round_seconds):
            road.step(1.0)
            self.sim_time += 1.0
            beacons: list[Beacon] = []
            for mv in road.vehicles:
                v = by_vid[mv.vid]
                if v.revoked:
                    continue
                if step % period == 0:
                    if v.switch_pseudonym() is not None:
                        self.true_changes += 1 if step > 0 or v.changes > 1 else 0
                        silent_until[mv.vid] = self.sim_time + cfg.silent_period
                if self.sim_time < silent_until.get(mv.vid, 0.0):
                    continue
                msg = v.beacon(mv.x, mv.v, mv.direction)
                if msg is None:
                    continue
                messages += 1
                rsu = self.rsus[mv.rsu]
                if not rsu.receive_message(v, msg):
                    rejected += 1
                x_seen = (mv.x + self.rng.gauss(0, cfg.position_noise_m)) % road.cfg.length_m \
                    if cfg.position_noise_m else mv.x
                beacons.append(Beacon(self.sim_time, msg.pid, x_seen, mv.v, mv.direction, mv.rsu, mv.vid))
                if v.malicious and step == period - 1:
                    replay = v.replay_used()
                    if replay is not None:
                        messages += 1
                        if not rsu.receive_message(v, replay):
                            rejected += 1
            self.adversary.observe(beacons)
        # retire the pseudonym in use so it is returned with the others
        for v in self.vehicles:
            if v.current is not None:
                v.used.append(v.current)
                v.history.append(v.current.pid)
                v.current = None
        return messages, rejected

    def _process_reports(self) -> None:
        """PM -> CA: a vehicle caught reusing a pseudonym has its certificate revoked."""
        for pm in self.pms:
            while pm.misbehaviour_reports:
                rep = pm.misbehaviour_reports.pop()
                v = next(v for v in self.vehicles if v.vehicle_id == rep["vehicle"])
                if not v.revoked:
                    self.pki.revoke(v.credential.cert)
                    v.revoked = True
                    self.revocations.append(rep)

    def run(self, rounds: int) -> list[RoundStats]:
        for _ in range(rounds):
            self.run_round()
        return self.rounds

    # ------------------------------------------------------------------
    def linkability_report(self) -> dict:
        """What a Global Passive Adversary sees: every safety message carries a
        pseudonym; can it chain the messages of one vehicle across rounds?"""
        total = 0
        same_vehicle_reuse = 0
        for v in self.vehicles:
            total += len(v.history)
            same_vehicle_reuse += len(v.history) - len(set(v.history))
        multi_holder = sum(1 for h in self.holder_history.values() if len(h) > 1)
        return {
            "messages_observed": total,
            "pid_reused_by_same_vehicle": same_vehicle_reuse,
            "pids_issued": len(self.holder_history),
            "pids_held_by_more_than_one_vehicle": multi_holder,
            "vehicles": len(self.vehicles),
            "revoked_vehicles": sum(v.revoked for v in self.vehicles),
            "flagged_messages": sum(len(r.flagged) for r in self.rsus),
            "pki_accesses": self.pki.accesses,
        }

    def anchoring_report(self) -> dict:
        """Tamper detection from the PM level and the cost of one allotment proof."""
        if not self.cfg.anchoring:
            return {"enabled": False}
        pm = self.pms[0]
        proof = None
        # a pseudonym allotted in an RSU block that a PM block already anchors
        for b in pm.rsu_chain.chain[1: pm.anchored_upto]:
            for tx in b.transactions:
                if tx.kind == "allot":
                    pids = tx.open(pm.keys).get("pids", [])
                    if pids:
                        proof = build_allotment_proof(pm.rsu_chain, self.pm_chain, pm.pm_id, pids[0], pm.keys)
                        break
            if proof:
                break
        return {
            "enabled": True,
            "tamper_detected_on_clean_chains": any(detect_rsu_tamper(p.rsu_chain, self.pm_chain, p.pm_id) for p in self.pms),
            "proof_bytes": proof_size_bytes(proof) if proof else None,
            "proof_verify_seconds": time_verify(proof, self.pm_chain) if proof else None,
            "rsu_blocks_anchored": {p.pm_id: p.anchored_upto for p in self.pms},
        }

    def summary(self) -> dict:
        return {
            "stockouts": sum(r.stockouts for r in self.rsus),
            "tracking": self.adversary.report(self.true_changes).to_dict() if self.adversary else None,
            "anchoring": self.anchoring_report(),
            "sim_seconds": self.sim_time,
            "config": asdict(self.cfg),
            "rounds": [asdict(r) for r in self.rounds],
            "pm_chain_blocks": len(self.pm_chain),
            "pm_chain_valid": self.pm_chain.is_valid(),
            "rsu_chains_valid": all(pm.rsu_chain.is_valid() for pm in self.pms),
            "rsu_chain_blocks": {pm.pm_id: len(pm.rsu_chain) for pm in self.pms},
            "linkability": self.linkability_report(),
            "revocations": self.revocations,
        }
