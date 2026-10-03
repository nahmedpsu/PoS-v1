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
from .consensus.pow2 import mine_pow2
from .entities import PKI, PMCloud, Manufacturer, PrivacyManager, Pseudonym, PseudonymLedger, RSU, Vehicle

CONSENSUS_KINDS = ("pop", "poet", "pow2", "pokw")


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
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        cfg = self.cfg
        vidx = 0
        for i in range(cfg.n_pm):
            pm = PrivacyManager(f"PM-{i+1}", self.cloud, self.rng, self.ledger)
            pm.rsu_chain.validator = self.validate_block
            self.pms.append(pm)
            for j in range(cfg.rsus_per_pm):
                rsu = RSU(f"RSU-{i+1}.{j+1}", pm, self.rng)
                pm.rsus.append(rsu)
                self.rsus.append(rsu)
                for _ in range(cfg.vehicles_per_rsu):
                    vidx += 1
                    v = Vehicle(vidx, self.rng)
                    self.manufacturer.provision(v)            # Alg. 4 steps 1-3
                    rsu.vehicles.append(v)
                    self.vehicles.append(v)
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
        return True

    def _node_ids(self, nodes) -> list[str]:
        return [getattr(n, "pm_id", None) or n.rsu_id for n in nodes]

    def _mine(self, chain: Blockchain, nodes, txs: list[Transaction]) -> tuple[ConsensusOutcome, int]:
        """Elect a publisher among ``nodes`` and append a block of ``txs``."""
        ids = self._node_ids(nodes)
        data_hash = crypto.sha256_hex("".join(t.hash() for t in txs) + chain.last.hash)
        outcome = run_consensus(self.cfg.consensus, ids, data_hash, self.rng,
                                self.cfg.pow_difficulty, self.pop_server)
        block = chain.new_block(txs, miner=outcome.winner, consensus=outcome.kind,
                                proof={**outcome.proof, "miners": outcome.miners})
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
        for rsu in self.rsus:
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
        outcome, pm_txs = self._mine(self.pm_chain, self.pms, txs)

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

    def summary(self) -> dict:
        return {
            "config": asdict(self.cfg),
            "rounds": [asdict(r) for r in self.rounds],
            "pm_chain_blocks": len(self.pm_chain),
            "pm_chain_valid": self.pm_chain.is_valid(),
            "rsu_chains_valid": all(pm.rsu_chain.is_valid() for pm in self.pms),
            "rsu_chain_blocks": {pm.pm_id: len(pm.rsu_chain) for pm in self.pms},
            "linkability": self.linkability_report(),
            "revocations": self.revocations,
        }
