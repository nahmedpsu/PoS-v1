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

from . import clock, crypto
from .blockchain import Blockchain, Transaction
from .consensus.poet import poet_elect
from .consensus.pokw import pokw_mine
from .consensus.pop import PoPServer, verify_election
from .consensus.popv2 import EquivocationDetector, V2Node, popv2_elect, verify_popv2_proof
from .consensus.pow2 import mine_pow2
from .entities import PKI, RSU, Manufacturer, PMCloud, PrivacyManager, Pseudonym, PseudonymLedger, Vehicle
from .v2.anchoring import (
    anchors_to_proof,
    build_allotment_proof,
    detect_rsu_tamper,
    make_anchor,
    proof_size_bytes,
    time_verify,
)
from .v2.insider import Evidence, full_table
from .v2.metrics import OpCosts, cpu_seconds, exposure_windows, forged_acceptance, per_1000_vehicles_per_hour
from .v2.mobility import Beacon, Road, RoadConfig
from .v2.recycling_attacks import STRATEGIES, FormerHolderAdversary
from .v2.tracker_kalman import make_tracker
from .v2.v2v import V2VLayer
from .vrf import generate_vrf_keypair

CONSENSUS_KINDS = ("pop", "poet", "pow2", "pokw", "popv2")
ISSUANCE_MODES = ("recycle", "fresh", "fresh_vgk", "rekey", "window")


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
    vrf_scheme: str | None = None        # "ecvrf" (default when coincurve is installed) or "rsa-fdh"
    vrf_bits: int = 2048                 # RSA-FDH-VRF key size when that scheme is used
    tracker: str = "kalman"              # eavesdropper model: "kalman" (GNN tracker) or "nn" (baseline)
    mobility: bool = False               # vehicles drive on a ring road and beacon every second
    road: RoadConfig | None = None       # mobility parameters (n_rsu is forced to n_pm * rsus_per_pm)
    round_seconds: int = 30              # simulated seconds per shuffle round in mobility mode
    silent_period: float = 0.0           # seconds without beacons after a pseudonym change
    position_noise_m: float = 0.0        # GPS error added to what the eavesdropper sees
    forecast_alpha: float = 0.5          # EMA weight of the RSU demand forecast
    safety_stock: float = 0.0            # extra fraction of sets an RSU asks for above its forecast
    adversary_gate_m: float = 8.0        # tracking adversary's matching gate
    verify_vehicle_certs: bool = True    # RSU allots only to vehicles with a valid, unrevoked PKI certificate
    # ---- pseudonym recycling study (defaults reproduce v2.2.1 exactly) ----
    attribution: str = "oracle"          # "oracle": RSU knows the true sender; "ledger": attributes by ledger holder
    v2v: bool = False                    # vehicle-to-vehicle receivers (certificate + signature, no ledger)
    v2v_range_m: float = 300.0
    v2v_plausibility: bool = False       # receivers apply the local two-places-at-once rule
    former_holders: int = 0              # A2 adversaries: vehicles that keep every key they held
    former_holder_strategy: str = "S1"   # S1 remote shadow, S2 co-located ghost, S3 gap filler
    ghost_offset_m: float = 40.0
    issuance: str = "recycle"            # recycle | fresh | fresh_vgk | rekey | window
    pseudonym_lifetime: float = 3600.0   # certificate lifetime in seconds
    revoked_keep_transmitting: bool = False   # a revoked vehicle keeps beaconing under the pseudonyms it holds
    shuffle_before_upload: bool = False  # PM shuffles used sets before uploading (cloud-order leak fix)

    def __post_init__(self):
        if self.consensus not in CONSENSUS_KINDS:
            raise ValueError(f"consensus must be one of {CONSENSUS_KINDS}")
        if self.attribution not in ("oracle", "ledger"):
            raise ValueError("attribution must be 'oracle' or 'ledger'")
        if self.issuance not in ISSUANCE_MODES:
            raise ValueError(f"issuance must be one of {ISSUANCE_MODES}")
        if self.former_holder_strategy not in STRATEGIES:
            raise ValueError(f"former_holder_strategy must be one of {STRATEGIES}")


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
        ts = clock.now()
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

    def __init__(self, cfg: ITSConfig, road=None):
        """``road``: an object with the ``Road`` interface (for example a
        ``v2.mobility_sumo.TraceRoad``) to drive on instead of the synthetic ring."""
        self._external_road = road
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)
        crypto.seed_keys(random.Random(cfg.seed ^ 0x5EED))   # key generation reproducible per seed
        clock.set_virtual(1_700_000_000.0)                    # transaction and block times from a virtual clock
        self.pki = PKI(self.rng, pseudonym_lifetime=cfg.pseudonym_lifetime)
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
        self.equivocation = EquivocationDetector()
        self.v2v: V2VLayer | None = None
        self.former: FormerHolderAdversary | None = None
        self.revoked_at: dict[str, float] = {}               # vehicle -> sim time of revocation
        self.revoked_accepted: dict[str, list[float]] = {}   # vehicle -> times V2V receivers accepted it after revocation
        self.pid_seconds: dict[str, float] = {}              # epoch node -> beacon seconds
        self.epoch_histories: dict[str, list[str]] = {}      # vehicle -> epoch nodes in order of use
        self.truth_of_node: dict[str, str] = {}
        self.tracker_nodes: list[tuple[str, str]] = []
        self._tracker_seen = 0
        self.last_node_of_pid: dict[str, str] = {}           # pid -> node as of its last beacon
        self.noise_rng = random.Random(cfg.seed ^ 0x0153)    # GPS noise only: the same traffic in every mode
        self.rsu_allots: dict[str, list[tuple[str, str]]] = {}
        self.pm_domains: dict[str, list[tuple[str, str]]] = {}
        self.cloud_uploads: list[list[str]] = []
        self.pki_reports: list[tuple[str, str]] = []
        self.road: Road | None = None
        self.adversary = None
        self.true_changes = 0
        self.sim_time = 0.0
        self._build()
        # work done at set-up (registration, initial sets) is reported separately from steady-state work
        self.setup_load = {"pki": self.pki.load.to_dict(),
                           "pm": {k: sum(p.load.to_dict()[k] for p in self.pms) for k in ("signatures", "keygens", "bytes", "verifications")},
                           "rsu": {k: sum(r.load.to_dict()[k] for r in self.rsus) for k in ("signatures", "keygens", "bytes", "verifications")},
                           "vehicles": {k: sum(v.load.to_dict()[k] for v in self.vehicles) for k in ("signatures", "keygens", "bytes", "verifications")}}

    # ------------------------------------------------------------------
    def _build(self) -> None:
        cfg = self.cfg
        vidx = 0
        for i in range(cfg.n_pm):
            pm = PrivacyManager(f"PM-{i+1}", self.cloud, self.rng, self.ledger)
            pm.rsu_chain.validator = self.validate_block
            pm.anchored_upto = 0
            self.pms.append(pm)
            pm.pm_cert = self.pki.certify_pm(pm.pm_id, pm.keys.pk_hex)
            for j in range(cfg.rsus_per_pm):
                rsu = RSU(f"RSU-{i+1}.{j+1}", pm, self.rng)
                rsu.attribution = cfg.attribution
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
            self.road = self._external_road if self._external_road is not None else Road(road_cfg)
            road_cfg = self.road.cfg
            self.ledger.ring_length = road_cfg.length_m
            self.adversary = make_tracker(cfg.tracker, road_cfg.length_m, cfg.adversary_gate_m, 1.0)
            for mv in self.road.vehicles:
                v = Vehicle(mv.vid, self.rng)
                self.manufacturer.provision(v)
                self.vehicles.append(v)
            self._place_vehicles()
            for rsu in self.rsus:
                rsu.update_forecast(cfg.forecast_alpha, cfg.safety_stock)
        if cfg.consensus == "popv2":
            for node_id in [pm.pm_id for pm in self.pms] + [r.rsu_id for r in self.rsus]:
                node = V2Node(node_id, generate_vrf_keypair(cfg.vrf_bits, cfg.vrf_scheme, rng=crypto.key_rng()))
                node.cert = self.pki.certify_vrf_key(node_id, node.pk.to_hex())
                self.v2nodes[node_id] = node
        for v in self.rng.sample(self.vehicles, cfg.malicious_vehicles):
            v.malicious = True
        if cfg.former_holders:
            honest = [v for v in self.vehicles if not v.malicious]
            for v in self.rng.sample(honest, min(cfg.former_holders, len(honest))):
                v.former_holder = True
            self.former = FormerHolderAdversary(cfg.former_holder_strategy, cfg.ghost_offset_m, cfg.v2v_range_m)
        if cfg.mobility and cfg.v2v:
            self.v2v = V2VLayer(self.pki.keys.pk, self.road.cfg.length_m, cfg.v2v_range_m, cfg.v2v_plausibility,
                                mode="holder" if cfg.issuance in ("rekey", "window") else "pki",
                                pm_cert_check=self.pki.verify_pm_cert)

        # Alg. 4 steps 4-6: PKI generates the pseudonym sets and broadcasts them
        # to the PMs, encrypted with the PM's public key and signed by PKI.
        for pm in self.pms:
            if cfg.issuance == "fresh_vgk":
                continue                                      # vehicles make their own keys at distribution
            ps = self.pki.generate_pseudonyms(pm.demand(cfg.pseudonyms_per_vehicle))
            ct, sig = self.pki.package_for_pm(pm.keys.pk, ps)
            pm.receive_from_pki(ct, sig, self.pki.keys.pk)
        # Alg. 4 steps 8-9 and Alg. 5 lines 1-6: PM -> RSU -> vehicles.
        self._allot_and_distribute(initial=True)

    # ------------------------------------------------------------------
    def _members_of(self, chain) -> set[str]:
        """The nodes that elect on ``chain``: the PMs on the PM chain, a PM's RSUs on its RSU chain."""
        if chain is self.pm_chain:
            return {pm.pm_id for pm in self.pms}
        for pm in self.pms:
            if chain is pm.rsu_chain:
                return {r.rsu_id for r in pm.rsus}
        return set(self.v2nodes)

    def _previous_block(self, block, chain=None):
        chains = [chain] if chain is not None else [self.pm_chain] + [pm.rsu_chain for pm in self.pms]
        for c in chains:
            for b in c.chain:
                if b.hash == block.previous_hash:
                    return b
        return None

    def validate_block(self, block, chain=None) -> bool:
        """Nodes accept a block only from the node the consensus elected.  Under
        PoP v1 the election record is signed by the server, so a spoofed PM that
        was not selected cannot publish (Section VI-B-3).  Under PoP v2 the
        block's VRF proof must verify under the miner's PKI-certified key for
        this position and the chained seed, and a second block with the same
        proof (equivocation) is rejected."""
        if block.consensus == "pop":
            return verify_election(block.proof, self.pop_server.keys.pk_hex) and \
                block.miner == block.proof.get("winner")
        if block.consensus == "popv2":
            node = self.v2nodes.get(block.miner)
            if node is None or not self.pki.verify_vrf_cert(node.node_id, node.pk.to_hex(), node.cert):
                return False
            prev = self._previous_block(block, chain)
            prev_beta = prev.proof.get("beta") if prev is not None else None
            members = self._members_of(chain) if chain is not None else None
            certified = {nid: n.pk.to_hex() for nid, n in self.v2nodes.items()
                         if (members is None or nid in members)
                         and self.pki.verify_vrf_cert(n.node_id, n.pk.to_hex(), n.cert)}
            if not verify_popv2_proof(block.proof, block.previous_hash, block.index, block.miner,
                                      certified_pk=node.pk.to_hex(), prev_beta_hex=prev_beta,
                                      certified_pks=certified):
                return False
            return not self.equivocation.observe(block.proof, block.hash or block.compute_hash())
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
            res, pi = popv2_elect(v2, chain.last.hash, len(chain.chain), prev_beta_hex=chain.last.proof.get("beta"))
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
                if self.cfg.issuance == "fresh_vgk":
                    self._distribute_vehicle_generated(rsu, per_vehicle)
                else:
                    rsu.distribute(per_vehicle, avoid_previous=self.cfg.avoid_previous_holder,
                                   pki=self.pki if self.cfg.verify_vehicle_certs else None)
                    if self.cfg.issuance in ("rekey", "window"):
                        self._bind_holders(rsu, pm)
                for v in rsu.vehicles:
                    for p in v.pseudonyms:
                        holders = self.holder_history.setdefault(p.pid, set())
                        if not initial and v.vehicle_id in holders:
                            reassigned += 1
                        holders.add(v.vehicle_id)
                        self.rsu_allots.setdefault(rsu.rsu_id, []).append((self._node(p.pid), v.vehicle_id))
                        self.pm_domains.setdefault(pm.pm_id, []).append((self._node(p.pid), v.vehicle_id))
                        self.truth_of_node[self._node(p.pid)] = v.vehicle_id
        return cpu, blocks, txs_total, reassigned

    def _node(self, pid: str) -> str:
        """Identity node of a pseudonym *holding*: a recycled pid is a different
        node for every holder, so linking metrics are about holdings."""
        return f"{pid}#{self.ledger.epoch.get(pid, 0)}"

    def _distribute_vehicle_generated(self, rsu, per_vehicle: int) -> None:
        """fresh_vgk: each vehicle makes its own key pairs and PKI signs the
        certificates (SCMS style); the private key never leaves the vehicle."""
        for v in rsu.vehicles:
            if v.revoked:
                continue
            c = v.credential
            if self.cfg.verify_vehicle_certs and (c is None or self.pki.is_revoked(c.cert) or
                                                 not crypto.verify(self.pki.keys.pk, c.credential_bytes(), bytes.fromhex(c.cert))):
                rsu.rejected_uncertified += 1
                continue
            keys = [crypto.generate_keypair() for _ in range(per_vehicle)]
            v.load.keygens += per_vehicle
            ps = self.pki.certify(keys)
            v.receive_pseudonyms(ps)
            for p in ps:
                self.ledger.allot(p, v.vehicle_id)
                rsu.allot_log.append((p.pid, v.vehicle_id))

    def _bind_holders(self, rsu, pm) -> None:
        """rekey / window: replace each vehicle's freshly allotted recycled
        pseudonym by a holder copy carrying a PM-signed holder certificate.
        Under rekey the copy has a key the vehicle just generated; under
        window the key is unchanged (the ablation)."""
        now = clock.now()
        t_end = now + self.cfg.round_seconds          # the holder's last message is at now + round_seconds
        for v in rsu.vehicles:
            bound = []
            for p in v.pseudonyms:
                if self.cfg.issuance == "rekey":
                    keys = crypto.generate_keypair()
                    v.load.keygens += 1
                else:
                    keys = p.keys
                hc = pm.sign_holder_cert(p.pid, keys.pk_hex, now, t_end)
                copy = Pseudonym(p.pid, keys, p.cert, p.expiry, p.issuer_pk, hc, p.cert_pk or p.certified_pk)
                bound.append(copy)
                self.ledger.pk[p.pid] = keys.pk_hex
                self.ledger.holder_cert[p.pid] = hc
            v.pseudonyms = bound

    # ------------------------------------------------------------------
    def run_round(self) -> RoundStats:
        r = len(self.rounds) + 1
        t0 = time.perf_counter()
        if not self.cfg.mobility:
            clock.advance(float(self.cfg.round_seconds))
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
        #    Fresh issuance modes retire the used sets instead and ask PKI.
        pm_by_id = {pm.pm_id: pm for pm in self.pms}
        txs = []
        relocated: dict = {}
        if self.cfg.issuance in ("fresh", "fresh_vgk"):
            for pm in self.pms:
                pm.collect_from_rsus()
                for p, _ in pm.collected:
                    self.ledger.retire(p.pid)
                pm.collected = []
                n = pm.net_demand(per_vehicle) if self.cfg.issuance == "fresh" else 0
                if n:
                    ps = self.pki.generate_pseudonyms(n)
                    ct, sig = self.pki.package_for_pm(pm.keys.pk, ps)
                    pm.receive_from_pki(ct, sig, self.pki.keys.pk)
                txs.append(pm.make_tx("issue", pm.keys.pk, {"pm": pm.pm_id, "count": n}))
            shuffled = 0
        else:
            for pm in self.pms:
                pm.collect_from_rsus()
                pm.upload_to_cloud(shuffle_first=self.cfg.shuffle_before_upload)
                self.cloud_uploads.append([self._node(pid) for pid in pm.upload_log[-1]])
            demands = {pm.pm_id: pm.net_demand(per_vehicle) for pm in self.pms}
            relocated = self.cloud.shuffle_and_relocate(demands, seed=self.rng.getrandbits(64))
            shuffled = sum(len(v) for v in relocated.values())
            # recycled certificates that would expire before the next shuffle are
            # renewed by PKI (counted as its work)
            horizon = clock.now() + 2 * self.cfg.round_seconds + 1.0
            in_circulation = [p for ps in relocated.values() for _, p in ps]
            in_circulation += [p for pm in self.pms for p in pm.pool]           # stock held back at PMs ...
            in_circulation += [p for rsu in self.rsus for p in rsu.shuffled_sets]   # ... and at RSUs
            for p in in_circulation:
                if p.expiry <= horizon:
                    self.pki.renew(p)

        # 4. Algorithm 4 lines 18-19: shuffle results become transactions of the
        #    PM-level blockchain; the PMs mine with the configured consensus.
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
            clock.advance(1.0)
            now = clock.now()                     # one time base for messages, certificates and receivers
            beacons: list[Beacon] = []
            positions = {mv.vid: mv.x for mv in road.vehicles}
            holder_x: dict[str, float] = {}
            for mv in road.vehicles:
                v = by_vid[mv.vid]
                if v.revoked and not cfg.revoked_keep_transmitting:
                    continue
                if v.revoked and v.current is None and not v.pseudonyms and v.kept_keys:
                    # a revoked vehicle with no sets left falls back to the copies it kept
                    v.current = v.kept_keys[(step // period) % len(v.kept_keys)]
                if step % period == 0 and not v.revoked:
                    if v.switch_pseudonym() is not None:
                        self.true_changes += 1 if step > 0 or v.changes > 1 else 0
                        silent_until[mv.vid] = self.sim_time + cfg.silent_period
                        node = self._node(v.current.pid)
                        self.epoch_histories.setdefault(v.vehicle_id, []).append(node)
                        self.truth_of_node.setdefault(node, v.vehicle_id)
                if self.sim_time < silent_until.get(mv.vid, 0.0):
                    continue
                msg = v.beacon(mv.x, mv.v, mv.direction, now)
                if msg is None:
                    continue
                messages += 1
                holder_x[v.vehicle_id] = mv.x
                node = self._node(msg.pid)
                self.pid_seconds[node] = self.pid_seconds.get(node, 0.0) + 1.0
                self.last_node_of_pid[msg.pid] = node
                rsu = self.rsus[mv.rsu]
                if not rsu.receive_message(v, msg):
                    rejected += 1
                if self.v2v is not None:
                    acc, _ = self.v2v.deliver(msg, mv.x, positions, now, exclude=mv.vid)
                    if v.revoked and acc:
                        self.revoked_accepted.setdefault(v.vehicle_id, []).append(now)
                x_seen = (mv.x + self.noise_rng.gauss(0, cfg.position_noise_m)) % road.cfg.length_m \
                    if cfg.position_noise_m else mv.x
                beacons.append(Beacon(self.sim_time, msg.pid, x_seen, mv.v, mv.direction, mv.rsu, mv.vid, node))
                if v.malicious and step == period - 1:
                    replay = v.replay_used()
                    if replay is not None:
                        messages += 1
                        if not rsu.receive_message(v, replay):
                            rejected += 1
            if self.former is not None:
                messages += self._former_holder_step(by_vid, positions, holder_x, now)
            self.adversary.observe(beacons)
            pairs = self.adversary.linked_pairs
            self.tracker_nodes.extend(pairs[self._tracker_seen:])        # beacons carry their holding ids
            self._tracker_seen = len(pairs)
        # retire the pseudonym in use so it is returned with the others
        for v in self.vehicles:
            if v.current is None:
                continue
            if v.revoked and v.current in v.kept_keys and v.current not in v.pseudonyms:
                v.current = None                          # a kept copy: never returned to the pool
                continue
            v.used.append(v.current)
            v.history.append(v.current.pid)
            v.current = None
        return messages, rejected

    def _former_holder_step(self, by_vid: dict, positions: dict, holder_x: dict, now: float) -> int:
        """One second of the A2 adversary: every former holder tries every key
        it kept, by the configured strategy, over V2V and towards its RSU."""
        cfg = self.cfg
        road = self.road
        sent = 0
        for mv in road.vehicles:
            a = by_vid[mv.vid]
            if not a.former_holder or a.revoked:
                continue
            for p in list(a.kept_keys):
                fm = self.former.forge(a, mv.x, p, self.ledger, road.cfg.length_m, holder_x, now,
                                       mv.v, mv.direction, self.ledger.holder_cert.get(p.pid))
                if fm is None:
                    continue
                sent += 1
                acc, rx = (0, 0)
                if self.v2v is not None:
                    acc, rx = self.v2v.deliver(fm.msg, mv.x, positions, now, forged=True, exclude=mv.vid)
                rsu = self.rsus[mv.rsu]
                before = len(rsu.pm.misbehaviour_reports)
                rsu_ok = rsu.receive_message(a if cfg.attribution == "oracle" else None, fm.msg)
                for rep in rsu.pm.misbehaviour_reports[before:]:
                    if fm.victim_vid and rep["vehicle"] == fm.victim_vid:
                        self.former.stats.victims_blamed += 1
                self.former.record(fm, acc, rx, rsu_ok, now)
        return sent

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
                    self.revoked_at[v.vehicle_id] = clock.now()
                    self.pki_reports.append((self._node(rep["pid"]), rep["vehicle"]))
                    # its remaining pseudonyms are retired in the ledger at once
                    for p in v.pseudonyms + ([v.current] if v.current else []):
                        self.ledger.mark_used(p.pid)

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

    def insider_evidence(self) -> Evidence:
        return Evidence(rsu_allots=self.rsu_allots, pm_domains=self.pm_domains, cloud_uploads=self.cloud_uploads,
                        pki_reports=self.pki_reports, tracker_pairs=self.tracker_nodes,
                        histories=self.epoch_histories, truth_of_pid=self.truth_of_node,
                        pid_seconds=self.pid_seconds, group_size=self.cfg.pseudonyms_per_vehicle)

    def load_report(self, costs: OpCosts | None = None) -> dict:
        costs = costs or OpCosts()
        n = len(self.vehicles)
        secs = max(self.sim_time, 1.0)
        pki = self.pki.load.to_dict()
        pm = {k: sum(p.load.to_dict()[k] for p in self.pms) for k in ("signatures", "keygens", "bytes", "verifications")}
        rsu = {k: sum(r.load.to_dict()[k] for r in self.rsus) for k in ("signatures", "keygens", "bytes", "verifications")}
        veh = {k: sum(v.load.to_dict()[k] for v in self.vehicles) for k in ("signatures", "keygens", "bytes", "verifications")}
        rounds = max(1, len(self.rounds))
        steady = {ent: {k: tot[k] - self.setup_load[ent][k] for k in tot}
                  for ent, tot in (("pki", pki), ("pm", pm), ("rsu", rsu), ("vehicles", veh))}
        return {
            "pki": pki, "pm": pm, "rsu": rsu, "vehicles": veh, "setup": self.setup_load, "steady_state": steady,
            "pki_cpu_s_per_1000_veh_h": per_1000_vehicles_per_hour(cpu_seconds(steady["pki"], costs), n, secs),
            "pm_cpu_s_per_1000_veh_h": per_1000_vehicles_per_hour(cpu_seconds(steady["pm"], costs), n, secs),
            "rsu_cpu_s_per_1000_veh_h": per_1000_vehicles_per_hour(cpu_seconds(steady["rsu"], costs), n, secs),
            "vehicle_keygens_per_vehicle_per_round": steady["vehicles"]["keygens"] / max(1, n) / rounds,
            "bytes_per_vehicle_per_round": steady["vehicles"]["bytes"] / max(1, n) / rounds,
            "sim_seconds": secs, "n_vehicles": n,
        }

    def recycling_report(self) -> dict:
        out: dict = {"issuance": self.cfg.issuance, "attribution": self.cfg.attribution,
                     "v2v": self.v2v.stats.to_dict() if self.v2v else None, "load": self.load_report()}
        if self.former is not None:
            st = self.former.stats
            out["forgery"] = {**st.to_dict(), **forged_acceptance(st), "exposure": exposure_windows(st.accepted_times),
                              "by_strategy": self.former.by_strategy, "strategy": self.cfg.former_holder_strategy}
        if self.revoked_at:
            per = {}
            for vid, t0 in self.revoked_at.items():
                later = [t for t in self.revoked_accepted.get(vid, []) if t >= t0]
                per[vid] = {"revoked_at": t0, "accepted_after": len(later),
                            "seconds_to_last": (max(later) - t0) if later else 0.0}
            out["revoked_persistence"] = per
        if self.cfg.mobility:
            out["insider"] = full_table(self.insider_evidence())
        return out

    def summary(self) -> dict:
        return {
            "recycling": self.recycling_report() if (self.cfg.mobility or self.former or self.revoked_at) else None,
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
