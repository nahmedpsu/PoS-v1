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
from .entities import (
    PKI,
    RSU,
    Manufacturer,
    PMCloud,
    PrivacyManager,
    Pseudonym,
    PseudonymLedger,
    SafetyMessage,
    Vehicle,
)
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

DEFAULT_OP_COSTS: list[OpCosts] = [OpCosts()]   # replaced by measured coefficients via set_op_costs (review R17)


def set_op_costs(costs: OpCosts) -> None:
    DEFAULT_OP_COSTS[0] = costs

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
    position_noise_m: float = 0.0        # observer error added to what the eavesdropper sees (on top of gps_noise_m)
    gps_noise_m: float = 0.0             # sensor error in the position a vehicle measures and signs (review R08)
    gps_noise_corr: float = 0.9          # AR(1) correlation of that error from one second to the next
    forecast_alpha: float = 0.5          # EMA weight of the RSU demand forecast
    safety_stock: float = 0.0            # extra fraction of sets an RSU asks for above its forecast
    adversary_gate_m: float = 8.0        # tracking adversary's matching gate
    verify_vehicle_certs: bool = True    # RSU allots only to vehicles with a valid, unrevoked PKI certificate
    # ---- pseudonym recycling study (defaults reproduce v2.2.1 exactly) ----
    attribution: str = "oracle"          # "oracle": RSU knows the true sender; "ledger": attributes by ledger holder
    v2v: bool = False                    # vehicle-to-vehicle receivers (certificate + signature, no ledger)
    v2v_range_m: float = 300.0
    v2v_plausibility: bool = False
    v2v_detectors: tuple = ("ssc",)      # plausibility detectors at receivers: ssc, art, kin (review R09)
    v2v_allowance_m: float = 25.0        # ssc: distance allowed on top of max speed x elapsed time
    v2v_kin_tolerance_m: float = 10.0    # kin: allowed deviation from the dead-reckoned position
    v2v_loss: float = 0.0                # independent per-reception loss probability       # receivers apply the local two-places-at-once rule
    former_holders: int = 0              # A2 adversaries: vehicles that keep every key they held
    former_holder_strategy: str = "S1"   # S1 remote shadow, S2 co-located ghost, S3 gap filler
    ghost_offset_m: float = 40.0
    issuance: str = "recycle"            # recycle | fresh | fresh_vgk | rekey | window
    pseudonym_lifetime: float = 3600.0   # certificate lifetime in seconds
    revoked_keep_transmitting: bool = False   # a revoked vehicle keeps beaconing under the pseudonyms it holds
    shuffle_before_upload: bool = False  # PM shuffles used sets before uploading (cloud-order leak fix)
    revocation_reports: int = 1          # clone reports against a vehicle before the PM asks the PKI to revoke it
    revocation_distinct_rsus: int = 1    # ... and from at least this many different RSUs
    rsu_history: str = "shared"          # clone-check history: "shared" ledger state or "local" per RSU (review R10)
    report_processing: str = "round"     # "round": PM acts at round ends; "continuous": every second (review R11)
    report_delay_s: float = 1.0          # continuous: seconds for a report to reach the PM
    malicious_replay: str = "per_round"  # genuine misbehaver replays "per_round" or "per_second" (matched workload, R11)
    departed_return_prob: float = 1.0    # trace roads: chance a departing vehicle's pseudonyms ever come back (review R21)
    departed_return_delay_rounds: int = 0  # ... and how many rounds later they reach an RSU
    insider_forgery: bool = False        # E3b: each infrastructure entity signs with keys it holds
    insider_strategy: str = "offset"     # "offset": ghost_offset_m from the holder; "near": within the 25 m
                                         # same-second tolerance; "silent": during the holder's silent period
    insider_forgeries_per_round: int = 1 # per entity; "offset"/"near" spread them evenly over the round
    insider_near_m: float = 10.0

    def __post_init__(self):
        if self.consensus not in CONSENSUS_KINDS:
            raise ValueError(f"consensus must be one of {CONSENSUS_KINDS}")
        if self.attribution not in ("oracle", "ledger"):
            raise ValueError("attribution must be 'oracle' or 'ledger'")
        if self.issuance not in ISSUANCE_MODES:
            raise ValueError(f"issuance must be one of {ISSUANCE_MODES}")
        if self.rsu_history not in ("shared", "local"):
            raise ValueError("rsu_history must be 'shared' or 'local'")
        if self.report_processing not in ("round", "continuous"):
            raise ValueError("report_processing must be 'round' or 'continuous'")
        if self.malicious_replay not in ("per_round", "per_second"):
            raise ValueError("malicious_replay must be 'per_round' or 'per_second'")
        if self.former_holder_strategy not in STRATEGIES:
            raise ValueError(f"former_holder_strategy must be one of {STRATEGIES}")
        if self.insider_strategy not in ("offset", "near", "silent"):
            raise ValueError("insider_strategy must be 'offset', 'near' or 'silent'")
        if self.revocation_reports < 1 or self.revocation_distinct_rsus < 1:
            raise ValueError("revocation_reports and revocation_distinct_rsus must be at least 1")


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
        self.first_report_at: dict[str, float] = {}           # vehicle -> time of the first report against it (R11)
        self.first_replay_at: dict[str, float] = {}           # genuine misbehaver -> time of its first replay (R11)
        self.report_tally: dict[str, list[dict]] = {}        # vehicle -> clone reports received so far (revocation rule)
        self.present_vehicle_steps = 0                       # sum over driven seconds of vehicles on the road (traces: not all are)
        self.departed_returns = 0                            # pseudonyms returned by vehicles that left the corridor
        self.retained_valid: list[tuple[float, int, int]] = []   # (time, unexpired retained credentials, retained)
        self.departed_lost = 0                               # pseudonyms that never came back from departed vehicles
        self._pending_returns: list[tuple[int, object, list]] = []   # (due round, rsu, pseudonyms)
        self.attacker_present_steps = 0                      # former-holder vehicle-seconds on the road (review R22)
        self.return_rng = random.Random(cfg.seed ^ 0x2E7)
        self.gps_rng = random.Random(cfg.seed ^ 0x6B5)       # sensor error, independent of the protocol's randomness
        self._gps_err: dict[int, float] = {}
        self.attack_opportunities = 0                        # (former holder, retained credential, second) checked
        self.insider_stats: dict[str, dict] = {}             # E3b: per entity, key custody share and forgery outcome
        self.driven_steps = 0
        self.road: Road | None = None
        self.adversary = None
        self.true_changes = 0
        self.sim_time = 0.0
        self._build()
        # work done at set-up (registration, initial sets) is reported separately from steady-state work
        self.setup_load = {"pki": self.pki.load.to_dict(),
                           "pm": {k: sum(p.load.to_dict()[k] for p in self.pms) for k in ("signatures", "keygens", "bytes", "verifications", "encryptions", "decryptions")},
                           "rsu": {k: sum(r.load.to_dict()[k] for r in self.rsus) for k in ("signatures", "keygens", "bytes", "verifications", "encryptions", "decryptions")},
                           "vehicles": {k: sum(v.load.to_dict()[k] for v in self.vehicles) for k in ("signatures", "keygens", "bytes", "verifications", "encryptions", "decryptions")}}

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
                if cfg.rsu_history == "local":
                    rsu.local_history = {}
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
            # distances wrap around on the synthetic ring; a straight corridor (a SUMO trace) never wraps
            self.wrap_m = road_cfg.length_m if getattr(self.road, "is_ring", True) else 1e12
            self.ledger.ring_length = self.wrap_m
            self.adversary = make_tracker(cfg.tracker, self.wrap_m, cfg.adversary_gate_m, 1.0)
            for mv in getattr(self.road, "all_vehicles", self.road.vehicles):   # a trace: every vehicle that ever appears
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
            window = getattr(self.road, "window_ids", None)       # traces: only vehicles present in the evaluated window
            honest = [v for v in self.vehicles if not v.malicious and (window is None or v.index in window)]
            for v in self.rng.sample(honest, min(cfg.former_holders, len(honest))):
                v.former_holder = True
            self.former = FormerHolderAdversary(cfg.former_holder_strategy, cfg.ghost_offset_m, cfg.v2v_range_m)
        if cfg.mobility and cfg.v2v:
            self.v2v = V2VLayer(self.pki.keys.pk, self.wrap_m, cfg.v2v_range_m, cfg.v2v_plausibility,
                                mode="holder" if cfg.issuance in ("rekey", "window") else "pki",
                                pm_cert_check=self.pki.verify_pm_cert, detectors=tuple(cfg.v2v_detectors),
                                allowance_m=cfg.v2v_allowance_m, kin_tolerance_m=cfg.v2v_kin_tolerance_m,
                                loss=cfg.v2v_loss, seed=cfg.seed)

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

    def _measured_x(self, vid: int, x: float) -> float:
        """True position plus an AR(1) GPS error of standard deviation
        ``gps_noise_m`` (review R08); the true position when it is zero."""
        sd = self.cfg.gps_noise_m
        if not sd:
            return x
        rho = self.cfg.gps_noise_corr
        prev = self._gps_err.get(vid)
        e = self.gps_rng.gauss(0, sd) if prev is None else rho * prev + (1 - rho * rho) ** 0.5 * self.gps_rng.gauss(0, sd)
        self._gps_err[vid] = e
        return (x + e) % self.wrap_m

    def _return_departed(self) -> None:
        """A vehicle that left the corridor during the round (trace roads only)
        returns everything it holds, used or not, through the RSU it was last in:
        in the protocol it would return them to the next RSU it meets, and the
        study area is a window on the network, not a closed box.  On the ring
        nobody leaves and this is a no-op."""
        if not self.cfg.mobility or self.road is None:
            return
        present = {mv.vid for mv in self.road.vehicles}
        round_no = len(self.rounds)
        for rsu in self.rsus:
            for v in rsu.vehicles:
                if v.index in present:
                    continue
                # everything the departed vehicle carries: unused sets, the one in use, and used ones
                held = v.pseudonyms + ([v.current] if v.current is not None else []) + v.used
                if not held:
                    continue
                v.pseudonyms, v.current, v.used = [], None, []
                if self.return_rng.random() >= self.cfg.departed_return_prob:
                    self.departed_lost += len(held)            # never returned: stays allotted in the ledger
                elif self.cfg.departed_return_delay_rounds <= 0:
                    v.used.extend(held)
                    self.departed_returns += len(held)
                else:
                    self._pending_returns.append((round_no + self.cfg.departed_return_delay_rounds, rsu, held))
        due = [x for x in self._pending_returns if x[0] <= round_no]
        self._pending_returns = [x for x in self._pending_returns if x[0] > round_no]
        for _, rsu, held in due:                               # returned late, through the RSU last seen
            for p in held:
                rsu.used.append((p, {}))
                self.ledger.mark_used(p.pid)
            self.departed_returns += len(held)

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
                rsu.load.signatures += 1                  # review R17: RSU block transactions were not counted
                rsu.load.encryptions += 1
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
            ps = self.pki.certify([k.pk for k in keys])       # only the public keys leave the vehicle
            for p, k in zip(ps, keys):
                p.keys = k
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
        self._process_reports(clock.now() if self.cfg.report_processing == "continuous" else None)
        self._return_departed()

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
                rsu.load.signatures += 1                  # review R17: RSU block transactions were not counted
                rsu.load.encryptions += 1
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
            pm_by_id[dst_id].receive_pool([p for _, p in ps])
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
            self.present_vehicle_steps += len(road.vehicles)
            self.attacker_present_steps += sum(1 for mv in road.vehicles if by_vid[mv.vid].former_holder)
            self.driven_steps += 1
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
                x_tx = self._measured_x(mv.vid, mv.x)          # what the vehicle measures and signs (R08)
                msg = v.beacon(x_tx, mv.v, mv.direction, now)
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
                x_seen = (x_tx + self.noise_rng.gauss(0, cfg.position_noise_m)) % self.wrap_m \
                    if cfg.position_noise_m else x_tx
                beacons.append(Beacon(self.sim_time, msg.pid, x_seen, mv.v, mv.direction, mv.rsu, mv.vid, node))
                replay_now = step == period - 1 if cfg.malicious_replay == "per_round" else True
                if v.malicious and replay_now:
                    replay = v.replay_used()
                    if replay is not None:
                        self.first_replay_at.setdefault(v.vehicle_id, now)
                        messages += 1
                        if not rsu.receive_message(v, replay):
                            rejected += 1
            if self.former is not None:
                messages += self._former_holder_step(by_vid, positions, holder_x, now, beacons)
            if cfg.insider_forgery:
                messages += self._insider_step(by_vid, positions, now, step, silent_until)
            if cfg.report_processing == "continuous":
                self._process_reports(now)
            self.adversary.observe(beacons)
            pairs = self.adversary.linked_pairs
            self.tracker_nodes.extend(pairs[self._tracker_seen:])        # beacons carry their holding ids
            self._tracker_seen = len(pairs)
        # retained credentials still unexpired (review R02): sampled once per round
        held = [k for v in self.vehicles if v.former_holder or v.malicious for k in v.kept_keys]
        if held:
            self.retained_valid.append((self.sim_time, sum(k.expiry >= clock.now() for k in held), len(held)))
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

    def _insider_entities(self) -> dict:
        """One instance of each infrastructure entity, as in E3: the PKI, the
        first PM, the first RSU and the cloud, with the private keys each has held."""
        return {"pki": self.pki.key_custody, "pm": self.pms[0].key_custody,
                "rsu": self.rsus[0].key_custody, "cloud": self.cloud.key_custody}

    def _insider_step(self, by_vid: dict, positions: dict, now: float, step: int, silent_until: dict) -> int:
        """E3b, the A3 adversary with a key.  Once per round (last second) each
        entity measures the share of pseudonyms in use whose current signing key
        it holds.  It forges up to ``insider_forgeries_per_round`` messages per
        round, each with a held key on behalf of the pseudonym's current holder,
        sent to the V2V receivers and to the holder's RSU:

        * ``offset``: ``ghost_offset_m`` from the holder, at evenly spaced seconds
          (receivers that just heard the holder see two places at once);
        * ``near``: within ``insider_near_m`` of the holder, inside the 25 m
          tolerance receivers and RSUs allow for one second;
        * ``silent``: while the holder is in its post-change silent period, at
          its position, before any receiver has heard the new pseudonym."""
        cfg = self.cfg
        rs = cfg.round_seconds
        n = max(1, cfg.insider_forgeries_per_round)
        in_use = {}
        for mv in self.road.vehicles:
            v = by_vid[mv.vid]
            if v.current is not None and not v.revoked:
                in_use[v.current.pid] = (v, mv)
        sent = 0
        scheduled = step in {(i + 1) * rs // n - 1 for i in range(n)}
        for name, custody in self._insider_entities().items():
            st = self.insider_stats.setdefault(name, {"rounds": 0, "share_sum": 0.0, "sent": 0, "accepted": 0,
                                                      "receivers_total": 0, "receivers_accepting": 0,
                                                      "rsu_accepted": 0, "holder_blamed": 0, "round_sent": 0})
            if step == 0:
                st["round_sent"] = 0
            held = sorted(pid for pid, (v, mv) in in_use.items()
                          if pid in custody and custody[pid].sk is not None
                          and custody[pid].pk_hex == v.current.keys.pk_hex)
            if step == rs - 1 and in_use:
                st["rounds"] += 1
                st["share_sum"] += len(held) / len(in_use)
            if cfg.insider_strategy == "silent":
                targets = [pid for pid in held if self.sim_time < silent_until.get(in_use[pid][1].vid, 0.0)]
                if not targets or st["round_sent"] >= n:
                    continue
            else:
                if not scheduled or not held:
                    continue
                targets = [pid for pid in held if self.sim_time >= silent_until.get(in_use[pid][1].vid, 0.0)] or held
            pid = targets[(step + len(name)) % len(targets)]
            v, mv = in_use[pid]
            keys = custody[pid]
            if cfg.insider_strategy == "offset":
                claimed_x = mv.x + cfg.ghost_offset_m
            elif cfg.insider_strategy == "near":
                claimed_x = mv.x + cfg.insider_near_m
            else:
                claimed_x = mv.x
            claimed_x %= self.wrap_m
            msg = SafetyMessage(pid, (claimed_x, 0.0), mv.v, float(mv.direction), now)
            msg.signature = crypto.sign(keys.sk, msg.body()).hex()
            msg.cred = v.current.cert_wire()                 # public: the certificate every message carries
            st["sent"] += 1
            st["round_sent"] += 1
            sent += 1
            if self.v2v is not None:
                acc, rx = self.v2v.deliver(msg, claimed_x, positions, now, forged=True, exclude=mv.vid)
                st["receivers_total"] += rx
                st["receivers_accepting"] += acc
                if acc:
                    st["accepted"] += 1
            rsu = self.rsus[mv.rsu]
            before = len(rsu.pm.misbehaviour_reports)
            if rsu.receive_message(None, msg):
                st["rsu_accepted"] += 1
            if any(r["vehicle"] == v.vehicle_id for r in rsu.pm.misbehaviour_reports[before:]):
                st["holder_blamed"] += 1
        return sent

    def _former_holder_step(self, by_vid: dict, positions: dict, holder_x: dict, now: float,
                            beacons: list | None = None) -> int:
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
                self.attack_opportunities += 1
                fm = self.former.forge(a, mv.x, p, self.ledger, self.wrap_m, holder_x, now,
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
                        self.former.stats.victims_blamed_ids.add(fm.victim_vid)
                self.former.record(fm, acc, rx, rsu_ok, now)
                if beacons is not None:
                    # the eavesdropper hears forged CAMs too (review R14); the true sender is for scoring only
                    x_seen = (fm.msg.position[0] + self.noise_rng.gauss(0, cfg.position_noise_m)) % self.wrap_m \
                        if cfg.position_noise_m else fm.msg.position[0]
                    beacons.append(Beacon(self.sim_time, fm.msg.pid, x_seen, fm.msg.speed, int(fm.msg.direction),
                                          mv.rsu, mv.vid, f"{fm.msg.pid}#forged"))
        return sent

    def _revocation_due(self, vid: str) -> bool:
        """The revocation rule: at least ``revocation_reports`` clone reports
        against the vehicle, from at least ``revocation_distinct_rsus``
        different RSUs (defaults 1 and 1: the first report revokes)."""
        reps = self.report_tally.get(vid, [])
        return (len(reps) >= self.cfg.revocation_reports and
                len({r["rsu"] for r in reps}) >= self.cfg.revocation_distinct_rsus)

    def _process_reports(self, now: float | None = None) -> None:
        """PM -> CA: a vehicle caught reusing a pseudonym has its certificate
        revoked once the revocation rule is met.  With ``now`` (continuous
        processing) only reports older than ``report_delay_s`` are handled,
        oldest first; without it, everything pending (round processing)."""
        for pm in self.pms:
            due = [r for r in pm.misbehaviour_reports
                   if now is None or r.get("t", 0.0) + self.cfg.report_delay_s <= now]
            if not due:
                continue
            pm.misbehaviour_reports = [r for r in pm.misbehaviour_reports if r not in due]
            for rep in sorted(due, key=lambda r: r.get("t", 0.0)):
                v = next(v for v in self.vehicles if v.vehicle_id == rep["vehicle"])
                self.report_tally.setdefault(v.vehicle_id, []).append(rep)
                self.first_report_at.setdefault(v.vehicle_id, rep.get("t"))
                if not v.revoked and self._revocation_due(v.vehicle_id):
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
    def population_report(self) -> dict:
        """Disjoint population and revocation counts (review R01).  Attackers are
        vehicles configured as former holders or as misbehaving; everyone else
        is honest.  ``revoked_total == revoked_honest + revoked_attackers`` and
        ``vehicles == honest + attackers`` hold by construction."""
        attackers = [v for v in self.vehicles if v.former_holder or v.malicious]
        honest = [v for v in self.vehicles if not (v.former_holder or v.malicious)]
        return {"population": {"vehicles": len(self.vehicles), "honest": len(honest), "attackers": len(attackers),
                               "revoked_total": sum(v.revoked for v in self.vehicles),
                               "revoked_honest": sum(v.revoked for v in honest),
                               "revoked_attackers": sum(v.revoked for v in attackers)}}

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
            **self.population_report(),
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
        costs = costs or DEFAULT_OP_COSTS[0]
        # per-vehicle figures are normalised by the vehicles actually on the road: on
        # the synthetic ring that is every vehicle; on a trace, the mean present per second
        n = self.present_vehicle_steps / self.driven_steps if self.driven_steps else len(self.vehicles)
        secs = max(self.sim_time, 1.0)
        pki = self.pki.load.to_dict()
        pm = {k: sum(p.load.to_dict()[k] for p in self.pms) for k in ("signatures", "keygens", "bytes", "verifications", "encryptions", "decryptions")}
        rsu = {k: sum(r.load.to_dict()[k] for r in self.rsus) for k in ("signatures", "keygens", "bytes", "verifications", "encryptions", "decryptions")}
        veh = {k: sum(v.load.to_dict()[k] for v in self.vehicles) for k in ("signatures", "keygens", "bytes", "verifications", "encryptions", "decryptions")}
        rounds = max(1, len(self.rounds))
        steady = {ent: {k: tot[k] - self.setup_load[ent][k] for k in tot}
                  for ent, tot in (("pki", pki), ("pm", pm), ("rsu", rsu), ("vehicles", veh))}
        cpu_range = {ent: [per_1000_vehicles_per_hour(cpu_seconds(steady[ent], costs) * f, n, secs) for f in (0.5, 2.0)]
                     for ent in ("pki", "pm", "rsu")}
        return {
            "pki": pki, "pm": pm, "rsu": rsu, "vehicles": veh, "setup": self.setup_load, "steady_state": steady,
            "cost_model": {**{k: getattr(costs, k) for k in ("sign", "verify", "keygen", "encrypt", "decrypt", "source")},
                           "note": "modelled: counted cryptographic operations x per-operation coefficients"},
            "cpu_range_x0.5_x2_per_1000_veh_h": cpu_range,
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
                              "opportunities": self.attack_opportunities,
                              "unique_victims_blamed": len(st.victims_blamed_ids),

                              "by_strategy": self.former.by_strategy, "strategy": self.cfg.former_holder_strategy}
        out["retained_valid"] = [{"t": t, "valid": a, "retained": n} for t, a, n in self.retained_valid]
        # revocation latency decomposed (review R11): misbehaviour -> first report -> decision
        out["revocation_timing"] = {
            vid: {"first_replay": self.first_replay_at.get(vid), "first_report": self.first_report_at.get(vid),
                  "revoked": t, "detection_s": (self.first_report_at[vid] - self.first_replay_at[vid])
                  if vid in self.first_replay_at and vid in self.first_report_at else None,
                  "decision_s": (t - self.first_report_at[vid]) if vid in self.first_report_at else None}
            for vid, t in self.revoked_at.items()}
        if self.revoked_at:
            per = {}
            for vid, t0 in self.revoked_at.items():
                later = [t for t in self.revoked_accepted.get(vid, []) if t >= t0]
                per[vid] = {"revoked_at": t0, "accepted_after": len(later),
                            "seconds_to_last": (max(later) - t0) if later else 0.0}
            out["revoked_persistence"] = per
        if self.cfg.mobility:
            out["insider"] = full_table(self.insider_evidence())
        if self.insider_stats:
            out["insider_forgery"] = {
                name: {"key_share": st["share_sum"] / max(1, st["rounds"]), "rounds": st["rounds"], "sent": st["sent"],
                       "accepted": st["accepted"], "message_rate": st["accepted"] / st["sent"] if st["sent"] else 0.0,
                       "rsu_rate": st["rsu_accepted"] / st["sent"] if st["sent"] else 0.0,
                       "blame_rate": st["holder_blamed"] / st["sent"] if st["sent"] else 0.0,
                       "receivers_total": st["receivers_total"],
                       "receivers_accepting": st["receivers_accepting"],
                       "receiver_rate": st["receivers_accepting"] / st["receivers_total"] if st["receivers_total"] else 0.0,
                       "rsu_accepted": st["rsu_accepted"], "holder_blamed": st["holder_blamed"]}
                for name, st in self.insider_stats.items()}
        return out

    def summary(self) -> dict:
        return {
            "recycling": self.recycling_report() if (self.cfg.mobility or self.former or self.revoked_at) else None,
            "stockouts": sum(r.stockouts for r in self.rsus),
            "departed_returns": self.departed_returns,
            "departed_lost": self.departed_lost,
            "attacker_vehicle_seconds": self.attacker_present_steps,
            "vehicle_seconds": self.present_vehicle_steps,
            "achieved_attack_share": (self.attacker_present_steps / self.present_vehicle_steps
                                      if self.present_vehicle_steps else None),
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
