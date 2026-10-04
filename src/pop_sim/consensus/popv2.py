"""Proof of Pseudonym v2: a serverless, verifiable election.

PoP v1 (Algorithm 6 of the manuscript) needs a cloud server to pick the
miners and trusts every node's self-reported "random short time".  PoP v2
keeps the idea (no puzzle; a random subset of the nodes competes; the
smallest random value publishes) and makes it cheat-proof:

* every node evaluates a VRF on the public seed ``prev_block_hash || index``
  with a key whose public part PKI certified at registration;
* the seed of block ``i`` is, by default, the VRF *output* of block ``i-1``'s
  winner (``prev_beta``), not the block hash: a block hash can be ground
  (the winner re-arranges its block until its own next value is small), a
  VRF output cannot (``seed_mode="block_hash"`` reproduces the weaker
  variant for the attack bench);
* a node is a *miner* for this block when its VRF output, read as a number
  in [0, 1), is below the sortition threshold (0.5 reproduces the paper's
  "not less than 50 percent");
* among the miners the smallest VRF output wins, and the proof travels in
  the block so that every node can verify it, including nodes that were not
  selected.  No node can lie about or grind its value, and there is nothing
  for a spoofed server to decide.

Cost per node per block: one VRF proof (its own) and one VRF verification
(the winner's).  The ``n`` comparisons of the race are over received values
and happen in parallel on every node.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from .. import vrf

SORTITION_THRESHOLD = 0.5


@dataclass
class V2Node:
    node_id: str
    keys: object                    # vrf.VRFKeyPair (RSA-FDH) or ecvrf.ECVRFKeyPair
    cert: str = ""                  # PKI signature over (node_id, vrf pk), hex

    @property
    def pk(self):
        return self.keys.public


@dataclass
class PoPv2Result:
    seed_hex: str
    nodes: int
    miners: list[str]
    winner: str
    winner_value: float
    values: dict[str, float] = field(default_factory=dict)
    prove_seconds_mean: float = 0.0     # what one node spends on its own proof
    verify_seconds: float = 0.0         # verifying the winner's proof
    race_seconds: float = 0.0           # the comparison over received values
    cpu_seconds: float = 0.0            # whole election, all nodes, sequential

    def proof(self, winner_node: V2Node, pi: bytes) -> dict:
        return {"seed": self.seed_hex, "winner": self.winner, "vrf_pk": winner_node.pk.to_hex(),
                "pi": pi.hex(), "beta": vrf.vrf_proof_to_hash(pi).hex(), "value": self.winner_value,
                "threshold": SORTITION_THRESHOLD, "miners": len(self.miners)}


def election_seed(prev_block_hash: str, index: int, prev_beta_hex: str | None = None) -> bytes:
    """Seed of the election for block ``index``: the previous winner's VRF
    output when known (unforgeable, ungrindable), else the previous hash."""
    if prev_beta_hex:
        return f"beta:{prev_beta_hex}:{index}".encode()
    return f"{prev_block_hash}:{index}".encode()


def popv2_elect(nodes: list[V2Node], prev_block_hash: str, index: int,
                threshold: float = SORTITION_THRESHOLD, prev_beta_hex: str | None = None) -> tuple[PoPv2Result, bytes]:
    """Run the election for block ``index`` on top of ``prev_block_hash``
    (seeded by ``prev_beta_hex`` when given).  Returns the result and the
    winner's proof ``pi``."""
    if not nodes:
        raise ValueError("no nodes")
    t0 = time.perf_counter()
    seed = election_seed(prev_block_hash, index, prev_beta_hex)
    proofs: dict[str, bytes] = {}
    values: dict[str, float] = {}
    prove_times = []
    for node in nodes:                                   # in reality: in parallel, one per node
        t = time.perf_counter()
        pi = vrf.vrf_prove(node.keys, seed)
        prove_times.append(time.perf_counter() - t)
        proofs[node.node_id] = pi
        values[node.node_id] = vrf.beta_to_unit(vrf.vrf_proof_to_hash(pi))
    t1 = time.perf_counter()
    miners = [nid for nid, v in values.items() if v < threshold]
    pool = miners or list(values)                        # vanishingly rare: nobody below threshold
    winner = min(pool, key=values.get)
    t2 = time.perf_counter()
    wnode = next(n for n in nodes if n.node_id == winner)
    assert vrf.vrf_verify(wnode.pk, seed, proofs[winner]) is not None
    t3 = time.perf_counter()
    res = PoPv2Result(seed.hex(), len(nodes), miners, winner, values[winner], values,
                      sum(prove_times) / len(prove_times), t3 - t2, t2 - t1, t3 - t0)
    return res, proofs[winner]


def verify_popv2_proof(proof: dict, prev_block_hash: str, index: int, miner: str,
                       certified_pk: str | None = None, prev_beta_hex: str | None = None) -> bool:
    """What every node runs on a received block: the proof must verify under
    the miner's certified VRF key, for this chain position and seed, and the
    value must be below the sortition threshold (unless the block says nobody was)."""
    try:
        if proof["winner"] != miner:
            return False
        if certified_pk is not None and proof["vrf_pk"] != certified_pk:
            return False
        if proof["seed"] != election_seed(prev_block_hash, index, prev_beta_hex).hex():
            return False
        pk = vrf.VRFPublicKey.from_hex(proof["vrf_pk"])
        beta = vrf.vrf_verify(pk, bytes.fromhex(proof["seed"]), bytes.fromhex(proof["pi"]))
        if beta is None:
            return False
        if "beta" in proof and proof["beta"] != beta.hex():
            return False
        value = vrf.beta_to_unit(beta)
        if abs(value - proof["value"]) > 1e-12:
            return False
        return value < proof["threshold"] or proof.get("miners", 1) == 0
    except (KeyError, ValueError, TypeError):
        return False


def fork_rule(candidates: list[dict]) -> dict:
    """When two valid blocks for the same position reach a node (the network
    delivered them within the time limit), the one with the smaller VRF value
    wins; ties are impossible for distinct keys."""
    return min(candidates, key=lambda p: p["value"])


class EquivocationDetector:
    """Two different blocks carrying the same (key, seed) proof is
    equivocation: the detector records the first block hash seen per proof
    and reports any second one, so that both are discarded and the node is
    reported to PKI."""

    def __init__(self):
        self.seen: dict[tuple[str, str], str] = {}
        self.equivocators: set[str] = set()

    def observe(self, proof: dict, block_hash: str) -> bool:
        key = (proof.get("vrf_pk", ""), proof.get("seed", ""))
        first = self.seen.setdefault(key, block_hash)
        if first != block_hash:
            self.equivocators.add(proof.get("winner", ""))
            return True
        return False


def make_nodes(ids: list[str], bits: int = 2048, rng: random.Random | None = None,
               scheme: str | None = None) -> list[V2Node]:
    return [V2Node(i, vrf.generate_vrf_keypair(bits, scheme)) for i in ids]
