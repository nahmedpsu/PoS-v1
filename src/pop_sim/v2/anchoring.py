"""Blockchain of blockchains, done with commitments.

The manuscript keeps an RSU-level chain under every PM and a PM-level chain
above them but does not say how the two are tied.  Here every PM-level
block carries, for each PM, the Merkle root of the RSU-level block hashes
produced since the previous anchor.  Consequences:

* a tampered RSU chain is detectable from the PM level alone
  (``detect_rsu_tamper``);
* a vehicle entering another PM's area can carry a compact proof that a
  pseudonym was allotted to it: Merkle path from the ``allot`` transaction
  to its RSU block, the RSU block header, the Merkle path from that block's
  hash to the anchor root, and the PM block header (``build_allotment_proof``
  / ``verify_allotment_proof``).  The proof size and verification time are
  measured so the "fully traceable record" claim comes with numbers.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from ..blockchain import Block, Blockchain


def _h(a: str, b: str) -> str:
    return hashlib.sha256((a + b).encode()).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_h(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Sibling hashes with their side ("L" or "R") from leaf to root."""
    path = []
    level = list(leaves)
    i = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        path.append((level[sib], "L" if sib < i else "R"))
        level = [_h(level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return path


def merkle_verify(leaf: str, path: list[tuple[str, str]], root: str) -> bool:
    cur = leaf
    for sib, side in path:
        cur = _h(sib, cur) if side == "L" else _h(cur, sib)
    return cur == root


# --------------------------------------------------------------- anchors
@dataclass
class AnchorRecord:
    pm_id: str
    first_index: int            # RSU block index range covered
    last_index: int
    root: str


def make_anchor(rsu_chain: Blockchain, pm_id: str, since_index: int) -> AnchorRecord:
    blocks = rsu_chain.chain[since_index:]
    return AnchorRecord(pm_id, since_index, len(rsu_chain.chain) - 1, merkle_root([b.hash for b in blocks]))


def anchors_to_proof(anchors: list[AnchorRecord]) -> dict:
    return {"anchors": {a.pm_id: {"first": a.first_index, "last": a.last_index, "root": a.root} for a in anchors}}


def detect_rsu_tamper(rsu_chain: Blockchain, pm_chain: Blockchain, pm_id: str) -> bool:
    """Recompute every anchor for ``pm_id`` from the RSU chain and compare
    with what the PM chain committed to.  True if anything differs."""
    for b in pm_chain.chain:
        a = b.proof.get("anchors", {}).get(pm_id)
        if not a:
            continue
        blocks = rsu_chain.chain[a["first"]: a["last"] + 1]
        if merkle_root([blk.hash for blk in blocks]) != a["root"]:
            return True
        if any(blk.hash != blk.compute_hash() for blk in blocks):
            return True
    return False


# ------------------------------------------------------- allotment proofs
def _anchor_for(pm_chain: Blockchain, pm_id: str, rsu_index: int) -> tuple[Block, dict] | None:
    for pb in pm_chain.chain:
        a = pb.proof.get("anchors", {}).get(pm_id)
        if a and a["first"] <= rsu_index <= a["last"]:
            return pb, a
    return None


def build_allotment_proof(rsu_chain: Blockchain, pm_chain: Blockchain, pm_id: str, pid: str, pm_keys) -> dict | None:
    """Proof that ``pid`` was allotted on the RSU chain of ``pm_id`` and that
    the RSU block is anchored in the PM chain.  The newest *anchored*
    allotment is used.  The transaction stays encrypted; the verifier learns
    the pseudonym's inclusion, not the set."""
    for block in reversed(rsu_chain.chain):
        anchored = _anchor_for(pm_chain, pm_id, block.index)
        if anchored is None:
            continue
        for ti, tx in enumerate(block.transactions):
            if tx.kind != "allot" or pid not in tx.open(pm_keys).get("pids", []):
                continue
            pb, a = anchored
            tx_hashes = [t.hash() for t in block.transactions]
            leaves = [b.hash for b in rsu_chain.chain[a["first"]: a["last"] + 1]]
            return {
                "pid": pid, "pm_id": pm_id,
                "tx_hash": tx_hashes[ti], "tx_path": merkle_path(tx_hashes, ti),
                "rsu_header": block.header_fields(),
                "anchor_path": merkle_path(leaves, block.index - a["first"]),
                "anchor_root": a["root"], "pm_block_hash": pb.hash, "pm_block_index": pb.index,
            }
    return None


def verify_allotment_proof(proof: dict, pm_chain: Blockchain) -> bool:
    """Verify with nothing but the proof and the PM chain's block hashes."""
    try:
        hdr = dict(proof["rsu_header"])
        if not merkle_verify(proof["tx_hash"], [tuple(p) for p in proof["tx_path"]], hdr["tx_root"]):
            return False
        rsu_hash = Block.hash_of_fields(hdr)
        if not merkle_verify(rsu_hash, [tuple(p) for p in proof["anchor_path"]], proof["anchor_root"]):
            return False
        pb = pm_chain.chain[proof["pm_block_index"]]
        if pb.hash != proof["pm_block_hash"]:
            return False
        return pb.proof["anchors"][proof["pm_id"]]["root"] == proof["anchor_root"]
    except (KeyError, IndexError, TypeError):
        return False


def proof_size_bytes(proof: dict) -> int:
    return len(json.dumps(proof).encode())


def time_verify(proof: dict, pm_chain: Blockchain, repeats: int = 50) -> float:
    t0 = time.perf_counter()
    for _ in range(repeats):
        assert verify_allotment_proof(proof, pm_chain)
    return (time.perf_counter() - t0) / repeats
