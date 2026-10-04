"""A minimal private blockchain: signed, encrypted transactions linked by hash.

Each block "contains a hash of the preceding block" (Section I, feature 5) and
transactions carry the sender/receiver public keys, a timestamp, the payload
encrypted for the receiver and the sender's signature (Section IV-D).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from . import crypto


@dataclass
class Transaction:
    kind: str
    sender_pk: str
    receiver_pk: str
    timestamp: float
    ciphertext: str
    signature: str = ""

    def signing_bytes(self) -> bytes:
        return json.dumps(
            {
                "kind": self.kind,
                "sender_pk": self.sender_pk,
                "receiver_pk": self.receiver_pk,
                "timestamp": self.timestamp,
                "ciphertext": self.ciphertext,
            },
            sort_keys=True,
        ).encode()

    def hash(self) -> str:
        return crypto.sha256_hex(self.signing_bytes() + self.signature.encode())

    def verify_signature(self) -> bool:
        pk = crypto.pk_from_hex(self.sender_pk)
        return crypto.verify(pk, self.signing_bytes(), bytes.fromhex(self.signature))

    @classmethod
    def create(cls, kind: str, sender: crypto.KeyPair, receiver_pk, payload: dict) -> "Transaction":
        """Encrypt ``payload`` for ``receiver_pk`` and sign it with ``sender.sk``."""
        ct = crypto.encrypt(receiver_pk, json.dumps(payload, sort_keys=True).encode())
        tx = cls(
            kind=kind,
            sender_pk=sender.pk_hex,
            receiver_pk=crypto.pk_to_hex(receiver_pk),
            timestamp=time.time(),
            ciphertext=ct.hex(),
        )
        tx.signature = crypto.sign(sender.sk, tx.signing_bytes()).hex()
        return tx

    def open(self, receiver: crypto.KeyPair) -> dict:
        return json.loads(crypto.decrypt(receiver.sk, bytes.fromhex(self.ciphertext)))


@dataclass
class Block:
    index: int
    previous_hash: str
    timestamp: float
    transactions: list[Transaction]
    miner: str
    consensus: str
    proof: dict = field(default_factory=dict)
    nonce: int = 0
    hash: str = ""

    def tx_root(self) -> str:
        """Merkle root of the transaction hashes (see ``v2.anchoring``)."""
        from .v2.anchoring import merkle_root  # local import: anchoring imports this module

        return merkle_root([t.hash() for t in self.transactions])

    def header_fields(self) -> dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "tx_root": self.tx_root(),
            "tx_count": len(self.transactions),
            "miner": self.miner,
            "consensus": self.consensus,
            "proof": self.proof,
            "nonce": self.nonce,
        }

    @staticmethod
    def hash_of_fields(fields: dict) -> str:
        return crypto.sha256_hex(json.dumps(fields, sort_keys=True).encode())

    def header_bytes(self) -> bytes:
        return json.dumps(self.header_fields(), sort_keys=True).encode()

    def compute_hash(self) -> str:
        return crypto.sha256_hex(self.header_bytes())

    def seal(self) -> "Block":
        self.hash = self.compute_hash()
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class Blockchain:
    """Append-only chain with full validation (hash links and tx signatures)."""

    def __init__(self, name: str = "chain", validator=None):
        """``validator(block, chain) -> bool`` is consulted before a block is
        appended (e.g. to check the consensus proof names the block's miner)."""
        self.name = name
        self.validator = validator
        genesis = Block(0, "0" * 64, time.time(), [], miner="genesis", consensus="none").seal()
        self.chain: list[Block] = [genesis]

    @property
    def last(self) -> Block:
        return self.chain[-1]

    def __len__(self) -> int:
        return len(self.chain)

    def new_block(self, transactions: list[Transaction], miner: str, consensus: str, proof: dict | None = None) -> Block:
        return Block(
            index=len(self.chain),
            previous_hash=self.last.hash,
            timestamp=time.time(),
            transactions=list(transactions),
            miner=miner,
            consensus=consensus,
            proof=proof or {},
        )

    def add_block(self, block: Block) -> Block:
        if block.previous_hash != self.last.hash:
            raise ValueError("block does not link to the chain head")
        if block.index != len(self.chain):
            raise ValueError("bad block index")
        for tx in block.transactions:
            if not tx.verify_signature():
                raise ValueError("block contains a transaction with an invalid signature")
        if not block.hash:
            block.seal()
        elif block.hash != block.compute_hash():
            raise ValueError("block hash does not match its contents")
        if self.validator is not None and not self.validator(block, self):
            raise ValueError(f"block from {block.miner} rejected by consensus validation")
        self.chain.append(block)
        return block

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            cur, prev = self.chain[i], self.chain[i - 1]
            if cur.previous_hash != prev.hash:
                return False
            if cur.hash != cur.compute_hash():
                return False
            if any(not tx.verify_signature() for tx in cur.transactions):
                return False
        return True

    def transactions(self, kind: str | None = None):
        for b in self.chain:
            for tx in b.transactions:
                if kind is None or tx.kind == kind:
                    yield b, tx
