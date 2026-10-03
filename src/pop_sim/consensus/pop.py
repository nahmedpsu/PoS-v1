"""Algorithm 6 - Proof of Pseudonym consensus (the proposed protocol).

Section IV-3 describes PoP as a client/server protocol:

1. The server detects new client nodes N1..Nn connecting to it.
2. The server randomly decides the percentage of miners among the
   participants, not less than 50 percent (formula (1)):
   ``(N1 + N2 + ... + Nn) / Nx * threshold = i % nodes``.
3. The server randomly picks which nodes make up that percentage and informs
   only them; the other nodes are told nothing about the elected miners.
4. The elected miners reach consensus to publish a block; the server also
   sets the time limit.
5. Elected nodes generate a random short time.
6. The node with the shortest time wins and publishes the block.

Algorithm 6 phrases the same thing as a handshake: a client ``C_IP`` requests
the server (Step 1); the server checks ``Nn <= Nt`` and grants access while
the mining list is below the threshold (Step 4); a granted client is selected
for mining and generates its time (Step 3); a refused client finishes the
handshake (Step 5).  Only about half the nodes work per round, which is why
the paper gives the average complexity as O(n/2).
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass, field

from .. import crypto


@dataclass
class ClientNode:
    node_id: str
    ip: str
    selected: bool = False
    short_time: float | None = None


@dataclass
class PoPResult:
    nodes: int
    threshold_percent: int
    mining_list: list[str]
    winner: str
    winner_time: float
    times: dict[str, float] = field(default_factory=dict)
    cpu_seconds: float = 0.0
    time_limit: float = 0.0
    selection_seconds: float = 0.0   # steps 1-4: handshakes and random selection
    race_seconds: float = 0.0        # steps 5-6: random short times and comparison
    attestation: str = ""          # server signature over the election result
    server_pk: str = ""

    @property
    def miners(self) -> int:
        return len(self.mining_list)

    def proof(self) -> dict:
        """Election record to embed in the published block."""
        return {"threshold_percent": self.threshold_percent, "mining_list": self.mining_list,
                "winner": self.winner, "winner_time": self.winner_time,
                "attestation": self.attestation, "server_pk": self.server_pk}


def election_bytes(winner: str, mining_list: list[str], threshold_percent: int) -> bytes:
    return json.dumps({"winner": winner, "mining_list": sorted(mining_list),
                       "threshold_percent": threshold_percent}, sort_keys=True).encode()


def verify_election(proof: dict, expected_server_pk: str | None = None) -> bool:
    """Check that a block's PoP proof was issued by the server for its miner."""
    try:
        if expected_server_pk is not None and proof.get("server_pk") != expected_server_pk:
            return False
        if proof["winner"] not in proof["mining_list"]:
            return False
        pk = crypto.pk_from_hex(proof["server_pk"])
        data = election_bytes(proof["winner"], proof["mining_list"], proof["threshold_percent"])
        return crypto.verify(pk, data, bytes.fromhex(proof["attestation"]))
    except (KeyError, ValueError):
        return False


class PoPServer:
    """The cloud server that runs the Proof of Pseudonym election."""

    def __init__(self, port: int = 8000, min_threshold: int = 50, max_threshold: int = 50,
                 time_limit: float = 0.25, rng: random.Random | None = None):
        """``min_threshold``/``max_threshold`` bound the random percentage of
        miners.  The paper sets the percentage to 50 ("not less than 50
        percent"); pass ``max_threshold=100`` to let the server draw it
        anywhere in [50, 100]."""
        if not 0 < min_threshold <= max_threshold <= 100:
            raise ValueError("threshold bounds must satisfy 0 < min <= max <= 100")
        self.port = port
        self.min_threshold = min_threshold
        self.max_threshold = max_threshold
        self.time_limit = time_limit
        self.rng = rng or random.Random()
        self.keys = crypto.generate_keypair()
        self.clients: dict[str, ClientNode] = {}

    # Step 1 of Algorithm 6: the client handshakes with the server.
    def connect(self, node_id: str, ip: str | None = None) -> ClientNode:
        node = ClientNode(node_id, ip or f"10.0.{len(self.clients) // 250}.{len(self.clients) % 250 + 1}")
        self.clients[node_id] = node
        return node

    def decide_threshold(self) -> int:
        """Step 2: random percentage of miners, never below ``min_threshold``."""
        return self.rng.randint(self.min_threshold, self.max_threshold)

    @staticmethod
    def miners_for(nodes: int, threshold_percent: int) -> int:
        """Formula (1): number of miners = threshold % of the participating nodes."""
        return max(1, math.ceil(nodes * threshold_percent / 100))

    def elect(self, threshold_percent: int | None = None, real_wait: bool = False) -> PoPResult:
        """Run one PoP round over the currently connected clients."""
        if not self.clients:
            raise ValueError("no client nodes connected")
        t0 = time.perf_counter()
        nt = threshold_percent if threshold_percent is not None else self.decide_threshold()
        nn = len(self.clients)
        quota = self.miners_for(nn, nt)

        # Step 3/4: the server randomly grants access while Nn <= Nt.
        mining_list: list[str] = []
        order = list(self.clients)
        self.rng.shuffle(order)
        for nid in order:
            node = self.clients[nid]
            if len(mining_list) < quota:         # Nn <= Nt -> access granted
                node.selected = True
                mining_list.append(nid)
            else:                                # Step 5: finish handshake
                node.selected = False
                node.short_time = None

        t1 = time.perf_counter()
        # Step 5/6: selected nodes generate random short times; shortest wins.
        times: dict[str, float] = {}
        winner, smallest = mining_list[0], float("inf")
        for nid in mining_list:
            t = round(self.rng.uniform(0.01, self.time_limit), 2)
            self.clients[nid].short_time = t
            times[nid] = t
            if t < smallest:
                smallest, winner = t, nid
        t2 = time.perf_counter()
        if real_wait:
            time.sleep(smallest)
        attestation = crypto.sign(self.keys.sk, election_bytes(winner, mining_list, nt)).hex()
        return PoPResult(nn, nt, mining_list, winner, smallest, times,
                         time.perf_counter() - t0, self.time_limit, t1 - t0, t2 - t1,
                         attestation, self.keys.pk_hex)

    def disconnect_all(self) -> None:
        self.clients.clear()
