"""Core components of the architecture (Section IV): PKI, Manufacturer,
Privacy Manager (PM), PM cloud, Road Side Unit (RSU) and Vehicle.

Hierarchy (Section IV-1): PKI at the top, PMs below it as miners of the
PM-level blockchain, RSUs third, vehicles at the bottom.  PKI is accessed only
twice: at initial registration and on revocation.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from . import crypto
from .blockchain import Blockchain, Transaction
from .crypto import KeyPair


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------
@dataclass
class Pseudonym:
    """``PID_i`` together with its certificate and key pair (Algorithm 4, step 4)."""

    pid: str
    keys: KeyPair
    cert: str                 # PKI signature over (pid, pk, expiry), hex
    expiry: float
    issuer_pk: str

    def credential_bytes(self) -> bytes:
        return json.dumps({"pid": self.pid, "pk": self.keys.pk_hex, "expiry": self.expiry}, sort_keys=True).encode()

    def to_wire(self) -> dict:
        """Serialisable form used inside encrypted PKI -> PM packages."""
        return {
            "pid": self.pid,
            "pk": self.keys.pk_hex,
            "sk": format(self.keys.sk.private_numbers().private_value, "x"),
            "cert": self.cert,
            "expiry": self.expiry,
            "issuer_pk": self.issuer_pk,
        }

    @classmethod
    def from_wire(cls, d: dict) -> "Pseudonym":
        sk = ec.derive_private_key(int(d["sk"], 16), crypto.CURVE)
        return cls(d["pid"], KeyPair(sk, sk.public_key()), d["cert"], d["expiry"], d["issuer_pk"])

    def verify(self, pki_pk) -> bool:
        return crypto.verify(pki_pk, self.credential_bytes(), bytes.fromhex(self.cert))


@dataclass
class VehicleCredential:
    """Permanent identity issued by PKI through the manufacturer (steps 1-3)."""

    permanent_id: str
    keys: KeyPair
    cert: str

    def credential_bytes(self) -> bytes:
        return json.dumps({"id": self.permanent_id, "pk": self.keys.pk_hex}, sort_keys=True).encode()


@dataclass
class SafetyMessage:
    """Cooperative Awareness Message signed with a pseudonym (Section IV-1)."""

    pid: str
    position: tuple[float, float]
    speed: float
    direction: float
    timestamp: float
    signature: str = ""

    def body(self) -> bytes:
        return json.dumps(
            {"pid": self.pid, "position": self.position, "speed": self.speed,
             "direction": self.direction, "timestamp": self.timestamp}, sort_keys=True).encode()


# --------------------------------------------------------------------------
# PKI and manufacturer
# --------------------------------------------------------------------------
class PKI:
    """Certificate Authority: issues permanent ids, pseudonym sets and the CRL."""

    def __init__(self, rng: random.Random, pseudonym_lifetime: float = 3600.0):
        self.rng = rng
        self.keys = crypto.generate_keypair()
        self.lifetime = pseudonym_lifetime
        self.registry: dict[str, str] = {}        # permanent_id -> pk
        self.crl: set[str] = set()                # revoked certificates
        self.issued_pids: set[str] = set()
        self.accesses = 0                         # paper: PKI accessed only twice
        self._pid_counter = 0

    # Algorithm 4, step 1-2 ------------------------------------------------
    def register_vehicle(self, index: int) -> VehicleCredential:
        self.accesses += 1
        keys = crypto.generate_keypair()
        perm_id = f"VEH-{index:05d}-{self.rng.getrandbits(32):08x}"
        cred = VehicleCredential(perm_id, keys, "")
        cred.cert = crypto.sign(self.keys.sk, cred.credential_bytes()).hex()
        self.registry[perm_id] = keys.pk_hex
        return cred

    # Algorithm 4, step 4 --------------------------------------------------
    def generate_pseudonyms(self, n: int) -> list[Pseudonym]:
        out = []
        for _ in range(n):
            self._pid_counter += 1
            keys = crypto.generate_keypair()
            pid = f"PID-{self.rng.getrandbits(48):012x}"
            p = Pseudonym(pid, keys, "", time.time() + self.lifetime, self.keys.pk_hex)
            p.cert = crypto.sign(self.keys.sk, p.credential_bytes()).hex()
            self.issued_pids.add(pid)
            out.append(p)
        return out

    # Algorithm 4, step 6: {pid, cert, pk}_{pk(PM)}, signature_{sk(PKI)} --
    def package_for_pm(self, pm_pk, pseudonyms: list[Pseudonym]) -> tuple[bytes, bytes]:
        plaintext = json.dumps([p.to_wire() for p in pseudonyms]).encode()
        ciphertext = crypto.encrypt(pm_pk, plaintext)
        signature = crypto.sign(self.keys.sk, ciphertext)
        return ciphertext, signature

    # Revocation (second and last PKI access in the vehicle lifecycle) ----
    def revoke(self, cert: str) -> None:
        self.accesses += 1
        self.crl.add(cert)

    def is_revoked(self, cert: str) -> bool:
        return cert in self.crl


class Manufacturer:
    """Algorithm 4, step 3: installs ``pid_i, cert_i, pk_i, sk_i`` in the OBU."""

    def __init__(self, pki: PKI):
        self.pki = pki

    def provision(self, vehicle: "Vehicle") -> None:
        vehicle.credential = self.pki.register_vehicle(vehicle.index)


# --------------------------------------------------------------------------
# Pseudonym ledger (materialised view of the RSU-level blockchain)
# --------------------------------------------------------------------------
class PseudonymLedger:
    """State of every pseudonym as recorded by the ``allot`` and ``used``
    transactions of the RSU blockchains: who currently holds it, or that it
    has been returned and is waiting to be shuffled.  "The pseudonyms in the
    sets are tracked by the blockchain and any vehicle using the same used
    sets is identified and reported to PM" (Section IV-2)."""

    def __init__(self):
        self.holder: dict[str, str] = {}      # pid -> vehicle currently allotted
        self.pk: dict[str, str] = {}          # pid -> public key (from the certificate)
        self.used: set[str] = set()           # returned, not yet re-allotted
        self.past_holders: dict[str, set[str]] = {}

    def allot(self, p: "Pseudonym", vehicle_id: str) -> None:
        self.holder[p.pid] = vehicle_id
        self.pk[p.pid] = p.keys.pk_hex
        self.used.discard(p.pid)
        self.past_holders.setdefault(p.pid, set()).add(vehicle_id)

    def held_before(self, pid: str, vehicle_id: str) -> bool:
        return vehicle_id in self.past_holders.get(pid, ())

    def mark_used(self, pid: str) -> None:
        self.holder.pop(pid, None)
        self.used.add(pid)

    def check(self, pid: str, vehicle_id: str, msg: "SafetyMessage") -> tuple[bool, str]:
        """Return (ok, reason) for a safety message carrying ``pid``."""
        if pid in self.used:
            return False, "reuse-of-returned-pseudonym"
        holder = self.holder.get(pid)
        if holder is None:
            return False, "unknown-pseudonym"
        if holder != vehicle_id:
            return False, "pseudonym-held-by-another-vehicle"
        if not msg.signature or not crypto.verify(crypto.pk_from_hex(self.pk[pid]), msg.body(),
                                                  bytes.fromhex(msg.signature)):
            return False, "bad-signature"
        return True, "ok"


# --------------------------------------------------------------------------
# Vehicle
# --------------------------------------------------------------------------
class Vehicle:
    def __init__(self, index: int, rng: random.Random):
        self.index = index
        self.rng = rng
        self.credential: VehicleCredential | None = None
        self.pseudonyms: list[Pseudonym] = []          # fresh set from the RSU
        self.used: list[Pseudonym] = []                # used, awaiting return
        self.position = (rng.uniform(0, 1000), rng.uniform(0, 1000))
        self.speed = rng.uniform(0, 30)
        self.direction = rng.uniform(0, 360)
        self.history: list[str] = []                   # pids actually used (for linkability analysis)
        self.malicious = False
        self.revoked = False
        self._kept_copy: Pseudonym | None = None       # a malicious OBU keeps a used credential

    @property
    def vehicle_id(self) -> str:
        return self.credential.permanent_id if self.credential else f"VEH-{self.index}"

    def receive_pseudonyms(self, pseudonyms: list[Pseudonym]) -> None:
        self.pseudonyms = list(pseudonyms)

    def broadcast(self) -> SafetyMessage | None:
        """Sign a safety message with the current pseudonym and rotate it."""
        if not self.pseudonyms:
            return None
        p = self.pseudonyms.pop(0)
        self.position = (self.position[0] + self.speed, self.position[1])
        msg = SafetyMessage(p.pid, self.position, self.speed, self.direction, time.time())
        msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
        self.used.append(p)
        self.history.append(p.pid)
        if self.malicious and self._kept_copy is None:
            self._kept_copy = p
        return msg

    def replay_used(self) -> SafetyMessage | None:
        """Internal Tricking Adversary behaviour: re-use a pseudonym that was
        already returned to the RSU, signing with the copy of its key the
        compromised OBU kept."""
        p = self._kept_copy
        if p is None:
            return None
        msg = SafetyMessage(p.pid, self.position, self.speed, self.direction, time.time())
        msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
        return msg

    def return_used(self) -> list[Pseudonym]:
        """Vehicles return used/expired pseudonyms to the RSU (Alg. 4 bullet 6)."""
        out, self.used = self.used, []
        return out


# --------------------------------------------------------------------------
# RSU
# --------------------------------------------------------------------------
class RSU:
    """Road Side Unit: distributes shuffled sets, collects used ones, keeps the
    local RSU-level blockchain (Section IV-2 and Algorithm 5)."""

    def __init__(self, rsu_id: str, pm: "PrivacyManager", rng: random.Random):
        self.rsu_id = rsu_id
        self.pm = pm
        self.rng = rng
        self.keys = crypto.generate_keypair()
        self.vehicles: list[Vehicle] = []
        self.shuffled_sets: list[Pseudonym] = []      # received from the PM
        self.used: list[tuple[Pseudonym, dict]] = []  # used pseudonyms with vehicle status
        self.ledger = pm.ledger                       # view of the RSU-level blockchain
        self.observed: list[SafetyMessage] = []
        self.flagged: list[tuple[str, str]] = []

    def demand(self, per_vehicle: int) -> int:
        """Traffic need reported to the PM: active vehicles under coverage."""
        return sum(1 for v in self.vehicles if not v.revoked) * per_vehicle

    def receive_sets(self, pseudonyms: list[Pseudonym]) -> None:
        self.shuffled_sets.extend(pseudonyms)

    def distribute(self, per_vehicle: int, avoid_previous: bool = True, attempts: int = 25) -> int:
        """Assign pseudonyms to vehicles under coverage; returns number assigned.

        With ``avoid_previous`` the RSU looks for an assignment in which no
        vehicle receives a pseudonym it has already used (so the shuffle never
        hands an identity back to its earlier owner).  The assignment is found
        by greedy allotment over up to ``attempts`` random orderings of the
        set; the ordering with the fewest violations is used."""
        active = [v for v in self.vehicles if not v.revoked]
        if not active or not self.shuffled_sets:
            return 0
        best = None
        for _ in range(attempts if avoid_previous else 1):
            pool = list(self.shuffled_sets)
            if avoid_previous:
                self.rng.shuffle(pool)
            plan: dict[int, list[Pseudonym]] = {}
            violations = 0
            for v in active:
                take: list[Pseudonym] = []
                rest: list[Pseudonym] = []
                for p in pool:
                    if len(take) < per_vehicle and not (avoid_previous and self.ledger.held_before(p.pid, v.vehicle_id)):
                        take.append(p)
                    else:
                        rest.append(p)
                if len(take) < per_vehicle:               # fall back to any remaining set
                    extra = rest[: per_vehicle - len(take)]
                    violations += sum(self.ledger.held_before(p.pid, v.vehicle_id) for p in extra)
                    take += extra
                    rest = rest[len(extra):]
                plan[v.index] = take
                pool = rest
            if best is None or violations < best[0]:
                best = (violations, plan, pool)
            if violations == 0:
                break
        _, plan, leftover = best
        self.shuffled_sets = leftover
        assigned = 0
        for v in active:
            take = plan.get(v.index, [])
            if not take:
                continue
            v.receive_pseudonyms(take)
            for p in take:
                self.ledger.allot(p, v.vehicle_id)
            assigned += len(take)
        return assigned

    def receive_message(self, vehicle: Vehicle, msg: SafetyMessage) -> bool:
        """Verify a safety message; detect reuse of a pseudonym already recorded as used."""
        self.observed.append(msg)
        ok, reason = self.ledger.check(msg.pid, vehicle.vehicle_id, msg)
        if not ok:
            self.flagged.append((msg.pid, reason))
            self.pm.report_misbehaviour(vehicle, msg.pid, self.rsu_id, reason)
        return ok

    def collect_used(self) -> int:
        """Collect used pseudonyms along with vehicle status (Alg. 5, line 7)."""
        n = 0
        for v in self.vehicles:
            for p in v.return_used():
                status = {"position": v.position, "speed": v.speed, "direction": v.direction}
                self.used.append((p, status))
                self.ledger.mark_used(p.pid)
                n += 1
        return n

    def package_used(self) -> list[tuple[Pseudonym, dict]]:
        out, self.used = self.used, []
        return out


# --------------------------------------------------------------------------
# Privacy Manager and PM cloud
# --------------------------------------------------------------------------
class PMCloud:
    """Cloud used by the PMs to hold and shuffle the collected pseudonym sets."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.store: list[tuple[str, Pseudonym]] = []     # (origin PM, pseudonym)

    def upload(self, pm_id: str, pseudonyms: list[Pseudonym]) -> None:
        self.store.extend((pm_id, p) for p in pseudonyms)

    def total(self) -> int:
        return len(self.store)

    def shuffle_and_relocate(self, demands: dict[str, int], seed: int | None = None
                             ) -> dict[str, list[tuple[str, Pseudonym]]]:
        """Algorithm 4, line 16: shuffle all collected PID sets and relocate them
        to destination PMs according to the traffic need each PM reported.
        Returns ``{destination PM: [(origin PM, pseudonym), ...]}``."""
        rng = random.Random(seed) if seed is not None else self.rng
        pool = list(self.store)
        rng.shuffle(pool)
        self.store = []
        out: dict[str, list[tuple[str, Pseudonym]]] = {pm: [] for pm in demands}
        total_demand = sum(demands.values()) or 1
        idx = 0
        for pm, need in demands.items():        # proportional allotment ...
            share = int(len(pool) * need / total_demand)
            out[pm] = pool[idx: idx + share]
            idx += share
        pms = list(demands)
        for i, item in enumerate(pool[idx:]):    # ... then round-robin remainder
            out[pms[i % len(pms)]].append(item)
        return out


class PrivacyManager:
    """PM: receives sets from PKI, serves its RSUs, collects used sets, shuffles
    them in the cloud and mines the PM-level blockchain."""

    def __init__(self, pm_id: str, cloud: PMCloud, rng: random.Random, ledger: PseudonymLedger | None = None):
        self.pm_id = pm_id
        self.cloud = cloud
        self.rng = rng
        self.keys = crypto.generate_keypair()
        self.rsus: list[RSU] = []
        self.pool: list[Pseudonym] = []              # fresh / shuffled sets
        self.collected: list[tuple[Pseudonym, dict]] = []
        self.ledger = ledger or PseudonymLedger()
        self.misbehaviour_reports: list[dict] = []
        self.rsu_chain = Blockchain(f"rsu-chain-{pm_id}")   # blockchain over RSU (Fig. 5)

    # Algorithm 4, step 6 (receiving side) --------------------------------
    def receive_from_pki(self, ciphertext: bytes, signature: bytes, pki_pk) -> int:
        if not crypto.verify(pki_pk, ciphertext, signature):
            raise ValueError(f"{self.pm_id}: PKI signature invalid, package rejected")
        wire = json.loads(crypto.decrypt(self.keys.sk, ciphertext))
        ps = [Pseudonym.from_wire(d) for d in wire]
        for p in ps:
            if not p.verify(pki_pk):
                raise ValueError(f"{self.pm_id}: pseudonym certificate invalid")
        self.pool.extend(ps)
        return len(ps)

    def demand(self, per_vehicle: int) -> int:
        return sum(r.demand(per_vehicle) for r in self.rsus)

    def net_demand(self, per_vehicle: int) -> int:
        """Demand not already covered by sets held at the PM or its RSUs."""
        stock = len(self.pool) + sum(len(r.shuffled_sets) for r in self.rsus)
        return max(0, self.demand(per_vehicle) - stock)

    # Algorithm 4, steps 8-9: PID broadcast to RSUs -------------------------
    def serve_rsus(self, per_vehicle: int) -> int:
        sent = 0
        for rsu in self.rsus:
            need = rsu.demand(per_vehicle) - len(rsu.shuffled_sets)
            if need <= 0:
                continue
            take, self.pool = self.pool[:need], self.pool[need:]
            rsu.receive_sets(take)
            sent += len(take)
        return sent

    # Algorithm 4, lines 12-14 --------------------------------------------
    def collect_from_rsus(self) -> int:
        n = 0
        for rsu in self.rsus:
            pkg = rsu.package_used()
            self.collected.extend(pkg)
            n += len(pkg)
        return n

    def upload_to_cloud(self) -> int:
        ps = [p for p, _ in self.collected]
        self.cloud.upload(self.pm_id, ps)
        self.collected = []
        return len(ps)

    def report_misbehaviour(self, vehicle: Vehicle, pid: str, rsu_id: str, reason: str) -> None:
        self.misbehaviour_reports.append(
            {"vehicle": vehicle.vehicle_id, "pid": pid, "rsu": rsu_id, "reason": reason})

    def make_tx(self, kind: str, receiver_pk, payload: dict) -> Transaction:
        return Transaction.create(kind, self.keys, receiver_pk, payload)
