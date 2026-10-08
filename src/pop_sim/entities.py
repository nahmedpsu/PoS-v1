"""Core components of the architecture (Section IV): PKI, Manufacturer,
Privacy Manager (PM), PM cloud, Road Side Unit (RSU) and Vehicle.

Hierarchy (Section IV-1): PKI at the top, PMs below it as miners of the
PM-level blockchain, RSUs third, vehicles at the bottom.  PKI is accessed only
twice: at initial registration and on revocation.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec

from . import clock, crypto
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
    holder_cert: dict | None = None   # rekey / window modes: PM-signed (pid, pk, window) for the holder
    cert_pk: str | None = None        # the key the PKI certificate covers (differs from keys under rekey)

    @property
    def certified_pk(self) -> str:
        return self.cert_pk or self.keys.pk_hex

    def credential_bytes(self) -> bytes:
        return json.dumps({"pid": self.pid, "pk": self.certified_pk, "expiry": self.expiry}, sort_keys=True).encode()

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
        return cls(d["pid"], KeyPair(sk, sk.public_key()), d["cert"], d["expiry"], d["issuer_pk"], d.get("holder"))

    def verify(self, pki_pk) -> bool:
        return crypto.verify(pki_pk, self.credential_bytes(), bytes.fromhex(self.cert))

    def cert_wire(self) -> dict:
        """The certificate a message carries (what ETSI / IEEE 1609.2 messages
        attach): no private key, plus the holder-bound certificate when the
        issuance mode uses one."""
        d = {"pid": self.pid, "pk": self.certified_pk, "expiry": self.expiry, "cert": self.cert,
             "issuer_pk": self.issuer_pk}
        if self.holder_cert is not None:
            d["holder"] = dict(self.holder_cert)
        return d


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
    """Cooperative Awareness Message signed with a pseudonym (Section IV-1).
    ``cred`` carries the pseudonym certificate for receivers that have no
    ledger (vehicle-to-vehicle); it is not part of the signed body."""

    pid: str
    position: tuple[float, float]
    speed: float
    direction: float
    timestamp: float
    signature: str = ""
    cred: dict | None = field(default=None, repr=False, compare=False)

    def wire_bytes(self) -> int:
        """Serialised size on air: body, signature and certificate."""
        return len(self.body()) + len(self.signature) // 2 + (len(json.dumps(self.cred)) if self.cred else 0)

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
        self.load = Load()                        # signatures / key generations / bytes done here

    # Algorithm 4, step 1-2 ------------------------------------------------
    def register_vehicle(self, index: int) -> VehicleCredential:
        self.accesses += 1
        keys = crypto.generate_keypair()
        self.load.keygens += 1
        perm_id = f"VEH-{index:05d}-{self.rng.getrandbits(32):08x}"
        cred = VehicleCredential(perm_id, keys, "")
        cred.cert = crypto.sign(self.keys.sk, cred.credential_bytes()).hex()
        self.load.signatures += 1
        self.registry[perm_id] = keys.pk_hex
        return cred

    # Algorithm 4, step 4 --------------------------------------------------
    def generate_pseudonyms(self, n: int) -> list[Pseudonym]:
        out = []
        for _ in range(n):
            self._pid_counter += 1
            keys = crypto.generate_keypair()
            self.load.keygens += 1
            pid = f"PID-{self.rng.getrandbits(48):012x}"
            p = Pseudonym(pid, keys, "", clock.now() + self.lifetime, self.keys.pk_hex)
            p.cert = crypto.sign(self.keys.sk, p.credential_bytes()).hex()
            self.load.signatures += 1
            self.issued_pids.add(pid)
            out.append(p)
        return out

    def certify(self, keypairs: list[KeyPair]) -> list[Pseudonym]:
        """SCMS-style issuance: the vehicle made the key pair, PKI only signs
        the certificate and never holds the private key."""
        out = []
        for keys in keypairs:
            self._pid_counter += 1
            pid = f"PID-{self.rng.getrandbits(48):012x}"
            p = Pseudonym(pid, keys, "", clock.now() + self.lifetime, self.keys.pk_hex)
            p.cert = crypto.sign(self.keys.sk, p.credential_bytes()).hex()
            self.load.signatures += 1
            self.issued_pids.add(pid)
            out.append(p)
        return out

    def renew(self, p: Pseudonym) -> None:
        """Re-certify a recycled pseudonym whose certificate is about to expire
        (same key, new expiry).  Counted as PKI work: recycling needs it."""
        p.expiry = clock.now() + self.lifetime
        p.cert = crypto.sign(self.keys.sk, p.credential_bytes()).hex()
        self.load.signatures += 1

    def certify_pm(self, pm_id: str, pm_pk_hex: str) -> str:
        """Certificate that lets a PM sign holder-bound pseudonym certificates."""
        self.load.signatures += 1
        return crypto.sign(self.keys.sk, f"pm:{pm_id}:{pm_pk_hex}".encode()).hex()

    def verify_pm_cert(self, pm_id: str, pm_pk_hex: str, cert: str) -> bool:
        return crypto.verify(self.keys.pk, f"pm:{pm_id}:{pm_pk_hex}".encode(), bytes.fromhex(cert))

    # Algorithm 4, step 6: {pid, cert, pk}_{pk(PM)}, signature_{sk(PKI)} --
    def package_for_pm(self, pm_pk, pseudonyms: list[Pseudonym]) -> tuple[bytes, bytes]:
        plaintext = json.dumps([p.to_wire() for p in pseudonyms]).encode()
        ciphertext = crypto.encrypt(pm_pk, plaintext)
        signature = crypto.sign(self.keys.sk, ciphertext)
        self.load.signatures += 1
        self.load.bytes += len(ciphertext)
        return ciphertext, signature

    # PoP v2: PKI binds a node's VRF key to its identity (Sybil resistance) --
    def certify_vrf_key(self, node_id: str, vrf_pk_hex: str) -> str:
        return crypto.sign(self.keys.sk, f"vrf:{node_id}:{vrf_pk_hex}".encode()).hex()

    def verify_vrf_cert(self, node_id: str, vrf_pk_hex: str, cert: str) -> bool:
        return crypto.verify(self.keys.pk, f"vrf:{node_id}:{vrf_pk_hex}".encode(), bytes.fromhex(cert))

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


@dataclass
class Load:
    """Work done by one entity: what recycling claims to save at the PKI."""

    signatures: int = 0
    keygens: int = 0
    bytes: int = 0
    verifications: int = 0

    def to_dict(self) -> dict:
        return {"signatures": self.signatures, "keygens": self.keygens, "bytes": self.bytes,
                "verifications": self.verifications}


def holder_cert_bytes(pid: str, pk_hex: str, t_start: float, t_end: float, pm_id: str) -> bytes:
    return json.dumps({"pid": pid, "pk": pk_hex, "t_start": t_start, "t_end": t_end, "pm": pm_id},
                      sort_keys=True).encode()


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
        self.retired: set[str] = set()        # never to be allotted again (fresh issuance modes)
        self.past_holders: dict[str, set[str]] = {}
        self.last_seen: dict[str, tuple[float, float]] = {}   # pid -> (x, t) of the last accepted message
        self.ring_length: float | None = None                  # road length when positions wrap around
        self.holder_cert: dict[str, dict] = {}                 # pid -> current holder-bound certificate (rekey/window)
        self.epoch: dict[str, int] = {}                        # pid -> number of allotments so far

    def allot(self, p: "Pseudonym", vehicle_id: str) -> None:
        self.holder[p.pid] = vehicle_id
        self.pk[p.pid] = p.keys.pk_hex
        self.used.discard(p.pid)
        self.last_seen.pop(p.pid, None)
        self.epoch[p.pid] = self.epoch.get(p.pid, 0) + 1
        if p.holder_cert is not None:
            self.holder_cert[p.pid] = p.holder_cert
        else:
            self.holder_cert.pop(p.pid, None)
        self.past_holders.setdefault(p.pid, set()).add(vehicle_id)

    def held_before(self, pid: str, vehicle_id: str) -> bool:
        return vehicle_id in self.past_holders.get(pid, ())

    def mark_used(self, pid: str) -> None:
        self.holder.pop(pid, None)
        self.used.add(pid)

    def retire(self, pid: str) -> None:
        self.holder.pop(pid, None)
        self.used.discard(pid)
        self.retired.add(pid)

    MAX_SPEED = 60.0          # m/s plausibility bound for the clone check

    def check(self, pid: str, vehicle_id: str, msg: "SafetyMessage") -> tuple[bool, str]:
        """Return (ok, reason) for a safety message carrying ``pid``."""
        if pid in self.retired:
            return False, "retired-pseudonym"
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
        # Clone check: one pseudonym cannot be in two places at once.
        last = self.last_seen.get(pid)
        if last is not None:
            dt = max(1e-6, msg.timestamp - last[1])
            dx = abs(msg.position[0] - last[0])
            if self.ring_length:
                dx = min(dx, self.ring_length - dx)
            if dx > self.MAX_SPEED * dt + 25.0:
                return False, "pseudonym-cloned"
        self.last_seen[pid] = (msg.position[0], msg.timestamp)
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
        self.kept_keys: list[Pseudonym] = []           # a dishonest OBU keeps every credential it held
        self.former_holder = False                     # recycling study: acts as the A2 adversary
        self.current: Pseudonym | None = None          # mobility mode: pseudonym in use for beacons
        self.changes = 0
        self.load = Load()

    @property
    def vehicle_id(self) -> str:
        return self.credential.permanent_id if self.credential else f"VEH-{self.index}"

    @property
    def _kept_copy(self) -> "Pseudonym | None":
        return self.kept_keys[0] if self.kept_keys else None

    @_kept_copy.setter
    def _kept_copy(self, p: "Pseudonym | None") -> None:
        if p is not None and p not in self.kept_keys:
            self.kept_keys.insert(0, p)

    def _keep(self, p: "Pseudonym") -> None:
        if (self.malicious or self.former_holder) and all(k.pid != p.pid for k in self.kept_keys):
            self.kept_keys.append(p)

    def receive_pseudonyms(self, pseudonyms: list[Pseudonym]) -> None:
        self.pseudonyms = list(pseudonyms)

    def broadcast(self) -> SafetyMessage | None:
        """Sign a safety message with the current pseudonym and rotate it."""
        if not self.pseudonyms:
            return None
        p = self.pseudonyms.pop(0)
        self.position = (self.position[0] + self.speed, self.position[1])
        msg = SafetyMessage(p.pid, self.position, self.speed, self.direction, clock.now())
        msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
        msg.cred = p.cert_wire()
        self.load.signatures += 1
        self.used.append(p)
        self.history.append(p.pid)
        self._keep(p)
        return msg

    def switch_pseudonym(self) -> Pseudonym | None:
        """Mobility mode: retire the current pseudonym and take the next one."""
        if self.current is not None:
            self.used.append(self.current)
            self.history.append(self.current.pid)
            self._keep(self.current)
            self.current = None
        if self.pseudonyms:
            self.current = self.pseudonyms.pop(0)
            self.changes += 1
        return self.current

    def beacon(self, x: float, v: float, direction: int, t: float | None = None) -> SafetyMessage | None:
        """Mobility mode: sign a CAM with the current pseudonym (no rotation).
        ``t`` is the simulated time stamped into the message."""
        if self.current is None:
            return None
        self.position = (x, 0.0)
        self.speed = v
        self.direction = float(direction)
        msg = SafetyMessage(self.current.pid, self.position, v, float(direction), clock.now() if t is None else t)
        msg.signature = crypto.sign(self.current.keys.sk, msg.body()).hex()
        msg.cred = self.current.cert_wire()
        self.load.signatures += 1
        self.load.bytes += msg.wire_bytes()
        return msg

    def replay_used(self) -> SafetyMessage | None:
        """Internal Tricking Adversary behaviour: re-use a pseudonym that was
        already returned to the RSU, signing with the copy of its key the
        compromised OBU kept."""
        p = self._kept_copy
        if p is None:
            return None
        msg = SafetyMessage(p.pid, self.position, self.speed, self.direction, clock.now())
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
        self.forecast: float | None = None
        self.safety_stock: float = 0.0
        self.stockouts = 0                            # vehicles that got fewer sets than needed
        self.rejected_uncertified = 0                 # allotment requests without a valid certificate
        self.attribution = "oracle"                   # "oracle" | "ledger"
        self.load = Load()
        self.allot_log: list[tuple[str, str]] = []    # (pid, vehicle) this RSU handed out: insider evidence

    def active_vehicles(self) -> int:
        return sum(1 for v in self.vehicles if not v.revoked)

    def demand(self, per_vehicle: int) -> int:
        """Traffic need reported to the PM: active vehicles under coverage,
        or the forecast when one is maintained (mobility mode)."""
        if self.forecast is not None:
            return int(math.ceil(self.forecast * (1 + self.safety_stock))) * per_vehicle
        return self.active_vehicles() * per_vehicle

    def update_forecast(self, alpha: float, safety_stock: float) -> None:
        """Exponential moving average of the vehicles seen under coverage."""
        n = self.active_vehicles()
        self.forecast = n if self.forecast is None else alpha * n + (1 - alpha) * self.forecast
        self.safety_stock = safety_stock

    def receive_sets(self, pseudonyms: list[Pseudonym]) -> None:
        self.shuffled_sets.extend(pseudonyms)

    def distribute(self, per_vehicle: int, avoid_previous: bool = True, attempts: int = 25, pki: "PKI | None" = None) -> int:
        """Assign pseudonyms to vehicles under coverage; returns number assigned.

        With ``avoid_previous`` the RSU looks for an assignment in which no
        vehicle receives a pseudonym it has already used (so the shuffle never
        hands an identity back to its earlier owner).  The assignment is found
        by greedy allotment over up to ``attempts`` random orderings of the
        set; the ordering with the fewest violations is used."""
        active = [v for v in self.vehicles if not v.revoked]
        if pki is not None:                       # PoP v2: a set is handed only to a certified vehicle
            checked = []
            for v in active:
                c = v.credential
                if c is None or pki.is_revoked(c.cert) or \
                        not crypto.verify(pki.keys.pk, c.credential_bytes(), bytes.fromhex(c.cert)):
                    self.rejected_uncertified += 1
                    continue
                checked.append(v)
            active = checked
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
            if len(take) < per_vehicle:
                self.stockouts += 1
            if not take:
                continue
            v.receive_pseudonyms(take)
            for p in take:
                self.ledger.allot(p, v.vehicle_id)
                self.allot_log.append((p.pid, v.vehicle_id))
            assigned += len(take)
        return assigned

    def receive_message(self, vehicle: Vehicle | None, msg: SafetyMessage) -> bool:
        """Verify a safety message; detect reuse of a pseudonym already recorded as used.

        ``attribution="oracle"`` (v2.2.1 behaviour) lets the RSU know the true
        sender.  ``attribution="ledger"`` is what a real RSU can do: it sees
        only the pseudonym and attributes the message to the ledger's current
        holder, so a misbehaviour report names that holder, whoever sent it."""
        self.observed.append(msg)
        self.load.verifications += 1
        if self.attribution == "ledger" or vehicle is None:
            holder = self.ledger.holder.get(msg.pid)
            ok, reason = self.ledger.check(msg.pid, holder or "", msg)
            if not ok:
                self.flagged.append((msg.pid, reason))
                # an unsigned or wrongly signed message cannot be attributed to anyone
                if holder and reason != "bad-signature":
                    self.pm.report_misbehaviour(holder, msg.pid, self.rsu_id, reason)
            return ok
        ok, reason = self.ledger.check(msg.pid, vehicle.vehicle_id, msg)
        if not ok:
            self.flagged.append((msg.pid, reason))
            if reason != "bad-signature":
                self.pm.report_misbehaviour(vehicle.vehicle_id, msg.pid, self.rsu_id, reason)
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
        self.load = Load()
        self.pm_cert = ""                            # PKI certificate for signing holder certs
        self.upload_log: list[list[str]] = []        # pid order of every upload to the cloud (insider evidence)
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

    def upload_to_cloud(self, shuffle_first: bool = False) -> int:
        ps = [p for p, _ in self.collected]
        if shuffle_first:
            self.rng.shuffle(ps)
        self.upload_log.append([p.pid for p in ps])
        self.cloud.upload(self.pm_id, ps)
        self.collected = []
        return len(ps)

    def report_misbehaviour(self, vehicle, pid: str, rsu_id: str, reason: str) -> None:
        vid = vehicle if isinstance(vehicle, str) else vehicle.vehicle_id
        self.misbehaviour_reports.append({"vehicle": vid, "pid": pid, "rsu": rsu_id, "reason": reason})

    def sign_holder_cert(self, pid: str, pk_hex: str, t_start: float, t_end: float) -> dict:
        """Holder-bound certificate (rekey / window modes): binds ``pid`` to
        ``pk_hex`` for one holder's validity window, signed by this PM."""
        sig = crypto.sign(self.keys.sk, holder_cert_bytes(pid, pk_hex, t_start, t_end, self.pm_id)).hex()
        self.load.signatures += 1
        return {"pid": pid, "pk": pk_hex, "t_start": t_start, "t_end": t_end, "pm": self.pm_id,
                "pm_pk": self.keys.pk_hex, "pm_cert": self.pm_cert, "sig": sig}

    def make_tx(self, kind: str, receiver_pk, payload: dict) -> Transaction:
        self.load.signatures += 1
        return Transaction.create(kind, self.keys, receiver_pk, payload)
