"""Vehicle-to-vehicle receivers: what standard V2X stations check.

An RSU in this simulator checks every message against the ledger.  A vehicle
receiving a Cooperative Awareness Message has no ledger: it checks the
pseudonym certificate (PKI signature, expiry), the message signature, and
optionally a local plausibility rule.  Nothing else.  That is the receiver a
former holder of a recycled pseudonym has to fool, and it is the receiver
that decides whether a forged braking warning is believed.

Cryptographic validity is the same for every receiver, so it is computed once
per message and cached; only the plausibility state is per receiver.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import crypto

MAX_SPEED = 60.0


@dataclass
class ReceiverState:
    last_seen: dict[str, tuple[float, float]] = field(default_factory=dict)   # pid -> (x, t)


@dataclass
class V2VStats:
    received: int = 0                 # (message, receiver) pairs
    accepted: int = 0
    messages: int = 0
    messages_accepted_by_any: int = 0
    rejected: dict[str, int] = field(default_factory=dict)
    forged_received: int = 0
    forged_accepted: int = 0
    forged_messages: int = 0
    forged_messages_accepted_by_any: int = 0
    accepted_forged_by_pid: dict[str, list[float]] = field(default_factory=dict)
    verifications: int = 0

    def to_dict(self) -> dict:
        return {"received": self.received, "accepted": self.accepted, "messages": self.messages,
                "messages_accepted_by_any": self.messages_accepted_by_any, "rejected": dict(self.rejected),
                "forged_received": self.forged_received, "forged_accepted": self.forged_accepted,
                "forged_messages": self.forged_messages,
                "forged_messages_accepted_by_any": self.forged_messages_accepted_by_any,
                "verifications": self.verifications}


class V2VLayer:
    """``mode="pki"``: a PKI pseudonym certificate is enough (recycle, fresh,
    fresh_vgk).  ``mode="holder"``: the message must also carry a holder-bound
    certificate from a PKI-certified PM whose window contains ``now`` and
    whose key signed the message (window and rekey modes)."""

    def __init__(self, pki_pk, ring_length: float, range_m: float = 300.0, plausibility: bool = False,
                 mode: str = "pki", freshness: float = 2.0, pm_cert_check=None):
        self.pki_pk = pki_pk
        self.ring_length = ring_length
        self.range_m = range_m
        self.plausibility = plausibility
        self.mode = mode
        self.freshness = freshness
        self.pm_cert_check = pm_cert_check       # callable(pm_id, pm_pk_hex, cert) -> bool
        self.receivers: dict[int, ReceiverState] = {}
        self.stats = V2VStats()
        self._cache: dict[str, tuple[bool, str]] = {}

    # -- geometry
    def _dist(self, a: float, b: float) -> float:
        d = abs(a - b) % self.ring_length
        return min(d, self.ring_length - d)

    def neighbours(self, x: float, positions: dict[int, float], exclude: int | None = None) -> list[int]:
        return [vid for vid, px in positions.items() if vid != exclude and self._dist(x, px) <= self.range_m]

    # -- cryptographic validity (cached per message)
    def verify(self, msg, now: float) -> tuple[bool, str]:
        key = crypto.sha256_hex(msg.body() + msg.signature.encode())
        if key in self._cache:
            return self._cache[key]
        res = self._verify(msg, now)
        self._cache[key] = res
        return res

    def _verify(self, msg, now: float) -> tuple[bool, str]:
        cred = msg.cred
        if not cred:
            return False, "no-certificate"
        self.stats.verifications += 1
        if cred.get("pid") != msg.pid:
            return False, "certificate-pid-mismatch"
        if now > cred.get("expiry", 0):
            return False, "certificate-expired"
        try:
            pk = crypto.pk_from_hex(cred["pk"])
            data = __import__("json").dumps({"pid": cred["pid"], "pk": cred["pk"], "expiry": cred["expiry"]},
                                            sort_keys=True).encode()
            if not crypto.verify(self.pki_pk, data, bytes.fromhex(cred["cert"])):
                return False, "certificate-invalid"
            sign_pk = pk
            if self.mode == "holder":
                h = cred.get("holder")
                if not h:
                    return False, "no-holder-certificate"
                if not (h["t_start"] <= now <= h["t_end"]):
                    return False, "holder-window"
                if h["pid"] != msg.pid:
                    return False, "holder-pid-mismatch"
                if self.pm_cert_check is None or not self.pm_cert_check(h["pm"], h["pm_pk"], h["pm_cert"]):
                    return False, "pm-certificate-invalid"
                from ..entities import holder_cert_bytes
                if not crypto.verify(crypto.pk_from_hex(h["pm_pk"]),
                                     holder_cert_bytes(h["pid"], h["pk"], h["t_start"], h["t_end"], h["pm"]),
                                     bytes.fromhex(h["sig"])):
                    return False, "holder-certificate-invalid"
                sign_pk = crypto.pk_from_hex(h["pk"])
            if abs(now - msg.timestamp) > self.freshness:
                return False, "stale"
            if not crypto.verify(sign_pk, msg.body(), bytes.fromhex(msg.signature)):
                return False, "bad-signature"
        except (KeyError, ValueError):
            return False, "malformed"
        return True, "ok"

    # -- delivery
    def deliver(self, msg, sender_x: float, positions: dict[int, float], now: float, forged: bool = False,
                exclude: int | None = None) -> tuple[int, int]:
        """Deliver ``msg`` from a sender physically at ``sender_x`` to every
        vehicle in range.  Returns (accepting receivers, receivers in range)."""
        rx = self.neighbours(sender_x, positions, exclude)
        ok, reason = self.verify(msg, now)
        accepted = 0
        self.stats.messages += 1
        if forged:
            self.stats.forged_messages += 1
        for vid in rx:
            st = self.receivers.setdefault(vid, ReceiverState())
            self.stats.received += 1
            if forged:
                self.stats.forged_received += 1
            r_ok, r_reason = ok, reason
            if r_ok and self.plausibility:
                last = st.last_seen.get(msg.pid)
                if last is not None:
                    dt = max(1e-6, msg.timestamp - last[1])
                    if self._dist(msg.position[0], last[0]) > MAX_SPEED * dt + 25.0:
                        r_ok, r_reason = False, "implausible"
            if r_ok:
                st.last_seen[msg.pid] = (msg.position[0], msg.timestamp)
                accepted += 1
                self.stats.accepted += 1
                if forged:
                    self.stats.forged_accepted += 1
            else:
                self.stats.rejected[r_reason] = self.stats.rejected.get(r_reason, 0) + 1
        if accepted:
            self.stats.messages_accepted_by_any += 1
            if forged:
                self.stats.forged_messages_accepted_by_any += 1
                self.stats.accepted_forged_by_pid.setdefault(msg.pid, []).append(now)
        return accepted, len(rx)
