"""Vehicle-to-vehicle receivers: what standard V2X stations check.

An RSU in this simulator checks every message against the ledger.  A vehicle
receiving a Cooperative Awareness Message has no ledger: it checks the
pseudonym certificate (PKI signature, expiry), the message signature, and
optionally local plausibility detectors.  Nothing else.  That is the receiver
a former holder of a recycled pseudonym has to fool.

Caching (review R03): only immutable cryptographic work is cached, keyed by
everything it depends on (certificate fields and signature; holder-certificate
fields and signature; message body, signature and the verifying key).  The
time-dependent checks (certificate expiry, holder window, freshness) and the
match between message and certificate are redone on every delivery.

Plausibility detectors (review R09), applied per receiver when
``plausibility`` is on, by name in ``detectors``:

* ``ssc``  simple speed check: the claimed position may not move more than
           ``max_speed * dt + allowance_m`` from the last accepted message
           under the same pseudonym (the detector of versions up to 3.4);
* ``art``  acceptance range threshold: a claimed position farther than
           ``art_range_m`` from the receiver cannot have been heard directly;
* ``kin``  kinematic consistency: the claimed position must lie within
           ``kin_tolerance_m`` of the last accepted message dead-reckoned with
           its own claimed speed and heading (applied for gaps up to 5 s).

``loss`` drops each reception independently with that probability.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field

from .. import crypto

MAX_SPEED = 60.0
DETECTORS = ("ssc", "art", "kin")


@dataclass
class ReceiverState:
    last_seen: dict[str, tuple[float, float, float, float]] = field(default_factory=dict)   # pid -> (x, t, v, dir)


@dataclass
class V2VStats:
    received: int = 0                 # (message, receiver) pairs that reached the receiver
    lost: int = 0                     # (message, receiver) pairs dropped by the channel
    accepted: int = 0
    messages: int = 0
    messages_accepted_by_any: int = 0
    rejected: dict[str, int] = field(default_factory=dict)
    honest_received: int = 0
    honest_rejected_implausible: int = 0   # benign false positives of the detectors
    forged_received: int = 0
    forged_accepted: int = 0
    forged_messages: int = 0
    forged_messages_accepted_by_any: int = 0
    accepted_forged_by_pid: dict[str, list[float]] = field(default_factory=dict)
    verifications: int = 0            # signature verifications actually computed (cache misses)

    def to_dict(self) -> dict:
        return {"received": self.received, "lost": self.lost, "accepted": self.accepted, "messages": self.messages,
                "messages_accepted_by_any": self.messages_accepted_by_any, "rejected": dict(self.rejected),
                "honest_received": self.honest_received, "honest_rejected_implausible": self.honest_rejected_implausible,
                "honest_false_positive_rate": (self.honest_rejected_implausible / self.honest_received
                                               if self.honest_received else None),
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
                 mode: str = "pki", freshness: float = 2.0, pm_cert_check=None, detectors=("ssc",),
                 allowance_m: float = 25.0, max_speed: float = MAX_SPEED, art_range_m: float | None = None,
                 kin_tolerance_m: float = 10.0, loss: float = 0.0, seed: int = 0):
        unknown = set(detectors) - set(DETECTORS)
        if unknown:
            raise ValueError(f"unknown detectors {sorted(unknown)}; choose from {DETECTORS}")
        self.pki_pk = pki_pk
        self.ring_length = ring_length
        self.range_m = range_m
        self.plausibility = plausibility
        self.detectors = tuple(detectors)
        self.allowance_m = allowance_m
        self.max_speed = max_speed
        self.art_range_m = art_range_m if art_range_m is not None else range_m
        self.kin_tolerance_m = kin_tolerance_m
        self.loss = loss
        self.loss_rng = random.Random(seed ^ 0x105E)
        self.mode = mode
        self.freshness = freshness
        self.pm_cert_check = pm_cert_check       # callable(pm_id, pm_pk_hex, cert) -> bool
        self.receivers: dict[int, ReceiverState] = {}
        self.stats = V2VStats()
        self._sig_cache: dict[tuple, bool] = {}

    # -- geometry
    def _dist(self, a: float, b: float) -> float:
        d = abs(a - b) % self.ring_length
        return min(d, self.ring_length - d)

    def _signed(self, a: float, b: float) -> float:
        """b - a on the ring, in (-L/2, L/2]."""
        d = (b - a) % self.ring_length
        return d - self.ring_length if d > self.ring_length / 2 else d

    def neighbours(self, x: float, positions: dict[int, float], exclude: int | None = None) -> list[int]:
        return [vid for vid, px in positions.items() if vid != exclude and self._dist(x, px) <= self.range_m]

    # -- cryptography: cached by everything it depends on, never by time
    def _verify_sig(self, pk_hex: str, data: bytes, sig_hex: str) -> bool:
        key = (pk_hex, crypto.sha256_hex(data), sig_hex)
        hit = self._sig_cache.get(key)
        if hit is None:
            self.stats.verifications += 1
            hit = crypto.verify(crypto.pk_from_hex(pk_hex), data, bytes.fromhex(sig_hex))
            self._sig_cache[key] = hit
        return hit

    def _pm_cert_ok(self, h: dict) -> bool:
        key = ("pm", h["pm"], h["pm_pk"], h["pm_cert"])
        hit = self._sig_cache.get(key)
        if hit is None:
            hit = bool(self.pm_cert_check is not None and self.pm_cert_check(h["pm"], h["pm_pk"], h["pm_cert"]))
            self._sig_cache[key] = hit
        return hit

    def verify(self, msg, now: float) -> tuple[bool, str]:
        """Full receiver check at time ``now``: every time-dependent condition
        is evaluated here, at every delivery."""
        cred = msg.cred
        if not cred:
            return False, "no-certificate"
        try:
            if cred.get("pid") != msg.pid:
                return False, "certificate-pid-mismatch"
            if now > cred["expiry"]:
                return False, "certificate-expired"
            pki_hex = crypto.pk_to_hex(self.pki_pk)
            data = json.dumps({"pid": cred["pid"], "pk": cred["pk"], "expiry": cred["expiry"]}, sort_keys=True).encode()
            if not self._verify_sig(pki_hex, data, cred["cert"]):
                return False, "certificate-invalid"
            sign_pk = cred["pk"]
            if self.mode == "holder":
                h = cred.get("holder")
                if not h:
                    return False, "no-holder-certificate"
                if not (h["t_start"] <= now <= h["t_end"]):
                    return False, "holder-window"
                if h["pid"] != msg.pid:
                    return False, "holder-pid-mismatch"
                if not self._pm_cert_ok(h):
                    return False, "pm-certificate-invalid"
                from ..entities import holder_cert_bytes
                if not self._verify_sig(h["pm_pk"], holder_cert_bytes(h["pid"], h["pk"], h["t_start"], h["t_end"], h["pm"]),
                                        h["sig"]):
                    return False, "holder-certificate-invalid"
                sign_pk = h["pk"]
            if abs(now - msg.timestamp) > self.freshness:
                return False, "stale"
            if not msg.signature or not self._verify_sig(sign_pk, msg.body(), msg.signature):
                return False, "bad-signature"
        except (KeyError, ValueError, TypeError):
            return False, "malformed"
        return True, "ok"

    # -- plausibility
    def _plausible(self, st: ReceiverState, msg, rx_x: float) -> tuple[bool, str]:
        cx = msg.position[0]
        if "art" in self.detectors and self._dist(cx, rx_x) > self.art_range_m:
            return False, "implausible-range"
        last = st.last_seen.get(msg.pid)
        if last is None:
            return True, "ok"
        lx, lt, lv, ldir = last
        dt = max(1e-6, msg.timestamp - lt)
        if "ssc" in self.detectors and self._dist(cx, lx) > self.max_speed * dt + self.allowance_m:
            return False, "implausible"
        if "kin" in self.detectors and dt <= 5.0:
            pred = (lx + (1 if ldir >= 0 else -1) * lv * dt) % self.ring_length
            if self._dist(cx, pred) > self.kin_tolerance_m + 2.0 * dt:
                return False, "implausible-kinematics"
        return True, "ok"

    # -- delivery
    def deliver(self, msg, sender_x: float, positions: dict[int, float], now: float, forged: bool = False,
                exclude: int | None = None) -> tuple[int, int]:
        """Deliver ``msg`` from a transmitter physically at ``sender_x`` to every
        vehicle in radio range.  ``msg.position`` is what the message claims and
        may differ from ``sender_x``.  Returns (accepting receivers, receivers
        reached)."""
        rx = self.neighbours(sender_x, positions, exclude)
        ok, reason = self.verify(msg, now)
        accepted = reached = 0
        self.stats.messages += 1
        if forged:
            self.stats.forged_messages += 1
        for vid in rx:
            if self.loss and self.loss_rng.random() < self.loss:
                self.stats.lost += 1
                continue
            reached += 1
            st = self.receivers.setdefault(vid, ReceiverState())
            self.stats.received += 1
            if forged:
                self.stats.forged_received += 1
            else:
                self.stats.honest_received += 1
            r_ok, r_reason = ok, reason
            if r_ok and self.plausibility:
                r_ok, r_reason = self._plausible(st, msg, positions[vid])
                if not r_ok and not forged:
                    self.stats.honest_rejected_implausible += 1
            if r_ok:
                st.last_seen[msg.pid] = (msg.position[0], msg.timestamp, msg.speed, msg.direction)
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
        return accepted, reached
