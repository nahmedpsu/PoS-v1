"""The former-holder adversary (A2) and revoked-vehicle persistence.

A vehicle that once held pseudonym ``p`` keeps ``p``'s private key (the
credential travels with it: ``Pseudonym.to_wire`` carries the key) and signs
messages under ``p`` after ``p`` has been recycled to someone else.  Three
strategies cover the space from naive to smart:

* **S1 remote shadow** - signs under ``p`` at its own true position while the
  new holder is also using ``p``.  Plausibility checks (two places at once)
  can catch it at receivers that heard both.
* **S2 co-located ghost** - listens for ``p`` and, when physically within radio
  range of the new holder, claims a position next to it (a fake braking
  warning).  Nothing in V2V stops it; an RSU that attributes by ledger blames
  the innocent holder.
* **S3 gap filler** - uses ``p`` only while nobody holds it: between return and
  re-allotment.  Nothing stops it until the certificate expires.

Under ``window`` issuance the attacker replays the current holder's
holder-bound certificate (public, carried in every message) with the shared
key.  Under ``rekey`` it has no key for the new holder's certificate, so it
can only present its own expired window.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import crypto
from ..entities import Pseudonym, SafetyMessage
from .metrics import ForgeryStats

STRATEGIES = ("S1", "S2", "S3")


@dataclass
class ForgedMessage:
    msg: SafetyMessage
    attacker_vid: int
    attacker_x: float
    victim_vid: str | None
    strategy: str


@dataclass
class FormerHolderAdversary:
    strategy: str = "S1"
    ghost_offset_m: float = 40.0
    radio_range_m: float = 300.0
    stats: ForgeryStats = field(default_factory=ForgeryStats)
    by_strategy: dict = field(default_factory=dict)

    def forge(self, attacker, attacker_x: float, p: Pseudonym, ledger, ring_length: float,
              holder_state: dict, now: float, speed: float, direction: int,
              current_holder_cert: dict | None) -> ForgedMessage | None:
        """Decide whether and how to forge under ``p`` this second."""
        holder = ledger.holder.get(p.pid)
        own = attacker.vehicle_id
        if holder == own:
            return None                                   # it still legitimately holds p
        if p.pid in ledger.retired:
            return None                                   # fresh modes: the pseudonym is never used again
        claimed_x = attacker_x
        victim = None
        if self.strategy == "S3":
            if holder is not None:
                return None                               # only between holders
        elif holder is None:
            return None                                   # S1 / S2 need a current victim
        else:
            victim = holder
            vx = holder_state.get(holder)
            if vx is None:
                return None
            if self.strategy == "S2":
                if self._dist(vx, attacker_x, ring_length) > self.radio_range_m:
                    return None                           # must really be near the victim's neighbours
                claimed_x = (vx + self.ghost_offset_m) % ring_length
        msg = SafetyMessage(p.pid, (claimed_x, 0.0), speed, float(direction), now)
        msg.signature = crypto.sign(p.keys.sk, msg.body()).hex()
        cred = p.cert_wire()
        if current_holder_cert is not None:               # window mode: replay the holder's certificate
            cred = dict(cred)
            cred["holder"] = dict(current_holder_cert)
        msg.cred = cred
        return ForgedMessage(msg, attacker.index, attacker_x, victim, self.strategy)

    @staticmethod
    def _dist(a: float, b: float, ring: float) -> float:
        d = abs(a - b) % ring
        return min(d, ring - d)

    def record(self, fm: ForgedMessage, accepted_rx: int, rx_total: int, rsu_ok: bool, now: float) -> None:
        st = self.stats
        st.sent += 1
        st.receivers_total += rx_total
        st.receivers_accepting += accepted_rx
        if accepted_rx:
            st.accepted_v2v += 1
            st.accepted_times.setdefault(fm.msg.pid, []).append(now)
        if rsu_ok:
            st.accepted_rsu += 1
        b = self.by_strategy.setdefault(fm.strategy, {"sent": 0, "accepted_v2v": 0, "accepted_rsu": 0})
        b["sent"] += 1
        b["accepted_v2v"] += bool(accepted_rx)
        b["accepted_rsu"] += bool(rsu_ok)
