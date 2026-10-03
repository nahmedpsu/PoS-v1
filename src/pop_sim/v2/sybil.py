"""Sybil and collusion analysis of Proof of Pseudonym.

The manuscript states that PoP "prevents Sybil attacks as it chooses a
certain number of nodes for consensus and not all".  Random selection does
not prevent an attacker with ``k`` identities among ``n`` honest nodes from
winning: by symmetry it wins a fraction ``k / (n + k)`` of the blocks, and
in PoP v1 an identity that simply *reports* the smallest possible timer
wins every block it is selected for.  What limits ``k`` is the PKI binding
of the election key to a certificate (PoP v2), which turns a Sybil attack
into a certificate-theft problem.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass


def analytic_win_probability(n_honest: int, k_sybil: int) -> float:
    """Honest timers / VRF values: every identity is equally likely to win."""
    return k_sybil / (n_honest + k_sybil) if n_honest + k_sybil else 0.0


def analytic_win_probability_lying_v1(n_honest: int, k_sybil: int, participation: float = 0.5) -> float:
    """PoP v1 with an attacker that always reports the minimum timer: it wins
    whenever at least one of its identities is selected."""
    return 1 - (1 - participation) ** k_sybil


@dataclass
class SybilRow:
    n_honest: int
    k_sybil: int
    v1_honest: float
    v1_lying: float
    v2_vrf: float
    v2_pki_bound: float
    analytic: float
    analytic_lying: float


def simulate_sybil(n_honest: int, k_values=(0, 1, 2, 5, 10, 20), rounds: int = 2000,
                   participation: float = 0.5, seed: int = 1) -> list[SybilRow]:
    rng = random.Random(seed)
    rows = []
    for k in k_values:
        wins = {"v1_honest": 0, "v1_lying": 0, "v2": 0, "v2_bound": 0}
        for _ in range(rounds):
            honest = [rng.random() for _ in range(n_honest)]
            sybil = [rng.random() for _ in range(k)]
            sel_h = [v for v in honest if rng.random() < participation]
            sel_s = [v for v in sybil if rng.random() < participation]
            # v1, honest attacker: timers are what they are.
            if sel_s and (not sel_h or min(sel_s) < min(sel_h)):
                wins["v1_honest"] += 1
            # v1, lying attacker: any selected Sybil identity reports the minimum.
            if sel_s:
                wins["v1_lying"] += 1
            # v2: VRF values cannot be chosen; sortition is on the value itself.
            m_h = [v for v in honest if v < participation]
            m_s = [v for v in sybil if v < participation]
            if m_s and (not m_h or min(m_s) < min(m_h)):
                wins["v2"] += 1
            # v2 with PKI-bound keys: the attacker has as many identities as
            # certificates it holds; one compromised PM = one identity.
            m_b = [v for v in sybil[:1] if v < participation]
            if m_b and (not m_h or min(m_b) < min(m_h)):
                wins["v2_bound"] += 1
        rows.append(SybilRow(n_honest, k, wins["v1_honest"] / rounds, wins["v1_lying"] / rounds,
                             wins["v2"] / rounds, wins["v2_bound"] / rounds,
                             analytic_win_probability(n_honest, k),
                             analytic_win_probability_lying_v1(n_honest, k, participation)))
    return rows


def blocks_to_control(win_probability: float, horizon: int = 1000) -> float:
    """Expected number of blocks the attacker publishes over ``horizon`` blocks."""
    return statistics.fmean([win_probability] * horizon) * horizon
