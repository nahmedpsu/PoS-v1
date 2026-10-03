"""Consensus algorithms compared in the manuscript (Section III and V).

* :mod:`pow1`  - Algorithm 1, Proof of Work 1 (linear search of a puzzle string)
* :mod:`pow2`  - Algorithm 2, Proof of Work 2 (hash with leading-zero difficulty)
* :mod:`pokw`  - Proof of Kernel Work (random kernel of miners runs PoW)
* :mod:`poet`  - Algorithm 3, Proof of Elapsed Time
* :mod:`pop`   - Algorithm 6, Proof of Pseudonym (the proposed protocol)
"""

from .poet import PoETResult, poet_elect
from .pokw import PoKWResult, pokw_mine
from .pop import PoPResult, PoPServer, verify_election
from .pow1 import PoW1Result, solve_pow1
from .pow2 import PoW2Result, mine_pow2

__all__ = [
    "PoETResult", "poet_elect",
    "PoKWResult", "pokw_mine",
    "PoPResult", "PoPServer", "verify_election",
    "PoW1Result", "solve_pow1",
    "PoW2Result", "mine_pow2",
]
