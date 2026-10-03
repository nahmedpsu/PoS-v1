"""Algorithm 1 - Proof_of_Work_1 consensus.

The paper's first PoW implementation "takes a whole string and we change the
string manually to see how much time the whole string (puzzle) takes for
guessing".  The guessing characters ``ABC...Zabc...z0123...9#...`` form the
search set; the miner walks the search set in order (``for St = 1..n: if
P == St[i] return P``) until it hits the puzzle.  The cost is therefore the
position of the puzzle in the enumeration of all strings of its length over
the character set - best case O(1), average and worst case O(n).
"""

from __future__ import annotations

import itertools
import string
import time
from dataclasses import dataclass

CHARSET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "#$%&*@!?"


@dataclass
class PoW1Result:
    puzzle: str
    found: bool
    guesses: int
    seconds: float
    search_space: int
    extrapolated_seconds: float | None = None

    @property
    def cpu_seconds(self) -> float:
        """Measured time if the search finished, otherwise the extrapolation."""
        return self.seconds if self.found else (self.extrapolated_seconds or self.seconds)


def search_space(puzzle: str, charset: str = CHARSET) -> int:
    return len(charset) ** len(puzzle)


def puzzle_position(puzzle: str, charset: str = CHARSET) -> int:
    """1-based index of ``puzzle`` in the lexicographic enumeration of strings
    of its length over ``charset``.  This is exactly the number of guesses
    Algorithm 1 makes, computed without running it."""
    base = len(charset)
    pos = 0
    for ch in puzzle:
        pos = pos * base + charset.index(ch)
    return pos + 1


def solve_pow1(puzzle: str, charset: str = CHARSET, max_guesses: int | None = 5_000_000) -> PoW1Result:
    """Run Algorithm 1: enumerate candidate strings until ``puzzle`` is matched.

    ``max_guesses`` bounds the run; if the bound is hit the result carries an
    extrapolated time computed from the measured guess rate and the known
    position of the puzzle in the search set.
    """
    if any(c not in charset for c in puzzle):
        raise ValueError("puzzle contains a character outside the guessing set")
    n = len(puzzle)
    guesses = 0
    start = time.perf_counter()
    for cand in itertools.product(charset, repeat=n):
        guesses += 1
        if "".join(cand) == puzzle:
            elapsed = time.perf_counter() - start
            return PoW1Result(puzzle, True, guesses, elapsed, search_space(puzzle, charset))
        if max_guesses is not None and guesses >= max_guesses:
            break
    elapsed = time.perf_counter() - start
    rate = guesses / elapsed if elapsed > 0 else float("inf")
    needed = puzzle_position(puzzle, charset)
    return PoW1Result(
        puzzle, False, guesses, elapsed, search_space(puzzle, charset),
        extrapolated_seconds=needed / rate,
    )
