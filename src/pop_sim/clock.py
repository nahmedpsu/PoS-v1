"""Simulation clock.  ``now()`` returns the virtual time when one is set
(``set_virtual``), else the wall clock, so that a seeded run produces
byte-identical transactions and blocks."""

from __future__ import annotations

import time

_virtual: float | None = None


def now() -> float:
    return time.time() if _virtual is None else _virtual


def set_virtual(t: float | None) -> None:
    global _virtual
    _virtual = t


def advance(dt: float) -> None:
    global _virtual
    if _virtual is not None:
        _virtual += dt
