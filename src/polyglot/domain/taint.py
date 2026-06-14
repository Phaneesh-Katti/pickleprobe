"""Security taint lattice labels."""

from __future__ import annotations

from enum import Enum, auto


class SecurityTaint(Enum):
    """Security risk label (orthogonal to resolution TaintKind)."""

    CLEAN = auto()
    INCONCLUSIVE = auto()
    SUSPICIOUS = auto()
    SINK = auto()


_RANK: dict[SecurityTaint, int] = {
    SecurityTaint.CLEAN: 0,
    SecurityTaint.INCONCLUSIVE: 1,
    SecurityTaint.SUSPICIOUS: 2,
    SecurityTaint.SINK: 3,
}


def join_security(*taints: SecurityTaint) -> SecurityTaint:
    if not taints:
        return SecurityTaint.CLEAN
    return max(taints, key=lambda t: _RANK[t])
