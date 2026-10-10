"""Dust-aware debit planning (paper Proposition 20, spec section 3.2).

A debit of A from residuals r_1..r_n consumes c_i in {0} U (0, r_i - omega] U {r_i}
from entry i, because every new residual must be 0 or >= omega.  A is constructible
iff some set F has  sum_F r_i <= A <= sum_F r_i + sum_{not F} (r_i - omega).
"""
from __future__ import annotations

from itertools import combinations


class Infeasible(Exception):
    pass


def constructible(residuals: list, A: int, omega: int) -> bool:
    n = len(residuals)
    if A <= 0:
        return False
    if n <= 18:
        return _search(residuals, A, omega) is not None
    return _greedy(residuals, A, omega) is not None


def _split(residuals, F, A, omega):
    """Given the fully-consumed set F, spread the rest of A over the other entries."""
    need = A - sum(residuals[i] for i in F)
    if need < 0:
        return None
    take = [0] * len(residuals)
    for i in F:
        take[i] = residuals[i]
    for i in range(len(residuals)):
        if i in F or need == 0:
            continue
        cap = residuals[i] - omega
        if cap <= 0:
            continue
        c = min(cap, need)
        take[i] = c
        need -= c
    return take if need == 0 else None


def _search(residuals, A, omega):
    n = len(residuals)
    # prefer the smallest number of parents, then lexicographic order (FIFO bias)
    for size in range(0, n + 1):
        for F in combinations(range(n), size):
            tot = sum(residuals[i] for i in F)
            if tot > A:
                continue
            slack = sum(residuals[i] - omega for i in range(n) if i not in F and residuals[i] > omega)
            if A <= tot + slack:
                t = _split(residuals, set(F), A, omega)
                if t is not None:
                    return t
    return None


def _greedy(residuals, A, omega):
    need, take = A, [0] * len(residuals)
    for i, r in enumerate(residuals):
        if need == 0:
            break
        if r <= need:
            take[i], need = r, need - r
        elif r - need >= omega:
            take[i], need = need, 0
        elif r - omega > 0:
            take[i] = r - omega
            need -= r - omega
    return take if need == 0 else None


def plan_debit(residuals: list, A: int, omega: int) -> list:
    """Returns the consumed amount per entry (same order); raises Infeasible."""
    if A < omega:
        raise Infeasible("payment below the dust floor")
    t = _greedy(residuals, A, omega)            # FIFO-biased first
    if t is None and len(residuals) <= 18:
        t = _search(residuals, A, omega)        # exact fallback (Prop 20)
    if t is None:
        raise Infeasible("no dust-feasible parent set")
    return t


def feasible_intervals(residuals: list, omega: int) -> list:
    """Merged intervals of constructible totals (Prop 20): for each fully-consumed set F,
    [sum_F r, sum_F r + sum_{not F} (r - omega)^+]. Exact for n <= 18."""
    n = len(residuals)
    iv = []
    for mask in range(1 << n):
        tot = sum(r for i, r in enumerate(residuals) if mask >> i & 1)
        slack = sum(max(0, r - omega) for i, r in enumerate(residuals) if not mask >> i & 1)
        iv.append((tot, tot + slack))
    iv.sort()
    out = []
    for a, b in iv:
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def least_feasible_at_least(residuals: list, m: int, omega: int):
    """Least constructible m' >= max(m, omega), None if none (Rev rounding, paper section 5)."""
    lo = max(m, omega)
    if len(residuals) > 18:
        for x in range(lo, sum(residuals) + 1):
            if constructible(residuals, x, omega):
                return x
        return None
    for a, b in feasible_intervals(residuals, omega):
        if b >= lo:
            return max(a, lo)
    return None


def greatest_feasible_at_most(residuals: list, m: int, omega: int):
    hi = min(m, sum(residuals))
    if len(residuals) > 18:
        for x in range(hi, omega - 1, -1):
            if constructible(residuals, x, omega):
                return x
        return None
    best = None
    for a, b in feasible_intervals(residuals, omega):
        if a <= hi:
            best = min(b, hi)
    return best if best is not None and best >= omega else None
