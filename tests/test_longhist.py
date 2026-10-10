"""Tests for the structure-only long-history measurement (sealedtrail/measure/longhist.py)."""
import hashlib

import numpy as np
import pytest

from sealedtrail.measure.longhist import OMEGA, Index, Ledger, measure_root, pick_roots
import random


def make(events=3000, **kw):
    L = Ledger(banks=kw.pop("banks", 10), seed=kw.pop("seed", 3), **kw)
    L.run_to(events)
    return L


def digest(L):
    h = hashlib.sha256()
    for a in (L.owner, L.resid, L.e_par, L.e_c, L.ev_first, L.ev_nout):
        h.update(a.tobytes())
    return h.hexdigest()


def test_value_is_conserved_and_floor_holds():
    L = make()
    assert abs(sum(L.resid) - L.minted) <= 1e-9 * L.minted             # no mint after genesis, no destruction
    assert all(r == 0.0 or r >= OMEGA for r in L.resid)                # every live residual is 0 or >= the dust floor
    live = [i for i, r in enumerate(L.resid) if r > 0]
    assert sorted(live) == sorted(e for pool in L.pool for e in pool)  # pools hold exactly the live entries
    assert all(L.pool[L.owner[e]][L.pos[e]] == e for e in live)
    for b in range(L.n):
        assert abs(L.bal[b] - sum(L.resid[e] for e in L.pool[b])) < 1e-6 * max(1.0, L.minted)


def test_parents_precede_outputs_and_are_distinct():
    L = make()
    for ev in range(L.n_genesis, L.n_events):
        s = L.ev_es[ev]
        t = L.ev_es[ev + 1] if ev + 1 < L.n_events else len(L.e_par)
        ps = list(L.e_par[s:t])
        assert ps and len(set(ps)) == len(ps)
        assert max(ps) < L.ev_first[ev]


def test_deterministic_for_a_seed():
    assert digest(make(seed=5)) == digest(make(seed=5))
    assert digest(make(seed=5)) != digest(make(seed=6))


@pytest.mark.parametrize("zipf", [0.0, 1.1])
def test_cone_matches_brute_force(zipf):
    L = make(events=2500, zipf=zipf)
    ix = Index(L)
    for root in pick_roots(L, 3, random.Random(1))["old"] + pick_roots(L, 3, random.Random(2))["young"]:
        got = set(ix.cone(root)["events"])
        tainted, want = {root}, set()
        for ev in range(L.n_events):
            s = ix.es[ev]
            t = ix.es[ev + 1]
            if any(p in tainted for p in ix.e_par[s:t].tolist()):
                want.add(ev)
                f = int(ix.ev_first[ev])
                tainted.update(range(f, f + int(ix.ev_nout[ev])))
        assert got == want


def test_mass_identity_and_oracle_hold():
    L = make(events=4000)
    ix = Index(L)
    for root in pick_roots(L, 4, random.Random(4))["old"]:
        row = measure_root(ix, root, rho_cap=10**9)
        assert row["mass_identity_rel_err"] < 1e-9                       # Theorem 14 with no exits: sum rho*R = P
        assert row["held_value_over_P"] >= 1.0 - 1e-9                    # whole-entry hold always covers at least the flagged value
        prev = None
        for eps in (0.001, 0.01, 0.1, 0.5):                              # looser tolerance never holds more
            v = row[f"held_value_over_P_eps{eps}"]
            assert prev is None or v <= prev + 1e-9
            prev = v
