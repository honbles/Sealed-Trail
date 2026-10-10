"""M6 part 2: REV, Algorithm 3 phases, opening log, restitution, refusal, Prop 20 rounding.
T-REV-ROUND, S-REFUSE, T-FREEZE-1, T-OPEN-1 (V6), Thm 14/15(v)."""
from fractions import Fraction as F
from itertools import combinations

import pytest

from sealedtrail import monitors
from sealedtrail.builder import build_spend
from sealedtrail.plan import (constructible, feasible_intervals, greatest_feasible_at_most,
                              least_feasible_at_least)
from sealedtrail.reversal import Reversal, fraction
from sealedtrail.sim import Cluster
from test_flags import chain


def setup(banks="ABCR", prof="dev", **kw):
    c, root = chain(prof, banks)
    f = c.make_flag([root], brec="R", ttl=3600)
    return c, root, f


def test_rev_round_full_cooperation():
    c, root, f = setup()
    rv = Reversal(c, f)
    rep = rv.run()
    assert all(r[0] == "ok" for r in rep["phase0"].values())
    assert rep["exposure"]["foreign"] == []
    assert rep["reversed"] == {"A": 80_000, "B": 70_000, "C": 50_000}
    assert rep["non_compliant"] == [] and rep["unresolved_banks"] == []
    assert rep["identity_ok"]                                   # Thm 14 with REV events in the cone
    assert rep["metrics"]["RecoveryRate"] == 1                  # everything recovered at the recovery bank
    assert rep["Tb"]["A"] == rep["Tb"]["B"] == rep["Tb"]["C"] == 0
    assert rep["Tb"]["R"] == 200_000                            # Thm 15(v): T_brec rose by exactly sum of m
    # the holder pays out of its own residuals: customers reconcile, losses are explicit
    for n in "ABC":
        assert c.banks[n].reconcile()
    assert c.banks["A"].customers["_bank_loss"] == -80_000
    assert monitors.all_monitors(c) == []
    # Phase 4: resolved entries of banks that reversed are released; recovery entries stay Held (D7)
    held = c.held_keys("R")
    assert held and all(k in held for k in c.banks["R"].holdings)
    assert not (c.held_keys("A") & set(c.banks["A"].holdings))


def test_restitution_moves_mass_to_D():
    c, root, f = setup()
    rv = Reversal(c, f)
    rv.run()
    R = c.banks["R"]
    c.tick(1)
    res, eid = R.issue_rev(f.id, 30_000, "R", kind="restitution", beneficiary="A")
    assert res.ok
    rv.ingest_rev(eid)
    eng = rv.engine()
    assert eng.identity_ok()
    assert eng.D == 30_000 and eng.entries[(eid, 0)].rho == 0
    rec = sum(e.rho * e.R for e in eng.entries.values() if e.owner == "R")
    assert rec == 170_000
    assert eng.metrics("R")["RecoveryRate"] == 1                # (recovery mass + D) / P


def test_partial_policy_leaves_exactly_Tb_minus_m():
    c, root, f = setup()
    rv = Reversal(c, f, policy=fraction(F(1, 2)))
    rep = rv.run()
    assert rep["reversed"] == {"A": 40_000, "B": 35_000, "C": 25_000}
    assert rep["Tb"]["A"] == 40_000 and rep["Tb"]["B"] == 35_000 and rep["Tb"]["C"] == 25_000
    assert rep["identity_ok"]
    assert rep["Tb"]["R"] == 100_000


def mixed():
    """B receives an entry that mixes 50k flagged and 50k clean value (rho = 1/2), built before the flag."""
    c = Cluster("dev", banks=("A", "B", "R"))
    A, B = c.banks["A"], c.banks["B"]
    root = A.onboard("dirty", 100_000)
    clean_id = A.onboard("clean", 100_000)
    c.tick(1)
    hs = {h.eid: h for h in A.entries()}
    ev = build_spend(A.kp, "A", c.P, "NGN", [(hs[root], 50_000), (hs[clean_id], 50_000)], [("B", 100_000)],
                     c.trust.epoch_at(c.clock.now()), c.token)
    assert c.submit("A", ev.event).ok
    from sealedtrail.bank import Delivery
    o = ev.outputs[0]
    B.receive(Delivery(ev.event.id, 0, o[2], o[3], 0, None, b"", "A"))
    # the sender's bank applies the finalized debit locally
    for h, cc, rc in ev.parents:
        h.cons.append((cc, rc))
    A.customers["dirty"] -= 50_000
    A.customers["clean"] -= 50_000
    c.tick(1)
    return c, root, ev.event.id


def test_lambda_settles_mixed_entry_and_releases_clean_remainder():
    c, root, mixed_id = mixed()
    f = c.make_flag([root], brec="R", ttl=3600)
    rv = Reversal(c, f)
    rep = rv.run()
    eng = rv.eng
    # B's entry carried rho = 1/2; Tb(B) = 50k; full policy: m = Tb, so lambda = 0 and the rest is clean
    assert rep["Tb"]["B"] == 0 and rep["reversed"]["B"] == 50_000
    rem = [e for k, e in eng.entries.items() if e.owner == "B" and k[0] == mixed_id][0]
    assert rem.R == 50_000 and rem.rho == 0
    assert rep["identity_ok"]
    # Phase 4 released it: B can spend the clean remainder
    c.tick(1)
    assert c.banks["B"].pay("_unassigned", "A", "x", 10_000).ok if c.banks["B"].customers.get("_unassigned") else True
    assert (mixed_id, 0) not in c.held_keys("B")


def test_single_refusal_is_defeated_by_counterparty_openings():
    """Finding: for a one-parent, one-output debit the consumed-portion commitment equals the output
    commitment (r* = 0), so a cooperating neighbour's opening resolves a refusing bank's event."""
    c, root, f = setup()
    c.banks["B"].behavior = "refuse_open"
    rv = Reversal(c, f)
    rep = rv.run()
    assert rep["non_compliant"] == ["B"] and rep["unanswered"] == {"B": 2}      # B did refuse
    assert rep["unresolved_banks"] == []                                          # but nothing is Unresolved
    assert rep["identity_ok"] and rep["reversed"] == {"A": 80_000, "B": 70_000, "C": 50_000}


def test_refusal_by_both_sides_leaves_descendants_unresolved_and_held_until_expiry():
    c, root, f = setup()
    c.banks["B"].behavior = "refuse_open"
    c.banks["C"].behavior = "refuse_open"            # nobody can open the B -> C commitment
    rv = Reversal(c, f)
    rep = rv.run()
    assert rep["non_compliant"] == ["B", "C"]
    assert rep["unresolved_banks"] == ["B", "C"]                 # B's source entry and C's entry are Unresolved
    assert rep["reversed"] == {"A": 80_000}                      # the part upstream of the gap still reverses
    cone = set(rv.cone())
    for n in "BC":                                               # fail closed: cone entries stay Held, clean ones do not
        mine = {k for k in c.banks[n].holdings if k[0] in cone}
        assert mine and mine <= c.held_keys(n)
    c.tick(3600)                                                 # expiry lifts the flag by default
    assert c.held_keys("B") == set() and c.held_keys("C") == set()


def test_bank_that_declines_to_issue_rev_is_not_compelled():
    c, root, f = setup()
    c.banks["B"].behavior = "refuse_rev"
    rv = Reversal(c, f)
    rep = rv.run()
    assert rep["reversed"] == {"A": 80_000, "C": 50_000}
    assert rep["non_compliant"] == ["B"]
    cone = set(rv.cone())
    mine = {k for k in c.banks["B"].holdings if k[0] in cone}
    assert mine and mine <= c.held_keys("B")                     # B's cone entries stay Held until t_exp
    assert rep["identity_ok"]


def test_lying_opening_is_rejected_by_regulator_and_validators():
    from sealedtrail import crypto as Cr
    c, root, f = setup()
    c.banks["B"].behavior = "lie_open"
    rv = Reversal(c, f)
    rep = rv.run()
    assert rep["rejected_openings"] > 0 and "B" in rep["non_compliant"]
    assert all(Cr.commit(a, r) == k for k, (a, r) in rv.log.items())           # nothing wrong was accepted
    v = c.honest()[0]
    for (eid, j) in c.banks["B"].openings:
        row = v.store.conn.execute("SELECT kappa FROM entries WHERE eid=? AND j=?", (eid, j)).fetchone()
        got = v.opening(row[0]) if row else None
        assert got is None or Cr.commit(*got) == row[0]
    assert v.record_opening(b"\x01" * 32, 5, 7)[0] == "reject"                   # not a public commitment


# V6 rejections
def raw_rev(c, bank, holdings, flag_id, brec="R", kind="reversal", tamper=None):
    parents = [(h, h.residual()[0]) for h in holdings]
    amt = sum(a for _, a in parents)
    b = build_spend(bank.kp, bank.name, c.P, "NGN", parents, [(brec, amt)], c.trust.epoch_at(c.clock.now()),
                    c.token, rev=(kind, flag_id))
    if tamper:
        tamper(b.event)
    return c.submit(bank.name, b.event)


def test_v6_rejections():
    c, root, mixed_id = mixed()
    f = c.make_flag([root], brec="R", ttl=3600)
    rv = Reversal(c, f)
    rv.phase0(); c.tick(1); rv.phase1(); rv.phase2()
    A, B = c.banks["A"], c.banks["B"]
    mixed_h = B.holdings[(mixed_id, 0)]
    codes = lambda r: set(r.reasons.values())
    # parent not Held (a clean entry of A)
    clean = [h for h in A.entries() if h.eid != root][0]
    assert codes(raw_rev(c, A, [clean], f.id)) == {"V6_NOT_HELD"}
    # m larger than Tb(B) = 50k (the entry has rho = 1/2)
    assert codes(raw_rev(c, B, [mixed_h], f.id)) == {"V6_TB"}
    # restitution by a bank that is not the recovery bank
    assert codes(raw_rev(c, B, [mixed_h], f.id, kind="restitution")) == {"V6_BREC"}
    # recovery entry not owned by the recovery bank
    assert codes(raw_rev(c, B, [mixed_h], f.id, brec="A")) == {"V6_BREC"}
    # tampered opening of the output amount
    def bad(e):
        m, rb = e.rev_open["m"]
        e.rev_open["m"] = [m + 1, rb]
    assert codes(raw_rev(c, B, [mixed_h], f.id, tamper=bad)) == {"V6_OPENING"}
    # unknown flag
    assert codes(raw_rev(c, B, [mixed_h], b"\x00" * 32)) == {"V6_FLAG"}
    # a released flag no longer accepts REV
    assert all(x[0] == "ok" for x in c.release(f.id).values())
    assert codes(raw_rev(c, B, [mixed_h], f.id)) == {"V6_FLAG"}


def test_rev_by_bank_outside_scope_rejected():
    c, root, f = setup(banks="ABCRX")
    c.set_jurisdiction("J1", ("A", "B", "C", "R"))
    f = c.make_flag([root], brec="R", ttl=3600)
    rv = Reversal(c, f)
    rv.phase0(); c.tick(1); rv.phase1(); rv.phase2()
    X = c.banks["X"]
    X.onboard("x", 10_000)
    h = X.entries()[0]
    r = raw_rev(c, X, [h], f.id)
    assert set(r.reasons.values()) == {"V6_SCOPE"}


# T-FREEZE-1 (Prop 20)
def brute(residuals, omega):
    T = sum(residuals)
    return {x for x in range(omega, T + 1) if constructible(residuals, x, omega)}


@pytest.mark.parametrize("omega", [1, 2, 3, 5])
def test_prop20_intervals_match_brute_force(omega):
    vals = [0] + list(range(omega, omega * 4 + 3))
    for n in (1, 2, 3):
        for r in combinations(vals, n):
            r = [x for x in r if x >= omega]
            if not r:
                continue
            ok = brute(r, omega)
            iv = feasible_intervals(r, omega)
            from_iv = {x for a, b in iv for x in range(max(a, omega), b + 1)}
            assert from_iv == ok, (r, omega)
            T = sum(r)
            for m in range(0, T + omega + 2):
                lo = least_feasible_at_least(r, m, omega)
                hi = greatest_feasible_at_most(r, m, omega)
                want_lo = min((x for x in ok if x >= m), default=None)
                want_hi = max((x for x in ok if x <= m), default=None)
                assert lo == want_lo and hi == want_hi, (r, omega, m)
                if want_lo is not None and m <= T:
                    assert lo - max(m, omega) < omega           # rounding gap < omega (paper)
                if want_hi is not None and omega <= m <= T:
                    assert m - hi < omega


def test_prop20_paper_counterexample():
    omega = 20                                                   # r = (1.1, 1.1) omega, A = 1.05 omega
    assert not constructible([22, 22], 21, omega)
    assert constructible([22, 22], 44, omega) and constructible([22, 22], 22, omega) and constructible([22, 22], 2, 1)
