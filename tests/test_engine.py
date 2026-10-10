"""M5 taint engine: T-POOL-1, T-MASS-1, T-CUST-1/T-G3W-1, T-TIV-4..8,10,12,16..18, T-GAMMA-1.

The engine consumes opened facts only (accepted openings, Theorem 18). Mass identity
(Theorem 14) is asserted after every processed event."""
import random
from fractions import Fraction as F

import pytest

from sealedtrail import custody
from sealedtrail.engine.cone import cone_build
from sealedtrail.engine.facts import BankOpenings, event_facts, run_engine
from sealedtrail.engine.taint import TaintEngine
from sealedtrail.model import DEB, EXT, ANC
from sealedtrail.shadow import ShadowLedger
from sealedtrail.sim import Cluster

OM = {"NGN": 100}


def store_of(c):
    return c.validators["val-00"].store


def stepwise(c, roots, refuse=(), w=None):
    """Yield (engine, facts) after each event of the cone, in (token time, depth, id) order."""
    w = c.P.w_esc if w is None else w
    st, src = store_of(c), BankOpenings(c.banks, refuse)
    ids = cone_build(st, list(roots), w)
    eng = TaintEngine(w, injections={r: "whole" for r in roots})
    for eid in ids:
        f = event_facts(st, eid, src)
        eng.process(f)
        yield eng, f


def run(c, roots, refuse=(), w=None):
    eng = None
    for eng, _ in stepwise(c, roots, refuse, w):
        assert eng.identity_ok(), eng.terms()
    return eng


def cl(banks="ABCD", profile="min", seed=1):
    sh = ShadowLedger(OM)
    c = Cluster(profile, banks=tuple(banks), seed=seed, shadow=sh)
    return c


# paper examples
def test_pool_example_matches_hand_computation():
    c = cl("AB")
    A, B = c.banks["A"], c.banks["B"]
    x = A.onboard("x", 150_000)                    # flagged root, rho = 1
    A.onboard("y", 500_000)                        # clean root
    c.tick(1)
    A.transfer("y", "x", 250_000)                  # intra-bank: no event, entries unchanged
    A.pay("x", "B", "b", 400_000)                  # FIFO: all of X (150k) + 250k of Y
    eng = run(c, [x])
    z = [k for k, e in eng.entries.items() if e.owner == "B"][0]
    assert eng.entries[z].rho == F(150_000, 400_000)                 # 3/8
    assert eng.entries[z].rho * eng.entries[z].A == 150_000          # mass carried is exact
    assert eng.P == 150_000 and eng.live() == 150_000                # nothing created or destroyed
    assert eng.Tb("B") == 150_000 and eng.Tb("A") == 0


def test_flagged_debit_not_its_parents():
    """Flag the debit Z, not its parents: parents stay clean and outside the cone."""
    c = cl("AB")
    A = c.banks["A"]
    A.onboard("x", 150_000); A.onboard("y", 500_000)
    c.tick(1)
    A.transfer("y", "x", 250_000)
    A.pay("x", "B", "b", 400_000)
    st = store_of(c)
    z = [eid for (eid,) in st.conn.execute("SELECT id FROM events WHERE type='DEB'")][0]
    ids = cone_build(st, [z], c.P.w_esc)
    assert ids == [z]                                       # parents are not in the cone
    eng = run(c, [z])
    assert eng.P == 400_000 and eng.entries[(z, 0)].rho == 1 and eng.Tb("B") == 400_000


# T-POOL-1
def random_cluster(seed, steps=25):
    rnd = random.Random(seed)
    c = cl("ABCD", seed=seed)
    roots = []
    for n in "ABCD":
        for k in range(2):
            roots.append(c.banks[n].onboard(f"{n}{k}", rnd.randrange(8_000, 600_000)))
    tiv = next(iter(c.tivs.values()))
    for _ in range(steps):
        c.tick(rnd.choice([0, 1, 2, 5]))
        b = c.banks[rnd.choice("ABCD")]
        acct = rnd.choice([a for a in b.customers if b.customers[a] > 0] or [None])
        if acct is None:
            continue
        kind = rnd.choice(["pay", "pay", "pay", "rehome", "exit", "anchor", "multi"])
        try:
            if kind == "pay":
                d = rnd.choice([n for n in "ABCD" if n != b.name])
                b.pay(acct, d, f"{d}0", rnd.randrange(100, max(101, b.customers[acct])))
            elif kind == "rehome":
                split = None
                amt = sum(h.residual()[0] for h in b.entries("NGN") if h.key not in b.busy)
                if amt >= 600 and rnd.random() < 0.5:
                    split = [amt // 2, amt - amt // 2]
                b.rehome("NGN", split=split)
            elif kind == "exit":
                b.exit(acct, rnd.randrange(100, max(101, b.customers[acct] // 2)))
            elif kind == "anchor":
                b.anchor(acct, rnd.randrange(1_000, 50_000), "NGN", tiv)
            else:
                ds = rnd.sample([n for n in "ABCD" if n != b.name], 2)
                t = b.customers[acct]
                b.pay_many(acct, [(ds[0], f"{ds[0]}1", rnd.randrange(100, max(101, t // 3)), None),
                                  (ds[1], f"{ds[1]}1", rnd.randrange(100, max(101, t // 3)), None)])
        except Exception:
            continue
    return c, roots


@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_pool_bounds_mass_identity_and_fraction_range(seed):
    c, roots = random_cluster(seed)
    flag = [roots[seed % len(roots)], roots[(seed + 3) % len(roots)]]
    st = store_of(c)
    for eng, f in stepwise(c, flag):
        assert eng.identity_ok(), eng.terms()                                   # T-MASS-1
        for k, ent in eng.entries.items():
            assert 0 <= ent.rho <= 1                                            # Prop 13: 0 <= rho <= 1
        if f.type == DEB and f.id not in flag:
            rhos = [eng.entries[k].rho if k in eng.entries and eng.entries[k].cons >= 0 else F(0) for k, _ in f.parents]
            out = eng.entries[(f.id, 0)].rho
            # parents that are not in the cone are clean (rho 0); pooled rho lies between extremes
            lo = min(F(0) if k not in eng.entries else eng.entries[k].rho for k, _ in f.parents)
            hi = max(F(0) if k not in eng.entries else eng.entries[k].rho for k, _ in f.parents)
            assert lo <= out <= hi
            assert all(eng.entries[(f.id, j)].rho == out for j in range(len(f.outputs)))   # same rho on every output


# T-CUST-1 / T-G3W-1 (Cor 16)
@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_custody_recovered_from_weighted_g3_and_rehoming_invariance(seed):
    c, roots = random_cluster(seed, steps=30)
    flag = [roots[seed % len(roots)]]
    st, src = store_of(c), BankOpenings(c.banks)
    ids = cone_build(st, flag, c.P.w_esc)
    eng = TaintEngine(c.P.w_esc, injections={r: "whole" for r in flag})
    for eid in ids:
        f = event_facts(st, eid, src)
        before = eng.all_Tb()
        eng.process(f)
        after = eng.all_Tb()
        if f.type == DEB and all(o[0] == f.issuer for o in f.outputs):         # re-homing
            assert before.get(f.issuer, F(0)) == after.get(f.issuer, F(0))     # Thm 15 (i), (iv)
        if f.type == DEB and any(o[0] != f.issuer for o in f.outputs):         # inter-bank: (ii)
            moved = sum((w for s_, d, t, w, e in eng.edges if e == f.id), F(0))
            assert before.get(f.issuer, F(0)) - after.get(f.issuer, F(0)) >= moved - 0
    for b in "ABCD":
        assert eng.Tb(b) == eng.custody_from_edges(b), b                        # Cor 16: Tb from G3 alone
    assert sum(eng.all_Tb().values(), F(0)) == eng.live()


# T-TIV-*
def scenario(flag_amount=100_000):
    c = cl("ABC")
    A, B = c.banks["A"], c.banks["B"]
    root = A.onboard("dirty", flag_amount)
    B.onboard("b0", 10_000)
    c.tick(1)
    return c, A, B, root, next(iter(c.tivs.values()))


def test_tiv4_exit_then_unattested_anchor_draws_taint():
    c, A, B, root, tiv = scenario()
    A.exit("dirty", 100_000); c.tick(10)
    B.anchor("b0", 100_000, "NGN", tiv)
    eng = run(c, [root])
    anc = [e for k, e in eng.entries.items() if e.owner == "B"][-1]
    assert anc.rho == 1 and eng.E_total() == 0 and eng.Y == 0
    assert eng.Tb("B") == 100_000


def test_tiv4_partial_draw_rho_is_min_over_amount():
    c, A, B, root, tiv = scenario()
    A.exit("dirty", 100_000); c.tick(10)
    B.anchor("b0", 250_000, "NGN", tiv)
    eng = run(c, [root])
    anc = [e for k, e in eng.entries.items() if e.owner == "B"][-1]
    assert anc.rho == F(100_000, 250_000) and eng.open_anchors and eng.open_anchors[0][1] == 150_000


def test_tiv5_anchor_first_then_exit_inside_window_gives_claim_not_rho():
    c, A, B, root, tiv = scenario()
    B.anchor("b0", 60_000, "NGN", tiv); c.tick(10)          # E = 0: enters clean, stays open
    A.exit("dirty", 100_000)
    eng = run(c, [root])                                     # two-sided window puts the earlier anchor in the cone
    anc = [e for k, e in eng.entries.items() if e.owner == "B"][-1]
    assert anc.rho == 0                                      # no entry's rho is revised
    assert eng.Y == 60_000 and eng.claims[tiv.id] == 60_000 and eng.E_total() == 40_000
    assert eng.live() + eng.E_total() + eng.Y + eng.Z + eng.D == eng.P == 100_000


def test_tiv6_exit_after_window_no_match_and_expiry_into_z():
    c, A, B, root, tiv = scenario()
    B.anchor("b0", 60_000, "NGN", tiv); c.tick(c.P.w_esc + 5)
    A.exit("dirty", 100_000)
    eng = run(c, [root])
    assert eng.Y == 0 and eng.E_total() == 100_000          # the anchor is outside the window: no match
    eng.settle(c.clock.now() + c.P.w_esc + 1)
    assert eng.Z == 100_000 and eng.E_total() == 0 and eng.identity_ok()


def test_tiv7_clean_attestation_liability_and_tiv16_eq_unchanged():
    c, A, B, root, tiv = scenario()
    A.exit("dirty", 100_000); c.tick(10)
    B.anchor("b0", 70_000, "NGN", tiv, clean=1)
    eng = run(c, [root])
    anc = [e for k, e in eng.entries.items() if e.owner == "B"][-1]
    assert anc.rho == 0 and eng.liab[tiv.id] == 70_000      # liability min(A, E)
    assert eng.E_total() == 100_000 and eng.identity_ok()   # E unchanged by a clean attestation
    eng.settle(c.clock.now() + c.P.w_esc + 1)
    assert eng.Z == 100_000                                 # the mass expires into Z
    # with E = 0 the liability is zero
    c2, A2, B2, root2, tiv2 = scenario()
    B2.anchor("b0", 70_000, "NGN", tiv2, clean=1)
    assert not run(c2, [root2]).liab


def test_tiv8_innocent_anchor_receives_taint_by_amount_and_time():
    c, A, B, root, tiv = scenario()
    A.exit("dirty", 100_000); c.tick(10)
    C = c.banks["C"]; C.onboard("c0", 5_000)
    C.anchor("c0", 30_000, "NGN", tiv)                       # unrelated deposit
    eng = run(c, [root])
    anc = [e for k, e in eng.entries.items() if e.owner == "C" and e.A == 30_000][0]
    assert anc.rho == 1                                      # tainted by amount and time; remedy is a clean attestation


def test_tiv10_flagged_anchor_is_whole_without_tiv_liability():
    c, A, B, root, tiv = scenario()
    aid = B.anchor("b0", 40_000, "NGN", tiv)
    eng = run(c, [aid])
    assert eng.entries[(aid, 0)].rho == 1 and eng.P == 40_000 and not eng.liab and not eng.claims


def test_tiv17_two_exits_oldest_tranche_first_and_younger_expires_later():
    c, A, B, root, tiv = scenario(200_000)
    A.exit("dirty", 80_000); c.tick(300)
    A.exit("dirty", 120_000); c.tick(10)
    B.anchor("b0", 100_000, "NGN", tiv)                      # draws 80k (older) + 20k (younger)
    eng = run(c, [root])
    assert eng.E_total() == 100_000 and eng.E[0][1] == 100_000     # only the younger tranche is left
    eng.settle(c.clock.now() + c.P.w_esc)                    # younger tranche (t=1311) expires after W_esc
    assert eng.Z == 100_000 and eng.identity_ok()


def test_tiv12_replicas_agree():
    c, A, B, root, tiv = scenario()
    A.exit("dirty", 100_000); c.tick(5)
    B.anchor("b0", 100_000, "NGN", tiv)
    c.sync_all()
    outs = []
    for v in list(c.validators.values())[:3]:
        eng = run_on(v.store, c, [root])
        outs.append((eng.terms(), sorted((k, e.rho) for k, e in eng.entries.items())))
    assert outs[0] == outs[1] == outs[2]


def run_on(store, c, roots):
    eng = TaintEngine(c.P.w_esc, injections={r: "whole" for r in roots})
    src = BankOpenings(c.banks)
    for eid in cone_build(store, list(roots), c.P.w_esc):
        eng.process(event_facts(store, eid, src))
    return eng


def test_tiv18_refusing_bank_makes_following_anchor_unresolved():
    c, A, B, root, tiv = scenario()
    A.exit("dirty", 100_000); c.tick(10)
    aid = B.anchor("b0", 100_000, "NGN", tiv)
    eng = run(c, [root], refuse={"A"})                       # A will not open the EXT's consumed portions
    assert aid in eng.unres_events                           # D29: no washing through an unresolved exit
    assert eng.entries[(aid, 0)].unres is True
    assert eng.live() == 0                                   # nothing resolved is claimed as live


def test_refusal_is_viral_through_parents():
    c = cl("ABC")
    A, B, C = (c.banks[n] for n in "ABC")
    root = A.onboard("a", 100_000); B.onboard("b", 1_000); C.onboard("c", 1_000)
    c.tick(1)
    A.pay("a", "B", "b", 50_000); c.tick(1)
    B.pay("b", "C", "c", 20_000)
    eng = run(c, [root], refuse={"A"})                       # the first debit is unresolved...
    assert all(e.unres for k, e in eng.entries.items() if k[0] != root)     # ...and so is everything below it
    assert all(e.rho == 0 for e in eng.entries.values() if e.unres)


# T-CONE-1 / gamma
def test_cone_equals_shadow_forward_closure():
    c, roots = random_cluster(5, steps=25)
    st = store_of(c)
    flag = [roots[2]]
    got = set(cone_build(st, flag, c.P.w_esc))
    # independent forward closure over parent edges, then the anchor window step
    sh_parents = {}
    for _, wire, _ in st.all_events():
        from sealedtrail.model import Event
        e = Event.from_wire(wire)
        sh_parents[e.id] = (e.type, [p.eid for p in e.parents], st.event_meta(e.id)["ttok"])
    seen, grow = set(flag), True
    while grow:
        grow = False
        for eid, (typ, ps, t) in sh_parents.items():
            if eid in seen:
                continue
            if any(p in seen for p in ps) or (typ == ANC and any(
                    sh_parents[x][0] == EXT and abs(t - sh_parents[x][2]) <= c.P.w_esc for x in seen)):
                seen.add(eid); grow = True
    assert got == seen


def test_gamma_identity_on_live_traffic():
    for inter in (2, 4):                                      # inter-bank payments out of 8 debits
        c = cl("AB")
        A = c.banks["A"]
        for k in range(8):
            A.onboard(f"a{k}", 100_000)
        c.banks["B"].onboard("b", 1_000)
        c.tick(1)
        for i in range(8):
            if i < inter:
                A.pay("a0", "B", "b", 1_000 + i) if A.customers["a0"] > 5_000 else None
            else:
                A.rehome("NGN", amount=2_000)
        g = custody.gamma(store_of(c))
        assert g["gamma"] is not None and abs(g["gamma"] - g["identity"]) < 1e-9     # Prop 17: gamma = dbar / eta
