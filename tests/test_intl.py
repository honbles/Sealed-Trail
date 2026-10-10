"""V4 international debits, oracles, Lemma 4 (T-MED-1), threat class 8 and the oracle-fraud flag."""
from fractions import Fraction as F

import pytest
from hypothesis import given, settings, strategies as st

from sealedtrail import crypto as C
from sealedtrail.builder import build_spend
from sealedtrail.monitors import all_monitors
from sealedtrail.oracle import lower_median, make_rate_doc, check_rate_doc, Oracle
from sealedtrail.reversal import Reversal
from sealedtrail.sim import Cluster

RATE = F(1, 1500)                      # USD per NGN


def two_banks(banks=("A", "B")):
    c = Cluster("dev", banks=banks)
    return c, c.banks["A"], c.banks["B"]


def raw_intl(c, bank, amount, ar, doc, out_cur="USD", dst="B", src_cur="NGN"):
    hs = [h for h in bank.entries(src_cur) if h.key not in bank.busy]
    h = hs[0]
    b = build_spend(bank.kp, bank.name, c.P, src_cur, [(h, amount)], [(dst, ar)], c.trust.epoch_at(c.clock.now()),
                    c.token, out_currency=out_cur, rate_doc=doc)
    return b


# basic V4
def test_intl_debit_accepted_and_supply_identity_holds():
    c, A, B = two_banks()
    A.onboard("a", 5_000_000, "NGN")
    c.tick(1)
    doc = c.rate_doc("NGN/USD", RATE)
    res = A.pay_intl("a", "B", "b", 1_500_000, "NGN", "USD", doc)
    assert res.ok
    assert B.customers["b"] == 1000                     # floor(1_500_000 / 1500)
    assert A.customers["a"] == 3_500_000
    assert A.reconcile() and B.reconcile()
    assert all_monitors(c) == []                                  # M1 per currency, including intl-in and intl-out


def test_tolerance_edges_are_exact():
    c, A, B = two_banks()
    for _ in range(6):
        A.onboard("a", 2_000_000, "NGN")
    c.tick(1)
    doc = c.rate_doc("NGN/USD", RATE)
    for ar in (995, 1000, 1005):                                  # |Ar - 1000| <= 0.5% of 1000 = 5
        b = raw_intl(c, A, 1_500_000, ar, doc)
        assert c.submit("A", b.event).ok, ar
        A.busy.add(b.parents[0][0].key)
        c.tick(1)
    for ar in (994, 1006, 1100, 900):
        with pytest.raises(ValueError):                           # an honest prover cannot even build the proof
            raw_intl(c, A, 1_500_000, ar, doc)
        A.busy.discard
    assert all_monitors(c) == []


def codes(r):
    return set(r.reasons.values())


def test_v4_rejections():
    c, A, B = two_banks()
    for _ in range(8):
        A.onboard("a", 2_000_000, "NGN")
    c.tick(1)
    doc = c.rate_doc("NGN/USD", RATE)
    ok = lambda: raw_intl(c, A, 1_500_000, 1000, doc)
    A_entries = lambda: [h for h in A.entries("NGN")]

    def fresh_bank_entry():
        hs = [h for h in A.entries("NGN") if h.key not in A.busy]
        A.busy.add(hs[0].key)
        return hs[0]

    def build(doc_=doc, ar=1000, **kw):
        h = [h for h in A.entries("NGN") if h.key not in A.busy][0]
        b = build_spend(A.kp, "A", c.P, "NGN", [(h, 1_500_000)], [("B", ar)], c.trust.epoch_at(c.clock.now()),
                        c.token, out_currency="USD", rate_doc=doc_)
        A.busy.add(h.key)
        return b

    # (a) limbs swapped between the two tolerance values
    b = build(); b.event.intl_limbs = b.event.intl_limbs[4:] + b.event.intl_limbs[:4]
    assert codes(c.submit("A", b.event)) == {"V4_LIMBS"}
    # (b) epsilon altered in the attached document (the event binds the document hash)
    b = build(); b.event.rate_doc = dict(b.event.rate_doc, n=b.event.rate_doc["n"] + 1)
    assert codes(c.submit("A", b.event)) == {"V4_RATE"}
    # (c) an oracle's observation is missing
    b = build(); d = dict(doc); d["obs"] = d["obs"][:-1]; b.event.rate_doc = d
    assert codes(c.submit("A", b.event)) == {"V4_RATE"}
    # (d) a forged observation: signed by a key that is not the oracle's
    b = build(); d = dict(doc); obs = [list(o) for o in d["obs"]]
    obs[0][4] = C.KeyPair().sign(b"x"); d["obs"] = obs; b.event.rate_doc = d
    assert codes(c.submit("A", b.event)) == {"V4_RATE"}
    # (e) a stale document
    old = c.rate_doc("NGN/USD", RATE, t=int(c.clock.now()) - 3600)
    b = build(old)
    assert codes(c.submit("A", b.event)) == {"V4_RATE"}
    # (f) a document for another pair
    wrong = c.rate_doc("NGN/EUR", RATE)
    b = build(wrong)
    assert codes(c.submit("A", b.event)) == {"V4_RATE"}
    # (g) same source and target currency
    h = [h for h in A.entries("NGN") if h.key not in A.busy][0]
    b = build_spend(A.kp, "A", c.P, "NGN", [(h, 1_500_000)], [("B", 1000)], c.trust.epoch_at(c.clock.now()),
                    c.token, out_currency="NGN", rate_doc=doc)
    assert codes(c.submit("A", b.event)) == {"V4_CURRENCY"}
    # (i) a self-consistent forged document: epsilon is not the lower median, and the event binds the forgery
    forged = dict(doc, n=doc["n"] * 3, d=doc["d"] * 2)              # 1.5x the oracles' median
    b = build(forged, ar=1500)
    assert codes(c.submit("A", b.event)) == {"V4_RATE"}
    # (h) tolerance attachments on a domestic debit
    A.onboard("z", 500_000, "NGN")
    h = [h for h in A.entries("NGN") if h.key not in A.busy][-1]
    b = build_spend(A.kp, "A", c.P, "NGN", [(h, 200_000)], [("B", 200_000)], c.trust.epoch_at(c.clock.now()), c.token)
    b.event.intl_limbs = [C.IDENTITY] * 8
    assert codes(c.submit("A", b.event)) == {"V4_SHAPE"}
    assert all_monitors(c) == []


# Lemma 4 (T-MED-1)
vals = st.fractions(min_value=F(1, 10_000), max_value=F(10), max_denominator=10**6)


@settings(max_examples=200, deadline=None)
@given(st.integers(3, 9), st.data())
def test_lemma4_median_within_honest_range(no, data):
    honest_n = no - (-(-no // 2) - 1)                               # corrupt count c = ceil(no/2) - 1
    hon = [data.draw(vals) for _ in range(honest_n)]
    liars = [data.draw(vals) for _ in range(no - honest_n)]
    med = lower_median(hon + liars)
    assert min(hon) <= med <= max(hon)


def test_lemma4_breaks_at_half():
    hon = [F(1), F(1), F(1)]
    liars = [F(5), F(5), F(5)]                                      # c = no/2 for no = 6 (even): lower median stays honest
    assert lower_median(hon + liars) == F(1)
    assert lower_median([F(1), F(1), F(5), F(5), F(5)]) == F(5)     # c = 3 of 5 = ceil(5/2): median is a liar's value


# threat class 8
def test_class8_up_to_two_liars_cannot_move_epsilon_out_of_the_honest_band():
    c, A, B = two_banks()
    A.onboard("a", 5_000_000, "NGN")
    theta_o = F(*c.P.theta_o)
    honest = {0: F(999, 1000), 1: F(1001, 1000), 2: F(1)}           # honest observations inside +-theta_o
    liars = {3: F(3, 2), 4: F(1, 2)}
    doc = c.rate_doc("NGN/USD", RATE, liars={**honest, **liars})
    eps = F(doc["n"], doc["d"])
    assert abs(eps - RATE) <= theta_o * RATE
    assert A.pay_intl("a", "B", "b", 1_500_000, "NGN", "USD", doc).ok


def test_class8_three_liars_win_validators_cannot_tell_and_the_flag_recovers_only_the_excess():
    c, A, B = two_banks(("A", "B", "R"))
    A.onboard("a", 5_000_000, "NGN")
    c.tick(1)
    doc = c.rate_doc("NGN/USD", RATE, liars={0: F(3, 2), 1: F(3, 2), 2: F(3, 2)})
    assert F(doc["n"], doc["d"]) == F(1, 1000)                      # 1.5x the true rate
    res = A.pay_intl("a", "B", "b", 1_500_000, "NGN", "USD", doc)
    assert res.ok                                                   # (V4) is relative to the document: fraud passes
    entry = [h for h in B.entries("USD")][0]
    assert entry.a == 1500                                          # true value would have been 1000
    eid = entry.eid
    excess = 1500 - 1000                                            # x = min(max(0, Ar - eps* As), (1 - rho_hat) Ar)
    c.tick(1)
    f = c.make_flag([eid], brec="R", ttl=3600, inj={eid: excess})
    rv = Reversal(c, f, currency="USD")
    rep = rv.run()
    assert rep["identity_ok"]
    assert rep["reversed"] == {"B": 500}                            # only the excess, not the whole debit
    assert rep["metrics"]["RecoveryRate"] == 1
    assert rep["Tb"]["B"] == 0 and rep["Tb"]["R"] == 500
    # B keeps 1000 USD, clean and released
    held = c.held_keys("B")
    rest = [h for h in B.entries("USD") if h.residual()[0] > 0]
    assert sum(h.residual()[0] for h in rest) == 1000
    assert all_monitors(c) == []


def test_check_rate_doc_needs_every_oracle_once():
    c, A, B = two_banks()
    doc = c.rate_doc("NGN/USD", RATE)
    assert check_rate_doc(doc, c.trust, c.clock.now(), 60) is None
    dup = dict(doc, obs=doc["obs"][:-1] + [doc["obs"][0]])
    assert check_rate_doc(dup, c.trust, c.clock.now(), 60) is not None
