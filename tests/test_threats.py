"""M7: threat classes 3, 6, 9, 12, 14, 15 and T-DISC-1, plus the coverage matrix for all 15 rows
of Table 6. 'boundary' tests assert the documented non-guarantee: the attack is NOT stopped."""
import itertools
import sqlite3
from fractions import Fraction as F

import pytest

from sealedtrail import cbor, monitors
from sealedtrail.bank import PaymentFailed
from sealedtrail.builder import build_spend
from sealedtrail.shadow import ShadowLedger
from sealedtrail.sim import Cluster
from sealedtrail.valid import validate, Invalid
from test_engine import run

# coverage matrix (F16)
COVERAGE = {
    1: ("pass", "test_valid.py (fabricated amounts/parents, GEN over Amax, rid/nu locks), test_spend.py"),
    2: ("pass", "test_valid.py::test_v2_revoked_bank_and_token_before_revocation (residual risk accepted)"),
    3: ("boundary", "test_threats.py::test_class3 (not detected, by design)"),
    4: ("pass", "test_valid.py replay of rid/nu, test_abort.py idempotent re-sign"),
    5: ("pass", "test_valid.py (missing, unfinalized, wrong-owner parent)"),
    6: ("pass", "test_spend.py + test_threats.py::test_class6 (grinding)"),
    7: ("pass", "test_live.py (stale token) + test_abort.py (existing locks still re-sign)"),
    8: ("pending", "needs V4 and oracles (not built)"),
    9: ("pass", "test_partition.py + test_threats.py::test_class9 sweep"),
    10: ("pass", "test_reversal.py (lying opening, refusal, refusal by both sides, REV not compelled)"),
    11: ("partial", "test_engine.py (EXT/ANC both orders, clean attestation, expiry). Cross-bank split and steering: pending"),
    12: ("boundary", "test_threats.py::test_class12 (single-key NA; FROST threshold pending)"),
    13: ("pass", "test_flags.py (scope, t_reg, unregistered/regulator release, expiry, release)"),
    14: ("pass", "test_threats.py::test_class14 (< m_t forged, skew, m_t boundary)"),
    15: ("partial", "test_threats.py::test_class15 (dust, floor bound, poisoning measured); poisoning stays open"),
}


def test_coverage_matrix_lists_all_15_classes():
    assert sorted(COVERAGE) == list(range(1, 16))
    assert {v[0] for v in COVERAGE.values()} <= {"pass", "partial", "boundary", "pending"}


def check(c, e):
    v = next(iter(c.validators.values()))
    return validate(e, v.store, c.P, c.trust)


# class 3
def test_class3_collusion_with_consistent_fictitious_flows_is_not_detected():
    sh = ShadowLedger({"NGN": 100})
    c = Cluster("min", banks=("A", "B"), shadow=sh)
    A, B = c.banks["A"], c.banks["B"]
    A.onboard("a", 500_000); B.onboard("b", 500_000)
    for _ in range(5):
        c.tick(1); assert A.pay("a", "B", "b", 120_000).ok
        c.tick(1); assert B.pay("b", "A", "a", 120_000).ok
    # every event is valid and finalized; no monitor, validator or rule distinguishes the churn
    assert monitors.all_monitors(c) == [] and sh.check() == []
    assert A.customers["a"] == 500_000 and B.customers["b"] == 500_000     # a documented non-guarantee


# class 6
def test_class6_free_field_grinding_gains_nothing():
    """A lowest-hash tiebreak would be grindable; quorum locks decide by first lock, so a
    double spend whose id is lower than the honest one still loses (and vice versa)."""
    for honest_first in (True, False):
        c = Cluster("dev", banks=("A", "B", "C"))
        A = c.banks["A"]
        A.onboard("a", 500_000); c.tick(1)
        h = A.entries()[0]
        mk = lambda amt, dst: build_spend(A.kp, "A", c.P, "NGN", [(h, amt)], [(dst, amt)], 0, c.token).event
        first = mk(1000, "B")
        ground, tries = mk(2000, "C"), 1
        while (ground.id < first.id) != honest_first:      # grind the free fields (blinding) for the order we want
            ground, tries = mk(2000, "C"), tries + 1
            assert tries < 200
        assert c.submit("A", first).ok
        r = c.submit("A", ground)
        assert not r.ok and set(r.reasons.values()) == {"LOCKED"}
        assert (ground.id < first.id) == honest_first                    # the grind produced the intended hash order, and it did not matter
        assert monitors.all_monitors(c) == []


# class 9
@pytest.mark.parametrize("prof,major", [("dev", 7), ("dev", 6), ("dev", 5), ("dev", 4),
                                        ("k5f1", 5), ("k5f1", 4), ("k5f1", 3),
                                        ("k5f0", 4), ("k5f0", 3), ("k5f0", 2)])
def test_class9_partition_sweep_finalizes_iff_group_has_q(prof, major):
    c = Cluster(prof, banks=("A", "B"))
    c.banks["A"].onboard("a", 500_000); c.tick(1)
    vids = list(c.validators)
    c.net.partition(set(vids[:major]) | {"A", "B"}, set(vids[major:]))
    res = c.banks["A"].pay("a", "B", "b", 5_000)
    assert res.ok == (major >= c.P.q), (prof, major, c.P.q)


# class 12
def test_class12_na_compromise_is_a_boundary_not_a_protection():
    """The prototype NA is a single Ed25519 key: whoever holds it can attest any reserve and
    mint without bound. The threshold claim (2 shares cannot sign, tau can) needs FROST."""
    c = Cluster("min", banks=("A",))
    A = c.banks["A"]
    rid, att = c.na.attest("NGN", 10 ** 15)                          # an attacker with the NA key
    from sealedtrail.builder import build_gen
    g = build_gen(A.kp, "A", c.P, "NGN", 10 ** 14, rid, 10 ** 15, att, 0, c.token).event
    assert "ttok" in check(c, g)                                     # accepted: nothing stops it
    assert c.submit("A", g).ok


@pytest.mark.skip(reason="threshold (tau, n) NA with FROST is not built; class 12 stays a documented boundary")
def test_class12_two_shares_cannot_sign():
    pass


# class 14
def test_class14_tsa_compromise():
    c = Cluster("dev", banks=("A", "B"))                              # n_tsa = 3, m_tsa = 2
    A = c.banks["A"]
    A.onboard("a", 500_000); c.tick(10)
    h = A.entries()[0]
    def ev(tsas):
        return build_spend(A.kp, "A", c.P, "NGN", [(h, 500)], [("B", 500)], 0,
                           lambda eid: c.token(eid, tsas)).event
    # fewer than m_t compromised authorities cannot forge a token (one valid signature only)
    c.tsas[0].offset = -3
    with pytest.raises(Invalid) as ei:
        check(c, ev([c.tsas[0]]))
    assert ei.value.code == "TOKEN"
    # skew beyond delta_skew between authorities: rejected
    c.tsas[0].offset = 0; c.tsas[1].offset = c.P.delta_skew + 8
    with pytest.raises(Invalid) as ei:
        check(c, ev([c.tsas[0], c.tsas[1]]))
    assert ei.value.code == "TOKEN"
    # a compromised and an honest authority that disagree beyond skew: rejected
    c.tsas[1].offset = 0; c.tsas[2].offset = -(c.P.delta_skew + 3)
    with pytest.raises(Invalid):
        check(c, ev([c.tsas[0], c.tsas[2]]))
    # boundary: m_t compromised authorities that agree can back-date within the window
    c.tsas[0].offset = c.tsas[1].offset = -3
    forged = ev([c.tsas[0], c.tsas[1]])
    assert check(c, forged)["ttok"] == int(c.clock.now()) - 3         # accepted: the documented boundary


# class 15
def test_class15_dust_floor_and_live_entries_bound():
    sh = ShadowLedger({"NGN": 100})
    c = Cluster("min", banks=("A", "B"), shadow=sh)
    A = c.banks["A"]
    A.onboard("a", 100_000); c.tick(1)
    with pytest.raises(PaymentFailed):
        A.pay("a", "B", "b", 50)                                      # below the dust floor: never built
    A.rehome("NGN", amount=100_000, split=[100] * 30 + [97_000])      # many entries at the floor
    assert sh.live("NGN") <= sh.supply["NGN"] // 100 and sh.check() == []
    assert monitors.all_monitors(c) == []


def test_class15_poisoning_holds_whole_entries_however_small_rho_is():
    """A poisoner sends a small tainted payment to a victim bank; the victim's own debit pools it
    with a large clean entry, and the whole output is Held although rho is tiny. Dilution bounds the
    eventual reversal amount, not the temporary hold (paper: open problem, measurement 9)."""
    c = Cluster("dev", banks=("X", "V", "W"))
    X, V, W = (c.banks[n] for n in "XVW")
    root = X.onboard("dirty", 300)
    V.onboard("v", 1_000_000); W.onboard("w", 1_000)
    c.tick(1)
    assert X.pay("dirty", "V", "v", 150).ok                           # the poison: 150 of flagged value
    c.tick(1)
    assert V.pay("v", "W", "w", 1_000_150).ok                         # victim pools clean + tainted
    out = [h for h in W.entries() if h.a == 1_000_150][0]
    c.tick(1)
    f = c.make_flag([root]); c.set_jurisdiction("J1", banks=("X", "V", "W")); f = c.make_flag([root])
    c.submit_flag(f)
    assert len(c.held_at(out.eid)) == c.P.k                            # the whole 1,000,150 entry is Held
    eng = run(c, [root])
    ent = eng.entries[(out.eid, 0)]
    assert ent.rho == F(150, 1_000_150) and ent.rho * ent.A == 150    # tiny rho: only 150 of mass
    assert eng.Tb("W") == 150                                          # the eventual reversal is bounded by it


# T-DISC-1
def scan_store(conn, secrets: dict):
    """Search every cell of every table for any secret pattern. Returns (table, label) hits."""
    hits = []
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for t in tables:
        for row in conn.execute(f"SELECT * FROM {t}"):
            for cell in row:
                blob = cell if isinstance(cell, (bytes, bytearray)) else (cell.encode() if isinstance(cell, str) else None)
                for label, pat in secrets.items():
                    if label.startswith("int:"):                      # integer secret: compare integer cells only
                        if isinstance(cell, int) and cell == int(label[4:]):
                            hits.append((t, label))
                    elif blob is not None and pat and pat in blob:     # byte pattern: search blobs and strings only
                        hits.append((t, label))
    return hits


def secrets_of(c, extra_names=()):
    out = {}
    for b in c.banks.values():
        for key, (a, r) in b.openings.items():
            if a >= 10_000:                                            # skip small ints that collide with public fields
                out[f"amount-cbor:{a}"] = cbor.encode(a)
                out[f"amount-be8:{a}"] = a.to_bytes(8, "big")
                out[f"int:{a}"] = b""
            out[f"blind-le:{r:x}"[:24]] = r.to_bytes(32, "little")
            out[f"blind-be:{r:x}"[:24]] = r.to_bytes(32, "big")
    for n in extra_names:
        out[f"name:{n}"] = n.encode()
    return out


def test_disc1_no_amounts_blindings_or_wallets_in_public_state():
    c = Cluster("min", banks=("A", "B"))
    A, B = c.banks["A"], c.banks["B"]
    A.onboard("alice-secret", 523_771); B.onboard("bob-secret", 88_417)
    c.tick(1); A.pay("alice-secret", "B", "carol-secret", 123_457, advice={"ref": "inv-secret-9"})
    c.tick(1); B.exit("bob-secret", 20_011)
    secrets = secrets_of(c, ("alice-secret", "bob-secret", "carol-secret", "inv-secret-9"))
    assert len(secrets) > 10
    for v in c.validators.values():
        assert scan_store(v.store.conn, secrets) == []


def test_disc1_scanner_detects_a_planted_leak():
    """Control: the scanner must find an amount and a blinding if one is stored."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t(x BLOB, y INTEGER)")
    conn.execute("INSERT INTO t VALUES(?,?)", (b"prefix" + cbor.encode(523_771) + b"suffix", 5))
    conn.execute("INSERT INTO t VALUES(?,?)", (b"\x01" * 32, 523_771))
    secrets = {"amount-cbor": cbor.encode(523_771), "int:523771": b"", "blind": b"\x01" * 32}
    assert {h[1] for h in scan_store(conn, secrets)} == {"amount-cbor", "int:523771", "blind"}
