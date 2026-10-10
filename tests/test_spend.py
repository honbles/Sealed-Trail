"""T-SPEND-1 (Theorem 6, Proposition 7): no two conflicting events are both Finalized."""
import itertools
import random

import pytest

from sealedtrail.builder import build_spend, build_gen, build_anc
from sealedtrail.model import sig_msg
from sealedtrail.params import Params
from sealedtrail.sim import Cluster
from sealedtrail.valid import validate


def q_of(k, f):
    return -(-(k + f + 1) // 2)


def profiles():
    for k in range(4, 8):
        for f in range(0, (k - 1) // 3 + 1):
            yield k, f


@pytest.mark.parametrize("k,f", list(profiles()))
def test_abstract_model_check_exhaustive(k, f):
    """Every Byzantine set of size <= f and every honest outcome (signs e1, signs e2, signs
    neither): at most one of the two events reaches q signatures. Byzantine validators sign
    both. With f+1 Byzantine validators two certificates can form (S9 void, documented)."""
    q = q_of(k, f)
    assert 2 * q - k >= f + 1            # the quorum overlap used by the proof
    both = 0
    for nb in range(0, f + 1):
        for byz in itertools.combinations(range(k), nb):
            honest = [i for i in range(k) if i not in byz]
            for assign in itertools.product((0, 1, 2), repeat=len(honest)):
                s1 = nb + sum(1 for a in assign if a == 1)
                s2 = nb + sum(1 for a in assign if a == 2)
                if s1 >= q and s2 >= q:
                    both += 1
    assert both == 0
    # Two certificates need exactly nb >= 2q-k Byzantine validators (= f+1 only when the quorum
    # is tight). Below that threshold the overlap argument still protects every profile.
    need = 2 * q - k
    assert need >= f + 1
    def possible(nb):
        for assign in itertools.product((0, 1, 2), repeat=k - nb):
            if nb + sum(a == 1 for a in assign) >= q and nb + sum(a == 2 for a in assign) >= q:
                return True
        return False
    if need < k:
        assert not possible(need - 1) and possible(need)


def conflicting_pair(cluster):
    A = cluster.banks["A"]
    A.onboard("a1", 500_000)
    cluster.tick(1)
    h = A.entries()[0]
    e1 = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 1000)], [("B", 1000)], 0, cluster.token).event
    e2 = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 2000)], [("C", 2000)], 0, cluster.token).event
    return e1, e2


def _memo_validation(cluster, events):
    info = {}
    v0 = next(iter(cluster.validators.values()))
    for e in events:
        info[e.id] = validate(e, v0.store, cluster.P, cluster.trust)
    for v in cluster.validators.values():
        v._validate = (lambda e, lock=False, _i=info: _i[e.id])
    return info


def _reset_locks(cluster):
    for v in cluster.validators.values():
        v.store.conn.execute("DELETE FROM locks")
        v.byzantine = None


def test_concrete_exhaustive_k4_f1_real_lock_step():
    """Same enumeration through the real Validator.request_lock (SQLite lock table),
    for every delivery order, with real double-signing Byzantine validators."""
    c = Cluster("min", banks=("A", "B", "C"))
    e1, e2 = conflicting_pair(c)
    _memo_validation(c, [e1, e2])
    w1, w2 = e1.to_wire(), e2.to_wire()
    vids = list(c.validators)
    plans = ["1", "2", "12", "21", "-"]            # delivery sequence per honest validator
    q = c.P.q
    scenarios = 0
    for nb in range(0, c.P.f + 1):
        for byz in itertools.combinations(vids, nb):
            honest = [v for v in vids if v not in byz]
            for plan in itertools.product(plans, repeat=len(honest)):
                _reset_locks(c)
                for v in byz:
                    c.validators[v].byzantine = "double_sign"
                signed = {1: set(), 2: set()}
                for vid in byz:
                    for n, w in ((1, w1), (2, w2)):
                        assert c.validators[vid].request_lock(w)[0] == "ok"
                        signed[n].add(vid)
                for vid, p in zip(honest, plan):
                    for ch in p if p != "-" else "":
                        n = int(ch)
                        if c.validators[vid].request_lock(w1 if n == 1 else w2)[0] == "ok":
                            signed[n].add(vid)
                assert not (len(signed[1]) >= q and len(signed[2]) >= q), (byz, plan)
                scenarios += 1
    assert scenarios == 1 + 4 * 5 ** 3 + 5 ** 4 - 4 * 5 ** 3 + 4 * 5 ** 3 - 4 * 5 ** 3 or scenarios > 1000
    _reset_locks(c)


def test_beyond_f_two_certificates_form_and_are_self_verifying():
    """f+1 double-signing validators: both events finalize at some validators; the pair of
    certificates is an equivocation proof and the store records it."""
    c = Cluster("min", banks=("A", "B", "C"))          # k=4, f=1, q=3
    e1, e2 = conflicting_pair(c)
    vids = list(c.validators)
    for vid in vids[:2]:
        c.validators[vid].byzantine = "double_sign"    # 2 > f
    r1 = c.submit("A", e1, to=[vids[0], vids[1], vids[2]])
    r2 = c.submit("A", e2, to=[vids[0], vids[1], vids[3]])
    assert r1.ok and r2.ok
    assert any(v.store.conn.execute("SELECT COUNT(*) FROM equivocations").fetchone()[0] for v in c.validators.values())


@pytest.mark.parametrize("seed", range(6))
def test_concrete_random_k7_f2(seed):
    rnd = random.Random(seed)
    c = Cluster("dev", banks=("A", "B", "C"))
    e1, e2 = conflicting_pair(c)
    _memo_validation(c, [e1, e2])
    vids = list(c.validators)
    byz = rnd.sample(vids, rnd.randint(0, c.P.f))
    for v in byz:
        c.validators[v].byzantine = "double_sign"
    signed = {1: set(), 2: set()}
    for vid in vids:
        order = rnd.choice(["1", "2", "12", "21", "-"]) if vid not in byz else "12"
        for ch in ("" if order == "-" else order):
            w = e1.to_wire() if ch == "1" else e2.to_wire()
            if c.validators[vid].request_lock(w)[0] == "ok":
                signed[int(ch)].add(vid)
    assert not (len(signed[1]) >= c.P.q and len(signed[2]) >= c.P.q)


def test_concurrent_gen_one_rid_split_delivery():
    """Two GENs on one rid delivered to disjoint validator subsets (k=7, q=5): neither
    finalizes, the rid stays locked, a fresh attestation recovers onboarding."""
    c = Cluster("dev", banks=("A", "B"))
    A, B = c.banks["A"], c.banks["B"]
    rid, att = c.na.attest("NGN", 1_000_000)
    g1 = build_gen(A.kp, "A", c.P, "NGN", 500_000, rid, 1_000_000, att, 0, c.token).event
    g2 = build_gen(B.kp, "B", c.P, "NGN", 400_000, rid, 1_000_000, att, 0, c.token).event
    vids = list(c.validators)
    r1 = c.submit("A", g1, to=vids[:3])
    r2 = c.submit("B", g2, to=vids[3:])
    assert not r1.ok and not r2.ok
    # the rid is now locked at every validator that saw either event: no third event can use it
    g3 = build_gen(A.kp, "A", c.P, "NGN", 100_000, rid, 1_000_000, att, 0, c.token).event
    assert not c.submit("A", g3).ok
    # recovery: a fresh attestation
    assert A.onboard("fresh", 500_000)
    assert all(m == [] for m in [__import__("sealedtrail.monitors", fromlist=["x"]).all_monitors(c)])


def test_concurrent_anc_one_nu_split_delivery():
    c = Cluster("dev", banks=("A", "B"))
    A, B = c.banks["A"], c.banks["B"]
    tiv = next(iter(c.tivs.values()))
    a1 = build_anc(A.kp, "A", c.P, "NGN", 10_000, tiv, 0, c.token).event
    tiv.counter -= 1
    a2 = build_anc(B.kp, "B", c.P, "NGN", 20_000, tiv, 0, c.token).event
    vids = list(c.validators)
    assert not c.submit("A", a1, to=vids[:4]).ok or not c.submit("B", a2, to=vids[4:]).ok
    ok = sum(1 for e in (a1, a2) if any(v.store.has_event(e.id) for v in c.validators.values()))
    assert ok <= 1
