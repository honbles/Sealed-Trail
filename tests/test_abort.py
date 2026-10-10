"""T-ABORT-1: lock recovery (paper section 3): idempotent re-sign, abort proofs, equivocation."""
from sealedtrail.builder import build_spend
from sealedtrail.sim import Cluster
from sealedtrail.store import kbytes


def mk(cluster, amt=1000, dst="B", n=0):
    A = cluster.banks["A"]
    if not A.entries():
        A.onboard("a", 500_000)
        cluster.tick(1)
    h = A.entries()[0]
    return build_spend(A.kp, "A", cluster.P, "NGN", [(h, amt)], [(dst, amt)], 0, cluster.token).event


def locked_at(c, e):
    k = kbytes(e.keys()[0])
    return [vid for vid, v in c.validators.items() if v.store.get_lock(k) == e.id]


def test_lost_replies_are_recovered_by_idempotent_resign():
    c = Cluster("dev", banks=("A", "B"))
    e = mk(c)
    for vid in list(c.validators)[:c.P.q]:              # q validators lock; the owner loses every reply
        assert c.validators[vid].request_lock(e.to_wire())[0] == "ok"
    c.tick(c.P.delta_stale + 10)                        # the token is now stale everywhere
    res = c.submit("A", e)                              # re-sign works whatever the token age
    assert res.ok


def test_abort_proof_all_honest_best_case():
    c = Cluster("dev", banks=("A", "B"))                # k=7, f=2, q=5: need 5 statements
    e = mk(c)
    S = list(c.validators)[:2]                          # e reached only 2 validators
    assert not c.submit("A", e, to=S).ok
    assert len(locked_at(c, e)) == 2
    c.tick(c.P.delta_stale + 5)
    out = c.abort("A", e)
    assert out["statements"] >= out["needed"] and set(out["applied_at"]) == set(c.validators)
    assert locked_at(c, e) == []                        # keys freed; e can never finalize (stale)
    assert not c.submit("A", e).ok
    c.banks["A"].abandon(e.id) if e.id in c.banks["A"].pending else None
    e2 = mk(c, 1500)                                    # a fresh event on the same key now works
    assert c.submit("A", e2).ok


def test_abort_fails_when_too_many_signed_keys_stay_locked():
    c = Cluster("dev", banks=("A", "B"))
    e = mk(c)
    assert not c.submit("A", e, to=list(c.validators)[:3]).ok       # 3 signers: only 4 non-signers < 5
    c.tick(c.P.delta_stale + 5)
    out = c.abort("A", e)
    assert out["statements"] < out["needed"] and out["applied_at"] == []
    assert len(locked_at(c, e)) == 3                    # stays locked (documented residual, Table 9)
    e2 = mk(c, 1500)
    assert not c.submit("A", e2).ok                     # 3 locked + 4 free = 4 < q: stuck


def test_equivocating_owner_stays_locked():
    c = Cluster("dev", banks=("A", "B", "C"))
    e1 = mk(c, 1000, "B")
    e2 = mk(c, 2000, "C")
    vids = list(c.validators)
    assert not c.submit("A", e1, to=vids[:3]).ok
    assert not c.submit("A", e2, to=vids[3:]).ok         # 3 vs 4: neither reaches q = 5
    c.tick(c.P.delta_stale + 5)
    assert c.abort("A", e1)["applied_at"] == [] and c.abort("A", e2)["applied_at"] == []
    e3 = mk(c, 3000)
    assert not c.submit("A", e3).ok                      # until validator reconfiguration (unspecified)


def test_k_equals_3f_plus_1_guaranteed_range_is_zero_but_best_case_is_one():
    # guaranteed range q-2f-1 = 0: a silent/crashed Byzantine validator blocks the abort proof
    c = Cluster("min", banks=("A", "B"))                 # k=4, f=1, q=3, need 3 statements
    e = mk(c)
    first = list(c.validators)[0]
    assert not c.submit("A", e, to=[first]).ok           # 1 honest validator signed
    c.tick(c.P.delta_stale + 5)
    c.net.crash(list(c.validators)[3])                   # the Byzantine validator does not respond
    assert c.abort("A", e)["applied_at"] == []
    # best case (everyone responds): q-f-1 = 1 honest lock can be freed
    c.net.restart(list(c.validators)[3])
    out = c.abort("A", e)
    assert first in out["applied_at"] and locked_at(c, e) == []
