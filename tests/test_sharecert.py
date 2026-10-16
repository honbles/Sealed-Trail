"""Taint-bound certificates and reserve proofs (sealedtrail/sharecert.py)."""
import random

import pytest

from sealedtrail import crypto as cr
from sealedtrail import sharecert as sc

K = sc.K_DEFAULT
CTX = b"test/sharecert"


def make_event(rng, r_parent, amounts=None):
    amounts = amounts or [rng.randrange(1, 1 << 30) for _ in r_parent]
    blinds = [cr.rand_scalar() for _ in r_parent]
    commits = [cr.commit(a, b) for a, b in zip(amounts, blinds)]
    return amounts, blinds, commits


def honest_r(amounts, r_parent):
    """Least integer r_ev with r_ev * sum(a) >= sum(a_p * r_p): the weighted average of the parents' bounds, rounded up."""
    return -((-sum(a * r for a, r in zip(amounts, r_parent))) // sum(amounts))


def test_honest_certificate_verifies_and_is_small():
    rng = random.Random(1)
    rp = [1 << K, 0, 12345]
    a, b, c = make_event(rng, rp)
    r_ev = honest_r(a, rp)
    proof = sc.prove_certs(CTX, [{"a": a, "blind": b, "r_parent": rp, "r_ev": r_ev}])
    assert sc.verify_certs(CTX, [{"commits": c, "r_parent": rp, "r_ev": r_ev}], proof)
    assert len(proof) < 800


def test_bound_below_weighted_average_cannot_be_proven():
    rng = random.Random(2)
    rp = [1 << K, 0]
    a, b, c = make_event(rng, rp, [1000, 1000])           # true average is 1/2
    low = (1 << K) // 2 - 1
    with pytest.raises(cr.CryptoError):
        sc.prove_certs(CTX, [{"a": a, "blind": b, "r_parent": rp, "r_ev": low}])


def test_proof_for_a_higher_bound_does_not_verify_for_a_lower_one():
    rng = random.Random(3)
    rp = [1 << K, 0]
    a, b, c = make_event(rng, rp, [1000, 1000])
    ok = (1 << K) // 2
    proof = sc.prove_certs(CTX, [{"a": a, "blind": b, "r_parent": rp, "r_ev": ok + 50}])
    assert sc.verify_certs(CTX, [{"commits": c, "r_parent": rp, "r_ev": ok + 50}], proof)
    assert not sc.verify_certs(CTX, [{"commits": c, "r_parent": rp, "r_ev": ok - 1}], proof)
    assert not sc.verify_certs(CTX, [{"commits": c, "r_parent": [rp[0], 5], "r_ev": ok + 50}], proof)   # wrong parent bound
    assert not sc.verify_certs(b"other", [{"commits": c, "r_parent": rp, "r_ev": ok + 50}], proof)       # wrong context


def test_wraparound_is_not_a_way_out():
    """A negative N would wrap to a huge u64 and must not verify; an honest-looking forged commitment is rejected."""
    rng = random.Random(4)
    rp = [1 << K, 0]
    a, b, c = make_event(rng, rp, [1000, 1000])
    forged = cr.rand_scalar()
    proof = cr.prove_range(CTX, [5], [forged])                      # proof about some other commitment
    assert not sc.verify_certs(CTX, [{"commits": c, "r_parent": rp, "r_ev": 1}], proof)


def test_aggregated_certificates():
    rng = random.Random(5)
    evs, pub = [], []
    for _ in range(16):
        rp = [rng.randrange(0, (1 << K) + 1) for _ in range(rng.randrange(1, 4))]
        a, b, c = make_event(rng, rp)
        r = honest_r(a, rp)
        evs.append({"a": a, "blind": b, "r_parent": rp, "r_ev": r})
        pub.append({"commits": c, "r_parent": rp, "r_ev": r})
    proof = sc.prove_certs(CTX, evs)
    assert sc.verify_certs(CTX, pub, proof)
    pub[3] = dict(pub[3], r_ev=pub[3]["r_ev"] - 1) if pub[3]["r_ev"] > 0 else pub[3]
    assert not sc.verify_certs(CTX, pub, proof) or evs[3]["r_ev"] == 0


def test_reserve_proof():
    rng = random.Random(6)
    R, rb = 1_000_000, cr.rand_scalar()
    r_e = (1 << K) // 8                                              # reserve = R / 8 = 125,000
    c_flag = cr.commit(R, rb)
    keep = 125_000
    ra = cr.rand_scalar()
    c_after = cr.commit(keep, ra)
    proof = sc.prove_reserve(CTX, keep, ra, R, rb, r_e)
    assert sc.verify_reserve(CTX, c_after, c_flag, r_e, proof)
    with pytest.raises(cr.CryptoError):                               # spending into the reserve
        sc.prove_reserve(CTX, keep - 1, ra, R, rb, r_e)
    c_less = cr.commit(keep - 1, ra)
    assert not sc.verify_reserve(CTX, c_less, c_flag, r_e, proof)
