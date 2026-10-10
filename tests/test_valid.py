"""T-VALID-n: one negative test per clause of Valid(e) (paper V1-V5, Algorithm 1)."""
import os
import pytest

from sealedtrail import crypto as C
from sealedtrail.builder import Holding, build_gen, build_anc, build_spend
from sealedtrail.model import GEN, ANC, DEB, sig_msg
from sealedtrail.valid import validate, Invalid, NeedParents
from forge import forge_deb, reseal, junk_proof


def check(cluster, e):
    v = next(iter(cluster.validators.values()))
    return validate(e, v.store, cluster.P, cluster.trust)


def setup(cluster):
    A, B = cluster.banks["A"], cluster.banks["B"]
    A.onboard("a1", 500_000)
    cluster.tick(1)
    return A, B, A.entries()[0]


def test_valid_event_accepts(cluster):
    A, B, h = setup(cluster)
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 1000)], [("B", 1000)], 0, cluster.token)
    assert "ttok" in check(cluster, b.event)


def test_v1_missing_parent(cluster):
    A, B, h = setup(cluster)
    ghost = Holding(os.urandom(32), 0, "A", "NGN", 1000, C.rand_scalar(), b"", [], 0.0, 99)
    ghost.kappa = C.commit(ghost.a, ghost.r)
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(ghost, 500)], [("B", 500)], 0, cluster.token)
    with pytest.raises(NeedParents):
        check(cluster, b.event)


def test_v1_unfinalized_earlier_version(cluster):
    A, B, h = setup(cluster)
    h.cons.append((100, C.rand_scalar()))          # claims version 0 was debited; it was not finalized
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], 0, cluster.token)
    with pytest.raises(NeedParents):
        check(cluster, b.event)
    h.cons.pop()


def test_v1_wrong_owner_parent(cluster):
    A, B, h = setup(cluster)
    b = build_spend(B.kp, "B", cluster.P, "NGN", [(h, 500)], [("C", 500)], 0, cluster.token)
    with pytest.raises(Invalid) as ei:
        check(cluster, b.event)
    assert ei.value.code == "V1_OWNER"


def test_v1_token_earlier_than_parent(cluster):
    A, B, h = setup(cluster)
    for t in cluster.tsas:
        t.offset = -500
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], 0, cluster.token)
    with pytest.raises(Invalid) as ei:
        check(cluster, b.event)
    assert ei.value.code == "V1_TOKEN_ORDER"


def test_v2_stale_epoch(cluster):
    A, B, h = setup(cluster)
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], 7, cluster.token)
    with pytest.raises(Invalid) as ei:
        check(cluster, b.event)
    assert ei.value.code == "V2_EPOCH"


def test_v2_revoked_bank_and_token_before_revocation(cluster):
    A, B, h = setup(cluster)
    t_rev = cluster.clock.now() + 10
    cluster.trust.revoke("A", t_rev, t_rev + 1)
    cluster.tick(20)
    # after revocation, citing the new epoch: revoked
    ep = cluster.trust.epoch_at(cluster.clock.now())
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], ep, cluster.token)
    with pytest.raises(Invalid) as ei:
        check(cluster, b.event)
    assert ei.value.code == "V2_REVOKED"
    # the residual risk of class 2: a token showing tsign < trev is still accepted
    for t in cluster.tsas:
        t.offset = -15
    ep0 = cluster.trust.epoch_at(cluster.clock.now() - 15)
    b2 = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 600)], [("B", 600)], ep0, cluster.token)
    assert "ttok" in check(cluster, b2.event)


def test_bad_signature_and_unknown_issuer(cluster):
    A, B, h = setup(cluster)
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], 0, cluster.token)
    b.event.sig = b"\0" * 64
    with pytest.raises(Invalid) as ei:
        check(cluster, b.event)
    assert ei.value.code == "SIG"
    e = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], 0, cluster.token).event
    e.issuer = "Z"
    reseal(e, A.kp, cluster)
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V2_NO_CERT"


def test_v3_imbalance(cluster):
    A, B, h = setup(cluster)
    e = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 500)], [("B", 500)], 0, cluster.token).event
    from sealedtrail.model import Out
    o = e.outputs[0]
    e.outputs = [Out(o.owner, o.currency, C.padd(o.kappa, C.G), o.hadv)]
    reseal(e, A.kp, cluster)
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V3_BALANCE"


def test_v3_negative_consumed_portion(cluster):
    A, B, h = setup(cluster)
    A.onboard("a2", 400_000)
    h2 = A.entries()[1]
    e = forge_deb(cluster, A, [h, h2], [5000, -5], [("B", 4995)])
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V3_RANGE"


def test_v3_overspend(cluster):
    A, B, h = setup(cluster)
    e = forge_deb(cluster, A, [h], [500_001], [("B", 500_001)])
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    # The sigma-OR proves the selector bit, not the sign. Non-negativity of the new residual
    # comes from the extra range party Cx - omega*Cz in the aggregate proof (D30), so an
    # overspend is rejected at the range stage.
    assert ei.value.code == "V3_RANGE"


def test_v3_residual_below_floor(cluster):
    A, B, h = setup(cluster)
    e = forge_deb(cluster, A, [h], [499_950], [("B", 499_950)])      # leaves 50 < omega = 100
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V3_FLOOR"


def test_v3_output_below_floor(cluster):
    A, B, h = setup(cluster)
    e = forge_deb(cluster, A, [h], [50], [("B", 50)])
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V3_RANGE"


def test_v3_floor_proof_not_replayable_across_parents(cluster):
    A, B, h = setup(cluster)
    A.onboard("a2", 400_000)
    h2 = A.entries()[1]
    b = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 1000), (h2, 1000)], [("B", 2000)], 0, cluster.token)
    e = b.event
    e.floor_proofs = [e.floor_proofs[1], e.floor_proofs[0]]       # swap
    reseal(e, A.kp, cluster)
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V3_FLOOR"


def test_v5_gen_over_amax(cluster):
    A = cluster.banks["A"]
    rid, att = cluster.na.attest("NGN", 1_000_000)
    b = build_gen(A.kp, "A", cluster.P, "NGN", 2_000_000, rid, 1_000_000, att, 0, cluster.token) if False else None
    # an honest prover cannot produce the cap party for a > Amax, so forge it with a junk proof
    ok = build_gen(A.kp, "A", cluster.P, "NGN", 900_000, rid, 1_000_000, att, 0, cluster.token)
    e = ok.event
    e.outputs[0] = type(e.outputs[0])("A", "NGN", C.commit(2_000_000, C.rand_scalar()))
    e.range_proof = junk_proof(500)
    reseal(e, A.kp, cluster)
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V3_RANGE"


def test_v5_bad_attestation_and_tiv(cluster):
    A = cluster.banks["A"]
    rid, att = cluster.na.attest("NGN", 1_000_000)
    e = build_gen(A.kp, "A", cluster.P, "NGN", 500_000, rid, 1_000_000, b"\0" * 64, 0, cluster.token).event
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V5_ATTESTATION"
    tiv = next(iter(cluster.tivs.values()))
    e = build_anc(A.kp, "A", cluster.P, "NGN", 10_000, tiv, 0, cluster.token).event
    e.tiv_sig = b"\0" * 64
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V5_TIV_SIG"
    from sealedtrail.actors import TIV
    rogue = TIV("rogue")
    e = build_anc(A.kp, "A", cluster.P, "NGN", 10_000, rogue, 0, cluster.token).event
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V5_TIV"


def test_bank_cannot_be_its_own_tiv(cluster):
    from sealedtrail.actors import TIV
    A = cluster.banks["A"]
    self_tiv = TIV("A", kp=A.kp)               # the bank's own key posing as a TIV
    e = build_anc(A.kp, "A", cluster.P, "NGN", 10_000, self_tiv, 0, cluster.token).event
    with pytest.raises(Invalid) as ei:
        check(cluster, e)
    assert ei.value.code == "V5_TIV"           # not in the static trust list


def test_replayed_rid_and_nu_are_locked(cluster):
    A, B = cluster.banks["A"], cluster.banks["B"]
    rid, att = cluster.na.attest("NGN", 1_000_000)
    g1 = build_gen(A.kp, "A", cluster.P, "NGN", 500_000, rid, 1_000_000, att, 0, cluster.token).event
    g2 = build_gen(B.kp, "B", cluster.P, "NGN", 400_000, rid, 1_000_000, att, 0, cluster.token).event
    assert cluster.submit("A", g1).ok
    r2 = cluster.submit("B", g2)
    assert not r2.ok                                  # rid already locked to g1 everywhere
    assert set(r2.reasons.values()) == {"LOCKED"}
    # idempotent re-sign of the same event
    v = next(iter(cluster.validators.values()))
    assert v.request_lock(g1.to_wire())[0] == "ok"
    # same for an anchor nonce
    tiv = next(iter(cluster.tivs.values()))
    a1 = build_anc(A.kp, "A", cluster.P, "NGN", 10_000, tiv, 0, cluster.token).event
    tiv.counter -= 1                                  # TIV reuses nu
    a2 = build_anc(B.kp, "B", cluster.P, "NGN", 20_000, tiv, 0, cluster.token).event
    assert a1.nu == a2.nu
    assert cluster.submit("A", a1).ok
    assert not cluster.submit("B", a2).ok


@pytest.mark.skip(reason="REV validity (not Held, over Tb) is M6: needs flags, Hold and openings")
def test_rev_clauses():
    pass
