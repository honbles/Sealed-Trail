"""T-ADV-1: settlement advice and the receiver's opening checks (paper section 2)."""
from sealedtrail.bank import advice_hash


def setup(cluster):
    A, B = cluster.banks["A"], cluster.banks["B"]
    A.onboard("alice", 500_000)
    B.onboard("bob", 10_000)
    cluster.tick(1)
    return A, B


def test_honest_delivery_credits_beneficiaries(cluster):
    A, B = setup(cluster)
    res = A.pay("alice", "B", "carol", 120_000, advice={"ref": "invoice-7"})
    assert res.ok
    assert B.customers["carol"] == 120_000 and B.reconcile() and A.reconcile()


def test_wrong_opening_is_rejected_and_not_credited(cluster):
    A, B = setup(cluster)
    A.behavior = "lie_amount"                      # announces one amount, committed another
    res = A.pay("alice", "B", "carol", 120_000)
    assert res.ok                                  # the network accepts the debit
    assert B.rejected and B.rejected[-1][1] == "OPENING"
    assert "carol" not in B.customers              # not credited
    assert B.reconcile()                           # B's books still match what it owns


def test_advice_amount_sum_mismatch_returns_value(cluster):
    A, B = setup(cluster)
    A.behavior = "bad_advice_sum"
    before_B = B.owned_total()
    A.pay("alice", "B", "carol", 120_000)
    assert B.rejected[-1][1] == "ADVICE_SUM"
    assert "carol" not in B.customers
    assert B.owned_total() == before_B             # B returned the value with a new debit
    assert A.owned_total() == 500_000              # and A holds it again
    assert B.reconcile() and A.reconcile()


def test_advice_hash_mismatch_returns_value(cluster):
    A, B = setup(cluster)
    res = A.pay("alice", "B", "carol", 120_000, deliver=False)
    (dst, d), = res.deliveries
    d.advice = {"items": [["mallory", 120_000, ""]], "from": "A"}          # swapped after the fact
    out = A.deliver(dst, d)
    assert out == ("reject", "ADVICE_HASH")
    assert "mallory" not in B.customers and "carol" not in B.customers
    assert B.owned_total() == 10_000               # the 120k went back to A


def test_advice_hash_binds_event_id(cluster):
    A, B = setup(cluster)
    res = A.pay("alice", "B", "carol", 1_000, deliver=False)
    (dst, d), = res.deliveries
    ev, _ = next(iter(cluster.validators.values())).store.get_event(d.event_id)
    assert ev.outputs[0].hadv == advice_hash(d.advice, d.salt)
