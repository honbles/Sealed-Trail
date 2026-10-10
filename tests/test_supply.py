"""T-SUPPLY-1 (Lemma 5): the M1 supply identity, shadow ledger and live-entry bound hold on
random workloads; also T-CUST-1-style checks that intra-bank payments leave G1 untouched."""
import random

import pytest

from sealedtrail.bank import PaymentFailed
from sealedtrail.sim import Cluster
from sealedtrail.shadow import ShadowLedger
from sealedtrail import monitors

OM = {"NGN": 100, "USD": 100, "EUR": 100}


def run_workload(seed, steps, profile="min", nbanks=4):
    rnd = random.Random(seed)
    sh = ShadowLedger(OM)
    names = [f"B{i}" for i in range(nbanks)]
    c = Cluster(profile, banks=tuple(names), seed=seed, shadow=sh)
    for n in names:
        for k in range(2):
            c.banks[n].onboard(f"{n}-acct{k}", rnd.randrange(5_000, 900_000))
    ops = {"pay": 0, "multi": 0, "exit": 0, "rehome": 0, "internal": 0, "refused": 0}
    for step in range(steps):
        c.tick(rnd.choice([0, 1, 1, 2]))
        src = c.banks[rnd.choice(names)]
        acct = rnd.choice([a for a in src.customers if src.customers[a] > 0] or [None])
        if acct is None:
            continue
        kind = rnd.choice(["pay", "pay", "multi", "exit", "rehome", "internal"])
        try:
            if kind == "pay":
                dst = rnd.choice([n for n in names if n != src.name])
                amt = rnd.randrange(100, max(101, src.customers[acct]))
                src.pay(acct, dst, f"{dst}-acct0", amt)
            elif kind == "multi":
                dsts = rnd.sample([n for n in names if n != src.name], 2)
                total = src.customers[acct]
                a1, a2 = rnd.randrange(100, max(101, total // 3)), rnd.randrange(100, max(101, total // 3))
                src.pay_many(acct, [(dsts[0], f"{dsts[0]}-acct1", a1, None), (dsts[1], f"{dsts[1]}-acct1", a2, None)])
            elif kind == "exit":
                src.exit(acct, rnd.randrange(100, max(101, src.customers[acct] // 2)))
            elif kind == "rehome":
                src.rehome("NGN", split=None)
            else:
                other = rnd.choice(list(src.customers))
                before = {vid: monitors.g1_digest(v.store) for vid, v in c.validators.items()}
                src.transfer(acct, other, rnd.randrange(1, max(2, src.customers[acct])))
                after = {vid: monitors.g1_digest(v.store) for vid, v in c.validators.items()}
                assert before == after            # an intra-bank payment never touches G1
        except PaymentFailed:
            ops["refused"] += 1
            continue
        ops[kind] += 1
        assert monitors.all_monitors(c) == []
        assert sh.check() == []
    return c, sh, ops


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_supply_random_workload(seed):
    c, sh, ops = run_workload(seed, steps=40)
    assert ops["pay"] + ops["multi"] > 0
    # M1 / Lemma 5, per bank and in total
    for n, b in c.banks.items():
        assert b.reconcile("NGN")                                  # M8
        assert b.owned_total("NGN") == sh.owned(n, "NGN")          # banks agree with the plaintext ledger
    assert sh.total("NGN") == sh.supply["NGN"]
    assert sh.live("NGN") <= sh.supply["NGN"] // OM["NGN"]         # M9: live <= S/omega


def test_supply_dev_profile_once():
    c, sh, ops = run_workload(7, steps=15, profile="dev", nbanks=3)
    assert monitors.all_monitors(c) == [] and sh.check() == []


def test_intra_bank_payment_is_not_an_event(cluster):
    A = cluster.banks["A"]
    A.onboard("alice", 500_000)
    A.onboard("bob", 100_000)
    v = next(iter(cluster.validators.values()))
    n_events, d = v.store.event_count(), monitors.g1_digest(v.store)
    A.transfer("alice", "bob", 200_000)
    assert A.customers == {"alice": 300_000, "bob": 300_000}
    assert v.store.event_count() == n_events and monitors.g1_digest(v.store) == d
    assert A.reconcile()
    assert all(h.version == 0 for h in A.entries())              # no version consumed
