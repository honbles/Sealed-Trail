"""T-PART-1..3 (Proposition 11): only a group with >= q validators finalizes; nothing finalized
is ever displaced; events without Q(e) are never merged. Runs on the network shim."""
import pytest

from sealedtrail import monitors
from sealedtrail.sim import Cluster


def split(c, n_major, banks_major=("A",), banks_minor=("B", "C")):
    vids = list(c.validators)
    c.net.partition(set(vids[:n_major]) | set(banks_major), set(vids[n_major:]) | set(banks_minor))
    return vids[:n_major], vids[n_major:]


def setup(prof):
    c = Cluster(prof, banks=("A", "B", "C"))
    for n in "ABC":
        c.banks[n].onboard(f"{n}1", 300_000)
    c.tick(1)
    return c


def test_part1_only_the_group_with_q_finalizes_and_nothing_is_displaced():
    c = setup("dev")                                    # k=7, q=5: split (5, 2)
    before = set().union(*(v.store.ids() for v in c.validators.values()))
    major, minor = split(c, 5)
    ra = c.banks["A"].pay("A1", "B", "B1", 5_000)       # A is with the 5 validators
    rb = c.banks["B"].pay("B1", "C", "C1", 7_000)       # B is with the 2 validators
    assert ra.ok and not rb.ok
    eb = next(iter(c.banks["B"].pending))
    assert all(not v.store.has_event(eb) for v in c.validators.values())     # never merged
    c.net.heal()
    c.sync_all()
    final = set(c.validators["val-00"].store.ids())
    assert before <= final                                                   # nothing displaced
    assert all(v.store.ids() == final for v in c.validators.values())        # replicas converge
    assert eb not in final                                                   # unfinalized stays out
    assert c.banks["A"].flush_outbox() and c.banks["B"].customers.get("B1") == 300_000 + 5_000
    # the minority bank recovers: its event is retried after the heal (idempotent re-sign)
    assert c.banks["B"].retry_pending()[0].ok
    assert monitors.all_monitors(c) == []


def test_part2_no_group_reaches_q():
    c = setup("dev")
    split(c, 4)                                          # (4, 3) with q = 5
    assert not c.banks["A"].pay("A1", "B", "B1", 5_000).ok
    assert not c.banks["B"].pay("B1", "C", "C1", 5_000).ok
    c.net.heal()
    c.sync_all()
    assert monitors.all_monitors(c) == []


@pytest.mark.parametrize("prof,major,expect_major", [("k5f1", 3, False), ("k5f0", 3, True)])
def test_part3_k5_three_two_split(prof, major, expect_major):
    c = setup(prof)
    split(c, major)
    ra = c.banks["A"].pay("A1", "B", "B1", 5_000)
    rb = c.banks["B"].pay("B1", "C", "C1", 5_000)
    assert ra.ok == expect_major and not rb.ok           # f=1: q=4 -> nothing; f=0: q=3 -> larger side
    c.net.heal()
    c.sync_all()
    assert monitors.all_monitors(c) == []
