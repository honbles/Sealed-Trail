"""T-MERGE-1 (Corollary 10): merge is a union of parent- and version-closed sets:
commutative, associative, idempotent; equal event sets give an identical G1."""
import itertools
import random

from sealedtrail import cbor, monitors
from sealedtrail.model import Event
from sealedtrail.sim import Cluster
from sealedtrail.validator import Ledger


def workload(seed=3):
    rnd = random.Random(seed)
    c = Cluster("min", banks=("A", "B", "C"), seed=seed)
    for n in "ABC":
        c.banks[n].onboard(f"{n}1", 400_000)
    for _ in range(9):
        c.tick(1)
        s, d = rnd.sample("ABC", 2)
        c.banks[s].pay(f"{s}1", d, f"{d}1", rnd.randrange(100, 20_000))
    return c


def closed_subset(src: Ledger, rnd, p=0.6):
    """Random subset closed under parents and earlier versions."""
    keep, order = set(), []
    for seq, wire, cert in src.store.all_events():
        e = Event.from_wire(wire)
        deps = set()
        for par in e.parents:
            deps.add(par.eid)
            for v in range(par.v):
                deps.add(src.store.consumed_by(par.eid, par.j, v))
        if deps <= keep and rnd.random() < p:
            keep.add(e.id)
            order.append((wire, cbor.decode(cert)))
    return order


def replica(c, name, items):
    L = Ledger(name, c.P, c.trust)
    for wire, cert in items:
        L.accept(wire, cert)
    return L


def test_merge_laws():
    c = workload()
    src = next(iter(c.validators.values()))
    rnd = random.Random(11)
    parts = [closed_subset(src, rnd) for _ in range(3)]

    def fresh(i):
        return replica(c, f"r{i}", parts[i])

    def merged(order):
        reps = [fresh(i) for i in range(3)]
        first = reps[order[0]]
        for i in order[1:]:
            first.sync_from(reps[i])
        return first

    results = [merged(o) for o in itertools.permutations(range(3))]
    ids = [r.store.ids() for r in results]
    assert all(x == ids[0] for x in ids)                                   # commutative + associative
    assert len({monitors.g1_digest(r.store) for r in results}) == 1        # equal Fr => identical G1
    r = results[0]
    assert r.sync_from(fresh(1)) == 0 and r.sync_from(r) == 0              # idempotent
    # grow-only: merging never removes an event
    assert r.store.ids() >= fresh(0).store.ids()
    assert monitors.m1_supply_identity(r.store) == [] and monitors.m2_single_spend(r.store) == []


def test_replica_is_parent_and_version_closed():
    c = workload(5)
    src = next(iter(c.validators.values()))
    items = [(w, cbor.decode(ce)) for _, w, ce in src.store.all_events()]
    L = Ledger("r", c.P, c.trust)
    L.fetcher = lambda eid: src.get(eid)
    L.accept(*items[-1])                                    # latest event first: parents fetched
    assert monitors.m2_single_spend(L.store) == []
    for _, wire, _ in L.store.all_events():
        e = Event.from_wire(wire)
        for par in e.parents:
            assert L.store.has_event(par.eid)
            assert all(L.store.consumed_by(par.eid, par.j, v) for v in range(par.v))
