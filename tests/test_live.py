"""T-LIVE-1 (Theorem 8): an honest owner finalizes iff at least q validators are reachable,
inside Delta_stale. Latency is the simulated network time (not a measurement)."""
import pytest

from sealedtrail.builder import build_spend
from sealedtrail.sim import Cluster


@pytest.mark.parametrize("prof", ["min", "k5f1", "k5f0", "dev"])
def test_finalizes_iff_quorum_reachable(prof):
    for crashed in range(0, Cluster(prof).P.k + 1):
        c = Cluster(prof, banks=("A", "B"))
        c.banks["A"].onboard("a", 500_000)
        c.tick(1)
        for vid in list(c.validators)[:crashed]:
            c.net.crash(vid)
        reach = c.P.k - crashed
        res = c.banks["A"].pay("a", "B", "b", 10_000)
        assert res.ok == (reach >= c.P.q), (prof, crashed)
        if res.ok:
            assert res.sim_ms > 0
    c = Cluster(prof)
    assert c.P.q <= c.P.k - c.P.f                  # Theorem 8's condition


def test_stale_token_is_refused_for_new_locks(cluster):
    A = cluster.banks["A"]
    A.onboard("a", 500_000)
    cluster.tick(1)
    h = A.entries()[0]
    e = build_spend(A.kp, "A", cluster.P, "NGN", [(h, 1000)], [("B", 1000)], 0, cluster.token).event
    cluster.tick(cluster.P.delta_stale + 1)
    res = cluster.submit("A", e)
    assert not res.ok and set(res.reasons.values()) == {"STALE"}
    assert all(v.store.get_lock(__import__("sealedtrail.store", fromlist=["x"]).kbytes(k)) is None
               for v in cluster.validators.values() for k in e.keys())
