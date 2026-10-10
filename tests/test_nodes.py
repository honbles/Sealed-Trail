"""M2 over real HTTP: validators, banks, TSAs, NA and TIV as separate processes (local runtime).

Slow (about a minute): marked `nodes`. Run with `pytest -m nodes` or the whole suite.
"""
import subprocess
import sys
import time

import httpx
import pytest

from sealedtrail.nodes import topology as T
from sealedtrail.nodes.driver import HttpDriver
from sealedtrail.nodes.runtime import LocalRuntime, ROOT

pytestmark = pytest.mark.nodes


@pytest.fixture(scope="module")
def net(tmp_path_factory):
    topo = T.make_topology(runtime="local", banks=3, accounts_per_bank=2, validators=4, byzantine=1,
                           seed="nodes-test", base_port=9400)
    rt = LocalRuntime(str(tmp_path_factory.mktemp("run")), topo)
    rt.up()
    drv = HttpDriver(topo)
    for bi in range(3):
        for aj in range(2):
            assert drv.onboard(bi, aj, 1_000_000)["ok"]
    yield rt, drv
    drv.close()
    rt.down()


def test_payments_and_independent_reverification(net):
    rt, drv = net
    for i in range(6):
        r = drv.pay(i % 3, 0, (i + 1) % 3, 1, 700 + i)
        assert r["ok"], r
    drv.flush_all()
    viol, reps = drv.monitors()          # every event re-verified from scratch from each validator's dump
    assert viol == []
    assert all(drv.status(b)["reconciled"] for b in range(3))


def test_intra_bank_is_not_a_network_event(net):
    rt, drv = net
    before = [httpx.get(rt.topo["nodes"][v]["url"] + "/v1/stats").json()["events"] for v in rt.topo["validators"]]
    assert drv.pay(0, 0, 0, 1, 500)["ok"]
    after = [httpx.get(rt.topo["nodes"][v]["url"] + "/v1/stats").json()["events"] for v in rt.topo["validators"]]
    assert before == after


def test_one_crashed_validator_does_not_stop_finality_and_catches_up(net):
    rt, drv = net
    rt.kill("val-03")
    for i in range(3):
        assert drv.pay(0, 0, 1, 0, 600 + i)["ok"]       # k=4, f=1, q=3: three validators suffice
    rt.restart("val-03")
    r = httpx.post(rt.topo["nodes"]["val-03"]["url"] + "/v1/sync", json={}, timeout=60).json()
    assert r["pulled"] >= 3
    viol, reps = drv.monitors()
    assert viol == []
    ids = [rep.store.ids() for rep in reps]
    assert ids[3] == ids[0]                               # recovered validator converged (Corollary 10)


def test_partition_blocks_finality_then_heal_recovers(net):
    rt, drv = net
    nodes = set(rt.topo["nodes"])
    minority = {"val-02", "val-03"}
    rt.partition(nodes - minority, minority)
    r = drv.pay(1, 0, 2, 0, 900)
    assert r["ok"] is False                               # only 2 of q=3 validators reachable
    assert drv.status(1)["pending"] == 1
    rt.heal()
    res = httpx.post(rt.topo["nodes"]["bank-0001"]["url"] + "/v1/retry", json={}, timeout=60).json()
    assert res["results"][0]["ok"] is True                # idempotent re-sign, then finalizes
    drv.flush_all()
    viol, _ = drv.monitors()
    assert viol == []
    assert all(drv.status(b)["reconciled"] for b in range(3))
    for v in rt.topo["validators"]:                       # catch everyone up before the next test
        httpx.post(rt.topo["nodes"][v]["url"] + "/v1/sync", json={}, timeout=60)


def test_single_worker_enforced(tmp_path):
    topo = T.make_topology(runtime="local", banks=1, validators=4, seed="w", base_port=9700)
    p = str(tmp_path / "t.json")
    T.save(topo, p)
    out = subprocess.run([sys.executable, "-m", "sealedtrail.nodes.server", "--role", "validator", "--id", "val-00",
                          "--topology", p, "--data-dir", str(tmp_path), "--workers", "2"],
                         capture_output=True, text=True, cwd=ROOT, timeout=30)
    assert out.returncode != 0 and "workers must be 1" in (out.stderr + out.stdout)


def test_drive_command_runs_against_a_running_cluster(net, tmp_path):
    """`stctl drive` is what the Docker driver container executes; here it runs against the local cluster."""
    rt, drv = net
    out = subprocess.run([sys.executable, "-m", "sealedtrail.nodes.stctl", "drive", "--topology", rt.topo_path,
                          "--payments", "6", "--workers", "2", "--wait", "30", "--out", str(tmp_path)],
                         capture_output=True, text=True, cwd=ROOT, timeout=200)
    assert out.returncode == 0, out.stdout[-800:] + out.stderr[-800:]
    import json
    res = json.load(open(next(tmp_path.glob("run-*.json"))))
    assert res["reconciled_all_banks"] and res["monitor_violations"] == [] and res["nodes"] == len(rt.topo["nodes"])
