"""Local runtime: one OS process per node on localhost ports (spec 2.4). No Docker needed."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import topology as T

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class LocalRuntime:
    def __init__(self, run_dir: str, topo: dict):
        self.run_dir, self.topo = run_dir, topo
        self.procs: dict = {}
        os.makedirs(run_dir, exist_ok=True)
        self.topo_path = os.path.join(run_dir, "topology.json")
        T.save(topo, self.topo_path)

    def _spawn(self, nid: str):
        n = self.topo["nodes"][nid]
        log = open(os.path.join(self.run_dir, f"{nid}.log"), "ab")
        env = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        p = subprocess.Popen([sys.executable, "-m", "sealedtrail.nodes.server", "--role", n["role"], "--id", nid,
                              "--topology", self.topo_path, "--data-dir", os.path.join(self.run_dir, "data", nid)],
                             stdout=log, stderr=log, env=env, cwd=ROOT)
        self.procs[nid] = p

    def up(self, timeout: float = 120.0):
        for nid in self.topo["nodes"]:
            self._spawn(nid)
        self.wait_ready(list(self.topo["nodes"]), timeout)
        with open(os.path.join(self.run_dir, "pids.json"), "w") as f:
            json.dump({k: p.pid for k, p in self.procs.items()}, f)

    def wait_ready(self, ids, timeout: float = 120.0):
        deadline = time.time() + timeout

        def ready(nid):
            url = self.topo["nodes"][nid]["url"] + "/health"
            while time.time() < deadline:
                if self.procs[nid].poll() is not None:
                    raise RuntimeError(f"{nid} exited early; see {self.run_dir}/{nid}.log")
                try:
                    if httpx.get(url, timeout=2.0).status_code == 200:
                        return True
                except httpx.HTTPError:
                    time.sleep(0.2)
            raise TimeoutError(f"{nid} not ready")
        with ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(ready, ids))

    def kill(self, nid: str):
        p = self.procs.get(nid)
        if p and p.poll() is None:
            p.send_signal(signal.SIGKILL)
            p.wait()

    def restart(self, nid: str):
        self.kill(nid)
        self._spawn(nid)
        self.wait_ready([nid])

    def down(self):
        for p in self.procs.values():
            if p.poll() is None:
                p.terminate()
        for p in self.procs.values():
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    # fault injection
    def post(self, nid: str, path: str, body: dict):
        return httpx.post(self.topo["nodes"][nid]["url"] + path, json=body, timeout=10.0)

    def partition(self, *groups):
        """Block traffic between groups (simulated partition: per-process blocklists)."""
        allnodes = set(self.topo["nodes"])
        gs = [set(g) for g in groups]
        for g in gs:
            others = set().union(*[x for x in gs if x is not g])
            for nid in g:
                self.post(nid, "/admin/block", {"nodes": sorted(others)})
        # nodes in no group are isolated from everyone grouped
        loose = allnodes - set().union(*gs)
        for nid in loose:
            self.post(nid, "/admin/block", {"nodes": sorted(set().union(*gs))})

    def heal(self):
        for nid in self.topo["nodes"]:
            if self.procs[nid].poll() is None:
                self.post(nid, "/admin/block", {"nodes": []})
