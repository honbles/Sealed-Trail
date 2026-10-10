"""Drivers: the same scenario code runs on `inproc` (library objects) and `local`/`docker` (HTTP)."""
from __future__ import annotations

import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from .. import cbor
from ..model import Event
from ..monitors import m1_supply_identity, m2_single_spend, m5_convergence
from ..validator import Ledger
from . import topology as T


class HttpDriver:
    def __init__(self, topo: dict):
        self.topo = topo
        self.client = httpx.Client(timeout=60.0, limits=httpx.Limits(max_connections=256))
        self.banks = topo["banks"]
        self.m = topo["accounts_per_bank"]
        self.P = T.params_of(topo)
        self.trust = T.trust_of(topo)

    def _url(self, nid):
        return self.topo["nodes"][nid]["url"]

    @staticmethod
    def _json(r, nid, path):
        """Raise an error that names the node, path and status when a reply is not JSON."""
        try:
            return r.json()
        except ValueError:
            raise RuntimeError(f"{nid} {path}: HTTP {r.status_code}, non-JSON body {r.text[:200]!r}") from None

    def _send(self, method, url, **kw):
        """Retry only connections that could not be established (the request was never sent)."""
        for attempt in range(8):
            try:
                return self.client.request(method, url, **kw)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt == 7:
                    raise
                time.sleep(min(0.25 * (2 ** attempt), 4.0))

    def post(self, nid, path, body=None):
        return self._json(self._send("POST", self._url(nid) + path, json=body or {}), nid, path)

    def get(self, nid, path):
        return self._json(self._send("GET", self._url(nid) + path), nid, path)

    def onboard(self, bi: int, aj: int, amount: int, currency="NGN"):
        return self.post(self.banks[bi], "/v1/onboard", {"account": T.acct_id(bi, aj), "amount": amount, "currency": currency})

    def pay(self, sb, sa, db, da, amount, currency="NGN"):
        s, d = self.banks[sb], self.banks[db]
        if sb == db:
            return self.post(s, "/v1/transfer", {"src": T.acct_id(sb, sa), "dst": T.acct_id(db, da), "amount": amount})
        return self.post(s, "/v1/pay", {"src_account": T.acct_id(sb, sa), "dst_bank": d,
                                        "dst_account": T.acct_id(db, da), "amount": amount, "currency": currency})

    def status(self, bi: int):
        return self.get(self.banks[bi], "/v1/status")

    def flush_all(self):
        for b in self.banks:
            self.post(b, "/v1/flush")

    def validator_replicas(self, only=None):
        reps = []
        for vid in (only or self.topo["validators"]):
            led = Ledger(vid, self.P, self.trust)
            after, rows_all = 0, []
            while True:
                r = self._send("GET", self._url(vid) + "/v1/dump", params={"after": after, "limit": 2000})
                rows = cbor.decode(r.content)
                if not rows:
                    break
                rows_all += rows
                after = rows[-1][0]
            pending = rows_all
            while pending:
                nxt = []
                for seq, wire, cert in pending:
                    try:
                        led.accept(wire, cbor.decode(cert))
                    except Exception:
                        nxt.append((seq, wire, cert))
                if len(nxt) == len(pending):
                    raise RuntimeError(f"{vid}: {len(nxt)} events failed independent re-verification")
                pending = nxt
            reps.append(led)
        return reps

    def monitors(self):
        reps = self.validator_replicas()
        out = []
        for r in reps:
            out += m1_supply_identity(r.store) + m2_single_spend(r.store)
        out += m5_convergence(reps)
        return out, reps

    def close(self):
        self.client.close()


class InprocDriver:
    def __init__(self, cluster, banks: list, m: int):
        self.cluster, self.banks, self.m = cluster, banks, m
        self.P = cluster.P

    def onboard(self, bi, aj, amount, currency="NGN"):
        self.cluster.banks[self.banks[bi]].onboard(T.acct_id(bi, aj), amount, currency)
        return {"ok": True}

    def pay(self, sb, sa, db, da, amount, currency="NGN"):
        b = self.cluster.banks[self.banks[sb]]
        if sb == db:
            b.transfer(T.acct_id(sb, sa), T.acct_id(db, da), amount)
            return {"ok": True}
        res = b.pay(T.acct_id(sb, sa), self.banks[db], T.acct_id(db, da), amount, currency)
        return {"ok": bool(res.ok), "wall_ms": res.sim_ms}

    def status(self, bi):
        b = self.cluster.banks[self.banks[bi]]
        return {"reconciled": b.reconcile(), "customers_total": sum(b.customers.values()),
                "owned_total": b.owned_total(), "entries": len(b.holdings), "pending": len(b.pending),
                "outbox": len(b.outbox)}

    def flush_all(self):
        for b in self.cluster.banks.values():
            b.flush_outbox()

    def monitors(self):
        from ..monitors import all_monitors
        return all_monitors(self.cluster), list(self.cluster.validators.values())

    def close(self):
        pass


def run_workload(drv, banks: int, m: int, payments: int, seed: int, initial: int = 1_000_000,
                 workers: int = 8, amount_range=(100, 5000)) -> dict:
    """Onboard every account, run random payments, verify. Returns a results dict."""
    rng = random.Random(seed)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=min(workers, banks)) as ex:
        list(ex.map(lambda bi: [drv.onboard(bi, aj, initial) for aj in range(m)], range(banks)))
    t_onb = time.perf_counter() - t0
    jobs = []
    for _ in range(payments):
        sb, sa = rng.randrange(banks), rng.randrange(m)
        db, da = rng.randrange(banks), rng.randrange(m)
        if (sb, sa) == (db, da):
            db = (db + 1) % banks if banks > 1 else db
        jobs.append((sb, sa, db, da, rng.randint(*amount_range)))
    lat, ok, fail = [], 0, 0

    def do(j):
        t = time.perf_counter()
        try:
            r = drv.pay(*j)
        except Exception as ex:  # noqa
            return False, 0.0, str(ex)
        return bool(r.get("ok", False)), (time.perf_counter() - t) * 1e3, r.get("error")
    t1 = time.perf_counter()
    # payments from one bank are serialized by its lock; parallelism comes from distinct banks
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for good, ms, err in ex.map(do, jobs):
            if good:
                ok += 1
                lat.append(ms)
            else:
                fail += 1
    t_pay = time.perf_counter() - t1
    drv.flush_all()
    stats = [drv.status(b) for b in range(banks)]
    viol, _ = drv.monitors()
    lat.sort()
    pct = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))] if lat else None
    return {
        "banks": banks, "accounts_per_bank": m, "payments_requested": payments, "ok": ok, "failed": fail,
        "onboard_s": round(t_onb, 3), "payments_s": round(t_pay, 3),
        "payments_per_s": round(ok / t_pay, 2) if t_pay else None,
        "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "mean": round(statistics.mean(lat), 2) if lat else None},
        "reconciled_all_banks": all(s["reconciled"] for s in stats),
        "banks_with_pending": sum(1 for s in stats if s.get("pending")),
        "monitor_violations": [list(map(str, v)) for v in viol],
        "note": "wall-clock on this machine; inproc latencies are simulated by the network shim",
    }
