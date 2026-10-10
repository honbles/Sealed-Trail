"""One image, one entrypoint: `python -m sealedtrail.nodes.server --role R --id ID --topology F`.

Roles: validator, bank, tsa, na, tiv. Every node serves /health and the simulation
admin endpoints (/admin/clock, /admin/block). Single process, single uvicorn worker:
the validator's lock step is one serialized writer (spec D33); the process refuses to
start with more than one worker.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time

from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .. import cbor
from .. import crypto as C
from ..actors import NA, TSA, TIV
from ..bank import Bank, Delivery, PaymentFailed
from ..store import Store
from ..validator import Validator
from ..valid import Invalid, NeedParents
from . import topology as T
from .context import HttpContext, Unreachable, WallClock

CBOR = "application/cbor"


def _hexitem(x):
    return x.hex() if isinstance(x, bytes) else ["v", x[1].hex(), x[2], x[3]]


class Admin:
    """Simulation admin: clock offset and partition blocklist (shared by all roles)."""

    def __init__(self, clock):
        self.clock = clock
        self.blocked: set = set()


def add_common(app: FastAPI, role: str, node_id: str, admin: Admin):
    @app.middleware("http")
    async def partition(request: Request, call_next):
        src = request.headers.get("X-ST-From")
        if src and src in admin.blocked and not request.url.path.startswith("/admin"):
            return JSONResponse({"error": "partitioned"}, status_code=503)
        return await call_next(request)

    @app.get("/health")
    def health():
        return {"ok": True, "role": role, "id": node_id, "t": admin.clock.now()}

    @app.post("/admin/clock")
    def set_clock(d: dict = Body(...)):
        admin.clock.offset = float(d.get("offset", 0.0))
        return {"offset": admin.clock.offset}

    @app.post("/admin/block")
    def block(d: dict = Body(...)):
        admin.blocked = set(d.get("nodes", []))
        return {"blocked": sorted(admin.blocked)}


# validator
def validator_app(node_id: str, topo: dict, data_dir: str) -> FastAPI:
    P, trust = T.params_of(topo), T.trust_of(topo)
    clock = WallClock()
    admin = Admin(clock)
    kp = T.keypair(topo["seed"], node_id)
    path = os.path.join(data_dir, f"{node_id}.sqlite")
    v = Validator(node_id, kp, P, trust, clock, path)
    wlock = threading.Lock()                       # single writer (D33)
    peers = [i for i in topo["validators"] if i != node_id]
    import httpx
    http = httpx.Client(timeout=10.0)

    def fetcher(item):
        for pid in peers:
            if pid in admin.blocked:
                continue
            if isinstance(item, tuple):
                url = f"{topo['nodes'][pid]['url']}/v1/fetch/v/{item[1].hex()}/{item[2]}/{item[3]}"
            else:
                url = f"{topo['nodes'][pid]['url']}/v1/fetch/e/{item.hex()}"
            try:
                r = http.get(url, headers={"X-ST-From": node_id})
            except httpx.TransportError:
                continue
            if r.status_code == 200:
                d = cbor.decode(r.content)
                return d["wire"], d["cert"]
        return None
    v.fetcher = fetcher

    app = FastAPI(title=f"validator {node_id}")
    add_common(app, "validator", node_id, admin)

    @app.post("/v1/lock")
    def lock(wire: bytes = Body(..., media_type="application/octet-stream")):
        with wlock:
            st, x = v.request_lock(wire)
        if st == "ok":
            return {"status": "ok", "sig": x.hex()}
        if st == "reject":
            return {"status": "reject", "code": x}
        return {"status": "need", "missing": [_hexitem(i) for i in x]}

    @app.post("/v1/finalize")
    def finalize(body: bytes = Body(..., media_type=CBOR)):
        d = cbor.decode(body)
        with wlock:
            try:
                v.finalize(d["wire"], d["cert"])
                return {"ok": True}
            except Invalid as ex:
                return {"ok": False, "code": ex.code}
            except NeedParents:
                return {"ok": False, "code": "NEED_PARENTS"}

    # reads: separate read-only connections, no writer lock (avoids peer-fetch deadlock)
    def reader():
        return Store.reader(path)

    @app.get("/v1/fetch/e/{eid}")
    def fetch_e(eid: str):
        r = reader()
        try:
            got = r.get_event(bytes.fromhex(eid))
        finally:
            r.close()
        if not got:
            raise HTTPException(404)
        return Response(cbor.encode({"wire": got[0].to_wire(), "cert": got[1]}), media_type=CBOR)

    @app.get("/v1/fetch/v/{eid}/{j}/{ver}")
    def fetch_v(eid: str, j: int, ver: int):
        r = reader()
        try:
            by = r.consumed_by(bytes.fromhex(eid), j, ver)
            got = r.get_event(by) if by else None
        finally:
            r.close()
        if not got:
            raise HTTPException(404)
        return Response(cbor.encode({"wire": got[0].to_wire(), "cert": got[1]}), media_type=CBOR)

    @app.get("/v1/entry/{eid}/{j}")
    def entry(eid: str, j: int):
        r = reader()
        try:
            e = r.entry(bytes.fromhex(eid), j)
            ev = r.get_event(bytes.fromhex(eid)) if e else None
        finally:
            r.close()
        if not e:
            raise HTTPException(404)
        h = ev[0].outputs[j].hadv if ev else None
        return {"owner": e["owner"], "currency": e["currency"], "kappa": e["kappa"].hex(),
                "ttok": e["ttok"], "hadv": h.hex() if h else None}

    @app.get("/v1/holds")
    def holds():
        r = reader()
        try:
            rows = r.held_keys(v.clock.now())
        finally:
            r.close()
        return {"holds": [[e.hex(), j] for e, j in rows]}

    @app.get("/v1/meta/{eid}")
    def meta(eid: str):
        r = reader()
        try:
            m = r.event_meta(bytes.fromhex(eid))
        finally:
            r.close()
        if not m:
            raise HTTPException(404)
        return m

    @app.get("/v1/dump")
    def dump(after: int = 0, limit: int = 500):
        r = reader()
        try:
            rows = r.conn.execute("SELECT seq, wire, cert FROM events WHERE seq>? ORDER BY seq LIMIT ?",
                                  (after, limit)).fetchall()
        finally:
            r.close()
        return Response(cbor.encode([[s, w, c] for s, w, c in rows]), media_type=CBOR)

    @app.post("/v1/sync")
    def sync(d: dict = Body(...)):
        """Pull-merge from peers (Corollary 10): fetch every event we lack, parents first."""
        n = 0
        for pid in d.get("peers", peers):
            if pid in admin.blocked:
                continue
            after = 0
            while True:
                try:
                    resp = http.get(f"{topo['nodes'][pid]['url']}/v1/dump", params={"after": after},
                                    headers={"X-ST-From": node_id})
                except httpx.TransportError:
                    break
                rows = cbor.decode(resp.content)
                if not rows:
                    break
                for seq, wire, cert in rows:
                    after = max(after, seq)
                    with wlock:
                        try:
                            from ..model import Event
                            if not v.store.has_event(Event.from_wire(wire).id):
                                v.accept(wire, cbor.decode(cert))
                                n += 1
                        except (Invalid, NeedParents):
                            pass
        return {"pulled": n}

    @app.post("/v1/abort/statement")
    def abort_statement(d: dict = Body(...)):
        with wlock:
            st = v.abort_statement(bytes.fromhex(d["eid"]), float(d["ttok"]))
        return {} if st is None else {"vid": st[0], "sig": st[1].hex()}

    @app.post("/v1/abort/apply")
    def abort_apply(d: dict = Body(...)):
        stmts = [(a, bytes.fromhex(b)) for a, b in d["statements"]]
        with wlock:
            return {"applied": v.apply_abort(bytes.fromhex(d["eid"]), stmts)}

    @app.post("/admin/byzantine")
    def byz(d: dict = Body(...)):
        v.byzantine = d.get("mode")
        return {"mode": v.byzantine}

    @app.get("/v1/stats")
    def stats():
        r = reader()
        try:
            n = r.event_count()
            nl = r.conn.execute("SELECT COUNT(*) FROM locks").fetchone()[0]
        finally:
            r.close()
        return {"events": n, "locks": nl, "k": P.k, "f": P.f, "q": P.q, "byzantine": v.byzantine}

    @app.get("/metrics")
    def metrics():
        s = stats()
        text = "".join(f"st_validator_{k} {s[k]}\n" for k in ("events", "locks", "k", "f", "q"))
        return Response(text, media_type="text/plain")

    return app


# tsa / na / tiv
def tsa_app(node_id: str, topo: dict, data_dir: str) -> FastAPI:
    clock = WallClock()
    admin = Admin(clock)
    tsa = TSA(node_id, clock, T.keypair(topo["seed"], node_id))
    app = FastAPI(title=f"tsa {node_id}")
    add_common(app, "tsa", node_id, admin)

    @app.post("/v1/stamp")
    def stamp(d: dict = Body(...)):
        return {"stamp": [(lambda s: [s[0], s[1], s[2].hex()])(tsa.stamp(bytes.fromhex(d["eid"])))][0]}
    return app


def na_app(node_id: str, topo: dict, data_dir: str) -> FastAPI:
    clock = WallClock()
    admin = Admin(clock)
    na = NA(T.keypair(topo["seed"], node_id))
    app = FastAPI(title="na")
    add_common(app, "na", node_id, admin)
    lk = threading.Lock()

    @app.post("/v1/attest")
    def attest(d: dict = Body(...)):
        with lk:
            rid, sig = na.attest(d["currency"], int(d["amax"]))
        return {"rid": rid.hex(), "sig": sig.hex()}

    @app.get("/v1/log")
    def log():
        return {"attestations": len(na.log)}
    return app


def tiv_app(node_id: str, topo: dict, data_dir: str) -> FastAPI:
    clock = WallClock()
    admin = Admin(clock)
    tiv = TIV(node_id, T.keypair(topo["seed"], node_id))
    cpath = os.path.join(data_dir, f"{node_id}.nu")
    if os.path.exists(cpath):
        tiv.counter = int(open(cpath).read() or 0)
    lk = threading.Lock()
    app = FastAPI(title=f"tiv {node_id}")
    add_common(app, "tiv", node_id, admin)

    @app.post("/v1/nu")
    def nu():
        with lk:
            n = tiv.next_nu()
            with open(cpath, "w") as f:           # persisted before signing
                f.write(str(n))
                f.flush()
                os.fsync(f.fileno())
        return {"nu": n}

    @app.post("/v1/sign")
    def sign(d: dict = Body(...)):
        sig = tiv.sign(d["issuer"], bytes.fromhex(d["kappa"]), int(d["nu"]), int(d["clean"]))
        return {"sig": sig.hex()}
    return app


# bank
def bank_app(node_id: str, topo: dict, data_dir: str) -> FastAPI:
    ctx = HttpContext(topo, node_id)
    admin = Admin(ctx.clock)
    admin.blocked = ctx.blocked                    # one shared blocklist (inbound and outbound)
    bank = Bank(node_id, T.keypair(topo["seed"], node_id), ctx)
    lk = threading.RLock()
    app = FastAPI(title=f"bank {node_id}")
    add_common(app, "bank", node_id, admin)

    def locked():
        class L:
            def __enter__(s):
                if not lk.acquire(timeout=30):
                    raise HTTPException(503, "busy")
            def __exit__(s, *a):
                lk.release()
        return L()

    def result(res):
        return {"ok": bool(res.ok), "sigs": res.sigs, "reasons": {k: (v if isinstance(v, str) else str(v)) for k, v in res.reasons.items()},
                "wall_ms": res.sim_ms}

    @app.post("/v1/onboard")
    def onboard(d: dict = Body(...)):
        with locked():
            try:
                eid = bank.onboard(d["account"], int(d["amount"]), d.get("currency", "NGN"))
            except PaymentFailed as ex:
                return {"ok": False, "error": str(ex)}
        return {"ok": True, "event": eid.hex()}

    @app.post("/v1/anchor")
    def anchor(d: dict = Body(...)):
        with locked():
            try:
                eid = bank.anchor(d["account"], int(d["amount"]), d.get("currency", "NGN"),
                                  ctx.tiv(d["tiv"]), int(d.get("clean", 0)))
            except PaymentFailed as ex:
                return {"ok": False, "error": str(ex)}
        return {"ok": True, "event": eid.hex()}

    @app.post("/v1/transfer")
    def transfer(d: dict = Body(...)):
        with locked():
            try:
                bank.transfer(d["src"], d["dst"], int(d["amount"]))
            except PaymentFailed as ex:
                return {"ok": False, "error": str(ex)}
        return {"ok": True}

    @app.post("/v1/pay")
    def pay(d: dict = Body(...)):
        with locked():
            try:
                res = bank.pay(d["src_account"], d["dst_bank"], d["dst_account"], int(d["amount"]),
                               d.get("currency", "NGN"), deliver=False)
            except PaymentFailed as ex:
                return {"ok": False, "error": str(ex)}
        out = result(res)
        dels = getattr(res, "deliveries", []) if res.ok else []
        statuses = []
        for dst, dl in dels:                       # deliver outside the bank lock (no cross-bank deadlock)
            st = bank.deliver(dst, dl)
            statuses.append(st[0] if st else None)
            if st and st[0] == "unreachable":
                with locked():
                    bank.outbox.append((dst, dl))
        out["delivery"] = statuses
        return out

    @app.post("/v1/exit")
    def exit_(d: dict = Body(...)):
        with locked():
            try:
                res = bank.exit(d["account"], int(d["amount"]), d.get("currency", "NGN"))
            except PaymentFailed as ex:
                return {"ok": False, "error": str(ex)}
        return result(res)

    @app.post("/v1/deliver")
    def deliver(d: dict = Body(...)):
        dl = Delivery(bytes.fromhex(d["event_id"]), int(d["j"]), int(d["a"]), int(d["r"]), int(d.get("rho", 0)),
                      d.get("advice"), bytes.fromhex(d.get("salt", "")), d.get("sender", ""))
        with locked():
            st = bank.receive(dl)
        return {"status": st[0], "code": st[1]}

    @app.post("/v1/flush")
    def flush():
        with locked():
            ok = bank.flush_outbox()
        return {"flushed": ok}

    @app.post("/v1/retry")
    def retry():
        with locked():
            return {"results": [result(r) for r in bank.retry_pending()]}

    @app.get("/v1/status")
    def status():
        with locked():
            return {"customers_total": sum(bank.customers.values()), "owned_total": bank.owned_total(),
                    "reconciled": bank.reconcile(), "entries": len(bank.holdings), "pending": len(bank.pending),
                    "outbox": len(bank.outbox), "rejected": len(bank.rejected), "accounts": len(bank.customers)}

    @app.get("/v1/balance/{account}")
    def balance(account: str):
        with locked():
            return {"balance": bank.customers.get(account, 0)}

    @app.post("/admin/behavior")
    def behavior(d: dict = Body(...)):
        bank.behavior = d.get("behavior", "honest")
        return {"behavior": bank.behavior}
    return app


FACTORIES = {"validator": validator_app, "tsa": tsa_app, "na": na_app, "tiv": tiv_app, "bank": bank_app}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", default=os.environ.get("ST_ROLE"))
    ap.add_argument("--id", default=os.environ.get("ST_ID"))
    ap.add_argument("--topology", default=os.environ.get("ST_TOPOLOGY", "topology.json"))
    ap.add_argument("--data-dir", default=os.environ.get("ST_DATA", "./data"))
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--host", default=os.environ.get("ST_HOST", "127.0.0.1"))
    ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args()
    if a.workers != 1:
        raise SystemExit("refusing to start: workers must be 1 (single writer, spec D33)")
    topo = T.load(a.topology)
    node = topo["nodes"][a.id]
    if node["role"] != a.role:
        raise SystemExit(f"{a.id} is a {node['role']}, not a {a.role}")
    os.makedirs(a.data_dir, exist_ok=True)
    app = FACTORIES[a.role](a.id, topo, a.data_dir)
    port = a.port or int(node["url"].rsplit(":", 1)[1])
    import uvicorn
    uvicorn.run(app, host=a.host, port=port, workers=1, log_level="warning")


if __name__ == "__main__":
    main()
