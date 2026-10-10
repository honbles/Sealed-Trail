"""HttpContext: what a Bank needs from "the cluster", implemented over HTTP (spec 3.2).

Provides the finality client (send to all validators, assemble Q(e) from q signatures,
post it to every validator, D22), token fetching from the TSAs, NA attestation, entry
lookups and bank-to-bank delivery. A per-process blocklist implements simulated
partitions in the `local` runtime (POST /admin/block).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from .. import cbor
from ..sim import Result
from . import topology as T


class Unreachable(Exception):
    pass


class WallClock:
    def __init__(self):
        self.offset = 0.0

    def now(self) -> float:
        return time.time() + self.offset


class RemoteNA:
    def __init__(self, ctx):
        self.ctx = ctx

    def attest(self, currency: str, amax: int):
        r = self.ctx.call("na", "POST", "/v1/attest", json={"currency": currency, "amax": amax})
        d = r.json()
        return bytes.fromhex(d["rid"]), bytes.fromhex(d["sig"])


class RemoteTIV:
    def __init__(self, ctx, tiv_id: str):
        self.ctx, self.id = ctx, tiv_id

    def next_nu(self) -> int:
        return self.ctx.call(self.id, "POST", "/v1/nu").json()["nu"]

    def sign(self, issuer: str, kappa: bytes, nu: int, clean: int = 0) -> bytes:
        r = self.ctx.call(self.id, "POST", "/v1/sign",
                          json={"issuer": issuer, "kappa": kappa.hex(), "nu": nu, "clean": clean})
        return bytes.fromhex(r.json()["sig"])


class HttpContext:
    def __init__(self, topo: dict, me: str, timeout: float = 20.0, workers: int = 32):
        self.topo, self.me = topo, me
        self.P = T.params_of(topo)
        self.trust = T.trust_of(topo)
        self.clock = WallClock()
        self.client = httpx.Client(timeout=timeout, limits=httpx.Limits(max_connections=200))
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.blocked: set = set()
        self.na = RemoteNA(self)
        self.validator_ids = list(topo["validators"])
        self.tsa_ids = [i for i, n in topo["nodes"].items() if n["role"] == "tsa"]

    # plumbing
    def call(self, node: str, method: str, path: str, **kw):
        if node in self.blocked:
            raise Unreachable(node)
        url = self.topo["nodes"][node]["url"] + path
        headers = dict(kw.pop("headers", {}))
        headers["X-ST-From"] = self.me
        # Only failed connects are retried: the request was never sent. Read timeouts and resets are not, the peer may have acted.
        r = None
        for attempt in range(5):
            try:
                r = self.client.request(method, url, headers=headers, **kw)
                break
            except (httpx.ConnectError, httpx.ConnectTimeout) as ex:
                if attempt == 4:
                    raise Unreachable(f"{node}: {type(ex).__name__}: {ex} (after {attempt + 1} connect attempts)") from ex
                time.sleep(0.2 * (2 ** attempt))
            except httpx.TransportError as ex:
                raise Unreachable(f"{node}: {type(ex).__name__}: {ex}") from ex
        if r.status_code >= 500:
            raise Unreachable(f"{node}: HTTP {r.status_code}")
        return r

    def tiv(self, tiv_id: str) -> RemoteTIV:
        return RemoteTIV(self, tiv_id)

    # services
    def token(self, eid: bytes) -> dict:
        def one(t):
            try:
                return self.call(t, "POST", "/v1/stamp", json={"eid": eid.hex()}).json()["stamp"]
            except Unreachable:
                return None
        out = [s for s in self.pool.map(one, self.tsa_ids) if s]
        sigs = [[s[0], s[1], bytes.fromhex(s[2])] for s in out]
        return {"sigs": sigs}

    def submit(self, src: str, e, plaintext=None, to=None) -> Result:
        wire = e.to_wire()
        t0 = time.perf_counter()
        vids = to or self.validator_ids

        def lock(vid):
            try:
                r = self.call(vid, "POST", "/v1/lock", content=wire,
                              headers={"content-type": "application/octet-stream"})
                return vid, r.json()
            except Unreachable:
                return vid, {"status": "unreachable"}
        sigs, reasons = {}, {}
        for vid, d in self.pool.map(lock, vids):
            if d["status"] == "ok":
                sigs[vid] = bytes.fromhex(d["sig"])
            elif d["status"] == "reject":
                reasons[vid] = d["code"]
            elif d["status"] == "unreachable":
                reasons[vid] = "UNREACHABLE"
            else:
                reasons[vid] = ("NEED", d.get("missing"))
        if len(sigs) < self.P.q:
            return Result(False, None, len(sigs), reasons, sim_ms=(time.perf_counter() - t0) * 1e3)
        cert = {vid: sigs[vid] for vid in sorted(sigs)[: self.P.q]}
        body = cbor.encode({"wire": wire, "cert": cert})

        def fin(vid):
            try:
                r = self.call(vid, "POST", "/v1/finalize", content=body,
                              headers={"content-type": "application/cbor"})
                d = r.json()
                return vid, None if d.get("ok") else d.get("code")
            except Unreachable:
                return vid, None
        for vid, code in self.pool.map(fin, vids):
            if code:
                reasons[vid] = code
        return Result(True, cert, len(sigs), reasons, sim_ms=(time.perf_counter() - t0) * 1e3)

    # read side
    def lookup_entry(self, who: str, eid: bytes, j: int):
        for vid in self.validator_ids:
            try:
                r = self.call(vid, "GET", f"/v1/entry/{eid.hex()}/{j}")
            except Unreachable:
                continue
            if r.status_code == 200:
                d = r.json()
                return {"owner": d["owner"], "currency": d["currency"], "kappa": bytes.fromhex(d["kappa"]),
                        "ttok": d["ttok"], "hadv": bytes.fromhex(d["hadv"]) if d["hadv"] else None}
        return None

    def held_keys(self, who: str) -> set:
        out = set()
        for vid in self.validator_ids:
            try:
                r = self.call(vid, "GET", "/v1/holds")
            except Unreachable:
                continue
            if r.status_code == 200:
                out |= {(bytes.fromhex(e), j) for e, j in r.json()["holds"]}
        return out

    def entry_ttok(self, who: str, eid: bytes) -> float:
        for vid in self.validator_ids:
            try:
                r = self.call(vid, "GET", f"/v1/meta/{eid.hex()}")
            except Unreachable:
                continue
            if r.status_code == 200:
                return r.json()["ttok"]
        raise KeyError("event not found at any reachable validator")

    def send_delivery(self, src: str, dst: str, d):
        body = {"event_id": d.event_id.hex(), "j": d.j, "a": str(d.a), "r": str(d.r), "rho": d.rho,
                "advice": d.advice, "salt": d.salt.hex(), "sender": d.sender}
        try:
            r = self.call(dst, "POST", "/v1/deliver", json=body)
        except Unreachable:
            return ("unreachable", None)
        if r.status_code != 200:
            return ("unreachable", None)
        out = r.json()
        return (out["status"], out.get("code"))
