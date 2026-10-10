"""In-process cluster: validators, TSAs, NA, TIVs, banks over the network shim (spec section 2.4).

This is the `inproc` runtime. The same Validator/Bank objects sit behind HTTP in the
`local` runtime (see sealedtrail/http/). Latencies from the shim are simulated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import cbor
from . import crypto as C
from .actors import NA, TSA, TIV
import os
from .bank import Bank
from .flags import Flag, Release, Regulator
from .net import Clock, Network, Unreachable
from .params import Params, profile
from .trust import Trust
from .valid import Invalid
from .oracle import Oracle, make_rate_doc
from .validator import Validator


@dataclass
class Result:
    ok: bool
    cert: dict | None = None
    sigs: int = 0
    reasons: dict = field(default_factory=dict)
    deliveries: list = field(default_factory=list)
    sim_ms: float = 0.0          # simulated network time spent (not a measurement)


class Cluster:
    def __init__(self, P: Params | str = "dev", banks: tuple = ("A", "B"), seed: int = 1,
                 clock: Clock | None = None, store_dir: str | None = None, shadow=None, tivs: int = 1,
                 oracles: int = 5):
        self.P = profile(P) if isinstance(P, str) else P
        self.clock = clock or Clock(1000.0)
        self.net = Network(seed)
        self.na = NA()
        self.tsas = [TSA(f"tsa-{i}", self.clock) for i in range(self.P.n_tsa)]
        self.tivs = {f"tiv-{i}": TIV(f"tiv-{i}") for i in range(tivs)}
        self.trust = Trust(na_pk=self.na.kp.pk,
                           tsa_pks={t.id: t.kp.pk for t in self.tsas},
                           tiv_pks={i: t.kp.pk for i, t in self.tivs.items()})
        self.oracles = [Oracle(f"oracle-{i}") for i in range(oracles)]
        self.trust.oracle_pks = {o.id: o.pk for o in self.oracles}
        self.validators: dict = {}
        for i in range(self.P.k):
            vid = f"val-{i:02d}"
            kp = C.KeyPair()
            self.trust.validator_pks[vid] = kp.pk
            path = f"{store_dir}/{vid}.sqlite" if store_dir else ":memory:"
            v = Validator(vid, kp, self.P, self.trust, self.clock, path)
            v.fetcher = self._fetcher(vid)
            self.validators[vid] = v
        self.regulators = [Regulator(f"reg-{i}", ("J1",)) for i in range(3)]       # t_reg = 2 of n_reg = 3
        self.review = Regulator("review-0", ())                                      # distinct review body
        self.trust.regulators = {r.id: (r.kp.pk, r.scope) for r in self.regulators}
        self.trust.review_pks = {self.review.id: self.review.kp.pk}
        self.trust.jurisdictions = {"J1": tuple(banks)}
        self.banks: dict = {}
        self.shadow = shadow
        self.log: list = []
        for b in banks:
            self.add_bank(b)

    def rate_doc(self, pair: str, true_rate, t: int | None = None, liars: dict | None = None) -> dict:
        """Rate document at the true rate; `liars` = {oracle index: multiplier} sets lying oracles."""
        from fractions import Fraction
        for i, o in enumerate(self.oracles):
            o.offset = Fraction((liars or {}).get(i, 1))
        t = int(self.clock.now() if t is None else t)
        doc = make_rate_doc(pair, [o.observe(pair, Fraction(true_rate), t) for o in self.oracles])
        for o in self.oracles:
            o.offset = Fraction(1)
        return doc

    # setup
    def add_bank(self, name: str) -> Bank:
        kp = C.KeyPair()
        self.trust.bank_pks[name] = kp.pk
        b = Bank(name, kp, self)
        self.banks[name] = b
        return b

    def _fetcher(self, vid: str):
        def fetch(eid: bytes):
            for other, ov in self.validators.items():
                if other == vid or not self.net.reachable(vid, other):
                    continue
                got = ov.get(eid)
                if got:
                    return got
            return None
        return fetch

    # services
    def token(self, eid: bytes, tsas=None) -> dict:
        use = tsas if tsas is not None else self.tsas
        return {"sigs": [t.stamp(eid) for t in use]}

    def tick(self, dt: float):
        self.clock.advance(dt)

    # finality
    def submit(self, src: str, e, plaintext: dict | None = None, to: list | None = None) -> Result:
        """Finality client (spec 3.2): send to all validators, assemble Q(e) from q signatures,
        post it to every reachable validator (D22)."""
        wire = e.to_wire()
        sigs, reasons = {}, {}
        t0 = self.net.sim_ms
        for vid in (to or list(self.validators)):
            v = self.validators[vid]
            try:
                res = self.net.call(src, vid, v.request_lock, wire)
            except Unreachable:
                reasons[vid] = "UNREACHABLE"
                continue
            if res[0] == "ok":
                sigs[vid] = res[1]
            else:
                reasons[vid] = res[1] if res[0] == "reject" else ("NEED", res[1])
        if len(sigs) < self.P.q:
            return Result(False, None, len(sigs), reasons, sim_ms=self.net.sim_ms - t0)
        cert = {vid: sigs[vid] for vid in sorted(sigs)[: self.P.q]}
        for vid, v in self.validators.items():
            try:
                self.net.call(src, vid, v.finalize, wire, cert)
            except Unreachable:
                pass
            except Invalid as ex:
                reasons[vid] = ex.code
        if self.shadow is not None and plaintext is not None:
            self.shadow.record(e, plaintext)
        self.log.append((self.clock.now(), src, e.type, e.id.hex()[:8]))
        return Result(True, cert, len(sigs), reasons, sim_ms=self.net.sim_ms - t0)

    def send_delivery(self, src: str, dst: str, d):
        """Bank-to-bank off-network delivery (opening, rho, advice) over the shim."""
        try:
            return self.net.call(src, dst, self.banks[dst].receive, d)
        except Unreachable:
            return ("unreachable", None)

    # read side
    def _reachable_validators(self, who: str):
        return [v for vid, v in self.validators.items() if self.net.reachable(who, vid)]

    def lookup_entry(self, who: str, eid: bytes, j: int):
        for v in self._reachable_validators(who):
            ent = v.store.entry(eid, j)
            if ent:
                got = v.store.get_event(eid)
                ent = dict(ent)
                ent["hadv"] = got[0].outputs[j].hadv if got else None
                return ent
        return None

    def held_keys(self, who: str) -> set:
        out = set()
        for v in self._reachable_validators(who):
            out |= v.store.held_keys(self.clock.now())
        return out

    def entry_ttok(self, who: str, eid: bytes) -> float:
        for v in self._reachable_validators(who):
            m = v.store.event_meta(eid)
            if m:
                return m["ttok"]
        raise KeyError("event not found at any reachable validator")

    # merging
    def sync_all(self):
        """Union merge between every reachable validator pair (Corollary 10)."""
        n = 0
        for a in self.validators:
            for b in self.validators:
                if a != b and self.net.reachable(a, b):
                    n += self.validators[a].sync_from(self.validators[b])
        return n

    def honest(self):
        return [v for v in self.validators.values() if v.byzantine is None]

    # lock recovery
    def abort(self, src: str, e) -> dict:
        """Gather abort statements for a stale event and apply them everywhere (paper section 3).
        Returns {'statements': n, 'needed': n, 'applied_at': [...]}."""
        ttok = None
        from .valid import token_time
        ttok = token_time(e, self.trust, self.P)
        stmts = []
        for vid, v in self.validators.items():
            try:
                st = self.net.call(src, vid, v.abort_statement, e.id, ttok)
            except Unreachable:
                continue
            if st:
                stmts.append(st)
        applied = []
        for vid, v in self.validators.items():
            try:
                if self.net.call(src, vid, v.apply_abort, e.id, stmts):
                    applied.append(vid)
            except Unreachable:
                pass
        return {"statements": len(stmts), "needed": self.P.k + self.P.f - self.P.q + 1, "applied_at": applied}

    # flags (M6)
    def set_jurisdiction(self, name: str, banks, mutual=()):
        self.trust.jurisdictions[name] = tuple(banks)
        self.trust.mutual[name] = tuple(mutual)
        for r in self.regulators:
            if name not in r.scope:
                r.scope = r.scope + (name,)
                self.trust.regulators[r.id] = (r.kp.pk, r.scope)

    def make_flag(self, roots, juris: str = "J1", ttl: float = 3600.0, signers=None, brec: str = "", inj: dict | None = None) -> Flag:
        f = Flag(list(roots), juris, int(self.clock.now()), int(self.clock.now() + ttl), os.urandom(8), brec=brec, inj=dict(inj or {}))
        for r in (signers if signers is not None else self.regulators[: self.trust.reg_threshold]):
            r.sign_flag(f)
        return f

    def submit_flag(self, f: Flag, to: list | None = None, src: str = "regulator") -> dict:
        out = {}
        for vid in (to or list(self.validators)):
            try:
                out[vid] = self.net.call(src, vid, self.validators[vid].submit_flag, f.to_wire())
            except Unreachable:
                out[vid] = ("unreachable", None)
        return out

    def release(self, flag_id: bytes, signers=None, src: str = "review") -> dict:
        r = Release(flag_id, os.urandom(8))
        for who in (signers if signers is not None else [self.review]):
            who.sign_release(r)
        out = {}
        for vid, v in self.validators.items():
            try:
                out[vid] = self.net.call(src, vid, v.submit_release, r.to_wire())
            except Unreachable:
                out[vid] = ("unreachable", None)
        return out

    def record_openings(self, got: dict, src: str = "regulator") -> dict:
        """Broadcast accepted openings to every validator's opening log (D13)."""
        out = {}
        for vid, v in self.validators.items():
            res = []
            for commit, (a, r) in got.items():
                try:
                    res.append(self.net.call(src, vid, v.record_opening, commit, a, r)[0])
                except Unreachable:
                    res.append("unreachable")
            out[vid] = res
        return out

    def make_phase4(self, flag_id: bytes, banks, signers=None):
        from .flags import Phase4
        p = Phase4(flag_id, list(banks), os.urandom(8))
        for r in (signers if signers is not None else self.regulators[: self.trust.reg_threshold]):
            r.sign_phase4(p)
        return p

    def submit_phase4(self, p, src: str = "regulator") -> dict:
        out = {}
        for vid, v in self.validators.items():
            try:
                out[vid] = self.net.call(src, vid, v.submit_phase4, p.to_wire())
            except Unreachable:
                out[vid] = ("unreachable", None)
        return out

    def held_at(self, eid: bytes, j: int = 0) -> list:
        return [vid for vid, v in self.validators.items() if v.store.is_held((eid, j))]
