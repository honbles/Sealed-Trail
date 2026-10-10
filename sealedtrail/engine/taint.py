"""Taint mass accounting (paper section 4, Algorithm 4 as edited, spec 6.4 and 8.2).

Exact rationals only. The engine consumes *facts* (opened amounts) in (token time,
depth, id) order and maintains: entry fractions rho, escrow tranches E, TIV claims Y,
written-off Z, restitution D, flagged principal P, the weighted custody graph G3, and
per-TIV clean-attestation liabilities.

Mass identity (Theorem 14), checked by `identity_ok` after every event:
    sum(rho*R) + E + Y + Z + D == P
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction as F

from ..model import GEN, DEB, ANC, EXT, REV


@dataclass
class EvFacts:
    id: bytes
    type: str
    issuer: str
    ttok: float
    depth: int
    parents: list = field(default_factory=list)     # [((eid, j), c | None)]
    outputs: list = field(default_factory=list)     # [(owner, currency, A | None)]
    clean: int = 0
    tiv: str | None = None
    rev_kind: str | None = None
    currency: str | None = None


@dataclass
class Entry:
    owner: str
    cur: str
    A: int | None
    rho: F
    cons: int = 0
    unres: bool = False

    @property
    def R(self):
        return None if self.A is None else self.A - self.cons


class EngineError(Exception):
    pass


class TaintEngine:
    def __init__(self, w_esc: float, injections: dict | None = None, brec: str | None = None):
        self.w = w_esc
        self.inj = dict(injections or {})       # event id -> "whole"
        self.brec = brec
        self.entries: dict = {}
        self.E: list = []                       # [[t, mass F]] oldest first
        self.open_anchors: list = []            # [[t, ua F, anchor id, tiv]]
        self.Y = self.Z = self.D = self.P = F(0)
        self.liab: dict = {}                    # tiv -> F contingent liability (clean attestations)
        self.claims: dict = {}                  # tiv -> F deferred-anchor claims (Y)
        self.edges: list = []                   # weighted G3: (src, dst, t, weight, event)
        self.root_inj: dict = {}                # bank -> injected mass at roots it owns
        self.lams: dict = {}                    # bank -> [lambda]
        self.unres_events: set = set()
        self.unres_ea: list = []                # times of Unresolved EXT/ANC
        self.processed: list = []
        self.unresolved_mass_unknown = False

    # helpers
    def rho_of(self, key) -> F:
        e = self.entries.get(key)
        return e.rho if e else F(0)

    def E_total(self) -> F:
        return sum((m for _, m in self.E), F(0))

    def live(self) -> F:
        return sum((e.rho * e.R for e in self.entries.values() if e.A is not None and not e.unres), F(0))

    def Tb(self, bank: str) -> F:
        return sum((e.rho * e.R for e in self.entries.values() if e.owner == bank and e.A is not None), F(0))

    def all_Tb(self) -> dict:
        out: dict = {}
        for e in self.entries.values():
            if e.A is not None:
                out[e.owner] = out.get(e.owner, F(0)) + e.rho * e.R
        return out

    def identity_ok(self) -> bool:
        if self.unres_events:
            return True            # identity is claimed over the resolved part only
        return self.live() + self.E_total() + self.Y + self.Z + self.D == self.P

    def terms(self) -> dict:
        return {"live": self.live(), "E": self.E_total(), "Y": self.Y, "Z": self.Z, "D": self.D, "P": self.P}

    # window
    def _expire(self, t: float):
        keep = []
        for ts, m in self.E:
            if t - ts > self.w:
                self.Z += m
            else:
                keep.append([ts, m])
        self.E = keep
        self.open_anchors = [a for a in self.open_anchors if t - a[0] <= self.w]

    def _draw(self, amount: F) -> F:
        """Draw up to `amount` from the oldest tranches first (decision D25)."""
        got = F(0)
        for tr in self.E:
            if got >= amount:
                break
            take = min(tr[1], amount - got)
            tr[1] -= take
            got += take
        self.E = [tr for tr in self.E if tr[1] > 0]
        return got

    def settle(self, t: float):
        """Advance the escrow clock to time t without an event (expiry into Z)."""
        self._expire(t)

    # events
    def process(self, ev: EvFacts):
        self._expire(ev.ttok)
        unres = ev.id in self.unres_events
        if ev.type in (EXT, ANC):
            if any(ev.ttok - t <= self.w for t in self.unres_ea):          # D29: window propagation
                unres = True
        # a consumed amount is only needed when some parent is a cone entry (all-clean parents give rho_hat = 0)
        in_cone = any(k in self.entries for k, _ in ev.parents)
        if (in_cone and any(c is None for _, c in ev.parents)) or any(A is None for _, _, A in ev.outputs) \
                or any(self.entries.get(k) is not None and self.entries[k].unres for k, _ in ev.parents):
            unres = True
        if unres:
            self.unres_events.add(ev.id)
            if ev.type in (EXT, ANC):
                self.unres_ea.append(ev.ttok)
            for j, (owner, cur, A) in enumerate(ev.outputs):
                self.entries[(ev.id, j)] = Entry(owner, cur, A, F(0), 0, True)
            for k, c in ev.parents:
                if k in self.entries:
                    if c is None:
                        self.entries[k].unres = True       # unknown consumption: the parent's residual is unknown too
                    else:
                        self.entries[k].cons += c
            self.processed.append(ev.id)
            return
        getattr(self, "_" + ev.type.lower())(ev)
        self.processed.append(ev.id)

    def _consume(self, ev):
        sumc, mass = 0, F(0)
        for k, c in ev.parents:
            ent = self.entries.get(k)
            if c is None:                       # unknown amount of a clean parent: weight irrelevant (rho = 0)
                continue
            rho = ent.rho if ent else F(0)
            sumc += c
            mass += rho * c
            if ent is not None:
                if ent.A is not None and c > ent.R:
                    raise EngineError("overspend in opened data")
                ent.cons += c
        return sumc, mass

    def _gen(self, ev):
        owner, cur, A = ev.outputs[0]
        whole = ev.id in self.inj
        rho = F(1) if whole else F(0)
        if whole:
            self.P += A
            self.root_inj[owner] = self.root_inj.get(owner, F(0)) + A
        self.entries[(ev.id, 0)] = Entry(owner, cur, A, rho)

    def _deb(self, ev):
        sumc, mass = self._consume(ev)
        rhohat = mass / sumc if sumc else F(0)
        spec = self.inj.get(ev.id)
        total_out = sum(A for _, _, A in ev.outputs)
        for j, (owner, cur, A) in enumerate(ev.outputs):
            if spec is None:
                x = F(0)
            elif spec == "whole":
                x = (1 - rhohat) * A
            else:                                   # oracle-fraud excess, allocated pro rata, capped by (1 - rho_hat) A
                x = min(F(spec) * A / total_out, (1 - rhohat) * A)
            self.P += x
            if x:
                self.root_inj[owner] = self.root_inj.get(owner, F(0)) + x
            rho = rhohat + x / A
            self.entries[(ev.id, j)] = Entry(owner, cur, A, rho)
            if owner != ev.issuer:
                self.edges.append((ev.issuer, owner, ev.ttok, rhohat * A, ev.id))

    def _ext(self, ev):
        sumc, mass = self._consume(ev)
        self.edges.append((ev.issuer, "⊥", ev.ttok, mass, ev.id))
        if mass > 0:
            self.E.append([ev.ttok, mass])
        # deferred-anchor rule: a later EXT inside the window of an unattested clean-entering anchor
        remaining = mass
        for a in self.open_anchors:
            if remaining <= 0:
                break
            take = min(remaining, a[1])
            if take > 0:
                a[1] -= take
                remaining -= take
                self.Y += take
                self.claims[a[3]] = self.claims.get(a[3], F(0)) + take
                self.E[-1][1] -= take
        self.open_anchors = [a for a in self.open_anchors if a[1] > 0]
        self.E = [tr for tr in self.E if tr[1] > 0]

    def _anc(self, ev):
        owner, cur, A = ev.outputs[0]
        if ev.id in self.inj:                                  # flagged anchor: whole, no TIV liability
            self.P += A
            self.root_inj[owner] = self.root_inj.get(owner, F(0)) + A
            self.entries[(ev.id, 0)] = Entry(owner, cur, A, F(1))
            return
        etot = self.E_total()
        if ev.clean:                                           # clean attestation: rho = 0, liability only
            self.entries[(ev.id, 0)] = Entry(owner, cur, A, F(0))
            if etot > 0:
                self.liab[ev.tiv] = self.liab.get(ev.tiv, F(0)) + min(F(A), etot)
            self.edges.append(("⊥", owner, ev.ttok, F(0), ev.id))
            return
        g = self._draw(min(F(A), etot))
        self.entries[(ev.id, 0)] = Entry(owner, cur, A, g / A)
        self.edges.append(("⊥", owner, ev.ttok, g, ev.id))
        if g < A:
            self.open_anchors.append([ev.ttok, F(A) - g, ev.id, ev.tiv])

    def _rev(self, ev):
        issuer = ev.issuer
        if ev.rev_kind == "restitution":
            sumc, mass = self._consume(ev)
            owner, cur, A = ev.outputs[0]
            self.entries[(ev.id, 0)] = Entry(owner, cur, A, F(0))
            self.D += mass
            self.edges.append((issuer, "Δ", ev.ttok, mass, ev.id))       # mass leaves to D
            return
        Tb = self.Tb(issuer)
        sumc, mass = self._consume(ev)
        m = sumc
        if m > Tb:
            raise EngineError(f"REV m={m} exceeds Tb={Tb}")
        denom = Tb - mass
        lam = F(0) if m == Tb else (Tb - m) / denom
        owner, cur, A = ev.outputs[0]
        self.entries[(ev.id, 0)] = Entry(owner, cur, A, F(1))
        for ent in self.entries.values():                       # rescale b's remaining cone entries
            if ent.owner == issuer and ent.A is not None:
                ent.rho *= lam
        self.lams.setdefault(issuer, []).append(lam)
        self.edges.append((issuer, owner, ev.ttok, F(m), ev.id))

    # metrics
    def metrics(self, brec: str | None = None) -> dict:
        brec = brec or self.brec
        tb = self.all_Tb()
        rec = sum((e.rho * e.R for e in self.entries.values() if e.owner == brec and e.A is not None), F(0)) if brec else F(0)
        P = self.P
        return {"TotalContamination": sum(tb.values(), F(0)), "BanksAffected": sum(1 for v in tb.values() if v > 0),
                "RecoveryRate": ((rec + self.D) / P) if P else None, "terms": self.terms()}

    # G3
    def custody_from_edges(self, bank: str) -> F:
        """Corollary 16: Tb recovered from the weighted graph alone:
        injections at roots owned + incoming - outgoing (incl. the EXT, ANC, REV and D terms)."""
        inc = sum((w for s_, d, t, w, e in self.edges if d == bank), F(0))
        out = sum((w for s_, d, t, w, e in self.edges if s_ == bank), F(0))
        return self.root_inj.get(bank, F(0)) + inc - out
