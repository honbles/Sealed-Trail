"""Reversal coordination: Algorithm 3 Phases 0-4 (paper section 5), regulator side.

Phase 0  Hold      validators, on receipt of the flag (flags.py / validator.submit_flag)
Phase 1  Exposure  B1 = owners of cone entries; foreign owners are reported, not held
Phase 2  Open      banks in B1 and (J or M_J) open the commitments they can; the regulator and the
                   validators accept an opening only if it matches the public commitment
Resolve  Alg 4     taint fractions and escrow from accepted openings (engine/taint.py)
Phase 3  Reverse   banks with no Unresolved ancestor and TA(b) >= Tmin are called on to issue REV(m_b)
                   (they cannot be compelled)
Phase 4  Release   regulator-signed PHASE4 list (banks below Tmin); validators release resolved Held
                   entries of banks that issued REV, of listed banks, and anchors that drew nothing

Nothing here forces a bank: refusals leave entries Held until t_exp and are reported.
"""
from __future__ import annotations

import math
from fractions import Fraction as F

from . import crypto as C
from .bank import PaymentFailed
from .engine.cone import cone_build
from .engine.facts import LogOpenings, run_engine
from .plan import least_feasible_at_least, greatest_feasible_at_most


def full(Tb):
    return Tb


def fraction(p):
    return lambda Tb: Tb * F(p)


class Reversal:
    def __init__(self, cluster, flag, policy=full, tmin: int = 0, actors: dict | None = None,
                 currency: str = "NGN"):
        self.c, self.f = cluster, flag
        self.policy, self.tmin, self.actors, self.cur = policy, tmin, actors or {}, currency
        self.log: dict = {}                       # accepted openings: commitment -> (a, r)
        self.rejected: list = []                  # (bank, commitment) openings that did not match
        self.unanswered: dict = {}                # bank -> count of requests not answered
        self.reversed: dict = {}                  # bank -> m
        self.below: list = []                     # banks released without a REV
        self.skipped: dict = {}                   # bank -> reason no REV was issued

    # helpers
    @property
    def store(self):
        return self.c.honest()[0].store

    def scope(self) -> set:
        j = self.f.juris
        return set(self.c.trust.jurisdictions.get(j, ())) | set(self.c.trust.mutual.get(j, ()))

    def cone(self) -> list:
        return cone_build(self.store, list(self.f.roots), self.c.P.w_esc)

    def engine(self):
        return run_engine(self.store, LogOpenings(self.store, self.log.get), list(self.f.roots),
                          self.c.P.w_esc, self.f.brec, self.f.inj)

    def ingest_rev(self, eid: bytes):
        """Add the openings a REV or restitution carries (verified at the validators when it was locked)."""
        ev, _ = self.store.get_event(eid)
        for p, (cv, rb) in zip(ev.parents, ev.rev_open["c"]):
            self.log[p.kc] = (cv, int.from_bytes(rb, "little"))
        mv, rb = ev.rev_open["m"]
        self.log[ev.outputs[0].kappa] = (mv, int.from_bytes(rb, "little"))

    # phases
    def phase0(self):
        return self.c.submit_flag(self.f)

    def phase1(self) -> dict:
        ids = self.cone()
        owners = set()
        for eid in ids:
            ev, _ = self.store.get_event(eid)
            owners |= {o.owner for o in ev.outputs}
        sc = self.scope()
        self.b1 = sorted(owners)
        return {"B1": self.b1, "held_scope": sorted(owners & sc), "foreign": sorted(owners - sc), "cone": len(ids)}

    def requests(self, bank: str, ids: list) -> list:
        reqs = []
        for eid in ids:
            ev, _ = self.store.get_event(eid)
            if ev.issuer == bank:
                reqs += [("c", p.key, p.v, p.kc) for p in ev.parents]
            reqs += [("o", eid, j, o.kappa) for j, o in enumerate(ev.outputs) if o.owner == bank]
        return reqs

    def phase2(self):
        ids = self.cone()
        sc = self.scope()
        for bank in self.b1:
            if bank not in sc:
                continue
            reqs = self.requests(bank, ids)
            got = self.c.banks[bank].open_for_flag(reqs)
            ok = {}
            for commit, (a, r) in got.items():
                if C.commit(a, r) == commit:
                    ok[commit] = (a, r)
                else:
                    self.rejected.append((bank, commit))
            self.log.update(ok)
            self.c.record_openings(ok)
            miss = sum(1 for q in reqs if q[3] not in ok)
            if miss:
                self.unanswered[bank] = miss

    def phase3(self):
        eng = self.engine()
        sc = self.scope()
        snap = {b: eng.Tb(b) for b in self.b1}
        group = lambda b: [x for g in self.actors.values() if b in g for x in g] or [b]
        om = self.c.P.floor(self.cur)
        for bank in sorted(self.b1):
            if bank not in sc or bank == self.f.brec:
                continue
            ents = [e for e in eng.entries.values() if e.owner == bank]
            if not ents:
                continue
            if any(e.unres for e in ents):
                self.skipped[bank] = "UNRESOLVED"
                continue
            Tb = snap[bank]
            TA = sum((snap.get(x, F(0)) for x in set(group(bank))), F(0))
            if Tb <= 0 or TA < self.tmin:
                self.below.append(bank)
                continue
            m0 = int(math.floor(self.policy(Tb)))
            res = [e.R for e in ents if e.R and e.R > 0]
            m1 = least_feasible_at_least(res, m0, om)
            m = m1 if (m1 is not None and m1 <= Tb) else greatest_feasible_at_most(res, m0, om)
            if m is None or m < om:
                self.skipped[bank] = "BELOW_FLOOR"
                self.below.append(bank)
                continue
            try:
                out, eid = self.c.banks[bank].issue_rev(self.f.id, m, self.f.brec, self.cur)
            except PaymentFailed:
                self.skipped[bank] = "REFUSED_REV"
                continue
            if not getattr(out, "ok", False):
                self.skipped[bank] = f"REV_REJECTED {getattr(out, 'reasons', out)}"
                continue
            self.reversed[bank] = m
            self.ingest_rev(eid)

    def phase4(self):
        p = self.c.make_phase4(self.f.id, self.below)
        return self.c.submit_phase4(p)

    # run
    def run(self, tick: bool = True) -> dict:
        P = self.c.P
        rep = {"phase0": self.phase0()}
        if tick:
            self.c.tick(P.t_hold)
        rep["exposure"] = self.phase1()
        self.phase2()
        if tick:
            self.c.tick(P.t_open)
        self.phase3()
        if tick:
            self.c.tick(P.t_rev)
        rep["phase4"] = self.phase4()
        eng = self.engine()
        rep.update({"reversed": dict(self.reversed), "below_tmin": list(self.below), "skipped": dict(self.skipped),
                    "unanswered": dict(self.unanswered), "rejected_openings": len(self.rejected),
                    "non_compliant": sorted(set(self.unanswered) | {b for b, r in self.skipped.items() if r == "REFUSED_REV"}),
                    "unresolved_banks": sorted(b for b, r in self.skipped.items() if r == "UNRESOLVED"),
                    "identity_ok": eng.identity_ok(), "metrics": eng.metrics(self.f.brec),
                    "Tb": {b: eng.Tb(b) for b in sorted(set(self.b1) | ({self.f.brec} if self.f.brec else set()))}})
        self.eng = eng
        return rep
