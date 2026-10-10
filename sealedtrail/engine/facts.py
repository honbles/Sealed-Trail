"""Facts extractor: public structure (any replica's store) + openings -> EvFacts (spec 8.2).

An opening is *accepted* only if it matches the public commitment (Theorem 18). A bank that
refuses, or offers a value that does not open the commitment, yields `None`, which the engine
turns into UNRESOLVED (viral by construction, D29 for EXT/ANC windows).
"""
from __future__ import annotations

from .. import crypto as C
from ..model import Event, GEN, ANC, EXT, DEB, REV
from .cone import cone_build
from .taint import EvFacts, TaintEngine


class BankOpenings:
    """In-process opening source backed by Bank objects. The HTTP runtime uses the same
    interface over each bank's /openings endpoint."""

    def __init__(self, banks: dict, refuse: set | frozenset = frozenset()):
        self.banks, self.refuse = banks, set(refuse)

    def consumed(self, bank: str, parent_key, v: int):
        b = self.banks.get(bank)
        if b is None or bank in self.refuse:
            return None
        h = b.holdings.get(parent_key)
        return h.cons[v] if h is not None and v < len(h.cons) else None     # (c, r_c)

    def output(self, bank: str, eid: bytes, j: int):
        b = self.banks.get(bank)
        if b is None or bank in self.refuse:
            return None
        return b.openings.get((eid, j))                                      # (a, r)


class LogOpenings:
    """Opening source backed by a commitment -> (a, r) getter (a validator's opening log, or the
    regulator's). Public structure comes from `store`; an opening is only used if it matches."""

    def __init__(self, store, getter):
        self.store, self.get = store, getter

    def consumed(self, bank: str, parent_key, v: int):
        row = self.store.conn.execute("SELECT kc FROM consumed WHERE eid=? AND j=? AND v=?",
                                      (parent_key[0], parent_key[1], v)).fetchone()
        return self.get(row[0]) if row else None

    def output(self, bank: str, eid: bytes, j: int):
        row = self.store.conn.execute("SELECT kappa FROM entries WHERE eid=? AND j=?", (eid, j)).fetchone()
        return self.get(row[0]) if row else None


def event_facts(store, eid: bytes, src) -> EvFacts:
    e, _cert = store.get_event(eid)
    m = store.event_meta(eid)
    parents = []
    for p in e.parents:
        got = src.consumed(e.issuer, p.key, p.v)
        c = got[0] if got is not None and C.commit(got[0], got[1]) == p.kc else None
        parents.append((p.key, c))
    outs = []
    for j, o in enumerate(e.outputs):
        got = src.output(o.owner, e.id, j)
        a = got[0] if got is not None and C.commit(got[0], got[1]) == o.kappa else None
        outs.append((o.owner, o.currency, a))
    cur = e.outputs[0].currency if e.outputs else e.currency
    return EvFacts(id=e.id, type=e.type, issuer=e.issuer, ttok=m["ttok"], depth=m["depth"], parents=parents,
                   outputs=outs, clean=getattr(e, "clean", 0) or 0, tiv=getattr(e, "tiv", None),
                   rev_kind=e.rev_kind, currency=cur)


def run_engine(store, src, flag_roots: list, w_esc: float, brec: str | None = None,
               inj: dict | None = None) -> TaintEngine:
    """Build the cone, extract facts, and run Algorithm 4 over it in (token time, depth, id) order."""
    ids = cone_build(store, list(flag_roots), w_esc)
    eng = TaintEngine(w_esc, injections={r: (inj or {}).get(r, "whole") for r in flag_roots}, brec=brec)
    for eid in ids:
        eng.process(event_facts(store, eid, src))
    return eng
