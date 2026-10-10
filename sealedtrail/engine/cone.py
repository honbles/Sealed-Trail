"""Cone construction (paper section 5, Algorithm 5, with the anchor-window rule).

Cone(K) is the closure of the flag's roots under two steps:
  (1) event -> every event that consumes one of its entries (child index), and
  (2) from an EXT in the cone, every ANC with |t(a) - t(x)| <= W_esc, before or after the exit.
Order of the result is (token time, depth, id), the order Algorithm 4 uses.
"""
from __future__ import annotations

from collections import deque

from ..model import EXT, ANC


def _order(store, ids):
    rows = []
    for eid in ids:
        m = store.event_meta(eid)
        rows.append((m["ttok"], m["depth"], eid))
    rows.sort()
    return [r[2] for r in rows]


def cone_build(store, roots, w_esc: float) -> list:
    seen = set(roots)
    q = deque(roots)
    anchors = store.ordered_ext_anc()           # [(ttok, depth, id, type)] by (ttok, depth, id)
    while q:
        eid = q.popleft()
        m = store.event_meta(eid)
        for c in store.children(eid):
            if c not in seen:
                seen.add(c)
                q.append(c)
        if m["type"] == EXT:
            for ttok, depth, aid, typ in anchors:
                if typ == ANC and abs(ttok - m["ttok"]) <= w_esc and aid not in seen:
                    seen.add(aid)
                    q.append(aid)
    return _order(store, seen)


class Cone:
    """Incremental cone for ONLEARN (late-arriving events and anchors)."""

    def __init__(self, store, roots, w_esc: float):
        self.store, self.w = store, w_esc
        self.ids = set(cone_build(store, roots, w_esc))
        self.roots = set(roots)

    def on_learn(self, e, ttok: float) -> bool:
        """Call for every newly finalized event; returns True if it joined the cone."""
        if e.id in self.ids:
            return False
        joins = any(p.eid in self.ids for p in e.parents)
        if not joins and e.type == ANC:
            for eid in list(self.ids):
                m = self.store.event_meta(eid)
                if m and m["type"] == EXT and abs(ttok - m["ttok"]) <= self.w:
                    joins = True
                    break
        if joins:
            self.ids.add(e.id)
            return True
        return False
