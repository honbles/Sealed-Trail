"""Continuous invariant monitors (spec section 8.4). Each returns a list of violations.

M1 supply identity, M2 single spend, M3 lock consistency, M5 replica convergence
need no openings and run on any replica.
"""
from __future__ import annotations

import hashlib

from . import cbor
from . import crypto as C
from .model import Event, GEN, ANC, EXT
from .store import kbytes


def m1_supply_identity(store) -> list:
    """Per currency: sum of derived residual commitments =
    sum of root kappa - sum of EXT kx (no international events in this build yet).
    An exact identity between group elements, because V3 forces r* = 0."""
    cur_of, lhs, rhs = {}, {}, {}
    for eid, j, owner, cur, kappa in store.all_entries():
        cur_of[(eid, j)] = cur
        lhs[cur] = C.padd(lhs.get(cur, C.IDENTITY), kappa)
    for eid, j, kc in store.conn.execute("SELECT eid, j, kc FROM consumed"):
        cur = cur_of[(eid, j)]
        lhs[cur] = C.psub(lhs[cur], kc)
    for seq, wire, cert in store.all_events():
        e = Event.from_wire(wire)
        if e.type in (GEN, ANC):
            cur = e.outputs[0].currency
            rhs[cur] = C.padd(rhs.get(cur, C.IDENTITY), e.outputs[0].kappa)
        elif e.type == EXT:
            rhs[e.currency] = C.psub(rhs.get(e.currency, C.IDENTITY), e.kx)
        elif e.intl is not None:                    # Lemma 5: + intl-in sum(kappa_j), - intl-out sum(kc)
            oc, sc_ = e.outputs[0].currency, e.intl["s"]
            rhs[oc] = C.padd(rhs.get(oc, C.IDENTITY), C.psum(o.kappa for o in e.outputs))
            rhs[sc_] = C.psub(rhs.get(sc_, C.IDENTITY), C.psum(p.kc for p in e.parents))
    out = []
    for cur in set(lhs) | set(rhs):
        if lhs.get(cur, C.IDENTITY) != rhs.get(cur, C.IDENTITY):
            out.append(("M1", cur, "supply commitment identity broken"))
    return out


def m2_single_spend(store) -> list:
    out = []
    seen: dict = {}
    for seq, wire, cert in store.all_events():
        e = Event.from_wire(wire)
        for k in e.keys():
            kb = kbytes(k)
            if kb in seen and seen[kb] != e.id:
                out.append(("M2", k, "two finalized events share a key"))
            seen[kb] = e.id
    chains: dict = {}
    for eid, j, v in store.conn.execute("SELECT eid, j, v FROM consumed ORDER BY eid, j, v"):
        chains.setdefault((eid, j), []).append(v)
    for key, vs in chains.items():
        if vs != list(range(len(vs))):
            out.append(("M2", key, f"version chain not contiguous: {vs}"))
    for row in store.conn.execute("SELECT key FROM equivocations"):
        out.append(("M2", row[0], "equivocation recorded"))
    return out


def m3_lock_consistency(v) -> list:
    """No lock of this validator names an event other than the finalized event holding that key."""
    out = []
    final_by_key = {}
    for seq, wire, cert in v.store.all_events():
        e = Event.from_wire(wire)
        for k in e.keys():
            final_by_key[kbytes(k)] = e.id
    for key, eid in v.store.conn.execute("SELECT key, event_id FROM locks"):
        if key in final_by_key and final_by_key[key] != eid:
            out.append(("M3", v.vid, "lock names a different event than the finalized one"))
    return out


def g1_digest(store) -> bytes:
    h = hashlib.sha256()
    for (eid,) in store.conn.execute("SELECT id FROM events ORDER BY id"):
        h.update(eid)
    for row in store.conn.execute("SELECT eid, j, owner, currency, kappa FROM entries ORDER BY eid, j"):
        h.update(cbor.encode(list(row)))
    for row in store.conn.execute("SELECT eid, j, v, kc, by FROM consumed ORDER BY eid, j, v"):
        h.update(cbor.encode(list(row)))
    return h.digest()


def m5_convergence(replicas: list) -> list:
    """Equal event sets imply identical G1 (entries and consumed chains)."""
    out = []
    for i, a in enumerate(replicas):
        for b in replicas[i + 1:]:
            if a.store.ids() == b.store.ids() and g1_digest(a.store) != g1_digest(b.store):
                out.append(("M5", (a.name, b.name), "equal event sets, different G1"))
    return out


def all_monitors(cluster) -> list:
    out = []
    for v in cluster.validators.values():
        if v.byzantine is None:
            out += m1_supply_identity(v.store) + m2_single_spend(v.store) + m3_lock_consistency(v)
    out += m5_convergence([v for v in cluster.validators.values() if v.byzantine is None])
    return out


def m10_hold_coverage(cluster, flag_id: bytes) -> list:
    """Every in-scope cone output is Held at >= q honest validators (once the flag has been delivered)."""
    out = []
    honest = [v for v in cluster.validators.values() if v.byzantine is None]
    ref = honest[0]
    meta = ref.store.conn.execute("SELECT juris FROM flagmeta WHERE id=?", (flag_id,)).fetchone()
    if not meta:
        return [("M10", "flag unknown at reference validator")]
    sc = ref._scope(meta[0])
    for eid, j, owner in ref.store.conn.execute(
            "SELECT eid, j, owner FROM entries WHERE eid IN (SELECT id FROM flagcone WHERE flag=?)", (flag_id,)).fetchall():
        if owner in sc and sum(1 for v in honest if v.store.is_held((eid, j))) < cluster.P.q:
            out.append(("M10", (eid.hex()[:8], j), "in-scope cone output held at fewer than q validators"))
    return out
