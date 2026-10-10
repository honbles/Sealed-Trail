"""Ledger replica and validator (paper section 3, Algorithm 2).

`Ledger` accepts finalized events (parent- and version-closed, Corollary 10).
`Validator` adds the lock step, finality certificates' signing and abort proofs.
"""
from __future__ import annotations

from . import cbor
from . import crypto as C
from .model import Event, lock_msg, DEB, REV, EXT, ANC
from .flags import Flag, Release, Phase4, flag_valid, release_valid, phase4_valid
from .params import Params
from .store import Store, Equivocation, kbytes
from .trust import Trust
from .valid import validate, Invalid, NeedParents


def abort_msg(eid: bytes) -> bytes:
    return b"st/abort/v1" + eid


class Ledger:
    """A replica of G1: finalized events only."""

    def __init__(self, name: str, P: Params, trust: Trust, path: str = ":memory:", rev_check=None):
        self.name, self.P, self.trust = name, P, trust
        self.store = Store(path)
        self.fetcher = None            # callable(eid) -> (wire, cert) | None
        self.rev_check = rev_check
        self.on_finalized = []         # callbacks(event, ttok) (ONLEARN hooks)

    def verify_cert(self, eid: bytes, cert: dict) -> bool:
        good = 0
        for vid, sig in cert.items():
            pk = self.trust.validator_pks.get(vid)
            if pk and C.verify_sig(pk, lock_msg(eid), sig):
                good += 1
        return good >= self.P.q

    def _validate(self, e: Event, lock: bool = False):
        # V6 (REV) is checked when locking; a finalized event is trusted on its q-certificate (D13)
        return validate(e, self.store, self.P, self.trust, rev_check=(self.rev_check if lock else None))

    def accept(self, wire: bytes, cert: dict, _depth: int = 0) -> bool:
        """Verify and store a finalized event. Fetches missing parents from peers."""
        e = Event.from_wire(wire)
        if self.store.has_event(e.id):
            return True
        if not self.verify_cert(e.id, cert):
            raise Invalid("CERT", "fewer than q valid signatures")
        for _ in range(8):
            try:
                info = self._validate(e)
                break
            except NeedParents as n:
                if self.fetcher is None or _depth > 200:
                    raise
                progressed = False
                for eid in n.missing:
                    got = self.fetcher(eid)
                    if got:
                        self.accept(got[0], got[1], _depth + 1)
                        progressed = True
                if not progressed:
                    raise
        else:
            raise Invalid("PARENTS", "could not fetch parents")
        try:
            with self.store.write():
                self.store.put_finalized(e, cert, info["ttok"])
        except Equivocation as ex:
            self.store.record_equivocation(ex.key, ex.a, ex.b)
            raise Invalid("EQUIVOCATION", "two certificates on one key")
        for cb in self.on_finalized:
            cb(e, info["ttok"])
        return True

    def get(self, eid):
        """Fetch an event by id, or the event that consumed version v of an entry: ("v", eid, j, v)."""
        if isinstance(eid, tuple):
            _, peid, j, v = eid
            eid = self.store.consumed_by(peid, j, v)
            if eid is None:
                return None
        r = self.store.get_event(eid)
        if not r:
            return None
        return r[0].to_wire(), r[1]

    def sync_from(self, other: "Ledger") -> int:
        """Union merge (Corollary 10): pull every event we lack, parents first."""
        n = 0
        for seq, wire, cert in other.store.all_events():
            e = Event.from_wire(wire)
            if not self.store.has_event(e.id):
                self.accept(wire, cbor.decode(cert))
                n += 1
        return n


class Validator(Ledger):
    def __init__(self, vid: str, kp: C.KeyPair, P: Params, trust: Trust, clock, path: str = ":memory:"):
        super().__init__(vid, P, trust, path)
        self.vid, self.kp, self.clock = vid, kp, clock
        self.byzantine: str | None = None   # None | "double_sign" | "silent"
        self.on_finalized.append(self._onlearn)
        self.on_finalized.append(self._record_rev_openings)
        self.rev_check = self._rev_check

    # Alg 2
    def request_lock(self, wire: bytes):
        """Returns ("ok", sig) | ("reject", code) | ("need", [eids])."""
        if self.byzantine == "silent":
            return ("reject", "SILENT")
        self.lapse()
        try:
            e = Event.from_wire(wire)
        except Exception:
            return ("reject", "ENCODING")
        try:
            info = self._validate(e, lock=True)
        except NeedParents as n:
            if self.fetcher:
                try:
                    for eid in n.missing:
                        got = self.fetcher(eid)
                        if got:
                            self.accept(got[0], got[1])
                    info = self._validate(e, lock=True)
                except NeedParents as n2:
                    return ("need", sorted(n2.missing, key=repr))
                except Invalid as ex:
                    return ("reject", ex.code)
            else:
                return ("need", sorted(n.missing, key=repr))
        except Invalid as ex:
            return ("reject", ex.code)
        ttok, now = info["ttok"], self.clock.now()
        keys = [kbytes(k) for k in e.keys()]
        with self.store.write():
            if e.type != REV and self.byzantine != "double_sign":      # a Byzantine validator ignores holds too
                for p in e.parents:
                    if self.store.is_held(p.key):
                        return ("reject", "HELD")
            if self.byzantine != "double_sign":
                cur = {k: self.store.get_lock(k) for k in keys}
                for v in cur.values():
                    if v is not None and v != e.id:
                        return ("reject", "LOCKED")
                if any(v is None for v in cur.values()) and now - ttok > self.P.delta_stale:
                    return ("reject", "STALE")
            for k in keys:
                self.store.conn.execute("INSERT OR IGNORE INTO locks(key,event_id) VALUES(?,?)", (k, e.id))
        # signature leaves the process only after COMMIT (D33)
        return ("ok", self.kp.sign(lock_msg(e.id)))

    def finalize(self, wire: bytes, cert: dict) -> bool:
        return self.accept(wire, cert)

    # flags and Hold (M6)
    def _scope(self, juris: str) -> set:
        return set(self.trust.jurisdictions.get(juris, ())) | set(self.trust.mutual.get(juris, ()))

    def _hold_outputs(self, fid: bytes, juris: str, eid: bytes):
        """Hold every output of a cone event owned in J or M_J (a zero residual looks live, D20)."""
        sc = self._scope(juris)
        for j, owner in self.store.conn.execute("SELECT j, owner FROM entries WHERE eid=?", (eid,)).fetchall():
            if owner in sc:
                self.store.conn.execute("INSERT OR IGNORE INTO holds(eid,j,flag) VALUES(?,?,?)", (eid, j, fid))

    def _join(self, fid: bytes, juris: str, eid: bytes) -> bool:
        cur = self.store.conn.execute("INSERT OR IGNORE INTO flagcone(flag,id) VALUES(?,?)", (fid, eid))
        if cur.rowcount:
            self._hold_outputs(fid, juris, eid)
            return True
        return False

    def submit_flag(self, wire: bytes):
        """Verify, append to the flag log, build the cone and Hold it (Algorithm 3, Phase 0)."""
        from .engine.cone import cone_build
        if self.byzantine == "silent":
            return ("reject", "SILENT")
        f = Flag.from_wire(wire)
        if not flag_valid(f, self.trust):
            return ("reject", "FLAG_INVALID")
        if self.clock.now() >= f.t_exp:
            return ("reject", "FLAG_EXPIRED")
        fid = f.id
        with self.store.write():
            if self.store.conn.execute("SELECT 1 FROM flaglog WHERE id=?", (fid,)).fetchone():
                return ("ok", fid)
            self.store.conn.execute("INSERT INTO flaglog VALUES(?,?,?)", (fid, "flag", wire))
            self.store.conn.execute("INSERT INTO flagmeta VALUES(?,?,1,?)", (fid, f.t_exp, f.juris))
            present = [r for r in f.roots if self.store.has_event(r)]
            for eid in cone_build(self.store, present, self.P.w_esc):
                self._join(fid, f.juris, eid)
        return ("ok", fid)

    def submit_release(self, wire: bytes):
        r = Release.from_wire(wire)
        if not release_valid(r, self.trust):
            return ("reject", "RELEASE_INVALID")
        with self.store.write():
            if self.store.conn.execute("SELECT 1 FROM flaglog WHERE id=?", (r.id,)).fetchone():
                return ("ok", r.id)
            self.store.conn.execute("INSERT INTO flaglog VALUES(?,?,?)", (r.id, "release", wire))
            self.store.conn.execute("UPDATE flagmeta SET active=0 WHERE id=?", (r.flag,))
            self.store.conn.execute("DELETE FROM holds WHERE flag=?", (r.flag,))
        return ("ok", r.id)

    def lapse(self):
        """Expiry lifts a flag by default."""
        now = self.clock.now()
        rows = self.store.conn.execute("SELECT id FROM flagmeta WHERE active=1 AND t_exp<=?", (now,)).fetchall()
        if rows:
            with self.store.write():
                for (fid,) in rows:
                    self.store.conn.execute("UPDATE flagmeta SET active=0 WHERE id=?", (fid,))
                    self.store.conn.execute("DELETE FROM holds WHERE flag=?", (fid,))

    def _onlearn(self, e: Event, ttok: float):
        """ONLEARN (Algorithm 5): a late-finalized event joins the cone if a parent is in it, if it
        is a root of the flag, or if it is an anchor inside the window of a cone exit."""
        flags = self.store.conn.execute("SELECT id, juris, wire FROM flagmeta JOIN flaglog USING(id) WHERE active=1").fetchall()
        if not flags:
            return
        with self.store.write():
            for fid, juris, wire in flags:
                f = Flag.from_wire(wire)
                joins = e.id in f.roots or any(
                    self.store.conn.execute("SELECT 1 FROM flagcone WHERE flag=? AND id=?", (fid, p.eid)).fetchone()
                    for p in e.parents)
                if not joins and e.type == ANC:
                    for (xid,) in self.store.conn.execute(
                            "SELECT id FROM flagcone WHERE flag=?", (fid,)).fetchall():
                        m = self.store.event_meta(xid)
                        if m and m["type"] == EXT and abs(ttok - m["ttok"]) <= self.P.w_esc:
                            joins = True
                            break
                if joins and self._join(fid, juris, e.id):
                    if e.type == EXT:                      # a new exit pulls in the anchors of its window
                        for ttk, dep, aid, typ in self.store.ordered_ext_anc():
                            if typ == ANC and abs(ttk - ttok) <= self.P.w_esc:
                                self._join(fid, juris, aid)

    def exposure(self, fid: bytes) -> dict:
        """B1 and its split into held (in J or M_J) and foreign owners (reported, not held)."""
        row = self.store.conn.execute("SELECT juris FROM flagmeta WHERE id=?", (fid,)).fetchone()
        sc = self._scope(row[0]) if row else set()
        owners = {o for (o,) in self.store.conn.execute(
            "SELECT DISTINCT owner FROM entries WHERE eid IN (SELECT id FROM flagcone WHERE flag=?)", (fid,))}
        return {"held": sorted(owners & sc), "foreign": sorted(owners - sc)}

    def sync_from(self, other):
        n = super().sync_from(other)
        if hasattr(other, "store"):
            for fid, kind, wire in other.store.conn.execute("SELECT id, kind, wire FROM flaglog").fetchall():
                if not self.store.conn.execute("SELECT 1 FROM flaglog WHERE id=?", (fid,)).fetchone():
                    {"flag": self.submit_flag, "release": self.submit_release, "phase4": self.submit_phase4}[kind](wire)
        return n

    # abort proofs
    def abort_statement(self, eid: bytes, ttok: float):
        """An honest validator states 'I have not signed e and e is stale at me'."""
        held = self.store.conn.execute("SELECT 1 FROM locks WHERE event_id=? LIMIT 1", (eid,)).fetchone()
        if held or self.clock.now() - ttok <= self.P.delta_stale:
            return None
        return (self.vid, self.kp.sign(abort_msg(eid)))

    def apply_abort(self, eid: bytes, statements: list) -> bool:
        need = self.P.k + self.P.f - self.P.q + 1
        good = {v for v, s in statements if v in self.trust.validator_pks and C.verify_sig(self.trust.validator_pks[v], abort_msg(eid), s)}
        if len(good) < need:
            return False
        with self.store.write():
            self.store.conn.execute("DELETE FROM locks WHERE event_id=?", (eid,))
        return True

    # opening log (D13)
    def record_opening(self, commit: bytes, a: int, r: int):
        """Accept an opening iff Com(a; r) equals a public commitment (Theorem 18)."""
        if C.commit(a, r) != commit:
            return ("reject", "OPENING")
        pub = self.store.conn.execute(
            "SELECT 1 FROM entries WHERE kappa=? UNION SELECT 1 FROM consumed WHERE kc=?", (commit, commit)).fetchone()
        if not pub:
            return ("reject", "NOT_PUBLIC")
        with self.store.write():
            self.store.conn.execute("INSERT OR REPLACE INTO openings VALUES(?,?,?)",
                                    (commit, str(a), r.to_bytes(32, "little")))
        return ("ok", None)

    def opening(self, commit: bytes):
        row = self.store.conn.execute("SELECT a, r FROM openings WHERE ref=?", (commit,)).fetchone()
        return None if row is None else (int(row[0]), int.from_bytes(row[1], "little"))

    def _record_rev_openings(self, e: Event, ttok: float):
        if e.type == REV and e.rev_open:
            for p, (c, rb) in zip(e.parents, e.rev_open["c"]):
                self.record_opening(p.kc, c, int.from_bytes(rb, "little"))
            m, rb = e.rev_open["m"]
            self.record_opening(e.outputs[0].kappa, m, int.from_bytes(rb, "little"))

    def _flag_row(self, fid: bytes):
        return self.store.conn.execute(
            "SELECT m.active, m.juris, l.wire FROM flagmeta m JOIN flaglog l ON l.id = m.id WHERE m.id=?", (fid,)).fetchone()

    def _engine(self, f: Flag):
        from .engine.facts import LogOpenings, run_engine
        return run_engine(self.store, LogOpenings(self.store, self.opening), list(f.roots), self.P.w_esc, f.brec, f.inj)

    # V6
    def _rev_check(self, e: Event):
        row = self._flag_row(e.flag)
        if not row or not row[0]:
            raise Invalid("V6_FLAG", "flag unknown, released or expired")
        f = Flag.from_wire(row[2])
        if e.issuer not in self._scope(f.juris):
            raise Invalid("V6_SCOPE")
        ro = e.rev_open
        if not ro or len(ro["c"]) != len(e.parents):
            raise Invalid("V6_OPENING", "missing")
        total = 0
        for p, (c, rb) in zip(e.parents, ro["c"]):
            if C.commit(c, int.from_bytes(rb, "little")) != p.kc:
                raise Invalid("V6_OPENING", "consumed portion")
            total += c
            held = self.store.conn.execute("SELECT 1 FROM holds WHERE eid=? AND j=? AND flag=?",
                                           (p.eid, p.j, e.flag)).fetchone()
            incone = self.store.conn.execute("SELECT 1 FROM flagcone WHERE flag=? AND id=?", (e.flag, p.eid)).fetchone()
            if not held or not incone:
                raise Invalid("V6_NOT_HELD", "parent must be Held and in the cone")
        m, rb = ro["m"]
        if C.commit(m, int.from_bytes(rb, "little")) != e.outputs[0].kappa or m != total:
            raise Invalid("V6_OPENING", "output amount")
        if e.rev_kind == "reversal":
            if e.outputs[0].owner != f.brec:
                raise Invalid("V6_BREC", "recovery entry must be owned by the recovery bank")
            eng = self._engine(f)
            if any(ent.unres for ent in eng.entries.values() if ent.owner == e.issuer) or \
                    any(eng.entries.get(p.key) is None or eng.entries[p.key].unres for p in e.parents):
                raise Invalid("V6_UNRESOLVED")
            if m > eng.Tb(e.issuer):
                raise Invalid("V6_TB", "m exceeds Tb")
        elif e.issuer != f.brec:
            raise Invalid("V6_BREC", "only the recovery bank issues a restitution")

    # Phase 4 (D6)
    def submit_phase4(self, wire: bytes):
        p = Phase4.from_wire(wire)
        row = self._flag_row(p.flag)
        if not row:
            return ("reject", "FLAG_UNKNOWN")
        if not phase4_valid(p, row[1], self.trust):
            return ("reject", "PHASE4_INVALID")
        f = Flag.from_wire(row[2])
        with self.store.write():
            if self.store.conn.execute("SELECT 1 FROM flaglog WHERE id=?", (p.id,)).fetchone():
                return ("ok", 0)
            self.store.conn.execute("INSERT INTO flaglog VALUES(?,?,?)", (p.id, "phase4", wire))
        issued = set()
        for (eid,) in self.store.conn.execute("SELECT id FROM events WHERE type='REV'").fetchall():
            ev = self.store.get_event(eid)[0]
            if ev.flag == p.flag and ev.rev_kind == "reversal":
                issued.add(ev.issuer)
        rel = set(p.banks) | issued
        eng = self._engine(f)
        released = []
        with self.store.write():
            for eid, j in self.store.holds_of(p.flag):
                ent = eng.entries.get((eid, j))
                if ent is None or ent.unres:
                    continue                                           # Unresolved stays Held until t_exp
                ev = self.store.get_event(eid)[0]
                if ev.type == REV and ev.rev_kind == "reversal":
                    continue                                           # recovery entries stay Held (D7)
                if ent.owner in rel or (ev.type == ANC and ent.rho == 0):
                    self.store.conn.execute("DELETE FROM holds WHERE eid=? AND j=? AND flag=?", (eid, j, p.flag))
                    released.append((eid, j))
        return ("ok", len(released))
