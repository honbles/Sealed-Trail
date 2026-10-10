"""Durable validator / replica state in SQLite (spec D33).

WAL + synchronous=FULL for file-backed stores; one writer per store; every write
transaction is BEGIN IMMEDIATE ... COMMIT.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

from . import cbor
from .model import Event, ANC, EXT

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, id BLOB UNIQUE, wire BLOB,
  cert BLOB, ttok REAL, depth INTEGER, type TEXT, issuer TEXT);
CREATE TABLE IF NOT EXISTS entries(eid BLOB, j INTEGER, owner TEXT, currency TEXT, kappa BLOB,
  ttok REAL, PRIMARY KEY(eid,j));
CREATE TABLE IF NOT EXISTS consumed(eid BLOB, j INTEGER, v INTEGER, kc BLOB, by BLOB,
  PRIMARY KEY(eid,j,v));
CREATE TABLE IF NOT EXISTS children(peid BLOB, j INTEGER, child BLOB);
CREATE INDEX IF NOT EXISTS ch_idx ON children(peid, j);
CREATE TABLE IF NOT EXISTS locks(key BLOB PRIMARY KEY, event_id BLOB);
CREATE INDEX IF NOT EXISTS lk_idx ON locks(event_id);
CREATE TABLE IF NOT EXISTS holds(eid BLOB, j INTEGER, flag BLOB, PRIMARY KEY(eid,j,flag));
CREATE TABLE IF NOT EXISTS e3(seq INTEGER PRIMARY KEY AUTOINCREMENT, src TEXT, dst TEXT, t REAL, event BLOB);
CREATE TABLE IF NOT EXISTS ordidx(ttok REAL, depth INTEGER, id BLOB, type TEXT, PRIMARY KEY(ttok,depth,id));
CREATE TABLE IF NOT EXISTS flaglog(id BLOB PRIMARY KEY, kind TEXT, wire BLOB);
CREATE TABLE IF NOT EXISTS flagmeta(id BLOB PRIMARY KEY, t_exp REAL, active INTEGER, juris TEXT);
CREATE TABLE IF NOT EXISTS flagcone(flag BLOB, id BLOB, PRIMARY KEY(flag,id));
CREATE TABLE IF NOT EXISTS openings(ref BLOB PRIMARY KEY, a TEXT, r BLOB);
CREATE TABLE IF NOT EXISTS equivocations(key BLOB, a BLOB, b BLOB);
"""


def kbytes(key) -> bytes:
    return cbor.encode(list(key))


class Equivocation(Exception):
    def __init__(self, key: bytes = b"", a: bytes = b"", b: bytes = b""):
        super().__init__("two certificates on one key")
        self.key, self.a, self.b = key, a, b


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(SCHEMA)
        self._depth = False

    @classmethod
    def reader(cls, path: str):
        """Short-lived read-only connection for HTTP read endpoints (WAL permits concurrent readers)."""
        s = cls.__new__(cls)
        s.path = path
        s.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, isolation_level=None, check_same_thread=False)
        return s

    def close(self):
        self.conn.close()

    @contextmanager
    def write(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    # reads
    def get_event(self, eid: bytes):
        r = self.conn.execute("SELECT wire, cert FROM events WHERE id=?", (eid,)).fetchone()
        if not r:
            return None
        return Event.from_wire(r[0]), cbor.decode(r[1])

    def has_event(self, eid: bytes) -> bool:
        return self.conn.execute("SELECT 1 FROM events WHERE id=?", (eid,)).fetchone() is not None

    def event_meta(self, eid: bytes):
        r = self.conn.execute("SELECT ttok, depth, type, issuer FROM events WHERE id=?", (eid,)).fetchone()
        return None if not r else dict(ttok=r[0], depth=r[1], type=r[2], issuer=r[3])

    def entry(self, eid: bytes, j: int):
        r = self.conn.execute(
            "SELECT owner, currency, kappa, ttok FROM entries WHERE eid=? AND j=?", (eid, j)).fetchone()
        return None if not r else dict(owner=r[0], currency=r[1], kappa=r[2], ttok=r[3])

    def consumed(self, eid: bytes, j: int) -> list:
        rows = self.conn.execute(
            "SELECT v, kc FROM consumed WHERE eid=? AND j=? ORDER BY v", (eid, j)).fetchall()
        out = []
        for i, (v, kc) in enumerate(rows):
            if v != i:
                break
            out.append(kc)
        return out

    def consumed_by(self, eid: bytes, j: int, v: int):
        r = self.conn.execute("SELECT by FROM consumed WHERE eid=? AND j=? AND v=?", (eid, j, v)).fetchone()
        return r[0] if r else None

    def children(self, eid: bytes, j: int | None = None):
        if j is None:
            rows = self.conn.execute("SELECT DISTINCT child FROM children WHERE peid=?", (eid,))
        else:
            rows = self.conn.execute("SELECT DISTINCT child FROM children WHERE peid=? AND j=?", (eid, j))
        return [r[0] for r in rows.fetchall()]

    def all_events(self, after_seq: int = 0):
        return self.conn.execute(
            "SELECT seq, wire, cert FROM events WHERE seq>? ORDER BY seq", (after_seq,)).fetchall()

    def event_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def ids(self) -> set:
        return {r[0] for r in self.conn.execute("SELECT id FROM events")}

    def get_lock(self, key: bytes):
        r = self.conn.execute("SELECT event_id FROM locks WHERE key=?", (key,)).fetchone()
        return r[0] if r else None

    def locks_of(self, eid: bytes):
        return [r[0] for r in self.conn.execute("SELECT key FROM locks WHERE event_id=?", (eid,))]

    def is_held(self, p) -> bool:
        return self.conn.execute("SELECT 1 FROM holds WHERE eid=? AND j=? LIMIT 1", (p[0], p[1])).fetchone() is not None

    def held_keys(self, now: float):
        """Entries Held by a flag that is active (not released) and not yet expired at `now`."""
        return {(r[0], r[1]) for r in self.conn.execute(
            "SELECT DISTINCT h.eid, h.j FROM holds h JOIN flagmeta m ON m.id = h.flag "
            "WHERE m.active=1 AND m.t_exp > ?", (now,))}

    def holds_of(self, flag: bytes):
        return [(r[0], r[1]) for r in self.conn.execute("SELECT eid, j FROM holds WHERE flag=?", (flag,))]

    def e3_edges(self):
        return self.conn.execute("SELECT src, dst, t, event FROM e3 ORDER BY seq").fetchall()

    def ordered_ext_anc(self):
        return self.conn.execute(
            "SELECT ttok, depth, id, type FROM ordidx ORDER BY ttok, depth, id").fetchall()

    def all_entries(self):
        return self.conn.execute("SELECT eid, j, owner, currency, kappa FROM entries").fetchall()

    # mutations
    def put_finalized(self, e: Event, cert: dict, ttok: float):
        """Insert a finalized event and update every index. Caller holds write()."""
        c = self.conn
        depth = 0
        for p in e.parents:
            m = self.event_meta(p.eid)
            depth = max(depth, 1 + (m["depth"] if m else 0))
        c.execute("INSERT OR IGNORE INTO events(id,wire,cert,ttok,depth,type,issuer) VALUES(?,?,?,?,?,?,?)",
                  (e.id, e.to_wire(), cbor.encode(cert), ttok, depth, e.type, e.issuer))
        for j, o in enumerate(e.outputs):
            c.execute("INSERT OR IGNORE INTO entries(eid,j,owner,currency,kappa,ttok) VALUES(?,?,?,?,?,?)",
                      (e.id, j, o.owner, o.currency, o.kappa, ttok))
        for p in e.parents:
            prev = self.consumed_by(p.eid, p.j, p.v)
            if prev is not None and prev != e.id:
                raise Equivocation(kbytes(("pv", p.eid, p.j, p.v)), prev, e.id)
            c.execute("INSERT OR IGNORE INTO consumed(eid,j,v,kc,by) VALUES(?,?,?,?,?)",
                      (p.eid, p.j, p.v, p.kc, e.id))
            c.execute("INSERT INTO children(peid,j,child) VALUES(?,?,?)", (p.eid, p.j, e.id))
        for j, o in enumerate(e.outputs):
            if o.owner != e.issuer:
                c.execute("INSERT INTO e3(src,dst,t,event) VALUES(?,?,?,?)", (e.issuer, o.owner, ttok, e.id))
        if e.type == EXT:
            c.execute("INSERT INTO e3(src,dst,t,event) VALUES(?,?,?,?)", (e.issuer, "⊥", ttok, e.id))
        if e.type == ANC:
            c.execute("INSERT INTO e3(src,dst,t,event) VALUES(?,?,?,?)", ("⊥", e.outputs[0].owner, ttok, e.id))
        if e.type in (EXT, ANC):
            c.execute("INSERT OR IGNORE INTO ordidx VALUES(?,?,?,?)", (ttok, depth, e.id, e.type))

    def record_equivocation(self, key: bytes, a: bytes, b: bytes):
        """Persist evidence in its own transaction (the failed insert was rolled back)."""
        with self.write():
            self.conn.execute("INSERT INTO equivocations VALUES(?,?,?)", (key, a, b))
