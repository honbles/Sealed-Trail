"""Flag and Release artifacts (paper section 5; spec 3.7).

A flag names root events (injection: the whole amount, D21; oracle-fraud partial roots come
with V4), a jurisdiction J, and an expiry. It is valid iff signed by t_reg distinct registered
regulators whose scope contains J. A Release is signed by a review body distinct from every
regulator and lifts a flag early; expiry lifts it by default.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import cbor
from . import crypto as C


def flag_msg(fid: bytes) -> bytes:
    return b"st/flag/v1" + fid


def release_msg(rid: bytes) -> bytes:
    return b"st/release/v1" + rid


@dataclass
class Flag:
    roots: list
    juris: str
    t_flag: float
    t_exp: float
    nonce: bytes
    sigs: dict = field(default_factory=dict)       # regulator id -> signature
    brec: str = ""                                  # recovery bank (must lie in J or M_J)
    inj: dict = field(default_factory=dict)         # root id -> injected amount (oracle-fraud flags); absent = whole

    def body(self):
        b = {"r": sorted(self.roots), "j": self.juris, "tf": int(self.t_flag), "te": int(self.t_exp), "n": self.nonce}
        if self.brec:
            b["b"] = self.brec
        if self.inj:
            b["x"] = [[k, v] for k, v in sorted(self.inj.items())]
        return b

    @property
    def id(self) -> bytes:
        return C.sha256(b"st/flag", cbor.encode(self.body()))

    def to_wire(self) -> bytes:
        return cbor.encode({"b": self.body(), "s": self.sigs})

    @classmethod
    def from_wire(cls, w: bytes) -> "Flag":
        d = cbor.decode(w)
        b = d["b"]
        return cls(list(b["r"]), b["j"], b["tf"], b["te"], b["n"], dict(d["s"]), brec=b.get("b", ""), inj={k: v for k, v in b.get("x", [])})


@dataclass
class Release:
    flag: bytes
    nonce: bytes
    sigs: dict = field(default_factory=dict)

    @property
    def id(self) -> bytes:
        return C.sha256(b"st/release", self.flag, self.nonce)

    def to_wire(self) -> bytes:
        return cbor.encode({"f": self.flag, "n": self.nonce, "s": self.sigs})

    @classmethod
    def from_wire(cls, w: bytes) -> "Release":
        d = cbor.decode(w)
        return cls(d["f"], d["n"], dict(d["s"]))


def flag_valid(f: Flag, trust) -> bool:
    if f.juris not in trust.jurisdictions or not f.roots or f.t_exp <= f.t_flag:
        return False
    good = set()
    for rid, sig in f.sigs.items():
        reg = trust.regulators.get(rid)
        if reg and f.juris in reg[1] and C.verify_sig(reg[0], flag_msg(f.id), sig):
            good.add(rid)
    return len(good) >= trust.reg_threshold


def release_valid(r: Release, trust) -> bool:
    good = {rid for rid, sig in r.sigs.items()
            if rid in trust.review_pks and rid not in trust.regulators
            and C.verify_sig(trust.review_pks[rid], release_msg(r.id), sig)}
    return len(good) >= trust.review_threshold


class Regulator:
    def __init__(self, rid: str, scope: tuple, kp: C.KeyPair | None = None):
        self.id, self.scope = rid, tuple(scope)
        self.kp = kp or C.KeyPair()

    def sign_flag(self, f: Flag):
        f.sigs[self.id] = self.kp.sign(flag_msg(f.id))
        return f

    def sign_phase4(self, p: "Phase4"):
        p.sigs[self.id] = self.kp.sign(phase4_msg(p.id))
        return p

    def sign_release(self, r: Release):
        r.sigs[self.id] = self.kp.sign(release_msg(r.id))
        return r


def phase4_msg(pid: bytes) -> bytes:
    return b"st/phase4/v1" + pid


@dataclass
class Phase4:
    """Regulator-signed release list for Phase 4 (decision D6): banks below Tmin."""
    flag: bytes
    banks: list
    nonce: bytes
    sigs: dict = field(default_factory=dict)

    @property
    def id(self) -> bytes:
        return C.sha256(b"st/phase4", self.flag, cbor.encode(sorted(self.banks)), self.nonce)

    def to_wire(self) -> bytes:
        return cbor.encode({"f": self.flag, "b": sorted(self.banks), "n": self.nonce, "s": self.sigs})

    @classmethod
    def from_wire(cls, w: bytes) -> "Phase4":
        d = cbor.decode(w)
        return cls(d["f"], list(d["b"]), d["n"], dict(d["s"]))


def phase4_valid(p: Phase4, juris: str, trust) -> bool:
    good = set()
    for rid, sig in p.sigs.items():
        reg = trust.regulators.get(rid)
        if reg and juris in reg[1] and C.verify_sig(reg[0], phase4_msg(p.id), sig):
            good.add(rid)
    return len(good) >= trust.reg_threshold
