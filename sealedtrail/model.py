"""Events, entries and their canonical encoding (paper section 2, spec section 4).

Preimage (Enc) covers the event body only. Range/floor proofs, the time-stamp
token, the issuer signature, the reserve attestation / TIV signatures and Q(e)
are attachments and are not part of the preimage (decision D1).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import cbor
from .crypto import sha256

GEN, DEB, ANC, EXT, REV = "GEN", "DEB", "ANC", "EXT", "REV"
TYPES = (GEN, DEB, ANC, EXT, REV)
TAG = {t: b"st/ev/" + t.encode() + b"/v1" for t in TYPES}


@dataclass(frozen=True)
class Out:
    owner: str
    currency: str
    kappa: bytes
    hadv: bytes | None = None   # settlement-advice hash h_j


@dataclass(frozen=True)
class Par:
    eid: bytes   # id of the event that created the entry
    j: int       # output index
    v: int       # version (number of earlier debits on the entry)
    kc: bytes    # commitment to the consumed portion

    @property
    def key(self):
        return (self.eid, self.j)


@dataclass
class Event:
    type: str
    issuer: str
    outputs: list = field(default_factory=list)
    parents: list = field(default_factory=list)
    epoch: int = 0
    rev_kind: str | None = None        # "reversal" | "restitution" for REV (D2)
    kx: bytes | None = None            # committed exit amount (EXT)
    currency: str | None = None        # currency of an EXT (no output carries it)
    rid: bytes | None = None           # GEN: reserve attestation nonce
    amax: int | None = None            # GEN: attested cap
    tiv: str | None = None             # ANC
    nu: int | None = None              # ANC nonce (unique per TIV)
    clean: int = 0                     # ANC clean-attestation bit c (D15)
    flag: bytes | None = None          # REV: flag id
    travel: bytes | None = None        # Travel Rule hash (optional)
    intl: dict | None = None           # international fields (V4), None otherwise
    # attachments (not in the preimage)
    sig: bytes = b""
    token: dict | None = None          # {"sigs": [[tsa, time, sig], ...]}
    range_proof: bytes = b""
    floor_proofs: list = field(default_factory=list)
    att_sig: bytes = b""               # GEN reserve attestation signature
    rev_open: dict | None = None       # REV attachment: openings of consumed portions and output (not in the preimage)
    rate_doc: dict | None = None       # V4 attachment: the oracle rate document (bound by its hash in `intl`)
    intl_limbs: list | None = None     # V4 attachment: 8 limb commitments of the two tolerance values
    tiv_sig: bytes = b""               # ANC TIV signature
    _id: bytes | None = field(default=None, repr=False, compare=False)

    # encoding
    def body(self) -> dict:
        b = {
            "t": self.type,
            "i": self.issuer,
            "ep": self.epoch,
            "o": [[o.owner, o.currency, o.kappa, o.hadv] for o in self.outputs],
            "p": [[p.eid, p.j, p.v, p.kc] for p in self.parents],
        }
        if self.rev_kind is not None:
            b["rk"] = self.rev_kind
        if self.kx is not None:
            b["kx"] = self.kx
        if self.currency is not None:
            b["cur"] = self.currency
        if self.rid is not None:
            b["rid"] = self.rid
            b["amax"] = self.amax
        if self.tiv is not None:
            b["tiv"] = self.tiv
            b["nu"] = self.nu
            b["cl"] = self.clean
        if self.flag is not None:
            b["fl"] = self.flag
        if self.travel is not None:
            b["tr"] = self.travel
        if self.intl is not None:
            b["x"] = self.intl
        return b

    def enc(self) -> bytes:
        return TAG[self.type] + cbor.encode(self.body())

    @property
    def id(self) -> bytes:
        if self._id is None:
            self._id = sha256(self.enc())
        return self._id

    def invalidate(self):
        self._id = None

    # wire
    def to_wire(self) -> bytes:
        return cbor.encode({
            "body": self.body(),
            "sig": self.sig,
            "tok": self.token,
            "rp": self.range_proof,
            "fp": list(self.floor_proofs),
            "as": self.att_sig,
            "ts": self.tiv_sig,
            "ro": self.rev_open,
            "rd": self.rate_doc,
            "il": self.intl_limbs,
        })

    @staticmethod
    def from_wire(raw: bytes) -> "Event":
        d = cbor.decode(raw)
        b = d["body"]
        t = b["t"]
        if t not in TYPES:
            raise cbor.CBORError("unknown type")
        e = Event(
            type=t,
            issuer=b["i"],
            epoch=b["ep"],
            outputs=[Out(o[0], o[1], o[2], o[3]) for o in b["o"]],
            parents=[Par(p[0], p[1], p[2], p[3]) for p in b["p"]],
            rev_kind=b.get("rk"),
            kx=b.get("kx"),
            currency=b.get("cur"),
            rid=b.get("rid"),
            amax=b.get("amax"),
            tiv=b.get("tiv"),
            nu=b.get("nu"),
            clean=b.get("cl", 0),
            flag=b.get("fl"),
            travel=b.get("tr"),
            intl=b.get("x"),
            sig=d["sig"],
            token=d["tok"],
            range_proof=d["rp"],
            floor_proofs=list(d["fp"]),
            att_sig=d["as"],
            tiv_sig=d["ts"],
            rev_open=d.get("ro"),
            rate_doc=d.get("rd"),
            intl_limbs=d.get("il"),
        )
        if e.body() != b:  # canonical re-encoding must reproduce the body exactly
            raise cbor.CBORError("non-canonical body")
        return e

    # helpers
    def keys(self):
        """Lock keys of the event (paper section 3)."""
        if self.type == GEN:
            return [("rid", self.rid)]
        if self.type == ANC:
            return [("anc", self.tiv, self.nu)]
        return [("pv", p.eid, p.j, p.v) for p in self.parents]

    def currency_of(self) -> str | None:
        if self.outputs:
            return self.outputs[0].currency
        return self.currency

    def token_time(self) -> float | None:
        if not self.token:
            return None
        ts = sorted(s[1] for s in self.token["sigs"])
        return ts[len(ts) // 2]


def sig_msg(eid: bytes) -> bytes:
    return b"st/sig/v1" + eid


def tok_msg(eid: bytes, t: int) -> bytes:
    return b"st/tok/v1" + eid + int(t).to_bytes(8, "big")


def lock_msg(eid: bytes) -> bytes:
    return b"st/lock/v1" + eid


def att_msg(rid: bytes, currency: str, amax: int) -> bytes:
    return b"st/att/v1" + cbor.encode([rid, currency, amax])


def tiv_msg(issuer: str, kappa: bytes, nu: int, clean: int) -> bytes:
    return b"st/tiv/v1" + cbor.encode([issuer, kappa, nu, clean])


def cert_msg(cert: dict) -> bytes:
    return b"st/cert/v1" + cbor.encode(cert)
