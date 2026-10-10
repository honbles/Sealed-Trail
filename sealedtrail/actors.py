"""Trusted outside actors with a test-mode clock: NA, TSA, TIV (spec sections 3.3-3.6, 6)."""
from __future__ import annotations

import os

from . import crypto as C
from .model import att_msg, tok_msg, tiv_msg


class NA:
    """Reserve-attestation signer. Prototype: one Ed25519 key (FROST threshold is M-later).

    Policy D17: attest at onboarding only, one attestation per account; every
    attestation is logged (stand-in for the CT log).
    """

    def __init__(self, kp: C.KeyPair | None = None):
        self.kp = kp or C.KeyPair()
        self.log: list = []

    def attest(self, currency: str, amax: int):
        rid = os.urandom(16)
        sig = self.kp.sign(att_msg(rid, currency, amax))
        self.log.append((rid, currency, amax))
        return rid, sig


class TSA:
    """RFC 3161-style time-stamp authority with injectable offset and rate."""

    def __init__(self, tsa_id: str, clock, kp: C.KeyPair | None = None):
        self.id, self.clock = tsa_id, clock
        self.kp = kp or C.KeyPair()
        self.offset = 0.0
        self.t_rev: float | None = None    # key revocation time (class 2/14 tests)

    def stamp(self, eid: bytes):
        t = int(self.clock.now() + self.offset)
        return [self.id, t, self.kp.sign(tok_msg(eid, t))]


class TIV:
    def __init__(self, tiv_id: str, kp: C.KeyPair | None = None):
        self.id = tiv_id
        self.kp = kp or C.KeyPair()
        self.counter = 0

    def next_nu(self) -> int:
        self.counter += 1          # persisted before signing in a real deployment
        return self.counter

    def sign(self, issuer: str, kappa: bytes, nu: int, clean: int = 0) -> bytes:
        return self.kp.sign(tiv_msg(issuer, kappa, nu, clean))
