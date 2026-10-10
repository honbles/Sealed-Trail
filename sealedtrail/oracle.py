"""Oracles and rate documents (paper section 2 'Oracle aggregation', Lemma 4; spec 3.5).

Each oracle signs (pair, value, t). A rate document carries one signed observation per oracle and
publishes the LOWER median as epsilon. Validators recompute the median and verify every signature,
so whoever assembles the document is untrusted.
"""
from __future__ import annotations

from fractions import Fraction as F

from . import cbor
from . import crypto as C

MAX_RATIO_BITS = 32          # epsilon numerator/denominator bound (spec D31: values stay below 2^224)


def obs_msg(pair: str, vn: int, vd: int, t: int) -> bytes:
    return b"st/obs/v1" + cbor.encode([pair, vn, vd, t])


class Oracle:
    def __init__(self, oid: str, kp: C.KeyPair | None = None):
        self.id, self.kp = oid, kp or C.KeyPair()
        self.offset = F(1)       # test profile: multiply the honest value (a lying oracle)

    @property
    def pk(self) -> bytes:
        return self.kp.pk

    def observe(self, pair: str, true_rate: F, t: int) -> list:
        v = F(true_rate) * self.offset
        return [self.id, v.numerator, v.denominator, int(t), self.kp.sign(obs_msg(pair, v.numerator, v.denominator, int(t)))]


def lower_median(values: list) -> F:
    vs = sorted(values)
    return vs[(len(vs) - 1) // 2]          # rank ceil(n/2), Lemma 4


def make_rate_doc(pair: str, observations: list) -> dict:
    eps = lower_median([F(o[1], o[2]) for o in observations])
    return {"pair": pair, "n": eps.numerator, "d": eps.denominator, "t": max(o[3] for o in observations),
            "obs": [list(o) for o in observations]}


def rate_doc_id(doc: dict) -> bytes:
    return C.sha256(b"st/ratedoc/v1", cbor.encode(doc))


def check_rate_doc(doc: dict, trust, ttok: float, fresh: float):
    """Returns None if valid, else a reason string."""
    try:
        obs = doc["obs"]
        ids = [o[0] for o in obs]
        if sorted(ids) != sorted(trust.oracle_pks) or len(set(ids)) != len(ids):
            return "needs exactly one observation per oracle"
        for oid, vn, vd, t, sig in obs:
            if vn <= 0 or vd <= 0 or not C.verify_sig(trust.oracle_pks[oid], obs_msg(doc["pair"], vn, vd, t), sig):
                return f"bad observation from {oid}"
            if abs(ttok - t) > fresh:
                return f"stale observation from {oid}"
        eps = lower_median([F(o[1], o[2]) for o in obs])
        if (doc["n"], doc["d"]) != (eps.numerator, eps.denominator):
            return "epsilon is not the lower median of the observations"
        if doc["n"].bit_length() > MAX_RATIO_BITS or doc["d"].bit_length() > MAX_RATIO_BITS:
            return "epsilon too wide"
        if doc["t"] != max(o[3] for o in obs):
            return "bad document time"
    except (KeyError, TypeError, ValueError, ZeroDivisionError) as ex:
        return f"malformed: {ex}"
    return None
