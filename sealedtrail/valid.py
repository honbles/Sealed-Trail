"""Valid(e): the validity predicate of paper section 2 (V1 to V3, V5; V6 via hook).

A pure function of the event and the replicated state (store + trust logs).
V4 (international debits) is not implemented yet and is rejected explicitly.
"""
from __future__ import annotations

from functools import lru_cache

from . import crypto as C
from .model import Event, GEN, DEB, ANC, EXT, REV, sig_msg, tok_msg, att_msg, tiv_msg
from .oracle import check_rate_doc, rate_doc_id
from .params import Params
from .trust import Trust


class Invalid(Exception):
    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}")
        self.code = code


class NeedParents(Exception):
    """Local state is behind: fetch these events (and their versions) from peers."""

    def __init__(self, missing):
        super().__init__("need parents")
        self.missing = set(missing)


@lru_cache(maxsize=256)
def _omega_g(omega: int) -> bytes:
    return C.pmul(C.G, omega)


def tol_coeffs(P, en: int, ed: int):
    """V4 coefficients with theta = tn/td and eps = en/ed:
    D+ = (tn+td)*en*As - td*ed*Ar >= 0 and D- = (tn-td)*en*As + td*ed*Ar >= 0,
    i.e. |ed*Ar - en*As| <= (tn/td)*en*As."""
    tn, td = P.theta
    return (tn + td) * en, (tn - td) * en, td * ed


def floor_ctx(eid: bytes, i: int) -> bytes:
    return eid + i.to_bytes(2, "big")


def range_party_commitments(e: Event, omega: int, floor_parties: list) -> list:
    """Commitments of the aggregated range proof, in canonical order (spec section 4):
    shifted outputs, consumed portions, floor parties, then the GEN cap party."""
    parties = [C.psub(o.kappa, _omega_g(omega)) for o in e.outputs]
    parties += [p.kc for p in e.parents]
    parties += list(floor_parties)
    if e.intl_limbs:
        parties += list(e.intl_limbs)                       # V4: limbs of the two tolerance values
    if e.type == GEN:
        parties.append(C.psub(C.pmul(C.G, e.amax), e.outputs[0].kappa))
    return parties


def token_time(e: Event, trust: Trust, P: Params) -> float:
    tok = e.token
    if not tok or not tok.get("sigs"):
        raise Invalid("TOKEN", "missing")
    seen, times = set(), []
    for tsa, t, sig in tok["sigs"]:
        if tsa in seen or tsa not in trust.tsa_pks:
            continue
        if C.verify_sig(trust.tsa_pks[tsa], tok_msg(e.id, int(t)), sig):
            seen.add(tsa)
            times.append(float(t))
    if len(times) < P.m_tsa:
        raise Invalid("TOKEN", f"only {len(times)} valid authorities, need {P.m_tsa}")
    if max(times) - min(times) > P.delta_skew:
        raise Invalid("TOKEN", "authority clocks disagree beyond skew")
    times.sort()
    return times[len(times) // 2]


def validate(e: Event, store, P: Params, trust: Trust, rev_check=None, check_proofs: bool = True) -> dict:
    t = e.type
    # structure
    if len(e.parents) > P.p_max or len(e.outputs) > P.m_max:
        raise Invalid("CAPS")
    if t == GEN:
        if e.parents or len(e.outputs) != 1 or e.rid is None or e.amax is None:
            raise Invalid("SHAPE", "GEN")
    elif t == ANC:
        if e.parents or len(e.outputs) != 1 or e.tiv is None or e.nu is None or e.clean not in (0, 1):
            raise Invalid("SHAPE", "ANC")
    elif t == EXT:
        if e.outputs or not e.parents or e.kx is None or e.currency is None:
            raise Invalid("SHAPE", "EXT")
    elif t == DEB:
        if not e.outputs or not e.parents:
            raise Invalid("SHAPE", "DEB")
    elif t == REV:
        if len(e.outputs) != 1 or not e.parents or e.flag is None or e.rev_kind not in ("reversal", "restitution"):
            raise Invalid("SHAPE", "REV")
    else:
        raise Invalid("TYPE")
    if e.intl is not None and t != DEB:
        raise Invalid("V4_SHAPE", "only a DEB can be international")
    if e.intl is None and (e.intl_limbs or e.rate_doc):
        raise Invalid("V4_SHAPE", "tolerance attachments on a domestic event")
    if t in (GEN, ANC) and e.outputs[0].owner != e.issuer:
        raise Invalid("SHAPE", "root output must be owned by the issuer")
    if len({o.currency for o in e.outputs}) > 1:
        raise Invalid("SHAPE", "mixed output currencies")

    # issuer signature and certificate (V2)
    pk = trust.bank_pks.get(e.issuer)
    if pk is None:
        raise Invalid("V2_NO_CERT", e.issuer)
    if not C.verify_sig(pk, sig_msg(e.id), e.sig):
        raise Invalid("SIG")
    ttok = token_time(e, trust, P)
    cur = trust.epoch_at(ttok)
    start_cur = max(s for s, n in trust.epochs if n == cur)
    if not (e.epoch == cur or (e.epoch == cur - 1 and ttok < start_cur + trust.epoch_grace)):
        raise Invalid("V2_EPOCH", f"cited {e.epoch}, in force {cur}")
    rev = trust.revoked.get(e.epoch, {})
    if e.issuer in rev and not (ttok < rev[e.issuer]):
        raise Invalid("V2_REVOKED")

    cur_code = e.currency_of()
    if cur_code not in P.omega:
        raise Invalid("CURRENCY")
    omega = P.floor(cur_code)                     # floor of the output currency
    src_cur, omega_src = cur_code, omega          # parents' currency and floor (differ only for V4)
    if e.intl is not None:
        it = e.intl
        src_cur = it.get("s")
        if src_cur not in P.omega or src_cur == cur_code:
            raise Invalid("V4_CURRENCY", "source and target currency must differ and be known")
        omega_src = P.floor(src_cur)
        why = check_rate_doc(e.rate_doc or {}, trust, ttok, P.rate_fresh)
        if why:
            raise Invalid("V4_RATE", why)
        doc = e.rate_doc
        if doc["pair"] != f"{src_cur}/{cur_code}" or (it["n"], it["d"], it["t"]) != (doc["n"], doc["d"], doc["t"]) \
                or it["doc"] != rate_doc_id(doc):
            raise Invalid("V4_RATE", "event does not bind the rate document")

    floor_party_comms: list = []
    # parents (V1) and balance (V3)
    if t in (DEB, EXT, REV):
        seen, missing = set(), set()
        for p in e.parents:
            if p.key in seen:
                raise Invalid("DUP_PARENT")
            seen.add(p.key)
            ent = store.entry(*p.key)
            if ent is None:
                missing.add(p.eid)
            else:                                   # earlier versions must be finalized too (V1)
                have = len(store.consumed(p.eid, p.j))
                for vv in range(have, p.v):
                    missing.add(("v", p.eid, p.j, vv))
        if missing:
            raise NeedParents(missing)
        residual_after = []
        kc_sum = C.IDENTITY
        for p in e.parents:
            ent = store.entry(*p.key)
            if ent["owner"] != e.issuer:
                raise Invalid("V1_OWNER")
            if ent["currency"] != src_cur:
                raise Invalid("CURRENCY", "parent currency differs")
            if ttok < ent["ttok"]:
                raise Invalid("V1_TOKEN_ORDER")
            cons = store.consumed(p.eid, p.j)
            res = ent["kappa"]
            for kc in cons[: p.v]:
                res = C.psub(res, kc)
            residual_after.append(C.psub(res, p.kc))
            kc_sum = C.padd(kc_sum, p.kc)
        kout = e.kx if t == EXT else C.psum(o.kappa for o in e.outputs)
        if e.intl is None:
            if C.psub(kc_sum, kout) != C.IDENTITY:
                raise Invalid("V3_BALANCE")
        else:                                       # V4: tolerance |Ar - eps*As| <= theta*eps*As over hidden amounts
            cp, cm, cr = tol_coeffs(P, e.intl["n"], e.intl["d"])
            limbs = e.intl_limbs
            if not limbs or len(limbs) != 8:
                raise Invalid("V4_LIMBS", "need 8 limb commitments")
            c_plus = C.psub(C.pmul(kc_sum, cp), C.pmul(kout, cr))
            c_minus = C.padd(C.pmul(kc_sum, cm), C.pmul(kout, cr))
            if C.limb_recombine(limbs[:4]) != c_plus or C.limb_recombine(limbs[4:]) != c_minus:
                raise Invalid("V4_LIMBS", "limbs do not recombine to the tolerance values")
        if len(e.floor_proofs) != len(e.parents):
            raise Invalid("V3_FLOOR", "one zero-or-floor proof per parent")
        if check_proofs:
            for i, (rc, fp) in enumerate(zip(residual_after, e.floor_proofs)):
                party = C.verify_floor(floor_ctx(e.id, i), rc, omega_src, fp)
                if party is None:
                    raise Invalid("V3_FLOOR", f"parent {i}")
                floor_party_comms.append(party)
        else:
            floor_party_comms = [C.IDENTITY] * len(e.parents)
    elif e.floor_proofs:
        raise Invalid("SHAPE", "roots carry no floor proofs")

    # roots (V5)
    if t == GEN:
        if not C.verify_sig(trust.na_pk, att_msg(e.rid, e.outputs[0].currency, e.amax), e.att_sig):
            raise Invalid("V5_ATTESTATION")
    if t == ANC:
        tpk = trust.tiv_pks.get(e.tiv)
        if tpk is None:
            raise Invalid("V5_TIV", "not in trust list")
        if not C.verify_sig(tpk, tiv_msg(e.issuer, e.outputs[0].kappa, e.nu, e.clean), e.tiv_sig):
            raise Invalid("V5_TIV_SIG")
    if t == REV and rev_check is not None:
        rev_check(e)

    # aggregated range proof
    if check_proofs:
        comms = range_party_commitments(e, omega, floor_party_comms)
        if not comms or not C.verify_range(e.id, comms, e.range_proof):
            raise Invalid("V3_RANGE")
    return {"ttok": ttok}
