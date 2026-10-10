"""Bank-side event construction (paper section 2, spec sections 3.2 and 5.2).

A bank keeps, per owned entry, the opening (a, r) of the entry commitment and the
opening (c, r^c) of every portion consumed from it, so it can derive the residual
amount and blinding and build proofs for the next debit.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import crypto as C
from .crypto import L
from .model import Event, Out, Par, GEN, DEB, EXT, ANC, REV, sig_msg
from .oracle import rate_doc_id
from .valid import floor_ctx, tol_coeffs


@dataclass
class Holding:
    eid: bytes
    j: int
    owner: str
    currency: str
    a: int
    r: int
    kappa: bytes
    cons: list = field(default_factory=list)   # [(c, r_c)] per finalized debit, in version order
    ttok: float = 0.0
    seq: int = 0                                # creation order, for FIFO selection

    @property
    def key(self):
        return (self.eid, self.j)

    @property
    def version(self) -> int:
        return len(self.cons)

    def residual(self):
        return (self.a - sum(c for c, _ in self.cons),
                (self.r - sum(rc for _, rc in self.cons)) % L)


@dataclass
class Built:
    event: Event
    parents: list            # [(Holding, c, r_c)]
    outputs: list            # [(owner, currency, a, r)]
    plaintext: dict          # side channel for the shadow ledger


def _omega(P, currency):
    return P.floor(currency)


def build_gen(kp, bank: str, P, currency: str, amount: int, rid: bytes, amax: int, att_sig: bytes,
              epoch: int, token_fn) -> Built:
    om = _omega(P, currency)
    r = C.rand_scalar()
    kappa = C.commit(amount, r)
    e = Event(type=GEN, issuer=bank, outputs=[Out(bank, currency, kappa)], epoch=epoch,
              rid=rid, amax=amax, att_sig=att_sig)
    # parties: shifted output, GEN cap party (valid.range_party_commitments)
    vals = [amount - om, amax - amount]
    bls = [r, (-r) % L]
    e.range_proof = C.prove_range(e.id, vals, bls)
    e.token = token_fn(e.id)
    e.sig = kp.sign(sig_msg(e.id))
    return Built(e, [], [(bank, currency, amount, r)], {"type": GEN, "out": [amount], "cons": []})


def build_anc(kp, bank: str, P, currency: str, amount: int, tiv, epoch: int, token_fn, clean: int = 0) -> Built:
    om = _omega(P, currency)
    r = C.rand_scalar()
    kappa = C.commit(amount, r)
    nu = tiv.next_nu()
    e = Event(type=ANC, issuer=bank, outputs=[Out(bank, currency, kappa)], epoch=epoch,
              tiv=tiv.id, nu=nu, clean=clean, tiv_sig=tiv.sign(bank, kappa, nu, clean))
    e.range_proof = C.prove_range(e.id, [amount - om], [r])
    e.token = token_fn(e.id)
    e.sig = kp.sign(sig_msg(e.id))
    return Built(e, [], [(bank, currency, amount, r)], {"type": ANC, "out": [amount], "cons": []})


def build_spend(kp, bank: str, P, currency: str, parents: list, outputs: list, epoch: int, token_fn,
                exit_: bool = False, hadv: list | None = None, rev: tuple | None = None,
                out_currency: str | None = None, rate_doc: dict | None = None) -> Built:
    """DEB (outputs = [(owner, amount)]) or EXT (exit_=True, no outputs).

    parents = [(Holding, c)] with c > 0. Fresh blindings r^c; output blindings sum to
    sum r^c so that sum kc - sum kappa_j is exactly the identity (r* = 0, V3).
    """
    om = _omega(P, currency)                    # floor of the parents' (source) currency
    ocur = out_currency or currency
    om_out = _omega(P, ocur)
    pars, cons = [], []
    for h, c in parents:
        rc = C.rand_scalar()
        cons.append((h, c, rc))
        pars.append(Par(h.eid, h.j, h.version, C.commit(c, rc)))
    total_c = sum(c for _, c, _ in cons)
    total_rc = sum(rc for _, _, rc in cons) % L
    outs, out_open = [], []
    if exit_:
        kx = C.commit(total_c, total_rc)
        e = Event(type=EXT, issuer=bank, parents=pars, epoch=epoch, kx=kx, currency=currency)
    else:
        m = len(outputs)
        if rate_doc is None:
            assert sum(a for _, a in outputs) == total_c, "outputs must sum to consumed portions"
            rs = [C.rand_scalar() for _ in range(m - 1)]
            rs.append((total_rc - sum(rs)) % L)
        else:                                    # V4: no balance identity, free output blindings
            rs = [C.rand_scalar() for _ in range(m)]
        for k, ((owner, a), r) in enumerate(zip(outputs, rs)):
            h = hadv[k] if hadv else None
            outs.append(Out(owner, ocur, C.commit(a, r), h))
            out_open.append((owner, ocur, a, r))
        if rev:                                    # rev = (rev_kind, flag id): one output, REV event
            assert len(outs) == 1
            e = Event(type=REV, issuer=bank, parents=pars, outputs=outs, epoch=epoch, flag=rev[1], rev_kind=rev[0])
        elif rate_doc is not None:
            e = Event(type=DEB, issuer=bank, parents=pars, outputs=outs, epoch=epoch,
                      intl={"s": currency, "n": rate_doc["n"], "d": rate_doc["d"], "t": rate_doc["t"],
                            "doc": rate_doc_id(rate_doc)})
            e.rate_doc = rate_doc
        else:
            e = Event(type=DEB, issuer=bank, parents=pars, outputs=outs, epoch=epoch)
    # floor proofs on the derived residuals (bound to the event id)
    fps, parties = [], []
    for i, (h, c, rc) in enumerate(cons):
        x, rx = h.residual()
        x -= c
        rx = (rx - rc) % L
        cx = C.commit(x, rx)
        proof, pv, pb = C.prove_floor(floor_ctx(e.id, i), cx, x, rx, om)
        fps.append(proof)
        parties.append((pv, pb))
    e.floor_proofs = fps
    vals = [a - om_out for _, _, a, _ in out_open] + [c for _, c, _ in cons] + [pv for pv, _ in parties]
    bls = [r for _, _, _, r in out_open] + [rc for _, _, rc in cons] + [pb for _, pb in parties]
    if rate_doc is not None:                      # V4 tolerance values as limb parties (spec D31)
        cp, cm, cr = tol_coeffs(P, rate_doc["n"], rate_doc["d"])
        Ar, rAr = sum(a for _, _, a, _ in out_open), sum(r for _, _, _, r in out_open) % L
        limbs = []
        for coef, sign in ((cp, -1), (cm, 1)):
            v = coef * total_c + sign * cr * Ar
            rv = (coef * total_rc + sign * cr * rAr) % L
            if v < 0:
                raise ValueError("amount outside the oracle tolerance")
            lv, lb = C.limb_split(v, rv)
            vals += lv
            bls += lb
            limbs += [C.commit(x, y) for x, y in zip(lv, lb)]
        e.intl_limbs = limbs
    e.range_proof = C.prove_range(e.id, vals, bls)
    e.token = token_fn(e.id)
    e.sig = kp.sign(sig_msg(e.id))
    if rev:                                        # V6 attachment: openings of the consumed portions and of m
        e.rev_open = {"c": [[c, rc.to_bytes(32, "little")] for _, c, rc in cons],
                      "m": [total_c, out_open[0][3].to_bytes(32, "little")]}
    return Built(e, cons, out_open,
                 {"type": e.type, "out": [a for _, _, a, _ in out_open], "cons": [c for _, c, _ in cons]})
