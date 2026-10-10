"""Build deliberately invalid events that still carry valid signatures and tokens,
so each validity clause can be tested in isolation (T-VALID-n)."""
import os

from sealedtrail import crypto as C
from sealedtrail.crypto import L
from sealedtrail.model import Event, Out, Par, DEB, GEN, sig_msg
from sealedtrail.valid import floor_ctx


def junk_proof(n=256):
    return os.urandom(n)


def reseal(e, kp, cluster, token_fn=None):
    e.invalidate()
    e.token = (token_fn or cluster.token)(e.id)
    e.sig = kp.sign(sig_msg(e.id))
    return e


def forge_deb(cluster, bank, parents, cs, outs, epoch=None, token_fn=None, owner_kp=None):
    """parents: [Holding]; cs: consumed amounts (may be negative or too large);
    outs: [(owner, amount)] (may be below the floor). Sum of outs need not equal sum of cs
    only if the caller wants an imbalance (use forge via tampering afterwards)."""
    P = cluster.P
    om = P.floor(parents[0].currency)
    kp = owner_kp or bank.kp
    pars, cons = [], []
    for h, c in zip(parents, cs):
        rc = C.rand_scalar()
        cons.append((h, c, rc))
        pars.append(Par(h.eid, h.j, h.version, C.commit(c, rc)))
    total_rc = sum(rc for _, _, rc in cons) % L
    rs = [C.rand_scalar() for _ in outs[:-1]]
    rs.append((total_rc - sum(rs)) % L)
    outputs = [Out(o, parents[0].currency, C.commit(a, r)) for (o, a), r in zip(outs, rs)]
    e = Event(type=DEB, issuer=kp_name(cluster, kp, bank), parents=pars, outputs=outputs,
              epoch=cluster.trust.epoch_at(cluster.clock.now()) if epoch is None else epoch)
    fps, parties, ok_floor = [], [], True
    for i, (h, c, rc) in enumerate(cons):
        x, rx = h.residual()
        x -= c
        rx = (rx - rc) % L
        try:
            proof, pv, pb = C.prove_floor(floor_ctx(e.id, i), C.commit(x, rx), x, rx, om)
            fps.append(proof)
            parties.append((pv, pb))
        except Exception:
            ok_floor = False
            fps.append(junk_proof())
            parties.append((0, 0))
    e.floor_proofs = fps
    vals = [a - om for _, a in outs] + [c for c in cs] + [pv for pv, _ in parties]
    bls = [r for r in rs] + [rc for _, _, rc in cons] + [pb for _, pb in parties]
    try:
        e.range_proof = C.prove_range(e.id, vals, bls)
    except Exception:
        e.range_proof = junk_proof(500)
    reseal(e, kp, cluster, token_fn)
    return e


def kp_name(cluster, kp, default_bank):
    for n, b in cluster.banks.items():
        if b.kp is kp:
            return n
    return default_bank.name
