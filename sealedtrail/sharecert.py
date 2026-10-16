"""Taint-bound certificates and reserve proofs: a hold that needs no amount openings (reversal amounts still do).

Setting. A flag fixes a cone. For every cone event ev the issuer publishes an integer r_ev in [0, 2^K], read as the public upper
bound rho_bar(ev) = r_ev / 2^K on the taint fraction of every output of ev. Parents outside the cone have r = 0; a whole-entry
flag root has r = 2^K.

Certificate for ev (checked by any validator, no opening). Let C_p be the commitments to the consumed portions a_p of ev, which are
already on the ledger, and r_p the published bounds of the parents. Both sides compute

    D_ev = sum_p (r_ev - r_p) * C_p            (a Pedersen commitment, by homomorphism, to  N = sum_p (r_ev - r_p) * a_p)

and the issuer attaches a Bulletproof that D_ev commits to a value in [0, 2^64). N >= 0 says exactly that
r_ev / 2^K >= (sum_p a_p r_p/2^K) / (sum_p a_p), the weighted average of the parents' bounds. By induction over the cone,
rho_bar >= rho (the pro-rata fraction of Definition 12 without a flagged addition), and nothing is opened.

Reserve proof for a spend of a held entry e. Let C_R be the commitment to the residual at the flag and C_R' the commitment to the
residual after the spend. The entry's reserve is h = r_e * R / 2^K. A spend is valid only if

    D_res = 2^K * C_R' - r_e * C_R    commits to a value in [0, 2^64),         i.e. R' >= h.

Both gadgets are one range proof (aggregable over up to 256 statements) over a commitment the verifier computes for itself, so the
only new data on the ledger is the published bound r and the proof. Amount range: the proven integers are at most 2^K times the amounts, so amounts must stay below
2^(64-K) (K = 20: 2^44, about 1.7e13 minor units); wider amounts need the limb split already used for the tolerance proof.
"""
from __future__ import annotations

from . import crypto as cr

K_DEFAULT = 20
ORDER = cr.L


def _combo(commits: list[bytes], coeffs: list[int]) -> bytes:
    """sum coeff_i * C_i, coefficients may be negative (taken mod the group order)."""
    acc = cr.IDENTITY
    for c, k in zip(commits, coeffs):
        if k % ORDER == 0:
            continue
        acc = cr.padd(acc, cr.pmul(c, k % ORDER))
    return acc


def cert_commitment(parent_commits: list[bytes], parent_r: list[int], r_ev: int) -> bytes:
    """D_ev from public data only."""
    return _combo(parent_commits, [r_ev - rp for rp in parent_r])


def prove_certs(ctx: bytes, events: list[dict]) -> bytes:
    """One aggregated proof for several events (<= 256). Each event dict holds the issuer's secrets:
    {'a': [a_p], 'blind': [blinding_p], 'r_parent': [r_p], 'r_ev': r_ev}."""
    vals, blinds = [], []
    for e in events:
        n = sum((e["r_ev"] - rp) * a for rp, a in zip(e["r_parent"], e["a"]))
        if n < 0 or n >= 1 << 64:
            raise cr.CryptoError("bound below the weighted average (or amounts too large): no valid certificate exists")
        b = sum((e["r_ev"] - rp) * bl for rp, bl in zip(e["r_parent"], e["blind"])) % ORDER
        vals.append(n)
        blinds.append(b)
    return cr.prove_range(ctx, vals, blinds)


def verify_certs(ctx: bytes, events: list[dict], proof: bytes) -> bool:
    """events: [{'commits': [C_p], 'r_parent': [r_p], 'r_ev': r_ev}] , public data only."""
    try:
        ds = [cert_commitment(e["commits"], e["r_parent"], e["r_ev"]) for e in events]
    except cr.CryptoError:
        return False
    return cr.verify_range(ctx, ds, proof)


def reserve_commitment(c_resid_after: bytes, c_resid_flag: bytes, r_e: int, k: int = K_DEFAULT) -> bytes:
    return _combo([c_resid_after, c_resid_flag], [1 << k, -r_e])


def prove_reserve(ctx: bytes, r_after: int, blind_after: int, r_flag: int, blind_flag: int, r_e: int, k: int = K_DEFAULT) -> bytes:
    n = (r_after << k) - r_e * r_flag
    if n < 0 or n >= 1 << 64:
        raise cr.CryptoError("spend would cut into the reserve (or amount too large)")
    b = ((blind_after << k) - r_e * blind_flag) % ORDER
    return cr.prove_range(ctx, [n], [b])


def verify_reserve(ctx: bytes, c_resid_after: bytes, c_resid_flag: bytes, r_e: int, proof: bytes, k: int = K_DEFAULT) -> bool:
    try:
        d = reserve_commitment(c_resid_after, c_resid_flag, r_e, k)
    except cr.CryptoError:
        return False
    return cr.verify_range(ctx, [d], proof)


def round_up_bound(num: int, den: int, k: int = K_DEFAULT) -> int:
    """Least r with r / 2^k >= num / den (integer arithmetic): the honest issuer's choice on a linear grid."""
    return -((-num * (1 << k)) // den)
