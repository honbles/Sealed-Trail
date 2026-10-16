"""Measurement 14: share-bounded hold with certified taint bounds, structure only.

The whole-entry hold of Phase 0 follows reachability. This measurement tests a replacement in which every cone entry e carries a
PUBLIC upper bound rho_bar(e) >= rho(e) on a fixed grid (multiples of 2^-k, rounded up), computed forward from the PUBLIC bounds of
its parents and the amounts the owner itself received:

    rho_bar(e) = ceil_k( sum_p a_p * rho_bar(p) / sum_p a_p ),            rho_bar(e) = 0 when below rho_min.

Only the share rho_bar(e) * residual(e) is held (a reserve floor on the residual), not the whole entry. The guarantee that every
tainted unit is covered holds for every entry whose bound was not pruned; the mass lost to pruning is measured, not assumed.

    python3 -m sealedtrail.measure.sharehold --events 1000000 [--out DIR]

Reuses the generator and the cone/rho code of longhist.py. No proofs are generated here: the arithmetic of the proof is tested in
the test file; the cost of proving is modelled separately (docs).
"""
from __future__ import annotations

import argparse
import json
import math
import random
import statistics as st
import sys
import time
from pathlib import Path

import numpy as np

from .bundle import Bundle
from .longhist import Index, Ledger, pick_roots


NOT_SHOWN = [
    "Generated traffic (Zipf-weighted banks, log-normal amounts, payroll and consolidation events); the mixing rate is an assumption, not an observation.",
    "Structure only: no cryptography here. The certificate and reserve proofs are exercised in tests/test_sharecert.py and costed in docs, not in this run.",
    "Whole-entry flags only (no injection at later events); no exits, anchors, refusals or time. Every cone event is assumed to be certified, so a refusing issuer is not modelled.",
    "The certificates narrow the hold; they do not fix a reversal amount, which still needs the Phase 2 openings.",
    "One seed per configuration; roots are sampled per age band (4 roots at 10^7 events, 8 at 10^6, 12 at 10^5).",
    "Bits published per event are an upper bound on information (log2 of the grid size), not a privacy proof.",
]


def certified_rho(ix: Index, cone: dict, k: int, rho_min: float, grid: str = "lin", jmax: int = 40) -> tuple[dict, int, int]:
    """Forward propagation of public upper bounds. Returns (rho_bar over cone entries, events certified, events pruned)."""
    scale = float(1 << k)
    rb = {cone["root"]: 1.0}
    es, e_par, e_c, ev_first, ev_nout = ix.es, ix.e_par, ix.e_c, ix.ev_first, ix.ev_nout
    certified = pruned = 0
    for ev in cone["events"]:
        s, t = int(es[ev]), int(es[ev + 1])
        ps, cs = e_par[s:t].tolist(), e_c[s:t].tolist()
        den = sum(cs)
        avg = sum(c * rb.get(p, 0.0) for p, c in zip(ps, cs)) / den if den > 0 else 0.0
        if grid == "log":                      # k = steps per octave; values 2^(-j/k), j = 0..jmax; never pruned, clamped up
            if avg <= 0:
                v = 0.0
            else:
                j = min(jmax * k, int(math.floor(-k * math.log2(min(avg, 1.0)) + 1e-9)))
                v = 2.0 ** (-j / k)
                if v < avg:                                     # float guard: the grid point must be an upper bound
                    v = 2.0 ** (-(j - 1) / k)
            certified += 1 if v > 0 else 0
            f = int(ev_first[ev])
            for y in range(f, f + int(ev_nout[ev])):
                rb[y] = v
            continue
        v = math.ceil(avg * scale - 1e-9) / scale if avg > 0 else 0.0
        if v < rho_min:
            if v > 0:
                pruned += 1
            v = 0.0
        else:
            certified += 1
        f = int(ev_first[ev])
        for y in range(f, f + int(ev_nout[ev])):
            rb[y] = v
    return rb, certified, pruned


def measure(ix: Index, root: int, k_list, rho_min_list, grid: str = "lin") -> dict:
    cn = ix.cone(root)
    ce = np.array(cn["entries"], dtype=np.int64)
    live = ce[ix.resid[ce] > 0]
    P = float(ix.amt0[root])
    rho = ix.rho(cn)
    rv = np.fromiter((rho.get(int(y), 0.0) for y in live), dtype=np.float64, count=len(live))
    res = ix.resid[live]
    mass = rv * res
    row = {"root": root, "P": P, "cone_events": len(cn["events"]), "live_cone": len(live),
           "whole_entry_value_over_P": float(res.sum() / P),
           "mass_identity_rel_err": abs(float(mass.sum()) - P) / P,
           "banks_in_cone_events": int(len(np.unique(ix.owner[np.array(cn["entries"], dtype=np.int64)])))}
    for k in k_list:
        for rm in rho_min_list:
            rb, cert, prn = certified_rho(ix, cn, k, rm, grid)
            bv = np.fromiter((rb.get(int(y), 0.0) for y in live), dtype=np.float64, count=len(live))
            share = bv * res
            uncovered = np.maximum(rv - bv, 0.0) * res
            tag = f"k{k}_m{rm:g}"
            row[f"held_over_P_{tag}"] = float(share.sum() / P)
            row[f"uncovered_over_P_{tag}"] = float(uncovered.sum() / P)
            row[f"certs_{tag}"] = cert
            row[f"pruned_{tag}"] = prn
            row[f"held_entries_{tag}"] = int((bv > 0).sum())
    return row


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", type=int, default=1_000_000)
    ap.add_argument("--banks", type=int, default=100)
    ap.add_argument("--zipf", type=float, default=1.1)
    ap.add_argument("--p-cons", type=float, default=0.05)
    ap.add_argument("--pool-cap", type=int, default=128)
    ap.add_argument("--per-band", type=int, default=4)
    ap.add_argument("--k", default="12,16,20,24")
    ap.add_argument("--rho-min", default="0,1e-6,1e-5,1e-4,1e-3")
    ap.add_argument("--grid", choices=["lin", "log"], default="lin", help="lin: multiples of 2^-k; log: k steps per octave down to 2^-40")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    ks = [int(x) for x in a.k.split(",")]
    rms = [float(x) for x in a.rho_min.split(",")]
    t0 = time.time()
    L = Ledger(banks=a.banks, zipf=a.zipf, seed=a.seed, pool_cap=a.pool_cap, p_cons=a.p_cons)
    L.run_to(a.events)
    ix = Index(L)
    print(f"ledger {L.n_events:,} events, {len(L.owner):,} entries, {int((ix.resid > 0).sum())} live, gen+index {time.time() - t0:.0f}s")
    rng = random.Random(a.seed + 7)
    rows = []
    for band, roots in pick_roots(L, a.per_band, rng).items():
        for r in roots:
            row = measure(ix, r, ks, rms, a.grid)
            row["band"] = band
            rows.append(row)
            print(f"  {band:7s} root {r:>9,} cone {row['cone_events']:>9,} live {row['live_cone']:>5}  whole-entry/P {row['whole_entry_value_over_P']:>10,.1f}",
                  flush=True)
    out = Path(a.out or "sharehold-out")
    b = Bundle(f"m14_sharehold_{a.grid}_{a.events}", "Measurement 14: share-bounded hold from certified taint bounds (structure-only)",
               {**vars(a), "grid": a.grid}, a.seed,
               "Held value relative to the flagged principal for a hold that keeps only rho_bar * residual of each cone entry, where rho_bar is a "
               "public upper bound on the taint fraction rounded up on a grid; uncovered mass; certificates needed per cone event.",
               NOT_SHOWN, runtime="structure-only", out=out)
    b.write(rows, None, {"wall_s": round(time.time() - t0, 1)})
    print("\nmedians over roots (held share value / flagged principal; uncovered mass / P; certificates needed / cone events)")
    print(f"  whole-entry hold, value/P: {st.median(r['whole_entry_value_over_P'] for r in rows):,.1f}   max id err {max(r['mass_identity_rel_err'] for r in rows):.1e}")
    for k in ks:
        for rm in rms:
            tag = f"k{k}_m{rm:g}"
            h = st.median(r[f"held_over_P_{tag}"] for r in rows)
            u = st.median(r[f"uncovered_over_P_{tag}"] for r in rows)
            umax = max(r[f"uncovered_over_P_{tag}"] for r in rows)
            cf = st.median(r[f"certs_{tag}"] / max(1, r["cone_events"]) for r in rows)
            ne = st.median(r[f"held_entries_{tag}"] for r in rows)
            print(f"  k={k:>2} rho_min={rm:<7g} held/P {h:>9.3f}   uncovered/P med {u:.4f} max {umax:.4f}   certs/cone {cf:.4f}   held entries {ne:,.0f}")
    print(f"wall {time.time() - t0:.0f}s -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
