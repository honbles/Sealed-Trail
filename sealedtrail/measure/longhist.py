"""Measurement 13: cone and hold size on long histories with skewed (hub) traffic, structure only.

Keeps what ConeBuild and the taint engine need: per entry its owner, initial amount and live residual; per event its parent edges
and consumed portions. No proofs, signatures or validators, about 60 bytes per event (10^6 events < 100 MB, 10^7 about 1 GB).

Modelled: one currency; debit-only events with one or more outputs (payroll); re-homing consolidations; pro-rata tracing with
whole-entry flags; bank-private parent selection. Not modelled: exits and anchors, refusals, time, the network, cryptography.

    python3 -m sealedtrail.measure.longhist --profile quick|full|sens|max [--out DIR] [--zip]
"""
from __future__ import annotations

import argparse
import bisect
import json
import math
import os
import random
import resource
import socket
import statistics as st
import sys
import time
import zipfile
from array import array
from pathlib import Path

import numpy as np

from .bundle import Bundle, env

OMEGA = 1.0                      # dust floor: every live residual is >= OMEGA
EPS_LEVELS = (0.5, 0.1, 0.01, 0.001)


# generator
class Ledger:
    """Append-only structure-only ledger. Entries and events are numbered in creation order, so event index is time and
    every event's parents have smaller entry numbers than its outputs (the order is topological)."""

    def __init__(self, banks=100, zipf=1.1, accounts=2, seed=1, policy="random", p_multi=0.01, p_cons=0.05,
                 pool_cap=128, mu=math.log(1e4), sigma=1.5):
        self.rng = random.Random(seed)
        self.n, self.policy, self.p_multi, self.p_cons, self.pool_cap = banks, policy, p_multi, p_cons, pool_cap
        self.mu, self.sigma = mu, sigma
        w = [1.0 / (i + 1) ** zipf for i in range(banks)]       # zipf = 0 is uniform; larger is more hub-dominated
        tot = sum(w)
        self.w = [x / tot for x in w]
        acc, self.cum = 0.0, []
        for x in self.w:
            acc += x
            self.cum.append(acc)
        self.cum[-1] = 1.0 + 1e-12
        # entries
        self.owner, self.amt0, self.resid, self.pos = array("i"), array("d"), array("d"), array("i")
        # events: first output entry, number of outputs, start of the parent-edge range
        self.ev_first, self.ev_nout, self.ev_es = array("i"), array("b"), array("i")
        self.e_par, self.e_c = array("i"), array("d")
        self.pool = [[] for _ in range(banks)]
        self.bal = [0.0] * banks
        self.minted = 0.0
        self.n_genesis = 0
        for b in range(banks):
            for _ in range(accounts):
                amt = 1e6 * max(1.0, banks * self.w[b])
                self._emit([], [(b, amt)])
                self.minted += amt
        self.n_genesis = len(self.ev_first)
        self.stats = {"payments": 0, "payroll": 0, "consolidations": 0, "skipped": 0}

    # -- primitives
    def _emit(self, parents, outs):
        self.ev_es.append(len(self.e_par))
        for p, c in parents:
            self.e_par.append(p)
            self.e_c.append(c)
        self.ev_first.append(len(self.owner))
        self.ev_nout.append(len(outs))
        for b, a in outs:
            eid = len(self.owner)
            self.owner.append(b)
            self.amt0.append(a)
            self.resid.append(a)
            self.pos.append(len(self.pool[b]))
            self.pool[b].append(eid)
            self.bal[b] += a

    def _remove(self, b, p):
        pool = self.pool[b]
        i = self.pos[p]
        last = pool[-1]
        pool[i] = last
        self.pos[last] = i
        pool.pop()

    def _take(self, b, want, kmax=8):
        """Consume portions from bank b's live entries (bank-private policy) until `want` is covered or kmax parents are used."""
        pool, res, rng = self.pool[b], self.resid, self.rng
        taken, got = [], 0.0
        while got < want - 1e-9 and pool and len(taken) < kmax:
            p = pool[-1] if self.policy == "newest" else pool[rng.randrange(len(pool))]
            r = res[p]
            c = want - got
            if c >= r - 1e-12 or r - c < OMEGA:          # take the whole entry (also when the remainder would be dust)
                c = r
                res[p] = 0.0
                self._remove(b, p)
            else:
                res[p] = r - c
            self.bal[b] -= c
            got += c
            taken.append((p, c))
        return taken, got

    def _pick(self):
        return bisect.bisect_left(self.cum, self.rng.random())

    # -- one step
    def step(self):
        rng = self.rng
        b = self._pick()
        pool = self.pool[b]
        if not pool:
            self.stats["skipped"] += 1
            return False
        r = rng.random()
        if len(pool) > self.pool_cap or (r < self.p_cons and len(pool) >= 2):
            taken, got = self._take(b, float("inf"), kmax=min(8, len(pool)))
            self._emit(taken, [(b, got)])
            self.stats["consolidations"] += 1
            return True
        amt = min(rng.lognormvariate(self.mu, self.sigma), 0.9 * self.bal[b])
        if amt < OMEGA:
            self.stats["skipped"] += 1
            return False
        ell = rng.randint(2, 8) if r > 1.0 - self.p_multi else 1
        taken, got = self._take(b, amt * ell if ell > 1 else amt)
        if ell > 1 and got / ell < OMEGA:
            ell = 1
        recv = []
        while len(recv) < ell:
            d = self._pick()
            if d != b and d not in recv:
                recv.append(d)
            elif self.n <= ell:                           # tiny networks: allow repeats
                recv.append((b + 1 + len(recv)) % self.n)
        self._emit(taken, [(d, got / ell) for d in recv])
        self.stats["payroll" if ell > 1 else "payments"] += 1
        return True

    def run_to(self, n_events):
        while len(self.ev_first) < n_events:
            self.step()

    @property
    def n_events(self):
        return len(self.ev_first)


# analysis
class Index:
    """Child index and arrays for one prefix of the history (what each validator's `children[p]` holds)."""

    def __init__(self, L: Ledger):
        t0 = time.perf_counter()
        self.L = L
        self.ne, self.nen = L.n_events, len(L.owner)
        self.e_par = np.array(L.e_par, dtype=np.int32)
        self.e_c = np.array(L.e_c, dtype=np.float64)
        es = np.array(L.ev_es, dtype=np.int64)
        self.es = np.append(es, len(self.e_par))
        self.ev_first = np.array(L.ev_first, dtype=np.int64)
        self.ev_nout = np.array(L.ev_nout, dtype=np.int64)
        self.owner = np.array(L.owner, dtype=np.int32)
        self.amt0 = np.array(L.amt0, dtype=np.float64)
        self.resid = np.array(L.resid, dtype=np.float64)
        ev_of_edge = np.repeat(np.arange(self.ne, dtype=np.int32), np.diff(self.es))
        order = np.argsort(self.e_par, kind="stable")
        self.child_ev = ev_of_edge[order]
        self.ptr = np.zeros(self.nen + 1, dtype=np.int64)
        np.cumsum(np.bincount(self.e_par, minlength=self.nen), out=self.ptr[1:])
        self.build_s = time.perf_counter() - t0
        self._seen_ev = bytearray(self.ne)

    def cone(self, root: int) -> dict:
        """ConeBuild from one flagged entry: closure under 'an event that lists it as a parent' (all outputs of the event)."""
        t0 = time.perf_counter()
        seen_ev, touched = self._seen_ev, []
        entries, events, frontier, hops = [root], [], [root], 0
        ptr, child_ev, ev_first, ev_nout = self.ptr, self.child_ev, self.ev_first, self.ev_nout
        while frontier:
            nxt = []
            for x in frontier:
                s, t = ptr[x], ptr[x + 1]
                if s == t:
                    continue
                for ev in child_ev[s:t].tolist():
                    if not seen_ev[ev]:
                        seen_ev[ev] = 1
                        touched.append(ev)
                        events.append(ev)
                        f = int(ev_first[ev])
                        nxt.extend(range(f, f + int(ev_nout[ev])))
            if nxt:
                hops += 1
                entries.extend(nxt)
            frontier = nxt
        for ev in touched:
            seen_ev[ev] = 0
        return {"root": root, "entries": entries, "events": sorted(events), "hops": hops, "build_s": time.perf_counter() - t0}

    def rho(self, cone: dict) -> dict:
        """Pro-rata taint fractions over the cone, whole-entry flag on the root (Definition 12 with x = A, rho(root) = 1)."""
        rho = {cone["root"]: 1.0}
        es, e_par, e_c, ev_first, ev_nout = self.es, self.e_par, self.e_c, self.ev_first, self.ev_nout
        for ev in cone["events"]:
            s, t = int(es[ev]), int(es[ev + 1])
            ps, cs = e_par[s:t].tolist(), e_c[s:t].tolist()
            den = sum(cs)
            rh = sum(c * rho.get(p, 0.0) for p, c in zip(ps, cs)) / den if den > 0 else 0.0
            f = int(ev_first[ev])
            for y in range(f, f + int(ev_nout[ev])):
                rho[y] = rh
        return rho


def measure_root(ix: Index, root: int, rho_cap: int, do_rho: bool = True) -> dict:
    cn = ix.cone(root)
    ce = np.array(cn["entries"], dtype=np.int64)
    live = ce[ix.resid[ce] > 0]
    P = float(ix.amt0[root])
    live_total = int((ix.resid > 0).sum())
    supply = float(ix.resid.sum())
    row = {"root": root, "P_phi": P, "cone_events": len(cn["events"]), "cone_entries": len(ce), "hops": cn["hops"],
           "cone_build_s": round(cn["build_s"], 4), "held_entries": len(live), "live_entries_total": live_total,
           "frac_live_held": len(live) / max(1, live_total), "held_banks": int(len(np.unique(ix.owner[live]))) if len(live) else 0,
           "held_value": float(ix.resid[live].sum()), "P_over_supply": P / supply}
    row["held_value_over_P"] = row["held_value"] / P
    row["held_value_over_supply"] = row["held_value"] / supply
    if not do_rho or len(cn["events"]) > rho_cap:
        row["rho_computed"] = False
        return row
    t0 = time.perf_counter()
    rho = ix.rho(cn)
    row["rho_s"] = round(time.perf_counter() - t0, 4)
    row["rho_computed"] = True
    rv = np.fromiter((rho.get(int(y), 0.0) for y in live), dtype=np.float64, count=len(live))
    mass = rv * ix.resid[live]
    row["mass_identity_rel_err"] = abs(float(mass.sum()) - P) / P            # Theorem 14 with no exits: sum rho*R = P
    row["median_rho_held"] = float(np.median(rv)) if len(rv) else 0.0
    row["frac_held_rho_below_1e-3"] = float((rv < 1e-3).mean()) if len(rv) else 0.0
    # Mass-bounded hold, ORACLE ordering: hold the entries with the largest tainted mass until (1-eps) of P is covered.
    # This is a bound on what a mass-bounded hold could achieve; an implementable version needs the openings progressively.
    order = np.argsort(-mass)
    cum = np.cumsum(mass[order])
    vals = ix.resid[live][order]
    cumv = np.cumsum(vals)
    for eps in EPS_LEVELS:
        k = int(np.searchsorted(cum, (1.0 - eps) * P * (1 - 1e-12))) + 1
        k = min(k, len(order))
        row[f"held_value_over_P_eps{eps}"] = float(cumv[k - 1] / P) if len(order) else 0.0
        row[f"held_entries_eps{eps}"] = k if len(order) else 0
    return row


def pick_roots(L: Ledger, per_band: int, rng: random.Random) -> dict:
    n0, nen = L.n_genesis, len(L.owner)
    span = nen - n0
    bands = {"genesis": (0, n0),
             "old": (n0, n0 + max(1, span // 10)),
             "mid": (n0 + int(span * 0.45), n0 + int(span * 0.55)),
             "young": (nen - max(1, span // 10), nen)}
    return {b: [rng.randrange(lo, max(lo + 1, hi)) for _ in range(per_band)] for b, (lo, hi) in bands.items()}


def rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def run_one(banks, zipf, events, checkpoints, seed, per_band, rho_cap, policy, pool_cap, p_cons=0.05, p_multi=0.01,
            rho_per_band=None, log=print):
    L = Ledger(banks=banks, zipf=zipf, seed=seed, policy=policy, pool_cap=pool_cap, p_cons=p_cons, p_multi=p_multi)
    rho_per_band = per_band if rho_per_band is None else rho_per_band
    rng = random.Random(seed + 7)
    rows, gen = [], []
    t_gen = 0.0
    for T in checkpoints:
        t0 = time.perf_counter()
        L.run_to(T)
        t_gen += time.perf_counter() - t0
        edges = len(L.e_par)
        supply_err = abs(sum(L.resid) - L.minted) / L.minted
        ix = Index(L)
        g = {"skew": zipf, "p_cons": p_cons, "pool_cap": pool_cap, "history_events": L.n_events, "entries": len(L.owner), "edges": edges,
             "dbar": edges / max(1, L.n_events - L.n_genesis), "gen_s_total": round(t_gen, 2),
             "index_build_s": round(ix.build_s, 2), "supply_rel_err": supply_err, "rss_mb": round(rss_mb(), 0),
             "top1_bank_share_of_live_value": float(max(L.bal) / max(1e-9, sum(L.bal))), **L.stats}
        gen.append(g)
        log(f"  skew={zipf} T={L.n_events:>9,}  d̄={g['dbar']:.2f}  gen {t_gen:6.1f}s  index {ix.build_s:5.1f}s  rss {g['rss_mb']:.0f} MB  conservation err {supply_err:.1e}")
        for band, roots in pick_roots(L, per_band, rng).items():
            for i, r in enumerate(roots):
                row = measure_root(ix, r, rho_cap, do_rho=i < rho_per_band)
                rank = int(ix.owner[r])
                row.update({"skew": zipf, "p_cons": p_cons, "pool_cap": pool_cap, "history_events": L.n_events, "band": band,
                            "root_bank_rank": rank})
                rows.append(row)
        for band in ("genesis", "old", "mid", "young"):
            sel = [x for x in rows if x["history_events"] == L.n_events and x["skew"] == zipf and x["band"] == band
                   and x["p_cons"] == p_cons and x["pool_cap"] == pool_cap]
            log(f"      {band:8s} median cone {st.median(x['cone_events'] for x in sel):>9,.0f} events, "
                f"held {st.median(x['held_entries'] for x in sel):>6,.0f}/{sel[0]['live_entries_total']:,} live, "
                f"held value / P = {st.median(x['held_value_over_P'] for x in sel):>10,.1f}")
        del ix
    return rows, gen


# "mix" lists (p_cons, pool_cap): how often a bank merges its entries (re-homing consolidations) and how many live entries it may
# hold before it must. This is the generator's mixing knob and the biggest driver of cone size, so every profile sweeps it.
PROFILES = {
    "quick": {"events": 100_000, "skews": [0.0, 1.1], "mix": [(0.05, 128)], "banks": 100, "per_band": 4, "rho_per_band": 4, "rho_cap": 500_000},
    "full": {"events": 1_000_000, "skews": [0.0, 1.1], "mix": [(0.05, 128)], "banks": 100, "per_band": 6, "rho_per_band": 6, "rho_cap": 2_000_000},
    "sens": {"events": 1_000_000, "skews": [1.1], "mix": [(0.0, 1024), (0.01, 256), (0.05, 128)], "banks": 100, "per_band": 4,
             "rho_per_band": 4, "rho_cap": 2_000_000},
    "max": {"events": 10_000_000, "skews": [1.1], "mix": [(0.05, 128)], "banks": 100, "per_band": 4, "rho_per_band": 2,
            "rho_cap": 15_000_000},
}


def checkpoints_for(events):
    cps, t = [], 10_000
    while t < events:
        cps.append(t)
        t *= 10
    cps.append(events)
    return cps


def plot(plt, rows, extra):
    fig, ax = plt.subplots(1, 3, figsize=(16, 4.4))
    skews = sorted({(r["skew"], r["p_cons"], r["pool_cap"]) for r in rows})
    rows = [dict(r, skew=(r["skew"], r["p_cons"], r["pool_cap"])) for r in rows]
    Ts = sorted({r["history_events"] for r in rows})
    for sk, ls in zip(skews, ["--", "-", ":", "-."]):
        for band, col in zip(("genesis", "old", "mid", "young"), ("C3", "C1", "C0", "C2")):
            med = [st.median(r["cone_events"] for r in rows if r["skew"] == sk and r["band"] == band and r["history_events"] == T) for T in Ts]
            ax[0].plot(Ts, med, ls, color=col, marker="o", label=f"{band}, skew {sk[0]}, p_cons {sk[1]}, cap {sk[2]}")
            fr = [st.median(r["frac_live_held"] for r in rows if r["skew"] == sk and r["band"] == band and r["history_events"] == T) for T in Ts]
            ax[1].plot(Ts, fr, ls, color=col, marker="o")
    ax[0].set(xscale="log", yscale="log", xlabel="events in history", ylabel="median cone size (events)", title="Cone growth")
    ax[0].legend(fontsize=6)
    ax[1].set(xscale="log", xlabel="events in history", ylabel="fraction of live entries held", title="Phase 0 hold, whole entries")
    Tl = Ts[-1]
    for sk, ls in zip(skews, ["--", "-", ":", "-."]):
        for band, col in zip(("genesis", "old", "mid", "young"), ("C3", "C1", "C0", "C2")):
            sel = [r for r in rows if r["skew"] == sk and r["band"] == band and r["history_events"] == Tl and r.get("rho_computed")]
            if sel:
                ys = [st.median(r[f"held_value_over_P_eps{e}"] for r in sel) for e in EPS_LEVELS]
                ax[2].plot(EPS_LEVELS, ys, ls, color=col, marker="o")
    ax[2].set(xscale="log", yscale="log", xlabel="tolerated unaccounted mass (eps)", ylabel="held value / flagged principal",
              title=f"Mass-bounded hold (oracle order), T={Tl:,}")
    fig.tight_layout()
    return fig


NOT_SHOWN = [
    "Generated traffic: Zipf-weighted banks, log-normal amounts, a few percent payroll and consolidation events. The shape is an assumption, not an observation of any market.",
    "Structure only: no exits or anchors (so no escrow and no anchor-window holds, which would add held entries), no refusals, no time beyond the event index, no network.",
    "Live entries per bank are bounded by consolidation (pool cap), so held-entry COUNTS are bounded by construction; read held VALUE relative to the flagged principal.",
    "Each flag names one whole entry. Real flags may name many roots, and a flagged root older than the history window is not represented.",
    "Mass-bounded hold uses an ORACLE order (largest tainted mass first). The protocol learns rho only from openings, so this is a bound on the benefit, not an implemented rule.",
    "One seed per configuration; roots are sampled per age band, so the medians have sampling noise (see the per-root rows).",
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=list(PROFILES), default="quick")
    ap.add_argument("--events", type=int)
    ap.add_argument("--banks", type=int)
    ap.add_argument("--skews", help="comma-separated Zipf exponents, e.g. 0,1.1")
    ap.add_argument("--per-band", type=int)
    ap.add_argument("--p-cons", type=float, help="override: consolidation probability (single mix)")
    ap.add_argument("--policy", choices=["random", "newest"], default="random")
    ap.add_argument("--pool-cap", type=int, help="override: live entries a bank may hold before it must consolidate")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None)
    ap.add_argument("--zip", action="store_true", help="also write a zip of the bundle to send back")
    a = ap.parse_args(argv)
    p = dict(PROFILES[a.profile])
    if a.events:
        p["events"] = a.events
    if a.banks:
        p["banks"] = a.banks
    if a.skews:
        p["skews"] = [float(x) for x in a.skews.split(",")]
    if a.per_band:
        p["per_band"] = a.per_band
        p["rho_per_band"] = min(p["rho_per_band"], a.per_band)
    if a.p_cons is not None or a.pool_cap:
        p["mix"] = [(a.p_cons if a.p_cons is not None else p["mix"][0][0], a.pool_cap or p["mix"][0][1])]
    out = Path(a.out or f"longhist-{socket.gethostname()}-{time.strftime('%Y%m%d-%H%M%S')}")
    cps = checkpoints_for(p["events"])
    print(f"longhist profile={a.profile} events={p['events']:,} banks={p['banks']} skews={p['skews']} mix={p['mix']} checkpoints={cps} out={out}")
    t0 = time.time()
    rows, gen = [], []
    for sk in p["skews"]:
        for pc, cap in p["mix"]:
            r, g = run_one(p["banks"], sk, p["events"], cps, a.seed, p["per_band"], p["rho_cap"], a.policy, cap, p_cons=pc,
                           rho_per_band=p["rho_per_band"])
            rows += r
            gen += g
    cfg = {**p, "checkpoints": cps, "policy": a.policy, "eps_levels": list(EPS_LEVELS)}
    b = Bundle(f"m13_longhist_{a.profile}", "Measurement 13: cone and hold size on long, skewed histories (structure-only)", cfg, a.seed,
               "Cone size, held entries and value, and mass-bounded hold (oracle order) against history length and traffic skew.",
               NOT_SHOWN, runtime="structure-only", out=out)
    d = b.write(rows, plot, {"generation": gen, "wall_s": round(time.time() - t0, 1)})
    bad = [x for x in rows if x.get("mass_identity_rel_err", 0) > 1e-6] + [x for x in gen if x["supply_rel_err"] > 1e-9]
    (d / "checks.json").write_text(json.dumps({"violations": len(bad), "rows_checked": len(rows)}, indent=1))
    print(f"wrote {d}   wall {time.time() - t0:.0f}s   violations={len(bad)}")
    if a.zip:
        zp = Path(str(out) + ".zip")
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(Path(out).rglob("*")):
                if f.is_file():
                    z.write(f, f.relative_to(out.parent))
        print(f"Archive: {zp}  ({zp.stat().st_size // 1024} KB)")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
