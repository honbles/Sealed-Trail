"""Measurements 1, 2, 3, 4, 6, 9 and the partition part of 12 (spec 10.4). In-process runtime:
CPU times are measured on this machine; network latency is SIMULATED where stated."""
from __future__ import annotations

import math
import random
import statistics as st
import time
import tracemalloc
from collections import deque

from .. import cbor, custody
from ..bank import PaymentFailed
from ..builder import build_spend
from ..engine.cone import cone_build
from ..engine.facts import BankOpenings, run_engine
from ..model import ANC, EXT, GEN
from ..params import Params
from ..sim import Cluster
from ..valid import validate
from .bundle import Bundle

pc = time.perf_counter


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


# 1 proof sizes (F1)
def proof_sizes(out, reps=5, seed=1, grid=(1, 2, 4, 8, 16)):
    c = Cluster("min", banks=("A", "B"), seed=seed)
    A = c.banks["A"]
    for i in range(max(grid)):
        A.onboard(f"a{i}", 100_000)
    c.tick(1)
    hs = A.entries()[: max(grid)]
    v = next(iter(c.validators.values()))
    rows = []
    for P in grid:
        for l in grid:
            par, tot = [(h, 2000) for h in hs[:P]], 2000 * P
            outs = [("B", tot // l)] * (l - 1) + [("B", tot - (tot // l) * (l - 1))]
            tb, tv = [], []
            for _ in range(reps):
                s = pc(); b = build_spend(A.kp, "A", c.P, "NGN", par, outs, 0, c.token); tb.append((pc() - s) * 1000)
                s = pc(); validate(b.event, v.store, c.P, c.trust); tv.append((pc() - s) * 1000)
            e = b.event
            est_agg = (2 * math.ceil(math.log2(64 * (P + l))) + 4) * 32 + 5 * 32
            rows.append({"P": P, "l": l, "wire_B": len(e.to_wire()), "range_proof_B": len(e.range_proof),
                         "floor_B": sum(len(x) for x in e.floor_proofs),
                         "proofs_total_B": len(e.range_proof) + sum(len(x) for x in e.floor_proofs),
                         "paper_est_B": est_agg + 750 * P,
                         "build_ms_med": st.median(tb), "build_ms_p99": pct(tb, 99),
                         "verify_ms_med": st.median(tv), "verify_ms_p99": pct(tv, 99), "reps": reps})

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 3, figsize=(14, 4))
        for l in sorted({r["l"] for r in rows}):
            rs = [r for r in rows if r["l"] == l]
            ax[0].plot([r["P"] for r in rs], [r["proofs_total_B"] for r in rs], "o-", label=f"l={l}")
            ax[1].plot([r["P"] for r in rs], [r["verify_ms_med"] for r in rs], "o-", label=f"l={l}")
            ax[2].plot([r["P"] for r in rs], [r["build_ms_med"] for r in rs], "o-", label=f"l={l}")
        r11 = [r for r in rows if r["l"] == 1]
        ax[0].plot([r["P"] for r in r11], [r["paper_est_B"] for r in r11], "k--", label="paper estimate (l=1)")
        for a, t, y in zip(ax, ("Proof bytes (range + floor)", "Verify time", "Build time"), ("bytes", "ms (median)", "ms (median)")):
            a.set_xscale("log", base=2); a.set_xlabel("parents P"); a.set_ylabel(y); a.set_title(t); a.grid(alpha=.3)
        ax[0].legend(fontsize=7)
        fig.suptitle("F1: proof size and prove/verify time vs P and l")
        return fig

    return Bundle("m1_proof_sizes", "Measurement 1: proof size and prover/verifier time per event",
                  {"reps": reps, "grid": list(grid), "profile": "min"}, seed,
                  "Bytes and ms of the aggregated range proof plus zero-or-floor proofs, per event, vs parents P and outputs l.",
                  ["One core, Python ctypes over the Rust core; no batching across events, no parallel verification.",
                   f"p99 over {reps} repetitions is a weak tail estimate.",
                   "Times are for the whole Valid(e) check, not only the proofs (signatures, lookups included).",
                   "The floor party is folded into the aggregate proof, so 'floor_B' counts only the sigma-OR parts."],
                  out=out).write(rows, plot)


# 2/3 quorum latency (F2) and cert size (F3)
NET = {"LAN": (0.4, 0.15), "regional": (20.0, 6.0), "WAN": (90.0, 30.0)}


def quorum_latency(out, events=25, mc=3000, seed=1, ks=(4, 7, 10, 13)):
    rows, cert_rows, cdf = [], [], {}
    for k in ks:
        f = (k - 1) // 3
        P = Params(k=k, f=f)
        c = Cluster(P, banks=("A", "B"), seed=seed)
        cpu = {vid: [] for vid in c.validators}
        for vid, v in c.validators.items():
            def wrap(wire, _o=v.request_lock, _l=cpu[vid]):
                s = pc(); r = _o(wire); _l.append((pc() - s) * 1000); return r
            v.request_lock = wrap
        A, B = c.banks["A"], c.banks["B"]
        A.onboard("a", 5_000_000); B.onboard("b", 1_000); c.tick(1)
        for l in cpu.values():
            l.clear()
        certs = []
        for i in range(events):
            c.tick(1)
            certs.append(len(cbor.encode(A.pay("a", "B", "b", 1_000 + i).cert)))
        cert_rows.append({"k": k, "f": f, "q": P.q, "cert_B_mean": st.mean(certs), "cert_B_min": min(certs),
                          "cert_B_max": max(certs), "sig_bytes_q64": P.q * 64})
        cpu_all = [x for l in cpu.values() for x in l]
        rng = random.Random(seed * 100 + k)
        for prof, (mu, sd) in NET.items():
            samples = []
            for _ in range(mc):
                lat = sorted(max(0.05, rng.gauss(mu, sd)) + rng.choice(cpu_all) for _ in range(k))
                tok = sorted(max(0.05, rng.gauss(mu, sd)) for _ in range(P.n_tsa))[P.m_tsa - 1]
                samples.append(tok + lat[P.q - 1])
            samples.sort()
            rows.append({"k": k, "f": f, "q": P.q, "profile": prof, "p50_ms": pct(samples, 50), "p95_ms": pct(samples, 95),
                         "p99_ms": pct(samples, 99), "mean_ms": st.mean(samples), "cpu_med_ms": st.median(cpu_all), "mc": mc})
            cdf[f"{k}/{prof}"] = [pct(samples, p) for p in range(0, 101, 2)]
    notes = ["Hybrid model: per-validator CPU time is MEASURED (sequentially, one core); network round trips are SIMULATED "
             "(Gaussian per profile). Parallel fan-out is assumed: latency = token + q-th fastest validator.",
             "No queueing, no contention between concurrent events, no packet loss, no real network stack.",
             "Real validators run on separate cores; here they were timed one after another."]

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 3, figsize=(14, 4), sharey=True)
        for a, prof in zip(ax, NET):
            for k in ks:
                a.plot(extra["cdf"][f"{k}/{prof}"], [p / 100 for p in range(0, 101, 2)], label=f"k={k}")
            a.set_title(prof); a.set_xlabel("quorum latency (ms)"); a.grid(alpha=.3)
        ax[0].set_ylabel("CDF"); ax[0].legend()
        fig.suptitle("F2: quorum latency CDFs (CPU measured, network simulated)")
        return fig

    Bundle("m2_quorum_latency", "Measurement 2: quorum latency vs k", {"events": events, "mc": mc, "ks": list(ks), "net": NET}, seed,
           "Time to collect q signatures (plus token) under three network profiles.", notes, out=out).write(rows, plot, {"cdf": cdf})

    def plot3(plt, rows, extra):
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.plot([r["k"] for r in rows], [r["cert_B_mean"] for r in rows], "o-", label="measured Q(e)")
        ax.plot([r["k"] for r in rows], [r["sig_bytes_q64"] for r in rows], "k--", label="q x 64 B")
        ax.set_xlabel("validators k"); ax.set_ylabel("bytes"); ax.set_title("F3: certificate size vs k"); ax.legend(); ax.grid(alpha=.3)
        return fig

    Bundle("m3_cert_size", "Measurement 3: certificate size vs k", {"events": events, "ks": list(ks)}, seed,
           "Serialized Q(e) (q Ed25519 signatures keyed by validator id).",
           ["Ed25519 signatures only; an aggregate-signature scheme would be smaller.", "Includes the validator-id strings and CBOR framing."],
           out=out).write(cert_rows, plot3)
    return rows, cert_rows


# 4 gamma vs eta (F4)
def gamma_vs_eta(out, seed=1, N=60, etas=(0.02, 0.05, 0.1, 0.2, 0.4)):
    rows = []
    for series, entry, amt, nent in (("dbar~1", 500_000, 1_500, 6), ("dbar~3", 10_000, 25_000, 100)):
        for eta in etas:
            rnd = random.Random(seed + int(eta * 1000))
            c = Cluster("min", banks=("A", "B"), seed=seed)
            A, B = c.banks["A"], c.banks["B"]
            for i in range(nent):
                A.onboard(f"a{i}", entry)
            B.onboard("b", 1_000); c.tick(1)
            for i in range(1, nent):                        # pool customer balances (intra-bank, no events) so a0 can pay
                A.transfer(f"a{i}", "a0", entry)
            done = 0
            for _ in range(N):
                c.tick(1)
                try:
                    if rnd.random() < eta:
                        A.pay("a0", "B", "b", amt) if A.customers["a0"] >= amt else A.pay("a1", "B", "b", amt)
                    else:
                        A.rehome("NGN", amount=amt // 3 if series == "dbar~3" else 1_500)
                    done += 1
                except PaymentFailed:
                    pass
            g = custody.gamma(c.validators["val-00"].store)
            rows.append({"series": series, "eta_target": eta, "N": g["N"], "E1": g["E1"], "E3": g["E3"], "eta_meas": g["eta"],
                         "dbar": g["dbar"], "gamma_meas": g["gamma"], "gamma_dbar_over_eta": g["identity"]})

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(figsize=(6, 4.2))
        for s, mk in (("dbar~1", "o"), ("dbar~3", "s")):
            rs = [r for r in rows if r["series"] == s and r["gamma_meas"]]
            ax.plot([r["eta_meas"] for r in rs], [r["gamma_meas"] for r in rs], mk, label=f"measured {s}")
        xs = [i / 100 for i in range(1, 60)]
        for d in (1, 3):
            ax.plot(xs, [d / x for x in xs], "--", alpha=.5, label=f"dbar/eta, dbar={d}")
        ax.set_yscale("log"); ax.set_xlabel("eta (inter-bank outputs per debit)"); ax.set_ylabel("gamma = |E1| / |E3|")
        ax.set_title("F4: compression ratio vs eta"); ax.legend(fontsize=7); ax.grid(alpha=.3)
        return fig

    return Bundle("m4_gamma_vs_eta", "Measurement 4: compression ratio gamma vs eta (replaces paper Table 7)",
                  {"N": N, "etas": list(etas)}, seed, "gamma = |E1|/|E3| from live traffic against the identity dbar/eta (Prop 17).",
                  ["The mixes are generated by this script: eta and dbar reflect the generator, not real payment traffic.",
                   "Two banks only; every inter-bank payment goes A to B.", "This checks the identity on a real ledger, not how much information G3 retains."],
                  out=out).write(rows, plot)


# 6 cone size (F6)
def hop_levels(store, root):
    lvl, q = {root: 0}, deque([root])
    while q:
        x = q.popleft()
        for ch in store.children(x):
            if ch not in lvl:
                lvl[ch] = lvl[x] + 1; q.append(ch)
    return lvl


def cone_size(out, seed=1, banks=24, snaps=(80, 160, 240), consolidate=0.1):
    rnd = random.Random(seed)
    names = [f"B{i:02d}" for i in range(banks)]
    c = Cluster("min", banks=tuple(names), seed=seed)
    roots = {}
    for n in names:
        for k in range(2):
            roots[c.banks[n].onboard(f"{n}-a{k}", rnd.randrange(100_000, 400_000))] = n
    st_ = c.validators["val-00"].store
    rows, hop_rows, done = [], [], 0
    for snap in snaps:
        while done < snap:
            c.tick(1)
            b = c.banks[rnd.choice(names)]
            try:
                if rnd.random() < consolidate:
                    b.rehome("NGN")
                else:
                    d = rnd.choice([n for n in names if n != b.name])
                    b.pay(f"{b.name}-a0", d, f"{d}-a0", rnd.randrange(1_000, 5_000))
            except PaymentFailed:
                pass
            done += 1
        total = st_.event_count()
        agg = {}
        for root, bank in roots.items():
            s = pc(); ids = cone_build(st_, [root], c.P.w_esc); ms = (pc() - s) * 1000
            lv = hop_levels(st_, root)
            held = sum(st_.conn.execute("SELECT COUNT(*) FROM entries WHERE eid=?", (i,)).fetchone()[0] for i in ids)
            rows.append({"volume": snap, "events_total": total, "root": root.hex()[:8], "root_bank": bank, "cone_events": len(ids),
                         "held_entries": held, "max_hops": max(lv.values()), "build_ms": ms})
            for h in lv.values():
                agg[h] = agg.get(h, 0) + 1
        for h, n in sorted(agg.items()):
            hop_rows.append({"volume": snap, "hop": h, "avg_events_at_hop": n / len(roots)})
    tracemalloc.start()
    mem = []
    for root in list(roots)[:6]:
        tracemalloc.reset_peak(); ids = cone_build(st_, [root], c.P.w_esc); mem.append((tracemalloc.get_traced_memory()[1] / 1024, len(ids)))
    tracemalloc.stop()

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 3, figsize=(14, 4))
        vols = sorted({r["volume"] for r in rows})
        ax[0].plot(vols, [st.median([r["cone_events"] for r in rows if r["volume"] == v]) for v in vols], "o-", label="median")
        ax[0].plot(vols, [max(r["cone_events"] for r in rows if r["volume"] == v) for v in vols], "s-", label="max")
        ax[0].set_xlabel("payments so far"); ax[0].set_ylabel("cone events"); ax[0].set_title("Cone size vs volume"); ax[0].legend()
        for v in vols:
            hs = [r for r in extra["hops"] if r["volume"] == v]
            ax[1].plot([r["hop"] for r in hs], [r["avg_events_at_hop"] for r in hs], "o-", label=f"volume {v}")
        ax[1].set_yscale("log"); ax[1].set_xlabel("hops from root"); ax[1].set_ylabel("avg cone events at hop"); ax[1].set_title("Cone size vs hops"); ax[1].legend(fontsize=7)
        last = [r for r in rows if r["volume"] == vols[-1]]
        ax[2].plot([r["cone_events"] for r in last], [r["build_ms"] for r in last], "o")
        ax[2].set_xlabel("cone events"); ax[2].set_ylabel("ConeBuild ms"); ax[2].set_title("ConeBuild time vs cone size")
        for a in ax:
            a.grid(alpha=.3)
        fig.suptitle("F6: cone size, hops and ConeBuild time")
        return fig

    return Bundle("m6_cone_size", "Measurement 6: cone size vs hops and volume; ConeBuild time and memory",
                  {"banks": banks, "snaps": list(snaps), "consolidate": consolidate}, seed,
                  "Cone size (events, held entries), hop profile and ConeBuild time for every root at three history lengths.",
                  ["Random uniform payments among 24 banks, 10% consolidations: a generator mix, not real traffic.",
                   "Small histories (hundreds of events); cone growth at 10^5 events is not shown.",
                   "Fan-out is whatever the generator produces; no hub banks."],
                  out=out).write(rows, plot, {"hops": hop_rows, "memory_peak_KB_vs_cone": mem})


# 9 hold sets (F9)
def hold_poisoning(out, seed=1, victims=10, steps=50, rates=(0, 5, 10, 20, 40), consolidate=0.15, t_min_frac=0.01):
    rows = []
    for rate in rates:
        rnd = random.Random(seed + rate)
        names = ["X"] + [f"V{i}" for i in range(victims)]
        c = Cluster("min", banks=tuple(names), seed=seed)
        root = c.banks["X"].onboard("dirty", 1_000_000)
        for n in names[1:]:
            for k in range(2):
                c.banks[n].onboard(f"{n}-a{k}", 200_000)
        c.tick(1)
        poison = 0
        for _ in range(steps):
            c.tick(1)
            v = c.banks[rnd.choice(names[1:])]
            try:
                if rnd.random() < consolidate:
                    v.rehome("NGN")
                else:
                    d = rnd.choice([n for n in names[1:] if n != v.name])
                    v.pay(f"{v.name}-a0", d, f"{d}-a1", rnd.randrange(1_000, 4_000))
                if rnd.random() < rate / 100:
                    c.banks["X"].pay("dirty", rnd.choice(names[1:]), f"V{rnd.randrange(victims)}-a1", 150); poison += 1
            except (PaymentFailed, KeyError):
                pass
        f = c.make_flag([root]); c.submit_flag(f)
        v0 = c.validators["val-00"]
        held = v0.store.held_keys(c.clock.now())
        owners = {v0.store.entry(*k)["owner"] for k in held}
        eng = run_engine(v0.store, BankOpenings(c.banks), [root], c.P.w_esc)
        tmin = int(eng.P * t_min_frac)
        keep = {k for k in held if eng.Tb(v0.store.entry(*k)["owner"]) >= tmin}
        total_entries = len(v0.store.all_entries())
        rows.append({"poison_rate_pct": rate, "poison_payments": poison, "P_flagged": int(eng.P), "t_min": tmin,
                     "total_entries": total_entries, "held_phase0": len(held), "banks_held_phase0": len(owners),
                     "held_after_tmin": len(keep), "banks_after_tmin": len({v0.store.entry(*k)["owner"] for k in keep}),
                     "victim_taint_mass": float(sum(eng.Tb(o) for o in owners if o != "X")),
                     "attacker_taint_mass": float(eng.Tb("X"))})
    return rows


def anchor_window(out, seed=1, anchors=40, span=3000, windows=(60, 300, 600, 1800, 3000)):
    c = Cluster("min", banks=("A", "B"), seed=seed)
    A, B = c.banks["A"], c.banks["B"]
    tiv = next(iter(c.tivs.values()))
    root = A.onboard("dirty", 100_000); B.onboard("b", 10_000); c.tick(1)
    step = 2 * span / anchors
    t_exit = anchors // 2
    for i in range(anchors + 1):
        c.tick(step)
        if i == t_exit:
            A.exit("dirty", 10_000)
        else:
            B.anchor("b", 2_000 + (i % 3) * 1_000, "NGN", tiv)
    rows = []
    store = c.validators["val-00"].store
    for w in windows:
        ids = cone_build(store, [root], w)
        ancs = [i for i in ids if store.event_meta(i)["type"] == ANC]
        eng = run_engine(store, BankOpenings(c.banks), [root], w)
        drew = sum(1 for a in ancs if (a, 0) in eng.entries and eng.entries[(a, 0)].rho > 0)
        t_exit = max(store.event_meta(i)["ttok"] for i in ids if store.event_meta(i)["type"] == EXT)
        before = sorted((store.event_meta(a)["ttok"], eng.entries[(a, 0)].A) for a in ancs
                        if store.event_meta(a)["ttok"] < t_exit and (a, 0) in eng.entries and eng.entries[(a, 0)].rho == 0)
        remaining, claimed = eng.Y, 0                 # deferred-anchor rule: oldest open anchors are closed first
        for _t, amt in before:
            if remaining <= 0:
                break
            claimed += 1
            remaining -= min(amt, remaining)
        rows.append({"w_esc_s": w, "anchors_total": anchors, "anchors_held": len(ancs), "anchors_that_drew_taint": drew,
                     "anchors_behind_tiv_claim": claimed, "unrelated_held": len(ancs) - drew - claimed})
    return rows


def hold_sets(out, **kw):
    pr = hold_poisoning(out, **{k: v for k, v in kw.items() if k in ("seed", "victims", "steps", "rates")})
    aw = anchor_window(out, seed=kw.get("seed", 1), anchors=kw.get("anchors", 40))

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 2, figsize=(11, 4))
        ax[0].plot([r["poison_rate_pct"] for r in rows], [r["held_phase0"] for r in rows], "o-", label="Phase 0 hold (entries)")
        ax[0].plot([r["poison_rate_pct"] for r in rows], [r["held_after_tmin"] for r in rows], "s-", label="after T_min release")
        ax[0].plot([r["poison_rate_pct"] for r in rows], [r["banks_held_phase0"] for r in rows], "^--", label="banks affected (Phase 0)")
        ax[0].set_xlabel("poisoning rate (% of steps)"); ax[0].set_ylabel("count"); ax[0].set_title("Hold set vs poisoning rate"); ax[0].legend(fontsize=7)
        aw_ = extra["anchor_window"]
        ax[1].plot([r["w_esc_s"] for r in aw_], [r["anchors_held"] for r in aw_], "o-", label="anchors held")
        ax[1].plot([r["w_esc_s"] for r in aw_], [r["anchors_that_drew_taint"] + r["anchors_behind_tiv_claim"] for r in aw_], "^--", label="related (drew taint or TIV claim)")
        ax[1].plot([r["w_esc_s"] for r in aw_], [r["unrelated_held"] for r in aw_], "s--", label="unrelated (drew nothing, no claim)")
        ax[1].set_xlabel("W_esc (s)"); ax[1].set_title("Unrelated anchors held vs W_esc"); ax[1].legend(fontsize=7)
        for a in ax:
            a.grid(alpha=.3)
        fig.suptitle("F9: temporary hold under dust poisoning and the anchor-window rule")
        return fig

    return Bundle("m9_hold_sets", "Measurement 9: hold set under dust poisoning; unrelated anchors held",
                  {"poison": kw, "t_min_frac": 0.01}, kw.get("seed", 1),
                  "Phase 0 hold-set size and banks affected vs poisoning rate, before and after the T_min release; anchors held vs W_esc.",
                  ["Ten victim banks, a 1,000,000 flagged principal and random consolidations: a generator mix, not real traffic.",
                   "T_min is 1% of the flagged principal; other thresholds shift the second curve.",
                   "The anchor series has one exit and uniformly spaced anchors; real inflow patterns would differ.",
                   "Release after T_min is computed from engine custody values, not by running the Phase 4 events."],
                  out=out).write(pr, plot, {"anchor_window": aw})


# 12 partition availability (F12)
SPLITS = {"dev": 5, "k5f1": 3, "k5f0": 3}


def partition_availability(out, seed=1, rounds=24, start=8, end=16):
    rows, abort_rows = [], []
    for prof, major in SPLITS.items():
        c = Cluster(prof, banks=("A", "B"), seed=seed)
        A, B = c.banks["A"], c.banks["B"]
        A.onboard("a", 5_000_000); B.onboard("b", 5_000_000); c.tick(1)
        vids = list(c.validators)
        stuck = []
        for r in range(rounds):
            c.tick(1)
            if r == start:
                c.net.partition(set(vids[:major]) | {"A"}, set(vids[major:]) | {"B"})
            if r == end:
                c.net.heal(); c.sync_all()
                c.tick(c.P.delta_stale + 1)                  # the stranded events are now stale: try abort proofs
                for name, ev in stuck:
                    a = c.abort(name, ev)
                    abort_rows.append({"profile": prof, "bank": name, "statements": a["statements"], "needed": a["needed"],
                                       "freed": int(bool(a["applied_at"]))})
                stuck = []
            phase = "before" if r < start else ("during" if r < end else "after")
            for side, bank, dst, acct in (("majority", A, "B", "a"), ("minority", B, "A", "b")):
                res = bank.pay(acct, dst, acct, 1_000 + r)
                ok = bool(res.ok)
                if not ok:
                    for eid in list(bank.pending):
                        if phase == "during" and not any(n == bank.name for n, _ in stuck):
                            stuck.append((bank.name, bank.pending[eid].built.event))
                        bank.abandon(eid)
                rows.append({"profile": prof, "q": c.P.q, "k": c.P.k, "round": r, "phase": phase, "side": side, "finalized": int(ok),
                             "analytic": int(major >= c.P.q) if (phase == "during" and side == "majority") else
                                         (0 if phase == "during" else 1)})
    summary = {}
    for r in rows:
        key = (r["profile"], r["phase"], r["side"])
        summary.setdefault(key, []).append(r["finalized"])

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 3, figsize=(14, 3.6), sharey=True)
        for a, prof in zip(ax, SPLITS):
            for side, mk in (("majority", "o-"), ("minority", "s--")):
                rs = [r for r in rows if r["profile"] == prof and r["side"] == side]
                a.plot([r["round"] for r in rs], [r["finalized"] + (0.04 if side == "minority" else 0) for r in rs], mk, label=side, alpha=.8)
            a.axvspan(start, end, color="red", alpha=.08)
            a.set_title(f"{prof} (q={rs[0]['q']}, split {SPLITS[prof]}/{rs[0]['k'] - SPLITS[prof]})"); a.set_xlabel("round")
        ax[0].set_ylabel("submission finalized (1/0)"); ax[0].legend()
        fig.suptitle("F12: finalization per partition side over time (shaded: partition)")
        return fig

    agg = [{"profile": k[0], "phase": k[1], "side": k[2], "fraction_finalized": sum(v) / len(v), "n": len(v)} for k, v in summary.items()]
    Bundle("m12_partition_availability", "Measurement 12 (partition part): fraction finalized per side over time",
           {"rounds": rounds, "partition_rounds": [start, end], "splits": SPLITS}, seed,
           "Whether a submission finalizes on each side before, during and after a partition, against Proposition 11.",
           ["Network shim partition, not netem; the heal is instantaneous and total.",
            "One submission per side per round; no load, no queueing, no latency model.",
            "Availability only: safety is covered by the T-PART and monitor checks.",
            "After the heal the harness tries one abort proof per stranded event; keys that cannot be freed stay locked "
            "(the paper's documented residual: reconfiguration is not specified)."],
           out=out).write(rows, plot, {"summary": agg, "abort": abort_rows})
    return agg
