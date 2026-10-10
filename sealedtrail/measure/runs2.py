"""Measurements 7, 8, 10 and figures F7, F8, F10, F11 (spec 10.4 and 10.5). In-process runtime; CPU times
measured on this machine, no network."""
from __future__ import annotations

import random
import statistics as st
import time
from fractions import Fraction as F

from .. import crypto as C
from ..bank import PaymentFailed
from ..engine.cone import cone_build
from ..engine.facts import LogOpenings, event_facts
from ..engine.taint import TaintEngine
from ..monitors import all_monitors
from ..reversal import Reversal
from ..sim import Cluster
from .bundle import Bundle

pc = time.perf_counter


def mk_chain(L, start=1_000_000, frac=0.6, profile="min", extra=("R",), seed=1):
    names = tuple(f"B{i}" for i in range(L)) + tuple(extra)
    c = Cluster(profile, banks=names, seed=seed)
    root = c.banks["B0"].onboard("x", start)
    c.tick(1)
    for i in range(L - 1):
        b = c.banks[f"B{i}"]
        amt = int(b.customers["x"] * frac) if i else int(start * frac)
        b.pay("x", f"B{i+1}", "x", amt)
        c.tick(1)
    return c, root, names


# F10: the mass trace
def mass_trace(out, seed=1):
    names = ("A", "B", "C", "D", "R")
    c = Cluster("min", banks=names, seed=seed)
    c.P.w_esc = 120
    tiv = c.tivs["tiv-0"]
    A, B, Cb, D = (c.banks[n] for n in "ABCD")
    root = A.onboard("dirty", 400_000); c.tick(1)
    A.pay("dirty", "B", "b", 150_000); c.tick(1)
    B.pay("b", "C", "c", 90_000); c.tick(1)
    Cb.exit("c", 60_000); c.tick(5)                       # EXT: 60k into the escrow
    D.anchor("d", 40_000, "NGN", tiv); c.tick(5)          # unattested: draws 40k
    D.anchor("d", 50_000, "NGN", tiv); c.tick(5)          # draws 20k, 30k stays open
    Cb.exit("c", 25_000); c.tick(5)                       # deferred rule: 25k moves to Y
    A.exit("dirty", 15_000); c.tick(c.P.w_esc + 30)       # a tranche that will expire
    A.pay("dirty", "B", "b", 10_000); c.tick(1)           # processed after the window: expiry into Z
    f = c.make_flag([root], brec="R", ttl=3600)
    rv = Reversal(c, f)
    rep = rv.run()
    c.tick(1)
    R = c.banks["R"]
    res, eid = R.issue_rev(f.id, 50_000, "R", kind="restitution", beneficiary="A")
    rv.ingest_rev(eid)
    store = rv.store
    ids = cone_build(store, [root], c.P.w_esc)
    eng = TaintEngine(c.P.w_esc, injections={root: "whole"}, brec="R")
    src = LogOpenings(store, rv.log.get)
    rows = []
    for i, eid in enumerate(ids):
        ev, _ = store.get_event(eid)
        eng.process(event_facts(store, eid, src))
        t = eng.terms()
        label = ev.type + (":" + ev.rev_kind[:3] if ev.rev_kind else "") + " " + ev.issuer
        rows.append({"step": i, "event": label, "live": float(t["live"]), "E": float(t["E"]), "Y": float(t["Y"]),
                     "Z": float(t["Z"]), "D": float(t["D"]), "P": float(t["P"]), "identity_ok": bool(eng.identity_ok())})
    extra = {"recovery_rate": float(eng.metrics("R")["RecoveryRate"]), "reversed": rep["reversed"],
             "claims_per_tiv": {k: float(v) for k, v in eng.claims.items()},
             "liabilities": {k: float(v) for k, v in eng.liab.items()}}

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(figsize=(9, 4.4))
        xs = [r["step"] for r in rows]
        ax.stackplot(xs, [r["live"] for r in rows], [r["E"] for r in rows], [r["Y"] for r in rows],
                     [r["Z"] for r in rows], [r["D"] for r in rows],
                     labels=["live flagged mass (sum rho*R)", "escrow E", "TIV claim Y", "written off Z", "restituted D"])
        ax.plot(xs, [r["P"] for r in rows], "k--", label="flagged principal P")
        ax.set_xticks(xs); ax.set_xticklabels([r["event"] for r in rows], rotation=70, ha="right", fontsize=6)
        ax.set_ylabel("mass (NGN units)"); ax.legend(fontsize=7, loc="center left", bbox_to_anchor=(1, .5))
        ax.set_title(f"F10: Theorem 14 mass identity after every event (all {len(rows)} steps ok="
                     f"{all(r['identity_ok'] for r in rows)}); final recovery rate {extra['recovery_rate']:.2f}")
        return fig
    return Bundle("f10_mass_trace", "F10: five-term mass identity over a scripted flag lifecycle",
                  {"scenario": "flag, flows, exit, two unattested anchors, deferred claim, expiry, REV round, restitution",
                   "w_esc": 120}, seed,
                  "sum(rho*R)+E+Y+Z+D = P (Theorem 14) after every event, including REV with lambda and restitution.",
                  ["One scripted scenario, not a distribution. Four banks and one TIV.", "Amounts are in a single currency (Thm 14 is stated per currency)."],
                  out=out).write(rows, plot, extra)


# F11: recovery vs refusing banks
def recovery_vs_refusal(out, seed=1, L=7, trials=5):
    rows = []
    for series in ("refuse_open", "refuse_rev", "refuse_both"):
        for r in range(0, L):
            for t in range(trials):
                rnd = random.Random(seed * 1000 + r * 10 + t)
                c, root, names = mk_chain(L, seed=seed)
                for b in rnd.sample([f"B{i}" for i in range(L)], r):
                    c.banks[b].behavior = series
                f = c.make_flag([root], brec="R", ttl=3600)
                rep = Reversal(c, f).run(tick=False)
                rec = rep["metrics"]["RecoveryRate"]            # None when the flagged root itself is unresolved (P unknown)
                rows.append({"series": series, "refusers": r, "trial": t, "recovery_rate": float(rec or 0),
                             "root_unresolved": rec is None,
                             "unresolved_banks": len(rep["unresolved_banks"]), "reversed_banks": len(rep["reversed"]),
                             "non_compliant": len(rep["non_compliant"])})

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 2, figsize=(10, 3.8))
        for s, mk in (("refuse_open", "o-"), ("refuse_rev", "s--"), ("refuse_both", "^:")):
            xs = sorted({r["refusers"] for r in rows})
            m = [st.mean(x["recovery_rate"] for x in rows if x["series"] == s and x["refusers"] == k) for k in xs]
            u = [st.mean(x["unresolved_banks"] for x in rows if x["series"] == s and x["refusers"] == k) for k in xs]
            ax[0].plot(xs, m, mk, label=s); ax[1].plot(xs, u, mk, label=s)
        ax[0].set_xlabel("refusing banks (of 7)"); ax[0].set_ylabel("recovery rate"); ax[0].set_ylim(-.02, 1.05)
        ax[0].legend(fontsize=7); ax[0].set_title("F11: recovery vs refusing banks")
        ax[1].set_xlabel("refusing banks (of 7)"); ax[1].set_ylabel("banks left Unresolved"); ax[1].set_title("contagion of Unresolved status")
        return fig
    return Bundle("f11_recovery_vs_refusal", "F11: recovery rate vs refusing banks on a 7-bank chain",
                  {"L": L, "trials": trials}, seed,
                  "RecoveryRate after a full Algorithm 3 round when random banks refuse to open, refuse to issue REV, or both.",
                  ["A single chain, full-value policy; real topologies branch and merge.",
                   "A lone refuse_open costs nothing: a neighbour's opening resolves the same commitment (V3). Loss appears when adjacent banks refuse (Unresolved spreads downstream) or banks decline to issue REV.",
                   "Refusers are chosen uniformly at random; an adversary would choose the positions."],
                  out=out).write(rows, plot)


# F8 / measurement 8: Unresolved vs refuser depth
def unresolved_vs_depth(out, seed=1, L=9):
    c, root, names = mk_chain(L, seed=seed)
    f = c.make_flag([root], brec="R", ttl=3600)
    rows = []

    def measure(cfg, label, d):
        for b in names:
            c.banks[b].behavior = "honest"
        for b in cfg:
            c.banks[b].behavior = "refuse_open"
        rv = Reversal(c, f)
        rv.phase1(); rv.phase2()
        eng = rv.engine()
        unres = [k for k, e in eng.entries.items() if e.unres]
        return {"config": label, "depth": d, "refusers": len(cfg), "unresolved_entries": len(unres),
                "unresolved_banks": len({eng.entries[k].owner for k in unres}), "cone_entries": len(eng.entries)}
    for d in range(1, L - 1):
        rows.append(measure([f"B{d}"], "single refuser", d))
        rows.append(measure([f"B{d}", f"B{d+1}"], "refuser + next hop", d))
        rows.append(measure([f"B{i}" for i in range(d, L)], "refuser + all downstream", d))

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(figsize=(6.5, 4))
        for cfg, mk in (("single refuser", "o-"), ("refuser + next hop", "s-"), ("refuser + all downstream", "^-")):
            rs = [r for r in rows if r["config"] == cfg]
            ax.plot([r["depth"] for r in rs], [r["unresolved_entries"] for r in rs], mk, label=cfg)
        ax.set_xlabel("depth of the refusing bank (hops from the flagged origin)"); ax.set_ylabel("Unresolved cone entries")
        ax.set_title("F8: size of the Unresolved set (9-bank chain)"); ax.legend(fontsize=8); ax.grid(alpha=.3)
        return fig
    return Bundle("m8_unresolved_vs_depth", "F8: Unresolved set size vs refuser depth and cooperation of neighbours",
                  {"L": L}, seed, "Unresolved entries in the cone after Phase 2 when banks refuse to open (Algorithm 4).",
                  ["A chain: no branching, so contagion cannot fan out; a branching graph can only be larger.",
                   "A single refuser leaves nothing Unresolved: neighbours' openings resolve the same commitment (V3, sum kc = sum kappa).",
                   "The multi-parent case (per-parent amounts hidden behind a refusal) is not measured here."],
                  out=out).write(rows, plot)


# F7 / measurement 7: opening cost
def opening_cost(out, seed=1, lengths=(4, 8, 16, 24)):
    rows = []
    for L in lengths:
        c, root, names = mk_chain(L, start=2_000_000_000, frac=0.8, seed=seed)
        f = c.make_flag([root], brec="R", ttl=3600)
        rv = Reversal(c, f)
        rv.phase1()
        ids = rv.cone()
        t_bank = t_reg = t_val = 0.0
        n = size = 0
        for bank in rv.b1:
            reqs = rv.requests(bank, ids)
            t0 = pc(); got = c.banks[bank].open_for_flag(reqs); t_bank += pc() - t0
            t0 = pc()
            ok = {k: v for k, v in got.items() if C.commit(v[0], v[1]) == k}
            t_reg += pc() - t0
            t0 = pc(); c.record_openings(ok); t_val += pc() - t0
            n += len(ok)
            size += sum(32 + 8 + 32 for _ in ok)                # commitment ref + amount + blinding
        k = c.P.k
        rows.append({"cone_events": len(ids), "openings": n, "bank_ms_per_opening": 1e3 * t_bank / n,
                     "regulator_verify_ms_per_opening": 1e3 * t_reg / n,
                     "validator_record_ms_per_opening_per_validator": 1e3 * t_val / n / k,
                     "bytes_per_opening": size / n, "total_bytes": size})

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 2, figsize=(10, 3.8))
        xs = [r["openings"] for r in rows]
        ax[0].plot(xs, [r["bank_ms_per_opening"] for r in rows], "o-", label="bank prepares")
        ax[0].plot(xs, [r["regulator_verify_ms_per_opening"] for r in rows], "s-", label="regulator verifies")
        ax[0].plot(xs, [r["validator_record_ms_per_opening_per_validator"] for r in rows], "^-", label="validator records (each)")
        ax[0].set_xlabel("openings in the cone"); ax[0].set_ylabel("ms per opening"); ax[0].legend(fontsize=7)
        ax[1].plot(xs, [r["total_bytes"] for r in rows], "o-"); ax[1].set_xlabel("openings in the cone"); ax[1].set_ylabel("bytes (commitment + amount + blinding)")
        ax[0].set_title("F7: opening cost"); return fig
    return Bundle("m7_opening_cost", "F7: opening cost per cone entry (bank, regulator, validator)", {"lengths": list(lengths)}, seed,
                  "CPU time and bytes to produce, verify and record the openings of a flag's cone.",
                  ["In-process: no network. Verification is one Pedersen commitment check per opening.",
                   "Chain cones only; k=4 validators."], out=out).write(rows, plot)


# measurement 10: continuous invariant checks
def invariants(out, seed=1, steps=220, banks=6):
    rnd = random.Random(seed)
    names = tuple(f"B{i}" for i in range(banks)) + ("R",)
    c = Cluster("min", banks=names, seed=seed)
    tiv = c.tivs["tiv-0"]
    roots = []
    for n in names[:-1]:
        for _ in range(3):
            roots.append(c.banks[n].onboard("x", 400_000))
    c.tick(1)
    counts = {k: 0 for k in ("M1M2M3M5", "M8_reconcile", "M9_live_bound", "M6_mass", "M7_rehome", "M10_hold")}
    viol = {k: 0 for k in counts}
    flag = None
    done = 0
    t0 = pc()
    while done < steps:
        done += 1
        c.tick(1)
        b = c.banks[rnd.choice(names[:-1])]
        try:
            u = rnd.random()
            if u < 0.55:
                b.pay("x", rnd.choice([n for n in names[:-1] if n != b.name]), "x", rnd.randint(300, 20_000))
            elif u < 0.80:
                b.rehome("NGN", rnd.randint(300, 20_000))
            elif u < 0.85:
                b.exit("x", rnd.randint(300, 10_000))
            else:
                b.anchor("x", rnd.randint(300, 20_000), "NGN", tiv)
        except PaymentFailed:
            pass
        if done == steps // 2 and flag is None:
            flag = c.make_flag(roots[:3], brec="R", ttl=3600)       # all three entries of one bank are flagged
            c.submit_flag(flag)
        counts["M1M2M3M5"] += 1; viol["M1M2M3M5"] += bool(all_monitors(c))
        counts["M8_reconcile"] += 1; viol["M8_reconcile"] += not all(bk.reconcile() for bk in c.banks.values())
        live = sum(1 for bk in c.banks.values() for h in bk.holdings.values() if h.residual()[0] > 0)
        total = sum(bk.owned_total() for bk in c.banks.values())
        counts["M9_live_bound"] += 1; viol["M9_live_bound"] += live > total // c.P.omega["NGN"]
        if flag is not None:
            from ..monitors import m10_hold_coverage
            counts["M10_hold"] += 1; viol["M10_hold"] += bool(m10_hold_coverage(c, flag.id))
    # M6 / M7 on the flagged cone
    rv = Reversal(c, flag)
    rv.phase1(); rv.phase2()
    store = rv.store
    eng = TaintEngine(c.P.w_esc, injections={r: "whole" for r in roots[:3]}, brec="R")
    src = LogOpenings(store, rv.log.get)
    for eid in cone_build(store, roots[:3], c.P.w_esc):
        ev, _ = store.get_event(eid)
        before = eng.Tb(ev.issuer)
        eng.process(event_facts(store, eid, src))
        counts["M6_mass"] += 1; viol["M6_mass"] += not eng.identity_ok()
        if ev.type == "DEB" and all(o.owner == ev.issuer for o in ev.outputs):
            counts["M7_rehome"] += 1; viol["M7_rehome"] += eng.Tb(ev.issuer) != before
    rows = [{"monitor": k, "checks": counts[k], "violations": viol[k]} for k in counts]

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(figsize=(7, 3.6))
        ax.bar([r["monitor"] for r in rows], [r["checks"] for r in rows], label="checks")
        ax.bar([r["monitor"] for r in rows], [r["violations"] for r in rows], color="red", label="violations")
        ax.set_ylabel("count"); ax.legend(); plt.setp(ax.get_xticklabels(), rotation=25, ha="right", fontsize=8)
        ax.set_title(f"Measurement 10: invariant monitors over {steps} random steps (violations = {sum(r['violations'] for r in rows)})")
        return fig
    return Bundle("m10_invariants", "Measurement 10: continuous invariant checks", {"steps": steps, "banks": banks}, seed,
                  "M1/M2/M3/M5 (supply identity, single spend, lock consistency, convergence), M8 reconciliation, M9 live-entry bound, "
                  "M10 hold coverage after a flag, M6 mass identity and M7 re-homing invariance over the flagged cone.",
                  ["M4 (acyclicity assertion) and M11 (per-TIV supply commitment) are not implemented.",
                   "A random workload on six banks, one flag; not an exhaustive state search.", "M6/M7 are checked after the run over the cone, event by event."],
                  out=out).write(rows, plot, {"total_seconds": pc() - t0})


# measurement 14: per-validator capacity
def validator_capacity(out, seed=1, events=40, k=7, cores=(1, 2, 4, 8, 16)):
    """Where one validator's time goes per event, and the ceiling it implies.

    One validator (val-00, file-backed SQLite store with WAL and synchronous=FULL) is timed while a cluster settles payments. The node
    server holds ONE writer lock around request_lock and around finalize, so a validator is strictly serial and every validator
    processes every event: that serial rate is the ceiling of the whole network, whatever the number of validators.
    The 'modelled' rows move the pure-function work (proof verification, certificate check) outside the lock; they are NOT measured.
    """
    import tempfile
    from ..model import DEB, Event

    parents_seen, per = {}, []
    with tempfile.TemporaryDirectory() as td:
        c = Cluster("dev", banks=("A", "B"), seed=seed, store_dir=td)
        v = c.validators["val-00"]
        acc = {"val": 0.0, "cert": 0.0}
        o_rl, o_acc, o_val, o_vc = v.request_lock, v.accept, v._validate, v.verify_cert
        cur = {"on": False}

        def val(e, lock=False):
            s = pc()
            try:
                return o_val(e, lock)
            finally:
                if cur["on"]:
                    acc["val"] += (pc() - s) * 1e3

        def vc(eid, cert):
            s = pc()
            try:
                return o_vc(eid, cert)
            finally:
                if cur["on"]:
                    acc["cert"] += (pc() - s) * 1e3

        def rl(wire):
            e = Event.from_wire(wire)
            cur["on"] = e.type == DEB
            acc["val"] = acc["cert"] = 0.0
            s = pc()
            r = o_rl(wire)
            dt = (pc() - s) * 1e3
            if cur["on"] and r[0] == "ok":
                per.append({"P": len(e.parents), "eid": e.id, "lock_ms": dt, "lock_validate_ms": acc["val"]})
            cur["on"] = False
            return r

        def accept(wire, cert, _depth=0):
            e = Event.from_wire(wire)
            cur["on"] = e.type == DEB
            acc["val"] = acc["cert"] = 0.0
            s = pc()
            try:
                return o_acc(wire, cert, _depth)
            finally:
                dt = (pc() - s) * 1e3
                if cur["on"]:
                    for r in reversed(per):
                        if r["eid"] == e.id:
                            r.update({"fin_ms": dt, "fin_validate_ms": acc["val"], "fin_cert_ms": acc["cert"]})
                            break
                cur["on"] = False
        v._validate, v.verify_cert, v.request_lock, v.accept = val, vc, rl, accept
        A, B = c.banks["A"], c.banks["B"]
        A.onboard("big", 80_000_000)
        B.onboard("b", 1_000)
        c.tick(1)
        for i in range(events):                           # single-parent debits
            c.tick(1)
            A.pay("big", "B", "b", 1_000 + i)
        for i in range(events):                           # multi-parent debits: bank B holds only small entries, a payment spans them
            for j in range(4):
                B.onboard("small", 3_000)
            c.tick(1)
            try:
                B.pay("small", "A", "a", 10_000 + i)
            except PaymentFailed:
                pass
    per = [r for r in per if "fin_ms" in r]
    rows = []
    byP = {}
    for r in per:
        byP.setdefault(min(r["P"], 4), []).append(r)
    comp = {}
    for P, rs in sorted(byP.items()):
        if len(rs) < 3:
            continue
        m = lambda key: st.median(x[key] for x in rs)
        lock, fin = m("lock_ms"), m("fin_ms")
        val_l, val_f, cert = m("lock_validate_ms"), m("fin_validate_ms"), m("fin_cert_ms")
        lock_w, fin_w = max(0.0, lock - val_l), max(0.0, fin - val_f - cert)
        comp[P] = dict(lock=lock, fin=fin, val_l=val_l, val_f=val_f, cert=cert, lock_w=lock_w, fin_w=fin_w)
        label = f"{'>=' if P == 4 else ''}{P}"
        for what, key in (("request_lock total", "lock_ms"), ("  of which Valid(e)", "lock_validate_ms"),
                          ("finalize total", "fin_ms"), ("  of which Valid(e)", "fin_validate_ms"),
                          ("  of which certificate check", "fin_cert_ms")):
            xs = sorted(x[key] for x in rs)
            rows.append({"kind": "measured", "parents": label, "what": what.strip(), "n": len(rs), "ms_med": m(key),
                         "ms_p95": xs[min(len(xs) - 1, int(0.95 * (len(xs) - 1) + 0.5))]})
        rows.append({"kind": "measured", "parents": label, "what": "lock write + sign (residual)", "n": len(rs), "ms_med": lock_w})
        rows.append({"kind": "measured", "parents": label, "what": "finalize store write + hooks (residual)", "n": len(rs), "ms_med": fin_w})
        serial = lock + fin
        rows.append({"kind": "ceiling", "parents": label, "what": "serial writer lock (current server), 1 validator",
                     "events_per_s": 1000.0 / serial, "ms_per_event": serial})
        s_ms = lock_w + fin_w                              # what must stay under the single writer lock
        p_ms = val_l + val_f + cert                        # pure functions of the event and replicated state
        for cr in cores:
            rows.append({"kind": "modelled", "parents": label, "what": "validation outside the lock", "cores": cr,
                         "events_per_s": min(1000.0 / s_ms, cr * 1000.0 / (s_ms + p_ms)),
                         "serial_ms": s_ms, "parallel_ms": p_ms})
    extra = {"k": k, "q": c.P.q, "store": "sqlite file, WAL, synchronous=FULL", "events_single_parent": events, "events_multi_parent": events,
             "components_ms": comp}

    def plot(plt, rows, extra):
        fig, ax = plt.subplots(1, 2, figsize=(11, 4))
        P1 = [r for r in rows if r["kind"] == "measured" and r["parents"] == "1" and r["what"] in
              ("Valid(e)", "certificate check", "lock write + sign (residual)", "finalize store write + hooks (residual)")]
        comp = extra["components_ms"].get(1) or extra["components_ms"].get("1")
        if comp:
            parts = [("Valid x2", comp["val_l"] + comp["val_f"]), ("cert check", comp["cert"]), ("lock write", comp["lock_w"]),
                     ("finalize write", comp["fin_w"])]
            ax[0].bar([p[0] for p in parts], [p[1] for p in parts])
        ax[0].set(ylabel="ms per event (median, 1 parent)", title="Where one validator's time goes")
        for P in sorted({r["parents"] for r in rows if r["kind"] == "modelled"}):
            sel = [r for r in rows if r["kind"] == "modelled" and r["parents"] == P]
            ax[1].plot([r["cores"] for r in sel], [r["events_per_s"] for r in sel], "o-", label=f"modelled, parents {P}")
            ser = next(r for r in rows if r["kind"] == "ceiling" and r["parents"] == P)
            ax[1].axhline(ser["events_per_s"], ls=":", color="gray")
        ax[1].set(xscale="log", xlabel="cores per validator", ylabel="events/s per validator", title="Ceiling (dotted = serial lock, measured)")
        ax[1].legend(fontsize=7)
        fig.tight_layout()
        return fig
    return Bundle("m14_validator_capacity", "Measurement 14: per-validator capacity and the serial-lock ceiling",
                  {"k": k, "events": events, "cores": list(cores)}, seed,
                  "Time per event inside one validator (lock, finalize, validation, certificate check, store write), the serial ceiling "
                  "it implies, and a model of the ceiling if validation ran outside the writer lock.",
                  ["Python prototype on one core, in-process: no HTTP, no network, no contention between concurrent events.",
                   "The modelled rows assume validation and certificate checks can run in parallel outside the lock and that the writes "
                   "stay serial; that is NOT implemented here and not measured.",
                   "Every validator processes every event, so adding validators raises fault tolerance, not throughput.",
                   "Single-currency debits to one receiving bank; verification time grows with parents and outputs (see measurement 1).",
                   "Timed on a file-backed store (WAL, synchronous=FULL) on this machine's disk; a different disk changes the write terms."],
                  out=out).write(rows, plot, extra)
