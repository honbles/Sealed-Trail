"""Cost of taint-bound certificates (sealedtrail/sharecert.py): proof bytes and prove/verify time per event, by aggregation size.

    python3 scripts/bench_certs.py [--out results/certs_bench.json]
Timings depend on the machine; the proof sizes do not. The first call also pays one-time generator setup, so a warm-up is run first.
"""
import argparse, json, os, platform, random, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sealedtrail import crypto as cr, sharecert as sc

K = sc.K_DEFAULT


def mk(rng, n_par):
    rp = [rng.randrange(0, (1 << K) + 1) for _ in range(n_par)]
    a = [rng.randrange(1, 1 << 30) for _ in rp]
    b = [cr.rand_scalar() for _ in rp]
    c = [cr.commit(x, y) for x, y in zip(a, b)]
    r = -((-sum(x * y for x, y in zip(a, rp))) // sum(a))
    return {"a": a, "blind": b, "r_parent": rp, "r_ev": r}, {"commits": c, "r_parent": rp, "r_ev": r}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/certs_bench.json")
    ap.add_argument("--reps", type=int, default=5)
    a = ap.parse_args()
    rng = random.Random(9)
    ev, pub = zip(*[mk(rng, 2) for _ in range(4)])
    sc.verify_certs(b"w", list(pub), sc.prove_certs(b"w", list(ev)))          # warm-up
    rows = []
    for batch in (1, 16, 64, 256):
        tp, tv, size = [], [], 0
        for _ in range(a.reps):
            ev, pub = zip(*[mk(rng, 2) for _ in range(batch)])
            t = time.perf_counter(); pr = sc.prove_certs(b"x", list(ev)); tp.append((time.perf_counter() - t) / batch)
            t = time.perf_counter(); ok = sc.verify_certs(b"x", list(pub), pr); tv.append((time.perf_counter() - t) / batch)
            assert ok
            size = len(pr)
        rows.append({"batch": batch, "proof_bytes": size, "bytes_per_event": round(size / batch, 1),
                     "prove_ms_per_event": round(1000 * sorted(tp)[len(tp) // 2], 2), "verify_ms_per_event": round(1000 * sorted(tv)[len(tv) // 2], 2)})
        print(rows[-1], flush=True)
    meta = {"cpus": os.cpu_count(), "platform": platform.platform(), "python": sys.version.split()[0], "K": K, "parents_per_event": 2, "reps": a.reps}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump({"env": meta, "rows": rows}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
