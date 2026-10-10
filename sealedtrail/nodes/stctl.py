"""stctl: bring up and drive a Sealed Trail network (spec 2.4).

  python -m sealedtrail.nodes.stctl run --runtime inproc --banks 20 --accounts-per-bank 10 --validators 7 --byzantine 2
  python -m sealedtrail.nodes.stctl run --runtime local  --banks 6  --accounts-per-bank 4  --validators 4 --byzantine 1
  python -m sealedtrail.nodes.stctl compose --banks 100 --accounts-per-bank 10 --validators 7 --byzantine 2

Runtimes: inproc (objects, simulated network), local (one process per node, real HTTP),
docker (compose file generated; run it with docker compose up).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import topology as T


def add_flags(ap):
    ap.add_argument("--runtime", choices=["inproc", "local", "docker"], default="local")
    ap.add_argument("--banks", type=int, default=3)
    ap.add_argument("--accounts-per-bank", type=int, default=2)
    ap.add_argument("--validators", type=int, default=4)
    ap.add_argument("--byzantine", type=int, default=1)
    ap.add_argument("--na-signers", type=int, default=5)
    ap.add_argument("--na-threshold", type=int, default=3)
    ap.add_argument("--tsa", type=int, default=3)
    ap.add_argument("--tsa-threshold", type=int, default=2)
    ap.add_argument("--tivs", type=int, default=1)
    ap.add_argument("--seed", default="1")
    ap.add_argument("--base-port", type=int, default=9000)
    ap.add_argument("--dir", default="run")


def topo_from(a) -> dict:
    return T.make_topology(runtime=a.runtime, banks=a.banks, accounts_per_bank=a.accounts_per_bank,
                           validators=a.validators, byzantine=a.byzantine, na_signers=a.na_signers,
                           na_threshold=a.na_threshold, tsa=a.tsa, tsa_threshold=a.tsa_threshold,
                           tivs=a.tivs, seed=a.seed, base_port=a.base_port)


def cmd_run(a):
    from .driver import HttpDriver, InprocDriver, run_workload
    topo = topo_from(a)
    summary_base = {"runtime": a.runtime, "validators": a.validators, "byzantine": a.byzantine,
                    "q": T.params_of(topo).q, "seed": a.seed}
    if a.runtime == "inproc":
        from ..params import Params
        from ..sim import Cluster
        P = T.params_of(topo)
        names = topo["banks"]
        cl = Cluster(P, banks=tuple(names), seed=int(a.seed) if str(a.seed).isdigit() else 1)
        drv = InprocDriver(cl, names, a.accounts_per_bank)
        res = run_workload(drv, a.banks, a.accounts_per_bank, a.payments, int(a.seed) if str(a.seed).isdigit() else 1,
                           workers=1)
    elif a.runtime == "local":
        from .runtime import LocalRuntime
        run_dir = os.path.abspath(a.dir)
        rt = LocalRuntime(run_dir, topo)
        t0 = time.time()
        try:
            rt.up()
            summary_base["startup_s"] = round(time.time() - t0, 2)
            drv = HttpDriver(topo)
            res = run_workload(drv, a.banks, a.accounts_per_bank, a.payments, int(a.seed) if str(a.seed).isdigit() else 1,
                               workers=a.workers)
            drv.close()
        finally:
            if not a.keep:
                rt.down()
    else:
        res = run_docker(a, topo)
        if res is None:
            return 2
    res.update(summary_base)
    os.makedirs("results", exist_ok=True)
    out = os.path.join("results", f"run-{a.runtime}-{a.banks}b-{a.accounts_per_bank}a-{a.validators}v.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))
    print("wrote", out)
    return 0 if not res["monitor_violations"] and res["reconciled_all_banks"] else 1


def _docker_diagnostics(base, topo, out, tail=40, max_nodes=6):
    """Print and save container status plus the log tail of the validators and the first banks, and of any container that is not
    running. This is what shows whether a node crashed, ran out of memory or only answered with an error page."""
    import subprocess
    parts = []

    def run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            parts.append("$ " + " ".join(cmd[-6:]) + "\n" + (r.stdout + r.stderr)[-6000:])
        except (OSError, subprocess.SubprocessError) as ex:
            parts.append("$ " + " ".join(cmd[-6:]) + f"\n(could not run: {ex})")
    run(base + ["ps", "-a", "--format", "table {{.Name}}\t{{.Status}}"])
    run(["docker", "ps", "-a", "--filter", "status=exited", "--filter", "status=dead", "--format", "{{.Names}}\t{{.Status}}"])
    names = [n for n in topo["nodes"]]
    vals = [n for n in names if n in topo.get("validators", [])][:2]
    banks = [n for n in names if n in topo.get("banks", [])][:max_nodes - len(vals)]
    for n in vals + banks:
        run(base + ["logs", "--no-color", "--tail", str(tail), n])
    # a node can answer 500 while its container is still up: keep every node's log and extract the tracebacks
    try:
        r = subprocess.run(base + ["logs", "--no-color"], capture_output=True, text=True, timeout=300)
        full = r.stdout + r.stderr
        with open(os.path.join(out, "docker_logs_full.txt"), "w") as f:
            f.write(full)
        lines = full.splitlines()
        hits = [i for i, ln in enumerate(lines) if "Traceback" in ln or "Exception" in ln or " 500 " in ln]
        shown, seen = [], set()
        for i in hits:
            if i in seen:
                continue
            blk = range(max(0, i - 2), min(len(lines), i + 18))
            seen.update(blk)
            shown.append("\n".join(lines[j] for j in blk))
            if len(shown) >= 8:
                break
        import re
        from collections import Counter
        pat = re.compile(r"^(\S+?)-\d+\s+\|\s+((?:[\w.]+\.)?\w*(?:Error|Exception|Unreachable|Timeout)\b.*)$")
        summ = Counter()
        for ln in lines:
            m = pat.match(ln)
            if m:
                summ[m.group(2)[:160]] += 1
        head = "\n".join(f"{n:5d} x {msg}" for msg, n in summ.most_common(15)) or "(no exception lines found)"
        parts.insert(0, "$ exception summary (the last line of each Traceback, counted)\n" + head)
        parts.append(f"$ node errors ({len(hits)} matching lines; full log in docker_logs_full.txt)\n" + "\n...\n".join(shown))
    except (OSError, subprocess.SubprocessError) as ex:
        parts.append(f"$ full node logs\n(could not run: {ex})")
    text = "\n\n".join(parts)
    try:
        with open(os.path.join(out, "diagnostics.txt"), "w") as f:
            f.write(text)
    except OSError:
        pass
    print("---- docker diagnostics ----\n" + text[:3000] + "\n[...]\n" + text[-9000:] + "\n---- end diagnostics ----", flush=True)


def run_docker(a, topo):
    """Build the image, start one container per node, run the driver inside the network, collect, tear down."""
    import shutil
    import subprocess
    from .dockergen import compose
    from .runtime import ROOT
    if not (shutil.which("docker") and subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0):
        print("docker and docker compose are required for --runtime docker", file=sys.stderr)
        return None
    out = os.path.abspath(a.dir)
    os.makedirs(os.path.join(out, "topo"), exist_ok=True)
    T.save(topo, os.path.join(out, "topo", "topology.json"))
    path = compose(topo, out, payments=a.payments, workers=a.workers, seed=str(a.seed))
    base = ["docker", "compose", "-p", "sealed-trail", "-f", path]
    steps = [["docker", "build", "-f", os.path.join(out, "Dockerfile"), "-t", "sealed-trail:latest", str(ROOT)],
             base + ["up", "-d", "--no-build"] + [n for n in topo["nodes"]]]
    for cmd in steps:
        print("$", " ".join(cmd), flush=True)
        if subprocess.run(cmd).returncode != 0:
            subprocess.run(base + ["down", "-v", "--remove-orphans"])
            raise SystemExit("docker step failed: " + " ".join(cmd[:3]))
    t0 = time.time()
    rc = subprocess.run(base + ["--profile", "drive", "run", "--rm", "driver"]).returncode
    files = sorted(os.listdir(os.path.join(out, "out")))
    failed = rc not in (0, 1) or not files
    if failed:
        # logs are gone after `down -v`
        _docker_diagnostics(base, topo, out)
    if not a.keep:
        subprocess.run(base + ["down", "-v", "--remove-orphans"])
    if failed:
        raise SystemExit(f"driver failed (rc={rc}); node state and log tails saved to {os.path.join(out, 'diagnostics.txt')} (printed above)")
    res = json.load(open(os.path.join(out, "out", files[-1])))
    res["driver_s"] = round(time.time() - t0, 1)
    return res


def cmd_drive(a):
    """Run the workload against an already running network (inside the compose network, or on the host)."""
    import httpx
    from concurrent.futures import ThreadPoolExecutor
    from .driver import HttpDriver, run_workload
    topo = T.load(a.topology)
    deadline = time.time() + a.wait

    def ready(nid):
        url = topo["nodes"][nid]["url"] + "/health"
        while time.time() < deadline:
            try:
                if httpx.get(url, timeout=3.0).status_code == 200:
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(1.0)
        return nid
    with ThreadPoolExecutor(max_workers=32) as ex:
        bad = [r for r in ex.map(ready, list(topo["nodes"])) if r is not True]
    if bad:
        print(f"nodes not ready after {a.wait}s: {bad[:10]}{' ...' if len(bad) > 10 else ''}", file=sys.stderr)
        return 3
    banks = len(topo["banks"])
    drv = HttpDriver(topo)
    seed = int(a.seed) if str(a.seed).isdigit() else 1
    res = run_workload(drv, banks, topo["accounts_per_bank"], a.payments, seed, workers=a.workers)
    drv.close()
    res.update({"runtime": topo.get("runtime", "?"), "validators": len(topo["validators"]), "byzantine": topo["params"]["f"],
                "q": T.params_of(topo).q, "seed": a.seed, "nodes": len(topo["nodes"])})
    os.makedirs(a.out, exist_ok=True)
    fn = os.path.join(a.out, f"run-{res['runtime']}-{banks}b-{topo['accounts_per_bank']}a-{len(topo['validators'])}v.json")
    json.dump(res, open(fn, "w"), indent=1)
    print(json.dumps(res, indent=1))
    return 0 if not res["monitor_violations"] and res["reconciled_all_banks"] else 1


def cmd_compose(a):
    from .dockergen import compose
    a.runtime = "docker"
    topo = topo_from(a)
    out = os.path.abspath(a.dir)
    os.makedirs(os.path.join(out, "topo"), exist_ok=True)
    T.save(topo, os.path.join(out, "topo", "topology.json"))
    path = compose(topo, out, seed=str(a.seed))
    print("wrote", path, f"({len(topo['nodes'])} nodes + driver)")
    print("easiest: python3 -m sealedtrail.nodes.stctl run --runtime docker  (same flags)  # builds, starts, drives, tears down")
    print("manual:  docker build -f", os.path.join(out, "Dockerfile"), "-t sealed-trail:latest .   # from the repo root")
    print("         docker compose -p sealed-trail -f", path, "up -d")
    print("         docker compose -p sealed-trail -f", path, "--profile drive run --rm driver")
    return 0


def cmd_up(a):
    from .runtime import LocalRuntime
    topo = topo_from(a)
    rt = LocalRuntime(os.path.abspath(a.dir), topo)
    rt.up()
    print(f"{len(topo['nodes'])} nodes up; topology at {rt.topo_path}; pids in {a.dir}/pids.json")
    print("stop with: python -m sealedtrail.nodes.stctl down --dir", a.dir)
    # keep processes alive after this command returns
    for p in rt.procs.values():
        pass
    return 0


def cmd_down(a):
    import signal
    p = os.path.join(a.dir, "pids.json")
    if not os.path.exists(p):
        print("no pids.json")
        return 1
    for nid, pid in json.load(open(p)).items():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    os.remove(p)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="stctl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    add_flags(r)
    r.add_argument("--payments", type=int, default=20)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--keep", action="store_true")
    r.set_defaults(fn=cmd_run)
    c = sub.add_parser("compose")
    add_flags(c)
    c.set_defaults(fn=cmd_compose)
    u = sub.add_parser("up")
    add_flags(u)
    u.set_defaults(fn=cmd_up)
    dr = sub.add_parser("drive")
    dr.add_argument("--topology", required=True)
    dr.add_argument("--payments", type=int, default=60)
    dr.add_argument("--workers", type=int, default=8)
    dr.add_argument("--wait", type=int, default=600)
    dr.add_argument("--seed", default="1")
    dr.add_argument("--out", default="out")
    dr.set_defaults(fn=cmd_drive)
    d = sub.add_parser("down")
    d.add_argument("--dir", default="run")
    d.set_defaults(fn=cmd_down)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
