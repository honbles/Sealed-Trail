#!/usr/bin/env python3
"""Run the test suite, every measurement, the local and Docker clusters, the concurrency ramp and the long-history runs,
and pack the results into one archive.

    python3 scripts/run_all_findings.py --profile smoke      # about 2 min: checks the setup
    python3 scripts/run_all_findings.py --profile quick      # tests, all measurements, 5 and 10 bank clusters
    python3 scripts/run_all_findings.py --profile full       # adds 20 and 50 bank clusters, the ramp, the 10^6 long-history run
    python3 scripts/run_all_findings.py --profile max --docker --docker-banks 100   # adds 100 banks, 10^7 events, the Docker run

A failing step never stops the run: every step is recorded as ok, fail or skipped, with its log, in manifest.json.
Needs Python >= 3.10, Rust >= 1.75 and the packages in requirements.txt (installed unless --skip-install).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
MB_PER_NODE = 70
PROFILES = {
    "smoke": dict(tests=False, measure=["proof"], ladder=[3], ramp=[], longhist=[], sharehold=[]),
    "quick": dict(tests=True, measure="all", ladder=[5, 10], ramp=[], longhist=["quick"], sharehold=["quick"]),
    "full":  dict(tests=True, measure="all", ladder=[5, 10, 20, 50], ramp=[4, 8, 16, 32, 64], longhist=["full"], sharehold=["quick", "full"]),
    "max":   dict(tests=True, measure="all", ladder=[5, 10, 20, 50, 100], ramp=[4, 8, 16, 32, 64], longhist=["full", "sens", "max"], sharehold=["quick", "full", "max", "log"]),
}
LONGHIST_TIMEOUT = {"quick": 900, "full": 3600, "sens": 5400, "max": 14400}
SHAREHOLD = {   # measurement 14: certified-share hold (args, timeout s)
    "quick": (["--events", "100000", "--per-band", "3", "--k", "12,16,20,24", "--rho-min", "0,1e-6,1e-5,1e-4,1e-3"], 1800),
    "full": (["--events", "1000000", "--per-band", "2", "--k", "20,24,32", "--rho-min", "0,1e-6,1e-5"], 3600),
    "max": (["--events", "10000000", "--per-band", "1", "--k", "24", "--rho-min", "0"], 7200),
    "log": (["--events", "100000", "--per-band", "3", "--grid", "log", "--k", "1,2,4,8,16", "--rho-min", "0"], 1800),
}


def sh(cmd: list, log: Path, timeout: int, cwd: Path = ROOT, env: dict | None = None) -> tuple[int, float]:
    t = time.time()
    with open(log, "w") as f:
        f.write("$ " + " ".join(map(str, cmd)) + "\n")
        f.flush()
        try:
            p = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT, timeout=timeout, env=env)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            f.write(f"\n[TIMEOUT after {timeout}s]\n")
            rc = 124
        except FileNotFoundError as e:
            f.write(f"\n[NOT FOUND] {e}\n")
            rc = 127
    return rc, time.time() - t


def out1(cmd) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return ""


def mem_mb() -> tuple[int, int]:
    total = avail = 0
    try:
        for l in open("/proc/meminfo"):
            if l.startswith("MemTotal"):
                total = int(l.split()[1]) // 1024
            if l.startswith("MemAvailable"):
                avail = int(l.split()[1]) // 1024
    except Exception:
        pass
    return total, avail


def src_hash() -> str:
    h = hashlib.sha256()
    for p in sorted(list((ROOT / "sealedtrail").rglob("*.py")) + [ROOT / "crypto" / "src" / "lib.rs"]):
        if "__pycache__" not in p.parts and p.exists():
            h.update(p.relative_to(ROOT).as_posix().encode()); h.update(p.read_bytes())
    return h.hexdigest()


def environment() -> dict:
    tot, av = mem_mb()
    git = out1(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    return {"date": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "host": socket.gethostname(), "platform": platform.platform(),
            "machine": platform.machine(), "cpus": os.cpu_count(), "ram_mb": tot, "ram_available_mb": av,
            "python": sys.version.split()[0], "cargo": out1(["cargo", "--version"]), "rustc": out1(["rustc", "--version"]),
            "docker": out1(["docker", "--version"]), "docker_compose": out1(["docker", "compose", "version"]),
            "git_sha": git if re.fullmatch(r"[0-9a-f]{40}", git or "") else None, "src_hash": src_hash()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", choices=list(PROFILES), default="quick")
    ap.add_argument("--out", default=None, help="output directory (default: findings-<host>-<time>)")
    ap.add_argument("--docker", action="store_true", help="also try the Docker runtime (best effort, if docker is installed)")
    ap.add_argument("--docker-banks", type=int, default=10, help="bank count for the Docker run (use 100 for the full run)")
    ap.add_argument("--skip-install", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--only", default="", help="comma list of step names to run (see --dry-run)")
    ap.add_argument("--timeout-scale", type=float, default=1.0, help="multiply every timeout (use 2-3 on a slow machine)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    a = ap.parse_args()
    prof = PROFILES[a.profile]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = Path(a.out or f"findings-{socket.gethostname()}-{stamp}").resolve()
    logs = out / "logs"
    ts = a.timeout_scale

    src = (ROOT / "sealedtrail" / "measure" / "__main__.py").read_text()
    reg = re.findall(r'"(\w+)":\s*runs2?\.\w+', src)
    measures = reg if prof["measure"] == "all" else prof["measure"]

    steps = []                                               # (name, kind, payload, timeout)
    if not a.skip_install:
        steps.append(("install", "cmd", [PY, "-m", "pip", "install", "-q", "-r", "requirements.txt", "--break-system-packages"], 600))
    steps.append(("crypto_build", "cmd", ["cargo", "build", "--release", "--locked", "--manifest-path", "crypto/Cargo.toml"], 1500))
    if prof["tests"] and not a.skip_tests:
        steps.append(("tests_inproc", "cmd", [PY, "-m", "pytest", "tests", "-q", "--ignore=tests/test_nodes.py",
                                              f"--junitxml={out}/tests_inproc.xml"], 1800))
        steps.append(("tests_http_nodes", "cmd", [PY, "-m", "pytest", "tests/test_nodes.py", "-q", f"--junitxml={out}/tests_http.xml"], 900))
    for m in measures:
        steps.append((f"measure_{m}", "cmd", [PY, "-m", "sealedtrail.measure", m, "--out", str(out / "measurements")], 1500))
    for i, n in enumerate(prof["ladder"]):
        steps.append((f"cluster_local_{n}banks", "cluster", (n, 21000 + 400 * i, 4, min(200, max(30, n * 3))), 3000))
    for j, w in enumerate(prof["ramp"]):                    # same cluster, more concurrent drivers: where does throughput stop rising?
        steps.append((f"ramp_w{w}", "cluster", (20, 31000 + 400 * j, w, 400), 1800))
    if a.docker:
        steps.append(("cluster_docker", "docker", None, 3600))
    for p in prof["longhist"]:                              # last: the long runs must not hold up the cheap, essential steps
        steps.append((f"longhist_{p}", "cmd", [PY, "-m", "sealedtrail.measure.longhist", "--profile", p, "--out", str(out / "measurements")],
                      LONGHIST_TIMEOUT[p]))
    for p in prof.get("sharehold", []):
        args, tmo = SHAREHOLD[p]
        steps.append((f"sharehold_{p}", "cmd", [PY, "-m", "sealedtrail.measure.sharehold", *args, "--out", str(out / "measurements")], tmo))
    only = {s for s in a.only.split(",") if s}
    if only:
        steps = [s for s in steps if s[0] in only]

    print(f"profile={a.profile}  steps={len(steps)}  out={out}")
    for s in steps:
        print("  -", s[0])
    if a.dry_run:
        return
    logs.mkdir(parents=True, exist_ok=True)
    env_info = environment()
    (out / "env.json").write_text(json.dumps(env_info, indent=1))
    print(f"machine: {env_info['cpus']} cpu, {env_info['ram_mb']} MB ({env_info['ram_available_mb']} available), cargo={bool(env_info['cargo'])}, docker={bool(env_info['docker'])}")

    manifest = []
    (ROOT / "results").mkdir(exist_ok=True)

    def _snap():
        # path -> mtime_ns, so a rerun that overwrites an existing result file still counts as new output
        return {f: os.stat(f).st_mtime_ns for f in glob.glob(str(ROOT / "results" / "run-*.json"))}

    def _changed(before):
        now = _snap()
        return sorted(f for f, m in now.items() if before.get(f) != m)

    def record(name, status, secs=0.0, rc=None, note=""):
        manifest.append({"step": name, "status": status, "seconds": round(secs, 1), "returncode": rc, "note": note,
                         "log": f"logs/{name}.log"})
        print(f"[{status:7s}] {name:28s} {secs:7.1f}s  {note}")

    for name, kind, payload, timeout in steps:
        log = logs / f"{name}.log"
        timeout = int(timeout * ts)
        if kind == "cmd":
            if name == "crypto_build" and not shutil.which("cargo"):
                record(name, "fail", 0, 127, "cargo not found: install Rust >= 1.75 (https://rustup.rs) and rerun"); continue
            rc, secs = sh(payload, log, timeout)
            record(name, "ok" if rc == 0 else "fail", secs, rc)
        elif kind == "cluster":
            banks, port, workers, payments = payload
            need = (banks + 7 + 5) * MB_PER_NODE
            total, avail = mem_mb()
            if avail and need > avail * 0.85:
                record(name, "skipped", 0, None, f"needs about {need} MB, only {avail} MB available"); continue
            before = _snap()
            work = out / "work" / name
            rc, secs = sh([PY, "-m", "sealedtrail.nodes.stctl", "run", "--runtime", "local", "--banks", str(banks),
                           "--accounts-per-bank", "2", "--validators", "7", "--payments", str(payments),
                           "--workers", str(workers), "--dir", str(work), "--base-port", str(port)], log, timeout)
            new = _changed(before)
            (out / "results").mkdir(exist_ok=True)
            for f in new:
                shutil.copy(f, out / "results" / f"{name}__{Path(f).name}")
            record(name, "ok" if rc == 0 and new else "fail", secs, rc, f"{len(new)} result file(s)")
            shutil.rmtree(work, ignore_errors=True)
        elif kind == "docker":
            if not env_info["docker"] or not env_info["docker_compose"]:
                record(name, "skipped", 0, None, "docker / docker compose not found"); continue
            nb = a.docker_banks
            need = (nb + 7 + 6) * MB_PER_NODE
            total, avail = mem_mb()
            if avail and need > avail * 0.85:
                record(name, "skipped", 0, None, f"needs about {need} MB, only {avail} MB available"); continue
            before = _snap()
            work = out / "work" / "docker"
            rc, secs = sh([PY, "-m", "sealedtrail.nodes.stctl", "run", "--runtime", "docker", "--banks", str(nb),
                           "--accounts-per-bank", "2", "--validators", "7", "--byzantine", "2",
                           "--payments", str(min(300, max(60, nb * 3))), "--workers", "8", "--dir", str(work)], log, timeout)
            new = _changed(before)
            (out / "results").mkdir(exist_ok=True)
            for f in new:
                shutil.copy(f, out / "results" / f"{name}__{Path(f).name}")
            record(name, "ok" if rc == 0 and new else "fail", secs, rc, f"{nb} banks; {len(new)} result file(s)")
            shutil.rmtree(work, ignore_errors=True)

    # test counts from junit
    tests = {}
    for x in ("tests_inproc", "tests_http"):
        p = out / f"{x}.xml"
        if p.exists():
            t = p.read_text()
            m = re.search(r'tests="(\d+)"', t); fl = re.search(r'failures="(\d+)"', t); er = re.search(r'errors="(\d+)"', t); sk = re.search(r'skipped="(\d+)"', t)
            tests[x] = {"tests": int(m.group(1)) if m else None, "failures": int(fl.group(1)) if fl else None,
                        "errors": int(er.group(1)) if er else None, "skipped": int(sk.group(1)) if sk else None}
    (out / "manifest.json").write_text(json.dumps({"profile": a.profile, "env": env_info, "tests": tests, "steps": manifest}, indent=1))
    ok = sum(1 for m in manifest if m["status"] == "ok")
    fail = [m["step"] for m in manifest if m["status"] == "fail"]
    skipped = [m["step"] for m in manifest if m["status"] == "skipped"]
    (out / "SUMMARY.txt").write_text(
        f"profile={a.profile} host={env_info['host']} cpus={env_info['cpus']} ram={env_info['ram_mb']}MB\n"
        f"steps ok={ok} failed={fail} skipped={skipped}\ntests={tests}\n")
    z = Path(str(out) + ".zip")
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in out.rglob("*"):
            if p.is_file() and "work" not in p.relative_to(out).parts:
                zf.write(p, p.relative_to(out.parent))
    print(f"\n{ok}/{len(manifest)} steps ok; failed={fail}; skipped={skipped}")
    print(f"Findings archive: {z}  ({z.stat().st_size // 1024} KB)")
    sys.exit(0)


if __name__ == "__main__":
    main()
