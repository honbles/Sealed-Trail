"""Results bundles (spec 10.4): raw data, config, seed, source hash, plot and an explicit statement of
what the number does NOT show. Every plot prints the runtime and hardware."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def src_hash() -> str:
    h = hashlib.sha256()
    for p in sorted(list((ROOT / "sealedtrail").rglob("*.py")) + [ROOT / "crypto" / "src" / "lib.rs"]):
        if "__pycache__" not in p.parts and p.exists():
            h.update(p.relative_to(ROOT).as_posix().encode()); h.update(p.read_bytes())
    return h.hexdigest()


def env() -> dict:
    mem = 0
    try:
        mem = int(next(l for l in open("/proc/meminfo") if l.startswith("MemTotal")).split()[1]) // 1024
    except Exception:
        pass
    return {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "cpus": os.cpu_count(), "ram_mb": mem, "src_hash": src_hash(), "date": time.strftime("%Y-%m-%d %H:%M:%S")}


class Bundle:
    def __init__(self, name: str, title: str, config: dict, seed: int, measures: str, not_shown: list,
                 runtime: str = "inproc", out: str | Path = "results/measure"):
        self.name, self.title, self.config, self.seed = name, title, config, seed
        self.measures, self.not_shown, self.runtime = measures, not_shown, runtime
        self.dir = Path(out) / name

    def write(self, rows: list, plot=None, extra: dict | None = None) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        e = env()
        keys = []
        for r in rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        with open(self.dir / "data.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)
        meta = {"name": self.name, "title": self.title, "config": self.config, "seed": self.seed,
                "runtime": self.runtime, "env": e, "measures": self.measures, "does_not_show": self.not_shown}
        (self.dir / "data.json").write_text(json.dumps({**meta, "rows": rows, "extra": extra or {}}, indent=1, default=str))
        if plot is not None:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig = plot(plt, rows, extra or {})
            foot = f"runtime={self.runtime} | {e['cpus']} cpu, {e['ram_mb']} MB | python {e['python']} | src {e['src_hash'][:8]} | seed {self.seed}"
            fig.text(0.5, 0.003, foot, ha="center", fontsize=7, color="gray")
            fig.savefig(self.dir / "plot.png", dpi=130, bbox_inches="tight")
            plt.close(fig)
        lines = [f"# {self.title}", "", f"**Measures:** {self.measures}", "", f"**Runtime:** {self.runtime}; seed {self.seed}; "
                 f"{e['cpus']} cpu / {e['ram_mb']} MB; source hash `{e['src_hash'][:12]}`; {e['date']}", "",
                 f"**Config:** `{json.dumps(self.config)}`", "", "## What this does not show", ""]
        lines += [f"- {x}" for x in self.not_shown]
        lines += ["", "## First rows", "", "| " + " | ".join(keys) + " |", "|" + "---|" * len(keys)]
        for r in rows[:12]:
            lines.append("| " + " | ".join(f"{r.get(k, '')}" if not isinstance(r.get(k), float) else f"{r[k]:.4g}" for k in keys) + " |")
        (self.dir / "README.md").write_text("\n".join(lines) + "\n")
        return self.dir
