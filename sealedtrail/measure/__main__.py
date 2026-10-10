import argparse
import sys
from . import runs, runs2

ALL = {"proof": runs.proof_sizes, "quorum": runs.quorum_latency, "gamma": runs.gamma_vs_eta, "cone": runs.cone_size,
       "hold": runs.hold_sets, "partition": runs.partition_availability,
       "mass": runs2.mass_trace, "recovery": runs2.recovery_vs_refusal, "unresolved": runs2.unresolved_vs_depth,
       "opening": runs2.opening_cost, "invariants": runs2.invariants,
       "capacity": runs2.validator_capacity}

ap = argparse.ArgumentParser(prog="python -m sealedtrail.measure")
ap.add_argument("which", choices=list(ALL) + ["all"])
ap.add_argument("--out", default="results/measure")
a = ap.parse_args()
for name in (list(ALL) if a.which == "all" else [a.which]):
    r = ALL[name](a.out)
    print(f"{name}: wrote bundle ->", r if r is not None and not isinstance(r, (list, tuple, dict)) else a.out)
