# Certified-share hold (paper: Section on reversal, Supplement S4 and S7)

A hold that keeps only a reserve `rho_bar * residual` of each cone entry, where `rho_bar` is a public upper bound certified by a range
proof against the commitments already on the ledger (no amount is opened). Reversal amounts still need the Phase 2 openings.

| What | Where |
|---|---|
| Certificate and reserve proofs (Bulletproofs) | `sealedtrail/sharecert.py`, tests in `tests/test_sharecert.py` |
| Measurement 14 (structure only) | `python3 -m sealedtrail.measure.sharehold --events 1000000 --per-band 2 --k 20,24,32 --rho-min 0,1e-6,1e-5` |
| Coarse logarithmic grid | `python3 -m sealedtrail.measure.sharehold --events 100000 --grid log --k 1,2,4,8,16 --rho-min 0` |
| Certificate cost | `python3 scripts/bench_certs.py` |
| Bundles used in the paper | `results/certified_hold/m14_*`, `results/certified_hold/certs_bench.json` |
| One-command run | `scripts/run_all_findings.py` steps `sharehold_quick`, `sharehold_full`, `sharehold_max`, `sharehold_log` |

Not implemented: the validators' Phase 0 narrowing, the certificate log, the reserve check at spend and the updated rho.
