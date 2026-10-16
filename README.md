# Sealed Trail

Reference prototype of Sealed Trail, a provenance network for bank payments. It implements a committed-entry, debit-only ledger
(Pedersen commitments, aggregated Bulletproof range proofs over Ristretto255), quorum-certified finality with per-key locks,
taint-mass accounting with pro-rata fractions, cone construction, holds, openings, reversal and the monitors that check the
invariants. It runs in three modes: in-process, one local process per node over HTTP, and one Docker container per node.

This is research code. It has had no external cryptographic review.

## Contents

| Path | What it is |
|---|---|
| `crypto/` | Rust crypto core (`st-crypto`), built once into `libst_crypto.so` and called through `ctypes` |
| `sealedtrail/` | Protocol layer: events, validator, bank, taint engine, reversal, monitors, simulated cluster |
| `sealedtrail/nodes/` | HTTP node servers, topology, driver, Docker Compose generator, `stctl` command line |
| `sealedtrail/measure/` | Measurements (`python -m sealedtrail.measure`) and the long-history model (`longhist.py`) |
| `scripts/run_all_findings.py` | One command that runs tests, measurements, clusters and long-history runs and packs the results |
| `tests/` | Test suite |
| `docs/SPEC.md` | Design spec and decision log (D1 to D33) that comments in the code refer to |

## Requirements

- Python 3.10 or newer
- Rust 1.75 or newer (`cargo`), from https://rustup.rs
- Docker 24 or newer with Compose v2, only for the Docker run
- About 70 MB of RAM per node (a 100-bank cluster needs roughly 8 GB), and about 4 GB for the 10^7-event long-history run

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
(cd crypto && cargo build --release --locked)     # produces crypto/target/release/libst_crypto.so
```

`ST_CRYPTO_LIB` can point to the shared library if it lives elsewhere.

## Tests

```bash
python3 -m pytest tests -q -m "not nodes"          # in-process tests, a few minutes
python3 -m pytest tests/test_nodes.py -q           # multi-process HTTP tests
```

## Running a network

`stctl` starts a network, runs a payment workload against it and prints throughput, latency percentiles, monitor violations and
whether every bank reconciles.

```bash
python3 -m sealedtrail.nodes.stctl run --runtime inproc --banks 20 --accounts-per-bank 10 --validators 7 --byzantine 2
python3 -m sealedtrail.nodes.stctl run --runtime local  --banks 10 --accounts-per-bank 2  --validators 7 --byzantine 2 --payments 300 --workers 8
```

`--validators k` and `--byzantine f` must satisfy k >= 3f + 1; the quorum is q = ceil((k + f + 1) / 2). Other options: `--tsa`,
`--na-signers`, `--tivs`, `--seed`, `--base-port`, `--dir`, `--keep`. The `Makefile` wraps the common cases (`make run-local BANKS=10`).

### Docker

One container per node (for 100 banks: 100 banks, 7 validators, 3 time-stamp authorities, 1 NA, 1 TIV) plus a short-lived driver
container that runs the workload inside the Docker network, so no host ports are needed.

```bash
python3 -m sealedtrail.nodes.stctl run --runtime docker --banks 100 --accounts-per-bank 2 \
        --validators 7 --byzantine 2 --payments 300 --workers 8 --dir run-docker100
```

The first run builds the image (a few minutes). Run Docker without `sudo`: add yourself to the `docker` group
(`sudo usermod -aG docker $USER`, then `newgrp docker`). On failure the node logs are saved to `diagnostics.txt` in the output
directory before the containers are removed. `--keep` leaves the containers running (`docker compose -p sealed-trail down -v`
removes them). Start with `--banks 20` if unsure about the host's capacity: 100 containers on one machine are CPU-bound, so
throughput there says little about the protocol.

## Measurements and findings

```bash
python3 scripts/run_all_findings.py --profile smoke                                # about 2 min, checks the setup
python3 scripts/run_all_findings.py --profile quick                                # tests, all measurements, 5 and 10 bank clusters
python3 scripts/run_all_findings.py --profile full                                 # adds 20 and 50 banks, the concurrency ramp, 10^6-event long history
python3 scripts/run_all_findings.py --profile max --docker --docker-banks 100      # adds 100 banks, 10^7 events, the Docker run
```

On an 8-CPU, 32 GB machine `max` took about 35 minutes plus about 8 minutes for the 100-bank Docker run. Useful options:
`--only step,step` runs selected steps (`--dry-run` lists the names), `--timeout-scale 3` for slow machines, `--skip-install`,
`--skip-tests`, `--out DIR`. A failing step never stops the run; each step is recorded as ok, fail or skipped in `manifest.json`
with its log. The last line printed is the path of the findings archive (`findings-<host>-<time>.zip`).

The archive holds `manifest.json`, `env.json` (machine, versions, source hash), `SUMMARY.txt`, `tests_*.xml`, `logs/`,
`results/` (one JSON per cluster run) and `measurements/` (one directory per measurement with `README.md`, `data.csv`,
`data.json` and `plot.png`; each README lists what the measurement does not show).

| Measurement | Command | What it measures |
|---|---|---|
| m1 | `proof` | proof sizes |
| m2, m3 | `quorum` | quorum latency, certificate size |
| m4 | `gamma` | gamma against eta |
| m6 | `cone` | cone size |
| m7 | `opening` | opening cost |
| m8 | `unresolved` | Unresolved against refuser depth |
| m9 | `hold` | hold sets |
| m10 | `invariants` | continuous invariant checks |
| m12 | `partition` | availability under partition |
| f10, f11 | `mass`, `recovery` | mass trace, recovery against refusing banks |
| m13 | `python -m sealedtrail.measure.longhist` | cone and hold on long, skewed histories |
| m14 | `python -m sealedtrail.measure.sharehold` | share-bounded hold from certified taint bounds (`sealedtrail/sharecert.py` has the proofs) |
| m14 | `capacity` | per-validator capacity |

Individual measurements: `python3 -m sealedtrail.measure <command> [--out DIR]` (`all` runs everything).

### Concurrency ramp

`ramp_w4` to `ramp_w64` drive one 20-bank local cluster with 4 to 64 concurrent workers. Latency grows with the worker count once
throughput stops rising, so throughput is workers divided by latency below the plateau and is not a capacity figure by itself.

### Per-validator capacity (m14)

Each validator holds one writer lock around `request_lock` and `finalize`, so a validator is serial. `capacity` times the lock
and finalize phases for single-parent and multi-parent events, gives the serial ceiling in events per second, and models the rate
if validation ran outside the lock on 1 to 16 cores. The modelled rows are not measurements of a different server.

### Long-history model (m13)

A structure-only generator (Zipf-weighted banks, log-normal amounts, payroll and consolidation events, pro-rata taint, whole-entry
flags) that keeps only parent edges and amounts, so 10^6 events take under 100 MB and 10^7 about 1 GB. It reports cone size, held
entries and value, the mass identity, and an oracle-ordered mass-bounded hold as a bound on what such a hold could achieve.

```bash
python3 -m sealedtrail.measure.longhist --profile quick|full|sens|max [--out DIR] [--zip]
```

Profiles: `quick` 10^5 events; `full` 10^6; `sens` 10^6 with three consolidation mixes; `max` 10^7. It does not model exits,
anchors, refusals, time, the network or cryptography, and the traffic shape is an assumption, not an observation of any market.

## Not implemented

FROST threshold signing for the NA (a single key is used), a Merkle revocation list (an epoch table is used), registry and
G3 services, the HTTP path for flags, reversal and oracles, the Phase 1 temporal walk, and monitors M4 and M11.

## Licence

MIT, see `LICENSE`.
