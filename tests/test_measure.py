"""The measurement harness itself: bundles carry their provenance and a 'does not show' statement, and the
numbers obey the identities they are supposed to check (Prop 17, Prop 11, mass bound, cone monotonicity)."""
import json
from collections import defaultdict

import pytest

from sealedtrail.measure import runs


def load(d, name):
    return json.load(open(d / name / "data.json")), (d / name / "README.md").read_text()


def test_bundle_provenance_and_does_not_show(tmp_path):
    runs.proof_sizes(tmp_path, reps=1, grid=(1, 2))
    meta, readme = load(tmp_path, "m1_proof_sizes")
    assert meta["env"]["src_hash"] and meta["seed"] == 1 and meta["runtime"] == "inproc"
    assert "What this does not show" in readme and (tmp_path / "m1_proof_sizes" / "plot.png").exists()
    rows = meta["rows"]
    assert all(r["verify_ms_med"] > 0 and r["proofs_total_B"] > 0 for r in rows)
    by = {(r["P"], r["l"]): r for r in rows}
    assert by[(2, 1)]["proofs_total_B"] > by[(1, 1)]["proofs_total_B"]          # more parents, more proof
    assert by[(1, 1)]["proofs_total_B"] < by[(1, 1)]["paper_est_B"]             # smaller than the paper's estimate


def test_gamma_equals_dbar_over_eta_exactly(tmp_path):
    runs.gamma_vs_eta(tmp_path, N=10, etas=(0.3, 0.6))
    rows = load(tmp_path, "m4_gamma_vs_eta")[0]["rows"]
    live = [r for r in rows if r["gamma_meas"]]
    assert live and all(abs(r["gamma_meas"] - r["gamma_dbar_over_eta"]) < 1e-9 for r in live)     # Prop 17
    assert all(r["E3"] > 0 and r["dbar"] >= 1 for r in live)


def test_partition_availability_matches_proposition_11(tmp_path):
    agg = runs.partition_availability(tmp_path, rounds=8, start=3, end=6)
    ab = load(tmp_path, "m12_partition_availability")[0]["extra"]["abort"]
    freed = {(a["profile"], a["bank"]): a["freed"] for a in ab}
    assert freed[("k5f1", "A")] == 0 and freed[("k5f1", "B")] == 1                  # only the 2-locked side can be freed
    f = {(a["profile"], a["phase"], a["side"]): a["fraction_finalized"] for a in agg}
    for prof, major in runs.SPLITS.items():
        q = {"dev": 5, "k5f1": 4, "k5f0": 3}[prof]
        assert f[(prof, "during", "majority")] == (1.0 if major >= q else 0.0)
        assert f[(prof, "during", "minority")] == 0.0
        assert f[(prof, "before", "majority")] == 1.0
        if prof == "k5f1":
            # q=4 with a 3/2 split: the majority side's failed events locked 3 of 5 keys, leaving 2 free validators
            # (< q) and only 2 non-signers (< k+f-q+1 = 3 needed for an abort proof): stranded after the heal.
            assert f[(prof, "after", "majority")] == 0.0
            assert f[(prof, "after", "minority")] == 1.0                            # 2 locked, 3 non-signers: abort frees it
        else:
            assert f[(prof, "after", "majority")] == f[(prof, "after", "minority")] == 1.0


def test_cone_grows_with_history_and_build_is_correct(tmp_path):
    runs.cone_size(tmp_path, banks=6, snaps=(12, 24, 36))
    meta = load(tmp_path, "m6_cone_size")[0]
    per_root = defaultdict(list)
    for r in sorted(meta["rows"], key=lambda r: r["volume"]):
        per_root[r["root"]].append(r["cone_events"])
    assert all(a <= b for v in per_root.values() for a, b in zip(v, v[1:]))        # cones only grow
    assert all(r["held_entries"] >= 1 and r["cone_events"] >= 1 for r in meta["rows"])


def test_hold_sets_bounds(tmp_path):
    runs.hold_sets(tmp_path, victims=4, steps=12, rates=(0, 50), anchors=8)
    meta = load(tmp_path, "m9_hold_sets")[0]
    for r in meta["rows"]:
        assert r["held_after_tmin"] <= r["held_phase0"]                             # T_min only releases
        assert r["victim_taint_mass"] <= 150 * r["poison_payments"]                 # dilution bounds the mass
        assert r["victim_taint_mass"] + r["attacker_taint_mass"] == r["P_flagged"]  # Thm 14 identity over banks
    aw = meta["extra"]["anchor_window"]
    assert all(a["anchors_held"] <= b["anchors_held"] for a, b in zip(aw, aw[1:]))   # a wider window holds more
    assert all(a["anchors_that_drew_taint"] + a["anchors_behind_tiv_claim"] + a["unrelated_held"] == a["anchors_held"] for a in aw)


def test_quorum_and_cert_bundles(tmp_path):
    rows, certs = runs.quorum_latency(tmp_path, events=3, mc=200, ks=(4, 7))
    assert {r["q"] for r in rows if r["k"] == 7} == {5} and {r["q"] for r in rows if r["k"] == 4} == {3}
    for k in (4, 7):
        r = {x["profile"]: x for x in rows if x["k"] == k}
        assert r["LAN"]["p50_ms"] < r["regional"]["p50_ms"] < r["WAN"]["p50_ms"]
    assert certs[1]["cert_B_mean"] > certs[0]["cert_B_mean"]                        # more validators, bigger Q(e)


def test_validator_capacity_components_and_ceilings(tmp_path):
    from sealedtrail.measure import runs2
    runs2.validator_capacity(tmp_path, events=4, cores=(1, 8))
    meta, readme = load(tmp_path, "m14_validator_capacity")
    rows = meta["rows"]
    assert "does not show" in readme.lower() and meta["runtime"] == "inproc"
    comp = meta["extra"]["components_ms"]
    assert comp and all(c["lock"] > 0 and c["fin"] > 0 and c["val_l"] <= c["lock"] for c in comp.values())
    ceil = {r["parents"]: r["events_per_s"] for r in rows if r["kind"] == "ceiling"}
    mod = {(r["parents"], r["cores"]): r["events_per_s"] for r in rows if r["kind"] == "modelled"}
    for P, serial_rate in ceil.items():
        assert mod[(P, 1)] == pytest.approx(serial_rate, rel=1e-9)             # one core: validation cannot overlap anything
        assert mod[(P, 8)] >= mod[(P, 1)]                                       # more cores never lower the model


def test_harness_plan_includes_ramp_capacity_and_longhist():
    import subprocess
    import sys
    out = subprocess.run([sys.executable, "scripts/run_all_findings.py", "--profile", "full", "--dry-run"], capture_output=True, text=True,
                         cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1])).stdout
    for step in ("measure_capacity", "ramp_w4", "ramp_w64", "longhist_full", "cluster_local_50banks"):
        assert f"- {step}" in out
