"""Topology generation: one node per bank, validator, TSA, NA signer, TIV (spec 2.4).

Node keys are derived from a master seed so a topology file holds only public keys and
URLs. TEST-ONLY: a real deployment runs a key ceremony instead (spec 11.1).
"""
from __future__ import annotations

import json
from dataclasses import asdict

from .. import crypto as C
from ..params import Params
from ..trust import Trust


def derive_seed(master: str, node_id: str) -> bytes:
    return C.sha256(b"st/seed/v1", master.encode(), node_id.encode())


def keypair(master: str, node_id: str) -> C.KeyPair:
    return C.KeyPair(derive_seed(master, node_id))


def bank_id(i: int) -> str:
    return f"bank-{i:04d}"


def acct_id(i: int, j: int) -> str:
    return f"acct-{i:04d}-{j:04d}"


def make_topology(*, runtime: str = "local", banks: int = 3, accounts_per_bank: int = 2,
                  validators: int = 4, byzantine: int = 1, na_signers: int = 5, na_threshold: int = 3,
                  tsa: int = 3, tsa_threshold: int = 2, tivs: int = 1, seed: str = "1",
                  base_port: int = 9000, host: str = "127.0.0.1", params: dict | None = None) -> dict:
    P = Params(k=validators, f=byzantine, n_tsa=tsa, m_tsa=tsa_threshold, na_n=na_signers, na_tau=na_threshold,
               **(params or {}))
    nodes: dict = {}

    def add(role: str, nid: str, port: int):
        url = f"http://{nid}:8000" if runtime == "docker" else f"http://{host}:{port}"
        nodes[nid] = {"role": role, "url": url, "pk": keypair(seed, nid).pk.hex()}

    add("na", "na", base_port + 1)
    for i in range(tsa):
        add("tsa", f"tsa-{i}", base_port + 10 + i)
    for i in range(tivs):
        add("tiv", f"tiv-{i}", base_port + 30 + i)
    for i in range(validators):
        add("validator", f"val-{i:02d}", base_port + 100 + i)
    for i in range(banks):
        add("bank", bank_id(i), base_port + 1000 + i)
    d = asdict(P)
    d["omega"] = dict(P.omega)
    return {"runtime": runtime, "seed": seed, "params": d, "nodes": nodes,
            "banks": [bank_id(i) for i in range(banks)], "accounts_per_bank": accounts_per_bank,
            "validators": [f"val-{i:02d}" for i in range(validators)],
            "notes": "na_signers/na_threshold recorded; prototype NA is a single key (FROST not built)"}


def save(topo: dict, path: str):
    with open(path, "w") as f:
        json.dump(topo, f, indent=1)


def load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def params_of(topo: dict) -> Params:
    d = dict(topo["params"])
    d["theta"] = tuple(d["theta"])
    d["theta_o"] = tuple(d["theta_o"])
    return Params(**d)


def trust_of(topo: dict) -> Trust:
    pk = lambda role: {i: bytes.fromhex(n["pk"]) for i, n in topo["nodes"].items() if n["role"] == role}
    return Trust(na_pk=bytes.fromhex(topo["nodes"]["na"]["pk"]), tsa_pks=pk("tsa"), tiv_pks=pk("tiv"),
                 validator_pks=pk("validator"), bank_pks=pk("bank"))
