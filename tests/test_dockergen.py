"""The Docker path cannot run in CI here, so test what can be tested: the generated files."""
import os

import pytest

yaml = pytest.importorskip("yaml")

from sealedtrail.nodes import topology as T
from sealedtrail.nodes.dockergen import compose, DOCKERFILE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.mark.parametrize("banks", [3, 100])
def test_compose_has_one_service_per_node_plus_driver(tmp_path, banks):
    topo = T.make_topology(runtime="docker", banks=banks, accounts_per_bank=2, validators=7, byzantine=2, seed="d")
    path = compose(topo, str(tmp_path), payments=60, workers=8)
    doc = yaml.safe_load(open(path))
    svc = doc["services"]
    assert set(svc) == set(topo["nodes"]) | {"driver"}
    assert len(topo["nodes"]) == banks + 7 + 3 + 1 + 1                      # banks, validators, tsa, na, tiv
    for nid, n in topo["nodes"].items():
        assert svc[nid]["command"] == ["--role", n["role"], "--id", nid]
        assert "ports" not in svc[nid]                                       # no host ports: 100+ nodes, no collisions
        assert svc[nid]["tmpfs"] == ["/data"]
        assert n["url"] == f"http://{nid}:8000"                              # compose DNS name
    d = svc["driver"]
    assert d["profiles"] == ["drive"] and d["entrypoint"][-1] == "sealedtrail.nodes.stctl"
    assert d["command"][0] == "drive" and "/topo/topology.json" in d["command"]
    assert os.path.isdir(os.path.join(tmp_path, "out"))


def test_dockerfile_uses_the_slim_requirements_and_a_dockerignore_exists():
    assert "requirements-node.txt" in DOCKERFILE and "--locked" in DOCKERFILE
    assert os.path.exists(os.path.join(ROOT, "requirements-node.txt")) and os.path.exists(os.path.join(ROOT, "Cargo.lock")) is False
    assert os.path.exists(os.path.join(ROOT, "crypto", "Cargo.lock"))
    ign = open(os.path.join(ROOT, ".dockerignore")).read().split()
    assert "crypto/target" in ign
    assert "matplotlib" not in open(os.path.join(ROOT, "requirements-node.txt")).read()
