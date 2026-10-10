import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

from sealedtrail.sim import Cluster
from sealedtrail.shadow import ShadowLedger


@pytest.fixture
def cluster():
    sh = ShadowLedger({"NGN": 100, "USD": 100, "EUR": 100})
    c = Cluster("dev", banks=("A", "B", "C"), shadow=sh)
    c.shadow_ledger = sh
    return c
