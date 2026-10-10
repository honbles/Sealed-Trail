"""Custody graph G3 and the compression ratio (paper section 4, Proposition 17; spec 8.2)."""
from __future__ import annotations

from .model import Event, DEB


def gamma(store) -> dict:
    """gamma = |E1| / |E3| = dbar / eta (Proposition 17). N counts network debits (including
    re-homing); E3 holds one tuple per inter-bank *output*. Customer payments inside a bank
    are not events, so eta is the inter-bank share of network debits."""
    e1 = n = e3 = 0
    for _seq, wire, _cert in store.all_events():
        e = Event.from_wire(wire)
        if e.type != DEB:
            continue
        n += 1
        e1 += len(e.parents)
        e3 += sum(1 for o in e.outputs if o.owner != e.issuer)
    dbar = e1 / n if n else 0.0
    eta = e3 / n if n else 0.0
    return {"N": n, "E1": e1, "E3": e3, "dbar": dbar, "eta": eta,
            "gamma": (e1 / e3) if e3 else None, "identity": (dbar / eta) if eta else None}
