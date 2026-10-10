"""Shadow ledger (spec section 11.2): an independent *plaintext* implementation.

It receives each event together with its plaintext amounts through a side channel and
computes balances, residuals and supply with plain integers. It imports only the Event
data classes, never the core validity code or the crypto, and is never present in a
non-test profile.
"""
from __future__ import annotations

from collections import defaultdict

from .model import GEN, ANC, DEB, EXT, REV


class ShadowLedger:
    def __init__(self, omega: dict):
        self.omega = omega
        self.entries: dict = {}              # (eid, j) -> dict(owner, currency, amount, cons[])
        self.supply: dict = defaultdict(int)
        self.violations: list = []
        self.events = 0

    def _bad(self, what, *info):
        self.violations.append((what,) + info)

    def record(self, e, pt: dict):
        self.events += 1
        om = self.omega
        outs, cons = pt["out"], pt["cons"]
        if e.type in (GEN, ANC):
            cur = e.outputs[0].currency
            if outs[0] < om[cur]:
                self._bad("root below floor", e.id)
            self.entries[(e.id, 0)] = dict(owner=e.outputs[0].owner, currency=cur, amount=outs[0], cons=[])
            self.supply[cur] += outs[0]
            return
        cur = e.currency_of()
        for p, c in zip(e.parents, cons):
            ent = self.entries.get(p.key)
            if ent is None:
                self._bad("unknown parent", e.id)
                continue
            if p.v != len(ent["cons"]):
                self._bad("version mismatch", e.id, p.key, p.v, len(ent["cons"]))
            if ent["owner"] != e.issuer:
                self._bad("wrong owner", e.id)
            if c < 0 or c > ent["amount"] - sum(ent["cons"]):
                self._bad("overspend", e.id)
            ent["cons"].append(c)
            res = ent["amount"] - sum(ent["cons"])
            if res != 0 and res < om[ent["currency"]]:
                self._bad("residual below floor", e.id, res)
        if e.type == EXT:
            self.supply[cur] -= sum(cons)
        else:
            if e.intl is not None:                                  # V4: supply moves between currencies
                self.supply[e.intl["s"]] -= sum(cons)
                self.supply[cur] += sum(outs)
            elif sum(outs) != sum(cons):
                self._bad("imbalance", e.id)
            for j, o in enumerate(e.outputs):
                if outs[j] < om[o.currency]:
                    self._bad("output below floor", e.id)
                self.entries[(e.id, j)] = dict(owner=o.owner, currency=o.currency, amount=outs[j], cons=[])

    # queries
    def residual(self, key) -> int:
        e = self.entries[key]
        return e["amount"] - sum(e["cons"])

    def total(self, currency: str) -> int:
        return sum(self.residual(k) for k, v in self.entries.items() if v["currency"] == currency)

    def owned(self, bank: str, currency: str | None = None) -> int:
        return sum(self.residual(k) for k, v in self.entries.items()
                   if v["owner"] == bank and (currency is None or v["currency"] == currency))

    def live(self, currency: str | None = None) -> int:
        return sum(1 for k, v in self.entries.items()
                   if self.residual(k) != 0 and (currency is None or v["currency"] == currency))

    def check(self) -> list:
        """Lemma 5: sum of residuals equals supply, and live entries <= supply / omega."""
        out = list(self.violations)
        for cur, s in self.supply.items():
            if self.total(cur) != s:
                out.append(("supply", cur, self.total(cur), s))
            if self.live(cur) > s // self.omega[cur]:
                out.append(("fragmentation bound", cur))
        return out
