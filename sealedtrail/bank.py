"""Bank node logic (spec section 3.2): private holdings, customers, payments, delivery.

Customer payments inside one bank are share reassignments and never leave this
object (paper section 2). Network events are built by `builder`, finalized through
the cluster's finality client, and only then applied to local state.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import cbor
from . import crypto as C
from .builder import Holding, build_gen, build_spend, build_anc
from .model import DEB
from .plan import plan_debit, Infeasible


class PaymentFailed(Exception):
    pass


def advice_hash(advice: dict, salt: bytes) -> bytes:
    return C.sha256(b"st/adv/v1", cbor.encode(advice), salt)


@dataclass
class Delivery:
    event_id: bytes
    j: int
    a: int
    r: int
    rho: int = 0                      # taint fraction; 0 until a flag exists
    advice: dict | None = None
    salt: bytes = b""
    sender: str = ""


@dataclass
class Pending:
    built: object
    deliveries: list = field(default_factory=list)   # [(dst, Delivery)]
    debits: list = field(default_factory=list)       # [(account, amount)]


class Bank:
    def __init__(self, name: str, kp: C.KeyPair, cluster):
        self.name, self.kp, self.cluster = name, kp, cluster
        self.P = cluster.P
        self.holdings: dict = {}              # (eid, j) -> Holding (private openings)
        self.customers: dict = {}             # account -> balance (private share map)
        self.busy: set = set()                # entries with a debit in flight
        self.pending: dict = {}               # event id -> Pending (not yet finalized)
        self.openings: dict = {}              # (eid, j) -> (a, r): every event issued or received
        self.rejected: list = []              # deliveries refused by the receiver checks
        self.outbox: list = []                # deliveries not yet reachable: (dst, Delivery)
        self.behavior = "honest"
        self._seq = 0

    # helpers
    def _token(self, eid):
        return self.cluster.token(eid)

    def _epoch(self):
        return self.cluster.trust.epoch_at(self.cluster.clock.now())

    def _register(self, eid, j, owner, currency, a, r, kappa, ttok):
        self._seq += 1
        h = Holding(eid, j, owner, currency, a, r, kappa, [], ttok, self._seq)
        self.holdings[(eid, j)] = h
        self.openings[(eid, j)] = (a, r)
        return h

    def entries(self, currency: str | None = None):
        out = [h for h in self.holdings.values() if (currency is None or h.currency == currency)]
        return sorted(out, key=lambda h: h.seq)

    def owned_total(self, currency: str | None = None) -> int:
        return sum(h.residual()[0] for h in self.entries(currency))

    # onboarding
    def onboard(self, account: str, amount: int, currency: str = "NGN") -> bytes:
        """One GEN per account, backed by an NA reserve attestation (D17)."""
        amax = 10 ** len(str(amount))              # public ceiling; hides the exact amount
        rid, att = self.cluster.na.attest(currency, amax)
        b = build_gen(self.kp, self.name, self.P, currency, amount, rid, amax, att,
                      self._epoch(), self._token)
        res = self.cluster.submit(self.name, b.event, b.plaintext)
        if not res.ok:
            raise PaymentFailed(f"GEN not finalized: {res.reasons}")
        ttok = self.cluster.entry_ttok(self.name, b.event.id)
        self._register(b.event.id, 0, self.name, currency, amount, b.outputs[0][3], b.event.outputs[0].kappa, ttok)
        self.customers[account] = self.customers.get(account, 0) + amount
        return b.event.id

    def anchor(self, account: str, amount: int, currency: str, tiv, clean: int = 0) -> bytes:
        b = build_anc(self.kp, self.name, self.P, currency, amount, tiv, self._epoch(), self._token, clean)
        res = self.cluster.submit(self.name, b.event, b.plaintext)
        if not res.ok:
            raise PaymentFailed(f"ANC not finalized: {res.reasons}")
        ttok = self.cluster.entry_ttok(self.name, b.event.id)
        self._register(b.event.id, 0, self.name, currency, amount, b.outputs[0][3], b.event.outputs[0].kappa, ttok)
        self.customers[account] = self.customers.get(account, 0) + amount
        return b.event.id

    # intra-bank
    def transfer(self, src: str, dst: str, amount: int):
        """Customer payment inside this bank: not a network event, no entry, no version."""
        if self.customers.get(src, 0) < amount:
            raise PaymentFailed("insufficient customer balance")
        self.customers[src] -= amount
        self.customers[dst] = self.customers.get(dst, 0) + amount

    # spending
    def _select(self, currency: str, amount: int):
        held = self.cluster.held_keys(self.name)          # Held entries cannot be locked: never select them
        free = [h for h in self.entries(currency)
                if h.key not in self.busy and h.key not in held and h.residual()[0] > 0]
        take = plan_debit([h.residual()[0] for h in free], amount, self.P.floor(currency))
        return [(h, c) for h, c in zip(free, take) if c > 0]

    def pay(self, src_account: str, dst_bank: str, dst_account: str, amount: int, currency: str = "NGN",
            advice: dict | None = None, deliver: bool = True):
        return self.pay_many(src_account, [(dst_bank, dst_account, amount, advice)], currency, deliver=deliver)

    def pay_many(self, src_account: str, items: list, currency: str = "NGN", deliver: bool = True):
        """One DEB with one output per receiving bank (multi-output, paper section 2).

        items = [(dst_bank, dst_account, amount, advice|None)]. Items to the same bank
        are merged into one output whose advice lists every beneficiary.
        """
        total = sum(i[2] for i in items)
        if self.customers.get(src_account, 0) < total:
            raise PaymentFailed("insufficient customer balance")
        groups: dict = {}
        for dst, acct, amt, adv in items:
            g = groups.setdefault(dst, {"amt": 0, "items": []})
            g["amt"] += amt
            g["items"].append([acct, amt, (adv or {}).get("ref", "")])
        order = list(groups)
        if len(order) > self.P.m_max:
            raise PaymentFailed(f"{len(order)} receiving banks exceed M_max={self.P.m_max}")
        try:
            parents = self._select(currency, total)
        except Infeasible as ex:
            raise PaymentFailed(str(ex))
        advs, salts = [], []
        for dst in order:
            its = groups[dst]["items"]
            if self.behavior == "bad_advice_sum":          # profile: advice does not add up
                its = [list(i) for i in its]
                its[0][1] += 1
            adv = {"items": its, "from": self.name}
            salt = os.urandom(16)
            advs.append(adv)
            salts.append(salt)
        b = build_spend(self.kp, self.name, self.P, currency, parents,
                        [(dst, groups[dst]["amt"]) for dst in order], self._epoch(), self._token,
                        hadv=[advice_hash(a, s) for a, s in zip(advs, salts)])
        for h, _ in parents:
            self.busy.add(h.key)
        dels = []
        for j, dst in enumerate(order):
            a, r = b.outputs[j][2], b.outputs[j][3]
            if self.behavior == "lie_amount":               # profile: announce one amount, commit another
                a += 1
            dels.append((dst, Delivery(b.event.id, j, a, r, 0, advs[j], salts[j], self.name)))
        self.pending[b.event.id] = Pending(b, dels, [(src_account, total)])
        return self._finish(b.event.id, deliver)

    def pay_intl(self, src_account: str, dst_bank: str, dst_account: str, amount: int, src_cur: str,
                 dst_cur: str, rate_doc: dict, deliver: bool = True):
        """International debit (V4): consume `amount` of src_cur, create floor(amount * eps) of dst_cur at
        dst_bank. Tolerance |Ar - eps*As| <= theta*eps*As is proven over the hidden amounts."""
        if self.customers.get(src_account, 0) < amount:
            raise PaymentFailed("insufficient customer balance")
        ar = amount * rate_doc["n"] // rate_doc["d"]
        try:
            parents = self._select(src_cur, amount)
        except Infeasible as ex:
            raise PaymentFailed(str(ex))
        adv = {"items": [[dst_account, ar, ""]], "from": self.name}
        salt = os.urandom(16)
        b = build_spend(self.kp, self.name, self.P, src_cur, parents, [(dst_bank, ar)], self._epoch(), self._token,
                        hadv=[advice_hash(adv, salt)], out_currency=dst_cur, rate_doc=rate_doc)
        for h, _ in parents:
            self.busy.add(h.key)
        a, r = b.outputs[0][2], b.outputs[0][3]
        self.pending[b.event.id] = Pending(b, [(dst_bank, Delivery(b.event.id, 0, a, r, 0, adv, salt, self.name))],
                                           [(src_account, amount)])
        return self._finish(b.event.id, deliver)

    def exit(self, account: str, amount: int, currency: str = "NGN"):
        """EXT: value leaves the network (paper section 4)."""
        parents = self._select(currency, amount)
        b = build_spend(self.kp, self.name, self.P, currency, parents, [], self._epoch(), self._token, exit_=True)
        for h, _ in parents:
            self.busy.add(h.key)
        self.pending[b.event.id] = Pending(b, [], [(account, amount)])
        return self._finish(b.event.id, False)

    def rehome(self, currency: str, amount: int | None = None, split: list | None = None):
        """Re-homing: an ordinary debit whose outputs are all owned by this bank."""
        free = [h for h in self.entries(currency) if h.key not in self.busy and h.residual()[0] > 0]
        amt = amount if amount is not None else sum(h.residual()[0] for h in free)
        parents = self._select(currency, amt)
        outs = [(self.name, a) for a in (split or [amt])]
        b = build_spend(self.kp, self.name, self.P, currency, parents, outs, self._epoch(), self._token)
        for h, _ in parents:
            self.busy.add(h.key)
        self.pending[b.event.id] = Pending(b, [], [])
        return self._finish(b.event.id, False)

    def _finish(self, eid: bytes, deliver: bool):
        """Submit a pending event; on finality apply it locally and deliver openings."""
        pen = self.pending[eid]
        b = pen.built
        res = self.cluster.submit(self.name, b.event, b.plaintext)
        if not res.ok:
            return res            # stays pending: re-submit is idempotent (lock recovery)
        for h, c, rc in b.parents:
            h.cons.append((c, rc))
            self.busy.discard(h.key)
        ttok = self.cluster.entry_ttok(self.name, eid)
        for j, (owner, cur, a, r) in enumerate(b.outputs):
            self.openings[(eid, j)] = (a, r)
            if owner == self.name:
                self._register(eid, j, owner, cur, a, r, b.event.outputs[j].kappa, ttok)
        for acct, amt in pen.debits:
            self.customers[acct] = self.customers.get(acct, 0) - amt
        del self.pending[eid]
        if deliver:
            for dst, d in pen.deliveries:
                if dst != self.name:
                    out = self.deliver(dst, d)
                    if out and out[0] == "unreachable":
                        self.outbox.append((dst, d))
        else:
            res.deliveries = pen.deliveries
        return res

    def flush_outbox(self):
        left = []
        for dst, d in self.outbox:
            out = self.deliver(dst, d)
            if out and out[0] == "unreachable":
                left.append((dst, d))
        self.outbox = left
        return not left

    def abandon(self, eid: bytes):
        """Drop a pending event that cannot finalize (its token went stale) and free its parents.
        The keys it locked at some validators stay locked until an abort proof or forever."""
        pen = self.pending.pop(eid, None)
        if pen:
            for h, _, _ in pen.built.parents:
                self.busy.discard(h.key)
        return pen

    def retry_pending(self):
        out = []
        for eid in list(self.pending):
            out.append(self._finish(eid, True))
        return out

    # reversal (Algorithm 3)
    def open_for_flag(self, requests: list) -> dict:
        """Phase 2: answer opening requests. requests = [("c", parent_key, version, commitment) |
        ("o", event_id, j, commitment)]. Returns {commitment: (a, r)} for what this bank can open.
        A refusing bank returns nothing; a lying bank returns a wrong amount (rejected by the
        regulator and validators because it does not open the public commitment, Theorem 18)."""
        if self.behavior in ("refuse_open", "refuse_both"):
            return {}
        out = {}
        for kind, a, b, commit in requests:
            if kind == "c":
                h = self.holdings.get(a)
                got = h.cons[b] if h is not None and b < len(h.cons) else None
            else:
                got = self.openings.get((a, b))
            if got is None:
                continue
            v, r = got
            out[commit] = (v + 1, r) if self.behavior == "lie_open" else (v, r)
        return out

    def issue_rev(self, flag_id: bytes, m: int, brec: str, currency: str = "NGN", kind: str = "reversal",
                  beneficiary: str | None = None):
        """REV(m): consume Held cone entries (Prop 20 selection over Held entries only) and create one
        recovery entry of amount m owned by `brec` (reversal), or, for the recovery bank, a restitution
        to `beneficiary`. The holder pays m out of its own residuals (loss allocation is policy, section 5).
        Returns (result, event id)."""
        if self.behavior in ("refuse_rev", "refuse_both"):
            raise PaymentFailed("bank declines to issue REV")      # reversal is cooperative: it cannot be compelled
        held = self.cluster.held_keys(self.name)
        cand = [h for h in self.entries(currency) if h.key in held and h.key not in self.busy and h.residual()[0] > 0]
        take = plan_debit([h.residual()[0] for h in cand], m, self.P.floor(currency))
        parents = [(h, c) for h, c in zip(cand, take) if c > 0]
        dst = brec if kind == "reversal" else beneficiary
        b = build_spend(self.kp, self.name, self.P, currency, parents, [(dst, m)], self._epoch(), self._token,
                        rev=(kind, flag_id))
        for h, _ in parents:
            self.busy.add(h.key)
        dels = [(dst, Delivery(b.event.id, 0, b.outputs[0][2], b.outputs[0][3], 0, None, b"", self.name))]
        debit = ("_bank_loss", m) if kind == "reversal" else ("_unassigned", m)
        self.pending[b.event.id] = Pending(b, dels, [debit])
        return self._finish(b.event.id, True), b.event.id

    # delivery
    def deliver(self, dst: str, d: Delivery):
        return self.cluster.send_delivery(self.name, dst, d)

    def receive(self, d: Delivery):
        """Receiver checks (paper section 2): entry finalized and ours, Com(a;r) = kappa_j,
        advice hash and amount sum; only then credit the beneficiaries."""
        ent = self.cluster.lookup_entry(self.name, d.event_id, d.j)
        if ent is None or ent["owner"] != self.name:
            self.rejected.append((d, "NO_ENTRY"))
            return ("reject", "NO_ENTRY")
        if C.commit(d.a, d.r) != ent["kappa"]:
            self.rejected.append((d, "OPENING"))
            return ("reject", "OPENING")          # cannot be spent or returned: no valid opening
        h = self._register(d.event_id, d.j, self.name, ent["currency"], d.a, d.r, ent["kappa"], ent["ttok"])
        adv_hash = ent.get("hadv")
        if d.advice is not None or adv_hash is not None:
            ok = (d.advice is not None and adv_hash is not None
                  and advice_hash(d.advice, d.salt) == adv_hash
                  and sum(i[1] for i in d.advice["items"]) == d.a)
            if not ok:
                reason = "ADVICE_HASH" if (d.advice is None or advice_hash(d.advice, d.salt) != adv_hash) else "ADVICE_SUM"
                self.rejected.append((d, reason))
                self._return_value(h, d.sender)
                return ("reject", reason)
            for acct, amt, _ref in d.advice["items"]:
                self.customers[acct] = self.customers.get(acct, 0) + amt
        else:
            self.customers["_unassigned"] = self.customers.get("_unassigned", 0) + d.a
        return ("ok", None)

    def _return_value(self, h: Holding, to: str):
        """Return a refused payment with a new debit (we hold a valid opening)."""
        if h.key in self.busy:
            return
        a = h.residual()[0]
        try:
            b = build_spend(self.kp, self.name, self.P, h.currency, [(h, a)], [(to, a)], self._epoch(), self._token)
        except Exception:
            return
        self.busy.add(h.key)
        dels = [(to, Delivery(b.event.id, 0, b.outputs[0][2], b.outputs[0][3], 0, None, b"", self.name))]
        self.pending[b.event.id] = Pending(b, dels, [])
        self._finish(b.event.id, True)

    # reconciliation
    def reconcile(self, currency: str | None = None) -> bool:
        """M8: customer balances equal the residuals of the entries this bank owns.
        The network cannot check this (Table 3)."""
        return sum(self.customers.values()) == self.owned_total(currency)
