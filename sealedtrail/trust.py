"""Trust configuration shared by validators and banks (spec sections 3.3, 3.4, 6.2).

NOTE (prototype): the NA is a single Ed25519 key here; FROST threshold signing and
Merkle CRL non-membership proofs are not implemented yet. TIVs are a static trust
list of public keys (decision D15a).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Trust:
    na_pk: bytes = b""
    tsa_pks: dict = field(default_factory=dict)        # tsa id -> pk
    tiv_pks: dict = field(default_factory=dict)        # tiv id -> pk (static trust list)
    validator_pks: dict = field(default_factory=dict)  # validator id -> pk
    bank_pks: dict = field(default_factory=dict)       # bank id -> pk (from NA-signed certs)
    bank_jurisdiction: dict = field(default_factory=dict)
    epochs: list = field(default_factory=lambda: [(0.0, 0)])  # (start time, epoch no), ascending
    revoked: dict = field(default_factory=dict)        # epoch -> {bank: t_rev}
    jurisdictions: dict = field(default_factory=dict)  # name -> tuple of banks (J)
    mutual: dict = field(default_factory=dict)         # name -> tuple of banks (M_J, registered with the NA)
    regulators: dict = field(default_factory=dict)     # id -> (pk, tuple of jurisdiction names it covers)
    reg_threshold: int = 2                             # t_reg
    review_pks: dict = field(default_factory=dict)     # review body (distinct from every regulator)
    oracle_pks: dict = field(default_factory=dict)     # oracle id -> pk (rate documents need all of them)
    review_threshold: int = 1
    epoch_grace: float = 5.0                           # publication delay for citing the predecessor epoch

    def epoch_at(self, t: float) -> int:
        e = self.epochs[0][1]
        for start, no in self.epochs:
            if start <= t:
                e = no
        return e

    def revoke(self, bank: str, t_rev: float, new_epoch_start: float):
        no = self.epochs[-1][1] + 1
        self.epochs.append((new_epoch_start, no))
        prev = dict(self.revoked.get(no - 1, {}))
        prev[bank] = t_rev
        self.revoked[no] = prev
        return no
