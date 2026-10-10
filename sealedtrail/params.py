"""Protocol parameters (paper Table 2) and named profiles (spec section 2.2)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Params:
    k: int = 7                    # validators
    f: int = 2                    # Byzantine bound
    omega: dict = field(default_factory=lambda: {"NGN": 100, "USD": 100, "EUR": 100})
    p_max: int = 16
    m_max: int = 16
    delta_stale: float = 30.0
    delta_skew: float = 2.0
    rate_fresh: float = 60.0      # max age of a rate document against the event's token time
    w_esc: float = 600.0
    t_hold: float = 5.0
    t_open: float = 60.0
    t_rev: float = 60.0
    theta: tuple = (1, 200)       # 0.5 percent, as (num, den)
    theta_o: tuple = (1, 400)
    n_tsa: int = 3
    m_tsa: int = 2
    na_n: int = 5
    na_tau: int = 3
    t_min: int = 0

    def __post_init__(self):
        assert self.k >= 3 * self.f + 1, "need k >= 3f+1"
        assert 2 * self.q > self.k, "need 2q > k"
        assert self.q <= self.k - self.f, "need q <= k-f"

    @property
    def q(self) -> int:
        return -(-(self.k + self.f + 1) // 2)  # ceil((k+f+1)/2)

    @property
    def t_exp_default(self) -> float:
        return self.t_hold + self.t_open + self.t_rev + 120.0

    def floor(self, currency: str) -> int:
        return self.omega[currency]


PROFILES = {
    "min": dict(k=4, f=1),
    "dev": dict(k=7, f=2),
    "k5f1": dict(k=5, f=1),
    "k5f0": dict(k=5, f=0),
}


def profile(name: str, **over) -> Params:
    d = dict(PROFILES[name])
    d.update(over)
    return Params(**d)
