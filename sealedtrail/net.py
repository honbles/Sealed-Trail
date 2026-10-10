"""Simulated clock and network shim (spec section 2.4).

Latency, loss and partitions apply to every call between nodes in `inproc` and
`local` runtimes, so partition tests need no Docker. Latencies are *simulated*.
"""
from __future__ import annotations

import random


class Unreachable(Exception):
    pass


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, dt: float):
        self.t += dt

    def set(self, t: float):
        self.t = t


class Network:
    def __init__(self, seed: int = 1, latency_ms: float = 1.0, jitter_ms: float = 0.0, loss: float = 0.0):
        self.rng = random.Random(seed)
        self.latency_ms = latency_ms
        self.jitter_ms = jitter_ms
        self.loss = loss
        self.groups: list[set] | None = None
        self.down: set = set()
        self.calls = 0
        self.sim_ms = 0.0

    # -- fault injection
    def partition(self, *groups):
        self.groups = [set(g) for g in groups]

    def heal(self):
        self.groups = None

    def crash(self, node: str):
        self.down.add(node)

    def restart(self, node: str):
        self.down.discard(node)

    def reachable(self, a: str, b: str) -> bool:
        if a in self.down or b in self.down:
            return False
        if self.groups is None:
            return True
        for g in self.groups:
            if a in g:
                return b in g
        return False  # node in no group is isolated

    def call(self, src: str, dst: str, fn, *args, **kw):
        if not self.reachable(src, dst):
            raise Unreachable(f"{src}->{dst}")
        if self.loss and self.rng.random() < self.loss:
            raise Unreachable(f"{src}->{dst} (lost)")
        self.calls += 1
        self.sim_ms += self.latency_ms + (self.rng.random() * self.jitter_ms if self.jitter_ms else 0.0)
        return fn(*args, **kw)
