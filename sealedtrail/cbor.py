"""Deterministic CBOR (RFC 8949 section 4.2.1 core profile) with strict decoding.

Supported: unsigned/negative integers up to 64 bits, byte strings, text strings,
arrays, maps, booleans, null. Floats, tags and indefinite lengths are rejected.

The decoder is strict (paper Lemma 2): it rejects duplicate map keys, map keys
not in bytewise-sorted order, integers and lengths not in shortest form,
indefinite lengths, tags, floats and trailing bytes, so that every accepted
byte string is the canonical encoding of the value it decodes to.
"""
from __future__ import annotations


class CBORError(ValueError):
    pass


def _head(major: int, n: int) -> bytes:
    if n < 0:
        raise CBORError("negative head")
    if n < 24:
        return bytes([major << 5 | n])
    if n < 1 << 8:
        return bytes([major << 5 | 24, n])
    if n < 1 << 16:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 1 << 32:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    if n < 1 << 64:
        return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
    raise CBORError("integer out of range")


def encode(x) -> bytes:
    if x is None:
        return b"\xf6"
    if x is True:
        return b"\xf5"
    if x is False:
        return b"\xf4"
    if isinstance(x, int):
        if x >= 0:
            return _head(0, x)
        return _head(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return _head(2, len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(x, (list, tuple)):
        return _head(4, len(x)) + b"".join(encode(i) for i in x)
    if isinstance(x, dict):
        items = sorted(((encode(k), encode(v)) for k, v in x.items()), key=lambda kv: kv[0])
        for a, b in zip(items, items[1:]):
            if a[0] == b[0]:
                raise CBORError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise CBORError(f"unsupported type {type(x)!r}")


class _Dec:
    def __init__(self, b: bytes):
        self.b = b
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise CBORError("truncated")
        r = self.b[self.i : self.i + n]
        self.i += n
        return r

    def head(self):
        ib = self.take(1)[0]
        major, ai = ib >> 5, ib & 31
        if ai < 24:
            return major, ai
        if ai == 24:
            n = self.take(1)[0]
            if n < 24:
                raise CBORError("non-shortest integer")
            return major, n
        if ai == 25:
            n = int.from_bytes(self.take(2), "big")
            if n < 1 << 8:
                raise CBORError("non-shortest integer")
            return major, n
        if ai == 26:
            n = int.from_bytes(self.take(4), "big")
            if n < 1 << 16:
                raise CBORError("non-shortest integer")
            return major, n
        if ai == 27:
            n = int.from_bytes(self.take(8), "big")
            if n < 1 << 32:
                raise CBORError("non-shortest integer")
            return major, n
        if ai == 31:
            raise CBORError("indefinite length")
        raise CBORError("reserved additional info")

    def value(self, depth=0):
        if depth > 64:
            raise CBORError("too deep")
        ib = self.b[self.i] if self.i < len(self.b) else None
        if ib is None:
            raise CBORError("truncated")
        if ib == 0xF4:
            self.i += 1
            return False
        if ib == 0xF5:
            self.i += 1
            return True
        if ib == 0xF6:
            self.i += 1
            return None
        major, n = self.head()
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return self.take(n)
        if major == 3:
            raw = self.take(n)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as e:
                raise CBORError("bad utf-8") from e
        if major == 4:
            return [self.value(depth + 1) for _ in range(n)]
        if major == 5:
            out = {}
            prev = None
            for _ in range(n):
                ks = self.i
                k = self.value(depth + 1)
                ke = self.b[ks : self.i]
                if prev is not None:
                    if ke == prev:
                        raise CBORError("duplicate map key")
                    if ke < prev:
                        raise CBORError("map keys not sorted")
                prev = ke
                if isinstance(k, (list, dict)):
                    raise CBORError("unhashable map key")
                out[k] = self.value(depth + 1)
            return out
        if major == 6:
            raise CBORError("tags not supported")
        raise CBORError("floats/simple values not supported")


def decode(b: bytes):
    d = _Dec(bytes(b))
    v = d.value()
    if d.i != len(d.b):
        raise CBORError("trailing bytes")
    return v
