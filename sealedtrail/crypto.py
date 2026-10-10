"""Python wrapper over the Rust crypto core (st-crypto) plus Ed25519 and hashing.

Scalars are Python ints mod L; points and scalars cross the FFI as 32-byte strings.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import secrets
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

L = 2**252 + 27742317777372353535851937790883648493  # Ristretto255 group order


def _find_lib() -> str:
    env = os.environ.get("ST_CRYPTO_LIB")
    if env:
        return env
    root = Path(__file__).resolve().parent.parent
    for p in (
        root / "crypto" / "target" / "release" / "libst_crypto.so",
        root / "libst_crypto.so",
        Path("/usr/local/lib/libst_crypto.so"),
    ):
        if p.exists():
            return str(p)
    raise ImportError("libst_crypto.so not found; run `make crypto` or set ST_CRYPTO_LIB")


_lib = ctypes.CDLL(_find_lib())
_u8p = ctypes.c_char_p
_lib.st_commit.argtypes = [_u8p, _u8p, _u8p]
_lib.st_point_op.argtypes = [ctypes.c_int, _u8p, _u8p, _u8p]
_lib.st_point_mul.argtypes = [_u8p, _u8p, _u8p]
_lib.st_identity.argtypes = [_u8p]
_lib.st_generators.argtypes = [_u8p, _u8p]
_lib.st_prove_range.argtypes = [
    _u8p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint64), _u8p, ctypes.c_size_t,
    _u8p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
_lib.st_verify_range.argtypes = [_u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t, _u8p, ctypes.c_size_t]
_lib.st_prove_floor.argtypes = [
    _u8p, ctypes.c_size_t, _u8p, ctypes.c_uint64, _u8p, ctypes.c_uint64,
    _u8p, ctypes.POINTER(ctypes.c_uint64), _u8p,
]
_lib.st_verify_floor.argtypes = [_u8p, ctypes.c_size_t, _u8p, ctypes.c_uint64, _u8p, ctypes.c_size_t, _u8p]
_lib.st_limb_split.argtypes = [_u8p, _u8p, ctypes.POINTER(ctypes.c_uint64), _u8p]
_lib.st_limb_recombine.argtypes = [_u8p, _u8p]

FLOOR_PROOF_LEN = 256
MAX_PARTIES = 256


class CryptoError(Exception):
    pass


def sc(x: int) -> bytes:
    return (x % L).to_bytes(32, "little")


def rand_scalar() -> int:
    return secrets.randbelow(L - 1) + 1


def _buf(n: int):
    return ctypes.create_string_buffer(n)


def commit(v: int, r: int) -> bytes:
    out = _buf(32)
    rc = _lib.st_commit(sc(v), sc(r), out)
    if rc != 0:
        raise CryptoError(f"commit rc={rc}")
    return out.raw


def padd(a: bytes, b: bytes) -> bytes:
    out = _buf(32)
    if _lib.st_point_op(0, a, b, out) != 0:
        raise CryptoError("bad point")
    return out.raw


def psub(a: bytes, b: bytes) -> bytes:
    out = _buf(32)
    if _lib.st_point_op(1, a, b, out) != 0:
        raise CryptoError("bad point")
    return out.raw


def pmul(p: bytes, s: int) -> bytes:
    out = _buf(32)
    if _lib.st_point_mul(p, sc(s), out) != 0:
        raise CryptoError("bad point")
    return out.raw


def identity() -> bytes:
    out = _buf(32)
    _lib.st_identity(out)
    return out.raw


IDENTITY = identity()


def generators() -> tuple[bytes, bytes]:
    g, h = _buf(32), _buf(32)
    _lib.st_generators(g, h)
    return g.raw, h.raw


G, H = generators()


def psum(points) -> bytes:
    acc = IDENTITY
    for p in points:
        acc = padd(acc, p)
    return acc


def prove_range(ctx: bytes, values: list[int], blinds: list[int]) -> bytes:
    n = len(values)
    arr = (ctypes.c_uint64 * n)(*values)
    bl = b"".join(sc(b) for b in blinds)
    out = _buf(4096)
    ln = ctypes.c_size_t(0)
    rc = _lib.st_prove_range(ctx, len(ctx), arr, bl, n, out, 4096, ctypes.byref(ln))
    if rc != 0:
        raise CryptoError(f"prove_range rc={rc}")
    return out.raw[: ln.value]


def verify_range(ctx: bytes, comms: list[bytes], proof: bytes) -> bool:
    if not comms or len(comms) > MAX_PARTIES:
        return False
    return _lib.st_verify_range(ctx, len(ctx), b"".join(comms), len(comms), proof, len(proof)) == 0


def prove_floor(ctx: bytes, cx: bytes, x: int, rx: int, omega: int):
    """Returns (proof, party_value, party_blinding)."""
    proof = _buf(FLOOR_PROOF_LEN)
    pv = ctypes.c_uint64(0)
    pb = _buf(32)
    rc = _lib.st_prove_floor(ctx, len(ctx), cx, x, sc(rx), omega, proof, ctypes.byref(pv), pb)
    if rc != 0:
        raise CryptoError(f"prove_floor rc={rc}")
    return proof.raw, pv.value, int.from_bytes(pb.raw, "little")


def verify_floor(ctx: bytes, cx: bytes, omega: int, proof: bytes) -> bytes | None:
    """Returns the extra range-party commitment (Cx - omega*Cz) or None."""
    out = _buf(32)
    rc = _lib.st_verify_floor(ctx, len(ctx), cx, omega, proof, len(proof), out)
    return out.raw if rc == 0 else None


def limb_split(v: int, rv: int):
    """Returns (values[4], blindings[4]) for v < 2^224."""
    if v < 0 or v >= 1 << 224:
        raise CryptoError("value out of limb range")
    vals = (ctypes.c_uint64 * 4)()
    bl = _buf(128)
    rc = _lib.st_limb_split(sc(v), sc(rv), vals, bl)
    if rc != 0:
        raise CryptoError(f"limb_split rc={rc}")
    return list(vals), [int.from_bytes(bl.raw[i * 32 : (i + 1) * 32], "little") for i in range(4)]


def limb_recombine(comms: list[bytes]) -> bytes:
    out = _buf(32)
    if _lib.st_limb_recombine(b"".join(comms), out) != 0:
        raise CryptoError("limb_recombine")
    return out.raw


# signatures

def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


class KeyPair:
    def __init__(self, seed: bytes | None = None):
        self._sk = SigningKey(seed) if seed else SigningKey.generate()
        self.pk: bytes = bytes(self._sk.verify_key)

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg).signature

    @property
    def seed(self) -> bytes:
        return bytes(self._sk)


def verify_sig(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(pk).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
