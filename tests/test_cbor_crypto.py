import pytest
from hypothesis import given, strategies as st

from sealedtrail import cbor, crypto as C

scalar = st.integers(min_value=1, max_value=C.L - 1)


# Lemma 2: injective, strict encoding
leaf = st.one_of(
    st.none(), st.booleans(), st.integers(min_value=-(2**63), max_value=2**64 - 1),
    st.binary(max_size=40), st.text(max_size=20),
)
tree = st.recursive(
    leaf,
    lambda ch: st.one_of(st.lists(ch, max_size=5), st.dictionaries(st.text(max_size=6), ch, max_size=5)),
    max_leaves=25,
)


@given(tree)
def test_roundtrip(x):
    assert cbor.decode(cbor.encode(x)) == x


@given(tree, tree)
def test_injective(a, b):
    if a != b:
        assert cbor.encode(a) != cbor.encode(b)


@pytest.mark.parametrize(
    "bad",
    [
        bytes.fromhex("1800"),            # 0 in 2 bytes: non-shortest
        bytes.fromhex("190001"),          # 1 in 3 bytes
        bytes.fromhex("5f4101ff"),        # indefinite byte string
        bytes.fromhex("9f01ff"),          # indefinite array
        bytes.fromhex("a201016102"),      # (bad keys: duplicate-free but check below)
        bytes.fromhex("a2616101616101"),  # duplicate keys "a","a"
        bytes.fromhex("a2616201616101"),  # unsorted keys "b","a"
        bytes.fromhex("01") + b"\x00",    # trailing byte
        bytes.fromhex("c101"),            # tag
        bytes.fromhex("f90000"),          # float16
        bytes.fromhex("1b0000000000000001"),  # 8-byte form of 1
    ],
)
def test_strict_rejects(bad):
    if bad == bytes.fromhex("a201016102"):
        # keys 1 and ... 0x61 0x02 is a text-string header with missing payload -> truncated
        with pytest.raises(cbor.CBORError):
            cbor.decode(bad)
        return
    with pytest.raises(cbor.CBORError):
        cbor.decode(bad)


def test_map_order_is_bytewise_and_canonical():
    a = cbor.encode({"b": 1, "a": 2, "ab": 3})
    b = cbor.encode({"ab": 3, "a": 2, "b": 1})
    assert a == b
    assert cbor.decode(a) == {"a": 2, "ab": 3, "b": 1}


# crypto wrappers
@given(scalar, scalar, scalar, scalar)
def test_commit_homomorphic(a, ra, b, rb):
    assert C.padd(C.commit(a, ra), C.commit(b, rb)) == C.commit(a + b, ra + rb)
    assert C.psub(C.commit(a, ra), C.commit(b, rb)) == C.commit(a - b, ra - rb)


def test_identity_balance():
    r1, r2 = C.rand_scalar(), C.rand_scalar()
    assert C.psub(C.padd(C.commit(5, r1), C.commit(7, r2)), C.commit(12, r1 + r2)) == C.IDENTITY


def test_range_proof_and_padding():
    for n in (1, 2, 3, 6, 9):
        vals = [i * 12345 + 1 for i in range(n)]
        bl = [C.rand_scalar() for _ in range(n)]
        cm = [C.commit(v, b) for v, b in zip(vals, bl)]
        p = C.prove_range(b"c", vals, bl)
        assert C.verify_range(b"c", cm, p)
        assert not C.verify_range(b"d", cm, p)
        bad = list(cm)
        bad[0] = C.commit(vals[0] + 1, bl[0])
        assert not C.verify_range(b"c", bad, p)


def test_floor_proof_wrapper():
    omega = 100
    for x in (0, 100, 12345):
        rx = C.rand_scalar()
        cx = C.commit(x, rx)
        pf, pv, pb = C.prove_floor(b"ev", cx, x, rx, omega)
        party = C.verify_floor(b"ev", cx, omega, pf)
        assert party == C.commit(pv, pb)
        rp = C.prove_range(b"ev", [pv], [pb])
        assert C.verify_range(b"ev", [party], rp)
    rx = C.rand_scalar()
    cx = C.commit(50, rx)
    with pytest.raises(C.CryptoError):
        C.prove_floor(b"ev", cx, 50, rx, omega)


def test_limbs():
    v = (1 << 213) - 1
    rv = C.rand_scalar()
    cv = C.commit(v, rv)
    vals, bls = C.limb_split(v, rv)
    cm = [C.commit(a, b) for a, b in zip(vals, bls)]
    assert C.limb_recombine(cm) == cv
    p = C.prove_range(b"w", vals, bls)
    assert C.verify_range(b"w", cm, p)
    with pytest.raises(C.CryptoError):
        C.limb_split(1 << 224, rv)


def test_ed25519():
    k = C.KeyPair()
    s = k.sign(b"m")
    assert C.verify_sig(k.pk, b"m", s)
    assert not C.verify_sig(k.pk, b"x", s)
