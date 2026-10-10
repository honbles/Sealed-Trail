//! Sealed Trail crypto core (paper v4, spec section 7).
//!
//! * Pedersen commitments over Ristretto255 with g = basepoint and
//!   h = hash-to-group("sealed-trail/h/v1").
//! * Aggregated 64-bit Bulletproof range proofs (published `RangeProof` only,
//!   no R1CS), parties padded to a power of two with identity commitments.
//! * Zero-or-floor proof (D30): selector-bit commitment Cz, Fiat-Shamir
//!   sigma-OR  [ z=1 ]  OR  [ z=0 and x=0 ], plus one extra range party
//!   Cx - omega*Cz.
//! * Limb split for wide values (D31): 64/64/64/32-bit limbs, the top limb is
//!   proven as a 64-bit party over l3*2^32.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand::rngs::OsRng;
use sha2::Sha512;
use std::sync::OnceLock;

pub const MAX_PARTIES: usize = 256;
const BITS: usize = 64;

pub type Bytes32 = [u8; 32];

#[derive(Debug)]
pub enum Error {
    BadPoint,
    BadScalar,
    BadInput(&'static str),
    Proof,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn pc_gens() -> &'static PedersenGens {
    static G: OnceLock<PedersenGens> = OnceLock::new();
    G.get_or_init(|| PedersenGens {
        B: RISTRETTO_BASEPOINT_POINT,
        B_blinding: RistrettoPoint::hash_from_bytes::<Sha512>(b"sealed-trail/h/v1"),
    })
}

fn bp_gens() -> &'static BulletproofGens {
    static G: OnceLock<BulletproofGens> = OnceLock::new();
    G.get_or_init(|| BulletproofGens::new(BITS, MAX_PARTIES))
}

pub fn scalar_from_bytes(b: &Bytes32) -> Result<Scalar> {
    let s = Scalar::from_canonical_bytes(*b);
    if bool::from(s.is_some()) {
        Ok(s.unwrap())
    } else {
        Err(Error::BadScalar)
    }
}

pub fn point_from_bytes(b: &Bytes32) -> Result<RistrettoPoint> {
    CompressedRistretto(*b).decompress().ok_or(Error::BadPoint)
}

fn pt(p: &RistrettoPoint) -> Bytes32 {
    p.compress().to_bytes()
}

pub fn commit(value: &Scalar, blinding: &Scalar) -> RistrettoPoint {
    let g = pc_gens();
    value * g.B + blinding * g.B_blinding
}

pub fn pow2(k: u32) -> Scalar {
    let mut s = Scalar::ONE;
    let two = Scalar::from(2u64);
    for _ in 0..k {
        s *= two;
    }
    s
}

// ---------------------------------------------------------------- range proofs

fn range_transcript(ctx: &[u8], n_real: usize) -> Transcript {
    let mut t = Transcript::new(b"sealed-trail/range/v1");
    t.append_message(b"ctx", ctx);
    t.append_u64(b"n", n_real as u64);
    t
}

/// Aggregated range proof over `values` (each in [0, 2^64)) with `blindings`.
/// Parties are padded to a power of two with (0, 0), i.e. identity commitments.
pub fn prove_range(ctx: &[u8], values: &[u64], blindings: &[Scalar]) -> Result<Vec<u8>> {
    let n = values.len();
    if n == 0 || n != blindings.len() || n > MAX_PARTIES {
        return Err(Error::BadInput("party count"));
    }
    let m = n.next_power_of_two();
    let mut v = values.to_vec();
    let mut b = blindings.to_vec();
    v.resize(m, 0);
    b.resize(m, Scalar::ZERO);
    let mut t = range_transcript(ctx, n);
    let (proof, _c) = RangeProof::prove_multiple(bp_gens(), pc_gens(), &mut t, &v, &b, BITS)
        .map_err(|_| Error::Proof)?;
    Ok(proof.to_bytes())
}

pub fn verify_range(ctx: &[u8], comms: &[Bytes32], proof: &[u8]) -> Result<()> {
    let n = comms.len();
    if n == 0 || n > MAX_PARTIES {
        return Err(Error::BadInput("party count"));
    }
    let m = n.next_power_of_two();
    let mut c: Vec<CompressedRistretto> = comms.iter().map(|x| CompressedRistretto(*x)).collect();
    c.resize(m, CompressedRistretto::identity());
    let proof = RangeProof::from_bytes(proof).map_err(|_| Error::Proof)?;
    let mut t = range_transcript(ctx, n);
    proof
        .verify_multiple(bp_gens(), pc_gens(), &mut t, &c, BITS)
        .map_err(|_| Error::Proof)
}

// ------------------------------------------------------- zero-or-floor (sigma-OR)

pub const FLOOR_PROOF_LEN: usize = 256;

fn floor_transcript(ctx: &[u8], cx: &Bytes32, cz: &Bytes32, omega: u64) -> Transcript {
    let mut t = Transcript::new(b"sealed-trail/floor/v1");
    t.append_message(b"ctx", ctx);
    t.append_u64(b"omega", omega);
    t.append_message(b"cx", cx);
    t.append_message(b"cz", cz);
    t
}

fn challenge(t: &mut Transcript, ta: &Bytes32, tb1: &Bytes32, tb2: &Bytes32) -> Scalar {
    t.append_message(b"ta", ta);
    t.append_message(b"tb1", tb1);
    t.append_message(b"tb2", tb2);
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

pub struct FloorOut {
    pub proof: [u8; FLOOR_PROOF_LEN],
    /// value and blinding of the extra range-proof party  Cx - omega*Cz
    pub party_value: u64,
    pub party_blinding: Scalar,
}

/// Prove that the residual `x` committed in `cx = Com(x; rx)` is 0 or >= omega.
pub fn prove_floor(ctx: &[u8], cx: &Bytes32, x: u64, rx: &Scalar, omega: u64) -> Result<FloorOut> {
    if omega == 0 {
        return Err(Error::BadInput("omega"));
    }
    let z: u64 = if x == 0 {
        0
    } else if x >= omega {
        1
    } else {
        return Err(Error::BadInput("residual in (0, omega)"));
    };
    let g = pc_gens();
    let (gb, h) = (g.B, g.B_blinding);
    let cx_pt = point_from_bytes(cx)?;
    let mut rng = OsRng;
    let rz = Scalar::random(&mut rng);
    let cz_pt = Scalar::from(z) * gb + rz * h;
    let cz = pt(&cz_pt);
    let ya = cz_pt - gb;

    let mut t = floor_transcript(ctx, cx, &cz, omega);
    let (ta, tb1, tb2, ca, sa, sb1, sb2);
    if z == 1 {
        // A real, B simulated
        let ka = Scalar::random(&mut rng);
        let cb = Scalar::random(&mut rng);
        let sb1_ = Scalar::random(&mut rng);
        let sb2_ = Scalar::random(&mut rng);
        let ta_ = ka * h;
        let tb1_ = sb1_ * h - cb * cz_pt;
        let tb2_ = sb2_ * h - cb * cx_pt;
        let c = challenge(&mut t, &pt(&ta_), &pt(&tb1_), &pt(&tb2_));
        let ca_ = c - cb;
        let sa_ = ka + ca_ * rz;
        ta = ta_;
        tb1 = tb1_;
        tb2 = tb2_;
        ca = ca_;
        sa = sa_;
        sb1 = sb1_;
        sb2 = sb2_;
    } else {
        // B real, A simulated
        let k1 = Scalar::random(&mut rng);
        let k2 = Scalar::random(&mut rng);
        let ca_ = Scalar::random(&mut rng);
        let sa_ = Scalar::random(&mut rng);
        let ta_ = sa_ * h - ca_ * ya;
        let tb1_ = k1 * h;
        let tb2_ = k2 * h;
        let c = challenge(&mut t, &pt(&ta_), &pt(&tb1_), &pt(&tb2_));
        let cb = c - ca_;
        sb1 = k1 + cb * rz;
        sb2 = k2 + cb * *rx;
        ta = ta_;
        tb1 = tb1_;
        tb2 = tb2_;
        ca = ca_;
        sa = sa_;
    }
    let mut proof = [0u8; FLOOR_PROOF_LEN];
    let parts: [Bytes32; 8] = [
        cz,
        pt(&ta),
        pt(&tb1),
        pt(&tb2),
        ca.to_bytes(),
        sa.to_bytes(),
        sb1.to_bytes(),
        sb2.to_bytes(),
    ];
    for (i, p) in parts.iter().enumerate() {
        proof[i * 32..(i + 1) * 32].copy_from_slice(p);
    }
    Ok(FloorOut {
        proof,
        party_value: x - z * omega,
        party_blinding: *rx - Scalar::from(omega) * rz,
    })
}

/// Verify the sigma-OR. On success returns the commitment of the extra range
/// party, Cx - omega*Cz, which the caller must include in the event's
/// aggregated range proof.
pub fn verify_floor(ctx: &[u8], cx: &Bytes32, omega: u64, proof: &[u8]) -> Result<Bytes32> {
    if proof.len() != FLOOR_PROOF_LEN || omega == 0 {
        return Err(Error::BadInput("floor proof length"));
    }
    let mut parts = [[0u8; 32]; 8];
    for i in 0..8 {
        parts[i].copy_from_slice(&proof[i * 32..(i + 1) * 32]);
    }
    let cz = parts[0];
    let cz_pt = point_from_bytes(&cz)?;
    let cx_pt = point_from_bytes(cx)?;
    let ta = point_from_bytes(&parts[1])?;
    let tb1 = point_from_bytes(&parts[2])?;
    let tb2 = point_from_bytes(&parts[3])?;
    let ca = scalar_from_bytes(&parts[4])?;
    let sa = scalar_from_bytes(&parts[5])?;
    let sb1 = scalar_from_bytes(&parts[6])?;
    let sb2 = scalar_from_bytes(&parts[7])?;
    let g = pc_gens();
    let (gb, h) = (g.B, g.B_blinding);
    let mut t = floor_transcript(ctx, cx, &cz, omega);
    let c = challenge(&mut t, &parts[1], &parts[2], &parts[3]);
    let cb = c - ca;
    let ok_a = sa * h == ta + ca * (cz_pt - gb);
    let ok_b1 = sb1 * h == tb1 + cb * cz_pt;
    let ok_b2 = sb2 * h == tb2 + cb * cx_pt;
    if ok_a && ok_b1 && ok_b2 {
        Ok(pt(&(cx_pt - Scalar::from(omega) * cz_pt)))
    } else {
        Err(Error::Proof)
    }
}

// ------------------------------------------------------------------- wide limbs

pub struct Limbs {
    pub values: [u64; 4],
    pub blindings: [Scalar; 4],
}

/// Split v (little-endian, v < 2^224) into four 64-bit range parties
/// l0, l1, l2, l3*2^32 whose blindings satisfy
///   rv = r0 + 2^64 r1 + 2^128 r2 + 2^160 r3'.
pub fn limb_split(v_le: &Bytes32, rv: &Scalar) -> Result<Limbs> {
    if v_le[28..].iter().any(|b| *b != 0) {
        return Err(Error::BadInput("value >= 2^224"));
    }
    let u = |i: usize| u64::from_le_bytes(v_le[i * 8..i * 8 + 8].try_into().unwrap());
    let l0 = u(0);
    let l1 = u(1);
    let l2 = u(2);
    let l3 = u32::from_le_bytes(v_le[24..28].try_into().unwrap()) as u64;
    let mut rng = OsRng;
    let r0 = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let r3 = (*rv - r0 - pow2(64) * r1 - pow2(128) * r2) * pow2(160).invert();
    Ok(Limbs {
        values: [l0, l1, l2, l3 << 32],
        blindings: [r0, r1, r2, r3],
    })
}

/// C_v = C0 + 2^64 C1 + 2^128 C2 + 2^160 C3'
pub fn limb_recombine(c: &[Bytes32; 4]) -> Result<Bytes32> {
    let p0 = point_from_bytes(&c[0])?;
    let p1 = point_from_bytes(&c[1])?;
    let p2 = point_from_bytes(&c[2])?;
    let p3 = point_from_bytes(&c[3])?;
    Ok(pt(&(p0 + pow2(64) * p1 + pow2(128) * p2 + pow2(160) * p3)))
}

// ------------------------------------------------------------------- C ABI

use std::slice;

fn rc<T>(r: Result<T>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(Error::BadPoint) => -1,
        Err(Error::BadScalar) => -2,
        Err(Error::BadInput(_)) => -3,
        Err(Error::Proof) => -4,
    }
}

#[no_mangle]
pub extern "C" fn st_commit(value: *const u8, blind: *const u8, out: *mut u8) -> i32 {
    let (v, b, o) = unsafe {
        (
            &*(value as *const Bytes32),
            &*(blind as *const Bytes32),
            &mut *(out as *mut Bytes32),
        )
    };
    match (scalar_from_bytes(v), scalar_from_bytes(b)) {
        (Ok(v), Ok(b)) => {
            *o = pt(&commit(&v, &b));
            0
        }
        _ => -2,
    }
}

/// op: 0 add, 1 sub
#[no_mangle]
pub extern "C" fn st_point_op(op: i32, a: *const u8, b: *const u8, out: *mut u8) -> i32 {
    let (a, b, o) = unsafe {
        (
            &*(a as *const Bytes32),
            &*(b as *const Bytes32),
            &mut *(out as *mut Bytes32),
        )
    };
    match (point_from_bytes(a), point_from_bytes(b)) {
        (Ok(a), Ok(b)) => {
            *o = pt(&if op == 0 { a + b } else { a - b });
            0
        }
        _ => -1,
    }
}

#[no_mangle]
pub extern "C" fn st_point_mul(p: *const u8, s: *const u8, out: *mut u8) -> i32 {
    let (p, s, o) = unsafe {
        (
            &*(p as *const Bytes32),
            &*(s as *const Bytes32),
            &mut *(out as *mut Bytes32),
        )
    };
    match (point_from_bytes(p), scalar_from_bytes(s)) {
        (Ok(p), Ok(s)) => {
            *o = pt(&(s * p));
            0
        }
        _ => -1,
    }
}

#[no_mangle]
pub extern "C" fn st_identity(out: *mut u8) {
    let o = unsafe { &mut *(out as *mut Bytes32) };
    *o = pt(&RistrettoPoint::identity());
}

#[no_mangle]
pub extern "C" fn st_generators(g_out: *mut u8, h_out: *mut u8) {
    let (g, h) = unsafe { (&mut *(g_out as *mut Bytes32), &mut *(h_out as *mut Bytes32)) };
    *g = pt(&pc_gens().B);
    *h = pt(&pc_gens().B_blinding);
}

#[no_mangle]
pub extern "C" fn st_prove_range(
    ctx: *const u8,
    ctx_len: usize,
    values: *const u64,
    blinds: *const u8,
    n: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let (ctx, vals, bl) = unsafe {
        (
            slice::from_raw_parts(ctx, ctx_len),
            slice::from_raw_parts(values, n),
            slice::from_raw_parts(blinds, n * 32),
        )
    };
    let mut bs = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bl[i * 32..(i + 1) * 32]);
        match scalar_from_bytes(&b) {
            Ok(s) => bs.push(s),
            Err(_) => return -2,
        }
    }
    match prove_range(ctx, vals, &bs) {
        Ok(p) => {
            if p.len() > out_cap {
                return -3;
            }
            unsafe {
                slice::from_raw_parts_mut(out, p.len()).copy_from_slice(&p);
                *out_len = p.len();
            }
            0
        }
        Err(e) => rc::<()>(Err(e)),
    }
}

#[no_mangle]
pub extern "C" fn st_verify_range(
    ctx: *const u8,
    ctx_len: usize,
    comms: *const u8,
    n: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let (ctx, cm, pf) = unsafe {
        (
            slice::from_raw_parts(ctx, ctx_len),
            slice::from_raw_parts(comms, n * 32),
            slice::from_raw_parts(proof, proof_len),
        )
    };
    let mut cs = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = [0u8; 32];
        b.copy_from_slice(&cm[i * 32..(i + 1) * 32]);
        cs.push(b);
    }
    rc(verify_range(ctx, &cs, pf))
}

#[no_mangle]
pub extern "C" fn st_prove_floor(
    ctx: *const u8,
    ctx_len: usize,
    cx: *const u8,
    x: u64,
    rx: *const u8,
    omega: u64,
    out_proof: *mut u8,
    out_party_value: *mut u64,
    out_party_blind: *mut u8,
) -> i32 {
    let (ctx, cx, rx) = unsafe {
        (
            slice::from_raw_parts(ctx, ctx_len),
            &*(cx as *const Bytes32),
            &*(rx as *const Bytes32),
        )
    };
    let rx = match scalar_from_bytes(rx) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match prove_floor(ctx, cx, x, &rx, omega) {
        Ok(o) => unsafe {
            slice::from_raw_parts_mut(out_proof, FLOOR_PROOF_LEN).copy_from_slice(&o.proof);
            *out_party_value = o.party_value;
            slice::from_raw_parts_mut(out_party_blind, 32).copy_from_slice(&o.party_blinding.to_bytes());
            0
        },
        Err(e) => rc::<()>(Err(e)),
    }
}

#[no_mangle]
pub extern "C" fn st_verify_floor(
    ctx: *const u8,
    ctx_len: usize,
    cx: *const u8,
    omega: u64,
    proof: *const u8,
    proof_len: usize,
    out_party: *mut u8,
) -> i32 {
    let (ctx, cx, pf) = unsafe {
        (
            slice::from_raw_parts(ctx, ctx_len),
            &*(cx as *const Bytes32),
            slice::from_raw_parts(proof, proof_len),
        )
    };
    match verify_floor(ctx, cx, omega, pf) {
        Ok(p) => unsafe {
            slice::from_raw_parts_mut(out_party, 32).copy_from_slice(&p);
            0
        },
        Err(e) => rc::<()>(Err(e)),
    }
}

#[no_mangle]
pub extern "C" fn st_limb_split(
    v: *const u8,
    rv: *const u8,
    out_values: *mut u64,
    out_blinds: *mut u8,
) -> i32 {
    let (v, rv) = unsafe { (&*(v as *const Bytes32), &*(rv as *const Bytes32)) };
    let rv = match scalar_from_bytes(rv) {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match limb_split(v, &rv) {
        Ok(l) => unsafe {
            for i in 0..4 {
                *out_values.add(i) = l.values[i];
                slice::from_raw_parts_mut(out_blinds.add(i * 32), 32)
                    .copy_from_slice(&l.blindings[i].to_bytes());
            }
            0
        },
        Err(e) => rc::<()>(Err(e)),
    }
}

#[no_mangle]
pub extern "C" fn st_limb_recombine(c: *const u8, out: *mut u8) -> i32 {
    let cs = unsafe { slice::from_raw_parts(c, 128) };
    let mut a = [[0u8; 32]; 4];
    for i in 0..4 {
        a[i].copy_from_slice(&cs[i * 32..(i + 1) * 32]);
    }
    match limb_recombine(&a) {
        Ok(p) => unsafe {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&p);
            0
        },
        Err(e) => rc::<()>(Err(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs() -> Scalar {
        Scalar::random(&mut OsRng)
    }

    #[test]
    fn range_roundtrip_and_padding() {
        for n in [1usize, 2, 3, 5, 8, 13] {
            let vals: Vec<u64> = (0..n as u64).map(|i| i * 1_000_003 + 7).collect();
            let bls: Vec<Scalar> = (0..n).map(|_| rs()).collect();
            let comms: Vec<Bytes32> = vals
                .iter()
                .zip(&bls)
                .map(|(v, b)| pt(&commit(&Scalar::from(*v), b)))
                .collect();
            let p = prove_range(b"ctx", &vals, &bls).unwrap();
            verify_range(b"ctx", &comms, &p).unwrap();
            assert!(verify_range(b"other", &comms, &p).is_err());
        }
    }

    #[test]
    fn range_rejects_wrong_commitment() {
        let vals = [5u64, 9];
        let bls = [rs(), rs()];
        let p = prove_range(b"c", &vals, &bls).unwrap();
        let bad = [
            pt(&commit(&Scalar::from(5u64), &bls[0])),
            pt(&commit(&Scalar::from(10u64), &bls[1])),
        ];
        assert!(verify_range(b"c", &bad, &p).is_err());
    }

    #[test]
    fn range_rejects_negative_via_shift() {
        // x = a - omega with a < omega is negative: represented mod l it is huge,
        // so a prover cannot build a valid proof; the verifier rejects a proof
        // built for a different (in-range) value.
        let omega = 100u64;
        let a = 40u64;
        let r = rs();
        let ka = pt(&commit(&Scalar::from(a), &r));
        let shifted = pt(&(point_from_bytes(&ka).unwrap() - Scalar::from(omega) * pc_gens().B));
        let p = prove_range(b"c", &[0u64], &[r]).unwrap();
        assert!(verify_range(b"c", &[shifted], &p).is_err());
    }

    fn floor_case(x: u64, omega: u64) -> (Bytes32, Scalar, FloorOut) {
        let rx = rs();
        let cx = pt(&commit(&Scalar::from(x), &rx));
        let out = prove_floor(b"ev", &cx, x, &rx, omega).unwrap();
        (cx, rx, out)
    }

    #[test]
    fn floor_zero_and_floor_accepted() {
        let omega = 100;
        for x in [0u64, 100, 101, 5_000, u64::MAX - 200] {
            let (cx, _rx, out) = floor_case(x, omega);
            let party = verify_floor(b"ev", &cx, omega, &out.proof).unwrap();
            // the party commitment opens to (x - z*omega, rx - omega*rz)
            let expect = pt(&commit(&Scalar::from(out.party_value), &out.party_blinding));
            assert_eq!(party, expect);
            // and the aggregated range proof over it verifies
            let rp = prove_range(b"ev", &[out.party_value], &[out.party_blinding]).unwrap();
            verify_range(b"ev", &[party], &rp).unwrap();
        }
    }

    #[test]
    fn floor_below_floor_cannot_be_proven() {
        let rx = rs();
        let cx = pt(&commit(&Scalar::from(50u64), &rx));
        assert!(prove_floor(b"ev", &cx, 50, &rx, 100).is_err());
    }

    #[test]
    fn floor_dishonest_below_floor_fails_range() {
        // A cheating prover with x = 50 < omega = 100 tries z = 1: the OR can be
        // proven for branch A, but the party value x - omega is negative so no
        // range proof exists for the party commitment.
        let omega = 100u64;
        let x = 50u64;
        let rx = rs();
        let cx = pt(&commit(&Scalar::from(x), &rx));
        // emulate a cheater by lying about x in prove_floor (x'=100 for the OR)
        let out = prove_floor(b"ev", &cx, 100, &rx, omega).unwrap();
        let party = verify_floor(b"ev", &cx, omega, &out.proof).unwrap();
        // honest party would be (0, ..) but the real committed value is 50-100<0:
        let rp = prove_range(b"ev", &[out.party_value], &[out.party_blinding]).unwrap();
        assert!(verify_range(b"ev", &[party], &rp).is_err());
    }

    #[test]
    fn floor_tampering_rejected() {
        let omega = 100;
        let (cx, _rx, out) = floor_case(0, omega);
        for i in 0..FLOOR_PROOF_LEN {
            let mut p = out.proof;
            p[i] ^= 1;
            assert!(verify_floor(b"ev", &cx, omega, &p).is_err(), "byte {i}");
        }
        assert!(verify_floor(b"other", &cx, omega, &out.proof).is_err());
        assert!(verify_floor(b"ev", &cx, omega + 1, &out.proof).is_err());
        // proof for another parent commitment cannot be replayed
        let (cx2, _r2, _o2) = floor_case(0, omega);
        assert!(verify_floor(b"ev", &cx2, omega, &out.proof).is_err());
    }

    #[test]
    fn floor_nonbit_selector_rejected() {
        // Cheater picks z = 2 (Cz = 2g + rz h): neither branch statement holds.
        // Check by hand that a proof built with a forged Cz cannot verify.
        let omega = 100u64;
        let rx = rs();
        let cx = pt(&commit(&Scalar::from(300u64), &rx));
        let out = prove_floor(b"ev", &cx, 300, &rx, omega).unwrap();
        let mut p = out.proof;
        let cz = point_from_bytes(&<[u8; 32]>::try_from(&p[0..32]).unwrap()).unwrap();
        let forged = pt(&(cz + pc_gens().B)); // z becomes 2
        p[0..32].copy_from_slice(&forged);
        assert!(verify_floor(b"ev", &cx, omega, &p).is_err());
    }

    #[test]
    fn limbs_roundtrip_and_bounds() {
        // v = 2^213 - 1
        let mut v = [0u8; 32];
        for i in 0..26 {
            v[i] = 0xff;
        }
        v[26] = 0x1f; // bits 208..212
        let rv = rs();
        let cv = pt(&commit(&Scalar::from_bytes_mod_order(v), &rv));
        let l = limb_split(&v, &rv).unwrap();
        let comms: Vec<Bytes32> = (0..4)
            .map(|i| pt(&commit(&Scalar::from(l.values[i]), &l.blindings[i])))
            .collect();
        let arr: [Bytes32; 4] = [comms[0], comms[1], comms[2], comms[3]];
        assert_eq!(limb_recombine(&arr).unwrap(), cv);
        let p = prove_range(b"w", &l.values, &l.blindings).unwrap();
        verify_range(b"w", &comms, &p).unwrap();
        // >= 2^224 rejected at split
        let mut big = [0u8; 32];
        big[28] = 1;
        assert!(limb_split(&big, &rv).is_err());
    }

    #[test]
    fn point_generators_distinct() {
        assert_ne!(pt(&pc_gens().B), pt(&pc_gens().B_blinding));
    }
}
