//! GLYPH: packed GKR-style sumcheck proof (docs/spec.md, packed arity-8 format).
//!
//! This module implements a deterministic prover for the packed calldata format
//! consumed by `contracts/GLYPHVerifier.sol`.
//!
//! Supported layout:
//! - Packed: per round includes c0,c1 (c2 is reconstructed from the sumcheck constraint)
//!
//! Important: This is a minimal vertical slice of the GLYPH Protocol path.
//! It proves internal consistency of a Fiat-Shamir sumcheck transcript and a
//! final state check. It does not by itself encode a full upstream verifier.


use crate::adapters::keccak256;
use crate::glyph_field_simd::ensure_two_thread_pool;
use rayon::prelude::*;
use std::sync::OnceLock;

pub const GLYPH_GKR_INIT_DOMAIN: &[u8] = b"GLYPH_GKR_INIT";
pub const GLYPH_GKR_COEFF_DOMAIN: &[u8] = b"GLYPH_GKR_COEFF";
pub const GLYPH_GKR_BIND_DOMAIN_UNBOUND: &[u8] = b"GLYPH_GKR_BIND_UNBOUND";
pub const GLYPH_GKR_BIND_DOMAIN_STATEMENT: &[u8] = b"GLYPH_GKR_BIND_STATEMENT";
pub const GLYPH_GKR_TOY_LIN_DOMAIN: &[u8] = b"GLYPH_GKR_TOY_LIN";
pub const GLYPH_GKR_TOY_FOLD_SEED_DOMAIN: &[u8] = b"GLYPH_GKR_TOY_FOLD_SEED";
pub const GLYPH_GKR_TOY_FOLD_INSTANCE_DOMAIN: &[u8] = b"GLYPH_GKR_TOY_FOLD_INSTANCE";
pub const GLYPH_GKR_TOY_BASEFOLD_ROOT_DOMAIN: &[u8] = b"GLYPH_GKR_TOY_BASEFOLD_ROOT";
pub const GLYPH_GKR_TOY_BASEFOLD_ALPHA_DOMAIN: &[u8] = b"GLYPH_GKR_TOY_BASEFOLD_ALPHA";
pub const GLYPH_GKR_BIND_DOMAIN_STMT_POLY: &[u8] = b"GLYPH_GKR_BIND_STMT_POLY";
pub const GLYPH_GKR_STMT_POLY_LIN_DOMAIN: &[u8] = b"GLYPH_GKR_STMT_POLY_LIN";
pub const GLYPH_GKR_ARTIFACT_LIN_DOMAIN: &[u8] = b"GLYPH_GKR_ARTIFACT_LIN";

static GKR_BIND_DOMAIN_UNBOUND_HASH: OnceLock<[u8; 32]> = OnceLock::new();
static GKR_BIND_DOMAIN_STATEMENT_HASH: OnceLock<[u8; 32]> = OnceLock::new();
static GKR_BIND_DOMAIN_STMT_POLY_HASH: OnceLock<[u8; 32]> = OnceLock::new();
static GKR_STMT_POLY_LIN_HASH: OnceLock<[u8; 32]> = OnceLock::new();
static GKR_ARTIFACT_LIN_HASH: OnceLock<[u8; 32]> = OnceLock::new();

#[inline]
fn gkr_domain_hash(cell: &OnceLock<[u8; 32]>, domain: &'static [u8]) -> [u8; 32] {
    *cell.get_or_init(|| keccak256(domain))
}

pub const GKR_MODULUS: u128 = 340282366920938463463374607431768211297; // 2^128 - 159
pub const GKR_INV2: u128 = 170141183460469231731687303715884105649;
pub const GKR_INV140: u128 = 308684718563994177570346965313104020248;
const GKR_MODULUS_C: u128 = 159;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedRound {
    pub c0: u128,
    pub c1: u128,
    pub c2: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedGkrProof {
    pub initial_claim: u128,
    pub rounds: Vec<PackedRound>,
    pub expected_final: u128,
}

fn empty_packed_gkr_proof() -> PackedGkrProof {
    PackedGkrProof {
        initial_claim: 0u128,
        rounds: Vec::new(),
        expected_final: 0u128,
    }
}

fn usize_to_u32(value: usize) -> Option<u32> {
    if value <= u32::MAX as usize {
        Some(value as u32)
    } else {
        None
    }
}

#[inline]
fn mul_u128_full(a: u128, b: u128) -> (u128, u128) {
    let a0 = a as u64;
    let a1 = (a >> 64) as u64;
    let b0 = b as u64;
    let b1 = (b >> 64) as u64;

    let p0 = (a0 as u128) * (b0 as u128);
    let p1 = (a0 as u128) * (b1 as u128);
    let p2 = (a1 as u128) * (b0 as u128);
    let p3 = (a1 as u128) * (b1 as u128);

    let w0 = p0 as u64;
    let w1a = (p0 >> 64) as u64;

    let w1b = p1 as u64;
    let w1c = p2 as u64;
    let (w1_sum1, c1) = w1a.overflowing_add(w1b);
    let (w1, c2) = w1_sum1.overflowing_add(w1c);
    let carry_w1 = (c1 as u64) + (c2 as u64);

    let w2a = (p1 >> 64) as u64;
    let w2b = (p2 >> 64) as u64;
    let w2c = p3 as u64;
    let (w2_sum1, c3) = w2a.overflowing_add(w2b);
    let (w2_sum2, c4) = w2_sum1.overflowing_add(w2c);
    let (w2, c5) = w2_sum2.overflowing_add(carry_w1);
    let carry_w2 = (c3 as u128) + (c4 as u128) + (c5 as u128);

    let w3 = (p3 >> 64) + carry_w2;
    let hi = (w3 << 64) | (w2 as u128);
    let lo = ((w1 as u128) << 64) | (w0 as u128);
    (hi, lo)
}

#[inline]
fn gkr_reduce_u256(mut hi: u128, mut lo: u128) -> u128 {
    while hi != 0 {
        let (m_hi, m_lo) = mul_u128_full(hi, GKR_MODULUS_C);
        let (sum_lo, carry) = lo.overflowing_add(m_lo);
        let sum_hi = m_hi.wrapping_add(carry as u128);
        lo = sum_lo;
        hi = sum_hi;
    }
    if lo >= GKR_MODULUS {
        lo - GKR_MODULUS
    } else {
        lo
    }
}

#[inline]
fn gkr_add(a: u128, b: u128) -> u128 {
    let (sum, carry) = a.overflowing_add(b);
    gkr_reduce_u256(carry as u128, sum)
}

#[inline]
fn gkr_sub(a: u128, b: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        GKR_MODULUS - (b - a)
    }
}

#[inline]
fn gkr_mul(a: u128, b: u128) -> u128 {
    let (hi, lo) = mul_u128_full(a, b);
    gkr_reduce_u256(hi, lo)
}

#[inline]
fn gkr_square(a: u128) -> u128 {
    gkr_mul(a, a)
}

#[inline]
fn gkr_canonicalize(x: u128) -> u128 {
    if x >= GKR_MODULUS { x - GKR_MODULUS } else { x }
}

#[inline]
pub fn gkr_canonicalize_u128(x: u128) -> u128 {
    gkr_canonicalize(x)
}

#[inline]
fn gkr_from_hash(hash: [u8; 32]) -> u128 {
    let mut hi_bytes = [0u8; 16];
    let mut lo_bytes = [0u8; 16];
    hi_bytes.copy_from_slice(&hash[0..16]);
    lo_bytes.copy_from_slice(&hash[16..32]);
    let hi = u128::from_be_bytes(hi_bytes);
    let lo = u128::from_be_bytes(lo_bytes);
    gkr_reduce_u256(hi, lo)
}

#[inline]
pub fn gkr_from_bytes32_mod_order(bytes: &[u8; 32]) -> u128 {
    gkr_from_hash(*bytes)
}

#[inline]
fn u128_to_u256_be(x: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&x.to_be_bytes());
    out
}

#[inline]
fn u256_be_to_u128(x: &[u8; 32]) -> Option<u128> {
    if x[0..16].iter().any(|b| *b != 0) {
        return None;
    }
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&x[16..32]);
    Some(u128::from_be_bytes(lo))
}

#[inline]
pub fn gkr_u128_to_bytes32_be(x: u128) -> [u8; 32] {
    u128_to_u256_be(x)
}

#[inline]
pub fn gkr_bytes32_to_u128(x: &[u8; 32]) -> Option<u128> {
    u256_be_to_u128(x)
}

#[inline]
fn is_canonical_u128(x: u128) -> bool {
    x < GKR_MODULUS
}

#[inline]
fn push_u128_be(out: &mut Vec<u8>, x: u128) {
    out.extend_from_slice(&x.to_be_bytes());
}

#[inline]
fn read_u128_be_at(buf: &[u8], offset: usize) -> Option<u128> {
    let slice = buf.get(offset..offset + 16)?;
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(slice);
    Some(u128::from_be_bytes(bytes))
}

#[inline]
fn u128_to_bytes16_be(x: u128) -> [u8; 16] {
    x.to_be_bytes()
}

#[inline]
fn pack_u128_pair_be(a: u128, b: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&a.to_be_bytes());
    out[16..32].copy_from_slice(&b.to_be_bytes());
    out
}

#[inline]
fn unpack_u128_pair_be(x: &[u8; 32]) -> (u128, u128) {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&x[0..16]);
    lo.copy_from_slice(&x[16..32]);
    (u128::from_be_bytes(hi), u128::from_be_bytes(lo))
}

#[inline]
fn artifact_tag(commitment: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(commitment);
    buf[32..64].copy_from_slice(point);
    keccak256(&buf)
}

#[inline]
fn keccak_u128(x: &u128) -> [u8; 32] {
    keccak256(&u128_to_bytes16_be(*x))
}

#[inline]
fn keccak_u128_pair(a: &u128, b: &u128) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0..16].copy_from_slice(&u128_to_bytes16_be(*a));
    buf[16..32].copy_from_slice(&u128_to_bytes16_be(*b));
    keccak256(&buf)
}

fn derive_init_claim(seed: &[u8]) -> u128 {
    let mut input = Vec::with_capacity(GLYPH_GKR_INIT_DOMAIN.len() + seed.len());
    input.extend_from_slice(GLYPH_GKR_INIT_DOMAIN);
    input.extend_from_slice(seed);
    let h = keccak256(&input);
    gkr_from_hash(h)
}

fn derive_coeff(seed: &[u8], round: u32, which: u8, r: &u128, claim: &u128) -> u128 {
    let mut input = Vec::with_capacity(
        GLYPH_GKR_COEFF_DOMAIN.len() + seed.len() + 4 + 1 + 32 + 32,
    );
    input.extend_from_slice(GLYPH_GKR_COEFF_DOMAIN);
    input.extend_from_slice(seed);
    input.extend_from_slice(&round.to_be_bytes());
    input.push(which);
    input.extend_from_slice(&u128_to_u256_be(*r));
    input.extend_from_slice(&u128_to_u256_be(*claim));
    let h = keccak256(&input);
    gkr_from_hash(h)
}

fn derive_toy_linear_coeff(seed: &[u8], idx: u32) -> u128 {
    let mut input = Vec::with_capacity(GLYPH_GKR_TOY_LIN_DOMAIN.len() + seed.len() + 4);
    input.extend_from_slice(GLYPH_GKR_TOY_LIN_DOMAIN);
    input.extend_from_slice(seed);
    input.extend_from_slice(&idx.to_be_bytes());
    gkr_from_hash(keccak256(&input))
}

fn derive_toy_instance_seed32(base_seed: &[u8], idx: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(GLYPH_GKR_TOY_FOLD_SEED_DOMAIN.len() + base_seed.len() + 4);
    input.extend_from_slice(GLYPH_GKR_TOY_FOLD_SEED_DOMAIN);
    input.extend_from_slice(base_seed);
    input.extend_from_slice(&idx.to_be_bytes());
    keccak256(&input)
}

fn toy_instance_digest(seed32: &[u8; 32], rounds: usize, statement: &u128) -> [u8; 32] {
    let rounds_u32 = match usize_to_u32(rounds) {
        Some(v) => v,
        None => {
            debug_assert!(false, "rounds exceeds u32 for toy instance digest");
            0u32
        }
    };
    let mut input = Vec::with_capacity(GLYPH_GKR_TOY_FOLD_INSTANCE_DOMAIN.len() + 32 + 4 + 32);
    input.extend_from_slice(GLYPH_GKR_TOY_FOLD_INSTANCE_DOMAIN);
    input.extend_from_slice(seed32);
    input.extend_from_slice(&rounds_u32.to_be_bytes());
    input.extend_from_slice(&u128_to_u256_be(*statement));
    keccak256(&input)
}

fn derive_toy_basefold_root(base_digests: &[[u8; 32]]) -> [u8; 32] {
    assert!(!base_digests.is_empty(), "derive_toy_basefold_root: must have >= 1 instance");
    let mut input = Vec::with_capacity(GLYPH_GKR_TOY_BASEFOLD_ROOT_DOMAIN.len() + 32 * base_digests.len());
    input.extend_from_slice(GLYPH_GKR_TOY_BASEFOLD_ROOT_DOMAIN);
    for d in base_digests {
        input.extend_from_slice(d);
    }
    keccak256(&input)
}

fn derive_toy_basefold_alpha(root: &[u8; 32], idx: u32) -> u128 {
    let mut input = Vec::with_capacity(GLYPH_GKR_TOY_BASEFOLD_ALPHA_DOMAIN.len() + 32 + 4 + 4);
    input.extend_from_slice(GLYPH_GKR_TOY_BASEFOLD_ALPHA_DOMAIN);
    input.extend_from_slice(root);
    input.extend_from_slice(&idx.to_be_bytes());

    for ctr in 0u32..32 {
        let mut attempt = input.clone();
        attempt.extend_from_slice(&ctr.to_be_bytes());
        let alpha = gkr_from_hash(keccak256(&attempt));
        if alpha != 0 {
            return alpha;
        }
    }
    debug_assert!(false, "derive_toy_basefold_alpha: failed to derive nonzero alpha");
    1u128
}

fn derive_toy_basefold_weights(base_digests: &[[u8; 32]]) -> Vec<u128> {
    let root = derive_toy_basefold_root(base_digests);
    base_digests
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let idx = usize_to_u32(i).unwrap_or_else(|| {
                debug_assert!(false, "instance index exceeds u32");
                0u32
            });
            derive_toy_basefold_alpha(&root, idx)
        })
        .collect()
}

fn eval_toy_quadratic(lin_coeffs: &[u128], statement: &u128, point: &[u128]) -> u128 {
    debug_assert_eq!(lin_coeffs.len(), point.len() + 1);
    let mut acc = gkr_add(lin_coeffs[0], *statement);
    for (i, x) in point.iter().enumerate() {
        acc = gkr_add(acc, gkr_mul(lin_coeffs[i + 1], *x));
    }
    gkr_square(acc)
}

fn interpolate_quadratic_power_basis_from_values(y0: u128, y1: u128, y2: u128) -> (u128, u128, u128) {
    // Interpolate g(t) = c0 + c1*t + c2*t^2 from values at t in {0,1,2}.
    // Using forward differences for unit steps:
    //   Δ^2 y0 = y2 - 2y1 + y0 = 2*c2
    //   Δ y0 = y1 - y0 = c1 + c2
    let dy0 = gkr_sub(y1, y0);
    let two_y1 = gkr_mul(2u128, y1);
    let d2y0 = gkr_add(gkr_sub(y2, two_y1), y0);

    let c2 = gkr_mul(d2y0, GKR_INV2);
    let c1 = gkr_sub(dy0, c2);
    let c0 = y0;
    (c0, c1, c2)
}

fn eval_quadratic_power_basis(c0: &u128, c1: &u128, c2: &u128, r: &u128) -> u128 {
    // c0 + r*(c1 + r*c2)
    let acc = gkr_add(gkr_mul(*c2, *r), *c1);
    gkr_add(gkr_mul(acc, *r), *c0)
}

fn sumcheck_arity8_constraint(c0: &u128, c1: &u128, c2: &u128) -> u128 {
    // g(0) + ... + g(7) for g(t)=c0+c1 t+c2 t^2
    // Sum t^0: 8*c0
    // Sum t^1: (0+...+7) = 28 -> 28*c1
    // Sum t^2: (0^2+...+7^2) = 140 -> 140*c2
    gkr_add(
        gkr_add(gkr_mul(8u128, *c0), gkr_mul(28u128, *c1)),
        gkr_mul(140u128, *c2),
    )
}

fn recover_c2_from_sumcheck_claim_arity8(
    current_claim: &u128,
    c0: &u128,
    c1: &u128,
) -> u128 {
    // From:
    //   current_claim = 8*c0 + 28*c1 + 140*c2
    // Derive:
    //   c2 = (current_claim - (8*c0 + 28*c1)) * inv140
    let partial = gkr_add(gkr_mul(8u128, *c0), gkr_mul(28u128, *c1));
    gkr_mul(gkr_sub(*current_claim, partial), GKR_INV140)
}

fn update_challenge(r: &u128, c0: &u128, c1: &u128, c2: &u128) -> u128 {
    let mix_val = *c0 ^ *c1 ^ *c2;
    let mut buf = [0u8; 32];
    buf[0..16].copy_from_slice(&u128_to_bytes16_be(*r));
    buf[16..32].copy_from_slice(&u128_to_bytes16_be(mix_val));
    gkr_from_hash(keccak256(&buf))
}

fn u64_to_u256_be(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}

fn addr20_to_u256_be(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(addr);
    out
}

pub fn binding_meta(
    chainid: u64,
    contract_addr: [u8; 20],
    initial_claim: &u128,
    expected_final: &u128,
) -> [u8; 32] {
    // Must match Solidity:
    //   keccak256(BIND_DOMAIN || chainid || address(this) || initial_claim || expected_final)
    // where BIND_DOMAIN = keccak256("GLYPH_GKR_BIND_UNBOUND").
    let bind_domain = gkr_domain_hash(&GKR_BIND_DOMAIN_UNBOUND_HASH, GLYPH_GKR_BIND_DOMAIN_UNBOUND);
    let mut buf = [0u8; 32 * 3 + 16 * 2];
    buf[0..32].copy_from_slice(&bind_domain);
    buf[32..64].copy_from_slice(&u64_to_u256_be(chainid));
    buf[64..96].copy_from_slice(&addr20_to_u256_be(&contract_addr));
    buf[96..112].copy_from_slice(&u128_to_bytes16_be(*initial_claim));
    buf[112..128].copy_from_slice(&u128_to_bytes16_be(*expected_final));
    keccak256(&buf)
}

pub fn binding_meta_statement(
    chainid: u64,
    contract_addr: [u8; 20],
    statement: &u128,
    initial_claim: &u128,
    expected_final: &u128,
) -> [u8; 32] {
    // Must match Solidity:
    //   keccak256(BIND_DOMAIN_STATEMENT || chainid || address(this) || statement || initial_claim || expected_final)
    let bind_domain = gkr_domain_hash(&GKR_BIND_DOMAIN_STATEMENT_HASH, GLYPH_GKR_BIND_DOMAIN_STATEMENT);
    let mut buf = [0u8; 32 * 3 + 16 * 3];
    buf[0..32].copy_from_slice(&bind_domain);
    buf[32..64].copy_from_slice(&u64_to_u256_be(chainid));
    buf[64..96].copy_from_slice(&addr20_to_u256_be(&contract_addr));
    buf[96..112].copy_from_slice(&u128_to_bytes16_be(*statement));
    buf[112..128].copy_from_slice(&u128_to_bytes16_be(*initial_claim));
    buf[128..144].copy_from_slice(&u128_to_bytes16_be(*expected_final));
    keccak256(&buf)
}

pub fn binding_meta_stmt_poly(
    chainid: u64,
    contract_addr: [u8; 20],
    statement: &u128,
    initial_claim: &u128,
) -> [u8; 32] {
    // Must match Solidity:
    //   keccak256(BIND_DOMAIN_STMT_POLY || chainid || address(this) || statement || initial_claim)
    // where BIND_DOMAIN_STMT_POLY = keccak256("GLYPH_GKR_BIND_STMT_POLY").
    let bind_domain = gkr_domain_hash(&GKR_BIND_DOMAIN_STMT_POLY_HASH, GLYPH_GKR_BIND_DOMAIN_STMT_POLY);
    let mut buf = [0u8; 32 * 3 + 16 * 2];
    buf[0..32].copy_from_slice(&bind_domain);
    buf[32..64].copy_from_slice(&u64_to_u256_be(chainid));
    buf[64..96].copy_from_slice(&addr20_to_u256_be(&contract_addr));
    buf[96..112].copy_from_slice(&u128_to_bytes16_be(*statement));
    buf[112..128].copy_from_slice(&u128_to_bytes16_be(*initial_claim));
    keccak256(&buf)
}

fn initial_challenge_unbound(initial_claim: &u128) -> u128 {
    gkr_from_hash(keccak_u128(initial_claim))
}

fn initial_challenge_statement_bound(initial_claim: &u128, statement: &u128) -> u128 {
    gkr_from_hash(keccak_u128_pair(initial_claim, statement))
}

fn initial_challenge_artifact_bound_env(
    chainid: u64,
    contract_addr: [u8; 20],
    artifact_tag: &[u8; 32],
    claim: &u128,
    initial_claim: &u128,
) -> u128 {
    let mut buf = [0u8; 32 * 4];
    buf[0..32].copy_from_slice(&u64_to_u256_be(chainid));
    buf[32..64].copy_from_slice(&addr20_to_u256_be(&contract_addr));
    buf[64..96].copy_from_slice(artifact_tag);
    let claim_initial = pack_u128_pair_be(*claim, *initial_claim);
    buf[96..128].copy_from_slice(&claim_initial);
    gkr_from_hash(keccak256(&buf))
}

fn derive_stmt_poly_lin_base_and_step(statement: &u128) -> (u128, u128) {
    // Must match Solidity:
    //   lin0 = keccak256(LIN_DOMAIN || statement || 0) mod q
    //   lin_step = keccak256(LIN_DOMAIN || statement || 1) mod q
    // where LIN_DOMAIN = keccak256("GLYPH_GKR_STMT_POLY_LIN").
    let lin_domain = gkr_domain_hash(&GKR_STMT_POLY_LIN_HASH, GLYPH_GKR_STMT_POLY_LIN_DOMAIN);
    let mut buf = [0u8; 32 * 3];
    buf[0..32].copy_from_slice(&lin_domain);
    buf[32..64].copy_from_slice(&u128_to_u256_be(*statement));
    buf[64..96].copy_from_slice(&u64_to_u256_be(0));
    let lin0 = gkr_from_hash(keccak256(&buf));
    buf[64..96].copy_from_slice(&u64_to_u256_be(1));
    let lin_step = gkr_from_hash(keccak256(&buf));
    (lin0, lin_step)
}

fn derive_artifact_poly_lin_base_and_step(artifact_tag: &[u8; 32], claim: &u128) -> (u128, u128) {
    // Must match Solidity:
    //   lin_hash = keccak256(LIN_DOMAIN || artifact_tag || claim) mod q
    //   lin0 = lin_hash[0..16] mod q
    //   lin_step = lin_hash[16..32] mod q
    // where:
    //   LIN_DOMAIN = keccak256("GLYPH_GKR_ARTIFACT_LIN")
    //   artifact_tag = keccak256(commitment || point)
    let lin_domain = gkr_domain_hash(&GKR_ARTIFACT_LIN_HASH, GLYPH_GKR_ARTIFACT_LIN_DOMAIN);
    let mut buf = [0u8; 80];
    buf[0..32].copy_from_slice(&lin_domain);
    buf[32..64].copy_from_slice(artifact_tag);
    buf[64..80].copy_from_slice(&u128_to_bytes16_be(*claim));
    let lin_hash = keccak256(&buf);
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&lin_hash[0..16]);
    lo.copy_from_slice(&lin_hash[16..32]);
    let lin0 = gkr_canonicalize(u128::from_be_bytes(hi));
    let lin_step = gkr_canonicalize(u128::from_be_bytes(lo));
    (lin0, lin_step)
}

fn build_stmt_poly_lin_coeffs(statement: &u128, rounds: usize) -> Vec<u128> {
    let (lin0, lin_step) = derive_stmt_poly_lin_base_and_step(statement);
    build_lin_coeffs(lin0, lin_step, rounds)
}

fn build_artifact_poly_lin_coeffs(artifact_tag: &[u8; 32], claim: &u128, rounds: usize) -> Vec<u128> {
    let (lin0, lin_step) = derive_artifact_poly_lin_base_and_step(artifact_tag, claim);
    build_lin_coeffs(lin0, lin_step, rounds)
}

fn gkr_pow(mut base: u128, mut exp: usize) -> u128 {
    let mut acc = 1u128;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = gkr_mul(acc, base);
        }
        base = gkr_mul(base, base);
        exp >>= 1;
    }
    acc
}

fn build_lin_coeffs(lin0: u128, lin_step: u128, rounds: usize) -> Vec<u128> {
    let total = rounds.saturating_add(1);
    let mut coeffs = vec![0u128; total];
    if total == 0 {
        return coeffs;
    }
    coeffs[0] = lin0;
    if rounds == 0 {
        return coeffs;
    }
    if rounds < 128 {
        let mut lin = lin0;
        for slot in coeffs.iter_mut().skip(1).take(rounds) {
            lin = gkr_mul(lin, lin_step);
            *slot = lin;
        }
        return coeffs;
    }
    ensure_two_thread_pool();
    let chunk = 128usize;
    let chunks = total.div_ceil(chunk);
    let step_chunk = gkr_pow(lin_step, chunk);
    let mut starts = vec![0u128; chunks];
    starts[0] = lin0;
    for i in 1..chunks {
        starts[i] = gkr_mul(starts[i - 1], step_chunk);
    }
    coeffs
        .par_chunks_mut(chunk)
        .enumerate()
        .for_each(|(chunk_idx, out_chunk)| {
            let mut lin = starts[chunk_idx];
            for slot in out_chunk.iter_mut() {
                *slot = lin;
                lin = gkr_mul(lin, lin_step);
            }
        });
    coeffs
}

#[allow(dead_code)]
fn stmt_poly_eval_at_point(statement: &u128, lin_coeffs: &[u128], point: &[u128]) -> u128 {
    debug_assert_eq!(lin_coeffs.len(), point.len() + 1);
    let mut acc = gkr_add(lin_coeffs[0], *statement);
    for (i, x) in point.iter().enumerate() {
        acc = gkr_add(acc, gkr_mul(lin_coeffs[i + 1], *x));
    }
    gkr_square(acc)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QuadraticMoment {
    m0: u128,
    m1: u128,
    m2: u128,
}

fn quadratic_moment_empty() -> QuadraticMoment {
    QuadraticMoment {
        m0: 1u128,
        m1: 0u128,
        m2: 0u128,
    }
}

fn quadratic_moment_add_coeff(next: QuadraticMoment, a: &u128) -> QuadraticMoment {
    // If X is the random sum over the next variables, then for a new variable t:
    // X' = X + a*t, t ∈ {0..7}. We keep M_k = sum X^k over all assignments.
    //
    // Power sums for t ∈ {0..7}:
    //   s0 = 8, s1 = 28, s2 = 140
    //
    // M0' = s0*M0
    // M1' = s0*M1 + a*s1*M0
    // M2' = s0*M2 + 2*a*s1*M1 + a^2*s2*M0
    let s0 = 8u128;
    let s1 = 28u128;
    let s2 = 140u128;
    let two = 2u128;
    let a2 = gkr_mul(*a, *a);
    QuadraticMoment {
        m0: gkr_mul(next.m0, s0),
        m1: gkr_add(gkr_mul(next.m1, s0), gkr_mul(gkr_mul(*a, s1), next.m0)),
        m2: gkr_add(
            gkr_add(gkr_mul(next.m2, s0), gkr_mul(gkr_mul(gkr_mul(*a, s1), two), next.m1)),
            gkr_mul(gkr_mul(a2, s2), next.m0),
        ),
    }
}

fn quadratic_sum_from_moments(u: &u128, m: QuadraticMoment) -> u128 {
    // sum_{X} (u + X)^2 where moments m_k = sum X^k.
    // (u+X)^2 = u^2 + 2u X + X^2
    let two = 2u128;
    let u2 = gkr_mul(*u, *u);
    gkr_add(
        gkr_add(gkr_mul(m.m0, u2), gkr_mul(gkr_mul(two, *u), m.m1)),
        m.m2,
    )
}

fn stmt_poly_univariate_from_suffix(
    fixed_sum: &u128,
    a_i: &u128,
    suffix: QuadraticMoment,
    t: &u128,
) -> u128 {
    let u = gkr_add(*fixed_sum, gkr_mul(*a_i, *t));
    quadratic_sum_from_moments(&u, suffix)
}

pub fn prove_packed_stmt_poly_sumcheck(statement: &u128, rounds: usize) -> PackedGkrProof {
    debug_assert!(rounds >= 1, "prove_packed_stmt_poly_sumcheck: rounds must be >= 1");
    if rounds == 0 {
        debug_assert!(false, "prove_packed_stmt_poly_sumcheck: rounds out of range");
        return empty_packed_gkr_proof();
    }

    let lin_coeffs = build_stmt_poly_lin_coeffs(statement, rounds);

    // a0 includes the statement offset (matches on-chain definition).
    let a0 = gkr_add(lin_coeffs[0], *statement);
    let a_vec = &lin_coeffs[1..];

    // Precompute suffix moments for X = sum_{j>=i} a_j * t_j, t_j ∈ {0..7}.
    let mut suffix = vec![quadratic_moment_empty(); rounds + 1];
    for i_rev in 0..rounds {
        let i = rounds - 1 - i_rev;
        suffix[i] = quadratic_moment_add_coeff(suffix[i + 1], &a_vec[i]);
    }

    // Initial claim: sum over t in {0..7}^rounds.
    let initial_claim = quadratic_sum_from_moments(&a0, suffix[0]);

    let mut current = initial_claim;
    let mut r_state = initial_challenge_statement_bound(&current, statement);

    let mut fixed_sum = a0;
    let mut out_rounds = Vec::with_capacity(rounds);

    for i in 0..rounds {
        let a_i = a_vec[i];
        let suf = suffix[i + 1];

        let y0 = stmt_poly_univariate_from_suffix(&fixed_sum, &a_i, suf, &0u128);
        let y1 = stmt_poly_univariate_from_suffix(&fixed_sum, &a_i, suf, &1u128);
        let y2 = stmt_poly_univariate_from_suffix(&fixed_sum, &a_i, suf, &2u128);
        let (c0, c1, c2) = interpolate_quadratic_power_basis_from_values(y0, y1, y2);
        debug_assert_eq!(sumcheck_arity8_constraint(&c0, &c1, &c2), current);

        r_state = update_challenge(&r_state, &c0, &c1, &c2);
        fixed_sum = gkr_add(fixed_sum, gkr_mul(a_i, r_state));
        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r_state);

        out_rounds.push(PackedRound { c0, c1, c2 });
    }

    let expected_final = gkr_square(fixed_sum);
    debug_assert_eq!(expected_final, current);

    PackedGkrProof {
        initial_claim,
        rounds: out_rounds,
        expected_final: current,
    }
}

pub fn prove_packed_artifact_poly_sumcheck(
    commitment: &[u8; 32],
    point: &[u8; 32],
    claim: &u128,
    chainid: u64,
    contract_addr: [u8; 20],
    rounds: usize,
) -> PackedGkrProof {
    let tag = artifact_tag(commitment, point);
    prove_packed_artifact_poly_sumcheck_with_tag(&tag, claim, chainid, contract_addr, rounds)
}

pub fn prove_packed_artifact_poly_sumcheck_with_tag(
    artifact_tag: &[u8; 32],
    claim: &u128,
    chainid: u64,
    contract_addr: [u8; 20],
    rounds: usize,
) -> PackedGkrProof {
    debug_assert!(
        rounds >= 1,
        "prove_packed_artifact_poly_sumcheck_with_tag: rounds must be >= 1"
    );
    if rounds == 0 {
        debug_assert!(false, "prove_packed_artifact_poly_sumcheck_with_tag: rounds out of range");
        return empty_packed_gkr_proof();
    }

    debug_assert!(
        is_canonical_u128(*claim),
        "prove_packed_artifact_poly_sumcheck_with_tag: claim must be canonical mod p"
    );
    if !is_canonical_u128(*claim) {
        debug_assert!(false, "prove_packed_artifact_poly_sumcheck_with_tag: claim not canonical");
        return empty_packed_gkr_proof();
    }

    let lin_coeffs = build_artifact_poly_lin_coeffs(artifact_tag, claim, rounds);

    let a0 = gkr_add(lin_coeffs[0], *claim);
    let a_vec = &lin_coeffs[1..];

    let mut suffix = vec![quadratic_moment_empty(); rounds + 1];
    for i_rev in 0..rounds {
        let i = rounds - 1 - i_rev;
        suffix[i] = quadratic_moment_add_coeff(suffix[i + 1], &a_vec[i]);
    }

    let initial_claim = quadratic_sum_from_moments(&a0, suffix[0]);

    let mut current = initial_claim;
    let mut r_state =
        initial_challenge_artifact_bound_env(chainid, contract_addr, artifact_tag, claim, &current);

    let mut fixed_sum = a0;
    let mut out_rounds = Vec::with_capacity(rounds);

    for i in 0..rounds {
        let a_i = a_vec[i];
        let suf = suffix[i + 1];

        let y0 = stmt_poly_univariate_from_suffix(&fixed_sum, &a_i, suf, &0u128);
        let y1 = stmt_poly_univariate_from_suffix(&fixed_sum, &a_i, suf, &1u128);
        let y2 = stmt_poly_univariate_from_suffix(&fixed_sum, &a_i, suf, &2u128);
        let (c0, c1, c2) = interpolate_quadratic_power_basis_from_values(y0, y1, y2);
        debug_assert_eq!(sumcheck_arity8_constraint(&c0, &c1, &c2), current);

        r_state = update_challenge(&r_state, &c0, &c1, &c2);
        fixed_sum = gkr_add(fixed_sum, gkr_mul(a_i, r_state));
        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r_state);

        out_rounds.push(PackedRound { c0, c1, c2 });
    }

    let expected_final = gkr_square(fixed_sum);
    debug_assert_eq!(expected_final, current);

    PackedGkrProof {
        initial_claim,
        rounds: out_rounds,
        expected_final: current,
    }
}

pub fn encode_stmt_poly_bound_packed_calldata_be(
    proof: &PackedGkrProof,
    chainid: u64,
    contract_addr: [u8; 20],
    statement: &u128,
    _truncated: bool,
) -> Vec<u8> {
    let meta = binding_meta_stmt_poly(chainid, contract_addr, statement, &proof.initial_claim);

    let per_round_bytes = 32;
    let mut out = Vec::with_capacity(32 * 3 + per_round_bytes * proof.rounds.len());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&u128_to_u256_be(*statement));
    out.extend_from_slice(&u128_to_u256_be(proof.initial_claim));

    for r in &proof.rounds {
        push_u128_be(&mut out, r.c0);
        push_u128_be(&mut out, r.c1);
    }
    out
}

pub fn encode_artifact_poly_bound_packed_calldata_be(
    proof: &PackedGkrProof,
    chainid: u64,
    contract_addr: [u8; 20],
    commitment: &[u8; 32],
    point: &[u8; 32],
    claim: &u128,
    _truncated: bool,
) -> Vec<u8> {
    let _ = (chainid, contract_addr);
    let tag = artifact_tag(commitment, point);
    encode_artifact_poly_bound_packed_calldata_be_with_tag(proof, &tag, claim, _truncated)
}

pub fn encode_artifact_poly_bound_packed_calldata_be_with_tag(
    proof: &PackedGkrProof,
    artifact_tag: &[u8; 32],
    claim: &u128,
    _truncated: bool,
) -> Vec<u8> {
    let tag = *artifact_tag;

    let per_round_bytes = 32;
    let mut out = Vec::with_capacity(32 * 2 + per_round_bytes * proof.rounds.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&pack_u128_pair_be(*claim, proof.initial_claim));

    for r in &proof.rounds {
        push_u128_be(&mut out, r.c0);
        push_u128_be(&mut out, r.c1);
    }
    out
}

pub fn verify_stmt_poly_packed_calldata_be(
    calldata: &[u8],
    chainid: u64,
    contract_addr: [u8; 20],
) -> bool {
    // header(96 bytes) + 1 packed round(32 bytes)
    if calldata.len() < 128 {
        return false;
    }
    let meta: [u8; 32] = match calldata.get(0..32).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };
    let statement_be: [u8; 32] = match calldata.get(32..64).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };
    let initial_be: [u8; 32] = match calldata.get(64..96).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };

    let statement = match u256_be_to_u128(&statement_be) {
        Some(v) if is_canonical_u128(v) => v,
        _ => return false,
    };
    let initial_claim = match u256_be_to_u128(&initial_be) {
        Some(v) if is_canonical_u128(v) => v,
        _ => return false,
    };

    let expect_meta = binding_meta_stmt_poly(chainid, contract_addr, &statement, &initial_claim);
    if meta != expect_meta {
        return false;
    }

    let rem_bytes = calldata.len() - 96;
    let rounds = if rem_bytes.is_multiple_of(32) {
        rem_bytes / 32
    } else {
        return false;
    };
    if rounds == 0 {
        return false;
    }

    let lin_coeffs = build_stmt_poly_lin_coeffs(&statement, rounds);
    let lin0 = lin_coeffs[0];

    let mut current = initial_claim;
    let mut r_state = initial_challenge_statement_bound(&current, &statement);
    let mut eval_lin = 0u128;

    for i in 0..rounds {
        let off = 96 + i * 32;
        let c0 = match read_u128_be_at(calldata, off) {
            Some(v) => v,
            None => return false,
        };
        let c1 = match read_u128_be_at(calldata, off + 16) {
            Some(v) => v,
            None => return false,
        };
        if !is_canonical_u128(c0) || !is_canonical_u128(c1) {
            return false;
        }
        let c2 = recover_c2_from_sumcheck_claim_arity8(&current, &c0, &c1);

        r_state = update_challenge(&r_state, &c0, &c1, &c2);

        let lin_i = lin_coeffs[i + 1];
        eval_lin = gkr_add(eval_lin, gkr_mul(lin_i, r_state));

        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r_state);
    }

    let base = gkr_add(gkr_add(lin0, statement), eval_lin);
    let expected_final = gkr_square(base);
    current == expected_final
}

pub fn verify_artifact_poly_packed_calldata_be(
    calldata: &[u8],
    chainid: u64,
    contract_addr: [u8; 20],
) -> bool {
    // Header(96 bytes) + one packed round(32 bytes).
    // Header(64 bytes) + one packed round(32 bytes).
    if calldata.len() < 96 {
        return false;
    }
    let tag: [u8; 32] = match calldata.get(0..32).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };
    let claim_initial_be: [u8; 32] = match calldata.get(32..64).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };

    let (claim, initial_claim) = unpack_u128_pair_be(&claim_initial_be);
    if !is_canonical_u128(claim) || !is_canonical_u128(initial_claim) {
        return false;
    }

    let rem_bytes = calldata.len() - 64;
    let rounds = if rem_bytes.is_multiple_of(32) {
        rem_bytes / 32
    } else {
        return false;
    };
    if rounds == 0 {
        return false;
    }

    let lin_coeffs = build_artifact_poly_lin_coeffs(&tag, &claim, rounds);
    let lin0 = lin_coeffs[0];

    let mut current = initial_claim;
    let mut r_state = initial_challenge_artifact_bound_env(chainid, contract_addr, &tag, &claim, &current);
    let mut eval_lin = 0u128;

    for i in 0..rounds {
        let off = 64 + i * 32;
        let c0 = match read_u128_be_at(calldata, off) {
            Some(v) => v,
            None => return false,
        };
        let c1 = match read_u128_be_at(calldata, off + 16) {
            Some(v) => v,
            None => return false,
        };
        if !is_canonical_u128(c0) || !is_canonical_u128(c1) {
            return false;
        }
        let c2 = recover_c2_from_sumcheck_claim_arity8(&current, &c0, &c1);

        r_state = update_challenge(&r_state, &c0, &c1, &c2);

        let lin_i = lin_coeffs[i + 1];
        eval_lin = gkr_add(eval_lin, gkr_mul(lin_i, r_state));

        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r_state);
    }

    let base = gkr_add(gkr_add(lin0, claim), eval_lin);
    let expected_final = gkr_square(base);
    current == expected_final
}

pub fn prove_packed(seed: &[u8], rounds: usize) -> PackedGkrProof {
    debug_assert!(rounds >= 1, "prove_packed: rounds must be >= 1");
    if rounds == 0 || rounds > u32::MAX as usize {
        debug_assert!(false, "prove_packed: rounds out of range");
        return empty_packed_gkr_proof();
    }

    let initial_claim = derive_init_claim(seed);
    let mut current = initial_claim;
    let mut r = initial_challenge_unbound(&current);

    let mut out_rounds = Vec::with_capacity(rounds);
    for i in 0..rounds {
        let round_u32 = i as u32;
        let c0 = derive_coeff(seed, round_u32, 0, &r, &current);
        let c1 = derive_coeff(seed, round_u32, 1, &r, &current);
        let c2 = recover_c2_from_sumcheck_claim_arity8(&current, &c0, &c1);

        // Fiat-Shamir challenge and next claim.
        r = update_challenge(&r, &c0, &c1, &c2);
        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r);

        out_rounds.push(PackedRound { c0, c1, c2 });
    }

    PackedGkrProof {
        initial_claim,
        rounds: out_rounds,
        expected_final: current,
    }
}

pub fn prove_packed_statement(seed: &[u8], rounds: usize, statement: &u128) -> PackedGkrProof {
    debug_assert!(rounds >= 1, "prove_packed_statement: rounds must be >= 1");
    if rounds == 0 || rounds > u32::MAX as usize {
        debug_assert!(false, "prove_packed_statement: rounds out of range");
        return empty_packed_gkr_proof();
    }

    let initial_claim = derive_init_claim(seed);
    let mut current = initial_claim;
    let mut r = initial_challenge_statement_bound(&current, statement);

    let mut out_rounds = Vec::with_capacity(rounds);
    for i in 0..rounds {
        let round_u32 = i as u32;
        let c0 = derive_coeff(seed, round_u32, 0, &r, &current);
        let c1 = derive_coeff(seed, round_u32, 1, &r, &current);
        let c2 = recover_c2_from_sumcheck_claim_arity8(&current, &c0, &c1);

        r = update_challenge(&r, &c0, &c1, &c2);
        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r);

        out_rounds.push(PackedRound { c0, c1, c2 });
    }

    PackedGkrProof {
        initial_claim,
        rounds: out_rounds,
        expected_final: current,
    }
}

pub fn prove_packed_toy_sumcheck(seed: &[u8], rounds: usize) -> PackedGkrProof {
    prove_packed_toy_sumcheck_inner(seed, rounds, None)
}

pub fn prove_packed_toy_sumcheck_statement(seed: &[u8], rounds: usize, statement: &u128) -> PackedGkrProof {
    prove_packed_toy_sumcheck_inner(seed, rounds, Some(statement))
}

pub fn prove_packed_toy_sumcheck_folded(seed: &[u8], rounds: usize, instances: usize) -> PackedGkrProof {
    prove_packed_toy_sumcheck_folded_inner(seed, rounds, instances, None)
}

pub fn prove_packed_toy_sumcheck_folded_statement(
    seed: &[u8],
    rounds: usize,
    instances: usize,
    statement: &u128,
) -> PackedGkrProof {
    prove_packed_toy_sumcheck_folded_inner(seed, rounds, instances, Some(statement))
}

fn prove_packed_toy_sumcheck_inner(seed: &[u8], rounds: usize, statement: Option<&u128>) -> PackedGkrProof {
    debug_assert!(rounds >= 1, "prove_packed_toy_sumcheck: rounds must be >= 1");
    debug_assert!(rounds <= 7, "prove_packed_toy_sumcheck: rounds too large for toy 8-ary enumeration");
    if rounds == 0 || rounds > 7 || rounds > u32::MAX as usize {
        debug_assert!(false, "prove_packed_toy_sumcheck: rounds out of range");
        return empty_packed_gkr_proof();
    }

    let statement_bound = statement.is_some();
    let statement = statement.copied().unwrap_or(0u128);

    let lin_coeffs: Vec<u128> = (0..=rounds)
        .map(|i| {
            let idx = i as u32;
            derive_toy_linear_coeff(seed, idx)
        })
        .collect();

    prove_toy_sumcheck_from_eval(rounds, statement_bound, &statement, |point| {
        eval_toy_quadratic(&lin_coeffs, &statement, point)
    })
}

fn prove_packed_toy_sumcheck_folded_inner(
    seed: &[u8],
    rounds: usize,
    instances: usize,
    statement: Option<&u128>,
) -> PackedGkrProof {
    debug_assert!(rounds >= 1, "prove_packed_toy_sumcheck_folded: rounds must be >= 1");
    debug_assert!(rounds <= 7, "prove_packed_toy_sumcheck_folded: rounds too large for toy 8-ary enumeration");
    debug_assert!(instances >= 1, "prove_packed_toy_sumcheck_folded: instances must be >= 1");
    debug_assert!(instances <= 64, "prove_packed_toy_sumcheck_folded: instances too large for toy implementation");
    if rounds == 0 || rounds > 7 || instances == 0 || instances > 64 || rounds > u32::MAX as usize {
        debug_assert!(false, "prove_packed_toy_sumcheck_folded: params out of range");
        return empty_packed_gkr_proof();
    }

    if instances == 1 {
        return prove_packed_toy_sumcheck_inner(seed, rounds, statement);
    }

    let statement_bound = statement.is_some();
    let statement = statement.copied().unwrap_or(0u128);

    let (lin_coeffs_per_instance, digests) = if instances >= 8 {
        ensure_two_thread_pool();
        let paired: Vec<(Vec<u128>, [u8; 32])> = (0..instances)
            .into_par_iter()
            .map(|i| {
                let idx = i as u32;
                let seed32 = derive_toy_instance_seed32(seed, idx);
                let lin_coeffs: Vec<u128> = (0..=rounds)
                    .map(|j| {
                        let j_u32 = j as u32;
                        derive_toy_linear_coeff(&seed32, j_u32)
                    })
                    .collect();
                let digest = toy_instance_digest(&seed32, rounds, &statement);
                (lin_coeffs, digest)
            })
            .collect();
        let mut lin_coeffs_per_instance = Vec::with_capacity(instances);
        let mut digests = Vec::with_capacity(instances);
        for (lin, dig) in paired {
            lin_coeffs_per_instance.push(lin);
            digests.push(dig);
        }
        (lin_coeffs_per_instance, digests)
    } else {
        let mut lin_coeffs_per_instance: Vec<Vec<u128>> = Vec::with_capacity(instances);
        let mut digests: Vec<[u8; 32]> = Vec::with_capacity(instances);
        for i in 0..instances {
            let idx = i as u32;
            let seed32 = derive_toy_instance_seed32(seed, idx);
            let lin_coeffs: Vec<u128> = (0..=rounds)
                .map(|j| {
                    let j_u32 = j as u32;
                    derive_toy_linear_coeff(&seed32, j_u32)
                })
                .collect();
            lin_coeffs_per_instance.push(lin_coeffs);
            digests.push(toy_instance_digest(&seed32, rounds, &statement));
        }
        (lin_coeffs_per_instance, digests)
    };

    let weights = derive_toy_basefold_weights(&digests);

    prove_toy_sumcheck_from_eval(rounds, statement_bound, &statement, |point| {
        let mut acc = 0u128;
        for (lin, w) in lin_coeffs_per_instance.iter().zip(weights.iter()) {
            acc = gkr_add(acc, gkr_mul(*w, eval_toy_quadratic(lin, &statement, point)));
        }
        acc
    })
}

fn prove_toy_sumcheck_from_eval(
    rounds: usize,
    statement_bound: bool,
    statement: &u128,
    mut eval: impl FnMut(&[u128]) -> u128,
) -> PackedGkrProof {
    let shift = match rounds.checked_mul(3).and_then(usize_to_u32) {
        Some(v) => v,
        None => {
            debug_assert!(false, "toy sumcheck rounds shift overflow");
            return empty_packed_gkr_proof();
        }
    };
    let total = match 1usize.checked_shl(shift) {
        Some(v) => v,
        None => {
            debug_assert!(false, "toy sumcheck total overflow");
            return empty_packed_gkr_proof();
        }
    };

    let mut point = vec![0u128; rounds];
    let mut initial_claim = 0u128;
    for mask in 0..total {
        for (j, slot) in point.iter_mut().take(rounds).enumerate() {
            let digit = (mask >> (3 * j)) & 7;
            *slot = digit as u128;
        }
        initial_claim = gkr_add(initial_claim, eval(&point));
    }

    let mut current = initial_claim;
    let mut r_state = if statement_bound {
        initial_challenge_statement_bound(&current, statement)
    } else {
        initial_challenge_unbound(&current)
    };

    let mut fixed = Vec::with_capacity(rounds);
    let mut out_rounds = Vec::with_capacity(rounds);

    for i in 0..rounds {
        point[..i].copy_from_slice(&fixed[..i]);

        let mut ys = [0u128; 3];
        for (t_idx, y) in ys.iter_mut().enumerate() {
            point[i] = t_idx as u128;
            let tail_len = rounds - i - 1;
            let tail_shift = match tail_len.checked_mul(3).and_then(usize_to_u32) {
                Some(v) => v,
                None => {
                    debug_assert!(false, "toy sumcheck tail shift overflow");
                    return empty_packed_gkr_proof();
                }
            };
            let tail_total = match 1usize.checked_shl(tail_shift) {
                Some(v) => v,
                None => {
                    debug_assert!(false, "toy sumcheck tail total overflow");
                    return empty_packed_gkr_proof();
                }
            };

            let mut sum = 0u128;
            for mask in 0..tail_total {
                for k in 0..tail_len {
                    let digit = (mask >> (3 * k)) & 7;
                    point[i + 1 + k] = digit as u128;
                }
                sum = gkr_add(sum, eval(&point));
            }
            *y = sum;
        }

        let (c0, c1, c2) = interpolate_quadratic_power_basis_from_values(ys[0], ys[1], ys[2]);
        assert_eq!(
            sumcheck_arity8_constraint(&c0, &c1, &c2),
            current,
            "toy sumcheck: sumcheck constraint mismatch at round {i}"
        );

        r_state = update_challenge(&r_state, &c0, &c1, &c2);
        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r_state);

        fixed.push(r_state);
        out_rounds.push(PackedRound { c0, c1, c2 });
    }

    PackedGkrProof {
        initial_claim,
        rounds: out_rounds,
        expected_final: current,
    }
}

pub fn encode_packed_calldata_be(proof: &PackedGkrProof) -> Vec<u8> {
    // Packed layout: initial + R*(c0,c1 as 2x16 bytes) + expected_final
    let mut out = Vec::with_capacity(64 + 32 * proof.rounds.len());
    out.extend_from_slice(&u128_to_u256_be(proof.initial_claim));
    for r in &proof.rounds {
        push_u128_be(&mut out, r.c0);
        push_u128_be(&mut out, r.c1);
    }
    out.extend_from_slice(&u128_to_u256_be(proof.expected_final));
    out
}

pub fn encode_packed_calldata_be_truncated(proof: &PackedGkrProof) -> Vec<u8> {
    encode_packed_calldata_be(proof)
}

pub fn encode_statement_bound_packed_calldata_be(
    proof: &PackedGkrProof,
    chainid: u64,
    contract_addr: [u8; 20],
    statement: &u128,
    truncated: bool,
) -> Vec<u8> {
    let meta = binding_meta_statement(chainid, contract_addr, statement, &proof.initial_claim, &proof.expected_final);
    let payload = if truncated {
        encode_packed_calldata_be_truncated(proof)
    } else {
        encode_packed_calldata_be(proof)
    };
    let mut out = Vec::with_capacity(64 + payload.len());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&u128_to_u256_be(*statement));
    out.extend_from_slice(&payload);
    out
}

pub fn verify_packed_calldata_be_with_binding_env(
    calldata: &[u8],
    chainid: u64,
    contract_addr: [u8; 20],
) -> bool {
    // Try statement-bound layout first if it is plausible, mirroring the Solidity disambiguation.
    if calldata.len() >= 160 {
        let meta: [u8; 32] = match calldata.get(0..32).and_then(|s| s.try_into().ok()) {
            Some(w) => w,
            None => return verify_packed_calldata_be(calldata),
        };
        let statement_u: [u8; 32] = match calldata.get(32..64).and_then(|s| s.try_into().ok()) {
            Some(w) => w,
            None => return verify_packed_calldata_be(calldata),
        };
        let statement = match u256_be_to_u128(&statement_u) {
            Some(v) if is_canonical_u128(v) => v,
            _ => return verify_packed_calldata_be(calldata),
        };
            let payload = &calldata[64..];
            if payload.len() >= 96 {
                let initial_u: [u8; 32] = match payload.get(0..32).and_then(|s| s.try_into().ok()) {
                    Some(w) => w,
                    None => return verify_packed_calldata_be(calldata),
                };
                let expected_u: [u8; 32] =
                    match payload.get(payload.len() - 32..).and_then(|s| s.try_into().ok()) {
                        Some(w) => w,
                        None => return verify_packed_calldata_be(calldata),
                    };
                let initial = match u256_be_to_u128(&initial_u) {
                    Some(v) if is_canonical_u128(v) => v,
                    _ => return verify_packed_calldata_be(calldata),
                };
                let expected = match u256_be_to_u128(&expected_u) {
                    Some(v) if is_canonical_u128(v) => v,
                    _ => return verify_packed_calldata_be(calldata),
                };
                    if meta == binding_meta_statement(chainid, contract_addr, &statement, &initial, &expected) {
                        let r0 = initial_challenge_statement_bound(&initial, &statement);
                        if verify_packed_payload_be_with_initial_r(payload, r0) {
                            return true;
                        }
                    }
            }
    }
    verify_packed_calldata_be(calldata)
}

fn verify_packed_payload_be_with_initial_r(calldata: &[u8], mut r: u128) -> bool {
    // Minimum (packed): initial(32) + one round(32) + expected_final(32) = 96 bytes.
    if calldata.len() < 96 {
        return false;
    }

    let rem = calldata.len() - 64;
    let rounds = if rem.is_multiple_of(32) && rem > 0 {
        rem / 32
    } else {
        return false;
    };
    if rounds == 0 {
        return false;
    }

    let claim_u: [u8; 32] = match calldata.get(0..32).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };
    let mut current = match u256_be_to_u128(&claim_u) {
        Some(v) if is_canonical_u128(v) => v,
        _ => return false,
    };

    for i in 0..rounds {
        let off = 32 + i * 32;
        let c0 = match read_u128_be_at(calldata, off) {
            Some(v) => v,
            None => return false,
        };
        let c1 = match read_u128_be_at(calldata, off + 16) {
            Some(v) => v,
            None => return false,
        };
        if !is_canonical_u128(c0) || !is_canonical_u128(c1) {
            return false;
        }
        let c2 = recover_c2_from_sumcheck_claim_arity8(&current, &c0, &c1);

        r = update_challenge(&r, &c0, &c1, &c2);
        current = eval_quadratic_power_basis(&c0, &c1, &c2, &r);
    }

    let expected_u: [u8; 32] = match calldata
        .get(calldata.len() - 32..)
        .and_then(|s| s.try_into().ok())
    {
        Some(w) => w,
        None => return false,
    };
    let expected = match u256_be_to_u128(&expected_u) {
        Some(v) if is_canonical_u128(v) => v,
        _ => return false,
    };
    current == expected
}

pub fn verify_packed_calldata_be(calldata: &[u8]) -> bool {
    if calldata.len() < 96 {
        return false;
    }
    let claim_u: [u8; 32] = match calldata.get(0..32).and_then(|s| s.try_into().ok()) {
        Some(w) => w,
        None => return false,
    };
    let initial = match u256_be_to_u128(&claim_u) {
        Some(v) if is_canonical_u128(v) => v,
        _ => return false,
    };
    let r0 = initial_challenge_unbound(&initial);
    verify_packed_payload_be_with_initial_r(calldata, r0)
}

#[cfg(test)]
    mod tests {
        use super::*;
        use hex;
        use std::fs;
        use std::path::Path;

        fn extract_uint256(text: &str, name: &str) -> Result<u128, String> {
            let needle = format!("constant {} = ", name);
            let start = text
                .find(&needle)
                .ok_or_else(|| "constant name not found".to_string())?;
            let rest = &text[start + needle.len()..];
            let end = rest
                .find(';')
                .ok_or_else(|| "constant line terminator not found".to_string())?;
            let value = rest[..end].trim();
            value
                .parse::<u128>()
                .map_err(|_| "constant parse failed".to_string())
        }

        fn extract_bytes32(text: &str, name: &str) -> Result<[u8; 32], String> {
            let needle = format!("constant {} = ", name);
            let start = text
                .find(&needle)
                .ok_or_else(|| "constant name not found".to_string())?;
            let rest = &text[start + needle.len()..];
            let end = rest
                .find(';')
                .ok_or_else(|| "constant line terminator not found".to_string())?;
            let value = rest[..end].trim();
            let hex_str = value
                .strip_prefix("0x")
                .ok_or_else(|| "bytes32 missing 0x prefix".to_string())?;
            let bytes = hex::decode(hex_str)
                .map_err(|_| "bytes32 hex decode failed".to_string())?;
            bytes
                .try_into()
                .map_err(|_| "bytes32 length mismatch".to_string())
        }

        fn check_constants_file(path: &Path) {
            let text = match fs::read_to_string(path) {
                Ok(text) => text,
                Err(_) => {
                    assert!(false, "constants file missing");
                    return;
                }
            };
            let modulus = match extract_uint256(&text, "MODULUS") {
                Ok(value) => value,
                Err(err) => {
                    assert!(false, "{err}");
                    return;
                }
            };
            let inv140 = match extract_uint256(&text, "INV140") {
                Ok(value) => value,
                Err(err) => {
                    assert!(false, "{err}");
                    return;
                }
            };
            let lin_domain = match extract_bytes32(&text, "LIN_DOMAIN") {
                Ok(value) => value,
                Err(err) => {
                    assert!(false, "{err}");
                    return;
                }
            };
            assert_eq!(modulus, GKR_MODULUS);
            assert_eq!(inv140, GKR_INV140);
            assert_eq!(lin_domain, keccak256(GLYPH_GKR_ARTIFACT_LIN_DOMAIN));
        }

    #[test]
    fn test_packed_gkr_roundtrip() {
        let proof = prove_packed(b"glyph-test-seed", 5);
        let calldata = encode_packed_calldata_be(&proof);
        assert!(verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_verifier_constants_sync() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        check_constants_file(&root.join("contracts/GLYPHVerifierConstants.sol"));
        check_constants_file(&root.join("scripts/tests/foundry/GLYPHVerifierConstants.sol"));
    }

    #[test]
    fn test_packed_gkr_roundtrip_truncated() {
        let proof = prove_packed(b"glyph-test-seed", 5);
        let calldata = encode_packed_calldata_be_truncated(&proof);
        assert!(verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_roundtrip_bound_full() {
        let statement = 0u128;
        let proof = prove_packed_statement(b"glyph-test-seed", 5, &statement);
        let addr = [0x11u8; 20];
        let calldata = encode_statement_bound_packed_calldata_be(&proof, 31337, addr, &statement, false);
        assert!(verify_packed_calldata_be_with_binding_env(&calldata, 31337, addr));
        // Unbound verifier should reject this in the common case because the header is not a field element.
        assert!(!verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_roundtrip_bound_truncated() {
        let statement = 0u128;
        let proof = prove_packed_statement(b"glyph-test-seed", 5, &statement);
        let addr = [0x22u8; 20];
        let calldata = encode_statement_bound_packed_calldata_be(&proof, 1, addr, &statement, true);
        assert!(verify_packed_calldata_be_with_binding_env(&calldata, 1, addr));
        assert!(!verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_bound_meta_tamper_fails() {
        let statement = 0u128;
        let proof = prove_packed_statement(b"glyph-test-seed", 5, &statement);
        let addr = [0x33u8; 20];
        let mut calldata = encode_statement_bound_packed_calldata_be(&proof, 10, addr, &statement, false);
        calldata[31] ^= 1;
        assert!(!verify_packed_calldata_be_with_binding_env(&calldata, 10, addr));
    }

    #[test]
    fn test_packed_gkr_roundtrip_statement_bound_full() {
        let statement = 123u128;
        let proof = prove_packed_statement(b"orioamimi-test-seed", 5, &statement);
        let addr = [0x44u8; 20];
        let calldata = encode_statement_bound_packed_calldata_be(&proof, 31337, addr, &statement, false);
        assert!(verify_packed_calldata_be_with_binding_env(&calldata, 31337, addr));
        assert!(!verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_roundtrip_statement_bound_truncated() {
        let statement = 123u128;
        let proof = prove_packed_statement(b"orioamimi-test-seed", 5, &statement);
        let addr = [0x55u8; 20];
        let calldata = encode_statement_bound_packed_calldata_be(&proof, 1, addr, &statement, true);
        assert!(verify_packed_calldata_be_with_binding_env(&calldata, 1, addr));
        assert!(!verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_statement_bound_wrong_statement_fails() {
        let statement = 123u128;
        let proof = prove_packed_statement(b"orioamimi-test-seed", 5, &statement);
        let addr = [0x66u8; 20];
        let mut calldata = encode_statement_bound_packed_calldata_be(&proof, 1, addr, &statement, false);
        // Flip one bit in the statement word (second word in calldata).
        calldata[63] ^= 1;
        assert!(!verify_packed_calldata_be_with_binding_env(&calldata, 1, addr));
    }

    #[test]
    fn test_packed_gkr_tamper_fails() {
        let proof = prove_packed(b"glyph-test-seed", 5);
        let mut calldata = encode_packed_calldata_be(&proof);
        // Flip one bit inside c1 of round 0 (packed in the lower 128 bits).
        let idx = 32 + 16; // initial + upper half of packed word
        calldata[idx + 15] ^= 1;
        assert!(!verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_length_rules() {
        assert!(!verify_packed_calldata_be(&[]));
        let buf_127 = [0u8; 127];
        assert!(!verify_packed_calldata_be(&buf_127));
        // Invalid because (len - 64) not multiple of 32.
        let buf_223 = [0u8; 223];
        assert!(!verify_packed_calldata_be(&buf_223));
    }

    #[test]
    fn test_packed_gkr_toy_sumcheck_roundtrip_full() {
        let proof = prove_packed_toy_sumcheck(b"glyph-toy-sumcheck-seed", 5);
        let calldata = encode_packed_calldata_be(&proof);
        assert!(verify_packed_calldata_be(&calldata));
    }

    #[test]
    fn test_packed_gkr_toy_sumcheck_roundtrip_statement_bound_full() {
        let statement = 123u128;
        let proof = prove_packed_toy_sumcheck_statement(b"glyph-toy-sumcheck-seed", 5, &statement);
        let addr = [0x77u8; 20];
        let calldata = encode_statement_bound_packed_calldata_be(&proof, 31337, addr, &statement, false);
        assert!(verify_packed_calldata_be_with_binding_env(&calldata, 31337, addr));
        assert!(!verify_packed_calldata_be(&calldata));
    }

    #[test]
        fn test_packed_gkr_toy_sumcheck_folded_statement_bound_full() {
            let statement = 123u128;
            let rounds = 5usize;
            let instances = 4usize;
            let seed = b"glyph-toy-fold-seed";

        let proof = prove_packed_toy_sumcheck_folded_statement(seed, rounds, instances, &statement);

        let mut digests = Vec::with_capacity(instances);
        let mut claims = Vec::with_capacity(instances);
        for i in 0..instances {
            let idx = match u32::try_from(i) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "instance index does not fit u32");
                    return;
                }
            };
            let seed32 = derive_toy_instance_seed32(seed, idx);
            digests.push(toy_instance_digest(&seed32, rounds, &statement));
            claims.push(prove_packed_toy_sumcheck_statement(&seed32, rounds, &statement).initial_claim);
        }
        let weights = derive_toy_basefold_weights(&digests);
        let mut expected = 0u128;
        for (w, c) in weights.iter().zip(claims.iter()) {
            expected = gkr_add(expected, gkr_mul(*w, *c));
        }
        assert_eq!(proof.initial_claim, expected);

        let addr = [0x88u8; 20];
        let calldata = encode_statement_bound_packed_calldata_be(&proof, 31337, addr, &statement, false);
            assert!(verify_packed_calldata_be_with_binding_env(&calldata, 31337, addr));
            assert!(!verify_packed_calldata_be(&calldata));
        }

        #[test]
        fn test_packed_gkr_stmt_poly_roundtrip_bound_full() {
            let statement = 123u128;
            let rounds = 5usize;
            let proof = prove_packed_stmt_poly_sumcheck(&statement, rounds);
            let addr = [0x99u8; 20];
            let calldata = encode_stmt_poly_bound_packed_calldata_be(&proof, 31337, addr, &statement, false);
            assert!(verify_stmt_poly_packed_calldata_be(&calldata, 31337, addr));
        }

        #[test]
        fn test_packed_gkr_stmt_poly_roundtrip_bound_truncated() {
            let statement = 123u128;
            let rounds = 5usize;
            let proof = prove_packed_stmt_poly_sumcheck(&statement, rounds);
            let addr = [0xAAu8; 20];
            let calldata = encode_stmt_poly_bound_packed_calldata_be(&proof, 1, addr, &statement, true);
            assert!(verify_stmt_poly_packed_calldata_be(&calldata, 1, addr));
        }

        #[test]
        fn test_packed_gkr_stmt_poly_bound_meta_tamper_fails() {
            let statement = 123u128;
            let rounds = 5usize;
            let proof = prove_packed_stmt_poly_sumcheck(&statement, rounds);
            let addr = [0xBBu8; 20];
            let mut calldata = encode_stmt_poly_bound_packed_calldata_be(&proof, 10, addr, &statement, false);
            calldata[31] ^= 1;
            assert!(!verify_stmt_poly_packed_calldata_be(&calldata, 10, addr));
        }

        #[test]
        fn test_packed_gkr_stmt_poly_bound_wrong_statement_fails() {
            let statement = 123u128;
            let rounds = 5usize;
            let proof = prove_packed_stmt_poly_sumcheck(&statement, rounds);
            let addr = [0xCCu8; 20];
            let mut calldata = encode_stmt_poly_bound_packed_calldata_be(&proof, 10, addr, &statement, false);
            // Flip one bit in the statement word (second word in calldata).
            calldata[63] ^= 1;
            assert!(!verify_stmt_poly_packed_calldata_be(&calldata, 10, addr));
        }

        #[test]
    fn test_packed_gkr_artifact_poly_roundtrip_bound_full() {
        let commitment = [0x11u8; 32];
        let point = [0x22u8; 32];
        let claim = 123u128;
        let rounds = 5usize;
        let proof = prove_packed_artifact_poly_sumcheck(&commitment, &point, &claim, 31337, [0xDDu8; 20], rounds);
        let addr = [0xDDu8; 20];
        let calldata =
                encode_artifact_poly_bound_packed_calldata_be(&proof, 31337, addr, &commitment, &point, &claim, false);
        assert!(verify_artifact_poly_packed_calldata_be(&calldata, 31337, addr));
    }

    #[test]
    fn test_packed_gkr_artifact_poly_roundtrip_bound_truncated() {
        let commitment = [0x33u8; 32];
        let point = [0x44u8; 32];
        let claim = 123u128;
        let rounds = 5usize;
        let proof = prove_packed_artifact_poly_sumcheck(&commitment, &point, &claim, 1, [0xEEu8; 20], rounds);
        let addr = [0xEEu8; 20];
        let calldata =
                encode_artifact_poly_bound_packed_calldata_be(&proof, 1, addr, &commitment, &point, &claim, true);
        assert!(verify_artifact_poly_packed_calldata_be(&calldata, 1, addr));
    }

    #[test]
    fn test_packed_gkr_artifact_poly_bound_env_tamper_fails() {
        let commitment = [0x55u8; 32];
        let point = [0x66u8; 32];
        let claim = 123u128;
        let rounds = 5usize;
        let proof = prove_packed_artifact_poly_sumcheck(&commitment, &point, &claim, 10, [0xEFu8; 20], rounds);
        let addr = [0xEFu8; 20];
        let calldata =
                encode_artifact_poly_bound_packed_calldata_be(&proof, 10, addr, &commitment, &point, &claim, false);
        assert!(!verify_artifact_poly_packed_calldata_be(&calldata, 11, addr));
    }

    #[test]
    fn test_packed_gkr_artifact_poly_claim_high_bits_fails() {
        let commitment = [0x77u8; 32];
        let point = [0x88u8; 32];
        let claim = 123u128;
        let rounds = 5usize;
        let proof = prove_packed_artifact_poly_sumcheck(&commitment, &point, &claim, 10, [0x01u8; 20], rounds);
        let addr = [0x01u8; 20];
        let mut calldata =
                encode_artifact_poly_bound_packed_calldata_be(&proof, 10, addr, &commitment, &point, &claim, false);
        // Flip one bit in the upper 128 bits of the claim word.
        calldata[32] ^= 1;
        assert!(!verify_artifact_poly_packed_calldata_be(&calldata, 10, addr));
    }
    }
