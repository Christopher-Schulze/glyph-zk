//! BN254 base-field helpers (Fq) for adapter kernels.
//!
//! This module provides canonical parsing and reference arithmetic for the BN254 base field.
//! It is intended for witness construction and strict input validation.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::should_implement_trait)]

use ark_bn254::Fq;
use ark_ff::{BigInt, PrimeField};
use num_bigint::BigUint;
use rayon::prelude::*;
use std::sync::OnceLock;

use crate::glyph_field_simd::{
    cuda_bn254_add_mod_batch,
    cuda_bn254_add_mod_batch_with_min,
    cuda_bn254_mul_mod_batch,
    cuda_bn254_mul_mod_batch_with_min,
    cuda_bn254_sub_mod_batch,
    cuda_bn254_sub_mod_batch_with_min,
    ensure_two_thread_pool,
    simd_add_u64x4,
    simd_mul_256_u32,
    simd_sub_u64x4,
    SimdBackend,
};

pub const BN254_FQ_MODULUS: BigInt<4> = Fq::MODULUS;
pub const BN254_FQ_MODULUS_LIMBS: [u64; 4] = BN254_FQ_MODULUS.0;

/// Montgomery-domain BN254 field element (a * R mod p).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MontgomeryFq {
    limbs: [u64; 4],
}

impl MontgomeryFq {
    /// Convert a canonical limb array into Montgomery domain.
    pub fn from_canonical(limbs: [u64; 4]) -> Option<Self> {
        if !is_canonical_limbs(limbs) {
            return None;
        }
        let r2 = bn254_r2();
        let mont = montgomery_mul(limbs, r2);
        Some(Self { limbs: mont })
    }

    /// Convert from Montgomery domain back to canonical limbs.
    pub fn to_canonical(self) -> [u64; 4] {
        montgomery_mul(self.limbs, [1u64, 0, 0, 0])
    }

    /// Add in Montgomery domain.
    pub fn add(self, rhs: Self) -> Self {
        let (sum, carry) = bn254_add_limbs_with_carry(self.limbs, rhs.limbs);
        let mut out = sum;
        if carry != 0 || bn254_limbs_ge(out, BN254_FQ_MODULUS_LIMBS) {
            out = bn254_sub_limbs_with_borrow(out, BN254_FQ_MODULUS_LIMBS).0;
        }
        Self { limbs: out }
    }

    /// Subtract in Montgomery domain.
    pub fn sub(self, rhs: Self) -> Self {
        let (diff, borrow) = bn254_sub_limbs_with_borrow(self.limbs, rhs.limbs);
        let out = if borrow != 0 {
            bn254_add_limbs_with_carry(diff, BN254_FQ_MODULUS_LIMBS).0
        } else {
            diff
        };
        Self { limbs: out }
    }

    /// Multiply in Montgomery domain.
    pub fn mul(self, rhs: Self) -> Self {
        Self { limbs: montgomery_mul(self.limbs, rhs.limbs) }
    }
}

pub fn is_canonical_limbs(limbs: [u64; 4]) -> bool {
    BigInt(limbs) < BN254_FQ_MODULUS
}

fn bn254_fast_path_enabled() -> bool {
    std::env::var("GLYPH_BN254_SIMD")
        .ok()
        .as_deref()
        .map(|v| v != "0")
        .unwrap_or(true)
}

fn bn254_simd_enabled() -> bool {
    bn254_fast_path_enabled() && SimdBackend::detect_cpu() != SimdBackend::Scalar
}

fn bn254_mul_fast_enabled() -> bool {
    if !bn254_fast_path_enabled() {
        return false;
    }
    std::env::var("GLYPH_BN254_MUL_MONT")
        .ok()
        .as_deref()
        .map(|v| v != "0")
        .unwrap_or(true)
}

fn cuda_debug_enabled() -> bool {
    std::env::var("GLYPH_CUDA_DEBUG")
        .ok()
        .as_deref()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn bn254_cuda_min_elems() -> usize {
    static MIN_ELEMS: OnceLock<usize> = OnceLock::new();
    *MIN_ELEMS.get_or_init(|| {
        std::env::var("GLYPH_CUDA_BN254_MIN_ELEMS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(1 << 15)
    })
}

fn bn254_par_min() -> usize {
    static MIN_ELEMS: OnceLock<usize> = OnceLock::new();
    *MIN_ELEMS.get_or_init(|| {
        std::env::var("GLYPH_BN254_PAR_MIN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(1 << 12)
    })
}

fn bn254_use_parallel(n: usize) -> bool {
    n >= bn254_par_min() && rayon::current_num_threads() > 1
}

pub fn fq_from_limbs(limbs: [u64; 4]) -> Option<Fq> {
    if !is_canonical_limbs(limbs) {
        return None;
    }
    Fq::from_bigint(BigInt(limbs))
}

pub fn limbs_from_fq(x: Fq) -> [u64; 4] {
    x.into_bigint().0
}

pub fn limbs_from_be_bytes(bytes: [u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let start = 32 - (i + 1) * 8;
        let end = start + 8;
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[start..end]);
        out[i] = u64::from_be_bytes(chunk);
    }
    out
}

pub fn be_bytes_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let start = 32 - (i + 1) * 8;
        let end = start + 8;
        out[start..end].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

pub fn is_canonical_be(bytes: [u8; 32]) -> bool {
    is_canonical_limbs(limbs_from_be_bytes(bytes))
}

fn bn254_add_mod_fq(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    let a = fq_from_limbs(a)?;
    let b = fq_from_limbs(b)?;
    Some(limbs_from_fq(a + b))
}

fn bn254_sub_mod_fq(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    let a = fq_from_limbs(a)?;
    let b = fq_from_limbs(b)?;
    Some(limbs_from_fq(a - b))
}

fn bn254_add_limbs_raw(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    if bn254_simd_enabled() {
        simd_add_u64x4(&a, &b)
    } else {
        [
            a[0].wrapping_add(b[0]),
            a[1].wrapping_add(b[1]),
            a[2].wrapping_add(b[2]),
            a[3].wrapping_add(b[3]),
        ]
    }
}

fn bn254_sub_limbs_raw(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    if bn254_simd_enabled() {
        simd_sub_u64x4(&a, &b)
    } else {
        [
            a[0].wrapping_sub(b[0]),
            a[1].wrapping_sub(b[1]),
            a[2].wrapping_sub(b[2]),
            a[3].wrapping_sub(b[3]),
        ]
    }
}

fn bn254_add_limbs_with_carry(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let raw = bn254_add_limbs_raw(a, b);
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = raw[i].wrapping_add(carry);
        let c0 = (raw[i] < a[i]) as u64;
        let c1 = (sum < raw[i]) as u64;
        out[i] = sum;
        carry = c0 | c1;
    }
    (out, carry)
}

fn bn254_sub_limbs_with_borrow(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let raw = bn254_sub_limbs_raw(a, b);
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let diff = raw[i].wrapping_sub(borrow);
        let b0 = (a[i] < b[i]) as u64;
        let b1 = (raw[i] < borrow) as u64;
        out[i] = diff;
        borrow = b0 | b1;
    }
    (out, borrow)
}

fn bn254_limbs_ge(a: [u64; 4], b: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn bn254_add_mod_fast(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    if !is_canonical_limbs(a) || !is_canonical_limbs(b) {
        return None;
    }
    let (sum, carry) = bn254_add_limbs_with_carry(a, b);
    if carry != 0 || bn254_limbs_ge(sum, BN254_FQ_MODULUS_LIMBS) {
        let (reduced, borrow) = bn254_sub_limbs_with_borrow(sum, BN254_FQ_MODULUS_LIMBS);
        if borrow != 0 {
            return bn254_add_mod_fq(a, b);
        }
        return Some(reduced);
    }
    Some(sum)
}

fn bn254_sub_mod_fast(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    if !is_canonical_limbs(a) || !is_canonical_limbs(b) {
        return None;
    }
    let (diff, borrow) = bn254_sub_limbs_with_borrow(a, b);
    if borrow == 0 {
        return Some(diff);
    }
    let (wrapped, _) = bn254_add_limbs_with_carry(diff, BN254_FQ_MODULUS_LIMBS);
    Some(wrapped)
}

pub fn bn254_add_mod(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    if bn254_fast_path_enabled() {
        bn254_add_mod_fast(a, b)
    } else {
        bn254_add_mod_fq(a, b)
    }
}

pub fn bn254_sub_mod(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    if bn254_fast_path_enabled() {
        bn254_sub_mod_fast(a, b)
    } else {
        bn254_sub_mod_fq(a, b)
    }
}

pub fn bn254_mul_mod(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    if bn254_mul_fast_enabled() {
        if let Some(out) = bn254_mul_mod_montgomery(a, b) {
            return Some(out);
        }
    }
    let a = fq_from_limbs(a)?;
    let b = fq_from_limbs(b)?;
    Some(limbs_from_fq(a * b))
}

pub fn bn254_add_mod_batch(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
) -> Result<bool, String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 add batch length mismatch".to_string());
    }
    if n == 0 {
        return Ok(false);
    }
    if n >= bn254_cuda_min_elems() && cuda_bn254_add_mod_batch(a, b, &mut out[..n]) {
        return Ok(true);
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_add_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 add batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok(false);
    }
    for i in 0..n {
        out[i] = bn254_add_mod(a[i], b[i]).ok_or_else(|| "bn254 add batch invalid limbs".to_string())?;
    }
    Ok(false)
}

pub fn bn254_add_mod_batch_with_min(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
    cuda_min_elems: usize,
) -> Result<bool, String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 add batch length mismatch".to_string());
    }
    if n == 0 {
        return Ok(false);
    }
    if n >= cuda_min_elems {
        let used = cuda_bn254_add_mod_batch_with_min(a, b, &mut out[..n], cuda_min_elems);
        if !used && cuda_debug_enabled() {
            eprintln!(
                "bn254 add cuda skipped: n={n} min={cuda_min_elems} backend={:?}",
                SimdBackend::detect()
            );
        }
        if used {
            return Ok(true);
        }
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_add_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 add batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok(false);
    }
    for i in 0..n {
        out[i] = bn254_add_mod(a[i], b[i]).ok_or_else(|| "bn254 add batch invalid limbs".to_string())?;
    }
    Ok(false)
}

pub fn bn254_sub_mod_batch(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
) -> Result<bool, String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 sub batch length mismatch".to_string());
    }
    if n == 0 {
        return Ok(false);
    }
    if n >= bn254_cuda_min_elems() && cuda_bn254_sub_mod_batch(a, b, &mut out[..n]) {
        return Ok(true);
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_sub_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 sub batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok(false);
    }
    for i in 0..n {
        out[i] = bn254_sub_mod(a[i], b[i]).ok_or_else(|| "bn254 sub batch invalid limbs".to_string())?;
    }
    Ok(false)
}

pub fn bn254_sub_mod_batch_with_min(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
    cuda_min_elems: usize,
) -> Result<bool, String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 sub batch length mismatch".to_string());
    }
    if n == 0 {
        return Ok(false);
    }
    if n >= cuda_min_elems {
        let used = cuda_bn254_sub_mod_batch_with_min(a, b, &mut out[..n], cuda_min_elems);
        if !used && cuda_debug_enabled() {
            eprintln!(
                "bn254 sub cuda skipped: n={n} min={cuda_min_elems} backend={:?}",
                SimdBackend::detect()
            );
        }
        if used {
            return Ok(true);
        }
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_sub_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 sub batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok(false);
    }
    for i in 0..n {
        out[i] = bn254_sub_mod(a[i], b[i]).ok_or_else(|| "bn254 sub batch invalid limbs".to_string())?;
    }
    Ok(false)
}

pub fn bn254_mul_mod_batch(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
) -> Result<bool, String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 mul batch length mismatch".to_string());
    }
    if n == 0 {
        return Ok(false);
    }
    if n >= bn254_cuda_min_elems() && cuda_bn254_mul_mod_batch(a, b, &mut out[..n]) {
        return Ok(true);
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_mul_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 mul batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok(false);
    }
    for i in 0..n {
        out[i] = bn254_mul_mod(a[i], b[i]).ok_or_else(|| "bn254 mul batch invalid limbs".to_string())?;
    }
    Ok(false)
}

pub fn bn254_mul_mod_batch_with_min(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
    cuda_min_elems: usize,
) -> Result<bool, String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 mul batch length mismatch".to_string());
    }
    if n == 0 {
        return Ok(false);
    }
    if n >= cuda_min_elems {
        let used = cuda_bn254_mul_mod_batch_with_min(a, b, &mut out[..n], cuda_min_elems);
        if !used && cuda_debug_enabled() {
            eprintln!(
                "bn254 mul cuda skipped: n={n} min={cuda_min_elems} backend={:?}",
                SimdBackend::detect()
            );
        }
        if used {
            return Ok(true);
        }
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_mul_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 mul batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok(false);
    }
    for i in 0..n {
        out[i] = bn254_mul_mod(a[i], b[i]).ok_or_else(|| "bn254 mul batch invalid limbs".to_string())?;
    }
    Ok(false)
}

pub fn bn254_add_mod_batch_cpu(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
) -> Result<(), String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 add batch length mismatch".to_string());
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_add_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 add batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok::<(), String>(());
    }
    for i in 0..n {
        out[i] = bn254_add_mod(a[i], b[i]).ok_or_else(|| "bn254 add batch invalid limbs".to_string())?;
    }
    Ok::<(), String>(())
}

pub fn bn254_sub_mod_batch_cpu(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
) -> Result<(), String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 sub batch length mismatch".to_string());
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_sub_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 sub batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok::<(), String>(());
    }
    for i in 0..n {
        out[i] = bn254_sub_mod(a[i], b[i]).ok_or_else(|| "bn254 sub batch invalid limbs".to_string())?;
    }
    Ok::<(), String>(())
}

pub fn bn254_mul_mod_batch_cpu(
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    out: &mut [[u64; 4]],
) -> Result<(), String> {
    let n = a.len();
    if n != b.len() || out.len() < n {
        return Err("bn254 mul batch length mismatch".to_string());
    }
    if bn254_use_parallel(n) {
        ensure_two_thread_pool();
        out[..n]
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(i, outi)| {
                *outi = bn254_mul_mod(a[i], b[i])
                    .ok_or_else(|| "bn254 mul batch invalid limbs".to_string())?;
                Ok::<(), String>(())
            })?;
        return Ok::<(), String>(());
    }
    for i in 0..n {
        out[i] = bn254_mul_mod(a[i], b[i]).ok_or_else(|| "bn254 mul batch invalid limbs".to_string())?;
    }
    Ok::<(), String>(())
}

pub fn bn254_mul_mod_and_quotient(a: [u64; 4], b: [u64; 4]) -> Option<([u64; 4], [u64; 4])> {
    if !is_canonical_limbs(a) || !is_canonical_limbs(b) {
        return None;
    }
    let product = mul_256(a, b);
    let (q, rem) = div_rem_u512_by_u256_bitwise(product, BN254_FQ_MODULUS_LIMBS)?;
    if !is_canonical_limbs(q) || !is_canonical_limbs(rem) {
        return None;
    }
    Some((rem, q))
}

fn mul_256_scalar(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let idx = i + j;
            let t = (a[i] as u128) * (b[j] as u128)
                + (out[idx] as u128)
                + carry;
            out[idx] = t as u64;
            carry = t >> 64;
        }
        let idx = i + 4;
        let t = (out[idx] as u128) + carry;
        out[idx] = t as u64;
        let mut k = idx + 1;
        let mut c = t >> 64;
        while c != 0 && k < 8 {
            let t2 = (out[k] as u128) + c;
            out[k] = t2 as u64;
            c = t2 >> 64;
            k += 1;
        }
    }
    out
}

fn mul_256(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    if bn254_simd_enabled() {
        if let Some(out) = simd_mul_256_u32(a, b) {
            return out;
        }
    }
    mul_256_scalar(a, b)
}

fn montgomery_inv64(x: u64) -> u64 {
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

fn bn254_mont_inv64() -> u64 {
    static INV: OnceLock<u64> = OnceLock::new();
    *INV.get_or_init(|| montgomery_inv64(BN254_FQ_MODULUS_LIMBS[0]))
}

fn bn254_r2() -> [u64; 4] {
    static R2: OnceLock<[u64; 4]> = OnceLock::new();
    *R2.get_or_init(|| {
        let modulus = biguint_from_limbs(BN254_FQ_MODULUS_LIMBS);
        let r: BigUint = BigUint::from(1u64) << 256;
        let r2 = (r.clone() * r) % modulus;
        limbs_from_biguint(&r2)
    })
}

fn montgomery_reduce(mut t: [u64; 8]) -> [u64; 4] {
    let n = BN254_FQ_MODULUS_LIMBS;
    let inv = bn254_mont_inv64();
    for i in 0..4 {
        let m = t[i].wrapping_mul(inv);
        let mut carry = 0u128;
        for j in 0..4 {
            let idx = i + j;
            let prod = (m as u128) * (n[j] as u128);
            let sum = (t[idx] as u128) + prod + carry;
            t[idx] = sum as u64;
            carry = sum >> 64;
        }
        let idx = i + 4;
        let sum = (t[idx] as u128) + carry;
        t[idx] = sum as u64;
        let mut k = idx + 1;
        let mut c = sum >> 64;
        while c != 0 && k < 8 {
            let sum2 = (t[k] as u128) + c;
            t[k] = sum2 as u64;
            c = sum2 >> 64;
            k += 1;
        }
    }
    let mut out = [t[4], t[5], t[6], t[7]];
    if bn254_limbs_ge(out, n) {
        out = bn254_sub_limbs_with_borrow(out, n).0;
    }
    out
}

fn montgomery_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let t = mul_256(a, b);
    montgomery_reduce(t)
}

fn bn254_mul_mod_montgomery(a: [u64; 4], b: [u64; 4]) -> Option<[u64; 4]> {
    if !is_canonical_limbs(a) || !is_canonical_limbs(b) {
        return None;
    }
    if a == [0u64; 4] || b == [0u64; 4] {
        return Some([0u64; 4]);
    }
    if a == [1u64, 0, 0, 0] {
        return Some(b);
    }
    if b == [1u64, 0, 0, 0] {
        return Some(a);
    }
    let ma = MontgomeryFq::from_canonical(a)?;
    let mb = MontgomeryFq::from_canonical(b)?;
    Some(ma.mul(mb).to_canonical())
}

#[allow(dead_code)]
fn sub_512_by_256(n: [u64; 8], sub: [u64; 4]) -> Option<[u64; 8]> {
    let mut out = n;
    let mut borrow = 0u64;
    for i in 0..8 {
        let sub_limb = if i < 4 { sub[i] } else { 0u64 };
        let (r1, b1) = out[i].overflowing_sub(sub_limb);
        let (r2, b2) = r1.overflowing_sub(borrow);
        out[i] = r2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    if borrow != 0 {
        return None;
    }
    Some(out)
}

fn div_rem_u512_by_u256_bitwise(n: [u64; 8], d: [u64; 4]) -> Option<([u64; 4], [u64; 4])> {
    if d == [0u64; 4] {
        return None;
    }
    let mut q = [0u64; 4];
    let mut r = [0u64; 5];
    let d5 = [d[0], d[1], d[2], d[3], 0u64];
    let ge = |a: [u64; 5], b: [u64; 5]| -> bool {
        for i in (0..5).rev() {
            if a[i] != b[i] {
                return a[i] > b[i];
            }
        }
        true
    };
    for bit in (0..512).rev() {
        let limb = bit / 64;
        let shift = bit % 64;
        let bit_val = (n[limb] >> shift) & 1;
        let mut carry = bit_val;
        for i in 0..5 {
            let new_carry = r[i] >> 63;
            r[i] = (r[i] << 1) | carry;
            carry = new_carry;
        }

        if ge(r, d5) {
            let mut borrow = 0u64;
            for i in 0..5 {
                let (r1, b1) = r[i].overflowing_sub(d5[i]);
                let (r2, b2) = r1.overflowing_sub(borrow);
                r[i] = r2;
                borrow = (b1 as u64) | (b2 as u64);
            }
            if bit >= 256 {
                return None;
            }
            let q_limb = bit / 64;
            let q_shift = bit % 64;
            q[q_limb] |= 1u64 << q_shift;
        }
    }
    if r[4] != 0 {
        return None;
    }
    let mut rem = [0u64; 4];
    rem.copy_from_slice(&r[0..4]);
    Some((q, rem))
}

pub fn bn254_mul_quotient(a: [u64; 4], b: [u64; 4], out: [u64; 4]) -> Option<[u64; 4]> {
    if !is_canonical_limbs(out) {
        return None;
    }
    let (rem, q) = bn254_mul_mod_and_quotient(a, b)?;
    if rem != out {
        return None;
    }
    Some(q)
}

pub fn bn254_inv_mod(a: [u64; 4]) -> Option<[u64; 4]> {
    if !is_canonical_limbs(a) {
        return None;
    }
    if a == [0u64; 4] {
        return None;
    }
    let modulus = biguint_from_limbs(BN254_FQ_MODULUS_LIMBS);
    let a_big = biguint_from_limbs(a);
    let exp = modulus.clone() - BigUint::from(2u64);
    let inv = a_big.modpow(&exp, &modulus);
    Some(limbs_from_biguint(&inv))
}

fn biguint_from_limbs(limbs: [u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let start = i * 8;
        bytes[start..start + 8].copy_from_slice(&limbs[i].to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn limbs_from_biguint(x: &BigUint) -> [u64; 4] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(32, 0);
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[start..start + 8]);
        limbs[i] = u64::from_le_bytes(chunk);
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};

    #[test]
    fn test_be_bytes_roundtrip() {
        let bytes = [0xABu8; 32];
        let limbs = limbs_from_be_bytes(bytes);
        let back = be_bytes_from_limbs(limbs);
        assert_eq!(bytes, back);
    }

    #[test]
    fn test_canonical_bounds() {
        let max = BN254_FQ_MODULUS_LIMBS;
        assert!(!is_canonical_limbs(max));
        let mut below = max;
        below[0] = below[0].wrapping_sub(1);
        assert!(is_canonical_limbs(below));
    }

    #[test]
    fn test_add_sub_roundtrip() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..256 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a_bytes = be_bytes_from_limbs([state, 0, 0, 0]);
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b_bytes = be_bytes_from_limbs([state, 0, 0, 0]);
            let a = limbs_from_be_bytes(a_bytes);
            let b = limbs_from_be_bytes(b_bytes);
            if !is_canonical_limbs(a) || !is_canonical_limbs(b) {
                continue;
            }
            let sum = match bn254_add_mod(a, b) {
                Some(sum) => sum,
                None => {
                    assert!(false, "sum");
                    return;
                }
            };
            let back = match bn254_sub_mod(sum, b) {
                Some(back) => back,
                None => {
                    assert!(false, "sub");
                    return;
                }
            };
            assert_eq!(back, a);
        }
    }

    #[test]
    fn test_add_sub_fast_matches_fq() {
        let mut rng = StdRng::seed_from_u64(0xfeed_beef);
        for _ in 0..256 {
            let a = Fq::rand(&mut rng);
            let b = Fq::rand(&mut rng);
            let a_limbs = limbs_from_fq(a);
            let b_limbs = limbs_from_fq(b);
            let fast_add = match bn254_add_mod_fast(a_limbs, b_limbs) {
                Some(val) => val,
                None => {
                    assert!(false, "fast add");
                    return;
                }
            };
            let fq_add = match bn254_add_mod_fq(a_limbs, b_limbs) {
                Some(val) => val,
                None => {
                    assert!(false, "fq add");
                    return;
                }
            };
            assert_eq!(fast_add, fq_add);
            let fast_sub = match bn254_sub_mod_fast(a_limbs, b_limbs) {
                Some(val) => val,
                None => {
                    assert!(false, "fast sub");
                    return;
                }
            };
            let fq_sub = match bn254_sub_mod_fq(a_limbs, b_limbs) {
                Some(val) => val,
                None => {
                    assert!(false, "fq sub");
                    return;
                }
            };
            assert_eq!(fast_sub, fq_sub);
        }
    }

    #[test]
    fn test_mul_matches_ark() {
        let mut state = 0x0bad_cafe_1234_5678u64;
        for _ in 0..128 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a_limbs = [state, state.rotate_left(17), state.rotate_left(33), state.rotate_left(49)];
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b_limbs = [state, state.rotate_left(9), state.rotate_left(27), state.rotate_left(45)];
            if !is_canonical_limbs(a_limbs) || !is_canonical_limbs(b_limbs) {
                continue;
            }
            let prod = match bn254_mul_mod(a_limbs, b_limbs) {
                Some(prod) => prod,
                None => {
                    assert!(false, "mul");
                    return;
                }
            };
            let a = match fq_from_limbs(a_limbs) {
                Some(a) => a,
                None => {
                    assert!(false, "a");
                    return;
                }
            };
            let b = match fq_from_limbs(b_limbs) {
                Some(b) => b,
                None => {
                    assert!(false, "b");
                    return;
                }
            };
            assert_eq!(prod, limbs_from_fq(a * b));
        }
    }

    #[test]
    fn test_mul_quotient_matches_biguint() {
        let modulus = biguint_from_limbs(BN254_FQ_MODULUS_LIMBS);
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..32 {
            let a = Fq::rand(&mut rng);
            let b = Fq::rand(&mut rng);
            let a_limbs = limbs_from_fq(a);
            let b_limbs = limbs_from_fq(b);
            let out = limbs_from_fq(a * b);
            let product = mul_256(a_limbs, b_limbs);
            let diff = match sub_512_by_256(product, out) {
                Some(diff) => diff,
                None => {
                    assert!(false, "diff");
                    return;
                }
            };
            let (q, rem) = match div_rem_u512_by_u256_bitwise(diff, BN254_FQ_MODULUS_LIMBS) {
                Some(val) => val,
                None => {
                    assert!(false, "div");
                    return;
                }
            };
            assert_eq!(rem, [0u64; 4]);

            let a_big = biguint_from_limbs(a_limbs);
            let b_big = biguint_from_limbs(b_limbs);
            let out_big = biguint_from_limbs(out);
            let diff = (a_big * b_big) - &out_big;
            let q_big = &diff / &modulus;
            let q_limbs = limbs_from_biguint(&q_big);
            assert_eq!(q, q_limbs);
        }
    }

    #[test]
    fn test_mul_256_simd_matches_scalar() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..64 {
            let a = Fq::rand(&mut rng);
            let b = Fq::rand(&mut rng);
            let a_limbs = limbs_from_fq(a);
            let b_limbs = limbs_from_fq(b);
            let scalar = mul_256_scalar(a_limbs, b_limbs);
            if let Some(simd) = simd_mul_256_u32(a_limbs, b_limbs) {
                assert_eq!(scalar, simd);
            }
        }
    }

    #[test]
    fn test_inv_roundtrip() {
        let mut state = 0xDECA_FBAD_1337_4242u64;
        for _ in 0..128 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a_limbs = [state, state.rotate_left(7), state.rotate_left(21), state.rotate_left(37)];
            if !is_canonical_limbs(a_limbs) || a_limbs == [0u64; 4] {
                continue;
            }
            let inv = match bn254_inv_mod(a_limbs) {
                Some(inv) => inv,
                None => {
                    assert!(false, "inv");
                    return;
                }
            };
            let prod = match bn254_mul_mod(a_limbs, inv) {
                Some(prod) => prod,
                None => {
                    assert!(false, "mul");
                    return;
                }
            };
            assert_eq!(prod, limbs_from_fq(Fq::ONE));
        }
    }
}
