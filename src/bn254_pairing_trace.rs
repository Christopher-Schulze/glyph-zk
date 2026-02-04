//! BN254 Groth16 pairing trace recorder for op events.

use ark_bn254::{Fq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ec::{AffineRepr, CurveGroup, bn::BnConfig, short_weierstrass::SWCurveConfig};
use ark_ff::{Field, PrimeField, Fp12Config, Fp6Config};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{Signed, ToPrimitive, Zero};
use std::sync::OnceLock;

use crate::bn254_field::{
    be_bytes_from_limbs,
    bn254_add_mod,
    bn254_add_mod_batch,
    bn254_mul_mod,
    bn254_mul_mod_batch,
    bn254_sub_mod,
    bn254_sub_mod_batch,
    fq_from_limbs,
    is_canonical_be,
    limbs_from_be_bytes,
    limbs_from_fq,
};
use crate::bn254_groth16::{Groth16Proof, Groth16VerifyingKey};
use crate::bn254_ops::{Bn254OpKind, Bn254OpTraceEvent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FqElem([u64; 4]);

impl FqElem {
    fn zero() -> Self {
        Self([0u64; 4])
    }

    fn one() -> Self {
        Self(limbs_from_fq(Fq::ONE))
    }

    fn is_zero(&self) -> bool {
        self.0 == [0u64; 4]
    }
}

fn fixed_base_precomp_enabled() -> bool {
    std::env::var("GLYPH_BN254_FIXED_BASE_PRECOMP")
        .ok()
        .as_deref()
        .map(|v| v != "0")
        .unwrap_or(true)
}

fn kzg_joint_msm_enabled() -> bool {
    std::env::var("GLYPH_BN254_KZG_JOINT_MSM")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn g1_ic_precomp_auto_enabled() -> bool {
    std::env::var("GLYPH_BN254_IC_PRECOMP_AUTO")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn g2_precomp_auto_enabled() -> bool {
    std::env::var("GLYPH_BN254_G2_PRECOMP_AUTO")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn trace_validate_batch_enabled() -> bool {
    std::env::var("GLYPH_BN254_TRACE_VALIDATE_BATCH")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn g1_generator() -> G1Affine {
    to_g1(ArkG1Affine::generator())
}

#[allow(dead_code)]
fn g2_generator() -> G2Affine {
    to_g2(ArkG2Affine::generator())
}

fn g1_precompute_window_const(window: usize) -> Vec<G1Affine> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<usize, Vec<G1Affine>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g1 window cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(points) = guard.get(&window) {
        return points.clone();
    }
    let count = (1usize << window) - 1;
    let base = ArkG1Affine::generator();
    let mut acc = base.into_group();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(to_g1(acc.into_affine()));
        acc += base;
    }
    guard.insert(window, out.clone());
    out
}

fn g1_precompute_wnaf_const(window: usize) -> Vec<G1Affine> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<usize, Vec<G1Affine>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g1 wnaf cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(points) = guard.get(&window) {
        return points.clone();
    }
    let count = 1usize << (window - 2);
    let base = ArkG1Affine::generator();
    let base2 = (base.into_group() + base).into_affine();
    let mut acc = base.into_group();
    let mut out = Vec::with_capacity(count);
    out.push(to_g1(acc.into_affine()));
    for _ in 1..count {
        acc += base2;
        out.push(to_g1(acc.into_affine()));
    }
    guard.insert(window, out.clone());
    out
}

#[allow(dead_code)]
fn g2_precompute_window_const(window: usize) -> Vec<G2Affine> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<usize, Vec<G2Affine>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g2 window cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(points) = guard.get(&window) {
        return points.clone();
    }
    let count = (1usize << window) - 1;
    let base = ArkG2Affine::generator();
    let mut acc = base.into_group();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(to_g2(acc.into_affine()));
        acc += base;
    }
    guard.insert(window, out.clone());
    out
}

#[allow(dead_code)]
fn g2_precompute_wnaf_const(window: usize) -> Vec<G2Affine> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<usize, Vec<G2Affine>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g2 wnaf cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(points) = guard.get(&window) {
        return points.clone();
    }
    let count = 1usize << (window - 2);
    let base = ArkG2Affine::generator();
    let base2 = (base.into_group() + base).into_affine();
    let mut acc = base.into_group();
    let mut out = Vec::with_capacity(count);
    out.push(to_g2(acc.into_affine()));
    for _ in 1..count {
        acc += base2;
        out.push(to_g2(acc.into_affine()));
    }
    guard.insert(window, out.clone());
    out
}

fn g1_wnaf_precomp_cached(base: G1Affine, window: usize) -> G1WnafPrecomp {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<G1PrecompKey, G1WnafPrecomp>>> = OnceLock::new();
    let key = G1PrecompKey {
        window,
        x: base.x.0,
        y: base.y.0,
        infinity: base.infinity,
    };
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g1 precomp cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(entry) = guard.get(&key) {
        return entry.clone();
    }
    let mut ctx = TraceCtx::new_discard();
    let base_table = g1_precompute_wnaf(&mut ctx, base, window);
    let phi = g1_endomorphism(&mut ctx, base);
    let phi_table = g1_precompute_wnaf(&mut ctx, phi, window);
    let out = G1WnafPrecomp {
        window,
        base: base_table,
        phi: phi_table,
    };
    guard.insert(key, out.clone());
    out
}

fn g1_ic_precomp_cached(vk: &Groth16VerifyingKey, window: usize) -> Vec<G1WnafPrecomp> {
    let mut out = Vec::with_capacity(vk.ic.len().saturating_sub(1));
    for ic in vk.ic.iter().skip(1) {
        let base = to_g1(*ic);
        out.push(g1_wnaf_precomp_cached(base, window));
    }
    out
}

fn fqelem_from_be_bytes(bytes: [u8; 32]) -> Result<FqElem, String> {
    if !is_canonical_be(bytes) {
        return Err("fq bytes not canonical".to_string());
    }
    Ok(FqElem(limbs_from_be_bytes(bytes)))
}

fn fqelem_to_be_bytes(a: FqElem) -> [u8; 32] {
    be_bytes_from_limbs(a.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fq2Elem {
    c0: FqElem,
    c1: FqElem,
}

fn fq2_from_be_bytes(im: [u8; 32], re: [u8; 32]) -> Result<Fq2Elem, String> {
    let c1 = fqelem_from_be_bytes(im)?;
    let c0 = fqelem_from_be_bytes(re)?;
    Ok(Fq2Elem { c0, c1 })
}

fn fq2_to_be_bytes(a: Fq2Elem) -> ([u8; 32], [u8; 32]) {
    (fqelem_to_be_bytes(a.c1), fqelem_to_be_bytes(a.c0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fq6Elem {
    c0: Fq2Elem,
    c1: Fq2Elem,
    c2: Fq2Elem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fq12Elem {
    c0: Fq6Elem,
    c1: Fq6Elem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct G1Affine {
    x: FqElem,
    y: FqElem,
    infinity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct G1Jacobian {
    x: FqElem,
    y: FqElem,
    z: FqElem,
    infinity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct G2Affine {
    x: Fq2Elem,
    y: Fq2Elem,
    infinity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
struct G2Jacobian {
    x: Fq2Elem,
    y: Fq2Elem,
    z: Fq2Elem,
    infinity: bool,
}

#[derive(Clone)]
pub struct G1WnafPrecomp {
    window: usize,
    base: Vec<G1Affine>,
    phi: Vec<G1Affine>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct G1PrecompKey {
    window: usize,
    x: [u64; 4],
    y: [u64; 4],
    infinity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct G2PrecompKey {
    x0: [u64; 4],
    x1: [u64; 4],
    y0: [u64; 4],
    y1: [u64; 4],
    infinity: bool,
}

enum TraceSink {
    Events(Vec<Bn254OpTraceEvent>),
    Discard,
}

impl TraceSink {
    fn push(
        &mut self,
        kind: Bn254OpKind,
        a: [u64; 4],
        b: [u64; 4],
        out: [u64; 4],
    ) -> Result<(), String> {
        match self {
            TraceSink::Events(events) => {
                events.push(Bn254OpTraceEvent { kind, a, b, out });
                Ok(())
            }
            TraceSink::Discard => Ok(()),
        }
    }

    fn finish_events(self) -> Result<Vec<Bn254OpTraceEvent>, String> {
        match self {
            TraceSink::Events(events) => Ok(events),
            TraceSink::Discard => Err("trace sink is discard-only, events unavailable".to_string()),
        }
    }
}

struct TraceCtx {
    sink: TraceSink,
    add_count: usize,
    sub_count: usize,
    mul_count: usize,
    error: Option<String>,
}

impl TraceCtx {
    fn new() -> Self {
        Self {
            sink: TraceSink::Events(Vec::new()),
            add_count: 0,
            sub_count: 0,
            mul_count: 0,
            error: None,
        }
    }

    fn new_discard() -> Self {
        Self {
            sink: TraceSink::Discard,
            add_count: 0,
            sub_count: 0,
            mul_count: 0,
            error: None,
        }
    }

    fn add(&mut self, a: FqElem, b: FqElem) -> FqElem {
        let out = match bn254_add_mod(a.0, b.0) {
            Some(value) => FqElem(value),
            None => {
                self.set_error("bn254 add invalid limbs".to_string());
                debug_assert!(false, "bn254 add invalid limbs");
                FqElem::zero()
            }
        };
        self.add_count += 1;
        if let Err(err) = self.sink.push(Bn254OpKind::Add, a.0, b.0, out.0) {
            self.set_error(err);
        }
        out
    }

    fn sub(&mut self, a: FqElem, b: FqElem) -> FqElem {
        let out = match bn254_sub_mod(a.0, b.0) {
            Some(value) => FqElem(value),
            None => {
                self.set_error("bn254 sub invalid limbs".to_string());
                debug_assert!(false, "bn254 sub invalid limbs");
                FqElem::zero()
            }
        };
        self.sub_count += 1;
        if let Err(err) = self.sink.push(Bn254OpKind::Sub, a.0, b.0, out.0) {
            self.set_error(err);
        }
        out
    }

    fn sub_with_expected(&mut self, a: FqElem, b: FqElem, out: FqElem) {
        self.sub_count += 1;
        if let Err(err) = self.sink.push(Bn254OpKind::Sub, a.0, b.0, out.0) {
            self.set_error(err);
        }
    }

    fn mul(&mut self, a: FqElem, b: FqElem) -> FqElem {
        let out = match bn254_mul_mod(a.0, b.0) {
            Some(value) => FqElem(value),
            None => {
                self.set_error("bn254 mul invalid limbs".to_string());
                debug_assert!(false, "bn254 mul invalid limbs");
                FqElem::zero()
            }
        };
        self.mul_count += 1;
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a.0, b.0, out.0) {
            self.set_error(err);
        }
        out
    }

    fn add_batch2(&mut self, a0: FqElem, b0: FqElem, a1: FqElem, b1: FqElem) -> (FqElem, FqElem) {
        let a = [a0.0, a1.0];
        let b = [b0.0, b1.0];
        let mut out = [[0u64; 4]; 2];
        if let Err(err) = bn254_add_mod_batch(&a, &b, &mut out) {
            self.set_error(err);
            return (FqElem::zero(), FqElem::zero());
        }
        self.add_count += 2;
        if let Err(err) = self.sink.push(Bn254OpKind::Add, a0.0, b0.0, out[0]) {
            self.set_error(err);
        }
        if let Err(err) = self.sink.push(Bn254OpKind::Add, a1.0, b1.0, out[1]) {
            self.set_error(err);
        }
        (FqElem(out[0]), FqElem(out[1]))
    }

    fn sub_batch2(&mut self, a0: FqElem, b0: FqElem, a1: FqElem, b1: FqElem) -> (FqElem, FqElem) {
        let a = [a0.0, a1.0];
        let b = [b0.0, b1.0];
        let mut out = [[0u64; 4]; 2];
        if let Err(err) = bn254_sub_mod_batch(&a, &b, &mut out) {
            self.set_error(err);
            return (FqElem::zero(), FqElem::zero());
        }
        self.sub_count += 2;
        if let Err(err) = self.sink.push(Bn254OpKind::Sub, a0.0, b0.0, out[0]) {
            self.set_error(err);
        }
        if let Err(err) = self.sink.push(Bn254OpKind::Sub, a1.0, b1.0, out[1]) {
            self.set_error(err);
        }
        (FqElem(out[0]), FqElem(out[1]))
    }

    fn mul_batch2(&mut self, a0: FqElem, b0: FqElem, a1: FqElem, b1: FqElem) -> (FqElem, FqElem) {
        let a = [a0.0, a1.0];
        let b = [b0.0, b1.0];
        let mut out = [[0u64; 4]; 2];
        if let Err(err) = bn254_mul_mod_batch(&a, &b, &mut out) {
            self.set_error(err);
            return (FqElem::zero(), FqElem::zero());
        }
        self.mul_count += 2;
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a0.0, b0.0, out[0]) {
            self.set_error(err);
        }
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a1.0, b1.0, out[1]) {
            self.set_error(err);
        }
        (FqElem(out[0]), FqElem(out[1]))
    }

    #[allow(clippy::too_many_arguments)]
    fn mul_batch4(
        &mut self,
        a0: FqElem,
        b0: FqElem,
        a1: FqElem,
        b1: FqElem,
        a2: FqElem,
        b2: FqElem,
        a3: FqElem,
        b3: FqElem,
    ) -> (FqElem, FqElem, FqElem, FqElem) {
        let a = [a0.0, a1.0, a2.0, a3.0];
        let b = [b0.0, b1.0, b2.0, b3.0];
        let mut out = [[0u64; 4]; 4];
        if let Err(err) = bn254_mul_mod_batch(&a, &b, &mut out) {
            self.set_error(err);
            return (FqElem::zero(), FqElem::zero(), FqElem::zero(), FqElem::zero());
        }
        self.mul_count += 4;
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a0.0, b0.0, out[0]) {
            self.set_error(err);
        }
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a1.0, b1.0, out[1]) {
            self.set_error(err);
        }
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a2.0, b2.0, out[2]) {
            self.set_error(err);
        }
        if let Err(err) = self.sink.push(Bn254OpKind::Mul, a3.0, b3.0, out[3]) {
            self.set_error(err);
        }
        (FqElem(out[0]), FqElem(out[1]), FqElem(out[2]), FqElem(out[3]))
    }

    fn counts(&self) -> (usize, usize, usize) {
        (self.add_count, self.sub_count, self.mul_count)
    }

    fn total_events(&self) -> usize {
        self.add_count + self.sub_count + self.mul_count
    }

    fn set_error(&mut self, err: String) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }

    fn finish_events(self) -> Result<Vec<Bn254OpTraceEvent>, String> {
        if let Some(err) = self.error {
            return Err(err);
        }
        self.sink.finish_events()
    }

}

fn fq_neg(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    if a.is_zero() {
        a
    } else {
        ctx.sub(FqElem::zero(), a)
    }
}

fn fq_square(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    ctx.mul(a, a)
}

fn fq_double(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    ctx.add(a, a)
}

fn fq_triple(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    let a2 = ctx.add(a, a);
    ctx.add(a2, a)
}

fn fq_quad(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    let a2 = ctx.add(a, a);
    ctx.add(a2, a2)
}

fn fq_oct(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    let a4 = fq_quad(ctx, a);
    ctx.add(a4, a4)
}

fn fq_mul_by_9(ctx: &mut TraceCtx, a: FqElem) -> FqElem {
    let a2 = ctx.add(a, a);
    let a4 = ctx.add(a2, a2);
    let a8 = ctx.add(a4, a4);
    ctx.add(a8, a)
}

fn fq2_add(ctx: &mut TraceCtx, a: Fq2Elem, b: Fq2Elem) -> Fq2Elem {
    let (c0, c1) = ctx.add_batch2(a.c0, b.c0, a.c1, b.c1);
    Fq2Elem {
        c0,
        c1,
    }
}

fn fq2_sub(ctx: &mut TraceCtx, a: Fq2Elem, b: Fq2Elem) -> Fq2Elem {
    let (c0, c1) = ctx.sub_batch2(a.c0, b.c0, a.c1, b.c1);
    Fq2Elem {
        c0,
        c1,
    }
}

fn fq2_neg(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    Fq2Elem {
        c0: fq_neg(ctx, a.c0),
        c1: fq_neg(ctx, a.c1),
    }
}

fn fq2_double(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    fq2_add(ctx, a, a)
}

#[allow(dead_code)]
fn fq2_triple(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    let a2 = fq2_add(ctx, a, a);
    fq2_add(ctx, a2, a)
}

#[allow(dead_code)]
fn fq2_quad(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    let a2 = fq2_add(ctx, a, a);
    fq2_add(ctx, a2, a2)
}

#[allow(dead_code)]
fn fq2_oct(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    let a4 = fq2_quad(ctx, a);
    fq2_add(ctx, a4, a4)
}

fn fq2_mul(ctx: &mut TraceCtx, a: Fq2Elem, b: Fq2Elem) -> Fq2Elem {
    // Karatsuba: 3 base muls.
    let (v0, v1) = ctx.mul_batch2(a.c0, b.c0, a.c1, b.c1);
    let (t0, t1) = ctx.add_batch2(a.c0, a.c1, b.c0, b.c1);
    let t2 = ctx.mul(t0, t1);
    let t2_minus_v0 = ctx.sub(t2, v0);
    let c1 = ctx.sub(t2_minus_v0, v1);
    let c0 = ctx.sub(v0, v1);
    Fq2Elem { c0, c1 }
}

fn fq2_mul_pair(
    ctx: &mut TraceCtx,
    a0: Fq2Elem,
    b0: Fq2Elem,
    a1: Fq2Elem,
    b1: Fq2Elem,
) -> (Fq2Elem, Fq2Elem) {
    let (v00, v01, v10, v11) = ctx.mul_batch4(
        a0.c0, b0.c0, a0.c1, b0.c1,
        a1.c0, b1.c0, a1.c1, b1.c1,
    );
    let (t00, t01) = ctx.add_batch2(a0.c0, a0.c1, b0.c0, b0.c1);
    let (t10, t11) = ctx.add_batch2(a1.c0, a1.c1, b1.c0, b1.c1);
    let (m0, m1) = ctx.mul_batch2(t00, t01, t10, t11);
    let m0_minus_v00 = ctx.sub(m0, v00);
    let c01 = ctx.sub(m0_minus_v00, v01);
    let c00 = ctx.sub(v00, v01);
    let m1_minus_v10 = ctx.sub(m1, v10);
    let c11 = ctx.sub(m1_minus_v10, v11);
    let c10 = ctx.sub(v10, v11);
    (Fq2Elem { c0: c00, c1: c01 }, Fq2Elem { c0: c10, c1: c11 })
}

fn fq2_square(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    let (t0, t2) = ctx.add_batch2(a.c0, a.c1, a.c0, a.c0);
    let t1 = ctx.sub(a.c0, a.c1);
    let (c0, c1) = ctx.mul_batch2(t0, t1, t2, a.c1);
    Fq2Elem { c0, c1 }
}

fn fq2_square_pair(ctx: &mut TraceCtx, a0: Fq2Elem, a1: Fq2Elem) -> (Fq2Elem, Fq2Elem) {
    let (t0_0, t2_0) = ctx.add_batch2(a0.c0, a0.c1, a0.c0, a0.c0);
    let (t0_1, t2_1) = ctx.add_batch2(a1.c0, a1.c1, a1.c0, a1.c0);
    let (t1_0, t1_1) = ctx.sub_batch2(a0.c0, a0.c1, a1.c0, a1.c1);
    let (c0_0, c1_0, c0_1, c1_1) = ctx.mul_batch4(
        t0_0, t1_0, t2_0, a0.c1,
        t0_1, t1_1, t2_1, a1.c1,
    );
    (
        Fq2Elem { c0: c0_0, c1: c1_0 },
        Fq2Elem { c0: c0_1, c1: c1_1 },
    )
}

fn fq2_mul_by_fp(ctx: &mut TraceCtx, a: Fq2Elem, b: FqElem) -> Fq2Elem {        
    let (c0, c1) = ctx.mul_batch2(a.c0, b, a.c1, b);
    Fq2Elem {
        c0,
        c1,
    }
}

fn fq2_mul_const(ctx: &mut TraceCtx, a: Fq2Elem, c: Fq2Elem) -> Fq2Elem {
    if c.c1.is_zero() {
        let (c0, c1) = ctx.mul_batch2(a.c0, c.c0, a.c1, c.c0);
        Fq2Elem {
            c0,
            c1,
        }
    } else if c.c0.is_zero() {
        let t0 = ctx.mul(a.c1, c.c1);
        let c0 = fq_neg(ctx, t0);
        let c1 = ctx.mul(a.c0, c.c1);
        Fq2Elem { c0, c1 }
    } else {
        fq2_mul(ctx, a, c)
    }
}

fn fq2_from_ark(v: ArkFq2) -> Fq2Elem {
    Fq2Elem {
        c0: FqElem(limbs_from_fq(v.c0)),
        c1: FqElem(limbs_from_fq(v.c1)),
    }
}

#[allow(dead_code)]
fn fq_to_ark(a: FqElem) -> Result<Fq, String> {
    fq_from_limbs(a.0).ok_or_else(|| "fq limbs not canonical".to_string())
}

#[allow(dead_code)]
fn fq2_to_ark(a: Fq2Elem) -> Result<ArkFq2, String> {
    Ok(ArkFq2::new(fq_to_ark(a.c0)?, fq_to_ark(a.c1)?))
}

#[allow(dead_code)]
fn fq2_inv_witness(a: Fq2Elem) -> Result<Fq2Elem, String> {
    let fq2 = fq2_to_ark(a)?;
    let inv = fq2.inverse().ok_or_else(|| "fq2 inverse does not exist".to_string())?;
    Ok(fq2_from_ark(inv))
}

fn fq6_mul_by_fp2(ctx: &mut TraceCtx, a: Fq6Elem, c: Fq2Elem) -> Fq6Elem {
    Fq6Elem {
        c0: fq2_mul_const(ctx, a.c0, c),
        c1: fq2_mul_const(ctx, a.c1, c),
        c2: fq2_mul_const(ctx, a.c2, c),
    }
}

fn fq6_neg(ctx: &mut TraceCtx, a: Fq6Elem) -> Fq6Elem {
    Fq6Elem {
        c0: fq2_neg(ctx, a.c0),
        c1: fq2_neg(ctx, a.c1),
        c2: fq2_neg(ctx, a.c2),
    }
}

fn frob_coeff_fp6_c1(power: usize) -> Fq2Elem {
    let coeff = ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1[power % 6];
    fq2_from_ark(coeff)
}

fn frob_coeff_fp6_c2(power: usize) -> Fq2Elem {
    let coeff = ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2[power % 6];
    fq2_from_ark(coeff)
}

fn frob_coeff_fp12_c1(power: usize) -> Fq2Elem {
    let coeff = ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1[power % 12];
    fq2_from_ark(coeff)
}

fn fq2_frobenius(ctx: &mut TraceCtx, a: Fq2Elem, power: usize) -> Fq2Elem {
    if power.is_multiple_of(2) {
        a
    } else {
        Fq2Elem {
            c0: a.c0,
            c1: fq_neg(ctx, a.c1),
        }
    }
}

fn fq6_frobenius(ctx: &mut TraceCtx, a: Fq6Elem, power: usize) -> Fq6Elem {
    let c0 = fq2_frobenius(ctx, a.c0, power);
    let c1 = fq2_frobenius(ctx, a.c1, power);
    let c2 = fq2_frobenius(ctx, a.c2, power);
    let c1 = fq2_mul_const(ctx, c1, frob_coeff_fp6_c1(power));
    let c2 = fq2_mul_const(ctx, c2, frob_coeff_fp6_c2(power));
    Fq6Elem { c0, c1, c2 }
}

fn fq12_frobenius(ctx: &mut TraceCtx, a: Fq12Elem, power: usize) -> Fq12Elem {
    let c0 = fq6_frobenius(ctx, a.c0, power);
    let c1 = fq6_frobenius(ctx, a.c1, power);
    let c1 = fq6_mul_by_fp2(ctx, c1, frob_coeff_fp12_c1(power));
    Fq12Elem { c0, c1 }
}

fn fq12_cyclotomic_inverse(ctx: &mut TraceCtx, a: Fq12Elem) -> Fq12Elem {
    Fq12Elem {
        c0: a.c0,
        c1: fq6_neg(ctx, a.c1),
    }
}

fn fq6_add(ctx: &mut TraceCtx, a: Fq6Elem, b: Fq6Elem) -> Fq6Elem {
    Fq6Elem {
        c0: fq2_add(ctx, a.c0, b.c0),
        c1: fq2_add(ctx, a.c1, b.c1),
        c2: fq2_add(ctx, a.c2, b.c2),
    }
}

fn fq6_sub(ctx: &mut TraceCtx, a: Fq6Elem, b: Fq6Elem) -> Fq6Elem {
    Fq6Elem {
        c0: fq2_sub(ctx, a.c0, b.c0),
        c1: fq2_sub(ctx, a.c1, b.c1),
        c2: fq2_sub(ctx, a.c2, b.c2),
    }
}

fn fq6_mul_by_nonresidue(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    let t0 = fq_mul_by_9(ctx, a.c0);
    let c0 = ctx.sub(t0, a.c1);
    let t1 = fq_mul_by_9(ctx, a.c1);
    let c1 = ctx.add(t1, a.c0);
    Fq2Elem { c0, c1 }
}

fn fq2_mul_by_nonresidue(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    fq6_mul_by_nonresidue(ctx, a)
}

fn fq6_mul(ctx: &mut TraceCtx, a: Fq6Elem, b: Fq6Elem) -> Fq6Elem {
    let (ad, be) = fq2_mul_pair(ctx, a.c0, b.c0, a.c1, b.c1);
    let cf = fq2_mul(ctx, a.c2, b.c2);

    let a1a2 = fq2_add(ctx, a.c1, a.c2);
    let b1b2 = fq2_add(ctx, b.c1, b.c2);
    let t0 = fq2_mul(ctx, a1a2, b1b2);
    let t1 = fq2_sub(ctx, t0, be);
    let x = fq2_sub(ctx, t1, cf);

    let a0a1 = fq2_add(ctx, a.c0, a.c1);
    let b0b1 = fq2_add(ctx, b.c0, b.c1);
    let a0a2 = fq2_add(ctx, a.c0, a.c2);
    let b0b2 = fq2_add(ctx, b.c0, b.c2);
    let (t2, t4) = fq2_mul_pair(ctx, a0a1, b0b1, a0a2, b0b2);
    let t3 = fq2_sub(ctx, t2, ad);
    let y = fq2_sub(ctx, t3, be);

    let t5 = fq2_sub(ctx, t4, ad);
    let t6 = fq2_add(ctx, t5, be);
    let z = fq2_sub(ctx, t6, cf);

    let x_nr = fq6_mul_by_nonresidue(ctx, x);
    let c0 = fq2_add(ctx, ad, x_nr);
    let cf_nr = fq6_mul_by_nonresidue(ctx, cf);
    let c1 = fq2_add(ctx, y, cf_nr);
    let c2 = z;
    Fq6Elem { c0, c1, c2 }
}

fn fq6_mul_pair(
    ctx: &mut TraceCtx,
    a0: Fq6Elem,
    b0: Fq6Elem,
    a1: Fq6Elem,
    b1: Fq6Elem,
) -> (Fq6Elem, Fq6Elem) {
    let (ad0, be0) = fq2_mul_pair(ctx, a0.c0, b0.c0, a0.c1, b0.c1);
    let (ad1, be1) = fq2_mul_pair(ctx, a1.c0, b1.c0, a1.c1, b1.c1);
    let (cf0, cf1) = fq2_mul_pair(ctx, a0.c2, b0.c2, a1.c2, b1.c2);

    let a0a1_0 = fq2_add(ctx, a0.c0, a0.c1);
    let b0b1_0 = fq2_add(ctx, b0.c0, b0.c1);
    let a0a2_0 = fq2_add(ctx, a0.c0, a0.c2);
    let b0b2_0 = fq2_add(ctx, b0.c0, b0.c2);
    let (t2_0, t4_0) = fq2_mul_pair(ctx, a0a1_0, b0b1_0, a0a2_0, b0b2_0);

    let a0a1_1 = fq2_add(ctx, a1.c0, a1.c1);
    let b0b1_1 = fq2_add(ctx, b1.c0, b1.c1);
    let a0a2_1 = fq2_add(ctx, a1.c0, a1.c2);
    let b0b2_1 = fq2_add(ctx, b1.c0, b1.c2);
    let (t2_1, t4_1) = fq2_mul_pair(ctx, a0a1_1, b0b1_1, a0a2_1, b0b2_1);

    let a1a2_0 = fq2_add(ctx, a0.c1, a0.c2);
    let b1b2_0 = fq2_add(ctx, b0.c1, b0.c2);
    let t0_0 = fq2_mul(ctx, a1a2_0, b1b2_0);
    let t1_0 = fq2_sub(ctx, t0_0, be0);
    let x0 = fq2_sub(ctx, t1_0, cf0);

    let a1a2_1 = fq2_add(ctx, a1.c1, a1.c2);
    let b1b2_1 = fq2_add(ctx, b1.c1, b1.c2);
    let t0_1 = fq2_mul(ctx, a1a2_1, b1b2_1);
    let t1_1 = fq2_sub(ctx, t0_1, be1);
    let x1 = fq2_sub(ctx, t1_1, cf1);

    let t3_0 = fq2_sub(ctx, t2_0, ad0);
    let y0 = fq2_sub(ctx, t3_0, be0);
    let t5_0 = fq2_sub(ctx, t4_0, ad0);
    let t6_0 = fq2_add(ctx, t5_0, be0);
    let z0 = fq2_sub(ctx, t6_0, cf0);

    let t3_1 = fq2_sub(ctx, t2_1, ad1);
    let y1 = fq2_sub(ctx, t3_1, be1);
    let t5_1 = fq2_sub(ctx, t4_1, ad1);
    let t6_1 = fq2_add(ctx, t5_1, be1);
    let z1 = fq2_sub(ctx, t6_1, cf1);

    let x0_nr = fq6_mul_by_nonresidue(ctx, x0);
    let c0_0 = fq2_add(ctx, ad0, x0_nr);
    let cf0_nr = fq6_mul_by_nonresidue(ctx, cf0);
    let c1_0 = fq2_add(ctx, y0, cf0_nr);

    let x1_nr = fq6_mul_by_nonresidue(ctx, x1);
    let c0_1 = fq2_add(ctx, ad1, x1_nr);
    let cf1_nr = fq6_mul_by_nonresidue(ctx, cf1);
    let c1_1 = fq2_add(ctx, y1, cf1_nr);

    (
        Fq6Elem { c0: c0_0, c1: c1_0, c2: z0 },
        Fq6Elem { c0: c0_1, c1: c1_1, c2: z1 },
    )
}

fn fq6_square(ctx: &mut TraceCtx, a: Fq6Elem) -> Fq6Elem {
    // CH-SQR2 from Devegili et al.
    let s0 = fq2_square(ctx, a.c0);
    let (ab, bc) = fq2_mul_pair(ctx, a.c0, a.c1, a.c1, a.c2);
    let s1 = fq2_add(ctx, ab, ab);
    let t0 = fq2_sub(ctx, a.c0, a.c1);
    let t1 = fq2_add(ctx, t0, a.c2);
    let s2 = fq2_square(ctx, t1);
    let s3 = fq2_add(ctx, bc, bc);
    let s4 = fq2_square(ctx, a.c2);

    let s3_nr = fq6_mul_by_nonresidue(ctx, s3);
    let c0 = fq2_add(ctx, s0, s3_nr);
    let s4_nr = fq6_mul_by_nonresidue(ctx, s4);
    let c1 = fq2_add(ctx, s1, s4_nr);

    let mut c2 = fq2_add(ctx, s1, s2);
    c2 = fq2_add(ctx, c2, s3);
    c2 = fq2_sub(ctx, c2, s0);
    c2 = fq2_sub(ctx, c2, s4);

    Fq6Elem { c0, c1, c2 }
}

fn fq6_square_pair(ctx: &mut TraceCtx, a0: Fq6Elem, a1: Fq6Elem) -> (Fq6Elem, Fq6Elem) {
    let (s00, s01) = fq2_square_pair(ctx, a0.c0, a1.c0);
    let (ab0, bc0) = fq2_mul_pair(ctx, a0.c0, a0.c1, a0.c1, a0.c2);
    let (ab1, bc1) = fq2_mul_pair(ctx, a1.c0, a1.c1, a1.c1, a1.c2);
    let s10 = fq2_add(ctx, ab0, ab0);
    let s11 = fq2_add(ctx, ab1, ab1);
    let t00 = fq2_sub(ctx, a0.c0, a0.c1);
    let t01 = fq2_sub(ctx, a1.c0, a1.c1);
    let t10 = fq2_add(ctx, t00, a0.c2);
    let t11 = fq2_add(ctx, t01, a1.c2);
    let s20 = fq2_square(ctx, t10);
    let s21 = fq2_square(ctx, t11);
    let s30 = fq2_add(ctx, bc0, bc0);
    let s31 = fq2_add(ctx, bc1, bc1);
    let (s40, s41) = fq2_square_pair(ctx, a0.c2, a1.c2);

    let s3_nr0 = fq6_mul_by_nonresidue(ctx, s30);
    let s3_nr1 = fq6_mul_by_nonresidue(ctx, s31);
    let c00 = fq2_add(ctx, s00, s3_nr0);
    let c01 = fq2_add(ctx, s01, s3_nr1);
    let s4_nr0 = fq6_mul_by_nonresidue(ctx, s40);
    let s4_nr1 = fq6_mul_by_nonresidue(ctx, s41);
    let c10 = fq2_add(ctx, s10, s4_nr0);
    let c11 = fq2_add(ctx, s11, s4_nr1);

    let mut c20 = fq2_add(ctx, s10, s20);
    c20 = fq2_add(ctx, c20, s30);
    c20 = fq2_sub(ctx, c20, s00);
    c20 = fq2_sub(ctx, c20, s40);

    let mut c21 = fq2_add(ctx, s11, s21);
    c21 = fq2_add(ctx, c21, s31);
    c21 = fq2_sub(ctx, c21, s01);
    c21 = fq2_sub(ctx, c21, s41);

    (
        Fq6Elem { c0: c00, c1: c10, c2: c20 },
        Fq6Elem { c0: c01, c1: c11, c2: c21 },
    )
}

fn fq6_mul_by_01(ctx: &mut TraceCtx, a: Fq6Elem, c0: Fq2Elem, c1: Fq2Elem) -> Fq6Elem {
    let (a_a, b_b) = fq2_mul_pair(ctx, a.c0, c0, a.c1, c1);

    let a1a2 = fq2_add(ctx, a.c1, a.c2);
    let a0a2 = fq2_add(ctx, a.c0, a.c2);
    let (t0_mul, t2_mul) = fq2_mul_pair(ctx, c1, a1a2, c0, a0a2);
    let t1 = fq2_sub(ctx, t0_mul, b_b);
    let t1 = fq6_mul_by_nonresidue(ctx, t1);
    let t1 = fq2_add(ctx, t1, a_a);

    let t3 = fq2_sub(ctx, t2_mul, a_a);
    let t3 = fq2_add(ctx, t3, b_b);

    let c0c1 = fq2_add(ctx, c0, c1);
    let a0a1 = fq2_add(ctx, a.c0, a.c1);
    let t4 = fq2_mul(ctx, c0c1, a0a1);
    let t5 = fq2_sub(ctx, t4, a_a);
    let t2 = fq2_sub(ctx, t5, b_b);

    Fq6Elem {
        c0: t1,
        c1: t2,
        c2: t3,
    }
}

fn fq12_mul_by_nonresidue(ctx: &mut TraceCtx, a: Fq6Elem) -> Fq6Elem {
    let old_c1 = a.c1;
    let c1 = a.c0;
    let c0 = fq6_mul_by_nonresidue(ctx, a.c2);
    let c2 = old_c1;
    Fq6Elem { c0, c1, c2 }
}

fn fq12_mul(ctx: &mut TraceCtx, a: Fq12Elem, b: Fq12Elem) -> Fq12Elem {
    let (v0, v1) = fq6_mul_pair(ctx, a.c0, b.c0, a.c1, b.c1);
    let a01 = fq6_add(ctx, a.c0, a.c1);
    let b01 = fq6_add(ctx, b.c0, b.c1);
    let t0 = fq6_mul(ctx, a01, b01);
    let t1 = fq6_sub(ctx, t0, v0);
    let c1 = fq6_sub(ctx, t1, v1);
    let v1_nr = fq12_mul_by_nonresidue(ctx, v1);
    let c0 = fq6_add(ctx, v1_nr, v0);
    Fq12Elem { c0, c1 }
}

fn fq12_square(ctx: &mut TraceCtx, a: Fq12Elem) -> Fq12Elem {
    let (t0, t1) = fq6_square_pair(ctx, a.c0, a.c1);
    let t2_base = fq6_add(ctx, a.c0, a.c1);
    let t2 = fq6_square(ctx, t2_base);
    let mut c1 = fq6_sub(ctx, t2, t0);
    c1 = fq6_sub(ctx, c1, t1);
    let t1_nr = fq12_mul_by_nonresidue(ctx, t1);
    let c0 = fq6_add(ctx, t0, t1_nr);
    Fq12Elem { c0, c1 }
}

fn fq12_cyclotomic_square(ctx: &mut TraceCtx, f: Fq12Elem) -> Fq12Elem {        
    let r0 = f.c0.c0;
    let r4 = f.c0.c1;
    let r3 = f.c0.c2;
    let r2 = f.c1.c0;
    let r1 = f.c1.c1;
    let r5 = f.c1.c2;

    let (tmp0, tmp1) = fq2_mul_pair(ctx, r0, r1, r2, r3);
    let r0r1 = fq2_add(ctx, r0, r1);
    let nr_r1 = fq2_mul_by_nonresidue(ctx, r1);
    let r0_plus_nr = fq2_add(ctx, nr_r1, r0);
    let r2r3 = fq2_add(ctx, r2, r3);
    let nr_r3 = fq2_mul_by_nonresidue(ctx, r3);
    let r2_plus_nr = fq2_add(ctx, nr_r3, r2);
    let (t0_mul, t2_mul) = fq2_mul_pair(ctx, r0r1, r0_plus_nr, r2r3, r2_plus_nr);
    let t0 = {
        let mut t0 = t0_mul;
        t0 = fq2_sub(ctx, t0, tmp0);
        let nr_tmp0 = fq2_mul_by_nonresidue(ctx, tmp0);
        fq2_sub(ctx, t0, nr_tmp0)
    };
    let t1 = fq2_double(ctx, tmp0);

    let t2 = {
        let mut t2 = t2_mul;
        t2 = fq2_sub(ctx, t2, tmp1);
        let nr_tmp1 = fq2_mul_by_nonresidue(ctx, tmp1);
        fq2_sub(ctx, t2, nr_tmp1)
    };
    let t3 = fq2_double(ctx, tmp1);

    let r4r5 = fq2_add(ctx, r4, r5);
    let nr_r5 = fq2_mul_by_nonresidue(ctx, r5);
    let r4_plus_nr = fq2_add(ctx, nr_r5, r4);
    let (tmp2, t4_mul) = fq2_mul_pair(ctx, r4, r5, r4r5, r4_plus_nr);
    let t4 = {
        let mut t4 = t4_mul;
        t4 = fq2_sub(ctx, t4, tmp2);
        let nr_tmp2 = fq2_mul_by_nonresidue(ctx, tmp2);
        fq2_sub(ctx, t4, nr_tmp2)
    };
    let t5 = fq2_double(ctx, tmp2);

    let z0 = {
        let mut z0 = fq2_sub(ctx, t0, r0);
        z0 = fq2_double(ctx, z0);
        fq2_add(ctx, z0, t0)
    };
    let z1 = {
        let mut z1 = fq2_add(ctx, t1, r1);
        z1 = fq2_double(ctx, z1);
        fq2_add(ctx, z1, t1)
    };
    let z2 = {
        let tmp = fq2_mul_by_nonresidue(ctx, t5);
        let mut z2 = fq2_add(ctx, r2, tmp);
        z2 = fq2_double(ctx, z2);
        fq2_add(ctx, z2, tmp)
    };
    let z3 = {
        let mut z3 = fq2_sub(ctx, t4, r3);
        z3 = fq2_double(ctx, z3);
        fq2_add(ctx, z3, t4)
    };
    let z4 = {
        let mut z4 = fq2_sub(ctx, t2, r4);
        z4 = fq2_double(ctx, z4);
        fq2_add(ctx, z4, t2)
    };
    let z5 = {
        let mut z5 = fq2_add(ctx, t3, r5);
        z5 = fq2_double(ctx, z5);
        fq2_add(ctx, z5, t3)
    };

    Fq12Elem {
        c0: Fq6Elem { c0: z0, c1: z4, c2: z3 },
        c1: Fq6Elem { c0: z2, c1: z1, c2: z5 },
    }
}

fn fq12_mul_by_034(ctx: &mut TraceCtx, f: &mut Fq12Elem, c0: Fq2Elem, c3: Fq2Elem, c4: Fq2Elem) {
    let (a0, a1) = fq2_mul_pair(ctx, f.c0.c0, c0, f.c0.c1, c0);
    let a2 = fq2_mul(ctx, f.c0.c2, c0);
    let a = Fq6Elem { c0: a0, c1: a1, c2: a2 };
    let b = fq6_mul_by_01(ctx, f.c1, c3, c4);

    let c0c3 = fq2_add(ctx, c0, c3);
    let f0f1 = fq6_add(ctx, f.c0, f.c1);
    let e = fq6_mul_by_01(ctx, f0f1, c0c3, c4);
    let ab = fq6_add(ctx, a, b);
    let c1 = fq6_sub(ctx, e, ab);
    let b_nr = fq12_mul_by_nonresidue(ctx, b);
    let c0 = fq6_add(ctx, b_nr, a);
    f.c0 = c0;
    f.c1 = c1;
}

fn g2_coeff_b() -> Fq2Elem {
    let b = ark_bn254::g2::Config::COEFF_B;
    Fq2Elem {
        c0: FqElem(limbs_from_fq(b.c0)),
        c1: FqElem(limbs_from_fq(b.c1)),
    }
}

fn twist_mul_by_q_x() -> Fq2Elem {
    let t = ark_bn254::Config::TWIST_MUL_BY_Q_X;
    Fq2Elem {
        c0: FqElem(limbs_from_fq(t.c0)),
        c1: FqElem(limbs_from_fq(t.c1)),
    }
}

fn twist_mul_by_q_y() -> Fq2Elem {
    let t = ark_bn254::Config::TWIST_MUL_BY_Q_Y;
    Fq2Elem {
        c0: FqElem(limbs_from_fq(t.c0)),
        c1: FqElem(limbs_from_fq(t.c1)),
    }
}

fn to_g1(p: ArkG1Affine) -> G1Affine {
    if p.is_zero() {
        return G1Affine {
            x: FqElem::zero(),
            y: FqElem::zero(),
            infinity: true,
        };
    }
    G1Affine {
        x: FqElem(limbs_from_fq(p.x)),
        y: FqElem(limbs_from_fq(p.y)),
        infinity: false,
    }
}

fn g1_jacobian_infinity() -> G1Jacobian {
    G1Jacobian {
        x: FqElem::zero(),
        y: FqElem::zero(),
        z: FqElem::zero(),
        infinity: true,
    }
}

fn g1_affine_infinity() -> G1Affine {
    G1Affine {
        x: FqElem::zero(),
        y: FqElem::zero(),
        infinity: true,
    }
}

fn g2_affine_infinity() -> G2Affine {
    G2Affine {
        x: Fq2Elem {
            c0: FqElem::zero(),
            c1: FqElem::zero(),
        },
        y: Fq2Elem {
            c0: FqElem::zero(),
            c1: FqElem::zero(),
        },
        infinity: true,
    }
}

#[allow(dead_code)]
fn g2_jacobian_infinity() -> G2Jacobian {
    G2Jacobian {
        x: Fq2Elem {
            c0: FqElem::zero(),
            c1: FqElem::zero(),
        },
        y: Fq2Elem {
            c0: FqElem::zero(),
            c1: FqElem::zero(),
        },
        z: Fq2Elem {
            c0: FqElem::zero(),
            c1: FqElem::zero(),
        },
        infinity: true,
    }
}

fn g1_jacobian_from_affine(p: G1Affine) -> G1Jacobian {
    if p.infinity {
        g1_jacobian_infinity()
    } else {
        G1Jacobian {
            x: p.x,
            y: p.y,
            z: FqElem::one(),
            infinity: false,
        }
    }
}

#[allow(dead_code)]
fn g2_jacobian_from_affine(p: G2Affine) -> G2Jacobian {
    if p.infinity {
        g2_jacobian_infinity()
    } else {
        G2Jacobian {
            x: p.x,
            y: p.y,
            z: Fq2Elem {
                c0: FqElem::one(),
                c1: FqElem::zero(),
            },
            infinity: false,
        }
    }
}

fn fq_inv_witness(a: FqElem) -> Result<FqElem, String> {
    let fq = fq_from_limbs(a.0).ok_or_else(|| "fq limbs not canonical".to_string())?;
    let inv = fq.inverse().ok_or_else(|| "fq inverse does not exist".to_string())?;
    Ok(FqElem(limbs_from_fq(inv)))
}

#[allow(dead_code)]
fn g2_jacobian_to_affine(ctx: &mut TraceCtx, p: G2Jacobian) -> Result<G2Affine, String> {
    if p.infinity {
        return Ok(G2Affine {
            x: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            y: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            infinity: true,
        });
    }

    let z_inv = fq2_inv_witness(p.z)?;
    let z_inv_check = fq2_mul(ctx, p.z, z_inv);
    let one = Fq2Elem {
        c0: FqElem::one(),
        c1: FqElem::zero(),
    };
    if z_inv_check != one {
        return Err("g2 jacobian z_inv invalid".to_string());
    }
    let z_inv2 = fq2_square(ctx, z_inv);
    let z_inv3 = fq2_mul(ctx, z_inv2, z_inv);
    let x = fq2_mul(ctx, p.x, z_inv2);
    let y = fq2_mul(ctx, p.y, z_inv3);
    Ok(G2Affine {
        x,
        y,
        infinity: false,
    })
}

fn g1_jacobian_to_affine(ctx: &mut TraceCtx, p: G1Jacobian) -> Result<G1Affine, String> {
    if p.infinity {
        return Ok(G1Affine {
            x: FqElem::zero(),
            y: FqElem::zero(),
            infinity: true,
        });
    }

    let z_inv = fq_inv_witness(p.z)?;
    let z_inv_check = ctx.mul(p.z, z_inv);
    if z_inv_check != FqElem::one() {
        return Err("g1 jacobian z_inv invalid".to_string());
    }
    let z_inv2 = fq_square(ctx, z_inv);
    let (z_inv3, x) = ctx.mul_batch2(z_inv2, z_inv, p.x, z_inv2);
    let y = ctx.mul(p.y, z_inv3);
    Ok(G1Affine {
        x,
        y,
        infinity: false,
    })
}

fn g1_jacobian_neg(ctx: &mut TraceCtx, p: G1Jacobian) -> G1Jacobian {
    if p.infinity {
        p
    } else {
        G1Jacobian {
            x: p.x,
            y: fq_neg(ctx, p.y),
            z: p.z,
            infinity: false,
        }
    }
}

#[allow(dead_code)]
fn g2_jacobian_neg(ctx: &mut TraceCtx, p: G2Jacobian) -> G2Jacobian {
    if p.infinity {
        p
    } else {
        G2Jacobian {
            x: p.x,
            y: fq2_neg(ctx, p.y),
            z: p.z,
            infinity: false,
        }
    }
}

fn g1_jacobian_double(ctx: &mut TraceCtx, p: G1Jacobian) -> G1Jacobian {
    if p.infinity || p.y.is_zero() {
        return g1_jacobian_infinity();
    }

    let a = fq_square(ctx, p.x);
    let b = fq_square(ctx, p.y);
    let c = fq_square(ctx, b);
    let x1_plus_b = ctx.add(p.x, b);
    let x1_plus_b_sq = fq_square(ctx, x1_plus_b);
    let x1_plus_b_sq_minus_a = ctx.sub(x1_plus_b_sq, a);
    let d = ctx.sub(x1_plus_b_sq_minus_a, c);
    let d = fq_double(ctx, d);
    let e = fq_triple(ctx, a);
    let f = fq_square(ctx, e);
    let d2 = fq_double(ctx, d);
    let x3 = ctx.sub(f, d2);
    let d_minus_x3 = ctx.sub(d, x3);
    let c8 = fq_oct(ctx, c);
    let (e_mul, yz) = ctx.mul_batch2(e, d_minus_x3, p.y, p.z);
    let y3 = ctx.sub(e_mul, c8);
    let z3 = fq_double(ctx, yz);

    G1Jacobian {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

#[allow(dead_code)]
fn g2_jacobian_double(ctx: &mut TraceCtx, p: G2Jacobian) -> G2Jacobian {
    if p.infinity || (p.y.c0.is_zero() && p.y.c1.is_zero()) {
        return g2_jacobian_infinity();
    }

    let a = fq2_square(ctx, p.x);
    let b = fq2_square(ctx, p.y);
    let c = fq2_square(ctx, b);
    let x1_plus_b = fq2_add(ctx, p.x, b);
    let x1_plus_b_sq = fq2_square(ctx, x1_plus_b);
    let x1_plus_b_sq_minus_a = fq2_sub(ctx, x1_plus_b_sq, a);
    let d = fq2_sub(ctx, x1_plus_b_sq_minus_a, c);
    let d = fq2_double(ctx, d);
    let e = fq2_triple(ctx, a);
    let f = fq2_square(ctx, e);
    let d2 = fq2_double(ctx, d);
    let x3 = fq2_sub(ctx, f, d2);
    let d_minus_x3 = fq2_sub(ctx, d, x3);
    let e_mul = fq2_mul(ctx, e, d_minus_x3);
    let c8 = fq2_oct(ctx, c);
    let y3 = fq2_sub(ctx, e_mul, c8);
    let yz = fq2_mul(ctx, p.y, p.z);
    let z3 = fq2_double(ctx, yz);

    G2Jacobian {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

fn g1_jacobian_add_mixed(ctx: &mut TraceCtx, p: G1Jacobian, q: G1Affine) -> G1Jacobian {
    if p.infinity {
        return g1_jacobian_from_affine(q);
    }
    if q.infinity {
        return p;
    }

    let z1z1 = fq_square(ctx, p.z);
    let (u2, z1_cubed) = ctx.mul_batch2(q.x, z1z1, z1z1, p.z);
    let s2 = ctx.mul(q.y, z1_cubed);
    let h = ctx.sub(u2, p.x);
    if h.is_zero() {
        let s2_minus_y1 = ctx.sub(s2, p.y);
        if s2_minus_y1.is_zero() {
            return g1_jacobian_double(ctx, p);
        }
        return g1_jacobian_infinity();
    }
    let hh = fq_square(ctx, h);
    let i = fq_quad(ctx, hh);
    let (j, v) = ctx.mul_batch2(h, i, p.x, i);
    let s2_minus_y1 = ctx.sub(s2, p.y);
    let r = fq_double(ctx, s2_minus_y1);
    let r2 = fq_square(ctx, r);
    let v2 = fq_double(ctx, v);
    let r2_minus_j = ctx.sub(r2, j);
    let x3 = ctx.sub(r2_minus_j, v2);
    let v_minus_x3 = ctx.sub(v, x3);
    let (y1j, rv) = ctx.mul_batch2(p.y, j, r, v_minus_x3);
    let y1j2 = fq_double(ctx, y1j);
    let y3 = ctx.sub(rv, y1j2);
    let z1_plus_h = ctx.add(p.z, h);
    let z1_plus_h_sq = fq_square(ctx, z1_plus_h);
    let z3_tmp = ctx.sub(z1_plus_h_sq, z1z1);
    let z3 = ctx.sub(z3_tmp, hh);

    G1Jacobian {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

#[allow(dead_code)]
fn g2_jacobian_add_mixed(ctx: &mut TraceCtx, p: G2Jacobian, q: G2Affine) -> G2Jacobian {
    if p.infinity {
        return g2_jacobian_from_affine(q);
    }
    if q.infinity {
        return p;
    }

    let z1z1 = fq2_square(ctx, p.z);
    let u2 = fq2_mul(ctx, q.x, z1z1);
    let s2 = {
        let z1_cubed = fq2_mul(ctx, z1z1, p.z);
        fq2_mul(ctx, q.y, z1_cubed)
    };
    let h = fq2_sub(ctx, u2, p.x);
    if h.c0.is_zero() && h.c1.is_zero() {
        let s2_minus_y1 = fq2_sub(ctx, s2, p.y);
        if s2_minus_y1.c0.is_zero() && s2_minus_y1.c1.is_zero() {
            return g2_jacobian_double(ctx, p);
        }
        return g2_jacobian_infinity();
    }
    let hh = fq2_square(ctx, h);
    let i = fq2_quad(ctx, hh);
    let j = fq2_mul(ctx, h, i);
    let s2_minus_y1 = fq2_sub(ctx, s2, p.y);
    let r = fq2_double(ctx, s2_minus_y1);
    let v = fq2_mul(ctx, p.x, i);
    let r2 = fq2_square(ctx, r);
    let v2 = fq2_double(ctx, v);
    let r2_minus_j = fq2_sub(ctx, r2, j);
    let x3 = fq2_sub(ctx, r2_minus_j, v2);
    let v_minus_x3 = fq2_sub(ctx, v, x3);
    let y1j = fq2_mul(ctx, p.y, j);
    let y1j2 = fq2_double(ctx, y1j);
    let rv = fq2_mul(ctx, r, v_minus_x3);
    let y3 = fq2_sub(ctx, rv, y1j2);
    let z1_plus_h = fq2_add(ctx, p.z, h);
    let z1_plus_h_sq = fq2_square(ctx, z1_plus_h);
    let z3_tmp = fq2_sub(ctx, z1_plus_h_sq, z1z1);
    let z3 = fq2_sub(ctx, z3_tmp, hh);

    G2Jacobian {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

fn g1_jacobian_add(ctx: &mut TraceCtx, p: G1Jacobian, q: G1Jacobian) -> G1Jacobian {
    if p.infinity {
        return q;
    }
    if q.infinity {
        return p;
    }

    let z1z1 = fq_square(ctx, p.z);
    let z2z2 = fq_square(ctx, q.z);
    let (u1, u2, z2_cubed, z1_cubed) = ctx.mul_batch4(
        p.x, z2z2, q.x, z1z1,
        z2z2, q.z, z1z1, p.z,
    );
    let (s1, s2) = ctx.mul_batch2(p.y, z2_cubed, q.y, z1_cubed);
    let h = ctx.sub(u2, u1);
    if h.is_zero() {
        let s2_minus_s1 = ctx.sub(s2, s1);
        if s2_minus_s1.is_zero() {
            return g1_jacobian_double(ctx, p);
        }
        return g1_jacobian_infinity();
    }
    let hh = fq_square(ctx, h);
    let i = fq_quad(ctx, hh);
    let (j, v) = ctx.mul_batch2(h, i, u1, i);
    let s2_minus_s1 = ctx.sub(s2, s1);
    let r = fq_double(ctx, s2_minus_s1);
    let r2 = fq_square(ctx, r);
    let v2 = fq_double(ctx, v);
    let r2_minus_j = ctx.sub(r2, j);
    let x3 = ctx.sub(r2_minus_j, v2);
    let v_minus_x3 = ctx.sub(v, x3);
    let (s1j, rv) = ctx.mul_batch2(s1, j, r, v_minus_x3);
    let s1j2 = fq_double(ctx, s1j);
    let y3 = ctx.sub(rv, s1j2);
    let (z1_plus_z2, z1z1_plus_z2z2) = ctx.add_batch2(p.z, q.z, z1z1, z2z2);
    let z1_plus_z2_sq = fq_square(ctx, z1_plus_z2);
    let z3_base = ctx.sub(z1_plus_z2_sq, z1z1_plus_z2z2);
    let z3 = ctx.mul(z3_base, h);

    G1Jacobian {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

fn g1_jacobian_mul_small(ctx: &mut TraceCtx, mut base: G1Jacobian, mut k: usize) -> G1Jacobian {
    if k == 0 || base.infinity {
        return g1_jacobian_infinity();
    }
    let mut acc = g1_jacobian_infinity();
    while k > 0 {
        if (k & 1) == 1 {
            acc = if acc.infinity { base } else { g1_jacobian_add(ctx, acc, base) };
        }
        k >>= 1;
        if k > 0 {
            base = g1_jacobian_double(ctx, base);
        }
    }
    acc
}

#[allow(dead_code)]
fn g2_jacobian_add(ctx: &mut TraceCtx, p: G2Jacobian, q: G2Jacobian) -> G2Jacobian {
    if p.infinity {
        return q;
    }
    if q.infinity {
        return p;
    }

    let z1z1 = fq2_square(ctx, p.z);
    let z2z2 = fq2_square(ctx, q.z);
    let u1 = fq2_mul(ctx, p.x, z2z2);
    let u2 = fq2_mul(ctx, q.x, z1z1);
    let s1 = {
        let z2_cubed = fq2_mul(ctx, z2z2, q.z);
        fq2_mul(ctx, p.y, z2_cubed)
    };
    let s2 = {
        let z1_cubed = fq2_mul(ctx, z1z1, p.z);
        fq2_mul(ctx, q.y, z1_cubed)
    };
    let h = fq2_sub(ctx, u2, u1);
    if h.c0.is_zero() && h.c1.is_zero() {
        let s2_minus_s1 = fq2_sub(ctx, s2, s1);
        if s2_minus_s1.c0.is_zero() && s2_minus_s1.c1.is_zero() {
            return g2_jacobian_double(ctx, p);
        }
        return g2_jacobian_infinity();
    }
    let hh = fq2_square(ctx, h);
    let i = fq2_quad(ctx, hh);
    let j = fq2_mul(ctx, h, i);
    let s2_minus_s1 = fq2_sub(ctx, s2, s1);
    let r = fq2_double(ctx, s2_minus_s1);
    let v = fq2_mul(ctx, u1, i);
    let r2 = fq2_square(ctx, r);
    let v2 = fq2_double(ctx, v);
    let r2_minus_j = fq2_sub(ctx, r2, j);
    let x3 = fq2_sub(ctx, r2_minus_j, v2);
    let v_minus_x3 = fq2_sub(ctx, v, x3);
    let s1j = fq2_mul(ctx, s1, j);
    let s1j2 = fq2_double(ctx, s1j);
    let rv = fq2_mul(ctx, r, v_minus_x3);
    let y3 = fq2_sub(ctx, rv, s1j2);
    let z1_plus_z2 = fq2_add(ctx, p.z, q.z);
    let z1_plus_z2_sq = fq2_square(ctx, z1_plus_z2);
    let z1z1_plus_z2z2 = fq2_add(ctx, z1z1, z2z2);
    let z3_base = fq2_sub(ctx, z1_plus_z2_sq, z1z1_plus_z2z2);
    let z3 = fq2_mul(ctx, z3_base, h);

    G2Jacobian {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

fn scalar_high_bit(limbs: [u64; 4]) -> Option<usize> {
    for i in (0..4).rev() {
        let limb = limbs[i];
        if limb != 0 {
            let leading = limb.leading_zeros() as usize;
            return Some(i * 64 + (63 - leading));
        }
    }
    None
}

fn scalar_bit(limbs: [u64; 4], bit: usize) -> bool {
    if bit >= 256 {
        return false;
    }
    let limb = bit / 64;
    let shift = bit % 64;
    ((limbs[limb] >> shift) & 1) == 1
}

fn scalar_window_width() -> usize {
    std::env::var("GLYPH_BN254_SCALAR_WINDOW")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| (1..=6).contains(v))
        .unwrap_or(3)
}

fn scalar_window_value(limbs: [u64; 4], start: usize, width: usize) -> usize {
    if width == 0 || start >= 256 {
        return 0;
    }
    let limb = start / 64;
    let offset = start % 64;
    let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
    if offset + width <= 64 {
        ((limbs[limb] >> offset) & mask) as usize
    } else {
        let low = limbs[limb] >> offset;
        let high = if limb + 1 < 4 {
            limbs[limb + 1] << (64 - offset)
        } else {
            0
        };
        ((low | high) & mask) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScalarMulAlgo {
    Window,
    Wnaf,
    GlvWnaf,
}

fn scalar_mul_algo() -> ScalarMulAlgo {
    match std::env::var("GLYPH_BN254_SCALAR_MUL")
        .ok()
        .as_deref()
    {
        Some("window") => ScalarMulAlgo::Window,
        Some("wnaf") => ScalarMulAlgo::Wnaf,
        Some("glv") => ScalarMulAlgo::GlvWnaf,
        _ => ScalarMulAlgo::GlvWnaf,
    }
}

fn wnaf_window_width() -> usize {
    scalar_window_width().max(2)
}

fn scalar_limbs_to_biguint(limbs: [u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn limbs_is_zero(limbs: [u64; 4]) -> bool {
    limbs == [0u64; 4]
}

fn limbs_shr1(mut limbs: [u64; 4]) -> [u64; 4] {
    let mut carry = 0u64;
    for i in (0..4).rev() {
        let next = limbs[i] & 1;
        limbs[i] = (limbs[i] >> 1) | (carry << 63);
        carry = next;
    }
    limbs
}

fn limbs_add_small(mut limbs: [u64; 4], mut val: u64) -> [u64; 4] {
    for limb in limbs.iter_mut() {
        let (next, carry) = limb.overflowing_add(val);
        *limb = next;
        val = if carry { 1 } else { 0 };
        if val == 0 {
            break;
        }
    }
    limbs
}

fn limbs_sub_small(mut limbs: [u64; 4], mut val: u64) -> [u64; 4] {
    for limb in limbs.iter_mut() {
        let (next, borrow) = limb.overflowing_sub(val);
        *limb = next;
        val = if borrow { 1 } else { 0 };
        if val == 0 {
            break;
        }
    }
    limbs
}

fn wnaf_digits_bigint(scalar_limbs: [u64; 4], window: usize) -> Vec<i8> {
    let mut k = BigInt::from(scalar_limbs_to_biguint(scalar_limbs));
    if k.is_zero() {
        return Vec::new();
    }
    let radix = BigInt::from(1u8) << window;
    let radix_half = BigInt::from(1u8) << (window - 1);
    let mut digits = Vec::new();
    while !k.is_zero() {
        let mut digit = 0i64;
        if k.is_odd() {
            let mut mod_val = k.mod_floor(&radix);
            if mod_val > radix_half {
                mod_val -= &radix;
            }
            digit = match mod_val.to_i64() {
                Some(value) => value,
                None => {
                    debug_assert!(false, "wnaf digit out of i64 range");
                    0
                }
            };
            k -= BigInt::from(digit);
        }
        digits.push(digit as i8);
        k >>= 1;
    }
    digits
}

fn wnaf_digits_fast(mut limbs: [u64; 4], window: usize) -> Vec<i8> {
    if limbs_is_zero(limbs) {
        return Vec::new();
    }
    let radix = 1u64 << window;
    let radix_half = 1u64 << (window - 1);
    let mut digits = Vec::new();
    while !limbs_is_zero(limbs) {
        let mut digit = 0i64;
        if (limbs[0] & 1) == 1 {
            let mut mod_val = (limbs[0] & (radix - 1)) as i64;
            if mod_val > radix_half as i64 {
                mod_val -= radix as i64;
            }
            digit = mod_val;
            if digit >= 0 {
                limbs = limbs_sub_small(limbs, digit as u64);
            } else {
                limbs = limbs_add_small(limbs, (-digit) as u64);
            }
        }
        digits.push(digit as i8);
        limbs = limbs_shr1(limbs);
    }
    digits
}

fn wnaf_digits(scalar_limbs: [u64; 4], window: usize) -> Vec<i8> {
    if std::env::var("GLYPH_BN254_WNAF_SLOW")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return wnaf_digits_bigint(scalar_limbs, window);
    }
    wnaf_digits_fast(scalar_limbs, window)
}

fn biguint_to_limbs(value: &BigUint) -> [u64; 4] {
    let bytes = value.to_bytes_le();
    let mut out = [0u64; 4];
    for (i, out_slot) in out.iter_mut().enumerate() {
        let start = i * 8;
        if start >= bytes.len() {
            break;
        }
        let end = (start + 8).min(bytes.len());
        let mut chunk = [0u8; 8];
        chunk[..end - start].copy_from_slice(&bytes[start..end]);
        *out_slot = u64::from_le_bytes(chunk);
    }
    out
}

struct GlvConstants {
    n11: BigInt,
    n12: BigInt,
    n21: BigInt,
    n22: BigInt,
    modulus: BigInt,
    beta: FqElem,
}

fn glv_constants() -> &'static GlvConstants {
    static GLV: OnceLock<GlvConstants> = OnceLock::new();
    GLV.get_or_init(|| {
        let n11 = BigInt::from_biguint(
            Sign::Minus,
            BigUint::parse_bytes(b"147946756881789319000765030803803410728", 10)
                .unwrap_or_else(|| {
                    debug_assert!(false, "glv n11 parse failed");
                    BigUint::zero()
                }),
        );
        let n12 = BigInt::from_biguint(
            Sign::Plus,
            BigUint::parse_bytes(b"9931322734385697763", 10).unwrap_or_else(|| {
                debug_assert!(false, "glv n12 parse failed");
                BigUint::zero()
            }),
        );
        let n21 = BigInt::from_biguint(
            Sign::Minus,
            BigUint::parse_bytes(b"9931322734385697763", 10).unwrap_or_else(|| {
                debug_assert!(false, "glv n21 parse failed");
                BigUint::zero()
            }),
        );
        let n22 = BigInt::from_biguint(
            Sign::Minus,
            BigUint::parse_bytes(b"147946756881789319010696353538189108491", 10)
                .unwrap_or_else(|| {
                    debug_assert!(false, "glv n22 parse failed");
                    BigUint::zero()
                }),
        );
        let modulus = BigInt::from(scalar_limbs_to_biguint(ark_bn254::Fr::MODULUS.0));
        let beta_big = BigUint::parse_bytes(
            b"21888242871839275220042445260109153167277707414472061641714758635765020556616",
            10,
        )
        .unwrap_or_else(|| {
            debug_assert!(false, "glv beta parse failed");
            BigUint::zero()
        });
        let beta_limbs = biguint_to_limbs(&beta_big);
        let beta_fq = match fq_from_limbs(beta_limbs) {
            Some(value) => value,
            None => {
                debug_assert!(false, "glv beta limbs not canonical");
                Fq::ZERO
            }
        };
        GlvConstants {
            n11,
            n12,
            n21,
            n22,
            modulus,
            beta: FqElem(limbs_from_fq(beta_fq)),
        }
    })
}

fn glv_decompose_scalar(scalar_limbs: [u64; 4]) -> ((bool, [u64; 4]), (bool, [u64; 4])) {
    let constants = glv_constants();
    let scalar = BigInt::from(scalar_limbs_to_biguint(scalar_limbs));
    let r = &constants.modulus;

    let (mut beta_1, rem1) = (&scalar * &constants.n22).div_rem(r);
    if (&rem1 + &rem1) > *r {
        beta_1 += 1;
    }
    let (mut beta_2, rem2) = (&scalar * (-constants.n12.clone())).div_rem(r);
    if (&rem2 + &rem2) > *r {
        beta_2 += 1;
    }

    let b1 = &beta_1 * &constants.n11 + &beta_2 * &constants.n21;
    let b2 = &beta_1 * &constants.n12 + &beta_2 * &constants.n22;

    let k1 = &scalar - b1;
    let k2 = -b2;

    let (sgn1, k1_abs) = if k1.is_negative() {
        (
            false,
            k1.abs().to_biguint().unwrap_or_else(|| {
                debug_assert!(false, "k1 abs to_biguint failed");
                BigUint::zero()
            }),
        )
    } else {
        (
            true,
            k1.to_biguint().unwrap_or_else(|| {
                debug_assert!(false, "k1 to_biguint failed");
                BigUint::zero()
            }),
        )
    };
    let (sgn2, k2_abs) = if k2.is_negative() {
        (
            false,
            k2.abs().to_biguint().unwrap_or_else(|| {
                debug_assert!(false, "k2 abs to_biguint failed");
                BigUint::zero()
            }),
        )
    } else {
        (
            true,
            k2.to_biguint().unwrap_or_else(|| {
                debug_assert!(false, "k2 to_biguint failed");
                BigUint::zero()
            }),
        )
    };

    ((sgn1, biguint_to_limbs(&k1_abs)), (sgn2, biguint_to_limbs(&k2_abs)))
}

fn g1_precompute_window(ctx: &mut TraceCtx, base: G1Affine, width: usize) -> Vec<G1Affine> {
    let count = (1usize << width) - 1;
    let mut out = Vec::with_capacity(count);
    if fixed_base_precomp_enabled() && base == g1_generator() {
        return g1_precompute_window_const(width);
    }
    let mut acc = g1_jacobian_from_affine(base);
    for _ in 0..count {
        let affine = match g1_jacobian_to_affine(ctx, acc) {
            Ok(value) => value,
            Err(err) => {
                ctx.set_error(err);
                debug_assert!(false, "g1 precomp affine failed");
                return vec![g1_affine_infinity(); count];
            }
        };
        out.push(affine);
        acc = g1_jacobian_add_mixed(ctx, acc, base);
    }
    out
}

fn g1_precompute_wnaf(ctx: &mut TraceCtx, base: G1Affine, window: usize) -> Vec<G1Affine> {
    let count = 1usize << (window - 2);
    let mut out = Vec::with_capacity(count);
    if fixed_base_precomp_enabled() && base == g1_generator() {
        return g1_precompute_wnaf_const(window);
    }
    let mut acc = g1_jacobian_from_affine(base);
    let first = match g1_jacobian_to_affine(ctx, acc) {
        Ok(value) => value,
        Err(err) => {
            ctx.set_error(err);
            debug_assert!(false, "g1 wnaf precomp affine failed");
            return vec![g1_affine_infinity(); count];
        }
    };
    out.push(first);
    if count == 1 {
        return out;
    }
    let base2 = g1_jacobian_double(ctx, acc);
    let base2_affine = match g1_jacobian_to_affine(ctx, base2) {
        Ok(value) => value,
        Err(err) => {
            ctx.set_error(err);
            debug_assert!(false, "g1 wnaf base2 affine failed");
            return vec![g1_affine_infinity(); count];
        }
    };
    for _ in 1..count {
        acc = g1_jacobian_add_mixed(ctx, acc, base2_affine);
        let affine = match g1_jacobian_to_affine(ctx, acc) {
            Ok(value) => value,
            Err(err) => {
                ctx.set_error(err);
                debug_assert!(false, "g1 wnaf precomp affine failed");
                return vec![g1_affine_infinity(); count];
            }
        };
        out.push(affine);
    }
    out
}

#[allow(dead_code)]
fn g2_precompute_window(ctx: &mut TraceCtx, base: G2Affine, width: usize) -> Vec<G2Affine> {
    let count = (1usize << width) - 1;
    let mut out = Vec::with_capacity(count);
    if fixed_base_precomp_enabled() && base == g2_generator() {
        return g2_precompute_window_const(width);
    }
    let mut acc = g2_jacobian_from_affine(base);
    for _ in 0..count {
        let affine = match g2_jacobian_to_affine(ctx, acc) {
            Ok(value) => value,
            Err(err) => {
                ctx.set_error(err);
                debug_assert!(false, "g2 precomp affine failed");
                return vec![g2_affine_infinity(); count];
            }
        };
        out.push(affine);
        acc = g2_jacobian_add_mixed(ctx, acc, base);
    }
    out
}

fn g1_scalar_mul_windowed(
    ctx: &mut TraceCtx,
    base: G1Affine,
    scalar_limbs: [u64; 4],
) -> G1Jacobian {
    if base.infinity {
        return g1_jacobian_infinity();
    }
    let Some(top) = scalar_high_bit(scalar_limbs) else {
        return g1_jacobian_infinity();
    };
    let width = scalar_window_width();
    let precomp = g1_precompute_window(ctx, base, width);
    let total_bits = top + 1;
    let windows = total_bits.div_ceil(width);
    let mut acc = g1_jacobian_infinity();
    for window in (0..windows).rev() {
        for _ in 0..width {
            acc = g1_jacobian_double(ctx, acc);
        }
        let start = window * width;
        let value = scalar_window_value(scalar_limbs, start, width);
        if value != 0 {
            let addend = precomp[value - 1];
            if acc.infinity {
                acc = g1_jacobian_from_affine(addend);
            } else {
                acc = g1_jacobian_add_mixed(ctx, acc, addend);
            }
        }
    }
    acc
}

#[allow(dead_code)]
fn g2_scalar_mul_windowed(
    ctx: &mut TraceCtx,
    base: G2Affine,
    scalar_limbs: [u64; 4],
) -> G2Jacobian {
    if base.infinity {
        return g2_jacobian_infinity();
    }
    let Some(top) = scalar_high_bit(scalar_limbs) else {
        return g2_jacobian_infinity();
    };
    let width = scalar_window_width();
    let precomp = g2_precompute_window(ctx, base, width);
    let total_bits = top + 1;
    let windows = total_bits.div_ceil(width);
    let mut acc = g2_jacobian_infinity();
    for window in (0..windows).rev() {
        for _ in 0..width {
            acc = g2_jacobian_double(ctx, acc);
        }
        let start = window * width;
        let value = scalar_window_value(scalar_limbs, start, width);
        if value != 0 {
            let addend = precomp[value - 1];
            if acc.infinity {
                acc = g2_jacobian_from_affine(addend);
            } else {
                acc = g2_jacobian_add_mixed(ctx, acc, addend);
            }
        }
    }
    acc
}

fn g1_scalar_mul_wnaf(ctx: &mut TraceCtx, base: G1Affine, scalar_limbs: [u64; 4]) -> G1Jacobian {
    if base.infinity {
        return g1_jacobian_infinity();
    }
    let window = wnaf_window_width();
    let digits = wnaf_digits(scalar_limbs, window);
    if digits.is_empty() {
        return g1_jacobian_infinity();
    }
    let precomp = g1_precompute_wnaf(ctx, base, window);
    let mut acc = g1_jacobian_infinity();
    for digit in digits.iter().rev() {
        acc = g1_jacobian_double(ctx, acc);
        if *digit == 0 {
            continue;
        }
        let idx = ((digit.unsigned_abs() as usize) - 1) / 2;
        let mut addend = precomp[idx];
        if *digit < 0 {
            addend = neg_g1(ctx, addend);
        }
        if acc.infinity {
            acc = g1_jacobian_from_affine(addend);
        } else {
            acc = g1_jacobian_add_mixed(ctx, acc, addend);
        }
    }
    acc
}

fn g1_scalar_mul_wnaf_precomp(
    ctx: &mut TraceCtx,
    base: G1Affine,
    scalar_limbs: [u64; 4],
    window: usize,
    precomp: &[G1Affine],
) -> G1Jacobian {
    if base.infinity {
        return g1_jacobian_infinity();
    }
    let digits = wnaf_digits(scalar_limbs, window);
    if digits.is_empty() {
        return g1_jacobian_infinity();
    }
    let mut acc = g1_jacobian_infinity();
    for digit in digits.iter().rev() {
        acc = g1_jacobian_double(ctx, acc);
        if *digit == 0 {
            continue;
        }
        let idx = ((digit.unsigned_abs() as usize) - 1) / 2;
        let mut addend = precomp[idx];
        if *digit < 0 {
            addend = neg_g1(ctx, addend);
        }
        if acc.infinity {
            acc = g1_jacobian_from_affine(addend);
        } else {
            acc = g1_jacobian_add_mixed(ctx, acc, addend);
        }
    }
    acc
}

#[allow(dead_code)]
fn g2_scalar_mul_wnaf(ctx: &mut TraceCtx, base: G2Affine, scalar_limbs: [u64; 4]) -> G2Jacobian {
    if base.infinity {
        return g2_jacobian_infinity();
    }
    let window = wnaf_window_width();
    let digits = wnaf_digits(scalar_limbs, window);
    if digits.is_empty() {
        return g2_jacobian_infinity();
    }
    let precomp = g2_precompute_wnaf(ctx, base, window);
    let mut acc = g2_jacobian_infinity();
    for digit in digits.iter().rev() {
        acc = g2_jacobian_double(ctx, acc);
        if *digit == 0 {
            continue;
        }
        let idx = ((digit.unsigned_abs() as usize) - 1) / 2;
        let mut addend = precomp[idx];
        if *digit < 0 {
            addend = neg_g2(ctx, addend);
        }
        if acc.infinity {
            acc = g2_jacobian_from_affine(addend);
        } else {
            acc = g2_jacobian_add_mixed(ctx, acc, addend);
        }
    }
    acc
}

fn g1_endomorphism(ctx: &mut TraceCtx, p: G1Affine) -> G1Affine {
    if p.infinity {
        return p;
    }
    let beta = glv_constants().beta;
    let x = ctx.mul(p.x, beta);
    G1Affine {
        x,
        y: p.y,
        infinity: false,
    }
}

fn g1_scalar_mul_glv(ctx: &mut TraceCtx, base: G1Affine, scalar_limbs: [u64; 4]) -> G1Jacobian {
    if base.infinity {
        return g1_jacobian_infinity();
    }
    let ((sgn1, k1_limbs), (sgn2, k2_limbs)) = glv_decompose_scalar(scalar_limbs);
    let mut p1 = g1_scalar_mul_wnaf(ctx, base, k1_limbs);
    if !sgn1 {
        p1 = g1_jacobian_neg(ctx, p1);
    }
    let phi = g1_endomorphism(ctx, base);
    let mut p2 = g1_scalar_mul_wnaf(ctx, phi, k2_limbs);
    if !sgn2 {
        p2 = g1_jacobian_neg(ctx, p2);
    }
    if p1.infinity {
        p2
    } else if p2.infinity {
        p1
    } else {
        g1_jacobian_add(ctx, p1, p2)
    }
}

fn g1_scalar_mul_glv_precomp(
    ctx: &mut TraceCtx,
    scalar_limbs: [u64; 4],
    precomp: &G1WnafPrecomp,
) -> G1Jacobian {
    let base = match precomp.base.first() {
        Some(base) => *base,
        None => return g1_jacobian_infinity(),
    };
    if base.infinity {
        return g1_jacobian_infinity();
    }
    let phi = match precomp.phi.first() {
        Some(phi) => *phi,
        None => return g1_jacobian_infinity(),
    };
    let ((sgn1, k1_limbs), (sgn2, k2_limbs)) = glv_decompose_scalar(scalar_limbs);
    let mut p1 = g1_scalar_mul_wnaf_precomp(ctx, base, k1_limbs, precomp.window, &precomp.base);
    if !sgn1 {
        p1 = g1_jacobian_neg(ctx, p1);
    }
    let mut p2 = g1_scalar_mul_wnaf_precomp(ctx, phi, k2_limbs, precomp.window, &precomp.phi);
    if !sgn2 {
        p2 = g1_jacobian_neg(ctx, p2);
    }
    if p1.infinity {
        p2
    } else if p2.infinity {
        p1
    } else {
        g1_jacobian_add(ctx, p1, p2)
    }
}

#[allow(dead_code)]
fn g2_precompute_wnaf(ctx: &mut TraceCtx, base: G2Affine, window: usize) -> Vec<G2Affine> {
    let count = 1usize << (window - 2);
    let mut out = Vec::with_capacity(count);
    if fixed_base_precomp_enabled() && base == g2_generator() {
        return g2_precompute_wnaf_const(window);
    }
    let mut acc = g2_jacobian_from_affine(base);
    let first = match g2_jacobian_to_affine(ctx, acc) {
        Ok(value) => value,
        Err(err) => {
            ctx.set_error(err);
            debug_assert!(false, "g2 wnaf precomp affine failed");
            return vec![g2_affine_infinity(); count];
        }
    };
    out.push(first);
    if count == 1 {
        return out;
    }
    let base2 = g2_jacobian_double(ctx, acc);
    let base2_affine = match g2_jacobian_to_affine(ctx, base2) {
        Ok(value) => value,
        Err(err) => {
            ctx.set_error(err);
            debug_assert!(false, "g2 wnaf base2 affine failed");
            return vec![g2_affine_infinity(); count];
        }
    };
    for _ in 1..count {
        acc = g2_jacobian_add_mixed(ctx, acc, base2_affine);
        let affine = match g2_jacobian_to_affine(ctx, acc) {
            Ok(value) => value,
            Err(err) => {
                ctx.set_error(err);
                debug_assert!(false, "g2 wnaf precomp affine failed");
                return vec![g2_affine_infinity(); count];
            }
        };
        out.push(affine);
    }
    out
}

fn g1_scalar_mul(ctx: &mut TraceCtx, base: G1Affine, scalar_limbs: [u64; 4]) -> G1Jacobian {
    match scalar_mul_algo() {
        ScalarMulAlgo::Window => g1_scalar_mul_windowed(ctx, base, scalar_limbs),
        ScalarMulAlgo::Wnaf => g1_scalar_mul_wnaf(ctx, base, scalar_limbs),
        ScalarMulAlgo::GlvWnaf => g1_scalar_mul_glv(ctx, base, scalar_limbs),
    }
}

#[allow(dead_code)]
fn g2_scalar_mul(ctx: &mut TraceCtx, base: G2Affine, scalar_limbs: [u64; 4]) -> G2Jacobian {
    match scalar_mul_algo() {
        ScalarMulAlgo::Window => g2_scalar_mul_windowed(ctx, base, scalar_limbs),
        ScalarMulAlgo::Wnaf | ScalarMulAlgo::GlvWnaf => g2_scalar_mul_wnaf(ctx, base, scalar_limbs),
    }
}

#[allow(dead_code)]
fn neg_g2(ctx: &mut TraceCtx, p: G2Affine) -> G2Affine {
    if p.infinity {
        p
    } else {
        G2Affine {
            x: p.x,
            y: fq2_neg(ctx, p.y),
            infinity: false,
        }
    }
}

#[allow(clippy::missing_const_for_thread_local)]
fn g1_msm_pippenger(
    ctx: &mut TraceCtx,
    bases: &[G1Affine],
    scalars: &[[u64; 4]],
) -> G1Jacobian {
    if bases.is_empty() {
        return g1_jacobian_infinity();
    }
    let width = msm_window_width(bases.len());
    let mut max_bit = 0usize;
    for scalar in scalars {
        if let Some(bit) = scalar_high_bit(*scalar) {
            if bit > max_bit {
                max_bit = bit;
            }
        }
    }
    let total_bits = max_bit + 1;
    let windows = total_bits.div_ceil(width);

    struct MsmScratch {
        scalar_windows: Vec<u16>,
        buckets: Vec<G1Jacobian>,
        used: Vec<usize>,
        used_bits: Vec<u64>,
        used_words: Vec<usize>,
    }

    const MSM_SCRATCH_INIT: MsmScratch = MsmScratch {
        scalar_windows: Vec::new(),
        buckets: Vec::new(),
        used: Vec::new(),
        used_bits: Vec::new(),
        used_words: Vec::new(),
    };

    thread_local! {
        static MSM_SCRATCH: std::cell::RefCell<MsmScratch> = std::cell::RefCell::new(MSM_SCRATCH_INIT);
    }

    let bucket_count = (1usize << width) - 1;
    MSM_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        let total_windows = bases.len() * windows;
        if scratch.scalar_windows.len() < total_windows {
            scratch.scalar_windows.resize(total_windows, 0u16);
        }
        if scratch.buckets.len() < bucket_count {
            scratch.buckets.resize(bucket_count, g1_jacobian_infinity());
        }
        let word_count = bucket_count.div_ceil(64);
        if scratch.used_bits.len() < word_count {
            scratch.used_bits.resize(word_count, 0u64);
        }
        scratch.used.clear();
        scratch.used_bits.fill(0u64);
        scratch.used_words.clear();

        {
            let scalar_windows = &mut scratch.scalar_windows[..total_windows];
            for (idx, scalar) in scalars.iter().enumerate() {
                let base = idx * windows;
                for window in 0..windows {
                    let start = window * width;
                    scalar_windows[base + window] = scalar_window_value(*scalar, start, width) as u16;
                }
            }
        }

        let scalar_windows_ptr = scratch.scalar_windows.as_ptr();
        let scalar_windows_len = total_windows;
        let buckets_ptr = scratch.buckets.as_mut_ptr();
        let used_ptr = &mut scratch.used as *mut Vec<usize>;
        let used_bits_ptr = &mut scratch.used_bits as *mut Vec<u64>;
        let used_words_ptr = &mut scratch.used_words as *mut Vec<usize>;
        let buckets = unsafe { std::slice::from_raw_parts_mut(buckets_ptr, bucket_count) };
        let used = unsafe { &mut *used_ptr };
        let used_bits = unsafe { &mut *used_bits_ptr };
        let used_words = unsafe { &mut *used_words_ptr };

        let mut acc = g1_jacobian_infinity();
        for window in (0..windows).rev() {
            for _ in 0..width {
                acc = g1_jacobian_double(ctx, acc);
            }
            for idx in used.iter() {
                buckets[*idx] = g1_jacobian_infinity();
            }
            used.clear();
            for &word_idx in used_words.iter() {
                used_bits[word_idx] = 0u64;
            }
            used_words.clear();
            for (base_idx, base) in bases.iter().enumerate() {
                let idx = base_idx * windows + window;
                let value = if idx < scalar_windows_len {
                    unsafe { *scalar_windows_ptr.add(idx) as usize }
                } else {
                    0
                };
                if value == 0 {
                    continue;
                }
                let bucket_idx = value - 1;
                let entry = &mut buckets[bucket_idx];
                if entry.infinity {
                    *entry = g1_jacobian_from_affine(*base);
                    used.push(bucket_idx);
                    let word_idx = bucket_idx >> 6;
                    let bit = 1u64 << (bucket_idx & 63);
                    let word = &mut used_bits[word_idx];
                    if *word == 0 {
                        used_words.push(word_idx);
                    }
                    *word |= bit;
                } else {
                    *entry = g1_jacobian_add_mixed(ctx, *entry, *base);
                }
            }
            if !used.is_empty() {
                let mut running = g1_jacobian_infinity();
                let mut window_sum = g1_jacobian_infinity();
                if used.len() > (bucket_count / 2) {
                    let mut bucket_idx = bucket_count;
                    while bucket_idx > 0 {
                        bucket_idx -= 1;
                        let word = used_bits[bucket_idx >> 6];
                        if (word >> (bucket_idx & 63)) & 1 == 0 {
                            continue;
                        }
                        let point = buckets[bucket_idx];
                        if !point.infinity {
                            running = if running.infinity {
                                point
                            } else {
                                g1_jacobian_add(ctx, running, point)
                            };
                        }
                        if !running.infinity {
                            window_sum = if window_sum.infinity {
                                running
                            } else {
                                g1_jacobian_add(ctx, window_sum, running)
                            };
                        }
                    }
                } else {
                    let sparse_sort_threshold = 2048usize;
                    if used.len() <= sparse_sort_threshold {
                        used.sort_unstable();
                        let mut last = bucket_count;
                        for &bucket_idx in used.iter().rev() {
                            let gap = last.saturating_sub(bucket_idx + 1);
                            if gap > 0 && !running.infinity {
                                let gap_mul = g1_jacobian_mul_small(ctx, running, gap);
                                if !gap_mul.infinity {
                                    window_sum = if window_sum.infinity {
                                        gap_mul
                                    } else {
                                        g1_jacobian_add(ctx, window_sum, gap_mul)
                                    };
                                }
                            }
                            let point = buckets[bucket_idx];
                            if !point.infinity {
                                if running.infinity {
                                    running = point;
                                } else {
                                    running = g1_jacobian_add(ctx, running, point);
                                }
                            }
                            if !running.infinity {
                                window_sum = if window_sum.infinity {
                                    running
                                } else {
                                    g1_jacobian_add(ctx, window_sum, running)
                                };
                            }
                            last = bucket_idx;
                        }
                        if last > 0 && !running.infinity {
                            let gap_mul = g1_jacobian_mul_small(ctx, running, last);
                            if !gap_mul.infinity {
                                window_sum = if window_sum.infinity {
                                    gap_mul
                                } else {
                                    g1_jacobian_add(ctx, window_sum, gap_mul)
                                };
                            }
                        }
                    } else {
                        let mut last = bucket_count;
                        let mut bucket_idx = bucket_count;
                        while bucket_idx > 0 {
                            bucket_idx -= 1;
                            let word = used_bits[bucket_idx >> 6];
                            if (word >> (bucket_idx & 63)) & 1 == 0 {
                                continue;
                            }
                            let gap = last.saturating_sub(bucket_idx + 1);
                            if gap > 0 && !running.infinity {
                                let gap_mul = g1_jacobian_mul_small(ctx, running, gap);
                                if !gap_mul.infinity {
                                    window_sum = if window_sum.infinity {
                                        gap_mul
                                    } else {
                                        g1_jacobian_add(ctx, window_sum, gap_mul)
                                    };
                                }
                            }
                            let point = buckets[bucket_idx];
                            if !point.infinity {
                                if running.infinity {
                                    running = point;
                                } else {
                                    running = g1_jacobian_add(ctx, running, point);
                                }
                            }
                            if !running.infinity {
                                window_sum = if window_sum.infinity {
                                    running
                                } else {
                                    g1_jacobian_add(ctx, window_sum, running)
                                };
                            }
                            last = bucket_idx;
                        }
                        if last > 0 && !running.infinity {
                            let gap_mul = g1_jacobian_mul_small(ctx, running, last);
                            if !gap_mul.infinity {
                                window_sum = if window_sum.infinity {
                                    gap_mul
                                } else {
                                    g1_jacobian_add(ctx, window_sum, gap_mul)
                                };
                            }
                        }
                    }
                }
                if !window_sum.infinity {
                    acc = if acc.infinity { window_sum } else { g1_jacobian_add(ctx, acc, window_sum) };
                }
            }
        }
        acc
    })
}

fn g1_msm_pippenger_glv(
    ctx: &mut TraceCtx,
    bases: &[G1Affine],
    scalars: &[[u64; 4]],
) -> G1Jacobian {
    let mut glv_bases = Vec::with_capacity(bases.len() * 2);
    let mut glv_scalars = Vec::with_capacity(bases.len() * 2);

    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        let ((sgn1, k1_limbs), (sgn2, k2_limbs)) = glv_decompose_scalar(*scalar);
        let mut p1 = *base;
        if !sgn1 {
            p1 = neg_g1(ctx, p1);
        }
        glv_bases.push(p1);
        glv_scalars.push(k1_limbs);

        let mut p2 = g1_endomorphism(ctx, *base);
        if !sgn2 {
            p2 = neg_g1(ctx, p2);
        }
        glv_bases.push(p2);
        glv_scalars.push(k2_limbs);
    }

    g1_msm_pippenger(ctx, &glv_bases, &glv_scalars)
}

fn g1_msm_pippenger_glv_precomp(
    ctx: &mut TraceCtx,
    bases: &[G1Affine],
    scalars: &[[u64; 4]],
    phi_bases: &[G1Affine],
) -> G1Jacobian {
    let mut glv_bases = Vec::with_capacity(bases.len() * 2);
    let mut glv_scalars = Vec::with_capacity(bases.len() * 2);

    for ((base, scalar), phi) in bases.iter().zip(scalars.iter()).zip(phi_bases.iter()) {
        let ((sgn1, k1_limbs), (sgn2, k2_limbs)) = glv_decompose_scalar(*scalar);
        let mut p1 = *base;
        if !sgn1 {
            p1 = neg_g1(ctx, p1);
        }
        glv_bases.push(p1);
        glv_scalars.push(k1_limbs);

        let mut p2 = *phi;
        if !sgn2 {
            p2 = neg_g1(ctx, p2);
        }
        glv_bases.push(p2);
        glv_scalars.push(k2_limbs);
    }

    g1_msm_pippenger(ctx, &glv_bases, &glv_scalars)
}

fn g1_pair_sum_precomp(p: G1Affine, q: G1Affine) -> G1Affine {
    if p.infinity {
        return q;
    }
    if q.infinity {
        return p;
    }
    let mut ctx = TraceCtx::new_discard();
    let sum = g1_jacobian_add_mixed(&mut ctx, g1_jacobian_from_affine(p), q);
    match g1_jacobian_to_affine(&mut ctx, sum) {
        Ok(value) => value,
        Err(err) => {
            debug_assert!(false, "g1 sum affine failed: {err}");
            g1_affine_infinity()
        }
    }
}

fn g1_msm_two_shamir(
    ctx: &mut TraceCtx,
    p: G1Affine,
    k1: [u64; 4],
    q: G1Affine,
    k2: [u64; 4],
) -> G1Jacobian {
    let max_bit = match (scalar_high_bit(k1), scalar_high_bit(k2)) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return g1_jacobian_infinity(),
    };
    let pq = g1_pair_sum_precomp(p, q);
    let mut acc = g1_jacobian_infinity();
    for bit in (0..=max_bit).rev() {
        acc = g1_jacobian_double(ctx, acc);
        let b1 = scalar_bit(k1, bit);
        let b2 = scalar_bit(k2, bit);
        if !b1 && !b2 {
            continue;
        }
        let addend = match (b1, b2) {
            (true, false) => p,
            (false, true) => q,
            (true, true) => pq,
            _ => {
                debug_assert!(false, "bit pattern");
                p
            }
        };
        acc = if acc.infinity {
            g1_jacobian_from_affine(addend)
        } else {
            g1_jacobian_add_mixed(ctx, acc, addend)
        };
    }
    acc
}

fn msm_use_glv() -> bool {
    std::env::var("GLYPH_BN254_MSM_GLV")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(true)
}

fn msm_window_width(bases_len: usize) -> usize {
    if let Ok(val) = std::env::var("GLYPH_BN254_MSM_WINDOW") {
        if let Ok(width) = val.parse::<usize>() {
            if (2..=12).contains(&width) {
                return width;
            }
        }
    }
    match bases_len {
        0..=4 => 2,
        5..=16 => 3,
        17..=64 => 4,
        65..=256 => 5,
        257..=1024 => 6,
        1025..=4096 => 7,
        _ => 8,
    }
}

fn msm_small_threshold() -> usize {
    std::env::var("GLYPH_BN254_MSM_SMALL_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| (1..=32).contains(v))
        .unwrap_or(8)
}

fn msm_precomp_threshold() -> usize {
    std::env::var("GLYPH_BN254_MSM_PRECOMP_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| (1..=64).contains(v))
        .unwrap_or(24)
}

fn msm_shamir_enabled() -> bool {
    std::env::var("GLYPH_BN254_MSM_SHAMIR")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(true)
}

fn g1_msm_with_trace(
    ctx: &mut TraceCtx,
    vk: &Groth16VerifyingKey,
    public_inputs: &[ark_bn254::Fr],
    ic_precomp: Option<&[G1WnafPrecomp]>,
) -> Result<G1Affine, String> {
    let zero_limbs = [0u64; 4];
    let one_limbs = ark_bn254::Fr::ONE.into_bigint().0;
    let neg_one_limbs = (-ark_bn254::Fr::ONE).into_bigint().0;
    let scalar_limbs: Vec<[u64; 4]> = public_inputs.iter().map(|s| s.into_bigint().0).collect();

    let wnaf_window = wnaf_window_width();
    let scalar_algo = scalar_mul_algo();
    let use_shamir = msm_shamir_enabled();
    let use_glv = msm_use_glv();
    let base_count = vk.ic.len().saturating_sub(1);
    if base_count == 0 || public_inputs.is_empty() {
        return Ok(to_g1(vk.ic[0]));
    }
    if let Some(precomp) = ic_precomp {
        if precomp.len() != base_count {
            return Err("groth16 ic precomp length mismatch".to_string());
        }
    }
    let mut acc = g1_jacobian_from_affine(to_g1(vk.ic[0]));
    let small_threshold = msm_small_threshold();
    if base_count <= small_threshold {
        let mut msm = g1_jacobian_infinity();
        for (idx, (ic, scalar_limbs)) in vk.ic.iter().skip(1).zip(scalar_limbs.iter()).enumerate() {
            if *scalar_limbs == zero_limbs {
                continue;
            }
            let base = to_g1(*ic);
            if *scalar_limbs == one_limbs {
                msm = if msm.infinity {
                    g1_jacobian_from_affine(base)
                } else {
                    g1_jacobian_add_mixed(ctx, msm, base)
                };
                continue;
            }
            if *scalar_limbs == neg_one_limbs {
                let neg = neg_g1(ctx, base);
                msm = if msm.infinity {
                    g1_jacobian_from_affine(neg)
                } else {
                    g1_jacobian_add_mixed(ctx, msm, neg)
                };
                continue;
            }
            let mul = if let Some(precomp) = ic_precomp.and_then(|p| p.get(idx)) {
                match scalar_algo {
                    ScalarMulAlgo::GlvWnaf => {
                        if precomp.window == wnaf_window {
                            g1_scalar_mul_glv_precomp(ctx, *scalar_limbs, precomp)
                        } else {
                            g1_scalar_mul_glv(ctx, base, *scalar_limbs)
                        }
                    }
                    ScalarMulAlgo::Wnaf => {
                        if precomp.window == wnaf_window {
                            g1_scalar_mul_wnaf_precomp(
                                ctx,
                                base,
                                *scalar_limbs,
                                precomp.window,
                                &precomp.base,
                            )
                        } else {
                            g1_scalar_mul_wnaf(ctx, base, *scalar_limbs)
                        }
                    }
                    ScalarMulAlgo::Window => g1_scalar_mul(ctx, base, *scalar_limbs),
                }
            } else {
                g1_scalar_mul(ctx, base, *scalar_limbs)
            };
            msm = if msm.infinity {
                mul
            } else {
                g1_jacobian_add(ctx, msm, mul)
            };
        }
        acc = g1_jacobian_add(ctx, acc, msm);
        return g1_jacobian_to_affine(ctx, acc);
    }

    let mut extra = g1_jacobian_infinity();
    let mut filtered_bases = Vec::with_capacity(base_count);
    let mut filtered_scalars = Vec::with_capacity(base_count);
    let mut filtered_phi = ic_precomp.map(|_| Vec::with_capacity(base_count));
    let mut phi_ok = filtered_phi.is_some();
    let mut kept_indices = Vec::with_capacity(base_count);
    for (idx, (ic, scalar_limbs)) in vk.ic.iter().skip(1).zip(scalar_limbs.iter()).enumerate() {
        if *scalar_limbs == zero_limbs {
            continue;
        }
        let base = to_g1(*ic);
        if *scalar_limbs == one_limbs {
            extra = if extra.infinity {
                g1_jacobian_from_affine(base)
            } else {
                g1_jacobian_add_mixed(ctx, extra, base)
            };
            continue;
        }
        if *scalar_limbs == neg_one_limbs {
            let neg = neg_g1(ctx, base);
            extra = if extra.infinity {
                g1_jacobian_from_affine(neg)
            } else {
                g1_jacobian_add_mixed(ctx, extra, neg)
            };
            continue;
        }
        if phi_ok {
            if let Some(precomp) = ic_precomp.and_then(|p| p.get(idx)) {
                if let Some(phi) = precomp.phi.first() {
                    if let Some(phi_vec) = filtered_phi.as_mut() {
                        phi_vec.push(*phi);
                    } else {
                        phi_ok = false;
                    }
                } else {
                    phi_ok = false;
                }
            } else {
                phi_ok = false;
            }
        }
        filtered_bases.push(base);
        filtered_scalars.push(*scalar_limbs);
        kept_indices.push(idx);
    }
    if !phi_ok {
        filtered_phi = None;
    }
    if use_shamir && filtered_bases.len() == 2 {
        let msm = g1_msm_two_shamir(
            ctx,
            filtered_bases[0],
            filtered_scalars[0],
            filtered_bases[1],
            filtered_scalars[1],
        );
        if !msm.infinity {
            acc = g1_jacobian_add(ctx, acc, msm);
        }
        if !extra.infinity {
            acc = g1_jacobian_add(ctx, acc, extra);
        }
        return g1_jacobian_to_affine(ctx, acc);
    }
    if filtered_bases.len() <= small_threshold {
        let mut msm = g1_jacobian_infinity();
        for (pos, base) in filtered_bases.iter().enumerate() {
            let scalar_limbs = filtered_scalars[pos];
            let precomp = ic_precomp.and_then(|p| p.get(kept_indices[pos]));
            let mul = if let Some(precomp) = precomp {
                match scalar_algo {
                    ScalarMulAlgo::GlvWnaf => {
                        if precomp.window == wnaf_window {
                            g1_scalar_mul_glv_precomp(ctx, scalar_limbs, precomp)
                        } else {
                            g1_scalar_mul_glv(ctx, *base, scalar_limbs)
                        }
                    }
                    ScalarMulAlgo::Wnaf => {
                        if precomp.window == wnaf_window {
                            g1_scalar_mul_wnaf_precomp(
                                ctx,
                                *base,
                                scalar_limbs,
                                precomp.window,
                                &precomp.base,
                            )
                        } else {
                            g1_scalar_mul_wnaf(ctx, *base, scalar_limbs)
                        }
                    }
                    ScalarMulAlgo::Window => g1_scalar_mul(ctx, *base, scalar_limbs),
                }
            } else {
                g1_scalar_mul(ctx, *base, scalar_limbs)
            };
            msm = if msm.infinity {
                mul
            } else {
                g1_jacobian_add(ctx, msm, mul)
            };
        }
        if !msm.infinity {
            acc = g1_jacobian_add(ctx, acc, msm);
        }
        if !extra.infinity {
            acc = g1_jacobian_add(ctx, acc, extra);
        }
        return g1_jacobian_to_affine(ctx, acc);
    }
    let precomp_threshold = if ic_precomp.is_some() {
        msm_precomp_threshold()
    } else {
        0
    };
    if precomp_threshold > 0 && filtered_bases.len() <= precomp_threshold {
        let mut msm = g1_jacobian_infinity();
        for (pos, base) in filtered_bases.iter().enumerate() {
            let scalar_limbs = filtered_scalars[pos];
            let precomp = ic_precomp.and_then(|p| p.get(kept_indices[pos]));
            let mul = if let Some(precomp) = precomp {
                match scalar_algo {
                    ScalarMulAlgo::GlvWnaf => {
                        if precomp.window == wnaf_window {
                            g1_scalar_mul_glv_precomp(ctx, scalar_limbs, precomp)
                        } else {
                            g1_scalar_mul_glv(ctx, *base, scalar_limbs)
                        }
                    }
                    ScalarMulAlgo::Wnaf => {
                        if precomp.window == wnaf_window {
                            g1_scalar_mul_wnaf_precomp(
                                ctx,
                                *base,
                                scalar_limbs,
                                precomp.window,
                                &precomp.base,
                            )
                        } else {
                            g1_scalar_mul_wnaf(ctx, *base, scalar_limbs)
                        }
                    }
                    ScalarMulAlgo::Window => g1_scalar_mul(ctx, *base, scalar_limbs),
                }
            } else {
                g1_scalar_mul(ctx, *base, scalar_limbs)
            };
            msm = if msm.infinity {
                mul
            } else {
                g1_jacobian_add(ctx, msm, mul)
            };
        }
        if !msm.infinity {
            acc = g1_jacobian_add(ctx, acc, msm);
        }
        if !extra.infinity {
            acc = g1_jacobian_add(ctx, acc, extra);
        }
        return g1_jacobian_to_affine(ctx, acc);
    }
    if !filtered_bases.is_empty() {
        let msm = if use_glv {
            if let Some(phi_bases) = filtered_phi.as_ref() {
                if phi_bases.len() == filtered_bases.len() {
                    g1_msm_pippenger_glv_precomp(ctx, &filtered_bases, &filtered_scalars, phi_bases)
                } else {
                    g1_msm_pippenger_glv(ctx, &filtered_bases, &filtered_scalars)
                }
            } else {
                g1_msm_pippenger_glv(ctx, &filtered_bases, &filtered_scalars)
            }
        } else {
            g1_msm_pippenger(ctx, &filtered_bases, &filtered_scalars)
        };
        acc = g1_jacobian_add(ctx, acc, msm);
    }
    if !extra.infinity {
        acc = g1_jacobian_add(ctx, acc, extra);
    }
    g1_jacobian_to_affine(ctx, acc)
}

fn to_g2(p: ArkG2Affine) -> G2Affine {
    if p.is_zero() {
        return G2Affine {
            x: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            y: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            infinity: true,
        };
    }
    G2Affine {
        x: Fq2Elem {
            c0: FqElem(limbs_from_fq(p.x.c0)),
            c1: FqElem(limbs_from_fq(p.x.c1)),
        },
        y: Fq2Elem {
            c0: FqElem(limbs_from_fq(p.y.c0)),
            c1: FqElem(limbs_from_fq(p.y.c1)),
        },
        infinity: false,
    }
}

fn expected_g2_precomp_coeffs_len() -> usize {
    let mut count = 0usize;
    for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
        count += 1;
        if *bit != 0 {
            count += 1;
        }
    }
    count + 2
}

fn expected_g2_precomp_bytes_len() -> usize {
    expected_g2_precomp_coeffs_len() * 192
}

fn expected_g1_wnaf_precomp_len(window: usize) -> Result<usize, String> {
    if window < 2 {
        return Err("g1 wnaf window must be >= 2".to_string());
    }
    Ok(1usize << (window - 2))
}

fn encode_g1_precomp_bytes(points: &[G1Affine]) -> Vec<u8> {
    let mut out = Vec::with_capacity(points.len() * 64);
    for point in points {
        out.extend_from_slice(&fqelem_to_be_bytes(point.x));
        out.extend_from_slice(&fqelem_to_be_bytes(point.y));
    }
    out
}

fn decode_g1_precomp_bytes(bytes: &[u8], window: usize) -> Result<Vec<G1Affine>, String> {
    let expected = expected_g1_wnaf_precomp_len(window)? * 64;
    if bytes.len() != expected {
        return Err(format!(
            "g1 precomp bytes length mismatch: expected {expected} got {}",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 64);
    let mut off = 0usize;
    while off < bytes.len() {
        let x = bytes
            .get(off..off + 32)
            .ok_or_else(|| "g1 precomp bytes unexpected EOF".to_string())?;
        let y = bytes
            .get(off + 32..off + 64)
            .ok_or_else(|| "g1 precomp bytes unexpected EOF".to_string())?;
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(x);
        y_bytes.copy_from_slice(y);
        if !is_canonical_be(x_bytes) || !is_canonical_be(y_bytes) {
            return Err("g1 precomp bytes not canonical".to_string());
        }
        let x_limbs = limbs_from_be_bytes(x_bytes);
        let y_limbs = limbs_from_be_bytes(y_bytes);
        out.push(G1Affine {
            x: FqElem(x_limbs),
            y: FqElem(y_limbs),
            infinity: false,
        });
        off += 64;
    }
    Ok(out)
}

fn decode_g1_precomp_bytes_cached(bytes: &[u8], window: usize) -> Result<Vec<G1Affine>, String> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    type G1PrecompCache = OnceLock<Mutex<HashMap<(usize, Vec<u8>), Vec<G1Affine>>>>;
    static CACHE: G1PrecompCache = OnceLock::new();
    let key = (window, bytes.to_vec());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g1 precomp bytes cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(entry) = guard.get(&key) {
        return Ok(entry.clone());
    }
    let out = decode_g1_precomp_bytes(bytes, window)?;
    guard.insert(key, out.clone());
    Ok(out)
}

pub fn encode_g1_wnaf_precomp_bytes(base: ArkG1Affine, window: usize) -> Vec<u8> {
    let mut ctx = TraceCtx::new();
    let base = to_g1(base);
    let precomp = g1_precompute_wnaf(&mut ctx, base, window);
    encode_g1_precomp_bytes(&precomp)
}

pub fn encode_g1_wnaf_precomp_phi_bytes(base: ArkG1Affine, window: usize) -> Vec<u8> {
    let mut ctx = TraceCtx::new();
    let base = to_g1(base);
    let phi = g1_endomorphism(&mut ctx, base);
    let precomp = g1_precompute_wnaf(&mut ctx, phi, window);
    encode_g1_precomp_bytes(&precomp)
}

pub fn decode_g1_wnaf_precomp_pair(
    window: usize,
    base_bytes: &[u8],
    phi_bytes: &[u8],
) -> Result<G1WnafPrecomp, String> {
    let base = decode_g1_precomp_bytes_cached(base_bytes, window)?;
    let phi = decode_g1_precomp_bytes_cached(phi_bytes, window)?;
    Ok(G1WnafPrecomp { window, base, phi })
}

fn encode_prepared_g2_bytes(prep: &G2Prepared) -> Vec<u8> {
    let mut out = Vec::with_capacity(prep.ell_coeffs.len() * 192);
    for (c0, c1, c2) in prep.ell_coeffs.iter() {
        for coeff in [*c0, *c1, *c2] {
            let (im, re) = fq2_to_be_bytes(coeff);
            out.extend_from_slice(&im);
            out.extend_from_slice(&re);
        }
    }
    out
}

fn decode_g2_precomp_bytes(bytes: &[u8]) -> Result<G2Prepared, String> {
    let expected = expected_g2_precomp_bytes_len();
    if bytes.len() != expected {
        return Err(format!(
            "g2 precomp bytes length mismatch: expected {expected} got {}",
            bytes.len()
        ));
    }
    if !bytes.len().is_multiple_of(192) {
        return Err("g2 precomp bytes length must be multiple of 192".to_string());
    }
    let mut off = 0usize;
    let mut ell_coeffs = Vec::with_capacity(bytes.len() / 192);
    let read32 = |bytes: &[u8], off: &mut usize| -> Result<[u8; 32], String> {
        let s = bytes
            .get(*off..*off + 32)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        *off += 32;
        Ok(out)
    };
    let read_fq2 = |bytes: &[u8], off: &mut usize| -> Result<Fq2Elem, String> {
        let im = read32(bytes, off)?;
        let re = read32(bytes, off)?;
        fq2_from_be_bytes(im, re)
    };
    while off < bytes.len() {
        let c0 = read_fq2(bytes, &mut off)?;
        let c1 = read_fq2(bytes, &mut off)?;
        let c2 = read_fq2(bytes, &mut off)?;
        ell_coeffs.push((c0, c1, c2));
    }
    Ok(G2Prepared {
        ell_coeffs,
        _infinity: false,
    })
}

fn decode_g2_precomp_bytes_cached(bytes: &[u8]) -> Result<G2Prepared, String> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, G2Prepared>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g2 precomp bytes cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(entry) = guard.get(bytes) {
        return Ok(entry.clone());
    }
    let prep = decode_g2_precomp_bytes(bytes)?;
    guard.insert(bytes.to_vec(), prep.clone());
    Ok(prep)
}

pub fn encode_g2_precomp_bytes(q: ArkG2Affine) -> Vec<u8> {
    let mut ctx = TraceCtx::new();
    let prep = G2Prepared::from(&mut ctx, to_g2(q));
    encode_prepared_g2_bytes(&prep)
}

fn kzg_accumulator_with_trace(
    ctx: &mut TraceCtx,
    g1: G1Affine,
    commitment: G1Affine,
    proof: G1Affine,
    z: ark_bn254::Fr,
    y: ark_bn254::Fr,
) -> Result<G1Affine, String> {
    if !kzg_joint_msm_enabled() {
        let neg_one = -ark_bn254::Fr::ONE;
        let mut acc = g1_jacobian_from_affine(commitment);
        if !y.is_zero() {
            if y == ark_bn254::Fr::ONE {
                let neg = neg_g1(ctx, g1);
                acc = g1_jacobian_add_mixed(ctx, acc, neg);
            } else if y == neg_one {
                acc = g1_jacobian_add_mixed(ctx, acc, g1);
            } else {
                let y_mul = g1_scalar_mul(ctx, g1, y.into_bigint().0);
                let y_neg = g1_jacobian_neg(ctx, y_mul);
                acc = g1_jacobian_add(ctx, acc, y_neg);
            }
        }
        if !z.is_zero() {
            if z == ark_bn254::Fr::ONE {
                acc = g1_jacobian_add_mixed(ctx, acc, proof);
            } else if z == neg_one {
                let neg = neg_g1(ctx, proof);
                acc = g1_jacobian_add_mixed(ctx, acc, neg);
            } else {
                let z_mul = g1_scalar_mul(ctx, proof, z.into_bigint().0);
                acc = g1_jacobian_add(ctx, acc, z_mul);
            }
        }
        return g1_jacobian_to_affine(ctx, acc);
    }

    let neg_one = -ark_bn254::Fr::ONE;
    let mut extra = g1_jacobian_infinity();
    let mut bases = Vec::with_capacity(2);
    let mut scalars = Vec::with_capacity(2);
    if !commitment.infinity {
        extra = g1_jacobian_from_affine(commitment);
    }
    let z_limbs = z.into_bigint().0;
    if !proof.infinity && scalar_high_bit(z_limbs).is_some() {
        if z == ark_bn254::Fr::ONE {
            extra = if extra.infinity {
                g1_jacobian_from_affine(proof)
            } else {
                g1_jacobian_add_mixed(ctx, extra, proof)
            };
        } else if z == neg_one {
            let neg = neg_g1(ctx, proof);
            extra = if extra.infinity {
                g1_jacobian_from_affine(neg)
            } else {
                g1_jacobian_add_mixed(ctx, extra, neg)
            };
        } else {
            bases.push(proof);
            scalars.push(z_limbs);
        }
    }
    let y_limbs = y.into_bigint().0;
    if scalar_high_bit(y_limbs).is_some() {
        if y == ark_bn254::Fr::ONE {
            let neg = neg_g1(ctx, g1);
            extra = if extra.infinity {
                g1_jacobian_from_affine(neg)
            } else {
                g1_jacobian_add_mixed(ctx, extra, neg)
            };
        } else if y == neg_one {
            extra = if extra.infinity {
                g1_jacobian_from_affine(g1)
            } else {
                g1_jacobian_add_mixed(ctx, extra, g1)
            };
        } else {
            bases.push(neg_g1(ctx, g1));
            scalars.push(y_limbs);
        }
    }
    if bases.is_empty() {
        return g1_jacobian_to_affine(ctx, extra);
    }
    let msm = if bases.len() == 1 {
        g1_scalar_mul(ctx, bases[0], scalars[0])
    } else if msm_shamir_enabled() && bases.len() == 2 {
        g1_msm_two_shamir(ctx, bases[0], scalars[0], bases[1], scalars[1])
    } else if msm_use_glv() {
        g1_msm_pippenger_glv(ctx, &bases, &scalars)
    } else {
        g1_msm_pippenger(ctx, &bases, &scalars)
    };
    let out = if extra.infinity {
        msm
    } else {
        g1_jacobian_add(ctx, extra, msm)
    };
    g1_jacobian_to_affine(ctx, out)
}

pub fn record_kzg_pairing_ops(
    g1: ArkG1Affine,
    g2: ArkG2Affine,
    g2_s: ArkG2Affine,
    commitment: ArkG1Affine,
    proof: ArkG1Affine,
    z: ark_bn254::Fr,
    y: ark_bn254::Fr,
) -> Result<Vec<Bn254OpTraceEvent>, String> {
    record_kzg_pairing_ops_with_precomp(g1, g2, g2_s, commitment, proof, z, y, None)
}

#[allow(clippy::too_many_arguments)]
pub fn record_kzg_pairing_ops_with_precomp(
    g1: ArkG1Affine,
    g2: ArkG2Affine,
    g2_s: ArkG2Affine,
    commitment: ArkG1Affine,
    proof: ArkG1Affine,
    z: ark_bn254::Fr,
    y: ark_bn254::Fr,
    g2s_precomp: Option<&[u8]>,
) -> Result<Vec<Bn254OpTraceEvent>, String> {
    let mut ctx = TraceCtx::new();

    let g2_auto = g2_precomp_auto_enabled();
    let g1 = to_g1(g1);
    let g2 = to_g2(g2);
    let g2_s = to_g2(g2_s);
    let commitment = to_g1(commitment);
    let proof = to_g1(proof);

    let c_plus_affine = kzg_accumulator_with_trace(&mut ctx, g1, commitment, proof, z, y)?;
    let proof_neg = neg_g1(&mut ctx, proof);

    let mut prepped = Vec::with_capacity(2);
    let g2_precomp = if g2 == to_g2(ArkG2Affine::generator()) {
        Some(g2_generator_precomp().clone())
    } else if g2_auto {
        Some(g2_prepared_cached(g2))
    } else {
        None
    };
    let g2s_precomp = match g2s_precomp {
        Some(bytes) => Some(decode_g2_precomp_bytes_cached(bytes)?),
        None => {
            if g2_auto {
                Some(g2_prepared_cached(g2_s))
            } else {
                None
            }
        }
    };
    push_prepared_pair(&mut prepped, &mut ctx, c_plus_affine, g2, g2_precomp);
    push_prepared_pair(&mut prepped, &mut ctx, proof_neg, g2_s, g2s_precomp);
    let product = pairing_product_prepared(&mut ctx, &mut prepped);
    assert_fq12_eq_one(&mut ctx, product);

    if std::env::var("GLYPH_KZG_BN254_TRACE_STATS")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        let (adds, subs, muls) = ctx.counts();
        eprintln!(
            "bn254 kzg trace ops: add={adds} sub={subs} mul={muls} total={}",
            ctx.total_events()
        );
    }

    let events = ctx.finish_events()?;
    if trace_validate_batch_enabled() {
        crate::bn254_ops::validate_bn254_op_trace_batch(&events)?;
    }
    Ok(events)
}


fn push_prepared_pair(
    prepped: &mut Vec<(G1Affine, G2Prepared, usize)>,
    ctx: &mut TraceCtx,
    p: G1Affine,
    q: G2Affine,
    precomp: Option<G2Prepared>,
) {
    if p.infinity || q.infinity {
        return;
    }
    let prepared = precomp.unwrap_or_else(|| G2Prepared::from(ctx, q));
    prepped.push((p, prepared, 0));
}

pub fn record_groth16_pairing_ops(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[ark_bn254::Fr],
) -> Result<Vec<Bn254OpTraceEvent>, String> {
    record_groth16_pairing_ops_with_precomp(vk, proof, public_inputs, None, None, None, None)
}

pub fn record_g1_msm_ops(
    vk: &Groth16VerifyingKey,
    public_inputs: &[ark_bn254::Fr],
    use_precomp: bool,
) -> Result<Vec<Bn254OpTraceEvent>, String> {
    let base_count = vk.ic.len().saturating_sub(1);
    if public_inputs.len() != base_count {
        return Err("groth16 public input length mismatch".to_string());
    }
    let mut ctx = TraceCtx::new();
    let precomp = if use_precomp {
        let window = wnaf_window_width();
        Some(g1_ic_precomp_cached(vk, window))
    } else {
        None
    };
    let _ = g1_msm_with_trace(&mut ctx, vk, public_inputs, precomp.as_deref())?;
    ctx.finish_events()
}

pub fn record_g2_scalar_mul_ops(
    base: ArkG2Affine,
    scalar: ark_bn254::Fr,
    window: usize,
) -> Result<Vec<Bn254OpTraceEvent>, String> {
    if !(2..=6).contains(&window) {
        return Err("g2 scalar window must be in 2..=6".to_string());
    }
    let prev_window = std::env::var("GLYPH_BN254_SCALAR_WINDOW").ok();
    let prev_algo = std::env::var("GLYPH_BN254_SCALAR_MUL").ok();
    std::env::set_var("GLYPH_BN254_SCALAR_WINDOW", window.to_string());
    std::env::set_var("GLYPH_BN254_SCALAR_MUL", "wnaf");

    let mut ctx = TraceCtx::new();
    let base = to_g2(base);
    let _ = g2_scalar_mul_wnaf(&mut ctx, base, scalar.into_bigint().0);
    let out = ctx.finish_events();

    match prev_window {
        Some(v) => std::env::set_var("GLYPH_BN254_SCALAR_WINDOW", v),
        None => std::env::remove_var("GLYPH_BN254_SCALAR_WINDOW"),
    }
    match prev_algo {
        Some(v) => std::env::set_var("GLYPH_BN254_SCALAR_MUL", v),
        None => std::env::remove_var("GLYPH_BN254_SCALAR_MUL"),
    }

    out
}


pub fn record_groth16_pairing_ops_with_precomp(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[ark_bn254::Fr],
    beta_precomp: Option<&[u8]>,
    gamma_precomp: Option<&[u8]>,
    delta_precomp: Option<&[u8]>,
    ic_precomp: Option<&[G1WnafPrecomp]>,
) -> Result<Vec<Bn254OpTraceEvent>, String> {
    if public_inputs.len() + 1 != vk.ic.len() {
        return Err("groth16 public input length mismatch".to_string());
    }

    let g2_auto = g2_precomp_auto_enabled();
    let mut ctx = TraceCtx::new();
    let auto_ic_precomp = if ic_precomp.is_some() {
        None
    } else if g1_ic_precomp_auto_enabled() {
        let window = wnaf_window_width();
        Some(g1_ic_precomp_cached(vk, window))
    } else {
        None
    };
    let ic_precomp_tables = ic_precomp.or(auto_ic_precomp.as_deref());
    let acc_affine = g1_msm_with_trace(&mut ctx, vk, public_inputs, ic_precomp_tables)?;
    let p1 = to_g1(proof.a);
    let q1 = to_g2(proof.b);
    let p2 = to_g1(vk.alpha_g1);
    let q2 = to_g2(vk.beta_g2);
    let p3 = acc_affine;
    let q3 = to_g2(vk.gamma_g2);
    let p4 = to_g1(proof.c);
    let q4 = to_g2(vk.delta_g2);

    let p2n = neg_g1(&mut ctx, p2);
    let p3n = neg_g1(&mut ctx, p3);
    let p4n = neg_g1(&mut ctx, p4);

    let beta_precomp = if let Some(bytes) = beta_precomp {
        Some(decode_g2_precomp_bytes_cached(bytes)?)
    } else if g2_auto {
        Some(g2_prepared_cached(q2))
    } else {
        None
    };
    let gamma_precomp = if let Some(bytes) = gamma_precomp {
        Some(decode_g2_precomp_bytes_cached(bytes)?)
    } else if g2_auto {
        Some(g2_prepared_cached(q3))
    } else {
        None
    };
    let delta_precomp = if let Some(bytes) = delta_precomp {
        Some(decode_g2_precomp_bytes_cached(bytes)?)
    } else if g2_auto {
        Some(g2_prepared_cached(q4))
    } else {
        None
    };

    let mut prepped = Vec::with_capacity(4);
    push_prepared_pair(&mut prepped, &mut ctx, p1, q1, None);
    push_prepared_pair(&mut prepped, &mut ctx, p2n, q2, beta_precomp);
    push_prepared_pair(&mut prepped, &mut ctx, p3n, q3, gamma_precomp);
    push_prepared_pair(&mut prepped, &mut ctx, p4n, q4, delta_precomp);
    let product = pairing_product_prepared(&mut ctx, &mut prepped);
    assert_fq12_eq_one(&mut ctx, product);

    if std::env::var("GLYPH_GROTH16_BN254_TRACE_STATS")
        .ok()
        .as_deref()
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        let (adds, subs, muls) = ctx.counts();
        eprintln!(
            "bn254 pairing trace ops: add={adds} sub={subs} mul={muls} total={}",
            ctx.total_events()
        );
    }

    let events = ctx.finish_events()?;
    if trace_validate_batch_enabled() {
        crate::bn254_ops::validate_bn254_op_trace_batch(&events)?;
    }
    Ok(events)
}


fn ell(ctx: &mut TraceCtx, f: &mut Fq12Elem, coeffs: &(Fq2Elem, Fq2Elem, Fq2Elem), p: &G1Affine) {
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;
    let c2 = coeffs.2;
    c0 = fq2_mul_by_fp(ctx, c0, p.y);
    c1 = fq2_mul_by_fp(ctx, c1, p.x);
    fq12_mul_by_034(ctx, f, c0, c1, c2);
}

#[derive(Clone, Copy)]
struct G2HomProjective {
    x: Fq2Elem,
    y: Fq2Elem,
    z: Fq2Elem,
}

impl G2HomProjective {
    fn double_in_place(&mut self, ctx: &mut TraceCtx, two_inv: FqElem) -> (Fq2Elem, Fq2Elem, Fq2Elem) {
        let xy = fq2_mul(ctx, self.x, self.y);
        let a = fq2_mul_by_fp(ctx, xy, two_inv);
        let b = fq2_square(ctx, self.y);
        let c = fq2_square(ctx, self.z);
        let c2 = fq2_add(ctx, c, c);
        let c3 = fq2_add(ctx, c2, c);
        let e = fq2_mul_const(ctx, c3, g2_coeff_b());
        let e2 = fq2_add(ctx, e, e);
        let f = fq2_add(ctx, e2, e);
        let bpf = fq2_add(ctx, b, f);
        let g = fq2_mul_by_fp(ctx, bpf, two_inv);
        let yz = fq2_add(ctx, self.y, self.z);
        let yz_sq = fq2_square(ctx, yz);
        let bc = fq2_add(ctx, b, c);
        let h = fq2_sub(ctx, yz_sq, bc);
        let i = fq2_sub(ctx, e, b);
        let j = fq2_square(ctx, self.x);
        let e_sq = fq2_square(ctx, e);
        let e_sq2 = fq2_add(ctx, e_sq, e_sq);
        let e_sq3 = fq2_add(ctx, e_sq2, e_sq);

        let bmf = fq2_sub(ctx, b, f);
        self.x = fq2_mul(ctx, a, bmf);
        let g_sq = fq2_square(ctx, g);
        self.y = fq2_sub(ctx, g_sq, e_sq3);
        self.z = fq2_mul(ctx, b, h);

        let j2 = fq2_add(ctx, j, j);
        let j3 = fq2_add(ctx, j2, j);
        (fq2_neg(ctx, h), j3, i)
    }

    fn add_in_place(&mut self, ctx: &mut TraceCtx, q: &G2Affine) -> (Fq2Elem, Fq2Elem, Fq2Elem) {
        let qy_z = fq2_mul(ctx, q.y, self.z);
        let theta = fq2_sub(ctx, self.y, qy_z);
        let qx_z = fq2_mul(ctx, q.x, self.z);
        let lambda = fq2_sub(ctx, self.x, qx_z);
        let c = fq2_square(ctx, theta);
        let d = fq2_square(ctx, lambda);
        let e = fq2_mul(ctx, lambda, d);
        let f = fq2_mul(ctx, self.z, c);
        let g = fq2_mul(ctx, self.x, d);
        let g2 = fq2_add(ctx, g, g);
        let ef = fq2_add(ctx, e, f);
        let h = fq2_sub(ctx, ef, g2);
        self.x = fq2_mul(ctx, lambda, h);
        let g_minus_h = fq2_sub(ctx, g, h);
        let t0 = fq2_mul(ctx, theta, g_minus_h);
        let t1 = fq2_mul(ctx, e, self.y);
        self.y = fq2_sub(ctx, t0, t1);
        self.z = fq2_mul(ctx, self.z, e);
        let t2 = fq2_mul(ctx, theta, q.x);
        let t3 = fq2_mul(ctx, lambda, q.y);
        let j = fq2_sub(ctx, t2, t3);
        (lambda, fq2_neg(ctx, theta), j)
    }
}

fn mul_by_char(ctx: &mut TraceCtx, mut r: G2Affine) -> G2Affine {
    let x_frob = fq2_frobenius_unit(ctx, r.x);
    let y_frob = fq2_frobenius_unit(ctx, r.y);
    r.x = fq2_mul_const(ctx, x_frob, twist_mul_by_q_x());
    r.y = fq2_mul_const(ctx, y_frob, twist_mul_by_q_y());
    r
}

fn fq2_frobenius_unit(ctx: &mut TraceCtx, a: Fq2Elem) -> Fq2Elem {
    fq2_frobenius(ctx, a, 1)
}

fn neg_g1(ctx: &mut TraceCtx, p: G1Affine) -> G1Affine {
    if p.infinity {
        p
    } else {
        G1Affine {
            x: p.x,
            y: fq_neg(ctx, p.y),
            infinity: false,
        }
    }
}

fn pairing_product_prepared(
    ctx: &mut TraceCtx,
    prepped: &mut [(G1Affine, G2Prepared, usize)],
) -> Fq12Elem {
    let ml = multi_miller_loop_prepared(ctx, prepped);
    final_exponentiation(ctx, ml)
}

#[allow(dead_code)]
fn pairing_product(ctx: &mut TraceCtx, pairs: &[(G1Affine, G2Affine)]) -> Fq12Elem {
    let ml = multi_miller_loop(ctx, pairs);
    final_exponentiation(ctx, ml)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use std::fs::File;
    use std::io::Read;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn load_groth16_bn254_fixture() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let mut file = File::open("scripts/tools/fixtures/groth16_bn254_fixture.txt")
            .map_err(|err| format!("fixture open: {err}"))?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .map_err(|err| format!("fixture read: {err}"))?;
        let mut vk_hex = None;
        let mut proof_hex = None;
        let mut pub_hex = None;
        for line in buf.lines() {
            if let Some(rest) = line.strip_prefix("vk_hex=") {
                vk_hex = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("proof_hex=") {
                proof_hex = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("pub_inputs_hex=") {
                pub_hex = Some(rest.trim().to_string());
            }
        }
        let vk_hex = vk_hex.ok_or_else(|| "vk_hex missing".to_string())?;
        let proof_hex = proof_hex.ok_or_else(|| "proof_hex missing".to_string())?;
        let pub_hex = pub_hex.ok_or_else(|| "pub_inputs_hex missing".to_string())?;
        let vk = hex::decode(vk_hex).map_err(|err| format!("vk hex: {err}"))?;
        let proof = hex::decode(proof_hex).map_err(|err| format!("proof hex: {err}"))?;
        let pub_inputs = hex::decode(pub_hex).map_err(|err| format!("pub hex: {err}"))?;
        Ok((vk, proof, pub_inputs))
    }

    fn to_ark_g1(p: G1Affine) -> Result<ArkG1Affine, String> {
        if p.infinity {
            Ok(ArkG1Affine::identity())
        } else {
            let x = fq_from_limbs(p.x.0).ok_or_else(|| "g1 x".to_string())?;
            let y = fq_from_limbs(p.y.0).ok_or_else(|| "g1 y".to_string())?;
            Ok(ArkG1Affine::new_unchecked(x, y))
        }
    }

    fn to_ark_g2(p: G2Affine) -> Result<ArkG2Affine, String> {
        if p.infinity {
            Ok(ArkG2Affine::identity())
        } else {
            let x = ArkFq2::new(
                fq_from_limbs(p.x.c0.0).ok_or_else(|| "g2 x.c0".to_string())?,
                fq_from_limbs(p.x.c1.0).ok_or_else(|| "g2 x.c1".to_string())?,
            );
            let y = ArkFq2::new(
                fq_from_limbs(p.y.c0.0).ok_or_else(|| "g2 y.c0".to_string())?,
                fq_from_limbs(p.y.c1.0).ok_or_else(|| "g2 y.c1".to_string())?,
            );
            Ok(ArkG2Affine::new_unchecked(x, y))
        }
    }

    fn sample_scalars() -> Vec<ark_bn254::Fr> {
        let mut out = vec![
            ark_bn254::Fr::from(0u64),
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(2u64),
            ark_bn254::Fr::from(5u64),
            ark_bn254::Fr::from(13u64),
            ark_bn254::Fr::from(0xdeadbeefu64),
        ];
        let big = ark_bn254::Fr::from_le_bytes_mod_order(&[
            0xff, 0xfe, 0xfd, 0xfc, 0x11, 0x22, 0x33, 0x44, 0x88, 0x77, 0x66, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ]);
        out.push(big);
        out
    }

    #[test]
    fn test_g1_scalar_mul_glv_matches_ark() -> Result<(), String> {
        let base = ArkG1Affine::generator();
        let base_trace = to_g1(base);
        for scalar in sample_scalars() {
            let mut ctx = TraceCtx::new();
            let mul = g1_scalar_mul_glv(&mut ctx, base_trace, scalar.into_bigint().0);
            let ours = g1_jacobian_to_affine(&mut ctx, mul)?;
            let expected = (base.into_group() * scalar).into_affine();
            assert_eq!(to_ark_g1(ours)?, expected);
        }
        Ok(())
    }

    #[test]
    fn test_g2_scalar_mul_wnaf_matches_ark() -> Result<(), String> {
        let base = ArkG2Affine::generator();
        let base_trace = to_g2(base);
        for scalar in sample_scalars() {
            let mut ctx = TraceCtx::new();
            let mul = g2_scalar_mul_wnaf(&mut ctx, base_trace, scalar.into_bigint().0);
            let ours = g2_jacobian_to_affine(&mut ctx, mul)?;
            let expected = (base.into_group() * scalar).into_affine();
            assert_eq!(to_ark_g2(ours)?, expected);
        }
        Ok(())
    }

    #[test]
    fn test_groth16_msm_matches_ark() -> Result<(), String> {
        let (vk_bytes, _proof_bytes, pub_bytes) = load_groth16_bn254_fixture()?;
        let vk = crate::bn254_groth16::decode_groth16_vk_bytes(&vk_bytes)
            .map_err(|err| format!("vk decode: {err}"))?;
        let pub_inputs =
            crate::bn254_groth16::decode_groth16_public_inputs(&pub_bytes)
                .map_err(|err| format!("pub decode: {err}"))?;

        let mut ctx = TraceCtx::new();
        let acc = g1_msm_with_trace(&mut ctx, &vk, &pub_inputs, None)?;
        let acc_ark = to_ark_g1(acc)?;

        let mut expected = vk.ic[0].into_group();
        for (input, base) in pub_inputs.iter().zip(vk.ic.iter().skip(1)) {
            expected += base.mul_bigint(input.into_bigint());
        }
        let expected = expected.into_affine();
        assert_eq!(acc_ark, expected);
        Ok(())
    }

    #[test]
    fn test_groth16_msm_glv_matches_ark() -> Result<(), String> {
        std::env::set_var("GLYPH_BN254_MSM_GLV", "1");
        let (vk_bytes, _proof_bytes, pub_bytes) = load_groth16_bn254_fixture()?;
        let vk = crate::bn254_groth16::decode_groth16_vk_bytes(&vk_bytes)
            .map_err(|err| format!("vk decode: {err}"))?;
        let pub_inputs =
            crate::bn254_groth16::decode_groth16_public_inputs(&pub_bytes)
                .map_err(|err| format!("pub decode: {err}"))?;

        let mut ctx = TraceCtx::new();
        let acc = g1_msm_with_trace(&mut ctx, &vk, &pub_inputs, None)?;
        let acc_ark = to_ark_g1(acc)?;

        let mut expected = vk.ic[0].into_group();
        for (input, base) in pub_inputs.iter().zip(vk.ic.iter().skip(1)) {
            expected += base.mul_bigint(input.into_bigint());
        }
        let expected = expected.into_affine();
        assert_eq!(acc_ark, expected);
        Ok(())
    }

    #[test]
    fn test_g2_precomp_bytes_roundtrip() -> Result<(), String> {
        let g2 = ArkG2Affine::generator();
        let bytes = encode_g2_precomp_bytes(g2);
        assert_eq!(bytes.len(), expected_g2_precomp_bytes_len());
        let prep = decode_g2_precomp_bytes(&bytes)?;
        let roundtrip = encode_prepared_g2_bytes(&prep);
        assert_eq!(bytes, roundtrip);

        let mut short = bytes.clone();
        short.pop();
        assert!(decode_g2_precomp_bytes(&short).is_err());
        Ok(())
    }

    #[test]
    fn test_kzg_g2s_precomp_reduces_trace_events() -> Result<(), String> {
        let _env_lock = crate::test_utils::lock_env();
        let _g2_auto = EnvGuard::set("GLYPH_BN254_G2_PRECOMP_AUTO", "0");
        let s = ark_bn254::Fr::from(5u64);
        let z = ark_bn254::Fr::from(13u64);
        let coeffs = [
            ark_bn254::Fr::from(3u64),
            ark_bn254::Fr::from(11u64),
            ark_bn254::Fr::from(7u64),
            ark_bn254::Fr::from(2u64),
        ];

        let eval_poly = |x: ark_bn254::Fr| -> ark_bn254::Fr {
            let mut pow = ark_bn254::Fr::ONE;
            let mut acc = ark_bn254::Fr::ZERO;
            for c in coeffs.iter() {
                acc += *c * pow;
                pow *= x;
            }
            acc
        };

        let y = eval_poly(z);
        let f_s = eval_poly(s);
        let denom = match (s - z).inverse() {
            Some(value) => value,
            None => {
                assert!(false, "s must not equal z");
                return Err("s must not equal z".to_string());
            }
        };
        let q_s = (f_s - y) * denom;

        let g1 = ArkG1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let g2_s = g2.mul_bigint(s.into_bigint()).into_affine();
        let commitment = g1.mul_bigint(f_s.into_bigint()).into_affine();
        let proof = g1.mul_bigint(q_s.into_bigint()).into_affine();

        let without = record_kzg_pairing_ops(g1, g2, g2_s, commitment, proof, z, y)?;
        let g2s_precomp = encode_g2_precomp_bytes(g2_s);
        let with_precomp = record_kzg_pairing_ops_with_precomp(
            g1,
            g2,
            g2_s,
            commitment,
            proof,
            z,
            y,
            Some(&g2s_precomp),
        )
        ?;

        assert!(with_precomp.len() < without.len());
        Ok(())
    }

    #[test]
    fn test_groth16_precomp_reduces_trace_events() -> Result<(), String> {
        let _env_lock = crate::test_utils::lock_env();
        let _g2_auto = EnvGuard::set("GLYPH_BN254_G2_PRECOMP_AUTO", "0");
        let _ic_auto = EnvGuard::set("GLYPH_BN254_IC_PRECOMP_AUTO", "0");
        let (vk_bytes, proof_bytes, pub_bytes) = load_groth16_bn254_fixture()?;
        let vk = crate::bn254_groth16::decode_groth16_vk_bytes(&vk_bytes)
            .map_err(|err| format!("vk decode: {err}"))?;
        let proof = crate::bn254_groth16::decode_groth16_proof_bytes(&proof_bytes)
            .map_err(|err| format!("proof: {err}"))?;
        let pub_inputs =
            crate::bn254_groth16::decode_groth16_public_inputs(&pub_bytes)
                .map_err(|err| format!("pub decode: {err}"))?;

        let without = record_groth16_pairing_ops(&vk, &proof, &pub_inputs)?;
        let beta_precomp = encode_g2_precomp_bytes(vk.beta_g2);
        let gamma_precomp = encode_g2_precomp_bytes(vk.gamma_g2);
        let delta_precomp = encode_g2_precomp_bytes(vk.delta_g2);
        let with_precomp = record_groth16_pairing_ops_with_precomp(
            &vk,
            &proof,
            &pub_inputs,
            Some(&beta_precomp),
            Some(&gamma_precomp),
            Some(&delta_precomp),
            None,
        )
        ?;

        assert!(with_precomp.len() < without.len());
        Ok(())
    }
}

fn fq12_is_one(a: Fq12Elem) -> bool {
    let one = fq12_one();
    a == one
}

fn fq12_one() -> Fq12Elem {
    Fq12Elem {
        c0: Fq6Elem {
            c0: Fq2Elem {
                c0: FqElem::one(),
                c1: FqElem::zero(),
            },
            c1: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c2: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
        },
        c1: Fq6Elem {
            c0: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c1: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c2: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
        },
    }
}

fn assert_fq_eq(ctx: &mut TraceCtx, a: FqElem, b: FqElem) {
    ctx.sub_with_expected(a, b, FqElem::zero());
}

fn assert_fq12_eq_one(ctx: &mut TraceCtx, a: Fq12Elem) {
    let one = fq12_one();
    assert_fq_eq(ctx, a.c0.c0.c0, one.c0.c0.c0);
    assert_fq_eq(ctx, a.c0.c0.c1, one.c0.c0.c1);
    assert_fq_eq(ctx, a.c0.c1.c0, one.c0.c1.c0);
    assert_fq_eq(ctx, a.c0.c1.c1, one.c0.c1.c1);
    assert_fq_eq(ctx, a.c0.c2.c0, one.c0.c2.c0);
    assert_fq_eq(ctx, a.c0.c2.c1, one.c0.c2.c1);
    assert_fq_eq(ctx, a.c1.c0.c0, one.c1.c0.c0);
    assert_fq_eq(ctx, a.c1.c0.c1, one.c1.c0.c1);
    assert_fq_eq(ctx, a.c1.c1.c0, one.c1.c1.c0);
    assert_fq_eq(ctx, a.c1.c1.c1, one.c1.c1.c1);
    assert_fq_eq(ctx, a.c1.c2.c0, one.c1.c2.c0);
    assert_fq_eq(ctx, a.c1.c2.c1, one.c1.c2.c1);
}

#[allow(dead_code)]
fn multi_miller_loop(ctx: &mut TraceCtx, pairs: &[(G1Affine, G2Affine)]) -> Fq12Elem {
    let mut prepped: Vec<(G1Affine, G2Prepared, usize)> = pairs
        .iter()
        .filter_map(|(p, q)| {
            if p.infinity || q.infinity {
                None
            } else {
                Some((*p, G2Prepared::from(ctx, *q), 0usize))
            }
        })
        .collect();
    multi_miller_loop_prepared(ctx, &mut prepped)
}

fn multi_miller_loop_prepared(
    ctx: &mut TraceCtx,
    prepped: &mut [(G1Affine, G2Prepared, usize)],
) -> Fq12Elem {
    let mut f = Fq12Elem {
        c0: Fq6Elem {
            c0: Fq2Elem {
                c0: FqElem::one(),
                c1: FqElem::zero(),
            },
            c1: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c2: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
        },
        c1: Fq6Elem {
            c0: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c1: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c2: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
        },
    };

    for i in (1..ATE_LOOP_COUNT.len()).rev() {
        if i != ATE_LOOP_COUNT.len() - 1 {
            f = fq12_square(ctx, f);
        }
        for (p, q, idx) in prepped.iter_mut() {
            let coeffs = q.ell_coeffs[*idx];
            *idx += 1;
            ell(ctx, &mut f, &coeffs, p);
        }
        let bit = ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            for (p, q, idx) in prepped.iter_mut() {
                let coeffs = q.ell_coeffs[*idx];
                *idx += 1;
                ell(ctx, &mut f, &coeffs, p);
            }
        }
    }

    for (p, q, idx) in prepped.iter_mut() {
        let coeffs = q.ell_coeffs[*idx];
        *idx += 1;
        ell(ctx, &mut f, &coeffs, p);
    }

    for (p, q, idx) in prepped.iter_mut() {
        let coeffs = q.ell_coeffs[*idx];
        *idx += 1;
        ell(ctx, &mut f, &coeffs, p);
    }

    f
}

fn fq12_pow_u64_cyclotomic(ctx: &mut TraceCtx, mut base: Fq12Elem, exp: u64) -> Fq12Elem {
    let mut res = Fq12Elem {
        c0: Fq6Elem {
            c0: Fq2Elem {
                c0: FqElem::one(),
                c1: FqElem::zero(),
            },
            c1: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c2: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
        },
        c1: Fq6Elem {
            c0: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c1: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
            c2: Fq2Elem {
                c0: FqElem::zero(),
                c1: FqElem::zero(),
            },
        },
    };
    let mut e = exp;
    while e > 0 {
        if (e & 1) == 1 {
            res = fq12_mul(ctx, res, base);
        }
        base = fq12_cyclotomic_square(ctx, base);
        e >>= 1;
    }
    res
}

fn exp_by_neg_x(ctx: &mut TraceCtx, f: Fq12Elem) -> Fq12Elem {
    let x = ark_bn254::Config::X[0];
    let mut out = fq12_pow_u64_cyclotomic(ctx, f, x);
    if !ark_bn254::Config::X_IS_NEGATIVE {
        out = fq12_cyclotomic_inverse(ctx, out);
    }
    out
}

fn to_ark_fq12(elem: Fq12Elem) -> Option<ArkFq12> {
    let c0 = ArkFq6::new(
        ArkFq2::new(
            fq_from_limbs(elem.c0.c0.c0.0)?,
            fq_from_limbs(elem.c0.c0.c1.0)?,
        ),
        ArkFq2::new(
            fq_from_limbs(elem.c0.c1.c0.0)?,
            fq_from_limbs(elem.c0.c1.c1.0)?,
        ),
        ArkFq2::new(
            fq_from_limbs(elem.c0.c2.c0.0)?,
            fq_from_limbs(elem.c0.c2.c1.0)?,
        ),
    );
    let c1 = ArkFq6::new(
        ArkFq2::new(
            fq_from_limbs(elem.c1.c0.c0.0)?,
            fq_from_limbs(elem.c1.c0.c1.0)?,
        ),
        ArkFq2::new(
            fq_from_limbs(elem.c1.c1.c0.0)?,
            fq_from_limbs(elem.c1.c1.c1.0)?,
        ),
        ArkFq2::new(
            fq_from_limbs(elem.c1.c2.c0.0)?,
            fq_from_limbs(elem.c1.c2.c1.0)?,
        ),
    );
    Some(ArkFq12::new(c0, c1))
}

fn from_ark_fq12(elem: ArkFq12) -> Fq12Elem {
    Fq12Elem {
        c0: Fq6Elem {
            c0: fq2_from_ark(elem.c0.c0),
            c1: fq2_from_ark(elem.c0.c1),
            c2: fq2_from_ark(elem.c0.c2),
        },
        c1: Fq6Elem {
            c0: fq2_from_ark(elem.c1.c0),
            c1: fq2_from_ark(elem.c1.c1),
            c2: fq2_from_ark(elem.c1.c2),
        },
    }
}

fn final_exponentiation(ctx: &mut TraceCtx, f: Fq12Elem) -> Fq12Elem {
    let f1 = fq12_cyclotomic_inverse(ctx, f);
    let f_inv = {
        let ark = match to_ark_fq12(f) {
            Some(value) => value,
            None => {
                ctx.set_error("fq12 limbs not canonical".to_string());
                debug_assert!(false, "fq12 limbs not canonical");
                return fq12_one();
            }
        };
        let inv = match ark.inverse() {
            Some(value) => value,
            None => {
                ctx.set_error("fq12 inverse missing".to_string());
                debug_assert!(false, "fq12 inverse missing");
                return fq12_one();
            }
        };
        from_ark_fq12(inv)
    };
    let inv_check = fq12_mul(ctx, f, f_inv);
    if !fq12_is_one(inv_check) {
        ctx.set_error("fq12 inverse check failed".to_string());
        debug_assert!(false, "fq12 inverse check failed");
        return fq12_one();
    }
    let mut r = fq12_mul(ctx, f1, f_inv);
    let f2 = r;
    r = fq12_frobenius(ctx, r, 2);
    r = fq12_mul(ctx, r, f2);

    let y0 = exp_by_neg_x(ctx, r);
    let y1 = fq12_cyclotomic_square(ctx, y0);
    let y2 = fq12_cyclotomic_square(ctx, y1);
    let mut y3 = fq12_mul(ctx, y2, y1);
    let y4 = exp_by_neg_x(ctx, y3);
    let y5 = fq12_cyclotomic_square(ctx, y4);
    let mut y6 = exp_by_neg_x(ctx, y5);
    y3 = fq12_cyclotomic_inverse(ctx, y3);
    y6 = fq12_cyclotomic_inverse(ctx, y6);
    let y7 = fq12_mul(ctx, y6, y4);
    let mut y8 = fq12_mul(ctx, y7, y3);
    let y9 = fq12_mul(ctx, y8, y1);
    let y10 = fq12_mul(ctx, y8, y4);
    let y11 = fq12_mul(ctx, y10, r);
    let mut y12 = y9;
    y12 = fq12_frobenius(ctx, y12, 1);
    let y13 = fq12_mul(ctx, y12, y11);
    y8 = fq12_frobenius(ctx, y8, 2);
    let y14 = fq12_mul(ctx, y8, y13);
    r = fq12_cyclotomic_inverse(ctx, r);
    let mut y15 = fq12_mul(ctx, r, y9);
    y15 = fq12_frobenius(ctx, y15, 3);
    fq12_mul(ctx, y15, y14)
}

#[derive(Clone, Debug)]
struct G2Prepared {
    ell_coeffs: Vec<(Fq2Elem, Fq2Elem, Fq2Elem)>,
    _infinity: bool,
}

impl G2Prepared {
    fn from(ctx: &mut TraceCtx, q: G2Affine) -> Self {
        if q.infinity {
            return Self {
                ell_coeffs: vec![],
                _infinity: true,
            };
        }

        let two = FqElem(limbs_from_fq(Fq::from(2u64)));
        let two_fq = match fq_from_limbs(two.0) {
            Some(value) => value,
            None => {
                ctx.set_error("bn254 constant two not canonical".to_string());
                debug_assert!(false, "bn254 constant two not canonical");
                return Self {
                    ell_coeffs: vec![],
                    _infinity: true,
                };
            }
        };
        let two_inv = match two_fq.inverse() {
            Some(value) => value,
            None => {
                ctx.set_error("inverse of two must exist".to_string());
                debug_assert!(false, "inverse of two must exist");
                return Self {
                    ell_coeffs: vec![],
                    _infinity: true,
                };
            }
        };
        let two_inv = FqElem(limbs_from_fq(two_inv));

        let mut ell_coeffs = Vec::new();
        let mut r = G2HomProjective {
            x: q.x,
            y: q.y,
            z: Fq2Elem {
                c0: FqElem::one(),
                c1: FqElem::zero(),
            },
        };
        let neg_q = G2Affine {
            x: q.x,
            y: fq2_neg(ctx, q.y),
            infinity: q.infinity,
        };

        for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
            ell_coeffs.push(r.double_in_place(ctx, two_inv));
            match bit {
                1 => ell_coeffs.push(r.add_in_place(ctx, &q)),
                -1 => ell_coeffs.push(r.add_in_place(ctx, &neg_q)),
                _ => {}
            }
        }

        let q1 = mul_by_char(ctx, q);
        let mut q2 = mul_by_char(ctx, q1);
        q2.y = fq2_neg(ctx, q2.y);

        ell_coeffs.push(r.add_in_place(ctx, &q1));
        ell_coeffs.push(r.add_in_place(ctx, &q2));

        Self {
            ell_coeffs,
            _infinity: false,
        }
    }
}

fn g2_prepared_cached(q: G2Affine) -> G2Prepared {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: OnceLock<Mutex<HashMap<G2PrecompKey, G2Prepared>>> = OnceLock::new();
    let key = G2PrecompKey {
        x0: q.x.c0.0,
        x1: q.x.c1.0,
        y0: q.y.c0.0,
        y1: q.y.c1.0,
        infinity: q.infinity,
    };
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(err) => {
            debug_assert!(false, "g2 precomp cache lock poisoned");
            err.into_inner()
        }
    };
    if let Some(entry) = guard.get(&key) {
        return entry.clone();
    }
    let mut ctx = TraceCtx::new_discard();
    let out = G2Prepared::from(&mut ctx, q);
    guard.insert(key, out.clone());
    out
}

fn g2_generator_precomp() -> &'static G2Prepared {
    static PRECOMP: OnceLock<G2Prepared> = OnceLock::new();
    PRECOMP.get_or_init(|| {
        let mut ctx = TraceCtx::new_discard();
        G2Prepared::from(&mut ctx, to_g2(ArkG2Affine::generator()))
    })
}

const ATE_LOOP_COUNT: &[i8] = &[
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0,
    0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0,
    -1, 0, 0, 1, 0, 1, 1,
];
