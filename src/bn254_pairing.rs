//! BN254 pairing arithmetic for adapter kernels.
//!
//! This module implements BN254 pairing operations using explicit limb arithmetic.
//! It is intended for witness construction and kernel verification, not for general use.

#![allow(clippy::should_implement_trait)]

use ark_bn254::{
    g2 as ark_g2,
    Config as ArkBnConfig,
    Fq,
    Fq12,
    Fq2,
    Fq6,
    G1Affine as ArkG1Affine,
    G2Affine as ArkG2Affine,
};
use ark_ec::{bn::BnConfig, pairing::Pairing, short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::{BigInteger, Field, PrimeField};
use num_bigint::BigUint;

use crate::bn254_field::{bn254_add_mod, bn254_inv_mod, bn254_mul_mod, bn254_sub_mod, fq_from_limbs, limbs_from_fq};

fn bn254_add_mod_checked(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    bn254_add_mod(a, b).unwrap_or_else(|| {
        debug_assert!(false, "bn254 add invalid limbs");
        [0u64; 4]
    })
}

fn bn254_sub_mod_checked(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    bn254_sub_mod(a, b).unwrap_or_else(|| {
        debug_assert!(false, "bn254 sub invalid limbs");
        [0u64; 4]
    })
}

fn bn254_mul_mod_checked(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    bn254_mul_mod(a, b).unwrap_or_else(|| {
        debug_assert!(false, "bn254 mul invalid limbs");
        [0u64; 4]
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FqElem(pub [u64; 4]);

impl FqElem {
    pub fn zero() -> Self {
        Self([0u64; 4])
    }

    pub fn one() -> Self {
        Self(limbs_from_fq(Fq::ONE))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u64; 4]
    }

    pub fn add(self, rhs: Self) -> Self {
        Self(bn254_add_mod_checked(self.0, rhs.0))
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self(bn254_sub_mod_checked(self.0, rhs.0))
    }

    pub fn mul(self, rhs: Self) -> Self {
        Self(bn254_mul_mod_checked(self.0, rhs.0))
    }

    pub fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            let zero = FqElem::zero();
            zero.sub(self)
        }
    }

    pub fn square(self) -> Self {
        self.mul(self)
    }

    pub fn inv(self) -> Option<Self> {
        bn254_inv_mod(self.0).map(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq2Elem {
    pub c0: FqElem,
    pub c1: FqElem,
}

impl Fq2Elem {
    pub fn zero() -> Self {
        Self {
            c0: FqElem::zero(),
            c1: FqElem::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: FqElem::one(),
            c1: FqElem::zero(),
        }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    pub fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        let a0 = self.c0.mul(rhs.c0);
        let a1 = self.c1.mul(rhs.c1);
        let c0 = a0.sub(a1);
        let c1 = self.c0.mul(rhs.c1).add(self.c1.mul(rhs.c0));
        Self { c0, c1 }
    }

    pub fn square(self) -> Self {
        let a = self.c0.add(self.c1);
        let b = self.c0.sub(self.c1);
        let c = self.c0.add(self.c0);
        let c0 = a.mul(b);
        let c1 = c.mul(self.c1);
        Self { c0, c1 }
    }

    pub fn mul_by_fp(self, rhs: FqElem) -> Self {
        Self {
            c0: self.c0.mul(rhs),
            c1: self.c1.mul(rhs),
        }
    }

    pub fn inv(self) -> Option<Self> {
        let t0 = self.c0.square().add(self.c1.square());
        let inv = t0.inv()?;
        Some(Self {
            c0: self.c0.mul(inv),
            c1: self.c1.neg().mul(inv),
        })
    }

    pub fn frobenius_map(self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq6Elem {
    pub c0: Fq2Elem,
    pub c1: Fq2Elem,
    pub c2: Fq2Elem,
}

impl Fq6Elem {
    pub fn zero() -> Self {
        Self {
            c0: Fq2Elem::zero(),
            c1: Fq2Elem::zero(),
            c2: Fq2Elem::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fq2Elem::one(),
            c1: Fq2Elem::zero(),
            c2: Fq2Elem::zero(),
        }
    }

    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
            c2: self.c2.add(rhs.c2),
        }
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
            c2: self.c2.sub(rhs.c2),
        }
    }

    pub fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        let a = rhs.c0;
        let b = rhs.c1;
        let c = rhs.c2;

        let d = self.c0;
        let e = self.c1;
        let f = self.c2;

        let ad = d.mul(a);
        let be = e.mul(b);
        let cf = f.mul(c);

        let x = (e.add(f)).mul(b.add(c)).sub(be).sub(cf);
        let y = (d.add(e)).mul(a.add(b)).sub(ad).sub(be);
        let z = (d.add(f)).mul(a.add(c)).sub(ad).add(be).sub(cf);

        let c0 = ad.add(fq6_mul_base_field_by_nonresidue(x));
        let c1 = y.add(fq6_mul_base_field_by_nonresidue(cf));
        let c2 = z;

        Self { c0, c1, c2 }
    }

    pub fn square(self) -> Self {
        self.mul(self)
    }

    pub fn mul_by_fp2(self, rhs: Fq2Elem) -> Self {
        Self {
            c0: self.c0.mul(rhs),
            c1: self.c1.mul(rhs),
            c2: self.c2.mul(rhs),
        }
    }

    pub fn mul_by_1(self, c1: &Fq2Elem) -> Self {
        let b_b = self.c1.mul(*c1);

        let mut t1 = c1.mul(self.c1.add(self.c2)).sub(b_b);
        t1 = fq6_mul_base_field_by_nonresidue(t1);

        let t2 = c1.mul(self.c0.add(self.c1)).sub(b_b);

        Self {
            c0: t1,
            c1: t2,
            c2: b_b,
        }
    }

    pub fn mul_by_01(self, c0: &Fq2Elem, c1: &Fq2Elem) -> Self {
        let a_a = self.c0.mul(*c0);
        let b_b = self.c1.mul(*c1);

        let mut t1 = c1.mul(self.c1.add(self.c2)).sub(b_b);
        t1 = fq6_mul_base_field_by_nonresidue(t1).add(a_a);

        let t3 = c0.mul(self.c0.add(self.c2)).sub(a_a).add(b_b);

        let t2 = c0.add(*c1).mul(self.c0.add(self.c1)).sub(a_a).sub(b_b);

        Self { c0: t1, c1: t2, c2: t3 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq12Elem {
    pub c0: Fq6Elem,
    pub c1: Fq6Elem,
}

impl Fq12Elem {
    pub fn zero() -> Self {
        Self {
            c0: Fq6Elem::zero(),
            c1: Fq6Elem::zero(),
        }
    }

    pub fn one() -> Self {
        Self {
            c0: Fq6Elem::one(),
            c1: Fq6Elem::zero(),
        }
    }

    pub fn is_one(&self) -> bool {
        *self == Self::one()
    }

    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    pub fn mul(self, rhs: Self) -> Self {
        let v0 = self.c0.mul(rhs.c0);
        let v1 = self.c1.mul(rhs.c1);

        let c1 = self.c1.add(self.c0).mul(rhs.c0.add(rhs.c1)).sub(v0).sub(v1);
        let v1_nr = fq12_mul_base_field_by_nonresidue(v1);
        let c0 = v1_nr.add(v0);

        Self { c0, c1 }
    }

    pub fn square(self) -> Self {
        self.mul(self)
    }

    pub fn mul_by_034(&mut self, c0: &Fq2Elem, c3: &Fq2Elem, c4: &Fq2Elem) {
        let a0 = self.c0.c0.mul(*c0);
        let a1 = self.c0.c1.mul(*c0);
        let a2 = self.c0.c2.mul(*c0);
        let a = Fq6Elem { c0: a0, c1: a1, c2: a2 };

        let b = self.c1.mul_by_01(c3, c4);

        let c0c3 = c0.add(*c3);
        let c1 = *c4;
        let e = self.c0.add(self.c1).mul_by_01(&c0c3, &c1);
        let c1_new = e.sub(a.add(b));
        let mut c0_new = b;
        c0_new = fq12_mul_base_field_by_nonresidue(c0_new);
        c0_new = c0_new.add(a);

        self.c0 = c0_new;
        self.c1 = c1_new;
    }
}

fn fq6_mul_base_field_by_nonresidue(fe: Fq2Elem) -> Fq2Elem {
    // (c0 + u*c1) * (9 + u) = (9*c0 - c1) + u*(9*c1 + c0)
    let nine = FqElem(limbs_from_fq(Fq::from(9u64)));
    let c0 = nine.mul(fe.c0).sub(fe.c1);
    let c1 = nine.mul(fe.c1).add(fe.c0);
    Fq2Elem { c0, c1 }
}

fn fq12_mul_base_field_by_nonresidue(fe: Fq6Elem) -> Fq6Elem {
    // (c0, c1, c2) * v where v^2 = (0, 1, 0) in Fq6
    let old_c1 = fe.c1;
    let c1 = fe.c0;
    let mut c0 = fe.c2;
    c0 = fq6_mul_base_field_by_nonresidue(c0);
    let c2 = old_c1;
    Fq6Elem { c0, c1, c2 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine {
    pub x: FqElem,
    pub y: FqElem,
    pub infinity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine {
    pub x: Fq2Elem,
    pub y: Fq2Elem,
    pub infinity: bool,
}

impl From<ArkG1Affine> for G1Affine {
    fn from(p: ArkG1Affine) -> Self {
        if p.is_zero() {
            return Self {
                x: FqElem::zero(),
                y: FqElem::zero(),
                infinity: true,
            };
        }
        Self {
            x: FqElem(limbs_from_fq(p.x)),
            y: FqElem(limbs_from_fq(p.y)),
            infinity: false,
        }
    }
}

impl From<ArkG2Affine> for G2Affine {
    fn from(p: ArkG2Affine) -> Self {
        if p.is_zero() {
            return Self {
                x: Fq2Elem::zero(),
                y: Fq2Elem::zero(),
                infinity: true,
            };
        }
        Self {
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
}

type EllCoeff = (Fq2Elem, Fq2Elem, Fq2Elem);

#[derive(Clone, Copy, Debug)]
struct G2HomProjective {
    x: Fq2Elem,
    y: Fq2Elem,
    z: Fq2Elem,
}

impl G2HomProjective {
    fn double_in_place(&mut self, two_inv: FqElem) -> EllCoeff {
        let a = self.x.mul(self.y).mul_by_fp(two_inv);
        let b = self.y.square();
        let c = self.z.square();
        let e = g2_coeff_b().mul(c.add(c).add(c));
        let f = e.add(e).add(e);
        let g = b.add(f).mul_by_fp(two_inv);
        let h = (self.y.add(self.z)).square().sub(b.add(c));
        let i = e.sub(b);
        let j = self.x.square();
        let e_square = e.square();

        self.x = a.mul(b.sub(f));
        self.y = g.square().sub(e_square.add(e_square).add(e_square));
        self.z = b.mul(h);

        (h.neg(), j.add(j).add(j), i)
    }

    fn add_in_place(&mut self, q: &G2Affine) -> EllCoeff {
        let theta = self.y.sub(q.y.mul(self.z));
        let lambda = self.x.sub(q.x.mul(self.z));
        let c = theta.square();
        let d = lambda.square();
        let e = lambda.mul(d);
        let f = self.z.mul(c);
        let g = self.x.mul(d);
        let h = e.add(f).sub(g.add(g));
        self.x = lambda.mul(h);
        self.y = theta.mul(g.sub(h)).sub(e.mul(self.y));
        self.z = self.z.mul(e);
        let j = theta.mul(q.x).sub(lambda.mul(q.y));

        (lambda, theta.neg(), j)
    }
}

#[derive(Clone, Debug)]
pub struct G2Prepared {
    pub ell_coeffs: Vec<EllCoeff>,
    pub infinity: bool,
}

impl From<G2Affine> for G2Prepared {
    fn from(q: G2Affine) -> Self {
        if q.infinity {
            return Self {
                ell_coeffs: vec![],
                infinity: true,
            };
        }

        let two = FqElem(limbs_from_fq(Fq::from(2u64)));
        let two_inv = two.inv().unwrap_or_else(|| {
            debug_assert!(false, "two_inv missing for G2Prepared");
            FqElem::zero()
        });
        let mut ell_coeffs = Vec::new();
        let mut r = G2HomProjective {
            x: q.x,
            y: q.y,
            z: Fq2Elem::one(),
        };

        let neg_q = G2Affine {
            x: q.x,
            y: q.y.neg(),
            infinity: q.infinity,
        };

        for bit in ATE_LOOP_COUNT.iter().rev().skip(1) {
            ell_coeffs.push(r.double_in_place(two_inv));
            match bit {
                1 => ell_coeffs.push(r.add_in_place(&q)),
                -1 => ell_coeffs.push(r.add_in_place(&neg_q)),
                _ => {}
            }
        }

        let q1 = mul_by_char(q);
        let mut q2 = mul_by_char(q1);
        q2.y = q2.y.neg();

        ell_coeffs.push(r.add_in_place(&q1));
        ell_coeffs.push(r.add_in_place(&q2));

        Self {
            ell_coeffs,
            infinity: false,
        }
    }
}

fn mul_by_char(mut r: G2Affine) -> G2Affine {
    r.x = r.x.frobenius_map().mul(twist_mul_by_q_x());
    r.y = r.y.frobenius_map().mul(twist_mul_by_q_y());
    r
}

fn ell(f: &mut Fq12Elem, coeffs: &EllCoeff, p: &G1Affine) {
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;
    let c2 = coeffs.2;
    c0 = c0.mul_by_fp(p.y);
    c1 = c1.mul_by_fp(p.x);
    f.mul_by_034(&c0, &c1, &c2);
}

pub fn multi_miller_loop(pairs: &[(G1Affine, G2Affine)]) -> Fq12Elem {
    let mut prepped: Vec<(G1Affine, G2Prepared, usize)> = pairs
        .iter()
        .filter_map(|(p, q)| {
            if p.infinity || q.infinity {
                None
            } else {
                Some((*p, G2Prepared::from(*q), 0usize))
            }
        })
        .collect();

    let mut f = Fq12Elem::one();
    for i in (1..ATE_LOOP_COUNT.len()).rev() {
        if i != ATE_LOOP_COUNT.len() - 1 {
            f = f.square();
        }
        for (p, q, idx) in prepped.iter_mut() {
            let coeffs = q.ell_coeffs[*idx];
            *idx += 1;
            ell(&mut f, &coeffs, p);
        }
        let bit = ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            for (p, q, idx) in prepped.iter_mut() {
                let coeffs = q.ell_coeffs[*idx];
                *idx += 1;
                ell(&mut f, &coeffs, p);
            }
        }
    }

    for (p, q, idx) in prepped.iter_mut() {
        let coeffs = q.ell_coeffs[*idx];
        *idx += 1;
        ell(&mut f, &coeffs, p);
    }

    for (p, q, idx) in prepped.iter_mut() {
        let coeffs = q.ell_coeffs[*idx];
        *idx += 1;
        ell(&mut f, &coeffs, p);
    }

    f
}

pub fn final_exponentiation(f: Fq12Elem) -> Option<Fq12Elem> {
    let ark = to_ark_fq12(f)?;
    let out = ark_bn254::Bn254::final_exponentiation(ark_ec::pairing::MillerLoopOutput(ark))?;
    Some(fq12_from_ark(out.0))
}

pub fn pairing(p: G1Affine, q: G2Affine) -> Option<Fq12Elem> {
    let ml = multi_miller_loop(&[(p, q)]);
    final_exponentiation(ml)
}

pub fn pairing_product_is_one(pairs: &[(G1Affine, G2Affine)]) -> bool {
    let ml = multi_miller_loop(pairs);
    match final_exponentiation(ml) {
        Some(out) => out.is_one(),
        None => false,
    }
}

#[allow(dead_code)]
fn fq12_pow(mut base: Fq12Elem, exp: &BigUint) -> Fq12Elem {
    let mut res = Fq12Elem::one();
    let mut e = exp.clone();
    while e > BigUint::from(0u64) {
        if (&e & BigUint::from(1u64)) == BigUint::from(1u64) {
            res = res.mul(base);
        }
        base = base.square();
        e >>= 1usize;
    }
    res
}

#[allow(dead_code)]
fn final_exponent() -> BigUint {
    let q = biguint_from_u64_le(Fq12::characteristic());
    let r = BigUint::from_bytes_be(&ark_bn254::Fr::MODULUS.to_bytes_be());
    let q12 = q.pow(12);
    (q12 - BigUint::from(1u64)) / r
}

#[allow(dead_code)]
fn biguint_from_u64_le(limbs: &[u64]) -> BigUint {
    let mut bytes = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn g2_coeff_b() -> Fq2Elem {
    let b = ark_g2::Config::COEFF_B;
    Fq2Elem {
        c0: FqElem(limbs_from_fq(b.c0)),
        c1: FqElem(limbs_from_fq(b.c1)),
    }
}

fn twist_mul_by_q_x() -> Fq2Elem {
    let t = ArkBnConfig::TWIST_MUL_BY_Q_X;
    Fq2Elem {
        c0: FqElem(limbs_from_fq(t.c0)),
        c1: FqElem(limbs_from_fq(t.c1)),
    }
}

fn twist_mul_by_q_y() -> Fq2Elem {
    let t = ArkBnConfig::TWIST_MUL_BY_Q_Y;
    Fq2Elem {
        c0: FqElem(limbs_from_fq(t.c0)),
        c1: FqElem(limbs_from_fq(t.c1)),
    }
}

const ATE_LOOP_COUNT: &[i8] = &[
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0,
    0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0,
    -1, 0, 0, 1, 0, 1, 1,
];

pub fn to_ark_fq12(elem: Fq12Elem) -> Option<Fq12> {
    let c0 = Fq6::new(
        to_ark_fq2(elem.c0.c0)?,
        to_ark_fq2(elem.c0.c1)?,
        to_ark_fq2(elem.c0.c2)?,
    );
    let c1 = Fq6::new(
        to_ark_fq2(elem.c1.c0)?,
        to_ark_fq2(elem.c1.c1)?,
        to_ark_fq2(elem.c1.c2)?,
    );
    Some(Fq12::new(c0, c1))
}

pub fn to_ark_fq2(elem: Fq2Elem) -> Option<Fq2> {
    let c0 = fq_from_limbs(elem.c0.0)?;
    let c1 = fq_from_limbs(elem.c1.0)?;
    Some(Fq2::new(c0, c1))
}

fn fq12_from_ark(x: Fq12) -> Fq12Elem {
    Fq12Elem {
        c0: fq6_from_ark(x.c0),
        c1: fq6_from_ark(x.c1),
    }
}

fn fq6_from_ark(x: Fq6) -> Fq6Elem {
    Fq6Elem {
        c0: fq2_from_ark(x.c0),
        c1: fq2_from_ark(x.c1),
        c2: fq2_from_ark(x.c2),
    }
}

fn fq2_from_ark(x: Fq2) -> Fq2Elem {
    Fq2Elem {
        c0: FqElem(limbs_from_fq(x.c0)),
        c1: FqElem(limbs_from_fq(x.c1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::Pairing;
    use ark_ff::UniformRand;
    use num_traits::Zero;
    use std::ops::Neg;

    #[test]
    fn test_pairing_matches_ark_generator() {
        let g1 = ArkG1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let ours = match pairing(G1Affine::from(g1), G2Affine::from(g2)) {
            Some(value) => value,
            None => {
                assert!(false, "pairing");
                return;
            }
        };
        let ark = ark_bn254::Bn254::pairing(g1, g2).0;
        let ours_ark = match to_ark_fq12(ours) {
            Some(value) => value,
            None => {
                assert!(false, "ark fq12");
                return;
            }
        };
        assert_eq!(ours_ark, ark);
    }

    #[test]
    fn test_miller_loop_matches_ark_generator() {
        let g1 = ArkG1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let ours = multi_miller_loop(&[(G1Affine::from(g1), G2Affine::from(g2))]);
        let ark = ark_bn254::Bn254::multi_miller_loop([g1], [g2]).0;
        let ours_ark = match to_ark_fq12(ours) {
            Some(value) => value,
            None => {
                assert!(false, "ark fq12");
                return;
            }
        };
        assert_eq!(ours_ark, ark);
    }

    #[test]
    fn test_final_exponent_matches_ark() {
        let g1 = ArkG1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let ours_ml = multi_miller_loop(&[(G1Affine::from(g1), G2Affine::from(g2))]);
        let ours = match final_exponentiation(ours_ml) {
            Some(value) => value,
            None => {
                assert!(false, "final exponent");
                return;
            }
        };
        let ark_ml = ark_bn254::Bn254::multi_miller_loop([g1], [g2]);
        let ark = match ark_bn254::Bn254::final_exponentiation(ark_ml) {
            Some(value) => value.0,
            None => {
                assert!(false, "final exponentiation must succeed");
                return;
            }
        };
        let ours_ark = match to_ark_fq12(ours) {
            Some(value) => value,
            None => {
                assert!(false, "ark fq12");
                return;
            }
        };
        assert_eq!(ours_ark, ark);
    }

    #[test]
    fn test_fq6_mul_matches_ark() {
        let mut rng = ark_std::test_rng();
        for _ in 0..32 {
            let a = Fq6::rand(&mut rng);
            let b = Fq6::rand(&mut rng);
            let a_mine = fq6_from_ark(a);
            let b_mine = fq6_from_ark(b);
            let prod = a_mine.mul(b_mine);
            let ark_prod = a * b;
            let ours_ark = match to_ark_fq6(prod) {
                Some(value) => value,
                None => {
                    assert!(false, "ark fq6");
                    return;
                }
            };
            assert_eq!(ours_ark, ark_prod);
        }
    }

    #[test]
    fn test_fq12_mul_matches_ark() {
        let mut rng = ark_std::test_rng();
        for _ in 0..16 {
            let a = Fq12::rand(&mut rng);
            let b = Fq12::rand(&mut rng);
            let a_mine = fq12_from_ark(a);
            let b_mine = fq12_from_ark(b);
            let prod = a_mine.mul(b_mine);
            let ark_prod = a * b;
            let ours_ark = match to_ark_fq12(prod) {
                Some(value) => value,
                None => {
                    assert!(false, "ark fq12");
                    return;
                }
            };
            assert_eq!(ours_ark, ark_prod);
        }
    }

    #[test]
    fn test_fq12_pow_matches_ark_small_exp() {
        let mut rng = ark_std::test_rng();
        let a = Fq12::rand(&mut rng);
        let exp = BigUint::from(1234567u64);
        let ours = fq12_pow(fq12_from_ark(a), &exp);
        let ark = a.pow(exp.to_u64_digits());
        let ours_ark = match to_ark_fq12(ours) {
            Some(value) => value,
            None => {
                assert!(false, "ark fq12");
                return;
            }
        };
        assert_eq!(ours_ark, ark);
    }

    #[test]
    fn test_final_exponent_pow_matches_ark() {
        let mut rng = ark_std::test_rng();
        let a = Fq12::rand(&mut rng);
        let exp = final_exponent();
        let ours = fq12_pow(fq12_from_ark(a), &exp);
        let ark = a.pow(exp.to_u64_digits());
        let ours_ark = match to_ark_fq12(ours) {
            Some(value) => value,
            None => {
                assert!(false, "ark fq12");
                return;
            }
        };
        assert_eq!(ours_ark, ark);
    }

    #[test]
    fn test_final_exponent_divisible() {
        let q = biguint_from_u64_le(Fq12::characteristic());
        let r = BigUint::from_bytes_be(&ark_bn254::Fr::MODULUS.to_bytes_be());
        let q12 = q.pow(12);
        let rem = (q12 - BigUint::from(1u64)) % r;
        assert!(rem.is_zero());
    }

    fn to_ark_fq6(elem: Fq6Elem) -> Option<Fq6> {
        Some(Fq6::new(
            to_ark_fq2(elem.c0)?,
            to_ark_fq2(elem.c1)?,
            to_ark_fq2(elem.c2)?,
        ))
    }

    #[test]
    fn test_pairing_product_is_one() {
        let g1 = ArkG1Affine::generator();
        let g2 = ArkG2Affine::generator();
        let p1 = G1Affine::from(g1);
        let p2 = G1Affine::from(g1.neg());
        let q = G2Affine::from(g2);
        assert!(pairing_product_is_one(&[(p1, q), (p2, q)]));
    }
}
