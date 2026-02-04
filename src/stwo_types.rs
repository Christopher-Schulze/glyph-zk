//! Stwo-compatible types and primitives based on the public stwo repo.
//! This module is used for native Stwo verification and toolchain import paths.

use core::cmp::Ordering;
use core::fmt::{Debug, Display};
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign};
use blake2::Digest;
use serde::{Deserialize, Serialize};

pub const M31_MODULUS: u32 = 2147483647;

pub trait FieldExpOps: Sized + Clone {
    fn square(&self) -> Self;
    fn inverse(&self) -> Self;
    fn one() -> Self;
}

pub trait ComplexConjugate: Sized {
    fn complex_conjugate(&self) -> Self;
}

#[repr(transparent)]
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct M31(pub u32);

pub type BaseField = M31;

impl M31 {
    pub const fn from_u32_unchecked(arg: u32) -> Self {
        Self(arg)
    }

    pub const fn reduce(val: u64) -> Self {
        Self((((((val >> 31) + val + 1) >> 31) + val) & (M31_MODULUS as u64)) as u32)
    }

    pub fn partial_reduce(val: u32) -> Self {
        Self(val.checked_sub(M31_MODULUS).unwrap_or(val))
    }

    pub fn inverse(&self) -> Self {
        assert!(!self.is_zero(), "0 has no inverse");
        pow2147483645(*self)
    }
}

impl Display for M31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for M31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self::partial_reduce(self.0 + rhs.0)
    }
}

impl AddAssign for M31 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Neg for M31 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self::partial_reduce(M31_MODULUS - self.0)
    }
}

impl Sub for M31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self::partial_reduce(self.0 + M31_MODULUS - rhs.0)
    }
}

impl SubAssign for M31 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for M31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self::reduce((self.0 as u64) * (rhs.0 as u64))
    }
}

impl MulAssign for M31 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Rem for M31 {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self::Output {
        Self::reduce((self.0 as u64) % (rhs.0 as u64))
    }
}

impl RemAssign for M31 {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for M31 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl DivAssign for M31 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl FieldExpOps for M31 {
    fn square(&self) -> Self {
        *self * *self
    }

    fn inverse(&self) -> Self {
        self.inverse()
    }

    fn one() -> Self {
        M31::one()
    }
}

impl ComplexConjugate for M31 {
    fn complex_conjugate(&self) -> Self {
        *self
    }
}

impl From<usize> for M31 {
    fn from(value: usize) -> Self {
        M31::reduce(value as u64)
    }
}

impl From<u32> for M31 {
    fn from(value: u32) -> Self {
        M31::reduce(value as u64)
    }
}

impl From<i32> for M31 {
    fn from(value: i32) -> Self {
        if value < 0 {
            const P2: u64 = 2 * M31_MODULUS as u64;
            return M31::reduce(P2 - value.unsigned_abs() as u64);
        }
        M31::reduce(value.unsigned_abs() as u64)
    }
}

impl M31 {
    pub fn zero() -> Self {
        Self(0)
    }
    pub fn one() -> Self {
        Self(1)
    }
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CM31(pub M31, pub M31);

impl CM31 {
    pub const fn from_u32_unchecked(a: u32, b: u32) -> CM31 {
        Self(M31::from_u32_unchecked(a), M31::from_u32_unchecked(b))
    }

    pub const fn from_m31(a: M31, b: M31) -> CM31 {
        Self(a, b)
    }

    pub fn zero() -> Self {
        Self(M31::zero(), M31::zero())
    }

    pub fn one() -> Self {
        Self(M31::one(), M31::zero())
    }
}

impl Display for CM31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} + {}i", self.0, self.1)
    }
}

impl Debug for CM31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} + {}i", self.0, self.1)
    }
}

impl Add for CM31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl AddAssign for CM31 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Neg for CM31 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl Sub for CM31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl SubAssign for CM31 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for CM31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0 - self.1 * rhs.1, self.0 * rhs.1 + self.1 * rhs.0)
    }
}

impl MulAssign for CM31 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for CM31 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl DivAssign for CM31 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl FieldExpOps for CM31 {
    fn square(&self) -> Self {
        *self * *self
    }

    fn inverse(&self) -> Self {
        assert!(!self.0.is_zero() || !self.1.is_zero(), "0 has no inverse");
        let denom = self.0.square() + self.1.square();
        let denom_inv = denom.inverse();
        Self(self.0 * denom_inv, -self.1 * denom_inv)
    }

    fn one() -> Self {
        CM31::one()
    }
}

impl ComplexConjugate for CM31 {
    fn complex_conjugate(&self) -> Self {
        Self(self.0, -self.1)
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct QM31(pub CM31, pub CM31);

pub type SecureField = QM31;

pub const SECURE_EXTENSION_DEGREE: usize = 4;

impl QM31 {
    pub const fn from_u32_unchecked(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self(CM31::from_u32_unchecked(a, b), CM31::from_u32_unchecked(c, d))
    }

    pub const fn from_m31(a: M31, b: M31, c: M31, d: M31) -> Self {
        Self(CM31::from_m31(a, b), CM31::from_m31(c, d))
    }

    pub const fn from_m31_array(array: [M31; SECURE_EXTENSION_DEGREE]) -> Self {
        Self::from_m31(array[0], array[1], array[2], array[3])
    }

    pub const fn to_m31_array(self) -> [M31; SECURE_EXTENSION_DEGREE] {
        [self.0 .0, self.0 .1, self.1 .0, self.1 .1]
    }

    pub fn from_partial_evals(evals: [Self; SECURE_EXTENSION_DEGREE]) -> Self {
        let mut res = evals[0];
        res += evals[1] * Self::from_u32_unchecked(0, 1, 0, 0);
        res += evals[2] * Self::from_u32_unchecked(0, 0, 1, 0);
        res += evals[3] * Self::from_u32_unchecked(0, 0, 0, 1);
        res
    }

    pub fn zero() -> Self {
        Self(CM31::zero(), CM31::zero())
    }

    pub fn one() -> Self {
        Self(CM31::one(), CM31::zero())
    }

    pub fn mul_cm31(self, rhs: CM31) -> Self {
        Self(self.0 * rhs, self.1 * rhs)
    }

    pub fn double(self) -> Self {
        self + self
    }
}

impl Display for QM31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "({}) + ({})u", self.0, self.1)
    }
}

impl Debug for QM31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "({}) + ({})u", self.0, self.1)
    }
}

impl Add for QM31 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl AddAssign for QM31 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Neg for QM31 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl Sub for QM31 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl SubAssign for QM31 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for QM31 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let r = CM31::from_u32_unchecked(2, 1);
        Self(self.0 * rhs.0 + r * self.1 * rhs.1, self.0 * rhs.1 + self.1 * rhs.0)
    }
}

impl MulAssign for QM31 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for QM31 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl DivAssign for QM31 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl FieldExpOps for QM31 {
    fn square(&self) -> Self {
        *self * *self
    }

    fn inverse(&self) -> Self {
        assert!(self.0 != CM31::zero() || self.1 != CM31::zero(), "0 has no inverse");
        let b2 = self.1.square();
        let ib2 = CM31(-b2.1, b2.0);
        let denom = self.0.square() - (b2 + b2 + ib2);
        let denom_inv = denom.inverse();
        Self(self.0 * denom_inv, -self.1 * denom_inv)
    }

    fn one() -> Self {
        QM31::one()
    }
}

impl ComplexConjugate for QM31 {
    fn complex_conjugate(&self) -> Self {
        Self(self.0.complex_conjugate(), self.1.complex_conjugate())
    }
}

pub fn pow2147483645<T: FieldExpOps + Mul<Output = T>>(v: T) -> T {
    let t0 = sqn::<2, T>(v.clone()) * v.clone();
    let t1 = sqn::<1, T>(t0.clone()) * t0.clone();
    let t2 = sqn::<3, T>(t1.clone()) * t0.clone();
    let t3 = sqn::<1, T>(t2.clone()) * t0.clone();
    let t4 = sqn::<8, T>(t3.clone()) * t3.clone();
    let t5 = sqn::<8, T>(t4.clone()) * t3.clone();
    sqn::<7, T>(t5) * t2
}

fn sqn<const N: usize, T: FieldExpOps>(mut v: T) -> T {
    for _ in 0..N {
        v = v.square();
    }
    v
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CirclePoint<F> {
    pub x: F,
    pub y: F,
}

impl<F: Clone + FieldExpOps + Add<Output = F> + Sub<Output = F>> CirclePoint<F> {
    pub fn double_x(x: F) -> F {
        let sx = x.square();
        sx.clone() + sx - F::one()
    }
}

impl CirclePoint<M31> {
    pub fn zero() -> Self {
        Self {
            x: M31::one(),
            y: M31::zero(),
        }
    }

    pub fn double(&self) -> Self {
        *self + *self
    }

    pub fn repeated_double(&self, n: u32) -> Self {
        let mut out = *self;
        for _ in 0..n {
            out = out.double();
        }
        out
    }

    pub fn conjugate(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }

    pub fn antipode(&self) -> Self {
        Self {
            x: -self.x,
            y: -self.y,
        }
    }
}

impl Add for CirclePoint<M31> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let x = self.x * rhs.x - self.y * rhs.y;
        let y = self.x * rhs.y + self.y * rhs.x;
        Self { x, y }
    }
}

impl Neg for CirclePoint<M31> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self { x: self.x, y: -self.y }
    }
}

impl Sub for CirclePoint<M31> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl ComplexConjugate for CirclePoint<M31> {
    fn complex_conjugate(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }
}

impl CirclePoint<QM31> {
    pub fn zero() -> Self {
        Self {
            x: QM31::one(),
            y: QM31::zero(),
        }
    }

    pub fn double(&self) -> Self {
        *self + *self
    }

    pub fn repeated_double(&self, n: u32) -> Self {
        let mut out = *self;
        for _ in 0..n {
            out = out.double();
        }
        out
    }

    pub fn conjugate(&self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }

    pub fn antipode(&self) -> Self {
        Self {
            x: -self.x,
            y: -self.y,
        }
    }

    pub fn get_random_point<C: Channel>(channel: &mut C) -> Self {
        let t = channel.draw_secure_felt();
        let t_square = t.square();
        let one_plus_tsquared_inv = (t_square + QM31::one()).inverse();
        let x = (QM31::one() - t_square) * one_plus_tsquared_inv;
        let y = t.double() * one_plus_tsquared_inv;
        Self { x, y }
    }
}

impl Add for CirclePoint<QM31> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let x = self.x * rhs.x - self.y * rhs.y;
        let y = self.x * rhs.y + self.y * rhs.x;
        Self { x, y }
    }
}

impl Neg for CirclePoint<QM31> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self { x: self.x, y: -self.y }
    }
}

impl Sub for CirclePoint<QM31> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl ComplexConjugate for CirclePoint<QM31> {
    fn complex_conjugate(&self) -> Self {
        Self {
            x: self.x.complex_conjugate(),
            y: self.y.complex_conjugate(),
        }
    }
}

pub const M31_CIRCLE_LOG_ORDER: u32 = 31;
pub const M31_CIRCLE_GEN: CirclePoint<M31> = CirclePoint {
    x: M31::from_u32_unchecked(2),
    y: M31::from_u32_unchecked(1268011823),
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct CirclePointIndex(pub usize);

impl CirclePointIndex {
    pub const fn zero() -> Self {
        Self(0)
    }

    pub const fn generator() -> Self {
        Self(1)
    }

    pub const fn reduce(self) -> Self {
        Self(self.0 & ((1 << M31_CIRCLE_LOG_ORDER) - 1))
    }

    pub fn subgroup_gen(log_size: u32) -> Self {
        assert!(log_size <= M31_CIRCLE_LOG_ORDER);
        Self(1 << (M31_CIRCLE_LOG_ORDER - log_size))
    }

    pub fn to_point(self) -> CirclePoint<M31> {
        let mut res = CirclePoint::<M31>::zero();
        let mut cur = M31_CIRCLE_GEN;
        let mut scalar = self.0 as u128;
        while scalar > 0 {
            if scalar & 1 == 1 {
                res = res + cur;
            }
            cur = cur.double();
            scalar >>= 1;
        }
        res
    }

    pub fn half(self) -> Self {
        assert!(self.0 & 1 == 0);
        Self(self.0 >> 1)
    }
}

impl Add for CirclePointIndex {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0).reduce()
    }
}

impl Sub for CirclePointIndex {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 + (1 << M31_CIRCLE_LOG_ORDER) - rhs.0).reduce()
    }
}

impl Mul<usize> for CirclePointIndex {
    type Output = Self;

    fn mul(self, rhs: usize) -> Self::Output {
        Self(self.0.wrapping_mul(rhs)).reduce()
    }
}

impl Neg for CirclePointIndex {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self((1 << M31_CIRCLE_LOG_ORDER) - self.0).reduce()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Coset {
    pub initial_index: CirclePointIndex,
    pub initial: CirclePoint<M31>,
    pub step_size: CirclePointIndex,
    pub step: CirclePoint<M31>,
    pub log_size: u32,
}

impl Coset {
    pub fn new(initial_index: CirclePointIndex, log_size: u32) -> Self {
        assert!(log_size <= M31_CIRCLE_LOG_ORDER);
        let step_size = CirclePointIndex::subgroup_gen(log_size);
        let initial = initial_index.to_point();
        let step = step_size.to_point();
        Self {
            initial_index,
            initial,
            step_size,
            step,
            log_size,
        }
    }

    pub fn subgroup(log_size: u32) -> Self {
        Self::new(CirclePointIndex::zero(), log_size)
    }

    pub fn odds(log_size: u32) -> Self {
        Self::new(CirclePointIndex::subgroup_gen(log_size + 1), log_size)
    }

    pub fn half_odds(log_size: u32) -> Self {
        Self::new(CirclePointIndex::subgroup_gen(log_size + 2), log_size)
    }

    pub const fn size(&self) -> usize {
        1 << self.log_size
    }

    pub fn at(&self, mut index: usize) -> CirclePoint<M31> {
        let mut res = self.initial;
        let mut step = self.step;
        while index > 0 {
            if index & 1 == 1 {
                res = res + step;
            }
            step = step.double();
            index >>= 1;
        }
        res
    }

    pub fn index_at(&self, index: usize) -> CirclePointIndex {
        self.initial_index + self.step_size * index
    }

    pub fn shift(&self, shift: CirclePointIndex) -> Self {
        let initial_index = self.initial_index + shift;
        Self {
            initial_index,
            initial: initial_index.to_point(),
            step_size: self.step_size,
            step: self.step,
            log_size: self.log_size,
        }
    }

    pub fn iter(&self) -> CosetIterator<CirclePoint<M31>> {
        CosetIterator {
            cur: self.initial,
            step: self.step,
            remaining: self.size(),
        }
    }

    pub fn iter_indices(&self) -> CosetIterator<CirclePointIndex> {
        CosetIterator {
            cur: self.initial_index,
            step: self.step_size,
            remaining: self.size(),
        }
    }

    pub fn double(&self) -> Self {
        Self {
            initial_index: self.initial_index * 2,
            initial: self.initial.double(),
            step_size: self.step_size * 2,
            step: self.step.double(),
            log_size: self.log_size.saturating_sub(1),
        }
    }

    pub fn conjugate(&self) -> Self {
        Self {
            initial_index: -self.initial_index,
            initial: (-self.initial_index).to_point(),
            step_size: -self.step_size,
            step: (-self.step_size).to_point(),
            log_size: self.log_size,
        }
    }
}

#[derive(Clone)]
pub struct CosetIterator<T> {
    pub cur: T,
    pub step: T,
    pub remaining: usize,
}

impl<T: Add<Output = T> + Copy> Iterator for CosetIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let res = self.cur;
        self.cur = self.cur + self.step;
        Some(res)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct CircleDomain {
    pub half_coset: Coset,
}

impl CircleDomain {
    pub const fn new(half_coset: Coset) -> Self {
        Self { half_coset }
    }

    pub fn log_size(&self) -> u32 {
        self.half_coset.log_size + 1
    }

    pub fn size(&self) -> usize {
        1 << self.log_size()
    }

    pub fn at(&self, index: usize) -> CirclePoint<M31> {
        self.index_at(index).to_point()
    }

    pub fn index_at(&self, index: usize) -> CirclePointIndex {
        if index < self.half_coset.size() {
            self.half_coset.index_at(index)
        } else {
            -self.half_coset.index_at(index - self.half_coset.size())
        }
    }

    pub fn is_canonic(&self) -> bool {
        self.half_coset.initial_index * 4 == self.half_coset.step_size
    }

    pub fn half_coset(&self) -> Coset {
        self.half_coset
    }

    pub fn iter(&self) -> std::iter::Chain<CosetIterator<CirclePoint<M31>>, CosetIterator<CirclePoint<M31>>> {
        self.half_coset
            .iter()
            .chain(self.half_coset.conjugate().iter())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LineDomain {
    coset: Coset,
}

impl LineDomain {
    pub fn new(coset: Coset) -> Self {
        match coset.size().cmp(&2) {
            Ordering::Less => {}
            Ordering::Equal => {
                assert!(coset.initial.x.0 != 0, "coset x-coordinates not unique");
            }
            Ordering::Greater => {
                assert!(coset.log_size >= 2, "coset x-coordinates not unique");
            }
        }
        Self { coset }
    }

    pub fn at(&self, i: usize) -> BaseField {
        self.coset.at(i).x
    }

    pub fn coset(&self) -> Coset {
        self.coset
    }

    pub fn size(&self) -> usize {
        self.coset.size()
    }

    pub fn log_size(&self) -> u32 {
        self.coset.log_size
    }

    pub fn double(&self) -> Self {
        Self {
            coset: self.coset.double(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct LinePoly {
    coeffs: Vec<SecureField>,
    log_size: u32,
}

impl LinePoly {
    pub fn new(coeffs: Vec<SecureField>) -> Self {
        assert!(coeffs.len().is_power_of_two());
        let log_size = coeffs.len().ilog2();
        Self { coeffs, log_size }
    }

    pub fn eval_at_point(&self, mut x: SecureField) -> SecureField {
        let mut doublings = Vec::new();
        for _ in 0..self.log_size {
            doublings.push(x);
            x = CirclePoint::double_x(x);
        }
        fold(&self.coeffs, &doublings)
    }

    pub fn len(&self) -> usize {
        1 << self.log_size
    }

    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    pub fn coeffs(&self) -> &[SecureField] {
        &self.coeffs
    }
}

fn fold(values: &[SecureField], doublings: &[SecureField]) -> SecureField {
    let mut acc = SecureField::zero();
    for (i, v) in values.iter().enumerate() {
        let mut term = *v;
        for (bit, dbl) in doublings.iter().enumerate() {
            if (i >> bit) & 1 == 1 {
                term *= *dbl;
            }
        }
        acc += term;
    }
    acc
}

pub fn bit_reverse_index(i: usize, log_size: u32) -> usize {
    if log_size == 0 {
        return i;
    }
    i.reverse_bits() >> (usize::BITS - log_size)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriConfig {
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: usize,
}

impl FriConfig {
    pub fn mix_into<C: Channel>(&self, channel: &mut C) {
        channel.mix_u64(self.log_blowup_factor as u64);
        channel.mix_u64(self.n_queries as u64);
        channel.mix_u64(self.log_last_layer_degree_bound as u64);
    }

    pub fn security_bits(&self) -> u32 {
        self.log_blowup_factor * self.n_queries as u32
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriLayerProof {
    pub fri_witness: Vec<SecureField>,
    pub decommitment: MerkleDecommitment,
    pub commitment: Blake2sHash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FriProof {
    pub first_layer: FriLayerProof,
    pub inner_layers: Vec<FriLayerProof>,
    pub last_layer_poly: LinePoly,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcsConfig {
    pub pow_bits: u32,
    pub fri_config: FriConfig,
}

impl PcsConfig {
    pub fn mix_into<C: Channel>(&self, channel: &mut C) {
        channel.mix_u64(self.pow_bits as u64);
        self.fri_config.mix_into(channel);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentSchemeProof {
    pub config: PcsConfig,
    pub commitments: Vec<Blake2sHash>,
    pub sampled_values: Vec<Vec<Vec<SecureField>>>,
    pub decommitments: Vec<MerkleDecommitment>,
    pub queried_values: Vec<Vec<BaseField>>,
    pub proof_of_work: u64,
    pub fri_proof: FriProof,
}

pub type StwoCommitmentSchemeProof = CommitmentSchemeProof;

pub fn decode_stwo_commitment_scheme_proof(
    bytes: &[u8],
) -> Result<StwoCommitmentSchemeProof, String> {
    serde_json::from_slice::<CommitmentSchemeProof>(bytes)
        .map_err(|e| format!("stwo proof json decode failed: {e}"))
}

pub fn encode_stwo_commitment_scheme_proof(
    proof: &StwoCommitmentSchemeProof,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(proof).map_err(|e| format!("stwo proof json encode failed: {e}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProof(pub CommitmentSchemeProof);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleDecommitment {
    pub hash_witness: Vec<Blake2sHash>,
    pub column_witness: Vec<BaseField>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blake2sHash(pub [u8; 32]);

impl From<Blake2sHash> for [u8; 32] {
    fn from(val: Blake2sHash) -> Self {
        val.0
    }
}

impl AsRef<[u8]> for Blake2sHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for Blake2sHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl Debug for Blake2sHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Blake2sHash as Display>::fmt(self, f)
    }
}

pub trait Channel: Default + Clone + Debug {
    const BYTES_PER_HASH: usize;
    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool;
    fn mix_u32s(&mut self, data: &[u32]);
    fn mix_felts(&mut self, felts: &[SecureField]);
    fn mix_u64(&mut self, value: u64);
    fn draw_secure_felt(&mut self) -> SecureField;
    fn draw_u32s(&mut self) -> Vec<u32>;
}

#[derive(Default, Clone, Debug)]
pub struct Blake2sChannel {
    digest: Blake2sHash,
    n_draws: u32,
}

impl Blake2sChannel {
    pub fn digest(&self) -> Blake2sHash {
        self.digest
    }

    pub fn update_digest(&mut self, new_digest: Blake2sHash) {
        self.digest = new_digest;
        self.n_draws = 0;
    }

    fn draw_base_felts(&mut self) -> [BaseField; 8] {
        loop {
            let u32s_vec = self.draw_u32s();
            if u32s_vec.len() != 8 {
                continue;
            }
            let u32s = [
                u32s_vec[0],
                u32s_vec[1],
                u32s_vec[2],
                u32s_vec[3],
                u32s_vec[4],
                u32s_vec[5],
                u32s_vec[6],
                u32s_vec[7],
            ];
            if u32s.iter().all(|x| *x < 2 * M31_MODULUS) {
                let mut out = [BaseField::zero(); 8];
                for (dst, src) in out.iter_mut().zip(u32s.iter()) {
                    *dst = BaseField::reduce(*src as u64);
                }
                return out;
            }
        }
    }

    pub fn mix_root(&mut self, root: Blake2sHash) {
        let digest = self.digest();
        let next = Blake2sHasher::concat_and_hash(&digest, &root);
        self.update_digest(next);
    }
}

impl Channel for Blake2sChannel {
    const BYTES_PER_HASH: usize = 32;

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        const POW_PREFIX: u32 = 0x12345678;
        let digest = self.digest();
        let mut hasher = Blake2sHasher::default();
        hasher.update(&POW_PREFIX.to_le_bytes());
        hasher.update(&[0_u8; 12]);
        hasher.update(&digest.0[..]);
        hasher.update(&n_bits.to_le_bytes());
        let prefixed_digest = hasher.finalize();
        let mut hasher = Blake2sHasher::default();
        hasher.update(prefixed_digest.as_ref());
        hasher.update(&nonce.to_le_bytes());
        let res = hasher.finalize();
        let n_zeros = u128::from_le_bytes(core::array::from_fn(|i| res.0[i])).trailing_zeros();
        n_zeros >= n_bits
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let mut hasher = Blake2sHasher::default();
        hasher.update(self.digest.as_ref());
        for word in data {
            hasher.update(&word.to_le_bytes());
        }
        self.update_digest(hasher.finalize());
    }

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let mut buf = Vec::with_capacity(felts.len() * SECURE_EXTENSION_DEGREE * 4);
        for qm31 in felts {
            for m31 in qm31.to_m31_array() {
                buf.extend_from_slice(&m31.0.to_le_bytes());
            }
        }
        let mut hasher = Blake2sHasher::default();
        hasher.update(self.digest.as_ref());
        hasher.update(&buf);
        self.update_digest(hasher.finalize());
    }

    fn mix_u64(&mut self, value: u64) {
        self.mix_u32s(&[value as u32, (value >> 32) as u32])
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let felts = self.draw_base_felts();
        SecureField::from_m31_array([felts[0], felts[1], felts[2], felts[3]])
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        let mut hash_input = self.digest.as_ref().to_vec();
        let counter_bytes = self.n_draws.to_le_bytes();
        hash_input.extend_from_slice(&counter_bytes);
        hash_input.push(0_u8);
        self.n_draws += 1;
        Blake2sHasher::hash(&hash_input)
            .0
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Blake2sHasher {
    state: blake2::Blake2s256,
}

impl Blake2sHasher {
    pub fn update(&mut self, data: &[u8]) {
        use blake2::Digest;
        self.state.update(data);
    }

    pub fn finalize(self) -> Blake2sHash {
        let r: [u8; 32] = self.state.finalize().into();
        Blake2sHash(r)
    }

    pub fn hash(data: &[u8]) -> Blake2sHash {
        let mut hasher = Self::default();
        hasher.update(data);
        hasher.finalize()
    }

    pub fn concat_and_hash(left: &Blake2sHash, right: &Blake2sHash) -> Blake2sHash {
        let mut hasher = Self::default();
        hasher.update(left.as_ref());
        hasher.update(right.as_ref());
        hasher.finalize()
    }
}

#[derive(Clone, Debug)]
pub struct MerkleVerifier {
    pub root: Blake2sHash,
    pub column_log_sizes: Vec<u32>,
    pub n_columns_per_log_size: std::collections::BTreeMap<u32, usize>,
}

impl MerkleVerifier {
    pub fn new(root: Blake2sHash, column_log_sizes: Vec<u32>) -> Self {
        let mut n_columns_per_log_size = std::collections::BTreeMap::new();
        for log_size in &column_log_sizes {
            *n_columns_per_log_size.entry(*log_size).or_insert(0) += 1;
        }
        Self {
            root,
            column_log_sizes,
            n_columns_per_log_size,
        }
    }

    pub fn verify(
        &self,
        queries_per_log_size: &std::collections::BTreeMap<u32, Vec<usize>>,
        queried_values: Vec<BaseField>,
        decommitment: MerkleDecommitment,
    ) -> Result<(), String> {
        let Some(max_log_size) = self.column_log_sizes.iter().max() else {
            return Ok(());
        };
        let mut queried_values = queried_values.into_iter();
        let mut hash_witness = decommitment.hash_witness.into_iter();
        let mut column_witness = decommitment.column_witness.into_iter();
        let mut last_layer_hashes: Option<Vec<(usize, Blake2sHash)>> = None;
        for layer_log_size in (0..=*max_log_size).rev() {
            let n_columns_in_layer = *self.n_columns_per_log_size.get(&layer_log_size).unwrap_or(&0);
            let mut layer_total_queries = vec![];
            let mut prev_layer_queries = last_layer_hashes
                .iter()
                .flatten()
                .map(|(q, _)| *q)
                .collect::<Vec<_>>()
                .into_iter()
                .peekable();
            let mut prev_layer_hashes = last_layer_hashes.as_ref().map(|x| x.iter().peekable());
            let mut layer_column_queries = queries_per_log_size
                .get(&layer_log_size)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .peekable();

            while let Some(node_index) = next_decommitment_node(&mut prev_layer_queries, &mut layer_column_queries) {
                while let Some(q) = prev_layer_queries.peek() {
                    if *q / 2 == node_index {
                        prev_layer_queries.next();
                    } else {
                        break;
                    }
                }
                let node_hashes = prev_layer_hashes
                    .as_mut()
                    .map(|prev_layer_hashes| {
                        let left_hash = prev_layer_hashes
                            .next_if(|(index, _)| *index == 2 * node_index)
                            .map(|(_, hash)| Ok(*hash))
                            .unwrap_or_else(|| {
                                hash_witness
                                    .next()
                                    .ok_or_else(|| "witness too short".to_string())
                            })?;
                        let right_hash = prev_layer_hashes
                            .next_if(|(index, _)| *index == 2 * node_index + 1)
                            .map(|(_, hash)| Ok(*hash))
                            .unwrap_or_else(|| {
                                hash_witness
                                    .next()
                                    .ok_or_else(|| "witness too short".to_string())
                            })?;
                        Ok::<(Blake2sHash, Blake2sHash), String>((left_hash, right_hash))
                    })
                    .transpose()?;

                let use_queried = layer_column_queries.next_if_eq(&node_index).is_some();
                let mut node_values = Vec::with_capacity(n_columns_in_layer);
                for _ in 0..n_columns_in_layer {
                    let v = if use_queried {
                        queried_values.next().ok_or("too few queried values")?
                    } else {
                        column_witness.next().ok_or("witness too short")?
                    };
                    node_values.push(v);
                }
                layer_total_queries.push((node_index, blake2s_hash_node(node_hashes, &node_values)));
            }
            last_layer_hashes = Some(layer_total_queries);
        }
        if hash_witness.next().is_some() {
            return Err("witness too long".to_string());
        }
        if queried_values.next().is_some() {
            return Err("too many queried values".to_string());
        }
        if column_witness.next().is_some() {
            return Err("witness too long".to_string());
        }
        let last_layer_hashes = last_layer_hashes.ok_or("missing last layer hashes")?;
        let [(_, computed_root)] = last_layer_hashes
            .try_into()
            .map_err(|_| "invalid root")?;
        if computed_root != self.root {
            return Err("root mismatch".to_string());
        }
        Ok(())
    }
}

pub fn blake2s_hash_node(children_hashes: Option<(Blake2sHash, Blake2sHash)>, column_values: &[BaseField]) -> Blake2sHash {
    const LEAF_PREFIX: [u8; 64] = [
        b'l', b'e', b'a', b'f', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    const NODE_PREFIX: [u8; 64] = [
        b'n', b'o', b'd', b'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    let mut hasher = blake2::Blake2s256::new();
    if let Some((left, right)) = children_hashes {
        hasher.update(NODE_PREFIX);
        hasher.update(left.0);
        hasher.update(right.0);
    } else {
        hasher.update(LEAF_PREFIX);
    }
    for value in column_values {
        hasher.update(value.0.to_le_bytes());
    }
    let r: [u8; 32] = hasher.finalize().into();
    Blake2sHash(r)
}

fn next_decommitment_node(
    prev_queries: &mut core::iter::Peekable<impl Iterator<Item = usize>>,
    layer_queries: &mut core::iter::Peekable<impl Iterator<Item = usize>>,
) -> Option<usize> {
    prev_queries
        .peek()
        .map(|q| *q / 2)
        .into_iter()
        .chain(layer_queries.peek().into_iter().copied())
        .min()
}
