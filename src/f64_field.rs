//! Prime field arithmetic for Goldilocks (p = 2^64 - 2^32 + 1).
//!
//! This module provides reference-quality arithmetic for the Goldilocks field profile
//! used by the STARK adapter.

pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
const GOLDILOCKS_R2: u64 = 0xffff_fffe_0000_0001;

#[inline]
const fn mont_red_cst(x: u128) -> u64 {
    let xl = x as u64;
    let xh = (x >> 64) as u64;
    let (a, e) = xl.overflowing_add(xl << 32);
    let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);
    let (r, c) = xh.overflowing_sub(b);
    r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64)
}

#[inline(always)]
const fn mont_to_int(x: u64) -> u64 {
    let (a, e) = x.overflowing_add(x << 32);
    let b = a.wrapping_sub(a >> 32).wrapping_sub(e as u64);
    let (r, c) = 0u64.overflowing_sub(b);
    r.wrapping_sub(0u32.wrapping_sub(c as u32) as u64)
}

#[inline]
pub fn f64_add_mod(a: u64, b: u64) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    let mut sum = sum.wrapping_add((carry as u64) * 0xffff_ffff);
    if sum >= GOLDILOCKS_MODULUS {
        sum = sum.wrapping_sub(GOLDILOCKS_MODULUS);
    }
    sum
}

#[inline]
pub fn f64_sub_mod(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a.wrapping_add(GOLDILOCKS_MODULUS).wrapping_sub(b)
    }
}

#[inline]
pub fn f64_mul_mod(a: u64, b: u64) -> u64 {
    let a_mont = mont_red_cst((a as u128) * (GOLDILOCKS_R2 as u128));
    let b_mont = mont_red_cst((b as u128) * (GOLDILOCKS_R2 as u128));
    let prod_mont = mont_red_cst((a_mont as u128) * (b_mont as u128));
    mont_to_int(prod_mont)
}

pub fn f64_pow_mod(mut base: u64, mut exp: u64) -> u64 {
    let mut acc: u64 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = f64_mul_mod(acc, base);
        }
        exp >>= 1;
        if exp > 0 {
            base = f64_mul_mod(base, base);
        }
    }
    acc
}

pub fn f64_inv_mod(a: u64) -> Option<u64> {
    if a == 0 {
        return None;
    }
    Some(f64_pow_mod(a, GOLDILOCKS_MODULUS - 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::fields::f64::BaseElement;

    #[test]
    fn test_f64_add_sub_roundtrip() {
        let cases = [
            (0u64, 0u64),
            (1u64, 2u64),
            (GOLDILOCKS_MODULUS - 1, 1u64),
            (GOLDILOCKS_MODULUS - 5, 4u64),
            (123456789u64, 987654321u64),
        ];
        for (a, b) in cases {
            let sum = f64_add_mod(a, b);
            let back = f64_sub_mod(sum, b);
            assert_eq!(back, a % GOLDILOCKS_MODULUS);
        }
    }

    #[test]
    fn test_f64_mul_properties() {
        let p = GOLDILOCKS_MODULUS;
        assert_eq!(f64_mul_mod(p - 1, p - 1), 1);
        assert_eq!(f64_mul_mod(p - 1, 2), p - 2);
        assert_eq!(f64_mul_mod(0, 123), 0);
        assert_eq!(f64_mul_mod(1, 123), 123);
    }

    #[test]
    fn test_f64_inv() {
        let cases = [1u64, 2u64, 3u64, 1234567u64, GOLDILOCKS_MODULUS - 2];
        for a in cases {
            let inv = match f64_inv_mod(a) {
                Some(value) => value,
                None => {
                    assert!(false, "nonzero has inverse");
                    return;
                }
            };
            assert_eq!(f64_mul_mod(a, inv), 1);
        }
        assert!(f64_inv_mod(0).is_none());
    }

    #[test]
    fn test_f64_matches_winterfell() {
        let cases = [
            (0u64, 0u64),
            (1u64, 2u64),
            (3u64, 5u64),
            (GOLDILOCKS_MODULUS - 1, GOLDILOCKS_MODULUS - 2),
            (123456789u64, 987654321u64),
        ];
        for (a, b) in cases {
            let a_elem = BaseElement::new(a);
            let b_elem = BaseElement::new(b);
            let sum = (a_elem + b_elem).as_int();
            let prod = (a_elem * b_elem).as_int();
            assert_eq!(sum, f64_add_mod(a, b));
            assert_eq!(prod, f64_mul_mod(a, b));
        }
    }

    #[test]
    fn test_f64_random_matches_winterfell() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..1000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = state % GOLDILOCKS_MODULUS;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b = state % GOLDILOCKS_MODULUS;
            let a_elem = BaseElement::new(a);
            let b_elem = BaseElement::new(b);
            let sum = (a_elem + b_elem).as_int();
            let diff = (a_elem - b_elem).as_int();
            let prod = (a_elem * b_elem).as_int();
            assert_eq!(sum, f64_add_mod(a, b));
            assert_eq!(diff, f64_sub_mod(a, b));
            assert_eq!(prod, f64_mul_mod(a, b));
        }
    }
}
