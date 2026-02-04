use winterfell::math::{StarkField, fields::f128::BaseElement};

pub const F128_MODULUS: u128 = u128::MAX - (45u128 << 40) + 2;

#[inline]
pub fn f128_add_mod(a: u128, b: u128) -> u128 {
    let (sum, carry) = a.overflowing_add(b);
    if carry {
        // sum + 2^128, and 2^128 = (45<<40) - 1 (mod p)
        let (sum, borrow) = sum.overflowing_sub(1);
        let sum = sum.wrapping_add(45u128 << 40);
        let sum = if borrow { sum.wrapping_add(1) } else { sum };
        f128_canonicalize(sum)
    } else {
        f128_canonicalize(sum)
    }
}

#[inline]
pub fn f128_sub_mod(a: u128, b: u128) -> u128 {
    let (diff, borrow) = a.overflowing_sub(b);
    if borrow {
        diff.wrapping_add(F128_MODULUS)
    } else {
        diff
    }
}

#[inline]
pub fn f128_mul_mod(a: u128, b: u128) -> u128 {
    let (hi, lo) = mul_u128_full(a, b);
    f128_reduce_u256(hi, lo)
}

#[inline]
pub fn base_to_u128(x: BaseElement) -> u128 {
    x.as_int()
}

#[inline]
pub fn u128_to_base(x: u128) -> BaseElement {
    BaseElement::new(f128_canonicalize(x))
}

#[inline]
pub fn f128_canonicalize(x: u128) -> u128 {
    if x >= F128_MODULUS {
        x - F128_MODULUS
    } else {
        x
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
fn f128_reduce_u256(mut hi: u128, mut lo: u128) -> u128 {
    // p = 2^128 - (45*2^40) + 1, so 2^128 = (45<<40) - 1 (mod p).
    // For t = lo + 2^128*hi:
    //   t mod p = lo - hi + (hi*45)<<40
    // This yields at most ~175 bits, so iterating 2-3 rounds is enough.
    for _ in 0..3 {
        if hi == 0 {
            break;
        }

        let (m_hi, m_lo) = mul_u128_full(hi, 45);
        let shift = 40u32;
        let sh_lo = m_lo << shift;
        let sh_hi = (m_hi << shift) | (m_lo >> (128 - shift));

        let (sum1, c1) = lo.overflowing_add(sh_lo);
        let mut sum_hi = sh_hi.wrapping_add(c1 as u128);
        let (sum2, b1) = sum1.overflowing_sub(hi);
        sum_hi = sum_hi.wrapping_sub(b1 as u128);

        lo = sum2;
        hi = sum_hi;
    }

    // Final fold if a tiny hi remains after 3 rounds.
    while hi != 0 {
        let (m_hi, m_lo) = mul_u128_full(hi, 45);
        let shift = 40u32;
        let sh_lo = m_lo << shift;
        let sh_hi = (m_hi << shift) | (m_lo >> (128 - shift));

        let (sum1, c1) = lo.overflowing_add(sh_lo);
        let mut sum_hi = sh_hi.wrapping_add(c1 as u128);
        let (sum2, b1) = sum1.overflowing_sub(hi);
        sum_hi = sum_hi.wrapping_sub(b1 as u128);
        lo = sum2;
        hi = sum_hi;
    }

    f128_canonicalize(lo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use rand::{RngCore, SeedableRng};
    use rand::rngs::StdRng;
    use winterfell::math::StarkField;

    fn big_modulus() -> BigUint {
        BigUint::from(F128_MODULUS)
    }

    #[test]
    fn test_f128_modulus_matches_winterfell() {
        // Sanity: Winterfell BaseElement modulus is exactly this constant.
        let m = BigUint::from(BaseElement::MODULUS);
        assert_eq!(m, big_modulus());
    }

    #[test]
    fn prop_mul_matches_biguint_mod() {
        let m = big_modulus();
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);

        for _ in 0..10_000 {
            let a = rng.next_u64() as u128 | ((rng.next_u64() as u128) << 64);
            let b = rng.next_u64() as u128 | ((rng.next_u64() as u128) << 64);

            let got = f128_mul_mod(a % F128_MODULUS, b % F128_MODULUS);

            let a_big = BigUint::from(a % F128_MODULUS);
            let b_big = BigUint::from(b % F128_MODULUS);
            let exp = (a_big * b_big) % &m;
            let exp_u128 = match exp.try_into() {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "fits u128");
                    return;
                }
            };

            assert_eq!(got, exp_u128);
        }
    }

    #[test]
    fn prop_add_sub_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0xBADC0DE);
        for _ in 0..100_000 {
            let a = (rng.next_u64() as u128 | ((rng.next_u64() as u128) << 64)) % F128_MODULUS;
            let b = (rng.next_u64() as u128 | ((rng.next_u64() as u128) << 64)) % F128_MODULUS;
            let s = f128_add_mod(a, b);
            let back = f128_sub_mod(s, b);
            assert_eq!(back, a);
        }
    }
}
