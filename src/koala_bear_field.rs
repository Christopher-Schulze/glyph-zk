//! Prime field arithmetic for Koala Bear (p = 2^31 - 2^24 + 1).
//!
//! This module provides reference-quality arithmetic for the Koala Bear field
//! used by Circle STARK profiles (e.g. Plonky3-style receipts).

pub const KOALA_BEAR_MODULUS: u32 = 0x7f000001;

#[inline]
fn koala_bear_reduce_u64(mut x: u64) -> u32 {
    let p = KOALA_BEAR_MODULUS as u64;
    x %= p;
    x as u32
}

#[inline]
pub fn koala_bear_add_mod(a: u32, b: u32) -> u32 {
    koala_bear_reduce_u64(a as u64 + b as u64)
}

#[inline]
pub fn koala_bear_sub_mod(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        (a + KOALA_BEAR_MODULUS) - b
    }
}

#[inline]
pub fn koala_bear_neg_mod(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        KOALA_BEAR_MODULUS - a
    }
}

#[inline]
pub fn koala_bear_mul_mod(a: u32, b: u32) -> u32 {
    koala_bear_reduce_u64((a as u64) * (b as u64))
}

#[inline]
pub fn koala_bear_from_be_bytes_strict(bytes: [u8; 4]) -> Result<u32, String> {
    let v = u32::from_be_bytes(bytes);
    if v >= KOALA_BEAR_MODULUS {
        return Err("koala bear bytes not canonical".to_string());
    }
    Ok(v)
}

#[inline]
pub fn koala_bear_to_be_bytes(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[inline]
pub fn koala_bear_from_hash(bytes: &[u8; 32]) -> u32 {
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&bytes[..8]);
    koala_bear_reduce_u64(u64::from_be_bytes(limb))
}

pub fn koala_bear_pow_mod(mut base: u32, mut exp: u32) -> u32 {
    let mut acc: u32 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = koala_bear_mul_mod(acc, base);
        }
        exp >>= 1;
        if exp > 0 {
            base = koala_bear_mul_mod(base, base);
        }
    }
    acc
}

pub fn koala_bear_inv_mod(a: u32) -> Option<u32> {
    if a == 0 {
        return None;
    }
    Some(koala_bear_pow_mod(a, KOALA_BEAR_MODULUS - 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_koala_bear_add_sub_roundtrip() {
        let cases = [
            (0u32, 0u32),
            (1u32, 2u32),
            (KOALA_BEAR_MODULUS - 1, 1u32),
            (KOALA_BEAR_MODULUS - 5, 4u32),
            (1234567u32, 7654321u32),
        ];
        for (a, b) in cases {
            let sum = koala_bear_add_mod(a, b);
            let back = koala_bear_sub_mod(sum, b);
            assert_eq!(back, a % KOALA_BEAR_MODULUS);
        }
    }

    #[test]
    fn test_koala_bear_mul_properties() {
        let p = KOALA_BEAR_MODULUS;
        assert_eq!(koala_bear_mul_mod(p - 1, p - 1), 1);
        assert_eq!(koala_bear_mul_mod(p - 1, 2), p - 2);
        assert_eq!(koala_bear_mul_mod(0, 123), 0);
        assert_eq!(koala_bear_mul_mod(1, 123), 123);
    }

    #[test]
    fn test_koala_bear_inv() {
        let cases = [1u32, 2u32, 3u32, 1234567u32, KOALA_BEAR_MODULUS - 2];
        for a in cases {
            let inv = match koala_bear_inv_mod(a) {
                Some(value) => value,
                None => {
                    assert!(false, "nonzero has inverse");
                    return;
                }
            };
            assert_eq!(koala_bear_mul_mod(a, inv), 1);
        }
        assert!(koala_bear_inv_mod(0).is_none());
    }
}
