//! Prime field arithmetic for Baby Bear (p = 2^31 - 2^27 + 1).
//!
//! This module provides reference-quality arithmetic for the Baby Bear field
//! used by Circle STARK profiles (e.g. RISC Zero style receipts).

pub const BABY_BEAR_MODULUS: u32 = 0x78000001;

#[inline]
fn baby_bear_reduce_u64(mut x: u64) -> u32 {
    let p = BABY_BEAR_MODULUS as u64;
    x %= p;
    x as u32
}

#[inline]
pub fn baby_bear_add_mod(a: u32, b: u32) -> u32 {
    baby_bear_reduce_u64(a as u64 + b as u64)
}

#[inline]
pub fn baby_bear_sub_mod(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        (a + BABY_BEAR_MODULUS) - b
    }
}

#[inline]
pub fn baby_bear_neg_mod(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        BABY_BEAR_MODULUS - a
    }
}

#[inline]
pub fn baby_bear_mul_mod(a: u32, b: u32) -> u32 {
    baby_bear_reduce_u64((a as u64) * (b as u64))
}

#[inline]
pub fn baby_bear_from_be_bytes_strict(bytes: [u8; 4]) -> Result<u32, String> {
    let v = u32::from_be_bytes(bytes);
    if v >= BABY_BEAR_MODULUS {
        return Err("baby bear bytes not canonical".to_string());
    }
    Ok(v)
}

#[inline]
pub fn baby_bear_to_be_bytes(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[inline]
pub fn baby_bear_from_hash(bytes: &[u8; 32]) -> u32 {
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&bytes[..8]);
    baby_bear_reduce_u64(u64::from_be_bytes(limb))
}

pub fn baby_bear_pow_mod(mut base: u32, mut exp: u32) -> u32 {
    let mut acc: u32 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = baby_bear_mul_mod(acc, base);
        }
        exp >>= 1;
        if exp > 0 {
            base = baby_bear_mul_mod(base, base);
        }
    }
    acc
}

pub fn baby_bear_inv_mod(a: u32) -> Option<u32> {
    if a == 0 {
        return None;
    }
    Some(baby_bear_pow_mod(a, BABY_BEAR_MODULUS - 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baby_bear_add_sub_roundtrip() {
        let cases = [
            (0u32, 0u32),
            (1u32, 2u32),
            (BABY_BEAR_MODULUS - 1, 1u32),
            (BABY_BEAR_MODULUS - 5, 4u32),
            (1234567u32, 7654321u32),
        ];
        for (a, b) in cases {
            let sum = baby_bear_add_mod(a, b);
            let back = baby_bear_sub_mod(sum, b);
            assert_eq!(back, a % BABY_BEAR_MODULUS);
        }
    }

    #[test]
    fn test_baby_bear_mul_properties() {
        let p = BABY_BEAR_MODULUS;
        assert_eq!(baby_bear_mul_mod(p - 1, p - 1), 1);
        assert_eq!(baby_bear_mul_mod(p - 1, 2), p - 2);
        assert_eq!(baby_bear_mul_mod(0, 123), 0);
        assert_eq!(baby_bear_mul_mod(1, 123), 123);
    }

    #[test]
    fn test_baby_bear_inv() {
        let cases = [1u32, 2u32, 3u32, 1234567u32, BABY_BEAR_MODULUS - 2];
        for a in cases {
            let inv = match baby_bear_inv_mod(a) {
                Some(value) => value,
                None => {
                    assert!(false, "nonzero has inverse");
                    return;
                }
            };
            assert_eq!(baby_bear_mul_mod(a, inv), 1);
        }
        assert!(baby_bear_inv_mod(0).is_none());
    }
}
