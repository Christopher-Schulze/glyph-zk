//! Prime field arithmetic for M31 (p = 2^31 - 1).
//!
//! This module provides reference-quality arithmetic for the legacy M31 field profile.
//! It is intentionally small and deterministic.

pub const M31_MODULUS: u32 = 0x7fffffff;

#[inline]
fn m31_reduce_u64(mut x: u64) -> u32 {
    let p = M31_MODULUS as u64;
    x = (x & p) + (x >> 31);
    if x >= p {
        x -= p;
    }
    x = (x & p) + (x >> 31);
    if x >= p {
        x -= p;
    }
    x as u32
}

#[inline]
pub fn m31_add_mod(a: u32, b: u32) -> u32 {
    m31_reduce_u64(a as u64 + b as u64)
}

#[inline]
pub fn m31_sub_mod(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        (a + M31_MODULUS) - b
    }
}

#[inline]
pub fn m31_neg_mod(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        M31_MODULUS - a
    }
}

#[inline]
pub fn m31_mul_mod(a: u32, b: u32) -> u32 {
    m31_reduce_u64((a as u64) * (b as u64))
}

#[inline]
pub fn m31_from_be_bytes_strict(bytes: [u8; 4]) -> Result<u32, String> {
    let v = u32::from_be_bytes(bytes);
    if v >= M31_MODULUS {
        return Err("m31 bytes not canonical".to_string());
    }
    Ok(v)
}

#[inline]
pub fn m31_to_be_bytes(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[inline]
pub fn m31_from_hash(bytes: &[u8; 32]) -> u32 {
    let mut limb = [0u8; 8];
    limb.copy_from_slice(&bytes[..8]);
    m31_reduce_u64(u64::from_be_bytes(limb))
}

pub fn m31_pow_mod(mut base: u32, mut exp: u32) -> u32 {
    let mut acc: u32 = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = m31_mul_mod(acc, base);
        }
        exp >>= 1;
        if exp > 0 {
            base = m31_mul_mod(base, base);
        }
    }
    acc
}

pub fn m31_inv_mod(a: u32) -> Option<u32> {
    if a == 0 {
        return None;
    }
    Some(m31_pow_mod(a, M31_MODULUS - 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_m31_add_sub_roundtrip() {
        let cases = [
            (0u32, 0u32),
            (1u32, 2u32),
            (M31_MODULUS - 1, 1u32),
            (M31_MODULUS - 5, 4u32),
            (1234567u32, 7654321u32),
        ];
        for (a, b) in cases {
            let sum = m31_add_mod(a, b);
            let back = m31_sub_mod(sum, b);
            assert_eq!(back, a % M31_MODULUS);
        }
    }

    #[test]
    fn test_m31_mul_properties() {
        let p = M31_MODULUS;
        assert_eq!(m31_mul_mod(p - 1, p - 1), 1);
        assert_eq!(m31_mul_mod(p - 1, 2), p - 2);
        assert_eq!(m31_mul_mod(0, 123), 0);
        assert_eq!(m31_mul_mod(1, 123), 123);
    }

    #[test]
    fn test_m31_inv() {
        let cases = [1u32, 2u32, 3u32, 1234567u32, M31_MODULUS - 2];
        for a in cases {
            let inv = match m31_inv_mod(a) {
                Some(value) => value,
                None => {
                    assert!(false, "nonzero has inverse");
                    return;
                }
            };
            assert_eq!(m31_mul_mod(a, inv), 1);
        }
        assert!(m31_inv_mod(0).is_none());
    }
}
