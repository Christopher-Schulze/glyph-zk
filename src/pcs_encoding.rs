//! PCS encoding helpers for binary field vectors.

use binius_field::{BinaryField128b, underlier::WithUnderlier};
use rayon::prelude::*;

fn basefold_par_min() -> usize {
    std::env::var("GLYPH_PCS_BASEFOLD_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1 << 12)
        .max(1)
}

/// Encode binary field elements into little-endian bytes.
pub fn encode_b128_vec_le(values: &[BinaryField128b]) -> Vec<u8> {
    let total = values.len().saturating_mul(16);
    if values.len() >= basefold_par_min() {
        let mut out = vec![0u8; total];
        out.par_chunks_mut(16)
            .zip(values.par_iter())
            .for_each(|(chunk, v)| {
                chunk.copy_from_slice(&v.to_underlier().to_le_bytes());
            });
        out
    } else {
        let mut out = Vec::with_capacity(total);
        for v in values {
            out.extend_from_slice(&v.to_underlier().to_le_bytes());
        }
        out
    }
}

/// Decode binary field elements from little-endian bytes with strict length checks.
pub fn decode_b128_vec_le(bytes: &[u8]) -> Result<Vec<BinaryField128b>, String> {
    if !bytes.len().is_multiple_of(16) {
        return Err("b128 vector bytes length must be a multiple of 16".to_string());
    }
    let count = bytes.len() / 16;
    if count >= basefold_par_min() {
        let mut out = vec![BinaryField128b::from_underlier(0u128); count];
        out.par_iter_mut()
            .zip(bytes.par_chunks_exact(16))
            .for_each(|(slot, chunk)| {
                let mut tmp = [0u8; 16];
                tmp.copy_from_slice(chunk);
                *slot = BinaryField128b::from_underlier(u128::from_le_bytes(tmp));
            });
        Ok(out)
    } else {
        let mut out = Vec::with_capacity(count);
        for chunk in bytes.chunks_exact(16) {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(chunk);
            out.push(BinaryField128b::from_underlier(u128::from_le_bytes(tmp)));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_b128_roundtrip() {
        let vals = [
            BinaryField128b::from_underlier(0u128),
            BinaryField128b::from_underlier(1u128),
            BinaryField128b::from_underlier(u128::MAX),
        ];
        let enc = encode_b128_vec_le(&vals);
        let dec = match decode_b128_vec_le(&enc) {
            Ok(dec) => dec,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(dec.len(), vals.len());
        for (a, b) in dec.iter().zip(vals.iter()) {
            assert_eq!(a.to_underlier(), b.to_underlier());
        }
    }

    #[test]
    fn test_decode_b128_rejects_bad_length() {
        let err = match decode_b128_vec_le(&[0u8; 15]) {
            Ok(_) => {
                assert!(false, "bad length");
                return;
            }
            Err(err) => err,
        };
        assert!(err.contains("multiple of 16"));
    }
}
