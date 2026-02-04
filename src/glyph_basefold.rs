//! BaseFold helpers for GLYPH adapters.
//!
//! Provides deterministic derivations for BaseFold roots, weights, evaluation points,
//! and GLYPH artifact tags without relying on legacy kernels.

use binius_field::{BinaryField128b, Field, underlier::WithUnderlier};
use rayon::prelude::*;
use crate::adapters::keccak256;

pub const GLYPH_BINIUS_BASEFOLD_ROOT_DOMAIN: &[u8] = b"GLYPH_BINIUS_BASEFOLD_ROOT";
pub const GLYPH_BINIUS_BASEFOLD_ALPHA_DOMAIN: &[u8] = b"GLYPH_BINIUS_BASEFOLD_ALPHA";
pub const GLYPH_BINIUS_EVAL_POINT_DOMAIN: &[u8] = b"GLYPH_BINIUS_EVAL_POINT";
pub const GLYPH_BINIUS_COMMITMENT_TAG_DOMAIN: &[u8] = b"GLYPH_BINIUS_COMMITMENT_TAG";
pub const GLYPH_BINIUS_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_BINIUS_POINT_TAG";
const BASEFOLD_PAR_THRESHOLD: usize = 8;

fn b128_from_hash_le(hash: &[u8; 32]) -> BinaryField128b {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[0..16]);
    BinaryField128b::from_underlier(u128::from_le_bytes(bytes))
}


pub fn derive_basefold_root(instance_digests: &[[u8; 32]]) -> Result<[u8; 32], String> {
    if instance_digests.is_empty() {
        return Err("basefold root requires at least one instance digest".to_string());
    }
    let mut input = Vec::with_capacity(
        GLYPH_BINIUS_BASEFOLD_ROOT_DOMAIN.len() + 32 * instance_digests.len(),
    );
    input.extend_from_slice(GLYPH_BINIUS_BASEFOLD_ROOT_DOMAIN);
    for d in instance_digests {
        input.extend_from_slice(d);
    }
    Ok(keccak256(&input))
}

pub fn derive_basefold_alpha(root: &[u8; 32], idx: u32) -> Result<BinaryField128b, String> {
    for ctr in 0u32..32 {
        let mut input = Vec::with_capacity(
            GLYPH_BINIUS_BASEFOLD_ALPHA_DOMAIN.len() + 32 + 4 + 4,
        );
        input.extend_from_slice(GLYPH_BINIUS_BASEFOLD_ALPHA_DOMAIN);
        input.extend_from_slice(root);
        input.extend_from_slice(&idx.to_be_bytes());
        input.extend_from_slice(&ctr.to_be_bytes());
        let h = keccak256(&input);
        let candidate = b128_from_hash_le(&h);
        if candidate != BinaryField128b::ZERO {
            return Ok(candidate);
        }
    }
    Err("basefold alpha derivation failed after 32 attempts".to_string())
}

pub fn derive_basefold_weights(
    instance_digests: &[[u8; 32]],
) -> Result<Vec<BinaryField128b>, String> {
    let root = derive_basefold_root(instance_digests)?;
    if instance_digests.len() >= BASEFOLD_PAR_THRESHOLD && rayon::current_num_threads() > 1 {
        (0..instance_digests.len())
            .into_par_iter()
            .map(|idx| derive_basefold_alpha(&root, idx as u32))
            .collect::<Result<Vec<_>, String>>()
    } else {
        let mut out = Vec::with_capacity(instance_digests.len());
        for (idx, _) in instance_digests.iter().enumerate() {
            out.push(derive_basefold_alpha(&root, idx as u32)?);
        }
        Ok(out)
    }
}

pub fn fold_instance_evals_with_weights(
    weights: &[BinaryField128b],
    per_instance_evals: &[BinaryField128b],
) -> Result<BinaryField128b, String> {
    if weights.len() != per_instance_evals.len() {
        return Err("weights and per_instance_evals length mismatch".to_string());
    }
    if weights.is_empty() {
        return Err("weights must be non-empty".to_string());
    }
    if weights.len() >= BASEFOLD_PAR_THRESHOLD && rayon::current_num_threads() > 1 {
        Ok(weights
            .par_iter()
            .zip(per_instance_evals.par_iter())
            .map(|(w, v)| *w * *v)
            .reduce(|| BinaryField128b::ZERO, |a, b| a + b))
    } else {
        let mut acc = BinaryField128b::ZERO;
        for (w, v) in weights.iter().zip(per_instance_evals.iter()) {
            acc += *w * *v;
        }
        Ok(acc)
    }
}

pub fn derive_binius_eval_point(
    seed: &[u8],
    oracle_id_index: u32,
    n_vars: usize,
) -> Vec<BinaryField128b> {
    let seed_len = seed.len().min(64);
    let mut prefix = Vec::with_capacity(GLYPH_BINIUS_EVAL_POINT_DOMAIN.len() + seed_len + 4);
    prefix.extend_from_slice(GLYPH_BINIUS_EVAL_POINT_DOMAIN);
    prefix.extend_from_slice(&seed[..seed_len]);
    prefix.extend_from_slice(&oracle_id_index.to_be_bytes());

    if n_vars >= BASEFOLD_PAR_THRESHOLD && rayon::current_num_threads() > 1 {
        (0..n_vars)
            .into_par_iter()
            .map(|i| {
                let mut local = Vec::with_capacity(prefix.len() + 4);
                local.extend_from_slice(&prefix);
                local.extend_from_slice(&(i as u32).to_be_bytes());
                let h = keccak256(&local);
                b128_from_hash_le(&h)
            })
            .collect()
    } else {
        let mut point = Vec::with_capacity(n_vars);
        let mut buf = Vec::with_capacity(prefix.len() + 4);
        buf.extend_from_slice(&prefix);
        let idx_offset = prefix.len();
        buf.resize(idx_offset + 4, 0u8);
        for i in 0..n_vars {
            buf[idx_offset..idx_offset + 4].copy_from_slice(&(i as u32).to_be_bytes());
            let h = keccak256(&buf);
            point.push(b128_from_hash_le(&h));
        }
        point
    }
}

#[derive(Clone, Debug)]
pub struct FoldedBaseFoldOracleEval {
    pub oracle_id_index: usize,
    pub n_vars: usize,
    pub eval_point: Vec<BinaryField128b>,
    pub instance_digests: Vec<[u8; 32]>,
    pub weights: Vec<BinaryField128b>,
    pub per_instance_evals: Vec<BinaryField128b>,
    pub folded_eval: BinaryField128b,
}

pub fn fold_instance_evals_to_folded_oracle_eval(
    seed: &[u8],
    oracle_id_index: usize,
    n_vars: usize,
    instance_digests: Vec<[u8; 32]>,
    per_instance_evals: Vec<BinaryField128b>,
) -> Result<FoldedBaseFoldOracleEval, String> {
    if instance_digests.is_empty() {
        return Err("folded oracle requires at least one instance digest".to_string());
    }
    if instance_digests.len() != per_instance_evals.len() {
        return Err("instance_digests and per_instance_evals length mismatch".to_string());
    }

    let weights = derive_basefold_weights(&instance_digests)?;
    let folded_eval = fold_instance_evals_with_weights(&weights, &per_instance_evals)?;

    Ok(FoldedBaseFoldOracleEval {
        oracle_id_index,
        n_vars,
        eval_point: derive_binius_eval_point(seed, oracle_id_index as u32, n_vars),
        instance_digests,
        weights,
        per_instance_evals,
        folded_eval,
    })
}

pub fn derive_glyph_artifact_from_folded_oracle_eval(
    folded: &FoldedBaseFoldOracleEval,
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let oracle_id_index_u32 = folded.oracle_id_index as u32;
    let n_vars_u32 = folded.n_vars as u32;

    let root = derive_basefold_root(&folded.instance_digests)?;

    let mut c_input = Vec::with_capacity(
        GLYPH_BINIUS_COMMITMENT_TAG_DOMAIN.len() + 32 + 4 + 4,
    );
    c_input.extend_from_slice(GLYPH_BINIUS_COMMITMENT_TAG_DOMAIN);
    c_input.extend_from_slice(&root);
    c_input.extend_from_slice(&oracle_id_index_u32.to_be_bytes());
    c_input.extend_from_slice(&n_vars_u32.to_be_bytes());
    let commitment_tag = keccak256(&c_input);

    let mut p_input = Vec::with_capacity(
        GLYPH_BINIUS_POINT_TAG_DOMAIN.len() + 4 + 4 + 16 * folded.eval_point.len(),
    );
    p_input.extend_from_slice(GLYPH_BINIUS_POINT_TAG_DOMAIN);
    p_input.extend_from_slice(&oracle_id_index_u32.to_be_bytes());
    p_input.extend_from_slice(&n_vars_u32.to_be_bytes());
    for x in &folded.eval_point {
        p_input.extend_from_slice(&x.to_underlier().to_be_bytes());
    }
    let point_tag = keccak256(&p_input);

    let claim128 = folded.folded_eval.to_underlier();
    Ok((commitment_tag, point_tag, claim128))
}

pub fn derive_glyph_artifact_from_instance_digests(
    instance_digests: &[[u8; 32]],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    if instance_digests.is_empty() {
        return Err("need at least one instance digest".to_string());
    }
    let root = derive_basefold_root(instance_digests)?;
    let weights = derive_basefold_weights(instance_digests)?;

    let mut c_input = Vec::with_capacity(
        GLYPH_BINIUS_COMMITMENT_TAG_DOMAIN.len() + 32 + 4,
    );
    c_input.extend_from_slice(GLYPH_BINIUS_COMMITMENT_TAG_DOMAIN);
    c_input.extend_from_slice(&root);
    c_input.extend_from_slice(&(instance_digests.len() as u32).to_be_bytes());
    let commitment_tag = keccak256(&c_input);

    let mut p_input = Vec::with_capacity(
        GLYPH_BINIUS_POINT_TAG_DOMAIN.len() + 32 + 4,
    );
    p_input.extend_from_slice(GLYPH_BINIUS_POINT_TAG_DOMAIN);
    p_input.extend_from_slice(&root);
    p_input.extend_from_slice(&(instance_digests.len() as u32).to_be_bytes());
    let point_tag = keccak256(&p_input);

    let weight_sum = if weights.len() >= BASEFOLD_PAR_THRESHOLD && rayon::current_num_threads() > 1 {
        weights
            .par_iter()
            .copied()
            .reduce(|| BinaryField128b::ZERO, |a, b| a + b)
    } else {
        let mut acc = BinaryField128b::ZERO;
        for w in &weights {
            acc += *w;
        }
        acc
    };
    let claim128 = weight_sum.to_underlier();
    Ok((commitment_tag, point_tag, claim128))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basefold_root_determinism() {
        let d1 = keccak256(b"a");
        let d2 = keccak256(b"b");
        let root1 = match derive_basefold_root(&[d1, d2]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "root");
                return;
            }
        };
        let root2 = match derive_basefold_root(&[d1, d2]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "root");
                return;
            }
        };
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_basefold_weights_nonzero() {
        let d1 = keccak256(b"w1");
        let weights = match derive_basefold_weights(&[d1]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "weights");
                return;
            }
        };
        assert_eq!(weights.len(), 1);
        assert_ne!(weights[0], BinaryField128b::ZERO);
    }

    #[test]
    fn test_instance_digest_artifact_roundtrip_shape() {
        let d1 = keccak256(b"x1");
        let (c, p, claim) = match derive_glyph_artifact_from_instance_digests(&[d1]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "artifact");
                return;
            }
        };
        assert_ne!(c, [0u8; 32]);
        assert_ne!(p, [0u8; 32]);
        assert_ne!(claim, 0u128);
    }
}
