//! Circle FRI proof types and verifier.

use crate::circle_merkle;
use rayon::prelude::*;

pub const CIRCLE_FRI_PROOF_TAG: &[u8] = b"CIRCLE_FRI_PROOF";
pub const CIRCLE_FRI_PROOF_VERSION: u16 = 1;

fn tag_offset(bytes: &[u8], tag: &[u8]) -> Result<usize, String> {
    if !bytes.starts_with(tag) {
        return Err("circle fri tag mismatch".to_string());
    }
    let mut off = tag.len();
    if bytes.len() >= off + 3 && bytes[off] == b'_' && bytes[off + 1] == b'V' && bytes[off + 2].is_ascii_digit()
    {
        off += 2;
        while off < bytes.len() && bytes[off].is_ascii_digit() {
            off += 1;
        }
    }
    Ok(off)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleFriQuery {
    pub position: u32,
    pub position_neg: u32,
    pub value: u32,
    pub value_neg: u32,
    pub next_value: u32,
    pub proof: Vec<[u8; 32]>,
    pub proof_neg: Vec<[u8; 32]>,
    pub next_proof: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleFriLayerProof {
    pub layer_root: [u8; 32],
    pub next_root: [u8; 32],
    pub queries: Vec<CircleFriQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleFriProof {
    pub version: u16,
    pub log_domain_size: u8,
    pub layers: Vec<CircleFriLayerProof>,
    pub final_value: u32,
}

impl CircleFriProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CIRCLE_FRI_PROOF_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.log_domain_size);
        out.extend_from_slice(&(self.layers.len() as u16).to_be_bytes());
        for layer in &self.layers {
            out.extend_from_slice(&layer.layer_root);
            out.extend_from_slice(&layer.next_root);
            out.extend_from_slice(&(layer.queries.len() as u16).to_be_bytes());
            for q in &layer.queries {
                out.extend_from_slice(&q.position.to_be_bytes());
                out.extend_from_slice(&q.position_neg.to_be_bytes());
                out.extend_from_slice(&q.value.to_be_bytes());
                out.extend_from_slice(&q.value_neg.to_be_bytes());
                out.extend_from_slice(&q.next_value.to_be_bytes());
                encode_proof_vec(&mut out, &q.proof);
                encode_proof_vec(&mut out, &q.proof_neg);
                encode_proof_vec(&mut out, &q.next_proof);
            }
        }
        out.extend_from_slice(&self.final_value.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CIRCLE_FRI_PROOF_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != CIRCLE_FRI_PROOF_VERSION {
            return Err(format!("unsupported circle fri version={version}"));
        }
        let log_domain_size = read_u8(bytes, &mut off)?;
        let layer_count = read_u16_be(bytes, &mut off)? as usize;
        let mut layers = Vec::with_capacity(layer_count);
        for _ in 0..layer_count {
            let layer_root = read_bytes32(bytes, &mut off)?;
            let next_root = read_bytes32(bytes, &mut off)?;
            let q_len = read_u16_be(bytes, &mut off)? as usize;
            let mut queries = Vec::with_capacity(q_len);
            for _ in 0..q_len {
                let position = read_u32_be(bytes, &mut off)?;
                let position_neg = read_u32_be(bytes, &mut off)?;
                let value = read_u32_be(bytes, &mut off)?;
                let value_neg = read_u32_be(bytes, &mut off)?;
                let next_value = read_u32_be(bytes, &mut off)?;
                let proof = decode_proof_vec(bytes, &mut off)?;
                let proof_neg = decode_proof_vec(bytes, &mut off)?;
                let next_proof = decode_proof_vec(bytes, &mut off)?;
                queries.push(CircleFriQuery {
                    position,
                    position_neg,
                    value,
                    value_neg,
                    next_value,
                    proof,
                    proof_neg,
                    next_proof,
                });
            }
            layers.push(CircleFriLayerProof {
                layer_root,
                next_root,
                queries,
            });
        }
        let final_value = read_u32_be(bytes, &mut off)?;
        if off != bytes.len() {
            return Err("circle fri proof trailing data".to_string());
        }
        Ok(Self {
            version,
            log_domain_size,
            layers,
            final_value,
        })
    }
}

pub fn verify_circle_fri(
    proof: &CircleFriProof,
    expected_positions: &[u32],
    alphas: &[u32],
    hash_id: u8,
    add_mod: fn(u32, u32) -> u32,
    mul_mod: fn(u32, u32) -> u32,
) -> Result<(), String> {
    if proof.log_domain_size == 0 {
        return Err("circle fri log_domain_size must be > 0".to_string());
    }
    if proof.layers.len() != alphas.len() {
        return Err("circle fri alpha count mismatch".to_string());
    }
    if expected_positions.is_empty() {
        return Err("circle fri requires at least one query".to_string());
    }
    if proof.layers.len() != proof.log_domain_size as usize {
        return Err("circle fri layer count mismatch".to_string());
    }
    let mut domain_size = 1usize << proof.log_domain_size;
    for (layer_idx, layer) in proof.layers.iter().enumerate() {
        if layer.queries.len() != expected_positions.len() {
            return Err("circle fri query count mismatch".to_string());
        }
        let alpha = alphas[layer_idx];
        let half = domain_size / 2;
        if half == 0 {
            return Err("circle fri domain underflow".to_string());
        }
        if layer.queries.len() >= 128 && rayon::current_num_threads() > 1 {
            layer
                .queries
                .par_iter()
                .enumerate()
                .try_for_each(|(q_idx, q)| -> Result<(), String> {
                    let expected_pos = (expected_positions[q_idx] as usize) & (domain_size - 1);
                    let expected_pos = expected_pos as u32;
                    let expected_neg = (expected_pos as usize ^ half) as u32;
                    let expected_next = (expected_pos as usize & (half - 1)) as u32;
                    if q.position != expected_pos {
                        return Err("circle fri position mismatch".to_string());
                    }
                    if q.position_neg != expected_neg {
                        return Err("circle fri position_neg mismatch".to_string());
                    }
                    let leaf = circle_merkle::hash_leaf_with_hash_id(
                        hash_id,
                        q.position,
                        &q.value.to_be_bytes(),
                    )?;
                    if !circle_merkle::verify_with_hash_id(
                        &layer.layer_root,
                        &leaf,
                        q.position as usize,
                        &q.proof,
                        hash_id,
                    )? {
                        return Err("circle fri leaf proof failed".to_string());
                    }
                    let leaf_neg = circle_merkle::hash_leaf_with_hash_id(
                        hash_id,
                        q.position_neg,
                        &q.value_neg.to_be_bytes(),
                    )?;
                    if !circle_merkle::verify_with_hash_id(
                        &layer.layer_root,
                        &leaf_neg,
                        q.position_neg as usize,
                        &q.proof_neg,
                        hash_id,
                    )? {
                        return Err("circle fri neg leaf proof failed".to_string());
                    }
                    let folded = if (q.position as usize) < half {
                        add_mod(q.value, mul_mod(alpha, q.value_neg))
                    } else {
                        add_mod(q.value_neg, mul_mod(alpha, q.value))
                    };
                    if folded != q.next_value {
                        return Err("circle fri fold mismatch".to_string());
                    }
                    let leaf_next = circle_merkle::hash_leaf_with_hash_id(
                        hash_id,
                        expected_next,
                        &q.next_value.to_be_bytes(),
                    )?;
                    if !circle_merkle::verify_with_hash_id(
                        &layer.next_root,
                        &leaf_next,
                        expected_next as usize,
                        &q.next_proof,
                        hash_id,
                    )? {
                        return Err("circle fri next proof failed".to_string());
                    }
                    if layer_idx == proof.layers.len().saturating_sub(1)
                        && q.next_value != proof.final_value
                    {
                        return Err("circle fri final value mismatch".to_string());
                    }
                    Ok(())
                })?;
        } else {
            for (q_idx, q) in layer.queries.iter().enumerate() {
                let expected_pos = (expected_positions[q_idx] as usize) & (domain_size - 1);
                let expected_pos = expected_pos as u32;
                let expected_neg = (expected_pos as usize ^ half) as u32;
                let expected_next = (expected_pos as usize & (half - 1)) as u32;
                if q.position != expected_pos {
                    return Err("circle fri position mismatch".to_string());
                }
                if q.position_neg != expected_neg {
                    return Err("circle fri position_neg mismatch".to_string());
                }
                let leaf = circle_merkle::hash_leaf_with_hash_id(
                    hash_id,
                    q.position,
                    &q.value.to_be_bytes(),
                )?;
                if !circle_merkle::verify_with_hash_id(
                    &layer.layer_root,
                    &leaf,
                    q.position as usize,
                    &q.proof,
                    hash_id,
                )? {
                    return Err("circle fri leaf proof failed".to_string());
                }
                let leaf_neg = circle_merkle::hash_leaf_with_hash_id(
                    hash_id,
                    q.position_neg,
                    &q.value_neg.to_be_bytes(),
                )?;
                if !circle_merkle::verify_with_hash_id(
                    &layer.layer_root,
                    &leaf_neg,
                    q.position_neg as usize,
                    &q.proof_neg,
                    hash_id,
                )? {
                    return Err("circle fri neg leaf proof failed".to_string());
                }
                let folded = if (q.position as usize) < half {
                    add_mod(q.value, mul_mod(alpha, q.value_neg))
                } else {
                    add_mod(q.value_neg, mul_mod(alpha, q.value))
                };
                if folded != q.next_value {
                    return Err("circle fri fold mismatch".to_string());
                }
                let leaf_next = circle_merkle::hash_leaf_with_hash_id(
                    hash_id,
                    expected_next,
                    &q.next_value.to_be_bytes(),
                )?;
                if !circle_merkle::verify_with_hash_id(
                    &layer.next_root,
                    &leaf_next,
                    expected_next as usize,
                    &q.next_proof,
                    hash_id,
                )? {
                    return Err("circle fri next proof failed".to_string());
                }
                if layer_idx == proof.layers.len().saturating_sub(1)
                    && q.next_value != proof.final_value
                {
                    return Err("circle fri final value mismatch".to_string());
                }
            }
        }
        domain_size = half;
    }
    Ok(())
}

fn encode_proof_vec(out: &mut Vec<u8>, proof: &[[u8; 32]]) {
    out.extend_from_slice(&(proof.len() as u16).to_be_bytes());
    for node in proof {
        out.extend_from_slice(node);
    }
}

fn decode_proof_vec(bytes: &[u8], off: &mut usize) -> Result<Vec<[u8; 32]>, String> {
    let len = read_u16_be(bytes, off)? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_bytes32(bytes, off)?);
    }
    Ok(out)
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let v = bytes.get(*off).copied().ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 1;
    Ok(v)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes.get(*off..*off + 2).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes.get(*off..*off + 4).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_bytes32(bytes: &[u8], off: &mut usize) -> Result<[u8; 32], String> {
    let s = bytes.get(*off..*off + 32).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 32;
    let mut out = [0u8; 32];
    out.copy_from_slice(s);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circle_fri_roundtrip() {
        let proof = CircleFriProof {
            version: CIRCLE_FRI_PROOF_VERSION,
            log_domain_size: 3,
            layers: vec![CircleFriLayerProof {
                layer_root: [1u8; 32],
                next_root: [2u8; 32],
                queries: vec![CircleFriQuery {
                    position: 1,
                    position_neg: 5,
                    value: 0,
                    value_neg: 0,
                    next_value: 0,
                    proof: vec![[3u8; 32]],
                    proof_neg: vec![[4u8; 32]],
                    next_proof: vec![[5u8; 32]],
                }],
            }],
            final_value: 0,
        };
        let enc = proof.encode();
        let dec = match CircleFriProof::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(proof, dec);
    }
}
