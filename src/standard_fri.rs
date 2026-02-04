//! Standard FRI proof types and verifier (power-of-two domain).
use crate::circle_merkle;
use rayon::prelude::*;

pub const STANDARD_FRI_PROOF_TAG: &[u8] = b"STANDARD_FRI_PROOF";
pub const STANDARD_FRI_PROOF_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardFriQuery {
    pub position: u32,
    pub position_pair: u32,
    pub value: u32,
    pub value_pair: u32,
    pub next_value: u32,
    pub proof: Vec<[u8; 32]>,
    pub proof_pair: Vec<[u8; 32]>,
    pub next_proof: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardFriLayerProof {
    pub layer_root: [u8; 32],
    pub next_root: [u8; 32],
    pub queries: Vec<StandardFriQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardFriProof {
    pub version: u16,
    pub log_domain_size: u8,
    pub layers: Vec<StandardFriLayerProof>,
    pub final_value: u32,
}

impl StandardFriProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STANDARD_FRI_PROOF_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.log_domain_size);
        out.extend_from_slice(&(self.layers.len() as u16).to_be_bytes());
        for layer in &self.layers {
            out.extend_from_slice(&layer.layer_root);
            out.extend_from_slice(&layer.next_root);
            out.extend_from_slice(&(layer.queries.len() as u16).to_be_bytes());
            for q in &layer.queries {
                out.extend_from_slice(&q.position.to_be_bytes());
                out.extend_from_slice(&q.position_pair.to_be_bytes());
                out.extend_from_slice(&q.value.to_be_bytes());
                out.extend_from_slice(&q.value_pair.to_be_bytes());
                out.extend_from_slice(&q.next_value.to_be_bytes());
                encode_proof_vec(&mut out, &q.proof);
                encode_proof_vec(&mut out, &q.proof_pair);
                encode_proof_vec(&mut out, &q.next_proof);
            }
        }
        out.extend_from_slice(&self.final_value.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(STANDARD_FRI_PROOF_TAG) {
            return Err("standard fri proof tag mismatch".to_string());
        }
        let mut off = STANDARD_FRI_PROOF_TAG.len();
        let version = read_u16_be(bytes, &mut off)?;
        if version != STANDARD_FRI_PROOF_VERSION {
            return Err(format!("unsupported standard fri version={version}"));
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
                let position_pair = read_u32_be(bytes, &mut off)?;
                let value = read_u32_be(bytes, &mut off)?;
                let value_pair = read_u32_be(bytes, &mut off)?;
                let next_value = read_u32_be(bytes, &mut off)?;
                let proof = decode_proof_vec(bytes, &mut off)?;
                let proof_pair = decode_proof_vec(bytes, &mut off)?;
                let next_proof = decode_proof_vec(bytes, &mut off)?;
                queries.push(StandardFriQuery {
                    position,
                    position_pair,
                    value,
                    value_pair,
                    next_value,
                    proof,
                    proof_pair,
                    next_proof,
                });
            }
            layers.push(StandardFriLayerProof {
                layer_root,
                next_root,
                queries,
            });
        }
        let final_value = read_u32_be(bytes, &mut off)?;
        if off != bytes.len() {
            return Err("standard fri proof trailing data".to_string());
        }
        Ok(Self {
            version,
            log_domain_size,
            layers,
            final_value,
        })
    }
}

pub fn verify_standard_fri(
    proof: &StandardFriProof,
    expected_positions: &[u32],
    alphas: &[u32],
    hash_id: u8,
    add_mod: fn(u32, u32) -> u32,
    mul_mod: fn(u32, u32) -> u32,
) -> Result<(), String> {
    if proof.log_domain_size == 0 {
        return Err("standard fri log_domain_size must be > 0".to_string());
    }
    if proof.layers.len() != alphas.len() {
        return Err("standard fri alpha count mismatch".to_string());
    }
    if expected_positions.is_empty() {
        return Err("standard fri requires at least one query".to_string());
    }
    if proof.layers.len() != proof.log_domain_size as usize {
        return Err("standard fri layer count mismatch".to_string());
    }
    let mut domain_size = 1usize << proof.log_domain_size;
    for (layer_idx, layer) in proof.layers.iter().enumerate() {
        if layer.queries.len() != expected_positions.len() {
            return Err("standard fri query count mismatch".to_string());
        }
        let alpha = alphas[layer_idx];
        let half = domain_size / 2;
        if half == 0 {
            return Err("standard fri domain underflow".to_string());
        }
        if layer.queries.len() >= 128 && rayon::current_num_threads() > 1 {
            layer
                .queries
                .par_iter()
                .enumerate()
                .try_for_each(|(q_idx, q)| -> Result<(), String> {
                    let expected_pos = (expected_positions[q_idx] as usize) & (domain_size - 1);
                    let expected_pos = expected_pos as u32;
                    let expected_pair = (expected_pos as usize ^ half) as u32;
                    let expected_next = (expected_pos as usize & (half - 1)) as u32;
                    if q.position != expected_pos {
                        return Err("standard fri position mismatch".to_string());
                    }
                    if q.position_pair != expected_pair {
                        return Err("standard fri position_pair mismatch".to_string());
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
                        return Err("standard fri leaf proof failed".to_string());
                    }
                    let leaf_pair = circle_merkle::hash_leaf_with_hash_id(
                        hash_id,
                        q.position_pair,
                        &q.value_pair.to_be_bytes(),
                    )?;
                    if !circle_merkle::verify_with_hash_id(
                        &layer.layer_root,
                        &leaf_pair,
                        q.position_pair as usize,
                        &q.proof_pair,
                        hash_id,
                    )? {
                        return Err("standard fri pair leaf proof failed".to_string());
                    }
                    let folded = if (q.position as usize) < half {
                        add_mod(q.value, mul_mod(alpha, q.value_pair))
                    } else {
                        add_mod(q.value_pair, mul_mod(alpha, q.value))
                    };
                    if folded != q.next_value {
                        return Err("standard fri fold mismatch".to_string());
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
                        return Err("standard fri next proof failed".to_string());
                    }
                    if layer_idx == proof.layers.len().saturating_sub(1)
                        && q.next_value != proof.final_value
                    {
                        return Err("standard fri final value mismatch".to_string());
                    }
                    Ok(())
                })?;
        } else {
            for (q_idx, q) in layer.queries.iter().enumerate() {
                let expected_pos = (expected_positions[q_idx] as usize) & (domain_size - 1);
                let expected_pos = expected_pos as u32;
                let expected_pair = (expected_pos as usize ^ half) as u32;
                let expected_next = (expected_pos as usize & (half - 1)) as u32;
                if q.position != expected_pos {
                    return Err("standard fri position mismatch".to_string());
                }
                if q.position_pair != expected_pair {
                    return Err("standard fri position_pair mismatch".to_string());
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
                    return Err("standard fri leaf proof failed".to_string());
                }
                let leaf_pair = circle_merkle::hash_leaf_with_hash_id(
                    hash_id,
                    q.position_pair,
                    &q.value_pair.to_be_bytes(),
                )?;
                if !circle_merkle::verify_with_hash_id(
                    &layer.layer_root,
                    &leaf_pair,
                    q.position_pair as usize,
                    &q.proof_pair,
                    hash_id,
                )? {
                    return Err("standard fri pair leaf proof failed".to_string());
                }
                let folded = if (q.position as usize) < half {
                    add_mod(q.value, mul_mod(alpha, q.value_pair))
                } else {
                    add_mod(q.value_pair, mul_mod(alpha, q.value))
                };
                if folded != q.next_value {
                    return Err("standard fri fold mismatch".to_string());
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
                    return Err("standard fri next proof failed".to_string());
                }
                if layer_idx == proof.layers.len().saturating_sub(1)
                    && q.next_value != proof.final_value
                {
                    return Err("standard fri final value mismatch".to_string());
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
    fn test_standard_fri_roundtrip() {
        let proof = StandardFriProof {
            version: STANDARD_FRI_PROOF_VERSION,
            log_domain_size: 3,
            layers: vec![StandardFriLayerProof {
                layer_root: [1u8; 32],
                next_root: [2u8; 32],
                queries: vec![StandardFriQuery {
                    position: 1,
                    position_pair: 5,
                    value: 0,
                    value_pair: 0,
                    next_value: 0,
                    proof: vec![[3u8; 32]],
                    proof_pair: vec![[4u8; 32]],
                    next_proof: vec![[5u8; 32]],
                }],
            }],
            final_value: 0,
        };
        let enc = proof.encode();
        let dec = match StandardFriProof::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(proof, dec);
    }
}
