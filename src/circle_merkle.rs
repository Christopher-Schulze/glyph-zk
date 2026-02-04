//! Circle STARK Merkle hashing and proof verification.
//!
//! Uses domain-separated hashing for leaf and node hashing.

use crate::stark_hash::{ensure_hash_id, hash_domain, HASH_SHA3_ID};
use rayon::prelude::*;

pub const CIRCLE_MERKLE_LEAF_DOMAIN: &[u8] = b"GLYPH_CIRCLE_MERKLE_LEAF";
pub const CIRCLE_MERKLE_NODE_DOMAIN: &[u8] = b"GLYPH_CIRCLE_MERKLE_NODE";

pub fn hash_leaf_with_hash_id(hash_id: u8, index: u32, data: &[u8]) -> Result<[u8; 32], String> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&index.to_be_bytes());
    buf.extend_from_slice(data);
    hash_domain(hash_id, CIRCLE_MERKLE_LEAF_DOMAIN, &buf)
}

pub fn hash_node_with_hash_id(
    hash_id: u8,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], String> {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    hash_domain(hash_id, CIRCLE_MERKLE_NODE_DOMAIN, &buf)
}

pub fn hash_leaf(index: u32, data: &[u8]) -> [u8; 32] {
    match hash_leaf_with_hash_id(HASH_SHA3_ID, index, data) {
        Ok(hash) => hash,
        Err(err) => {
            debug_assert!(false, "sha3 merkle hash failed: {err}");
            [0u8; 32]
        }
    }
}

pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    match hash_node_with_hash_id(HASH_SHA3_ID, left, right) {
        Ok(hash) => hash,
        Err(err) => {
            debug_assert!(false, "sha3 merkle node hash failed: {err}");
            [0u8; 32]
        }
    }
}

pub fn verify_with_hash_id(
    root: &[u8; 32],
    leaf: &[u8; 32],
    mut idx: usize,
    proof: &[[u8; 32]],
    hash_id: u8,
) -> Result<bool, String> {
    let mut current = *leaf;
    for sibling in proof {
        let mut left = current;
        let mut right = *sibling;
        if idx & 1 == 1 {
            std::mem::swap(&mut left, &mut right);
        }
        current = hash_node_with_hash_id(hash_id, &left, &right)?;
        idx >>= 1;
    }
    Ok(&current == root)
}

pub fn verify(root: &[u8; 32], leaf: &[u8; 32], idx: usize, proof: &[[u8; 32]]) -> bool {
    verify_with_hash_id(root, leaf, idx, proof, HASH_SHA3_ID)
        .unwrap_or(false)
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn build_with_hash_id(hash_id: u8, mut leaves: Vec<[u8; 32]>) -> Result<Self, String> {
        ensure_hash_id(hash_id)?;
        if leaves.is_empty() {
            return Ok(Self {
                layers: vec![vec![[0u8; 32]]],
            });
        }
        let target = leaves.len().next_power_of_two();
        while leaves.len() < target {
            leaves.push([0u8; 32]);
        }
        let mut layers = Vec::new();
        layers.push(leaves);
        while layers.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let prev = match layers.last() {
                Some(prev) => prev,
                None => break,
            };
            let next = if prev.len() >= 2048 && rayon::current_num_threads() > 1 {
                prev.par_chunks(2)
                    .map(|pair| hash_node_with_hash_id(hash_id, &pair[0], &pair[1]))
                    .collect::<Result<Vec<_>, String>>()?
            } else {
                let mut next = Vec::with_capacity(prev.len() / 2);
                for i in (0..prev.len()).step_by(2) {
                    next.push(hash_node_with_hash_id(hash_id, &prev[i], &prev[i + 1])?);
                }
                next
            };
            layers.push(next);
        }
        Ok(Self { layers })
    }

    pub fn build(leaves: Vec<[u8; 32]>) -> Self {
        match Self::build_with_hash_id(HASH_SHA3_ID, leaves) {
            Ok(tree) => tree,
            Err(err) => {
                debug_assert!(false, "sha3 merkle build failed: {err}");
                Self {
                    layers: vec![vec![[0u8; 32]]],
                }
            }
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn proof(&self, mut idx: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        for layer in &self.layers[..self.layers.len().saturating_sub(1)] {
            let sibling = if idx & 1 == 0 { idx + 1 } else { idx - 1 };
            if sibling < layer.len() {
                proof.push(layer[sibling]);
            }
            idx >>= 1;
        }
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stark_hash::{HASH_BLAKE3_ID, HASH_POSEIDON_ID, HASH_RESCUE_ID};

    #[test]
    fn test_circle_merkle_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0u32..8u32)
            .map(|i| hash_leaf(i, &i.to_be_bytes()))
            .collect();
        let tree = MerkleTree::build(leaves.clone());
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(idx);
            assert!(verify(&tree.root(), leaf, idx, &proof));
        }
    }

    #[test]
    fn test_circle_merkle_roundtrip_blake3() -> Result<(), String> {
        let mut leaves = Vec::new();
        for i in 0u32..8u32 {
            leaves.push(hash_leaf_with_hash_id(HASH_BLAKE3_ID, i, &i.to_be_bytes())?);
        }
        let tree = MerkleTree::build_with_hash_id(HASH_BLAKE3_ID, leaves.clone())?;
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(idx);
            let ok = verify_with_hash_id(&tree.root(), leaf, idx, &proof, HASH_BLAKE3_ID)?;
            assert!(ok);
        }
        Ok(())
    }

    #[test]
    fn test_circle_merkle_roundtrip_poseidon() -> Result<(), String> {
        let mut leaves = Vec::new();
        for i in 0u32..8u32 {
            leaves.push(
                hash_leaf_with_hash_id(HASH_POSEIDON_ID, i, &i.to_be_bytes())?,
            );
        }
        let tree = MerkleTree::build_with_hash_id(HASH_POSEIDON_ID, leaves.clone())?;
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(idx);
            let ok = verify_with_hash_id(&tree.root(), leaf, idx, &proof, HASH_POSEIDON_ID)?;
            assert!(ok);
        }
        Ok(())
    }

    #[test]
    fn test_circle_merkle_roundtrip_rescue() -> Result<(), String> {
        let mut leaves = Vec::new();
        for i in 0u32..8u32 {
            leaves.push(
                hash_leaf_with_hash_id(HASH_RESCUE_ID, i, &i.to_be_bytes())?,
            );
        }
        let tree = MerkleTree::build_with_hash_id(HASH_RESCUE_ID, leaves.clone())?;
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(idx);
            let ok = verify_with_hash_id(&tree.root(), leaf, idx, &proof, HASH_RESCUE_ID)?;
            assert!(ok);
        }
        Ok(())
    }
}
