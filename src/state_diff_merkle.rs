use crate::adapters::keccak256;
use crate::glyph_field_simd::Goldilocks;
use crate::glyph_ir::{CustomGate, Ucir2, WRef, WitnessLayout, CUSTOM_GATE_KECCAK_MERGE, encode_three_wref_payload};
use crate::glyph_ir_compiler::{CompileContext, CompiledUcir, embed_fq_limbs};
use rayon::prelude::*;

const STATE_DIFF_SCHEMA_DOMAIN: &[u8] = b"GLYPH_STATE_DIFF_MERKLE_V1";

pub trait MerkleHasher: Sync {
    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
}

pub struct CpuKeccakHasher;

impl MerkleHasher for CpuKeccakHasher {
    fn hash_pair(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(left);
        input[32..].copy_from_slice(right);
        keccak256(&input)
    }
}

pub fn state_diff_schema_id() -> [u8; 32] {
    keccak256(STATE_DIFF_SCHEMA_DOMAIN)
}

pub fn state_diff_chunks(bytes: &[u8]) -> Vec<[u8; 32]> {
    if bytes.is_empty() {
        return vec![[0u8; 32]];
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks(32) {
        let mut block = [0u8; 32];
        block[..chunk.len()].copy_from_slice(chunk);
        out.push(block);
    }
    let target = out.len().next_power_of_two();
    while out.len() < target {
        out.push([0u8; 32]);
    }
    out
}

fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let start = i * 8;
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&bytes[start..start + 8]);
        *limb = u64::from_le_bytes(limb_bytes);
    }
    out
}

fn merkle_layers_with_hasher(
    mut leaves: Vec<[u8; 32]>,
    hasher: &dyn MerkleHasher,
) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        leaves.push([0u8; 32]);
    }
    let mut layers = Vec::new();
    layers.push(leaves);
    loop {
        let current = match layers.last() {
            Some(current) => current,
            None => break,
        };
        if current.len() <= 1 {
            break;
        }
        let next = if current.len() >= 1024 {
            current
                .par_chunks(2)
                .map(|pair| hasher.hash_pair(&pair[0], &pair[1]))
                .collect()
        } else {
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                next.push(hasher.hash_pair(&pair[0], &pair[1]));
            }
            next
        };
        layers.push(next);
    }
    layers
}

pub fn state_diff_merkle_root(bytes: &[u8]) -> ([u8; 32], Vec<[u8; 32]>) {
    let leaves = state_diff_chunks(bytes);
    let layers = merkle_layers_with_hasher(leaves.clone(), &CpuKeccakHasher);
    let root = layers
        .last()
        .and_then(|layer| layer.first().copied())
        .unwrap_or([0u8; 32]);
    (root, leaves)
}

pub fn state_diff_merkle_root_with_hasher(
    bytes: &[u8],
    hasher: &dyn MerkleHasher,
) -> ([u8; 32], Vec<[u8; 32]>) {
    let leaves = state_diff_chunks(bytes);
    let layers = merkle_layers_with_hasher(leaves.clone(), hasher);
    let root = layers
        .last()
        .and_then(|layer| layer.first().copied())
        .unwrap_or([0u8; 32]);
    (root, leaves)
}

pub fn compile_state_diff_merkle(bytes: &[u8]) -> CompiledUcir {
    let leaves = state_diff_chunks(bytes);
    let layers = merkle_layers_with_hasher(leaves.clone(), &CpuKeccakHasher);
    let root = layers
        .last()
        .and_then(|layer| layer.first().copied())
        .unwrap_or([0u8; 32]);

    let mut public_inputs = Vec::with_capacity(leaves.len() * 4 + 4);
    for leaf in &leaves {
        public_inputs.extend_from_slice(&embed_fq_limbs(leaf));
    }
    public_inputs.extend_from_slice(&embed_fq_limbs(&root));

    let mut ctx = CompileContext::new(public_inputs.len() as u32);
    let mut wire_values: Vec<Goldilocks> = Vec::new();

    let leaf_count = leaves.len();
    let root_start = WRef((leaf_count * 4) as u32);
    let mut level_refs: Vec<WRef> = (0..leaf_count)
        .map(|i| WRef((i * 4) as u32))
        .collect();

    if leaf_count == 1 {
        for i in 0u32..4 {
            ctx.copy(WRef(i), WRef(root_start.0 + i));
        }
    } else {
        for (level_idx, layer) in layers.iter().enumerate() {
            if layer.len() <= 1 {
                break;
            }
            let mut next_refs = Vec::with_capacity(layer.len() / 2);
            for pair_idx in 0..layer.len() / 2 {
                let left_ref = level_refs[pair_idx * 2];
                let right_ref = level_refs[pair_idx * 2 + 1];
                let out_bytes = layers[level_idx + 1][pair_idx];
                let out_ref = if level_idx + 1 == layers.len() - 1 {
                    root_start
                } else {
                    ctx.alloc_fq_limbs(&mut wire_values, bytes_to_limbs(&out_bytes))
                };
                let payload = encode_three_wref_payload(left_ref, right_ref, out_ref);
                ctx.ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_KECCAK_MERGE, payload));
                next_refs.push(out_ref);
            }
            level_refs = next_refs;
        }
    }

    let mut ucir: Ucir2 = ctx.finalize();
    ucir.witness_layout = WitnessLayout::fast_mode(
        public_inputs.len() as u32,
        wire_values.len() as u32,
        0,
    );

    CompiledUcir {
        ucir,
        public_inputs,
        wire_values,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_pad_to_power_of_two() {
        let bytes = vec![1u8; 33];
        let chunks = state_diff_chunks(&bytes);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0][0], 1);
        assert_eq!(chunks[1][0], 1);
    }

    #[test]
    fn empty_bytes_root_is_zero_leaf() {
        let (root, leaves) = state_diff_merkle_root(&[]);
        assert_eq!(leaves.len(), 1);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn merkle_root_matches_single_pair() {
        let mut bytes = vec![0u8; 64];
        bytes[0] = 1;
        bytes[63] = 2;
        let (root, leaves) = state_diff_merkle_root(&bytes);
        assert_eq!(leaves.len(), 2);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&leaves[0]);
        input[32..].copy_from_slice(&leaves[1]);
        let expected = keccak256(&input);
        assert_eq!(root, expected);
    }
}
