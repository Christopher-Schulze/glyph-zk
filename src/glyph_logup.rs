//! Grand Product LogUp: Lookup argument via GKR.
//!
//! Implements LogUp per Prover-Blueprint.md Section 7.
//! Proves multiset membership without inversions using product trees.

use crate::glyph_field_simd::{
    Goldilocks,
    ensure_two_thread_pool,
    cuda_pairwise_product,
    goldilocks_mul_batch_into,
    goldilocks_sub_batch_into,
    with_goldilocks_scratch,
    with_goldilocks_scratch_pair,
};
use crate::glyph_transcript::{Transcript, DOMAIN_LOOKUP};
use rayon::prelude::*;
use std::env;
use crate::glyph_ir::{Ucir2, TABLE_BIT, TABLE_RANGE8, TABLE_RANGE16};
use crate::glyph_witness::WitnessBuffer;

// ============================================================
//                    PRODUCT TREE (Blueprint 7.1)
// ============================================================

/// Binary product tree for LogUp
#[derive(Clone, Debug)]
pub struct ProductTree {
    /// Flattened levels of the tree (level 0 = leaves, last = root)
    pub flat: Vec<Goldilocks>,
    /// Offset per level into flat buffer
    pub level_offsets: Vec<usize>,
    /// Size per level
    pub level_sizes: Vec<usize>,
    /// Root product
    pub root: Goldilocks,
}

impl ProductTree {
    fn level_slice(&self, idx: usize) -> &[Goldilocks] {
        let start = self.level_offsets[idx];
        let end = start + self.level_sizes[idx];
        &self.flat[start..end]
    }

    /// Build product tree from leaf values
    /// Per Blueprint 7.1: L_{k+1}[i] = L_k[2i] * L_k[2i+1]
    pub fn build(leaves: Vec<Goldilocks>) -> Self {
        ensure_two_thread_pool();
        if leaves.is_empty() {
            return Self {
                flat: vec![],
                level_offsets: vec![0],
                level_sizes: vec![0],
                root: Goldilocks::ONE,
            };
        }

        // Pad to power of two with 1s
        let mut padded = leaves;
        let n = padded.len().next_power_of_two();
        while padded.len() < n {
            padded.push(Goldilocks::ONE);
        }

        let mut flat = Vec::new();
        let mut level_offsets = Vec::new();
        let mut level_sizes = Vec::new();

        let mut current = padded;
        level_offsets.push(0);
        level_sizes.push(current.len());
        flat.extend_from_slice(&current);

        while current.len() > 1 {
            let next = if current.len() / 2 >= 1 {
                let pairs = current.len() / 2;
                let mut out = vec![Goldilocks::ZERO; pairs];
                if cuda_pairwise_product(&current, &mut out) {
                    out
                } else if pairs >= 2048 {
                    ensure_two_thread_pool();
                    let chunk = 512usize;
                    out.par_chunks_mut(chunk)
                        .enumerate()
                        .for_each(|(chunk_idx, out_chunk)| {
                            let start = chunk_idx * chunk;
                            let end = (start + out_chunk.len()).min(pairs);
                            let len = end - start;
                            with_goldilocks_scratch_pair(len, |left, right| {
                                for i in 0..len {
                                    let base = 2 * (start + i);
                                    left[i] = current[base];
                                    right[i] = current[base + 1];
                                }
                                goldilocks_mul_batch_into(left, right, out_chunk);
                            });
                        });
                    out
                } else if pairs >= 64 {
                    ensure_two_thread_pool();
                    let chunk = 512usize;
                    let mut left = vec![Goldilocks::ZERO; chunk];
                    let mut right = vec![Goldilocks::ZERO; chunk];
                    let chunks = pairs.div_ceil(chunk);
                    for c in 0..chunks {
                        let start = c * chunk;
                        let end = (start + chunk).min(pairs);
                        let len = end - start;
                        for i in 0..len {
                            let base = 2 * (start + i);
                            left[i] = current[base];
                            right[i] = current[base + 1];
                        }
                        goldilocks_mul_batch_into(&left[..len], &right[..len], &mut out[start..end]);
                    }
                    out
                } else {
                    current
                        .par_chunks(2)
                        .map(|pair| pair[0] * pair[1])
                        .collect()
                }
            } else {
                Vec::new()
            };
            level_offsets.push(flat.len());
            level_sizes.push(next.len());
            flat.extend_from_slice(&next);
            current = next;
        }

        let root = current[0];
        Self { flat, level_offsets, level_sizes, root }
    }

    /// Get witness values for all internal nodes
    pub fn all_witnesses(&self) -> Vec<Goldilocks> {
        self.flat.clone()
    }

    /// Number of multiplication gates
    pub fn gate_count(&self) -> usize {
        self.level_sizes.iter().skip(1).sum()
    }
}

// ============================================================
//                    LOGUP PROOF (Blueprint 7)
// ============================================================

/// LogUp proof for multiset membership across multiple tables
#[derive(Clone, Debug)]
pub struct LogUpProof {
    pub tables: Vec<TableLogUpProof>,
}

/// Per-table LogUp proof
#[derive(Clone, Debug)]
pub struct TableLogUpProof {
    pub table_id: u32,
    pub beta: Goldilocks,
    pub a_tree: ProductTree,
    pub b_tree: ProductTree,
}

fn logup_par_min() -> usize {
    env::var("GLYPH_LOGUP_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2048)
}

#[inline]
fn pow_multiplicity(base: Goldilocks, m: u64) -> Goldilocks {
    match m {
        0 => Goldilocks::ONE,
        1 => base,
        2 => base.square(),
        3 => base.square() * base,
        _ => base.pow(m),
    }
}

/// Build LogUp proof across all referenced tables.
/// Per Blueprint 7: Π (beta - v_i) = Π (beta - t_j)^{m_j}
pub fn prove_logup(ucir: &Ucir2, witness: &WitnessBuffer, transcript: &mut Transcript) -> LogUpProof {
    ensure_two_thread_pool();
    let mut table_proofs = Vec::new();
    let mut table_indices = std::collections::HashMap::with_capacity(ucir.tables.len());
    for (idx, table) in ucir.tables.iter().enumerate() {
        table_indices.insert(table.table_id, idx);
    }

    // Group lookups per table
    let mut lookups_by_table: std::collections::BTreeMap<u32, Vec<Goldilocks>> = std::collections::BTreeMap::new();
    for lookup in &ucir.lookups {
        let v = witness.get(lookup.value);
        lookups_by_table.entry(lookup.table_id).or_default().push(v);
    }

    for (table_id, lookup_values) in lookups_by_table {
        let table_idx = match table_indices.get(&table_id) {
            Some(idx) => *idx,
            None => {
                transcript.absorb(DOMAIN_LOOKUP, &table_id.to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, &(0u64).to_le_bytes());
                transcript.absorb_goldilocks_vec(DOMAIN_LOOKUP, &lookup_values);
                let beta = transcript.challenge_goldilocks();

                let a_leaves: Vec<Goldilocks> = if lookup_values.len() >= logup_par_min()
                    && rayon::current_num_threads() > 1
                {
                    lookup_values.par_iter().map(|v| beta - *v).collect()
                } else {
                    lookup_values.iter().map(|v| beta - *v).collect()
                };
                let a_tree = ProductTree::build(a_leaves);
                let b_tree = ProductTree::build(vec![a_tree.root + Goldilocks::ONE]);

                table_proofs.push(TableLogUpProof {
                    table_id,
                    beta,
                    a_tree,
                    b_tree,
                });
                continue;
            }
        };
        let table = &ucir.tables[table_idx];

        if table_id == TABLE_BIT {
            if table.width != 1
                || table.values.len() != 2
                || table.values[0] != Goldilocks::ZERO
                || table.values[1] != Goldilocks::ONE
            {
                transcript.absorb(DOMAIN_LOOKUP, &table_id.to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, &(table.values.len() as u64).to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, b"STD_TABLE");
                transcript.absorb(DOMAIN_LOOKUP, &table.width.to_le_bytes());
                transcript.absorb_goldilocks_vec(DOMAIN_LOOKUP, &lookup_values);
                let beta = transcript.challenge_goldilocks();

                let a_leaves: Vec<Goldilocks> = if lookup_values.len() >= logup_par_min()
                    && rayon::current_num_threads() > 1
                {
                    lookup_values.par_iter().map(|v| beta - *v).collect()
                } else {
                    lookup_values.iter().map(|v| beta - *v).collect()
                };
                let a_tree = ProductTree::build(a_leaves);
                let b_tree = ProductTree::build(vec![a_tree.root + Goldilocks::ONE]);

                table_proofs.push(TableLogUpProof {
                    table_id,
                    beta,
                    a_tree,
                    b_tree,
                });
                continue;
            }
        } else if table_id == TABLE_RANGE8 {
            let mut ok = table.width == 1 && table.values.len() == 256;
            if ok {
                for (i, v) in table.values.iter().enumerate() {
                    if v.0 != i as u64 {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                transcript.absorb(DOMAIN_LOOKUP, &table_id.to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, &(table.values.len() as u64).to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, b"STD_TABLE");
                transcript.absorb(DOMAIN_LOOKUP, &table.width.to_le_bytes());
                transcript.absorb_goldilocks_vec(DOMAIN_LOOKUP, &lookup_values);
                let beta = transcript.challenge_goldilocks();

                let a_leaves: Vec<Goldilocks> = if lookup_values.len() >= logup_par_min()
                    && rayon::current_num_threads() > 1
                {
                    lookup_values.par_iter().map(|v| beta - *v).collect()
                } else {
                    lookup_values.iter().map(|v| beta - *v).collect()
                };
                let a_tree = ProductTree::build(a_leaves);
                let b_tree = ProductTree::build(vec![a_tree.root + Goldilocks::ONE]);

                table_proofs.push(TableLogUpProof {
                    table_id,
                    beta,
                    a_tree,
                    b_tree,
                });
                continue;
            }
        } else if table_id == TABLE_RANGE16 {
            let mut ok = table.width == 1 && table.values.len() == 65536;
            if ok {
                for (i, v) in table.values.iter().enumerate() {
                    if v.0 != i as u64 {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                transcript.absorb(DOMAIN_LOOKUP, &table_id.to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, &(table.values.len() as u64).to_le_bytes());
                transcript.absorb(DOMAIN_LOOKUP, b"STD_TABLE");
                transcript.absorb(DOMAIN_LOOKUP, &table.width.to_le_bytes());
                transcript.absorb_goldilocks_vec(DOMAIN_LOOKUP, &lookup_values);
                let beta = transcript.challenge_goldilocks();

                let a_leaves: Vec<Goldilocks> = if lookup_values.len() >= logup_par_min()
                    && rayon::current_num_threads() > 1
                {
                    lookup_values.par_iter().map(|v| beta - *v).collect()
                } else {
                    lookup_values.iter().map(|v| beta - *v).collect()
                };
                let a_tree = ProductTree::build(a_leaves);
                let b_tree = ProductTree::build(vec![a_tree.root + Goldilocks::ONE]);

                table_proofs.push(TableLogUpProof {
                    table_id,
                    beta,
                    a_tree,
                    b_tree,
                });
                continue;
            }
        }

        let counts_owned;
        let multiplicities = match witness.table_multiplicities.get(table_idx) {
            Some(m) if m.table_id == table_id && m.counts.len() == table.values.len() => &m.counts,
            _ => {
                let mut counts = vec![0u64; table.values.len()];
                match table_id {
                    TABLE_BIT => {
                        if lookup_values.len() >= logup_par_min()
                            && rayon::current_num_threads() > 1
                        {
                            let locals: Vec<[u64; 2]> = lookup_values
                                .par_chunks(4096)
                                .map(|chunk| {
                                    let mut local = [0u64; 2];
                                    for v in chunk {
                                        if v.0 <= 1 {
                                            local[v.0 as usize] = local[v.0 as usize].saturating_add(1);
                                        }
                                    }
                                    local
                                })
                                .collect();
                            for local in locals {
                                counts[0] = counts[0].saturating_add(local[0]);
                                counts[1] = counts[1].saturating_add(local[1]);
                            }
                        } else {
                            for v in &lookup_values {
                                if v.0 <= 1 {
                                    counts[v.0 as usize] = counts[v.0 as usize].saturating_add(1);
                                }
                            }
                        }
                    }
                    TABLE_RANGE8 => {
                        if lookup_values.len() >= logup_par_min()
                            && rayon::current_num_threads() > 1
                        {
                            let locals: Vec<Vec<u64>> = lookup_values
                                .par_chunks(4096)
                                .map(|chunk| {
                                    let mut local = vec![0u64; 256];
                                    for v in chunk {
                                        if v.0 < 256 {
                                            local[v.0 as usize] = local[v.0 as usize].saturating_add(1);
                                        }
                                    }
                                    local
                                })
                                .collect();
                            for local in locals {
                                for (dst, src) in counts.iter_mut().zip(local.into_iter()) {
                                    *dst = dst.saturating_add(src);
                                }
                            }
                        } else {
                            for v in &lookup_values {
                                if v.0 < 256 {
                                    counts[v.0 as usize] = counts[v.0 as usize].saturating_add(1);
                                }
                            }
                        }
                    }
                    TABLE_RANGE16 => {
                        if lookup_values.len() >= logup_par_min()
                            && rayon::current_num_threads() > 1
                        {
                            let locals: Vec<Vec<u64>> = lookup_values
                                .par_chunks(4096)
                                .map(|chunk| {
                                    let mut local = vec![0u64; 65536];
                                    for v in chunk {
                                        if v.0 < 65536 {
                                            local[v.0 as usize] = local[v.0 as usize].saturating_add(1);
                                        }
                                    }
                                    local
                                })
                                .collect();
                            for local in locals {
                                for (dst, src) in counts.iter_mut().zip(local.into_iter()) {
                                    *dst = dst.saturating_add(src);
                                }
                            }
                        } else {
                            for v in &lookup_values {
                                if v.0 < 65536 {
                                    counts[v.0 as usize] = counts[v.0 as usize].saturating_add(1);
                                }
                            }
                        }
                    }
                    _ => {
                        let mut idx_map = std::collections::HashMap::new();
                        for (i, v) in table.values.iter().enumerate() {
                            idx_map.insert(*v, i);
                        }
                        if lookup_values.len() >= logup_par_min()
                            && rayon::current_num_threads() > 1
                        {
                            let locals: Vec<Vec<u64>> = lookup_values
                                .par_chunks(4096)
                                .map(|chunk| {
                                    let mut local = vec![0u64; table.values.len()];
                                    for v in chunk {
                                        if let Some(idx) = idx_map.get(v) {
                                            local[*idx] = local[*idx].saturating_add(1);
                                        }
                                    }
                                    local
                                })
                                .collect();
                            for local in locals {
                                for (dst, src) in counts.iter_mut().zip(local.into_iter()) {
                                    *dst = dst.saturating_add(src);
                                }
                            }
                        } else {
                            for v in &lookup_values {
                                if let Some(idx) = idx_map.get(v) {
                                    counts[*idx] = counts[*idx].saturating_add(1);
                                }
                            }
                        }
                    }
                }
                counts_owned = counts;
                &counts_owned
            }
        };

        // Absorb lookup and table info (bind table identity and shape)
        transcript.absorb(DOMAIN_LOOKUP, &table_id.to_le_bytes());
        transcript.absorb(DOMAIN_LOOKUP, &(table.values.len() as u64).to_le_bytes());
        if table_id == TABLE_BIT || table_id == TABLE_RANGE8 || table_id == TABLE_RANGE16 {
            transcript.absorb(DOMAIN_LOOKUP, b"STD_TABLE");
            transcript.absorb(DOMAIN_LOOKUP, &table.width.to_le_bytes());
        }
        transcript.absorb_goldilocks_vec(DOMAIN_LOOKUP, &lookup_values);
        if table_id != TABLE_BIT && table_id != TABLE_RANGE8 && table_id != TABLE_RANGE16 {
            transcript.absorb_goldilocks_vec(DOMAIN_LOOKUP, &table.values);
        }

        // Derive beta challenge
        let beta = transcript.challenge_goldilocks();

        // Build A: leaves = [beta - v_i]
        let a_leaves: Vec<Goldilocks> = if lookup_values.len() >= logup_par_min()
            && rayon::current_num_threads() > 1
        {
            lookup_values.par_iter().map(|v| beta - *v).collect()
        } else {
            lookup_values.iter().map(|v| beta - *v).collect()
        };
        let a_tree = ProductTree::build(a_leaves);

        // Build B: leaves = [(beta - t_j)^{m_j}] for m_j > 0 only.
        // Zero multiplicities contribute a factor of 1 and can be omitted.
        let b_leaves: Vec<Goldilocks> = if table.values.len() >= logup_par_min()
            && rayon::current_num_threads() > 1
        {
            table
                .values
                .par_iter()
                .zip(multiplicities.par_iter())
                .filter_map(|(t, m)| {
                    if *m == 0 {
                        None
                    } else {
                        Some(pow_multiplicity(beta - *t, *m))
                    }
                })
                .collect()
        } else {
            let mut out = Vec::new();
            for (t, &m) in table.values.iter().zip(multiplicities.iter()) {
                if m == 0 {
                    continue;
                }
                let base = beta - *t;
                out.push(pow_multiplicity(base, m));
            }
            out
        };
        let b_tree = ProductTree::build(b_leaves);

        table_proofs.push(TableLogUpProof {
            table_id,
            beta,
            a_tree,
            b_tree,
        });
    }

    LogUpProof { tables: table_proofs }
}

/// Verify LogUp proof (roots must be equal)
pub fn verify_logup(proof: &LogUpProof) -> bool {
    proof.tables.iter().all(|t| t.a_tree.root == t.b_tree.root)
}

// ============================================================
//                    GKR INTEGRATION (Blueprint 7.3)
// ============================================================

/// Generate constraints for product tree verification
/// Each internal node: node = left * right
pub fn product_tree_constraints(tree: &ProductTree) -> Vec<(usize, usize, usize)> {
    let mut constraints = Vec::new();
    let mut offset = 0;

    for level_idx in 0..tree.level_sizes.len() - 1 {
        let level = tree.level_slice(level_idx);
        let next_level = tree.level_slice(level_idx + 1);

        for i in 0..next_level.len() {
            let left_idx = offset + 2 * i;
            let right_idx = offset + 2 * i + 1;
            let out_idx = offset + level.len() + i;
            constraints.push((left_idx, right_idx, out_idx));
        }

        offset += level.len();
    }

    constraints
}

/// Evaluate product tree constraints (left * right - parent) for sumcheck inclusion
pub fn product_tree_constraint_evals(tree: &ProductTree) -> Vec<Goldilocks> {
    let mut evals = Vec::new();
    for level_idx in 0..tree.level_sizes.len().saturating_sub(1) {
        let level = tree.level_slice(level_idx);
        let next = tree.level_slice(level_idx + 1);
        let pairs = next.len();
        if pairs >= 2048 {
            ensure_two_thread_pool();
            let chunk = 512usize;
            let mut level_evals = vec![Goldilocks::ZERO; pairs];
            level_evals
                .par_chunks_mut(chunk)
                .enumerate()
                .for_each(|(chunk_idx, out_chunk)| {
                    let start = chunk_idx * chunk;
                    let end = (start + out_chunk.len()).min(pairs);
                    let len = end - start;
                    with_goldilocks_scratch_pair(len, |left, right| {
                        with_goldilocks_scratch(len, |tmp| {
                            for i in 0..len {
                                let base = 2 * (start + i);
                                left[i] = level[base];
                                right[i] = level[base + 1];
                            }
                            goldilocks_mul_batch_into(left, right, tmp);
                            goldilocks_sub_batch_into(tmp, &next[start..end], out_chunk);
                        });
                    });
                });
            evals.extend_from_slice(&level_evals);
        } else if pairs >= 64 {
            let mut level_evals = vec![Goldilocks::ZERO; pairs];
            with_goldilocks_scratch_pair(pairs, |left, right| {
                with_goldilocks_scratch(pairs, |tmp| {
                    for i in 0..pairs {
                        let base = 2 * i;
                        left[i] = level[base];
                        right[i] = level[base + 1];
                    }
                    goldilocks_mul_batch_into(left, right, tmp);
                    goldilocks_sub_batch_into(tmp, next, &mut level_evals);
                });
            });
            evals.extend_from_slice(&level_evals);
        } else {
            for i in 0..pairs {
                let left = level[2 * i];
                let right = level[2 * i + 1];
                let parent = next[i];
                evals.push(left * right - parent);
            }
        }
    }
    evals
}

/// Collect all LogUp constraint evaluations for sumcheck
pub fn logup_constraint_evals(proof: &LogUpProof) -> Vec<Goldilocks> {
    let mut out = Vec::new();
    for table in &proof.tables {
        out.extend(product_tree_constraint_evals(&table.a_tree));
        out.extend(product_tree_constraint_evals(&table.b_tree));
        out.push(table.a_tree.root - table.b_tree.root);
    }
    out
}

pub fn logup_constraint_evals_into(proof: &LogUpProof, out: &mut Vec<Goldilocks>) {
    for table in &proof.tables {
        out.extend(product_tree_constraint_evals(&table.a_tree));
        out.extend(product_tree_constraint_evals(&table.b_tree));
        out.push(table.a_tree.root - table.b_tree.root);
    }
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glyph_ir::{Ucir2, WRef, Table, TABLE_BIT};
    use crate::glyph_witness::WitnessBuffer;

    #[test]
    fn test_product_tree_basic() {
        let leaves = vec![
            Goldilocks(2),
            Goldilocks(3),
            Goldilocks(5),
            Goldilocks(7),
        ];
        let tree = ProductTree::build(leaves);

        // 2*3=6, 5*7=35, 6*35=210
        assert_eq!(tree.root, Goldilocks(210));
        assert_eq!(tree.level_sizes.len(), 3);

        println!("Product tree basic test passed.");
    }

    #[test]
    fn test_product_tree_padding() {
        let leaves = vec![Goldilocks(2), Goldilocks(3), Goldilocks(5)];
        let tree = ProductTree::build(leaves);

        // Padded to [2, 3, 5, 1]
        // 2*3=6, 5*1=5, 6*5=30
        assert_eq!(tree.root, Goldilocks(30));

        println!("Product tree padding test passed.");
    }

    #[test]
    fn test_logup_valid() {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = crate::glyph_ir::WitnessLayout::fast_mode(0, 3, 3);
        ucir.add_table(Table::bit());
        ucir.add_lookup(WRef(0), TABLE_BIT);
        ucir.add_lookup(WRef(1), TABLE_BIT);
        ucir.add_lookup(WRef(2), TABLE_BIT);

        let mut witness = WitnessBuffer::new(ucir.witness_layout.clone());
        witness.set(WRef(0), Goldilocks::ZERO);
        witness.set(WRef(1), Goldilocks::ONE);
        witness.set(WRef(2), Goldilocks::ONE);

        let mut transcript = Transcript::new();
        let proof = prove_logup(&ucir, &witness, &mut transcript);

        assert!(verify_logup(&proof), "LogUp verification should pass");

        println!("LogUp valid test passed.");
    }

    #[test]
    fn test_logup_invalid() {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = crate::glyph_ir::WitnessLayout::fast_mode(0, 3, 3);
        ucir.add_table(Table::bit());
        ucir.add_lookup(WRef(0), TABLE_BIT);
        ucir.add_lookup(WRef(1), TABLE_BIT);
        ucir.add_lookup(WRef(2), TABLE_BIT);

        let mut witness = WitnessBuffer::new(ucir.witness_layout.clone());
        witness.set(WRef(0), Goldilocks::ZERO);
        witness.set(WRef(1), Goldilocks::ONE);
        witness.set(WRef(2), Goldilocks(2));

        let mut transcript = Transcript::new();
        let proof = prove_logup(&ucir, &witness, &mut transcript);

        assert!(!verify_logup(&proof), "LogUp verification should fail for invalid value");

        println!("LogUp invalid test passed.");
    }

    #[test]
    fn test_product_tree_constraints() {
        let leaves = vec![Goldilocks(2), Goldilocks(3), Goldilocks(5), Goldilocks(7)];
        let tree = ProductTree::build(leaves);

        let constraints = product_tree_constraints(&tree);
        assert_eq!(constraints.len(), 3); // 2 at level 1, 1 at level 2

        println!("Product tree constraints test passed.");
    }

    #[test]
    fn test_logup_b_tree_is_sparse_on_nonzero_multiplicities() {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = crate::glyph_ir::WitnessLayout::fast_mode(0, 3, 3);
        ucir.add_table(Table::bit());
        ucir.add_lookup(WRef(0), TABLE_BIT);
        ucir.add_lookup(WRef(1), TABLE_BIT);
        ucir.add_lookup(WRef(2), TABLE_BIT);

        let mut witness = WitnessBuffer::new(ucir.witness_layout.clone());
        witness.set(WRef(0), Goldilocks::ZERO);
        witness.set(WRef(1), Goldilocks::ONE);
        witness.set(WRef(2), Goldilocks::ONE);

        let mut transcript = Transcript::new();
        let proof = prove_logup(&ucir, &witness, &mut transcript);
        assert_eq!(proof.tables.len(), 1);
        let t = &proof.tables[0];
        assert_eq!(t.table_id, TABLE_BIT);

        // Multiplicities are {0:1, 1:2} => two non-zero entries.
        assert_eq!(t.b_tree.level_sizes.first().copied().unwrap_or(0), 2);
    }
}
