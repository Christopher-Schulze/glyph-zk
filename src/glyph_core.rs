//! GLYPH-PROVER Core: Universal Prover Entry Point.
//!
//! Implements the main prover pipeline
//! Integrates all components: UCIR, witness stream, LogUp, PCS, and packed GKR.

mod sumcheck;
mod types;
pub use types::{
    GlyphArtifact,
    ProverConfig,
    ProverError,
    ProverMode,
    SumcheckRound,
    UniversalProof,
};

use crate::glyph_field_simd::{
    Goldilocks,
    goldilocks_sum,
    goldilocks_sum_strided,
    goldilocks_add_batch_into,
    goldilocks_scalar_mul_batch_into,
    prefetch_read,
    ensure_two_thread_pool,
    cuda_sumcheck_even_odd,
    cuda_sumcheck_next_layer,
};
use crate::arena::Arena;
use crate::glyph_transcript::{Transcript, DOMAIN_SUMCHECK, DOMAIN_SUMCHECK_MIX};
use tiny_keccak::Hasher;
use crate::glyph_ir::Ucir2;
use crate::glyph_pcs_basefold::{
    PcsProver, commit_zk_owned, absorb_opening,
    verify_opening, eval_point_from_sumcheck_challenges, basefold_zk_shape_for_len,
};
use crate::pcs_common::{derive_point_tag, ZkPcsConfig};
use crate::glyph_logup::{prove_logup, logup_constraint_evals_into};
use crate::glyph_witness::WitnessStream;
use crate::glyph_gkr::{
    gkr_canonicalize_u128,
    gkr_u128_to_bytes32_be,
    prove_packed_artifact_poly_sumcheck,
    encode_artifact_poly_bound_packed_calldata_be,
};
use crate::glyph_ir_compiler::CompiledUcir;
use rayon::prelude::*;
use rand::{SeedableRng, rngs::StdRng};
use sumcheck::{
    GOLDILOCKS_TWO,
    GOLDILOCKS_THREE,
    PagedLayer,
    SUMCHECK_PAGE_SIZE,
    interpolate_cubic_from_values,
    mix_evals_in_place,
    sample_nonzero_goldilocks,
    sum_paged,
    sum_scalar,
};

/// Main universal prover entry point
pub fn prove_universal(
    ucir: Ucir2,
    public_inputs: &[Goldilocks],
    wire_values: Option<&[Goldilocks]>,
    config: ProverConfig,
) -> Result<UniversalProof, ProverError> {
    ensure_two_thread_pool();
    if let Err(err) = crate::perf_config::init_once() {
        return Err(ProverError::InvalidInput {
            message: format!("perf config invalid: {err}"),
        });
    }
    let mut transcript = Transcript::new();
    let mut zk_rng = if config.mode == ProverMode::ZkMode {
        Some(match config.zk_seed {
            Some(seed) => StdRng::from_seed(seed),
            None => StdRng::from_entropy(),
        })
    } else {
        None
    };

    // ============================================
    // Phase 1: Witness Generation
    // ============================================
    let mut witness_stream = WitnessStream::try_new(ucir.clone(), config.memory_limit)?;
    witness_stream.phase_w1_produce(public_inputs, wire_values)?;

    // ============================================
    // Phase 2: Constraint Evaluation
    // ============================================
    let mut evals = witness_stream.phase_w2_evaluate()?;

    // Check all constraints are satisfied
    for (i, eval) in evals.iter().enumerate() {
        if *eval != Goldilocks::ZERO {
            return Err(ProverError::ConstraintViolation {
                message: format!("Constraint {} violated: eval = {:?}", i, eval),
            });
        }
    }

    // ============================================
    // Phase 3: LogUp (if lookups present)
    // ============================================
    let logup_proof = if !ucir.lookups.is_empty() {
        Some(prove_logup(&ucir, &witness_stream.witness, &mut transcript))
    } else {
        None
    };

    if let Some(lp) = &logup_proof {
        for table in &lp.tables {
            transcript.absorb_goldilocks(crate::glyph_transcript::DOMAIN_LOOKUP, table.beta);
            transcript.absorb_goldilocks(crate::glyph_transcript::DOMAIN_LOOKUP, table.a_tree.root);
            transcript.absorb_goldilocks(crate::glyph_transcript::DOMAIN_LOOKUP, table.b_tree.root);
        }
        logup_constraint_evals_into(lp, &mut evals);
    }
    witness_stream.release_witness();

    let ucir_hash = ucir.hash();
    transcript.absorb_bytes32(DOMAIN_SUMCHECK_MIX, &ucir_hash);
    transcript.absorb(DOMAIN_SUMCHECK_MIX, &(evals.len() as u64).to_le_bytes());
    let mix_alpha = transcript.challenge_goldilocks();
    mix_evals_in_place(&mut evals, mix_alpha);

    // ============================================
    // Phase 4: Bind statement, ZK layout, and PCS Commitment
    // ============================================
    let base_len = evals.len() + 1;
    let zk_mask_rows = if config.mode == ProverMode::ZkMode {
        std::env::var("GLYPH_PCS_MASK_ROWS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1)
    } else {
        0usize
    };

    let (mut n, rows, cols) = if config.mode == ProverMode::ZkMode {
        basefold_zk_shape_for_len(base_len, zk_mask_rows)
    } else {
        let n_fast = base_len.max(2).next_power_of_two();
        (n_fast, 0usize, 0usize)
    };
    if n < 2 {
        n = 2;
    }

    // Bind statement into evals (public inputs + UCIR hash)
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&ucir_hash);
    for v in public_inputs {
        hasher.update(&v.0.to_le_bytes());
    }
    let mut bind_hash = [0u8; 32];
    hasher.finalize(&mut bind_hash);
    let mut bind_bytes = [0u8; 8];
    bind_bytes.copy_from_slice(&bind_hash[0..8]);
    let bind_val = Goldilocks::new(u64::from_le_bytes(bind_bytes));
    evals.push(bind_val);

    let mut mask_row: Option<Vec<Goldilocks>> = None;
    if config.mode == ProverMode::ZkMode {
        let rng = zk_rng.as_mut().ok_or_else(|| ProverError::InvalidInput {
            message: "ZK RNG unavailable".to_string(),
        })?;
        let mut row = Vec::with_capacity(cols.saturating_mul(zk_mask_rows));
        for _ in 0..cols.saturating_mul(zk_mask_rows) {
            row.push(sample_nonzero_goldilocks(rng));
        }
        witness_stream.add_blinding_values(&row)?;
        let data_len = (rows.saturating_sub(zk_mask_rows)).saturating_mul(cols);
        if evals.len() > data_len {
            return Err(ProverError::InvalidInput {
                message: "ZK matrix shape too small for evals".to_string(),
            });
        }
        evals.resize(data_len, Goldilocks::ZERO);
        evals.extend_from_slice(&row);
        if evals.len() != rows.saturating_mul(cols) {
            return Err(ProverError::InvalidInput {
                message: "ZK eval length mismatch".to_string(),
            });
        }
        mask_row = Some(row);
    } else {
        evals.resize(n, Goldilocks::ZERO);
    }

    let (pcs_prover, pcs_salt) = match config.mode {
        ProverMode::ZkMode => {
            let zk_config = if let Some(seed) = config.zk_seed {
                ZkPcsConfig::from_seed(seed)
            } else {
                ZkPcsConfig::new_random()
            };
            let row = mask_row.as_ref().ok_or_else(|| ProverError::InvalidInput {
                message: "ZK mask row missing".to_string(),
            })?;
            let prover = commit_zk_owned(evals, rows, cols, row, &zk_config, &mut transcript)
                .map_err(|e| ProverError::PcsError {
                    message: e.to_string(),
                })?;
            (prover, Some(zk_config.salt))
        }
        ProverMode::FastMode => (
            PcsProver::commit_owned(evals, &mut transcript).map_err(|e| ProverError::PcsError {
                message: e.to_string(),
            })?,
            None,
        ),
    };
    let pcs_commitment = pcs_prover.commitment.clone();

    // ============================================
    // Phase 5: Sumcheck over evaluation table
    // ============================================
    let mut current_layer: Vec<Goldilocks> = Vec::new();
    let mut current_view: &[Goldilocks] = &pcs_prover.evals;

    debug_assert!(current_view.len().is_power_of_two());
    let rounds_expected = current_view.len().trailing_zeros() as usize;
    if config.sumcheck_rounds > 0 && config.sumcheck_rounds != rounds_expected {
        return Err(ProverError::InvalidInput {
            message: format!(
                "sumcheck_rounds mismatch: expected {}, got {}",
                rounds_expected, config.sumcheck_rounds
            ),
        });
    }

    let rounds = rounds_expected;
    let mut sumcheck_rounds = Vec::with_capacity(rounds);
    let mut sumcheck_challenges = Vec::with_capacity(rounds);
    let mut sum_arena: Arena<Goldilocks> = Arena::with_capacity(0);

    let use_paged = std::env::var("GLYPH_SUMCHECK_PAGED")
        .ok()
        .as_deref()
        .map(|v| v != "0" && v != "false")
        .unwrap_or(false);

    let mut next_layer: Vec<Goldilocks> = Vec::new();
    let mut current_claim: Goldilocks = goldilocks_sum(current_view);

    // Absorb UCIR hash and initial claim
    transcript.absorb_bytes32(DOMAIN_SUMCHECK, &ucir_hash);
    transcript.absorb_goldilocks(DOMAIN_SUMCHECK, current_claim);

    if use_paged {
        let mut paged_current = PagedLayer::from_slice(current_view, SUMCHECK_PAGE_SIZE);
        let mut paged_next = PagedLayer::new(paged_current.len / 2, SUMCHECK_PAGE_SIZE);
        let sum_even_odd_paged = |layer: &PagedLayer, half: usize| -> (Goldilocks, Goldilocks) {
            let mut s0 = Goldilocks::ZERO;
            let mut s1 = Goldilocks::ZERO;
            for i in 0..half {
                let even_idx = 2 * i;
                s0 = s0 + layer.get(even_idx);
                s1 = s1 + layer.get(even_idx + 1);
            }
            (s0, s1)
        };
        for _round in 0..rounds {
            let half = paged_current.len / 2;
            let chunk_size = config.sumcheck_chunk_size.max(1);
        let prefetch_dist = if cfg!(target_arch = "aarch64") {
            if chunk_size >= 2048 { 32usize } else { 16usize }
        } else if chunk_size >= 2048 {
            64usize
        } else {
            32usize
        };
            let mut y0 = Goldilocks::ZERO;
            let mut y1 = Goldilocks::ZERO;

            let chunks = half.div_ceil(chunk_size);
            sum_arena.reset();
            let partial = sum_arena.alloc_slice(chunks * 2);
            let (partial0, partial1) = partial.split_at_mut(chunks);

            partial0
                .par_iter_mut()
                .zip(partial1.par_iter_mut())
                .enumerate()
                .map_init(
                    || (Vec::new(), Vec::new()),
                    |(evens, odds), (chunk_idx, (s0, s1))| {
                        let start = chunk_idx * chunk_size;
                        let end = (start + chunk_size).min(half);
                        let mut local0 = Goldilocks::ZERO;
                        let mut local1 = Goldilocks::ZERO;
                        let len = end.saturating_sub(start);
                        if len >= 2048 {
                            evens.resize(len, Goldilocks::ZERO);
                            odds.resize(len, Goldilocks::ZERO);
                            for i in 0..len {
                                let even_idx = 2 * (start + i);
                                evens[i] = paged_current.get(even_idx);
                                odds[i] = paged_current.get(even_idx + 1);
                            }
                            *s0 = goldilocks_sum(evens);
                            *s1 = goldilocks_sum(odds);
                            return;
                        }
                        for i in start..end {
                            let even_idx = 2 * i;
                            let odd_idx = even_idx + 1;
                            if i + prefetch_dist < end {
                                let ptr = paged_current.ptr_at(2 * (i + prefetch_dist));
                                prefetch_read(ptr);
                            }
                            local0 = local0 + paged_current.get(even_idx);
                            local1 = local1 + paged_current.get(odd_idx);
                        }
                        *s0 = local0;
                        *s1 = local1;
                    },
                )
                .for_each(|_| {});

            for i in 0..chunks {
                y0 = y0 + partial0[i];
                y1 = y1 + partial1[i];
            }

            if y0 + y1 != current_claim {
                let recomputed = sum_paged(&paged_current);
                if y0 + y1 != recomputed {
                    let (s0, s1) = sum_even_odd_paged(&paged_current, half);
                    y0 = s0;
                    y1 = s1;
                    if y0 + y1 != recomputed {
                        return Err(ProverError::ConstraintViolation {
                            message: "Sumcheck claim mismatch".to_string(),
                        });
                    }
                }
            }

            let y2 = y0 + (y1 - y0) * GOLDILOCKS_TWO;
            let y3 = y0 + (y1 - y0) * GOLDILOCKS_THREE;

            let round_coeffs = interpolate_cubic_from_values(y0, y1, y2, y3);

            transcript.absorb_sumcheck_round(
                round_coeffs.c0,
                round_coeffs.c1,
                round_coeffs.c2,
                round_coeffs.c3,
            );
            let challenge = transcript.challenge_goldilocks();

            sumcheck_rounds.push(round_coeffs);
            sumcheck_challenges.push(challenge);

            let one_minus_r = Goldilocks::ONE - challenge;
            paged_next.reset(half);
            for i in 0..half {
                let lo = paged_current.get(2 * i);
                let hi = paged_current.get(2 * i + 1);
                paged_next.set(i, lo * one_minus_r + hi * challenge);
            }
            std::mem::swap(&mut paged_current, &mut paged_next);
            current_claim = paged_current.get(0);
        }
    } else {
    let sum_even_odd_scalar = |view: &[Goldilocks]| -> (Goldilocks, Goldilocks) {
        let mut s0 = Goldilocks::ZERO;
        let mut s1 = Goldilocks::ZERO;
        let mut i = 0usize;
        while i + 1 < view.len() {
            s0 = s0 + view[i];
            s1 = s1 + view[i + 1];
            i += 2;
        }
        (s0, s1)
    };
    for _round in 0..rounds {
        let half = current_view.len() / 2;
        let chunk_size = config.sumcheck_chunk_size.max(1);
        let mut used_gpu = false;
        let mut cpu_sum = || -> (Goldilocks, Goldilocks) {
            let chunks = half.div_ceil(chunk_size);
            sum_arena.reset();
            let partial = sum_arena.alloc_slice(chunks * 2);
            let (partial0, partial1) = partial.split_at_mut(chunks);

            partial0
                .par_iter_mut()
                .zip(partial1.par_iter_mut())
                .enumerate()
                .for_each(|(chunk_idx, (s0, s1))| {
                    let start = chunk_idx * chunk_size;
                    let end = (start + chunk_size).min(half);
                    let mut local0 = Goldilocks::ZERO;
                    let mut local1 = Goldilocks::ZERO;
                    let base = current_view.as_ptr();
                    let prefetch_dist = if chunk_size >= 2048 { 64usize } else { 32usize };
                    let len = end.saturating_sub(start);
                    if len >= 2048 {
                        let base = 2 * start;
                        *s0 = goldilocks_sum_strided(current_view, 2, len, base);
                        *s1 = goldilocks_sum_strided(current_view, 2, len, base + 1);
                        return;
                    }
                    for i in start..end {
                        let even_idx = 2 * i;
                        let odd_idx = even_idx + 1;
                        if i + prefetch_dist < end {
                            let ptr = unsafe { base.add(2 * (i + prefetch_dist)) };
                            prefetch_read(ptr);
                        }
                        local0 = local0 + current_view[even_idx];
                        local1 = local1 + current_view[odd_idx];
                    }
                    *s0 = local0;
                    *s1 = local1;
                });

            let mut acc0 = Goldilocks::ZERO;
            let mut acc1 = Goldilocks::ZERO;
            for i in 0..chunks {
                acc0 = acc0 + partial0[i];
                acc1 = acc1 + partial1[i];
            }
            (acc0, acc1)
        };

        let (mut y0, mut y1) = cpu_sum();
        if let Some((gpu_y0, gpu_y1)) = cuda_sumcheck_even_odd(current_view) {
            y0 = gpu_y0;
            y1 = gpu_y1;
            used_gpu = true;
        }

        if y0 + y1 != current_claim {
            if used_gpu {
                (y0, y1) = cpu_sum();
            }
            let recomputed = sum_scalar(current_view);
            if y0 + y1 != recomputed {
                let (s0, s1) = sum_even_odd_scalar(current_view);
                y0 = s0;
                y1 = s1;
                if y0 + y1 != recomputed {
                    return Err(ProverError::ConstraintViolation {
                        message: "Sumcheck claim mismatch".to_string(),
                    });
                }
            }
        }

        let y2 = y0 + (y1 - y0) * GOLDILOCKS_TWO;
        let y3 = y0 + (y1 - y0) * GOLDILOCKS_THREE;

        let round_coeffs = interpolate_cubic_from_values(y0, y1, y2, y3);

        transcript.absorb_sumcheck_round(
            round_coeffs.c0,
            round_coeffs.c1,
            round_coeffs.c2,
            round_coeffs.c3,
        );
        let challenge = transcript.challenge_goldilocks();

        sumcheck_rounds.push(round_coeffs);
        sumcheck_challenges.push(challenge);

        let one_minus_r = Goldilocks::ONE - challenge;
        next_layer.clear();
        next_layer.resize(half, Goldilocks::ZERO);
        if cuda_sumcheck_next_layer(current_view, challenge, &mut next_layer) {
            // GPU path filled next_layer
        } else if half >= 1 << 13 {
            // Threshold for parallel sumcheck layer, optimized for single proofs.
            let chunk = 4096usize;
            next_layer
                .par_chunks_mut(chunk)
                .enumerate()
                .map_init(
                    || (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
                    |(lo, hi, lo_scaled, hi_scaled), (chunk_idx, out_chunk)| {
                        let start = chunk_idx * chunk;
                        let len = out_chunk.len();
                        let end = (start + len).min(half);
                        let len = end - start;
                        lo.resize(len, Goldilocks::ZERO);
                        hi.resize(len, Goldilocks::ZERO);
                        lo_scaled.resize(len, Goldilocks::ZERO);
                        hi_scaled.resize(len, Goldilocks::ZERO);
                        for i in 0..len {
                            let base = 2 * (start + i);
                            lo[i] = current_view[base];
                            hi[i] = current_view[base + 1];
                        }
                        goldilocks_scalar_mul_batch_into(one_minus_r, lo, lo_scaled);
                        goldilocks_scalar_mul_batch_into(challenge, hi, hi_scaled);
                        goldilocks_add_batch_into(lo_scaled, hi_scaled, out_chunk);
                    },
                )
                .for_each(|_| {});
        } else {
            for i in 0..half {
                let lo = current_view[2 * i];
                let hi = current_view[2 * i + 1];
                next_layer[i] = lo * one_minus_r + hi * challenge;
            }
        }
        std::mem::swap(&mut current_layer, &mut next_layer);
        next_layer.clear();
        current_view = &current_layer;
        current_claim = current_view[0];
    }
    }

    let final_eval = [current_claim, Goldilocks::ZERO];

    // ============================================
    // Phase 6: PCS Opening (off-chain)
    // ============================================
    let eval_point = eval_point_from_sumcheck_challenges(&sumcheck_challenges);
    if eval_point.len() != pcs_prover.n_vars() {
        return Err(ProverError::PcsError {
            message: "sumcheck challenge length mismatch with PCS n_vars".to_string(),
        });
    }
    let pcs_opening_full = pcs_prover
        .open(&eval_point)
        .map_err(|e| ProverError::PcsError {
            message: e.to_string(),
        })?;

    let salt_ref = pcs_salt.as_ref();
    if !verify_opening(&pcs_commitment, &pcs_opening_full, pcs_prover.rho, salt_ref) {
        return Err(ProverError::PcsError { message: "PCS opening verification failed".to_string() });
    }
    absorb_opening(&mut transcript, &pcs_opening_full);

    // ============================================
    // Phase 7: GLYPH Artifact Derivation (Blueprint 12)
    // ============================================
    let commitment_tag = pcs_commitment.commitment_tag;
    let point_tag = derive_point_tag(&commitment_tag, &sumcheck_challenges);

    let claim128_raw = ((final_eval[0].0 as u128) << 64) | (final_eval[1].0 as u128);
    let claim128 = gkr_canonicalize_u128(claim128_raw);

    // Packed GKR now uses arity-8, grouping three challenges per round.
    let gkr_rounds = sumcheck_challenges.len().div_ceil(3).max(1);
    let (gkr_chainid, gkr_addr) = match (config.chainid, config.contract_addr) {
        (Some(chainid), Some(addr)) => (chainid, addr),
        _ => (0u64, [0u8; 20]),
    };
    let packed_gkr_proof = prove_packed_artifact_poly_sumcheck(
        &commitment_tag,
        &point_tag,
        &claim128,
        gkr_chainid,
        gkr_addr,
        gkr_rounds,
    );

    let initial_claim = gkr_u128_to_bytes32_be(packed_gkr_proof.initial_claim);

    let artifact = GlyphArtifact {
        commitment_tag,
        point_tag,
        claim128,
        initial_claim,
    };

    let packed_gkr_calldata = if let (Some(chainid), Some(addr)) = (config.chainid, config.contract_addr) {
        encode_artifact_poly_bound_packed_calldata_be(
            &packed_gkr_proof,
            chainid,
            addr,
            &commitment_tag,
            &point_tag,
            &claim128,
            config.gkr_truncated,
        )
    } else {
        Vec::new()
    };

    let (pcs_opening, pcs_salt_public, logup_public) = match config.mode {
        ProverMode::FastMode => (Some(pcs_opening_full), pcs_salt, logup_proof.clone()),
        ProverMode::ZkMode => (None, None, None),
    };

    let (sumcheck_rounds_out, sumcheck_challenges_out, final_eval_out) = match config.mode {
        ProverMode::FastMode => (sumcheck_rounds, sumcheck_challenges, final_eval),
        ProverMode::ZkMode => (Vec::new(), Vec::new(), [Goldilocks::ZERO; 2]),
    };

    Ok(UniversalProof {
        artifact,
        pcs_commitment,
        pcs_opening,
        pcs_rho: pcs_prover.rho,
        pcs_salt: pcs_salt_public,
        logup_proof: logup_public,
        sumcheck_rounds: sumcheck_rounds_out,
        sumcheck_challenges: sumcheck_challenges_out,
        final_eval: final_eval_out,
        packed_gkr_proof,
        packed_gkr_calldata,
        mode: config.mode,
    })
}

/// Convenience wrapper for compiled UCIR bundles
pub fn prove_compiled(
    compiled: CompiledUcir,
    config: ProverConfig,
) -> Result<UniversalProof, ProverError> {
    prove_universal(
        compiled.ucir,
        &compiled.public_inputs,
        Some(&compiled.wire_values),
        config,
    )
}

/// Encode universal proof as packed GKR calldata for GLYPHVerifier.sol
/// Per Blueprint 12.1
pub fn encode_packed_gkr_calldata(proof: &UniversalProof) -> Vec<u8> {
    encode_artifact_poly_bound_packed_calldata_be(
        &proof.packed_gkr_proof,
        0u64,
        [0u8; 20],
        &proof.artifact.commitment_tag,
        &proof.artifact.point_tag,
        &proof.artifact.claim128,
        false,
    )
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests;
