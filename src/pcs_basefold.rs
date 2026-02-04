//! BaseFold PCS wrapper using the binius ring-switch + PIOP pipeline.
//!
//! This module provides a single-committed-multilinear path suitable for
//! bridging the current GLYPH PCS to a binary tower BaseFold-style PCS.

use binius_compute::ComputeHolder;
use binius_compute::cpu::layer::CpuLayerHolder;
use binius_fast_compute::layer::FastCpuLayerHolder;
use binius_core::fiat_shamir::HasherChallenger;
use binius_core::merkle_tree::{BinaryMerkleTree, BinaryMerkleTreeProver};
use binius_core::piop;
use binius_core::protocols::evalcheck::subclaims::MemoizedData;
use binius_core::ring_switch;
use binius_core::transcript::{ProverTranscript, VerifierTranscript};
use binius_field::{BinaryField, BinaryField128b, TowerField, underlier::WithUnderlier};
use binius_field::tower::CanonicalTowerFamily;
use binius_hash::groestl::{Groestl256, Groestl256ByteCompression, Groestl256Parallel};
use binius_math::{B32, MLEDirectAdapter, MultilinearQuery};
use binius_ntt::SingleThreadedNTT;
use binius_utils::rayon::adjust_thread_pool;
use sha2::digest::Output;
use bytes::Bytes;

use std::sync::OnceLock;

use crate::pcs_binary_field::{BasefoldPackedBinaryField, b128_evals_to_multilinear};
use crate::glyph_transcript::{DOMAIN_PCS_BASEFOLD_COMMIT, DOMAIN_PCS_BASEFOLD_OPEN, keccak256};
use crate::pcs_ring_switch::RingSwitchSystem;

type BaseFoldField = BinaryField128b;

/// BaseFold proof encoding tag.
pub const BASEFOLD_PROOF_TAG: &[u8] = b"GLYPH_PCS_BASEFOLD";
/// BaseFold proof encoding version.
pub const BASEFOLD_PROOF_VERSION: u16 = 1;

fn ensure_binius_thread_pool() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = adjust_thread_pool();
    });
}

/// BaseFold PCS configuration.
#[derive(Clone, Debug)]
pub struct BaseFoldConfig {
    pub security_bits: usize,
    pub security_target_bits: usize,
    pub security_repeat: usize,
    pub log_inv_rate: usize,
    pub host_mem: usize,
    pub dev_mem: usize,
    pub fold_arity: Option<usize>,
}

impl Default for BaseFoldConfig {
    fn default() -> Self {
        Self {
            security_bits: 128,
            security_target_bits: 128,
            security_repeat: 1,
            log_inv_rate: 1,
            host_mem: 1 << 20,
            dev_mem: 1 << 20,
            fold_arity: Some(8),
        }
    }
}

/// BaseFold commitment metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseFoldCommitment {
    pub root: [u8; 32],
    pub depth: usize,
    pub n_vars: usize,
    pub security_bits: usize,
    pub security_target_bits: usize,
    pub log_inv_rate: usize,
    pub fold_arity: usize,
}

/// BaseFold proof transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseFoldProof {
    pub transcript: bytes::Bytes,
}

impl BaseFoldProof {
    pub fn digest(&self) -> [u8; 32] {
        crate::glyph_transcript::keccak256(&self.transcript)
    }
}

/// BaseFold opening result.
#[derive(Clone, Debug)]
pub struct BaseFoldOpening {
    pub eval: BaseFoldField,
    pub proofs: Vec<BaseFoldProof>,
}

/// Derive a commitment tag for BaseFold PCS binding.
pub fn derive_basefold_commitment_tag(commitment: &BaseFoldCommitment) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        DOMAIN_PCS_BASEFOLD_COMMIT.len() + 32 + 8 + 8 + 4 + 4 + 4,
    );
    input.extend_from_slice(DOMAIN_PCS_BASEFOLD_COMMIT);
    input.extend_from_slice(&commitment.root);
    input.extend_from_slice(&(commitment.depth as u64).to_be_bytes());
    input.extend_from_slice(&(commitment.n_vars as u64).to_be_bytes());
    input.extend_from_slice(&(commitment.security_bits as u32).to_be_bytes());
    input.extend_from_slice(&(commitment.security_target_bits as u32).to_be_bytes());
    input.extend_from_slice(&(commitment.log_inv_rate as u32).to_be_bytes());
    input.extend_from_slice(&(commitment.fold_arity as u32).to_be_bytes());
    keccak256(&input)
}

/// Derive a point tag for BaseFold PCS binding.
pub fn derive_basefold_point_tag(
    commitment_tag: &[u8; 32],
    eval_point: &[BaseFoldField],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        DOMAIN_PCS_BASEFOLD_OPEN.len() + 32 + eval_point.len().saturating_mul(16),
    );
    input.extend_from_slice(DOMAIN_PCS_BASEFOLD_OPEN);
    input.extend_from_slice(commitment_tag);
    for x in eval_point {
        input.extend_from_slice(&x.to_underlier().to_be_bytes());
    }
    keccak256(&input)
}

/// BaseFold prover state for a single committed multilinear.
pub struct BaseFoldProver {
    config: BaseFoldConfig,
    n_vars: usize,
    oracle_id: binius_core::oracle::OracleId,
    ring_system: RingSwitchSystem,
    fri_params: binius_core::protocols::fri::FRIParams<BaseFoldField, B32>,
    merkle_prover: BinaryMerkleTreeProver<BaseFoldField, Groestl256Parallel, Groestl256ByteCompression>,
    commitment: Output<Groestl256>,
    committed: BinaryMerkleTree<Output<Groestl256>>,
    codeword: Vec<BasefoldPackedBinaryField>,
    committed_multilins: Vec<MLEDirectAdapter<BasefoldPackedBinaryField>>,
    ntt: SingleThreadedNTT<B32>,
}

impl BaseFoldProver {
    /// Commit a single multilinear defined by its full evaluation table.
    pub fn commit(
        evals: &[BaseFoldField],
        n_vars: usize,
        config: BaseFoldConfig,
    ) -> Result<Self, String> {
        ensure_binius_thread_pool();
        let mut config = config;
        let trace = std::env::var("GLYPH_PCS_BASEFOLD_TRACE").ok().as_deref() == Some("1");
        if trace {
            eprintln!("basefold commit: start n_vars={} evals_len={} log_inv_rate={}", n_vars, evals.len(), config.log_inv_rate);
        }
        if evals.len() != (1usize << n_vars) {
            return Err("evals length must equal 2^n_vars".to_string());
        }

        let multilinear = b128_evals_to_multilinear(evals, n_vars)?;
        if trace {
            eprintln!("basefold commit: multilinear n_vars={} packed_len={}", multilinear.n_vars(), multilinear.evals().len());
        }
        let (ring_system, oracle_id) =
            RingSwitchSystem::new_committed_oracle(n_vars, BaseFoldField::TOWER_LEVEL)?;
        if trace {
            eprintln!("basefold commit: ring_system total_vars={} total_multilins={}", ring_system.commit_meta.total_vars(), ring_system.commit_meta.total_multilins());
        }
        let commit_meta = &ring_system.commit_meta;

        let merkle_prover = BinaryMerkleTreeProver::<
            BaseFoldField,
            Groestl256Parallel,
            Groestl256ByteCompression,
        >::new(Groestl256ByteCompression);
        let target_bits = config.security_target_bits.max(config.security_bits);
        let base_log_inv_rate = config.log_inv_rate;
        let base_fold_arity = config.fold_arity;
        let mut bits = config.security_bits;
        let min_bits = 64usize;
        let fri_params = loop {
            config.security_bits = bits;
            config.security_target_bits = target_bits;
            config.log_inv_rate = base_log_inv_rate;
            config.fold_arity = base_fold_arity;
            match make_basefold_fri_params(commit_meta, merkle_prover.scheme(), &mut config) {
                Ok(params) => {
                    config.security_repeat = basefold_security_repeat(bits, target_bits);
                    break params;
                }
                Err(err) => {
                    if target_bits < 128 || bits <= min_bits {
                        return Err(err);
                    }
                }
            }
            if target_bits < 128 || bits <= min_bits {
                return Err("fri params selection failed".to_string());
            }
            bits = bits.saturating_sub(8);
        };
        if trace {
            let rs_code = fri_params.rs_code();
            eprintln!(
                "basefold commit: fri_params log_dim={} log_inv_rate={} log_batch_size={} log_len={}",
                rs_code.log_dim(),
                rs_code.log_inv_rate(),
                fri_params.log_batch_size(),
                fri_params.log_len()
            );
        }
        let ntt = SingleThreadedNTT::<B32>::with_subspace(fri_params.rs_code().subspace())
            .map_err(|err| err.to_string())?;

        let committed_multilins = vec![MLEDirectAdapter::from(multilinear)];
        let commit_output = piop::commit(
            &fri_params,
            &ntt,
            &merkle_prover,
            &committed_multilins,
            None,
        )
        .map_err(|err| err.to_string())?;
        if std::env::var("GLYPH_PCS_BASEFOLD_TRACE").ok().as_deref() == Some("1") {
            let rs_code = fri_params.rs_code();
            eprintln!(
                "basefold commit: n_vars={} log_dim={} log_inv_rate={} log_batch_size={} log_len={} codeword_len={}",
                n_vars,
                rs_code.log_dim(),
                rs_code.log_inv_rate(),
                fri_params.log_batch_size(),
                fri_params.log_len(),
                commit_output.codeword.len()
            );
        }

        Ok(Self {
            config,
            n_vars,
            oracle_id,
            ring_system,
            fri_params,
            merkle_prover,
            commitment: commit_output.commitment,
            committed: commit_output.committed,
            codeword: commit_output.codeword,
            committed_multilins,
            ntt,
        })
    }

    /// Export the commitment metadata for binding.
    pub fn commitment(&self) -> BaseFoldCommitment {
        let fold_arity = if self.config.fold_arity.is_some() {
            self.fri_params
                .fold_arities()
                .first()
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        BaseFoldCommitment {
            root: digest_to_bytes(&self.commitment),
            depth: basefold_tree_depth(&self.fri_params),
            n_vars: self.n_vars,
            security_bits: self.config.security_bits,
            security_target_bits: self.config.security_target_bits,
            log_inv_rate: self.config.log_inv_rate,
            fold_arity,
        }
    }

    /// Open the committed multilinear at the provided evaluation point.
    pub fn open(&self, eval_point: &[BaseFoldField]) -> Result<BaseFoldOpening, String> {
        ensure_binius_thread_pool();
        let trace =
            std::env::var("GLYPH_PCS_BASEFOLD_TRACE").ok().as_deref() == Some("1");
        if eval_point.len() != self.n_vars {
            return Err("eval point length does not match n_vars".to_string());
        }
        if trace {
            eprintln!(
                "basefold open: start n_vars={} eval_point_len={}",
                self.n_vars,
                eval_point.len()
            );
        }

        let query = MultilinearQuery::<BasefoldPackedBinaryField>::expand(eval_point);
        let eval = self.committed_multilins[0]
            .as_ref()
            .evaluate::<BaseFoldField, BasefoldPackedBinaryField>(query.to_ref())
            .map_err(|err: binius_math::Error| err.to_string())?;

        let eval_point_vec = eval_point.to_vec();
        let eval_claims = self.ring_system.eval_claims_for_oracle(
            self.oracle_id,
            std::slice::from_ref(&eval_point_vec),
            std::slice::from_ref(&eval),
        )?;
        let eval_system = self
            .ring_system
            .build_eval_claim_system(&eval_claims)?;

        let cpu_only =
            std::env::var("GLYPH_PCS_BASEFOLD_CPU_ONLY").ok().as_deref() == Some("1");
        let mut transcript = ProverTranscript::<HasherChallenger<Groestl256>>::new();
        transcript.message().write(&self.commitment);

        if trace {
            eprintln!("basefold open: cpu_only={}", cpu_only);
        }

        let repeat = self.config.security_repeat.max(1);
        let proofs = if cpu_only {
            let mut compute_holder =
                CpuLayerHolder::<BaseFoldField>::new(self.config.host_mem, self.config.dev_mem);
            let compute_data = compute_holder.to_data();
            let mut proofs = Vec::with_capacity(repeat);
            for idx in 0..repeat {
                let mut transcript =
                    ProverTranscript::<HasherChallenger<Groestl256>>::new();
                transcript.message().write(&self.commitment);
                if repeat > 1 {
                    let idx_u32 = idx as u32;
                    transcript.message().write(&idx_u32);
                }

                let ring_switch::ReducedWitness { transparents, sumcheck_claims } = ring_switch::prove(
                    &eval_system,
                    &self.committed_multilins,
                    &mut transcript,
                    MemoizedData::<BasefoldPackedBinaryField>::new(),
                    compute_data.hal,
                    &compute_data.dev_alloc,
                    &compute_data.host_alloc,
                )
                .map_err(|err| err.to_string())?;
                if trace {
                    eprintln!(
                        "basefold open: ring_switch done (sumcheck_claims={})",
                        sumcheck_claims.len()
                    );
                }

                piop::prove(
                    &compute_data,
                    &self.fri_params,
                    &self.ntt,
                    &self.merkle_prover,
                    &self.ring_system.commit_meta,
                    self.committed.clone(),
                    &self.codeword,
                    &self.committed_multilins,
                    transparents,
                    &sumcheck_claims,
                    &mut transcript,
                )
                .map_err(|err| err.to_string())?;
                if trace {
                    eprintln!("basefold open: piop prove done");
                }

                let transcript_bytes = bytes::Bytes::from(transcript.finalize());
                if trace {
                    eprintln!(
                        "basefold open: transcript finalized (len={})",
                        transcript_bytes.len()
                    );
                }
                proofs.push(BaseFoldProof { transcript: transcript_bytes });
            }
            proofs
        } else {
            let mut compute_holder =
                FastCpuLayerHolder::<CanonicalTowerFamily, BasefoldPackedBinaryField>::new(
                    self.config.host_mem,
                    self.config.dev_mem,
                );
            let compute_data = compute_holder.to_data();
            let mut proofs = Vec::with_capacity(repeat);
            for idx in 0..repeat {
                let mut transcript =
                    ProverTranscript::<HasherChallenger<Groestl256>>::new();
            transcript.message().write(&self.commitment);
            if repeat > 1 {
                let idx_u32 = idx as u32;
                transcript.message().write(&idx_u32);
            }

                let ring_switch::ReducedWitness { transparents, sumcheck_claims } = ring_switch::prove(
                    &eval_system,
                    &self.committed_multilins,
                    &mut transcript,
                    MemoizedData::<BasefoldPackedBinaryField>::new(),
                    compute_data.hal,
                    &compute_data.dev_alloc,
                    &compute_data.host_alloc,
                )
                .map_err(|err| err.to_string())?;
                if trace {
                    eprintln!(
                        "basefold open: ring_switch done (sumcheck_claims={})",
                        sumcheck_claims.len()
                    );
                }

                piop::prove(
                    &compute_data,
                    &self.fri_params,
                    &self.ntt,
                    &self.merkle_prover,
                    &self.ring_system.commit_meta,
                    self.committed.clone(),
                    &self.codeword,
                    &self.committed_multilins,
                    transparents,
                    &sumcheck_claims,
                    &mut transcript,
                )
                .map_err(|err| err.to_string())?;
                if trace {
                    eprintln!("basefold open: piop prove done");
                }

                let transcript_bytes = bytes::Bytes::from(transcript.finalize());
                if trace {
                    eprintln!(
                        "basefold open: transcript finalized (len={})",
                        transcript_bytes.len()
                    );
                }
                proofs.push(BaseFoldProof { transcript: transcript_bytes });
            }
            proofs
        };

        Ok(BaseFoldOpening { eval, proofs })
    }
}

/// Verify a BaseFold opening proof for a single committed multilinear.
pub fn verify_basefold_opening(
    commitment: &BaseFoldCommitment,
    eval_point: &[BaseFoldField],
    claimed_eval: BaseFoldField,
    proofs: &[BaseFoldProof],
) -> Result<(), String> {
    ensure_binius_thread_pool();
    if eval_point.len() != commitment.n_vars {
        return Err("eval point length does not match commitment n_vars".to_string());
    }
    if commitment.security_bits == 0 {
        return Err("basefold commitment security_bits invalid".to_string());
    }
    let repeat = basefold_security_repeat(commitment.security_bits, commitment.security_target_bits);
    if proofs.len() != repeat {
        return Err("basefold proof repeat count mismatch".to_string());
    }

    let (ring_system, oracle_id) =
        RingSwitchSystem::new_committed_oracle(commitment.n_vars, BaseFoldField::TOWER_LEVEL)?;
    let commit_meta = &ring_system.commit_meta;
    let merkle_prover = BinaryMerkleTreeProver::<
        BaseFoldField,
        Groestl256Parallel,
        Groestl256ByteCompression,
    >::new(Groestl256ByteCompression);

    let mut verify_config = BaseFoldConfig {
        security_bits: commitment.security_bits,
        security_target_bits: commitment.security_target_bits,
        security_repeat: repeat,
        log_inv_rate: commitment.log_inv_rate,
        host_mem: 0,
        dev_mem: 0,
        fold_arity: if commitment.fold_arity == 0 {
            None
        } else {
            Some(commitment.fold_arity)
        },
    };
    let fri_params = make_basefold_fri_params(
        commit_meta,
        merkle_prover.scheme(),
        &mut verify_config,
    )?;

    let eval_point_vec = eval_point.to_vec();
    let eval_claims = ring_system.eval_claims_for_oracle(
        oracle_id,
        std::slice::from_ref(&eval_point_vec),
        std::slice::from_ref(&claimed_eval),
    )?;
    let eval_system = ring_system.build_eval_claim_system(&eval_claims)?;

    for (idx, proof) in proofs.iter().enumerate() {
        let mut transcript =
            VerifierTranscript::<HasherChallenger<Groestl256>>::new(proof.transcript.to_vec());
        let transcript_commitment: Output<Groestl256> = transcript
            .message()
            .read()
            .map_err(|err| err.to_string())?;
        if repeat > 1 {
            let open_idx: u32 = transcript
                .message()
                .read()
                .map_err(|err| err.to_string())?;
            if open_idx as usize != idx {
                return Err("basefold proof index mismatch".to_string());
            }
        }
        let transcript_root = digest_to_bytes(&transcript_commitment);
        let expected_depth = basefold_tree_depth(&fri_params);
        if transcript_root != commitment.root || commitment.depth != expected_depth {
            return Err("basefold commitment mismatch".to_string());
        }

        let ring_switch::ReducedClaim { transparents, sumcheck_claims } =
            ring_switch::verify(&eval_system, &mut transcript)
                .map_err(|err| err.to_string())?;

        piop::verify(
            commit_meta,
            merkle_prover.scheme(),
            &fri_params,
            &transcript_commitment,
            &transparents,
            &sumcheck_claims,
            &mut transcript,
        )
        .map_err(|err| err.to_string())?;

        transcript.finalize().map_err(|err| err.to_string())?;
    }
    Ok(())
}

/// Encode BaseFold proofs with tag, version, and count.
pub fn encode_basefold_proof(proofs: &[BaseFoldProof]) -> Vec<u8> {
    let mut size = BASEFOLD_PROOF_TAG.len() + 2 + 2;
    for proof in proofs {
        size = size
            .saturating_add(4)
            .saturating_add(proof.transcript.len());
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(BASEFOLD_PROOF_TAG);
    out.extend_from_slice(&BASEFOLD_PROOF_VERSION.to_be_bytes());
    out.extend_from_slice(&(proofs.len() as u16).to_be_bytes());
    for proof in proofs {
        out.extend_from_slice(&(proof.transcript.len() as u32).to_be_bytes());
        out.extend_from_slice(&proof.transcript);
    }
    out
}

/// Decode BaseFold proofs with strict length checks.
pub fn decode_basefold_proof(bytes: &[u8]) -> Result<Vec<BaseFoldProof>, String> {
    if !bytes.starts_with(BASEFOLD_PROOF_TAG) {
        return Err("basefold proof missing tag".to_string());
    }
    let mut off = BASEFOLD_PROOF_TAG.len();
    let version = read_u16_be(bytes, &mut off)?;
    if version != BASEFOLD_PROOF_VERSION {
        return Err(format!("basefold proof version unsupported: {version}"));
    }
    let count = read_u16_be(bytes, &mut off)? as usize;
    if count == 0 {
        return Err("basefold proof count empty".to_string());
    }
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32_be(bytes, &mut off)? as usize;
        let transcript = read_bytes(bytes, &mut off, len)?;
        if transcript.is_empty() {
            return Err("basefold proof transcript empty".to_string());
        }
        proofs.push(BaseFoldProof { transcript });
    }
    if off != bytes.len() {
        return Err("basefold proof has trailing bytes".to_string());
    }
    Ok(proofs)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let end = off.checked_add(2).ok_or_else(|| "u16 offset overflow".to_string())?;
    if end > bytes.len() {
        return Err("u16 read out of bounds".to_string());
    }
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(&bytes[*off..end]);
    *off = end;
    Ok(u16::from_be_bytes(tmp))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let end = off.checked_add(4).ok_or_else(|| "u32 offset overflow".to_string())?;
    if end > bytes.len() {
        return Err("u32 read out of bounds".to_string());
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&bytes[*off..end]);
    *off = end;
    Ok(u32::from_be_bytes(tmp))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| "vec length overflow".to_string())?;
    if end > bytes.len() {
        return Err("vec read out of bounds".to_string());
    }
    let out = bytes[*off..end].to_vec();
    *off = end;
    Ok(out)
}

fn read_bytes(bytes: &[u8], off: &mut usize, len: usize) -> Result<Bytes, String> {
    Ok(Bytes::from(read_vec(bytes, off, len)?))
}

fn digest_to_bytes(digest: &Output<Groestl256>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn basefold_tree_depth(
    fri_params: &binius_core::protocols::fri::FRIParams<BaseFoldField, B32>,
) -> usize {
    let log_elems = fri_params.log_len();
    let coset_log_len = fri_params
        .fold_arities()
        .first()
        .copied()
        .unwrap_or(log_elems);
    log_elems.saturating_sub(coset_log_len)
}

fn basefold_security_repeat(base_bits: usize, target_bits: usize) -> usize {
    let base_bits = base_bits.max(1);
    let target_bits = target_bits.max(base_bits);
    target_bits.div_ceil(base_bits)
}

fn make_basefold_fri_params(
    commit_meta: &binius_core::piop::CommitMeta,
    merkle_scheme: &impl binius_core::merkle_tree::MerkleTreeScheme<BaseFoldField>,
    config: &mut BaseFoldConfig,
) -> Result<binius_core::protocols::fri::FRIParams<BaseFoldField, B32>, String> {
    let ntt = SingleThreadedNTT::<B32>::new(B32::N_BITS)
        .map_err(|err| err.to_string())?;

    let try_constant = |log_inv_rate: usize, arity: usize| -> Result<
        binius_core::protocols::fri::FRIParams<BaseFoldField, B32>,
        String,
    > {
        binius_core::protocols::fri::FRIParams::choose_with_constant_fold_arity(
            &ntt,
            commit_meta.total_vars(),
            config.security_bits,
            log_inv_rate,
            arity,
        )
        .map_err(|err| err.to_string())
    };

    let try_optimal = |log_inv_rate: usize| -> Result<
        binius_core::protocols::fri::FRIParams<BaseFoldField, B32>,
        String,
    > {
        piop::make_commit_params_with_optimal_arity::<BaseFoldField, B32, _>(
            commit_meta,
            merkle_scheme,
            config.security_bits,
            log_inv_rate,
        )
        .map_err(|err| err.to_string())
    };

    let mut last_err: Option<String> = None;
    let log_start = config.log_inv_rate.max(1);
    let log_max = if config.security_bits >= 128 { 10 } else { log_start };

    let arity_candidates: &[usize] = if let Some(arity) = config.fold_arity {
        &[arity, 2, 4, 8, 16, 32]
    } else {
        &[4, 2, 8, 16, 32]
    };

    for log_inv_rate in log_start..=log_max {
        if config.fold_arity.is_none() {
            match try_optimal(log_inv_rate) {
                Ok(params) => {
                    config.log_inv_rate = log_inv_rate;
                    return Ok(params);
                }
                Err(err) => last_err = Some(err),
            }
        }

        for &arity in arity_candidates {
            match try_constant(log_inv_rate, arity) {
                Ok(params) => {
                    config.log_inv_rate = log_inv_rate;
                    config.fold_arity = Some(arity);
                    return Ok(params);
                }
                Err(err) => last_err = Some(err),
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "fri params selection failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_field::Field;
    use rand09::{rngs::StdRng, SeedableRng};

    fn init_test_env() {
        std::env::set_var("RAYON_NUM_THREADS", "1");
        std::env::set_var("GLYPH_PCS_BASEFOLD_CPU_ONLY", "1");
    }

    fn test_config() -> BaseFoldConfig {
        BaseFoldConfig {
            security_bits: 16,
            security_target_bits: 16,
            security_repeat: 1,
            log_inv_rate: 1,
            host_mem: 1 << 14,
            dev_mem: 1 << 14,
            ..BaseFoldConfig::default()
        }
    }

    #[test]
    fn test_basefold_encode_decode_roundtrip() {
        init_test_env();
        let proof = BaseFoldProof { transcript: Bytes::from(vec![1, 2, 3]) };
        let enc = encode_basefold_proof(std::slice::from_ref(&proof));
        let dec = match decode_basefold_proof(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0].transcript, proof.transcript);
    }

    #[test]
    fn test_basefold_commit_open_verify_roundtrip() {
        init_test_env();
        let mut rng = StdRng::seed_from_u64(0);
        let n_vars = 2;
        let evals = (0..(1 << n_vars))
            .map(|_| BaseFoldField::random(&mut rng))
            .collect::<Vec<_>>();
        let eval_point = (0..n_vars)
            .map(|_| BaseFoldField::random(&mut rng))
            .collect::<Vec<_>>();

        let config = test_config();

        let prover = match BaseFoldProver::commit(&evals, n_vars, config) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "commit");
                return;
            }
        };
        let commitment = prover.commitment();
        let commitment_tag = derive_basefold_commitment_tag(&commitment);
        let opening = match prover.open(&eval_point) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "open");
                return;
            }
        };
        let point_tag = derive_basefold_point_tag(&commitment_tag, &eval_point);
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        if let Err(_) = verify_basefold_opening(
            &commitment,
            &eval_point,
            opening.eval,
            &opening.proofs,
        ) {
            assert!(false, "verify");
        }
    }

    #[test]
    fn test_basefold_commit_codeword_len_matches_params() {
        init_test_env();
        let mut rng = StdRng::seed_from_u64(2);
        let n_vars = 4;
        let evals = (0..(1 << n_vars))
            .map(|_| BaseFoldField::random(&mut rng))
            .collect::<Vec<_>>();

        let config = test_config();

        let prover = match BaseFoldProver::commit(&evals, n_vars, config) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "commit");
                return;
            }
        };
        let rs_code = prover.fri_params.rs_code();
        let expected = 1usize << (rs_code.log_len() + prover.fri_params.log_batch_size());
        assert_eq!(prover.codeword.len(), expected);
    }

    #[test]
    fn test_basefold_tamper_rejects() {
        init_test_env();
        let mut rng = StdRng::seed_from_u64(1);
        let n_vars = 2;
        let evals = (0..(1 << n_vars))
            .map(|_| BaseFoldField::random(&mut rng))
            .collect::<Vec<_>>();
        let eval_point = (0..n_vars)
            .map(|_| BaseFoldField::random(&mut rng))
            .collect::<Vec<_>>();

        let config = test_config();

        let prover = match BaseFoldProver::commit(&evals, n_vars, config) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "commit");
                return;
            }
        };
        let opening = match prover.open(&eval_point) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "open");
                return;
            }
        };

        let mut commitment = prover.commitment();
        commitment.root[0] ^= 1;
        assert!(verify_basefold_opening(
            &commitment,
            &eval_point,
            opening.eval,
            &opening.proofs,
        )
        .is_err());

        let mut tampered_proofs = opening.proofs.clone();
        if let Some(first) = tampered_proofs.first_mut() {
            if !first.transcript.is_empty() {
                let mut bytes = first.transcript.to_vec();
                bytes[0] ^= 1;
                first.transcript = bytes::Bytes::from(bytes);
            }
        }
        let commitment = prover.commitment();
        assert!(verify_basefold_opening(
            &commitment,
            &eval_point,
            opening.eval,
            &tampered_proofs,
        )
        .is_err());
    }
}
