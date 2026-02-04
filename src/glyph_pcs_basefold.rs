//! BaseFold PCS integration for GLYPH using binary tower fields.

use binius_field::{BinaryField128b, underlier::WithUnderlier};
use crate::glyph_field_simd::Goldilocks;
use crate::pcs_common::{PCS_COMMIT_DOMAIN, ZkPcsConfig, pcs_salt_commitment};
use crate::glyph_transcript::{Transcript, DOMAIN_PCS, DOMAIN_PCS_BASEFOLD_OPEN, DOMAIN_PCS_ZK_MASK, keccak256};
use tiny_keccak::{Hasher, Keccak};
use crate::pcs_basefold::{
    BaseFoldCommitment,
    BaseFoldConfig,
    BaseFoldProof,
    BaseFoldProver,
    BASEFOLD_PROOF_TAG,
    derive_basefold_commitment_tag,
    verify_basefold_opening,
};
use crate::pcs_binary_field::{
    b128_from_goldilocks_le,
    b128_vec_from_goldilocks_le_into,
};

/// BaseFold PCS commitment bound into the GLYPH artifact.
#[derive(Clone, Debug)]
pub struct PcsCommitment {
    pub basefold: BaseFoldCommitment,
    pub salt_commitment: Option<[u8; 32]>,
    pub mask_commitment: Option<[u8; 32]>,
    pub commitment_tag: [u8; 32],
}

/// BaseFold PCS opening proof for a single evaluation point.
#[derive(Clone, Debug)]
pub struct PcsOpening {
    pub eval_point: Vec<BinaryField128b>,
    pub eval: BinaryField128b,
    pub proofs: Vec<BaseFoldProof>,
}

#[derive(Clone, Debug)]
pub enum PcsError {
    InvalidInput { message: String },
    BasefoldCommit { message: String },
    BasefoldOpen { message: String },
}

impl std::fmt::Display for PcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcsError::InvalidInput { message } => write!(f, "{message}"),
            PcsError::BasefoldCommit { message } => write!(f, "{message}"),
            PcsError::BasefoldOpen { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for PcsError {}

impl PcsOpening {
    pub fn encoded_len(&self) -> usize {
        let mut proof_len = BASEFOLD_PROOF_TAG.len() + 2 + 2 + 4;
        for proof in &self.proofs {
            proof_len = proof_len
                .saturating_add(4)
                .saturating_add(proof.transcript.len());
        }
        self.eval_point.len().saturating_mul(16) + 16 + proof_len
    }
}

/// BaseFold PCS prover state.
pub struct PcsProver {
    pub evals: Vec<Goldilocks>,
    pub rho: Goldilocks,
    pub commitment: PcsCommitment,
    basefold: BaseFoldProver,
}

impl PcsProver {
    pub fn n_vars(&self) -> usize {
        self.commitment.basefold.n_vars
    }

    pub fn commit_owned(
        evals: Vec<Goldilocks>,
        transcript: &mut Transcript,
    ) -> Result<Self, PcsError> {
        let n_vars = n_vars_for_len(evals.len())?;
        let basefold = commit_basefold(&evals, n_vars)?;
        let basefold_commitment = basefold.commitment();
        let commitment_tag = derive_commitment_tag(&basefold_commitment, None, None);
        transcript.absorb_bytes32(DOMAIN_PCS, &commitment_tag);
        let rho = transcript.challenge_goldilocks();
        let commitment = PcsCommitment {
            basefold: basefold_commitment,
            salt_commitment: None,
            mask_commitment: None,
            commitment_tag,
        };
        Ok(Self {
            evals,
            rho,
            commitment,
            basefold,
        })
    }

    pub fn open(&self, eval_point: &[BinaryField128b]) -> Result<PcsOpening, PcsError> {
        let opening = self
            .basefold
            .open(eval_point)
            .map_err(|err| PcsError::BasefoldOpen {
                message: format!("basefold open failed: {err}"),
            })?;
        Ok(PcsOpening {
            eval_point: eval_point.to_vec(),
            eval: opening.eval,
            proofs: opening.proofs,
        })
    }
}

/// Commit in ZK mode with a salt commitment.
pub fn commit_zk_owned(
    evals: Vec<Goldilocks>,
    rows: usize,
    cols: usize,
    mask_row: &[Goldilocks],
    zk_config: &ZkPcsConfig,
    transcript: &mut Transcript,
) -> Result<PcsProver, PcsError> {
    if cols == 0 {
        return Err(PcsError::InvalidInput {
            message: "PCS cols must be non-zero".to_string(),
        });
    }
    if !mask_row.len().is_multiple_of(cols) {
        return Err(PcsError::InvalidInput {
            message: "PCS mask row length mismatch".to_string(),
        });
    }
    let mask_rows = mask_row.len() / cols;
    if mask_rows < 1 {
        return Err(PcsError::InvalidInput {
            message: "PCS requires at least one mask row".to_string(),
        });
    }
    if rows <= mask_rows {
        return Err(PcsError::InvalidInput {
            message: "PCS rows too small for mask rows".to_string(),
        });
    }
    let data_rows = rows - mask_rows;
    let mut data = evals;
    data.resize(data_rows * cols, Goldilocks::ZERO);
    data.extend_from_slice(mask_row);
    let n_vars = n_vars_for_len(data.len())?;

    let mask_commitment = derive_mask_commitment(mask_row, cols);
    transcript.absorb_bytes32(DOMAIN_PCS, &zk_config.salt_commitment);
    transcript.absorb_bytes32(DOMAIN_PCS_ZK_MASK, &mask_commitment);
    let basefold = commit_basefold(&data, n_vars)?;
    let basefold_commitment = basefold.commitment();
    let commitment_tag = derive_commitment_tag(
        &basefold_commitment,
        Some(zk_config.salt_commitment),
        Some(mask_commitment),
    );
    transcript.absorb_bytes32(DOMAIN_PCS, &commitment_tag);
    let rho = transcript.challenge_goldilocks();
    let commitment = PcsCommitment {
        basefold: basefold_commitment,
        salt_commitment: Some(zk_config.salt_commitment),
        mask_commitment: Some(mask_commitment),
        commitment_tag,
    };

    Ok(PcsProver {
        evals: data,
        rho,
        commitment,
        basefold,
    })
}

/// Verify a BaseFold PCS opening.
pub fn verify_opening(
    commitment: &PcsCommitment,
    opening: &PcsOpening,
    _rho: Goldilocks,
    salt: Option<&[u8; 32]>,
) -> bool {
    if commitment.mask_commitment.is_some() != commitment.salt_commitment.is_some() {
        return false;
    }
    let expected_tag = derive_commitment_tag(
        &commitment.basefold,
        commitment.salt_commitment,
        commitment.mask_commitment,
    );
    if expected_tag != commitment.commitment_tag {
        return false;
    }
    if let Some(expected) = commitment.salt_commitment {
        let provided = match salt {
            Some(s) => s,
            None => return false,
        };
        if pcs_salt_commitment(provided) != expected {
            return false;
        }
    }
    verify_basefold_opening(
        &commitment.basefold,
        &opening.eval_point,
        opening.eval,
        &opening.proofs,
    )
    .is_ok()
}

/// Absorb a PCS opening into the GLYPH transcript.
pub fn absorb_opening(transcript: &mut Transcript, opening: &PcsOpening) {
    for point in &opening.eval_point {
        transcript.absorb(DOMAIN_PCS_BASEFOLD_OPEN, &point.to_underlier().to_le_bytes());
    }
    transcript.absorb(DOMAIN_PCS_BASEFOLD_OPEN, &opening.eval.to_underlier().to_le_bytes());
    let count = (opening.proofs.len() as u32).to_be_bytes();
    transcript.absorb(DOMAIN_PCS_BASEFOLD_OPEN, &count);
    for proof in &opening.proofs {
        let digest = proof.digest();
        transcript.absorb_bytes32(DOMAIN_PCS_BASEFOLD_OPEN, &digest);
    }
}

/// Sample a binary evaluation point from the GLYPH transcript.
pub fn sample_eval_point(transcript: &mut Transcript, n_vars: usize) -> Vec<BinaryField128b> {
    (0..n_vars)
        .map(|_| b128_from_goldilocks_le(transcript.challenge_goldilocks()))
        .collect()
}

pub fn eval_point_from_sumcheck_challenges(
    challenges: &[Goldilocks],
) -> Vec<BinaryField128b> {
    let mut out = Vec::with_capacity(challenges.len());
    b128_vec_from_goldilocks_le_into(challenges, &mut out);
    out
}

fn n_vars_for_len(len: usize) -> Result<usize, PcsError> {
    if !len.is_power_of_two() {
        return Err(PcsError::InvalidInput {
            message: "PCS eval length must be a power of two".to_string(),
        });
    }
    Ok(len.trailing_zeros() as usize)
}

pub fn basefold_zk_shape_for_len(base_len: usize, mask_rows: usize) -> (usize, usize, usize) {
    let mask_rows = mask_rows.max(1);
    let total = base_len.saturating_add(mask_rows);
    let n = total.max(2).next_power_of_two();
    (n, n, 1)
}

fn derive_commitment_tag(
    basefold_commitment: &BaseFoldCommitment,
    salt_commitment: Option<[u8; 32]>,
    mask_commitment: Option<[u8; 32]>,
) -> [u8; 32] {
    let base_tag = derive_basefold_commitment_tag(basefold_commitment);
    let mut input = Vec::with_capacity(
        PCS_COMMIT_DOMAIN.len()
            + 32
            + salt_commitment.map(|_| 32).unwrap_or(0)
            + mask_commitment.map(|_| 32).unwrap_or(0),
    );
    input.extend_from_slice(PCS_COMMIT_DOMAIN);
    input.extend_from_slice(&base_tag);
    if let Some(salt) = salt_commitment {
        input.extend_from_slice(&salt);
    }
    if let Some(mask) = mask_commitment {
        input.extend_from_slice(&mask);
    }
    keccak256(&input)
}

fn derive_mask_commitment(mask_row: &[Goldilocks], cols: usize) -> [u8; 32] {
    let mask_rows = if cols == 0 {
        0usize
    } else {
        mask_row.len() / cols
    };
    let mut hasher = Keccak::v256();
    hasher.update(DOMAIN_PCS_ZK_MASK);
    hasher.update(&(mask_rows as u64).to_be_bytes());
    hasher.update(&(cols as u64).to_be_bytes());
    for v in mask_row {
        hasher.update(&v.0.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn commit_basefold(evals: &[Goldilocks], n_vars: usize) -> Result<BaseFoldProver, PcsError> {
    let mut b128_evals = Vec::with_capacity(evals.len());
    b128_vec_from_goldilocks_le_into(evals, &mut b128_evals);
    let mut config = basefold_config_from_env(evals.len());
    let min_mem = basefold_min_mem_for_len(evals.len());
    config.host_mem = config.host_mem.max(min_mem);
    config.dev_mem = config.dev_mem.max(min_mem);
    BaseFoldProver::commit(&b128_evals, n_vars, config).map_err(|err| PcsError::BasefoldCommit {
        message: format!("basefold commit failed: {err}"),
    })
}

fn basefold_min_mem_for_len(len: usize) -> usize {
    let min_bytes = 1usize << 20;
    let max_bytes = 1usize << 30;
    let mut bytes = len.saturating_mul(128);
    bytes = bytes.max(min_bytes).min(max_bytes);
    bytes
}

fn basefold_config_from_env(evals_len: usize) -> BaseFoldConfig {
    let mut config = BaseFoldConfig::default();
    let min_mem = basefold_min_mem_for_len(evals_len);
    if let Some(bits) = std::env::var("GLYPH_PCS_BASEFOLD_SECURITY_BITS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        let target = bits.max(40);
        config.security_bits = target;
        config.security_target_bits = target;
        config.security_repeat = 1;
    }
    if let Some(log_inv) = std::env::var("GLYPH_PCS_BASEFOLD_LOG_INV_RATE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        config.log_inv_rate = log_inv.max(1);
    }
    if let Some(mem) = std::env::var("GLYPH_PCS_BASEFOLD_HOST_MEM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        config.host_mem = mem.max(1 << 12);
    } else {
        config.host_mem = config.host_mem.max(min_mem);
    }
    if let Some(mem) = std::env::var("GLYPH_PCS_BASEFOLD_DEV_MEM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        config.dev_mem = mem.max(1 << 12);
    } else {
        config.dev_mem = config.dev_mem.max(min_mem);
    }
    if let Some(arity) = std::env::var("GLYPH_PCS_BASEFOLD_FOLD_ARITY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        config.fold_arity = Some(arity.max(2));
    }
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glyph_transcript::Transcript;

    #[test]
    fn test_basefold_commitment_tag_binding() {
        let mut transcript = Transcript::new();
        let base_len = 9usize;
        let evals = (0..base_len)
            .map(|i| Goldilocks::new(i as u64 + 1))
            .collect::<Vec<_>>();
        let mask_rows = 1usize;
        let (n, rows, cols) = basefold_zk_shape_for_len(base_len, mask_rows);
        assert_eq!(rows.saturating_mul(cols), n);
        let mask_row = vec![Goldilocks::new(42); cols.saturating_mul(mask_rows)];
        let zk_config = ZkPcsConfig::from_seed([42u8; 32]);

        let prover = match commit_zk_owned(evals, rows, cols, &mask_row, &zk_config, &mut transcript) {
            Ok(prover) => prover,
            Err(err) => {
                assert!(false, "commit_zk_owned: {err}");
                return;
            }
        };
        let eval_point = sample_eval_point(&mut transcript, prover.n_vars());
        let opening = match prover.open(&eval_point) {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "basefold open: {err}");
                return;
            }
        };
        assert!(verify_opening(
            &prover.commitment,
            &opening,
            prover.rho,
            Some(&zk_config.salt),
        ));

        let mut bad_tag = prover.commitment.clone();
        bad_tag.commitment_tag[0] ^= 1;
        assert!(!verify_opening(
            &bad_tag,
            &opening,
            prover.rho,
            Some(&zk_config.salt),
        ));

        let mut missing_mask = prover.commitment.clone();
        missing_mask.mask_commitment = None;
        assert!(!verify_opening(
            &missing_mask,
            &opening,
            prover.rho,
            Some(&zk_config.salt),
        ));
    }
}
