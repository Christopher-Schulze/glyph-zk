use crate::glyph_field_simd::Goldilocks;
use crate::glyph_gkr::PackedGkrProof;
use crate::glyph_logup::LogUpProof;
use crate::glyph_pcs_basefold::{PcsCommitment, PcsOpening};
use crate::glyph_witness::WitnessError;

// ============================================================
//                    PROVER MODE
// ============================================================

/// Prover mode selection
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProverMode {
    /// fast-mode: non-ZK, maximum performance
    FastMode,
    /// zk-mode: ZK output, internal proofs redacted, salted PCS hashing
    #[default]
    ZkMode,
}

// ============================================================
//                    GLYPH ARTIFACT
// ============================================================

/// GLYPH artifact for on-chain verification
#[derive(Clone, Debug)]
pub struct GlyphArtifact {
    /// Commitment tag from PCS
    pub commitment_tag: [u8; 32],
    /// Point tag derived from eval point
    pub point_tag: [u8; 32],
    /// Final claim (128-bit packed)
    pub claim128: u128,
    /// Initial claim for binding
    pub initial_claim: [u8; 32],
}

impl GlyphArtifact {
    /// Derive claim word for on-chain use
    pub fn claim_word_bytes32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // Upper 128 bits zero, lower 128 bits are claim128
        let bytes = self.claim128.to_be_bytes();
        out[16..32].copy_from_slice(&bytes);
        out
    }
}

// ============================================================
//                    UNIVERSAL PROOF
// ============================================================

/// Complete universal proof from GLYPH-PROVER
#[derive(Clone, Debug)]
pub struct UniversalProof {
    /// GLYPH artifact for on-chain verification
    pub artifact: GlyphArtifact,
    /// PCS commitment
    pub pcs_commitment: PcsCommitment,
    /// PCS opening proof (off-chain verification, redacted in zk-mode)
    pub pcs_opening: Option<PcsOpening>,
    /// PCS rho challenge
    pub pcs_rho: Goldilocks,
    /// Optional PCS salt (fast-mode only, redacted in zk-mode)
    pub pcs_salt: Option<[u8; 32]>,
    /// LogUp proof (if lookups present, redacted in zk-mode)
    pub logup_proof: Option<LogUpProof>,
    /// Sumcheck rounds (coefficients)
    pub sumcheck_rounds: Vec<SumcheckRound>,
    /// Sumcheck challenges
    pub sumcheck_challenges: Vec<Goldilocks>,
    /// Final evaluation values
    pub final_eval: [Goldilocks; 2],
    /// Packed GKR proof for on-chain verification
    pub packed_gkr_proof: PackedGkrProof,
    /// Packed GKR calldata (Big-Endian) for GLYPH-VERIFIER
    pub packed_gkr_calldata: Vec<u8>,
    /// Mode used
    pub mode: ProverMode,
}

// ============================================================
//                    PROVER ERROR
// ============================================================

/// Error type for prover
#[derive(Debug, Clone)]
pub enum ProverError {
    /// Witness generation failed
    WitnessError(WitnessError),
    /// Constraint evaluation non-zero
    ConstraintViolation { message: String },
    /// PCS error
    PcsError { message: String },
    /// LogUp error
    LogUpError { message: String },
    /// Invalid input
    InvalidInput { message: String },
}

/// Sumcheck round coefficients in power basis
#[derive(Clone, Debug)]
pub struct SumcheckRound {
    pub c0: Goldilocks,
    pub c1: Goldilocks,
    pub c2: Goldilocks,
    pub c3: Goldilocks,
}

impl From<WitnessError> for ProverError {
    fn from(e: WitnessError) -> Self {
        ProverError::WitnessError(e)
    }
}

// ============================================================
//                    GLYPH-PROVER CORE
// ============================================================

/// GLYPH-PROVER universal prover configuration
#[derive(Clone, Debug)]
pub struct ProverConfig {
    /// Prover mode
    pub mode: ProverMode,
    /// Memory limit in bytes
    pub memory_limit: usize,
    /// Number of sumcheck rounds
    pub sumcheck_rounds: usize,
    /// Optional deterministic seed for ZK randomness (test only)
    pub zk_seed: Option<[u8; 32]>,
    /// Chain ID for packed calldata binding (optional)
    pub chainid: Option<u64>,
    /// Contract address for packed calldata binding (optional)
    pub contract_addr: Option<[u8; 20]>,
    /// Use truncated packed GKR format
    pub gkr_truncated: bool,
    /// Sumcheck parallel chunk size (pairs per chunk)
    pub sumcheck_chunk_size: usize,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            mode: ProverMode::ZkMode,
            memory_limit: 1024 * 1024 * 1024, // 1 GB
            sumcheck_rounds: 0,
            zk_seed: None,
            chainid: None,
            contract_addr: None,
            gkr_truncated: false,
            sumcheck_chunk_size: 4096,
        }
    }
}
