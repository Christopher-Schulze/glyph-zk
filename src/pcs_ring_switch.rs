//! Ring-switch proof helpers for the Binary Tower PCS.
//!
//! This module wraps the binius ring-switch verifier so GLYPH can bind small-field
//! evaluation claims into the large-field sumcheck pipeline.

use binius_core::fiat_shamir::HasherChallenger;
use binius_core::oracle::{MultilinearOracleSet, OracleId};
use binius_core::piop::{CommitMeta, make_oracle_commit_meta};
use binius_core::protocols::evalcheck::EvalcheckMultilinearClaim;
use binius_core::ring_switch::{self, EvalClaimSystem, ReducedClaim};
use binius_core::transcript::{ProverTranscript, VerifierTranscript};
use binius_hash::groestl::Groestl256;
use binius_math::{PackedTop, TowerTop};
use binius_utils::sparse_index::SparseIndex;
use binius_field::BinaryField128b;
use bytes::Bytes;
use rayon::prelude::*;

use crate::glyph_transcript::{Transcript, DOMAIN_PCS_RING_SWITCH, keccak256};

/// Ring-switch proof encoding tag.
pub const RING_SWITCH_PROOF_TAG: &[u8] = b"GLYPH_PCS_RING_SWITCH";
/// Ring-switch proof encoding version.
pub const RING_SWITCH_PROOF_VERSION: u16 = 1;
fn ring_switch_par_min() -> usize {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let default_min = (1024usize.saturating_mul(threads)).clamp(1024, 1 << 20);
    std::env::var("GLYPH_PCS_RING_SWITCH_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_min)
        .max(1)
}

/// Ring-switch proof payload used by the PCS pipeline.
#[derive(Clone, Debug)]
pub struct RingSwitchProof {
    pub transcript: Bytes,
}

#[derive(Clone, Copy, Debug)]
pub struct RingSwitchProofView<'a> {
    pub transcript: &'a [u8],
}

impl<'a> RingSwitchProofView<'a> {
    pub fn to_owned(&self) -> RingSwitchProof {
        RingSwitchProof {
            transcript: Bytes::copy_from_slice(self.transcript),
        }
    }
}

impl RingSwitchProof {
    /// Construct a ring-switch proof from raw transcript bytes.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("ring switch proof bytes are empty".to_string());
        }
        Ok(Self { transcript: bytes })
    }

    /// Finalize a binius prover transcript into a ring-switch proof.
    pub fn from_prover_transcript(
        transcript: ProverTranscript<HasherChallenger<Groestl256>>,
    ) -> Result<Self, String> {
        Self::from_bytes(Bytes::from(transcript.finalize()))
    }

    /// Access the raw transcript bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.transcript.as_ref()
    }

    /// Size in bytes for quick accounting.
    pub fn len(&self) -> usize {
        self.transcript.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.transcript.is_empty()
    }

    /// Digest the ring-switch transcript for binding in the GLYPH transcript.
    pub fn digest(&self) -> [u8; 32] {
        keccak256(self.transcript.as_ref())
    }
}

/// Minimal ring-switch system context for building eval-claim systems.
#[derive(Debug)]
pub struct RingSwitchSystem {
    pub oracles: MultilinearOracleSet<BinaryField128b>,
    pub commit_meta: CommitMeta,
    pub oracle_to_commit_index: SparseIndex<usize>,
}

impl RingSwitchSystem {
    /// Create a new oracle set with a single committed multilinear.
    pub fn new_committed_oracle(n_vars: usize, tower_level: usize) -> Result<(Self, OracleId), String> {
        let mut oracles = MultilinearOracleSet::<BinaryField128b>::new();
        let oracle_id = oracles.add_committed(n_vars, tower_level);
        let (commit_meta, oracle_to_commit_index) =
            make_oracle_commit_meta(&oracles).map_err(|err| err.to_string())?;
        Ok((
            Self {
                oracles,
                commit_meta,
                oracle_to_commit_index,
            },
            oracle_id,
        ))
    }

    /// Build eval claims for a single committed oracle.
    pub fn eval_claims_for_oracle(
        &self,
        oracle_id: OracleId,
        eval_points: &[Vec<BinaryField128b>],
        evals: &[BinaryField128b],
    ) -> Result<Vec<EvalcheckMultilinearClaim<BinaryField128b>>, String> {
        if eval_points.len() != evals.len() {
            return Err("eval points and evals length mismatch".to_string());
        }
        let n_vars = self.oracles.n_vars(oracle_id);
        if eval_points.iter().any(|point| point.len() != n_vars) {
            return Err("eval point length does not match oracle n_vars".to_string());
        }
        if eval_points.len() >= ring_switch_par_min() && rayon::current_num_threads() > 1 {
            Ok(eval_points
                .par_iter()
                .zip(evals.par_iter())
                .map(|(point, eval)| EvalcheckMultilinearClaim {
                    id: oracle_id,
                    eval_point: point.clone().into(),
                    eval: *eval,
                })
                .collect())
        } else {
            let mut claims = Vec::with_capacity(eval_points.len());
            for (point, eval) in eval_points.iter().zip(evals.iter()) {
                claims.push(EvalcheckMultilinearClaim {
                    id: oracle_id,
                    eval_point: point.clone().into(),
                    eval: *eval,
                });
            }
            Ok(claims)
        }
    }

    /// Build an eval-claim system for ring-switch verification.
    pub fn build_eval_claim_system<'a>(
        &'a self,
        eval_claims: &'a [EvalcheckMultilinearClaim<BinaryField128b>],
    ) -> Result<EvalClaimSystem<'a, BinaryField128b>, String> {
        EvalClaimSystem::new(
            &self.oracles,
            &self.commit_meta,
            &self.oracle_to_commit_index,
            eval_claims,
        )
        .map_err(|err| err.to_string())
    }
}

/// Encode a ring-switch proof with a strict tag + version + length prefix.
pub fn encode_ring_switch_proof(proof: &RingSwitchProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        RING_SWITCH_PROOF_TAG.len() + 2 + 4 + proof.transcript.len(),
    );
    out.extend_from_slice(RING_SWITCH_PROOF_TAG);
    out.extend_from_slice(&RING_SWITCH_PROOF_VERSION.to_be_bytes());
    out.extend_from_slice(&(proof.transcript.len() as u32).to_be_bytes());
    out.extend_from_slice(proof.transcript.as_ref());
    out
}

/// Decode a ring-switch proof with strict length checks and no trailing bytes.
pub fn decode_ring_switch_proof(bytes: &[u8]) -> Result<RingSwitchProof, String> {
    let view = decode_ring_switch_proof_view(bytes)?;
    Ok(view.to_owned())
}

pub fn decode_ring_switch_proof_view(bytes: &[u8]) -> Result<RingSwitchProofView<'_>, String> {
    if !bytes.starts_with(RING_SWITCH_PROOF_TAG) {
        return Err("ring switch proof missing tag".to_string());
    }
    let mut off = RING_SWITCH_PROOF_TAG.len();
    let version = read_u16_be(bytes, &mut off)?;
    if version != RING_SWITCH_PROOF_VERSION {
        return Err(format!("ring switch proof version unsupported: {version}"));
    }
    let len = read_u32_be(bytes, &mut off)? as usize;
    let transcript = read_slice(bytes, &mut off, len)?;
    if off != bytes.len() {
        return Err("ring switch proof has trailing bytes".to_string());
    }
    if transcript.is_empty() {
        return Err("ring switch proof bytes are empty".to_string());
    }
    Ok(RingSwitchProofView { transcript })
}

/// Bind a ring-switch proof digest into the GLYPH transcript.
pub fn absorb_ring_switch(transcript: &mut Transcript, proof: &RingSwitchProof) {
    let digest = proof.digest();
    transcript.absorb_bytes32(DOMAIN_PCS_RING_SWITCH, &digest);
}

/// Verify a ring-switch proof and return the reduced claim.
///
/// Uses the Groestl256-based challenger to match binius transcript defaults.
pub fn verify_ring_switch<'a, F>(
    system: &'a EvalClaimSystem<'a, F>,
    proof: &RingSwitchProof,
) -> Result<ReducedClaim<'a, F>, String>
where
    F: TowerTop + PackedTop<Scalar = F>,
{
    let mut transcript =
        VerifierTranscript::<HasherChallenger<Groestl256>>::new(proof.transcript.to_vec());
    let reduced = ring_switch::verify(system, &mut transcript)
        .map_err(|err| err.to_string())?;
    transcript
        .finalize()
        .map_err(|err| err.to_string())?;
    Ok(reduced)
}

pub fn verify_ring_switch_view<'a, F>(
    system: &'a EvalClaimSystem<'a, F>,
    proof: &RingSwitchProofView<'_>,
) -> Result<ReducedClaim<'a, F>, String>
where
    F: TowerTop + PackedTop<Scalar = F>,
{
    let mut transcript =
        VerifierTranscript::<HasherChallenger<Groestl256>>::new(proof.transcript.to_vec());
    let reduced = ring_switch::verify(system, &mut transcript)
        .map_err(|err| err.to_string())?;
    transcript
        .finalize()
        .map_err(|err| err.to_string())?;
    Ok(reduced)
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

fn read_slice<'a>(bytes: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = off
        .checked_add(len)
        .ok_or_else(|| "bytes length overflow".to_string())?;
    if end > bytes.len() {
        return Err("bytes read out of bounds".to_string());
    }
    let out = &bytes[*off..end];
    *off = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_field::{Field, TowerField};

    #[test]
    fn test_ring_switch_encode_decode_roundtrip() {
        let proof = match RingSwitchProof::from_bytes(Bytes::from(vec![1u8, 2, 3, 4])) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };
        let enc = encode_ring_switch_proof(&proof);
        let dec = match decode_ring_switch_proof(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(dec.as_bytes(), proof.as_bytes());
    }

    #[test]
    fn test_ring_switch_decode_rejects_tag() {
        let proof = match RingSwitchProof::from_bytes(Bytes::from(vec![9u8])) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };
        let mut bytes = encode_ring_switch_proof(&proof);
        bytes[0] ^= 0x5a;
        let err = match decode_ring_switch_proof(&bytes) {
            Ok(_) => {
                assert!(false, "bad tag");
                return;
            }
            Err(err) => err,
        };
        assert!(err.contains("missing tag"));
    }

    #[test]
    fn test_ring_switch_decode_rejects_version() {
        let proof = match RingSwitchProof::from_bytes(Bytes::from(vec![9u8])) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };
        let mut bytes = encode_ring_switch_proof(&proof);
        let tag_len = RING_SWITCH_PROOF_TAG.len();
        bytes[tag_len] = 0;
        bytes[tag_len + 1] = 2;
        let err = match decode_ring_switch_proof(&bytes) {
            Ok(_) => {
                assert!(false, "bad version");
                return;
            }
            Err(err) => err,
        };
        assert!(err.contains("version unsupported"));
    }

    #[test]
    fn test_ring_switch_decode_rejects_trailing_bytes() {
        let proof = match RingSwitchProof::from_bytes(Bytes::from(vec![9u8])) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };
        let mut bytes = encode_ring_switch_proof(&proof);
        bytes.push(0);
        let err = match decode_ring_switch_proof(&bytes) {
            Ok(_) => {
                assert!(false, "trailing");
                return;
            }
            Err(err) => err,
        };
        assert!(err.contains("trailing bytes"));
    }

    #[test]
    fn test_ring_switch_system_builds_eval_claim_system() {
        let (system, oracle_id) = match RingSwitchSystem::new_committed_oracle(
            4,
            BinaryField128b::TOWER_LEVEL,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "system");
                return;
            }
        };
        let eval_point = vec![BinaryField128b::ONE; 4];
        let evals = vec![BinaryField128b::ONE];
        let claims = system
            .eval_claims_for_oracle(oracle_id, &[eval_point], &evals);
        let claims = match claims {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "claims");
                return;
            }
        };
        let eval_system = match system.build_eval_claim_system(&claims) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "eval system");
                return;
            }
        };
        assert_eq!(eval_system.sumcheck_claim_descs.len(), 1);
    }
}
