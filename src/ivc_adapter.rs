//! Adapter IVC/Folding bridge into GLYPH artifacts.
//!
//! This module validates canonical proof bytes and derives the GLYPH artifact tags
//! without relying on legacy kernels.

use binius_field::{BinaryField128b, underlier::WithUnderlier};
use bytes::Bytes;
use tiny_keccak::{Hasher as KeccakHasher, Keccak};
use crate::adapters::{
    decode_ivc_statement_bytes, decode_ivc_vk_bytes,
};
use crate::adapter_ir::kernel_id;
use crate::ivc_hypernova::verify_hypernova_external_proof_bytes;
use crate::ivc_nova::verify_nova_external_proof_bytes;
use crate::ivc_r1cs::{decode_r1cs_receipt, verify_relaxed_r1cs, R1csReceipt};
use crate::ivc_sangria::verify_sangria_external_proof_bytes;
use crate::glyph_basefold::derive_basefold_weights;
use crate::pcs_basefold::{
    BaseFoldCommitment,
    BaseFoldProof,
    decode_basefold_proof,
    encode_basefold_proof,
    derive_basefold_commitment_tag,
    derive_basefold_point_tag,
    verify_basefold_opening,
};

pub const IVC_PROOF_DOMAIN: &[u8] = b"GLYPH_IVC_PROOF";

// Nova folding scheme domain tags
pub const IVC_NOVA_PROOF_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_PROOF";
pub const GLYPH_IVC_NOVA_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_POINT_TAG";
pub const GLYPH_IVC_NOVA_COMMIT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_COMMIT_TAG";
pub const GLYPH_IVC_NOVA_CLAIM_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_CLAIM_TAG";
pub const GLYPH_IVC_NOVA_U_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_U";
pub const GLYPH_IVC_NOVA_E_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_E";
pub const GLYPH_IVC_NOVA_W_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_W";
pub const GLYPH_IVC_NOVA_T_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_T";
pub const GLYPH_IVC_NOVA_ACC_U_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_ACC_U";
pub const GLYPH_IVC_NOVA_ACC_E_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_ACC_E";
pub const GLYPH_IVC_NOVA_ACC_W_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_ACC_W";

// SuperNova non-uniform IVC domain tags
pub const IVC_SUPERNOVA_PROOF_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_PROOF";
pub const GLYPH_IVC_SUPERNOVA_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_POINT_TAG";
pub const GLYPH_IVC_SUPERNOVA_COMMIT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_COMMIT_TAG";
pub const GLYPH_IVC_SUPERNOVA_CLAIM_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_CLAIM_TAG";
pub const GLYPH_IVC_SUPERNOVA_RIC_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_RIC";
pub const GLYPH_IVC_SUPERNOVA_STEP_U_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_STEP_U";
pub const GLYPH_IVC_SUPERNOVA_STEP_E_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_STEP_E";
pub const GLYPH_IVC_SUPERNOVA_STEP_W_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_STEP_W";
pub const GLYPH_IVC_SUPERNOVA_STEP_T_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_STEP_T";

// HyperNova CCS multi-folding domain tags
pub const IVC_HYPERNOVA_PROOF_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_PROOF";
pub const GLYPH_IVC_HYPERNOVA_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_POINT_TAG";
pub const GLYPH_IVC_HYPERNOVA_COMMIT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_COMMIT_TAG";
pub const GLYPH_IVC_HYPERNOVA_CLAIM_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_CLAIM_TAG";
pub const GLYPH_IVC_HYPERNOVA_CCS_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_CCS";
pub const GLYPH_IVC_HYPERNOVA_SUMCHECK_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_SUMCHECK";
pub const GLYPH_IVC_HYPERNOVA_PCS_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_HYPERNOVA_PCS";

// Sangria PLONKish folding domain tags
pub const IVC_SANGRIA_PROOF_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_PROOF";
pub const GLYPH_IVC_SANGRIA_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_POINT_TAG";
pub const GLYPH_IVC_SANGRIA_COMMIT_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_COMMIT_TAG";
pub const GLYPH_IVC_SANGRIA_CLAIM_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_CLAIM_TAG";
pub const GLYPH_IVC_SANGRIA_WIRE_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_WIRE";
pub const GLYPH_IVC_SANGRIA_ACC_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_ACC";
pub const GLYPH_IVC_SANGRIA_T_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_T";
pub const GLYPH_IVC_SANGRIA_CHALLENGE_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_CHALLENGE";
pub const GLYPH_IVC_SANGRIA_OPENING_TAG_DOMAIN: &[u8] = b"GLYPH_IVC_SANGRIA_OPENING";
pub const IVC_PCS_MAX_VARS: usize = 20;
const IVC_PUBLIC_INPUTS_LEN: usize = 0;
const IVC_SUPERNOVA_NUM_CIRCUITS: u16 = 1;
const IVC_SUPERNOVA_SELECTOR_INDEX: u16 = 0;
const IVC_HYPERNOVA_DEGREE: u16 = 2;
const IVC_SANGRIA_NUM_WIRES: u16 = 1;

fn keccak256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(bytes);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

fn verify_r1cs_receipt_and_hash(bytes: &[u8]) -> Result<(R1csReceipt, [u8; 32]), String> {
    let receipt = decode_r1cs_receipt(bytes)?;
    verify_relaxed_r1cs(&receipt)?;
    Ok((receipt, keccak256_bytes(bytes)))
}

fn derive_receipt_tag(domain: &[u8], receipt_hash: &[u8; 32]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(domain);
    keccak.update(receipt_hash);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

fn derive_receipt_tag_indexed(
    domain: &[u8],
    receipt_hash: &[u8; 32],
    idx: u32,
) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(domain);
    keccak.update(receipt_hash);
    keccak.update(&idx.to_be_bytes());
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

fn validate_nova_fields(
    proof: &NovaFoldingProof,
    receipt_hash: &[u8; 32],
) -> Result<(), String> {
    if proof.public_inputs.len() != IVC_PUBLIC_INPUTS_LEN {
        return Err("Nova public_inputs must be empty".to_string());
    }
    if proof.snark_proof.is_none() {
        return Err("Nova external proof is required".to_string());
    }
    let expected_u = derive_receipt_tag(GLYPH_IVC_NOVA_U_TAG_DOMAIN, receipt_hash);
    if proof.u != expected_u {
        return Err("Nova u mismatch".to_string());
    }
    let expected_e = derive_receipt_tag(GLYPH_IVC_NOVA_E_TAG_DOMAIN, receipt_hash);
    if proof.e_commitment != expected_e {
        return Err("Nova e_commitment mismatch".to_string());
    }
    let expected_w = derive_receipt_tag(GLYPH_IVC_NOVA_W_TAG_DOMAIN, receipt_hash);
    if proof.w_commitment != expected_w {
        return Err("Nova w_commitment mismatch".to_string());
    }
    let expected_t = derive_receipt_tag(GLYPH_IVC_NOVA_T_TAG_DOMAIN, receipt_hash);
    if proof.t_commitment != expected_t {
        return Err("Nova t_commitment mismatch".to_string());
    }
    let expected_acc_u = derive_receipt_tag(GLYPH_IVC_NOVA_ACC_U_TAG_DOMAIN, receipt_hash);
    if proof.acc_u != expected_acc_u {
        return Err("Nova acc_u mismatch".to_string());
    }
    let expected_acc_e = derive_receipt_tag(GLYPH_IVC_NOVA_ACC_E_TAG_DOMAIN, receipt_hash);
    if proof.acc_e_commitment != expected_acc_e {
        return Err("Nova acc_e_commitment mismatch".to_string());
    }
    let expected_acc_w = derive_receipt_tag(GLYPH_IVC_NOVA_ACC_W_TAG_DOMAIN, receipt_hash);
    if proof.acc_w_commitment != expected_acc_w {
        return Err("Nova acc_w_commitment mismatch".to_string());
    }
    Ok(())
}

fn validate_supernova_fields(
    proof: &SuperNovaProof,
    receipt_hash: &[u8; 32],
) -> Result<(), String> {
    if proof.num_circuits != IVC_SUPERNOVA_NUM_CIRCUITS {
        return Err("SuperNova num_circuits mismatch".to_string());
    }
    if proof.selector_index != IVC_SUPERNOVA_SELECTOR_INDEX {
        return Err("SuperNova selector_index mismatch".to_string());
    }
    if proof.running_instance_commitments.len() != IVC_SUPERNOVA_NUM_CIRCUITS as usize {
        return Err("SuperNova running_instance_commitments length mismatch".to_string());
    }
    for (idx, ric) in proof.running_instance_commitments.iter().enumerate() {
        let expected = derive_receipt_tag_indexed(
            GLYPH_IVC_SUPERNOVA_RIC_TAG_DOMAIN,
            receipt_hash,
            idx as u32,
        );
        if *ric != expected {
            return Err("SuperNova running_instance_commitment mismatch".to_string());
        }
    }
    let expected_step_u = derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_U_TAG_DOMAIN, receipt_hash);
    if proof.step_u != expected_step_u {
        return Err("SuperNova step_u mismatch".to_string());
    }
    let expected_step_e = derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_E_TAG_DOMAIN, receipt_hash);
    if proof.step_e_commitment != expected_step_e {
        return Err("SuperNova step_e_commitment mismatch".to_string());
    }
    let expected_step_w = derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_W_TAG_DOMAIN, receipt_hash);
    if proof.step_w_commitment != expected_step_w {
        return Err("SuperNova step_w_commitment mismatch".to_string());
    }
    let expected_step_t = derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_T_TAG_DOMAIN, receipt_hash);
    if proof.step_t_commitment != expected_step_t {
        return Err("SuperNova step_t_commitment mismatch".to_string());
    }
    if proof.public_inputs.len() != IVC_PUBLIC_INPUTS_LEN {
        return Err("SuperNova public_inputs must be empty".to_string());
    }
    Ok(())
}

fn validate_hypernova_fields(
    proof: &HyperNovaProof,
    receipt: &R1csReceipt,
    receipt_hash: &[u8; 32],
) -> Result<(), String> {
    if proof.num_vars != receipt.num_vars {
        return Err("HyperNova num_vars mismatch".to_string());
    }
    if proof.num_constraints != receipt.num_constraints {
        return Err("HyperNova num_constraints mismatch".to_string());
    }
    if proof.degree != IVC_HYPERNOVA_DEGREE {
        return Err("HyperNova degree mismatch".to_string());
    }
    let expected_ccs = derive_receipt_tag(GLYPH_IVC_HYPERNOVA_CCS_TAG_DOMAIN, receipt_hash);
    if proof.ccs_commitment != expected_ccs {
        return Err("HyperNova ccs_commitment mismatch".to_string());
    }
    if !proof.sumcheck_proof.is_empty() {
        return Err("HyperNova sumcheck_proof must be empty".to_string());
    }
    let expected_claim = derive_receipt_tag(GLYPH_IVC_HYPERNOVA_CLAIM_TAG_DOMAIN, receipt_hash);
    if proof.final_claim != expected_claim {
        return Err("HyperNova final_claim mismatch".to_string());
    }
    if !proof.pcs_opening.is_empty() {
        return Err("HyperNova pcs_opening must be empty".to_string());
    }
    if proof.public_inputs.len() != IVC_PUBLIC_INPUTS_LEN {
        return Err("HyperNova public_inputs must be empty".to_string());
    }
    if proof.snark_proof.as_ref().is_none_or(|s| s.is_empty()) {
        return Err("HyperNova external proof is required".to_string());
    }
    Ok(())
}

fn validate_sangria_fields(
    proof: &SangriaProof,
    receipt_hash: &[u8; 32],
) -> Result<(), String> {
    if proof.num_wires != IVC_SANGRIA_NUM_WIRES {
        return Err("Sangria num_wires mismatch".to_string());
    }
    if proof.wire_commitments.len() != IVC_SANGRIA_NUM_WIRES as usize {
        return Err("Sangria wire_commitments length mismatch".to_string());
    }
    for (idx, wc) in proof.wire_commitments.iter().enumerate() {
        let expected = derive_receipt_tag_indexed(
            GLYPH_IVC_SANGRIA_WIRE_TAG_DOMAIN,
            receipt_hash,
            idx as u32,
        );
        if *wc != expected {
            return Err("Sangria wire_commitment mismatch".to_string());
        }
    }
    let expected_acc = derive_receipt_tag(GLYPH_IVC_SANGRIA_ACC_TAG_DOMAIN, receipt_hash);
    if proof.acc_commitment != expected_acc {
        return Err("Sangria acc_commitment mismatch".to_string());
    }
    let expected_t = derive_receipt_tag(GLYPH_IVC_SANGRIA_T_TAG_DOMAIN, receipt_hash);
    if proof.t_commitment != expected_t {
        return Err("Sangria t_commitment mismatch".to_string());
    }
    let expected_challenge = derive_receipt_tag(GLYPH_IVC_SANGRIA_CHALLENGE_TAG_DOMAIN, receipt_hash);
    if proof.folding_challenge != expected_challenge {
        return Err("Sangria folding_challenge mismatch".to_string());
    }
    if !proof.opening_proof.is_empty() {
        return Err("Sangria opening_proof must be empty".to_string());
    }
    if proof.public_inputs.len() != IVC_PUBLIC_INPUTS_LEN {
        return Err("Sangria public_inputs must be empty".to_string());
    }
    if proof.snark_proof.as_ref().is_none_or(|s| s.is_empty()) {
        return Err("Sangria external proof is required".to_string());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseFoldPcsOpeningProof {
    pub instance_digests: Vec<[u8; 32]>,
    pub weights: Vec<BinaryField128b>,
    pub commitment: BaseFoldCommitment,
    pub eval_point: Vec<BinaryField128b>,
    pub claimed_eval: BinaryField128b,
    pub proofs: Vec<BaseFoldProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IvcProof {
    BaseFold(BaseFoldPcsOpeningProof),
    Nova(NovaFoldingProof),
    SuperNova(SuperNovaProof),
    HyperNova(HyperNovaProof),
    Sangria(SangriaProof),
}

/// Nova folding proof for Relaxed R1CS.
///
/// Encapsulates a Nova IVC proof with:
/// - Relaxed R1CS running instance (u, E, W)
/// - Cross-term commitment T
/// - Final accumulated instance
/// - Optional SNARK compression
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NovaFoldingProof {
    /// Scalar factor for relaxed R1CS: A·Z ○ B·Z = u·C·Z + E
    pub u: [u8; 32],
    /// Error vector commitment
    pub e_commitment: [u8; 32],
    /// Witness commitment
    pub w_commitment: [u8; 32],
    /// Public inputs (variable length)
    pub public_inputs: Vec<[u8; 32]>,
    /// Cross-term commitment for folding
    pub t_commitment: [u8; 32],
    /// Accumulated scalar factor
    pub acc_u: [u8; 32],
    /// Accumulated error commitment
    pub acc_e_commitment: [u8; 32],
    /// Accumulated witness commitment
    pub acc_w_commitment: [u8; 32],
    /// Optional SNARK proof for final instance compression
    pub snark_proof: Option<Bytes>,
    /// Transparent R1CS receipt bytes (canonical)
    pub r1cs_receipt: Bytes,
}

/// SuperNova non-uniform IVC proof.
///
/// Extends Nova with a selector function to handle multiple instruction circuits.
/// Each circuit type maintains its own running instance, and the selector determines
/// which circuit to execute at each step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuperNovaProof {
    /// Number of instruction circuits (k+1)
    pub num_circuits: u16,
    /// Current instruction/selector index (which circuit is being executed)
    pub selector_index: u16,
    /// Running instance commitments for each circuit (one per circuit type)
    pub running_instance_commitments: Vec<[u8; 32]>,
    /// Current step's Nova-style folding proof
    pub step_u: [u8; 32],
    pub step_e_commitment: [u8; 32],
    pub step_w_commitment: [u8; 32],
    /// Cross-term commitment for this step
    pub step_t_commitment: [u8; 32],
    /// Public inputs
    pub public_inputs: Vec<[u8; 32]>,
    /// Optional SNARK proof for final compression
    pub snark_proof: Option<Bytes>,
    /// Transparent R1CS receipt bytes (canonical)
    pub r1cs_receipt: Bytes,
}

/// HyperNova CCS (Customizable Constraint System) multi-folding proof.
///
/// Uses sum-check based folding for generalized constraint systems that
/// subsume R1CS, PLONKish, and AIR without overhead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HyperNovaProof {
    /// Number of variables in CCS
    pub num_vars: u32,
    /// Number of constraints
    pub num_constraints: u32,
    /// CCS degree (max degree of constraint polynomials)
    pub degree: u16,
    /// Committed CCS instance
    pub ccs_commitment: [u8; 32],
    /// Multi-folding sum-check proof
    pub sumcheck_proof: Bytes,
    /// Final evaluation claim
    pub final_claim: [u8; 32],
    /// PCS opening proof
    pub pcs_opening: Bytes,
    /// Public inputs
    pub public_inputs: Vec<[u8; 32]>,
    /// Optional SNARK proof for final compression
    pub snark_proof: Option<Bytes>,
    /// Transparent R1CS receipt bytes (canonical)
    pub r1cs_receipt: Bytes,
}

/// Sangria PLONKish folding proof.
///
/// Adapts Nova-style folding for PLONK-like circuits with
/// custom gates and lookup arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SangriaProof {
    /// Number of wire commitments
    pub num_wires: u16,
    /// Wire polynomial commitments
    pub wire_commitments: Vec<[u8; 32]>,
    /// Folding accumulator commitment
    pub acc_commitment: [u8; 32],
    /// Cross-term polynomial commitment
    pub t_commitment: [u8; 32],
    /// Challenge for folding
    pub folding_challenge: [u8; 32],
    /// Final IPA/KZG opening proof
    pub opening_proof: Bytes,
    /// Public inputs
    pub public_inputs: Vec<[u8; 32]>,
    /// Optional SNARK proof for final compression
    pub snark_proof: Option<Bytes>,
    /// Transparent R1CS receipt bytes (canonical)
    pub r1cs_receipt: Bytes,
}

fn b128_to_be_bytes(x: BinaryField128b) -> [u8; 16] {
    x.to_underlier().to_be_bytes()
}

fn b128_from_be_bytes(bytes: [u8; 16]) -> BinaryField128b {
    BinaryField128b::from_underlier(u128::from_be_bytes(bytes))
}

fn encode_basefold_commitment_bytes(commitment: &BaseFoldCommitment) -> Result<Vec<u8>, String> {
    let depth = u32::try_from(commitment.depth)
        .map_err(|_| "basefold commitment depth overflow".to_string())?;
    let n_vars = u32::try_from(commitment.n_vars)
        .map_err(|_| "basefold commitment n_vars overflow".to_string())?;
    let security_bits = u16::try_from(commitment.security_bits)
        .map_err(|_| "basefold commitment security_bits overflow".to_string())?;
    let security_target_bits = u16::try_from(commitment.security_target_bits)
        .map_err(|_| "basefold commitment security_target_bits overflow".to_string())?;
    let log_inv_rate = u16::try_from(commitment.log_inv_rate)
        .map_err(|_| "basefold commitment log_inv_rate overflow".to_string())?;
    let fold_arity = u16::try_from(commitment.fold_arity)
        .map_err(|_| "basefold commitment fold_arity overflow".to_string())?;
    let mut out = Vec::with_capacity(32 + 4 + 4 + 2 + 2 + 2 + 2);
    out.extend_from_slice(&commitment.root);
    out.extend_from_slice(&depth.to_be_bytes());
    out.extend_from_slice(&n_vars.to_be_bytes());
    out.extend_from_slice(&security_bits.to_be_bytes());
    out.extend_from_slice(&security_target_bits.to_be_bytes());
    out.extend_from_slice(&log_inv_rate.to_be_bytes());
    out.extend_from_slice(&fold_arity.to_be_bytes());
    Ok(out)
}

fn verify_basefold_pcs_opening(
    opening: &BaseFoldPcsOpeningProof,
) -> Result<(), String> {
    if opening.instance_digests.is_empty() {
        return Err("pcs opening must include at least one instance digest".to_string());
    }
    if opening.instance_digests.len() != opening.weights.len() {
        return Err("pcs opening weights length mismatch".to_string());
    }
    if opening.commitment.n_vars == 0 {
        return Err("pcs opening n_vars must be > 0".to_string());
    }
    if opening.commitment.n_vars > IVC_PCS_MAX_VARS {
        return Err("pcs opening n_vars exceeds max".to_string());
    }
    if opening.eval_point.len() != opening.commitment.n_vars {
        return Err("pcs opening eval_point length mismatch".to_string());
    }
    let expected_weights = derive_basefold_weights(&opening.instance_digests)?;
    if expected_weights != opening.weights {
        return Err("pcs opening weights mismatch".to_string());
    }
    verify_basefold_opening(
        &opening.commitment,
        &opening.eval_point,
        opening.claimed_eval,
        &opening.proofs,
    )?;
    Ok(())
}

pub fn encode_ivc_basefold_proof_bytes(
    proof: &BaseFoldPcsOpeningProof,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(IVC_PROOF_DOMAIN);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(proof.commitment.n_vars as u32).to_be_bytes());
    out.extend_from_slice(&(proof.instance_digests.len() as u32).to_be_bytes());
    for d in &proof.instance_digests {
        out.extend_from_slice(d);
    }
    out.extend_from_slice(&(proof.weights.len() as u32).to_be_bytes());
    for w in &proof.weights {
        out.extend_from_slice(&b128_to_be_bytes(*w));
    }
    let commitment_bytes = encode_basefold_commitment_bytes(&proof.commitment)?;
    out.extend_from_slice(&commitment_bytes);
    out.extend_from_slice(&(proof.eval_point.len() as u32).to_be_bytes());
    for x in &proof.eval_point {
        out.extend_from_slice(&b128_to_be_bytes(*x));
    }
    out.extend_from_slice(&b128_to_be_bytes(proof.claimed_eval));
    let proof_bytes = encode_basefold_proof(&proof.proofs);
    out.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof_bytes);
    Ok(out)
}

pub fn encode_ivc_proof_bytes(
    proof_type: crate::adapters::IvcProofType,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(IVC_PROOF_DOMAIN.len() + 2 + 1 + 4 + payload.len());
    out.extend_from_slice(IVC_PROOF_DOMAIN);
    out.extend_from_slice(&2u16.to_be_bytes());
    out.push(proof_type.as_u8());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encode a Nova folding proof to canonical bytes.
pub fn encode_nova_proof_bytes(proof: &NovaFoldingProof) -> Vec<u8> {
    let mut size = IVC_NOVA_PROOF_DOMAIN.len() + 2;
    size += 32 * 3;
    size += 4 + 32 * proof.public_inputs.len();
    size += 32 * 4;
    size += 1;
    if let Some(snark) = &proof.snark_proof {
        size += 4 + snark.len();
    }
    size += 4 + proof.r1cs_receipt.len();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(IVC_NOVA_PROOF_DOMAIN);
    out.extend_from_slice(&2u16.to_be_bytes()); // version
    out.extend_from_slice(&proof.u);
    out.extend_from_slice(&proof.e_commitment);
    out.extend_from_slice(&proof.w_commitment);
    out.extend_from_slice(&(proof.public_inputs.len() as u32).to_be_bytes());
    for pi in &proof.public_inputs {
        out.extend_from_slice(pi);
    }
    out.extend_from_slice(&proof.t_commitment);
    out.extend_from_slice(&proof.acc_u);
    out.extend_from_slice(&proof.acc_e_commitment);
    out.extend_from_slice(&proof.acc_w_commitment);
    match &proof.snark_proof {
        Some(snark) => {
            out.push(1u8);
            out.extend_from_slice(&(snark.len() as u32).to_be_bytes());
            out.extend_from_slice(snark);
        }
        None => {
            out.push(0u8);
        }
    }
    out.extend_from_slice(&(proof.r1cs_receipt.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.r1cs_receipt);
    out
}

/// Encode a SuperNova non-uniform IVC proof to canonical bytes.
pub fn encode_supernova_proof_bytes(proof: &SuperNovaProof) -> Vec<u8> {
    let mut size = IVC_SUPERNOVA_PROOF_DOMAIN.len() + 2;
    size += 2 + 2;
    size += 4 + 32 * proof.running_instance_commitments.len();
    size += 32 * 4;
    size += 4 + 32 * proof.public_inputs.len();
    size += 1;
    if let Some(snark) = &proof.snark_proof {
        size += 4 + snark.len();
    }
    size += 4 + proof.r1cs_receipt.len();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(IVC_SUPERNOVA_PROOF_DOMAIN);
    out.extend_from_slice(&2u16.to_be_bytes()); // version
    out.extend_from_slice(&proof.num_circuits.to_be_bytes());
    out.extend_from_slice(&proof.selector_index.to_be_bytes());
    out.extend_from_slice(&(proof.running_instance_commitments.len() as u32).to_be_bytes());
    for c in &proof.running_instance_commitments {
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&proof.step_u);
    out.extend_from_slice(&proof.step_e_commitment);
    out.extend_from_slice(&proof.step_w_commitment);
    out.extend_from_slice(&proof.step_t_commitment);
    out.extend_from_slice(&(proof.public_inputs.len() as u32).to_be_bytes());
    for pi in &proof.public_inputs {
        out.extend_from_slice(pi);
    }
    match &proof.snark_proof {
        Some(snark) => {
            out.push(1u8);
            out.extend_from_slice(&(snark.len() as u32).to_be_bytes());
            out.extend_from_slice(snark);
        }
        None => {
            out.push(0u8);
        }
    }
    out.extend_from_slice(&(proof.r1cs_receipt.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.r1cs_receipt);
    out
}

/// Encode a HyperNova CCS multi-folding proof to canonical bytes.
pub fn encode_hypernova_proof_bytes(proof: &HyperNovaProof) -> Vec<u8> {
    let mut size = IVC_HYPERNOVA_PROOF_DOMAIN.len() + 2;
    size += 2 + 2 + 2;
    size += 32;
    size += 4 + proof.sumcheck_proof.len();
    size += 32;
    size += 4 + proof.pcs_opening.len();
    size += 4 + 32 * proof.public_inputs.len();
    size += 1;
    if let Some(snark) = &proof.snark_proof {
        size += 4 + snark.len();
    }
    size += 4 + proof.r1cs_receipt.len();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(IVC_HYPERNOVA_PROOF_DOMAIN);
    out.extend_from_slice(&2u16.to_be_bytes()); // version
    out.extend_from_slice(&proof.num_vars.to_be_bytes());
    out.extend_from_slice(&proof.num_constraints.to_be_bytes());
    out.extend_from_slice(&proof.degree.to_be_bytes());
    out.extend_from_slice(&proof.ccs_commitment);
    out.extend_from_slice(&(proof.sumcheck_proof.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.sumcheck_proof);
    out.extend_from_slice(&proof.final_claim);
    out.extend_from_slice(&(proof.pcs_opening.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.pcs_opening);
    out.extend_from_slice(&(proof.public_inputs.len() as u32).to_be_bytes());
    for pi in &proof.public_inputs {
        out.extend_from_slice(pi);
    }
    match &proof.snark_proof {
        Some(snark) => {
            out.push(1u8);
            out.extend_from_slice(&(snark.len() as u32).to_be_bytes());
            out.extend_from_slice(snark);
        }
        None => {
            out.push(0u8);
        }
    }
    out.extend_from_slice(&(proof.r1cs_receipt.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.r1cs_receipt);
    out
}

/// Encode a Sangria PLONKish folding proof to canonical bytes.
pub fn encode_sangria_proof_bytes(proof: &SangriaProof) -> Vec<u8> {
    let mut size = IVC_SANGRIA_PROOF_DOMAIN.len() + 2;
    size += 2;
    size += 4 + 32 * proof.wire_commitments.len();
    size += 32 * 3;
    size += 4 + proof.opening_proof.len();
    size += 4 + 32 * proof.public_inputs.len();
    size += 1;
    if let Some(snark) = &proof.snark_proof {
        size += 4 + snark.len();
    }
    size += 4 + proof.r1cs_receipt.len();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(IVC_SANGRIA_PROOF_DOMAIN);
    out.extend_from_slice(&2u16.to_be_bytes()); // version
    out.extend_from_slice(&proof.num_wires.to_be_bytes());
    out.extend_from_slice(&(proof.wire_commitments.len() as u32).to_be_bytes());
    for wc in &proof.wire_commitments {
        out.extend_from_slice(wc);
    }
    out.extend_from_slice(&proof.acc_commitment);
    out.extend_from_slice(&proof.t_commitment);
    out.extend_from_slice(&proof.folding_challenge);
    out.extend_from_slice(&(proof.opening_proof.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.opening_proof);
    out.extend_from_slice(&(proof.public_inputs.len() as u32).to_be_bytes());
    for pi in &proof.public_inputs {
        out.extend_from_slice(pi);
    }
    match &proof.snark_proof {
        Some(snark) => {
            out.push(1u8);
            out.extend_from_slice(&(snark.len() as u32).to_be_bytes());
            out.extend_from_slice(snark);
        }
        None => {
            out.push(0u8);
        }
    }
    out.extend_from_slice(&(proof.r1cs_receipt.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.r1cs_receipt);
    out
}

fn decode_ivc_basefold_proof(bytes: &[u8]) -> Result<BaseFoldPcsOpeningProof, String> {
    if !bytes.starts_with(IVC_PROOF_DOMAIN) {
        return Err("ivc proof bytes missing domain tag".to_string());
    }
    let mut off = IVC_PROOF_DOMAIN.len();

    let read_u16 = |bytes: &[u8], off: &mut usize| -> Result<u16, String> {
        let s = bytes
            .get(*off..*off + 2)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        *off += 2;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let s = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        *off += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    };
    fn read_slice<'a>(bytes: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], String> {
        let s = bytes
            .get(*off..*off + len)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        *off += len;
        Ok(s)
    }

    let version = read_u16(bytes, &mut off)?;
    if version != 1 {
        return Err(format!("ivc proof bytes unsupported version={version}"));
    }
    let n_vars = read_u32(bytes, &mut off)? as usize;
    if n_vars == 0 {
        return Err("ivc proof n_vars must be > 0".to_string());
    }
    if n_vars > IVC_PCS_MAX_VARS {
        return Err("ivc proof n_vars exceeds max".to_string());
    }
    let digest_len = read_u32(bytes, &mut off)? as usize;
    if digest_len == 0 {
        return Err("ivc proof must include at least one instance digest".to_string());
    }
    let mut instance_digests = Vec::with_capacity(digest_len);
    for _ in 0..digest_len {
        let d = read_slice(bytes, &mut off, 32)?;
        instance_digests.push(
            d.try_into()
                .map_err(|_| "instance digest length mismatch".to_string())?,
        );
    }
    let weights_len = read_u32(bytes, &mut off)? as usize;
    let mut weights = Vec::with_capacity(weights_len);
    for _ in 0..weights_len {
        let w = read_slice(bytes, &mut off, 16)?;
        let w = b128_from_be_bytes(
            w.try_into()
                .map_err(|_| "weight length mismatch".to_string())?,
        );
        weights.push(w);
    }
    let commitment_root = read_slice(bytes, &mut off, 32)?;
    let commitment_root: [u8; 32] = commitment_root
        .try_into()
        .map_err(|_| "commitment root length mismatch".to_string())?;
    let commitment_depth = read_u32(bytes, &mut off)? as usize;
    let commitment_n_vars = read_u32(bytes, &mut off)? as usize;
    let commitment_security_bits = read_u16(bytes, &mut off)? as usize;
    let commitment_security_target_bits = read_u16(bytes, &mut off)? as usize;
    let commitment_log_inv_rate = read_u16(bytes, &mut off)? as usize;
    let commitment_fold_arity = read_u16(bytes, &mut off)? as usize;
    if commitment_n_vars != n_vars {
        return Err("ivc proof commitment n_vars mismatch".to_string());
    }
    if commitment_security_bits == 0 || commitment_log_inv_rate == 0 {
        return Err("ivc proof commitment params invalid".to_string());
    }
    if commitment_security_target_bits < commitment_security_bits {
        return Err("ivc proof commitment target bits invalid".to_string());
    }
    let commitment = BaseFoldCommitment {
        root: commitment_root,
        depth: commitment_depth,
        n_vars: commitment_n_vars,
        security_bits: commitment_security_bits,
        security_target_bits: commitment_security_target_bits,
        log_inv_rate: commitment_log_inv_rate,
        fold_arity: commitment_fold_arity,
    };
    let eval_len = read_u32(bytes, &mut off)? as usize;
    if eval_len != n_vars {
        return Err("ivc proof eval_point length mismatch".to_string());
    }
    let mut eval_point = Vec::with_capacity(eval_len);
    for _ in 0..eval_len {
        let x = read_slice(bytes, &mut off, 16)?;
        let x = b128_from_be_bytes(
            x.try_into()
                .map_err(|_| "eval point length mismatch".to_string())?,
        );
        eval_point.push(x);
    }
    let claimed_eval = read_slice(bytes, &mut off, 16)?;
    let claimed_eval = b128_from_be_bytes(
        claimed_eval
            .try_into()
            .map_err(|_| "claimed eval length mismatch".to_string())?,
    );
    let proof_len = read_u32(bytes, &mut off)? as usize;
    let proof_bytes = read_slice(bytes, &mut off, proof_len)?;
    let proofs = decode_basefold_proof(proof_bytes)?;
    if off != bytes.len() {
        return Err("ivc proof bytes trailing data".to_string());
    }

    Ok(BaseFoldPcsOpeningProof {
        instance_digests,
        weights,
        commitment,
        eval_point,
        claimed_eval,
        proofs,
    })
}

struct ByteReaderBytes {
    buf: Bytes,
    off: usize,
}

impl ByteReaderBytes {
    fn new(bytes: &[u8]) -> Self {
        Self {
            buf: Bytes::copy_from_slice(bytes),
            off: 0,
        }
    }

    fn from_bytes(buf: Bytes) -> Self {
        Self { buf, off: 0 }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.buf.len()
    }

    fn advance(&mut self, len: usize) -> Result<(), String> {
        let end = self
            .off
            .checked_add(len)
            .ok_or_else(|| "reader advance overflow".to_string())?;
        if end > self.buf.len() {
            return Err("reader advance out of bounds".to_string());
        }
        self.off = end;
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let end = self
            .off
            .checked_add(1)
            .ok_or_else(|| "u8 offset overflow".to_string())?;
        if end > self.buf.len() {
            return Err("u8 read out of bounds".to_string());
        }
        let value = self.buf[self.off];
        self.off = end;
        Ok(value)
    }

    fn read_u16_be(&mut self) -> Result<u16, String> {
        let end = self
            .off
            .checked_add(2)
            .ok_or_else(|| "u16 offset overflow".to_string())?;
        if end > self.buf.len() {
            return Err("u16 read out of bounds".to_string());
        }
        let mut tmp = [0u8; 2];
        tmp.copy_from_slice(&self.buf[self.off..end]);
        self.off = end;
        Ok(u16::from_be_bytes(tmp))
    }

    fn read_u32_be(&mut self) -> Result<u32, String> {
        let end = self
            .off
            .checked_add(4)
            .ok_or_else(|| "u32 offset overflow".to_string())?;
        if end > self.buf.len() {
            return Err("u32 read out of bounds".to_string());
        }
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&self.buf[self.off..end]);
        self.off = end;
        Ok(u32::from_be_bytes(tmp))
    }

    fn read_bytes(&mut self, len: usize) -> Result<Bytes, String> {
        let end = self
            .off
            .checked_add(len)
            .ok_or_else(|| "bytes length overflow".to_string())?;
        if end > self.buf.len() {
            return Err("bytes read out of bounds".to_string());
        }
        let out = self.buf.slice(self.off..end);
        self.off = end;
        Ok(out)
    }

    fn read_array_32(&mut self) -> Result<[u8; 32], String> {
        let bytes = self.read_bytes(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn is_end(&self) -> bool {
        self.off == self.buf.len()
    }
}

pub fn decode_ivc_proof_bytes(bytes: &[u8]) -> Result<IvcProof, String> {
    if !bytes.starts_with(IVC_PROOF_DOMAIN) {
        return Err("ivc proof bytes missing domain tag".to_string());
    }
    let mut reader = ByteReaderBytes::new(bytes);
    reader.advance(IVC_PROOF_DOMAIN.len())?;
    let version = reader.read_u16_be()?;
    if version == 1 {
        let basefold = decode_ivc_basefold_proof(bytes)?;
        return Ok(IvcProof::BaseFold(basefold));
    }
    if version != 2 {
        return Err(format!("ivc proof bytes unsupported version={version}"));
    }
    let proof_type = reader.read_u8()?;
    let payload_len = reader.read_u32_be()? as usize;
    let payload = reader.read_bytes(payload_len)?;
    if !reader.is_end() {
        return Err("ivc proof bytes trailing data".to_string());
    }
    let proof_type = crate::adapters::IvcProofType::from_u8(proof_type)?;
    match proof_type {
        crate::adapters::IvcProofType::BaseFoldTransparent => {
            let basefold = decode_ivc_basefold_proof(payload.as_ref())?;
            Ok(IvcProof::BaseFold(basefold))
        }
        crate::adapters::IvcProofType::Nova => {
            let proof = decode_nova_proof_bytes_owned(payload)?;
            Ok(IvcProof::Nova(proof))
        }
        crate::adapters::IvcProofType::SuperNova => {
            let proof = decode_supernova_proof_bytes_owned(payload)?;
            Ok(IvcProof::SuperNova(proof))
        }
        crate::adapters::IvcProofType::HyperNova => {
            let proof = decode_hypernova_proof_bytes_owned(payload)?;
            Ok(IvcProof::HyperNova(proof))
        }
        crate::adapters::IvcProofType::Sangria => {
            let proof = decode_sangria_proof_bytes_owned(payload)?;
            Ok(IvcProof::Sangria(proof))
        }
    }
}

/// Decode Nova folding proof from canonical bytes.
pub fn decode_nova_proof_bytes(bytes: &[u8]) -> Result<NovaFoldingProof, String> {
    decode_nova_proof_bytes_owned(Bytes::copy_from_slice(bytes))
}

fn decode_nova_proof_bytes_owned(bytes: Bytes) -> Result<NovaFoldingProof, String> {
    if !bytes.starts_with(IVC_NOVA_PROOF_DOMAIN) {
        return Err("Nova proof bytes missing domain tag".to_string());
    }
    let mut reader = ByteReaderBytes::from_bytes(bytes);
    reader.advance(IVC_NOVA_PROOF_DOMAIN.len())?;
    let version = reader.read_u16_be()?;
    if version != 2 {
        return Err(format!("Nova proof unsupported version={version}"));
    }
    let u = reader.read_array_32()?;
    let e_commitment = reader.read_array_32()?;
    let w_commitment = reader.read_array_32()?;
    let pi_len = reader.read_u32_be()? as usize;
    let mut public_inputs = Vec::with_capacity(pi_len);
    for _ in 0..pi_len {
        public_inputs.push(reader.read_array_32()?);
    }
    let t_commitment = reader.read_array_32()?;
    let acc_u = reader.read_array_32()?;
    let acc_e_commitment = reader.read_array_32()?;
    let acc_w_commitment = reader.read_array_32()?;
    let snark_flag = reader.read_u8()?;
    let snark_proof = if snark_flag == 1 {
        let len = reader.read_u32_be()? as usize;
        Some(reader.read_bytes(len)?)
    } else if snark_flag == 0 {
        None
    } else {
        return Err("invalid snark flag".to_string());
    };
    let r1cs_len = reader.read_u32_be()? as usize;
    let r1cs_receipt = reader.read_bytes(r1cs_len)?;
    if !reader.is_end() {
        return Err("Nova proof bytes trailing data".to_string());
    }

    Ok(NovaFoldingProof {
        u,
        e_commitment,
        w_commitment,
        public_inputs,
        t_commitment,
        acc_u,
        acc_e_commitment,
        acc_w_commitment,
        snark_proof,
        r1cs_receipt,
    })
}

/// Decode SuperNova non-uniform IVC proof from canonical bytes.
pub fn decode_supernova_proof_bytes(bytes: &[u8]) -> Result<SuperNovaProof, String> {
    decode_supernova_proof_bytes_owned(Bytes::copy_from_slice(bytes))
}

fn decode_supernova_proof_bytes_owned(bytes: Bytes) -> Result<SuperNovaProof, String> {
    if !bytes.starts_with(IVC_SUPERNOVA_PROOF_DOMAIN) {
        return Err("SuperNova proof bytes missing domain tag".to_string());
    }
    let mut reader = ByteReaderBytes::from_bytes(bytes);
    reader.advance(IVC_SUPERNOVA_PROOF_DOMAIN.len())?;
    let version = reader.read_u16_be()?;
    if version != 2 {
        return Err(format!("SuperNova proof unsupported version={version}"));
    }
    let num_circuits = reader.read_u16_be()?;
    let selector_index = reader.read_u16_be()?;
    if selector_index >= num_circuits {
        return Err("SuperNova selector_index >= num_circuits".to_string());
    }
    let ric_len = reader.read_u32_be()? as usize;
    if ric_len != num_circuits as usize {
        return Err("SuperNova running_instance_commitments length mismatch".to_string());
    }
    let mut running_instance_commitments = Vec::with_capacity(ric_len);
    for _ in 0..ric_len {
        running_instance_commitments.push(reader.read_array_32()?);
    }
    let step_u = reader.read_array_32()?;
    let step_e_commitment = reader.read_array_32()?;
    let step_w_commitment = reader.read_array_32()?;
    let step_t_commitment = reader.read_array_32()?;
    let pi_len = reader.read_u32_be()? as usize;
    let mut public_inputs = Vec::with_capacity(pi_len);
    for _ in 0..pi_len {
        public_inputs.push(reader.read_array_32()?);
    }
    let snark_flag = reader.read_u8()?;
    let snark_proof = if snark_flag == 1 {
        let len = reader.read_u32_be()? as usize;
        Some(reader.read_bytes(len)?)
    } else if snark_flag == 0 {
        None
    } else {
        return Err("invalid snark flag".to_string());
    };
    let r1cs_len = reader.read_u32_be()? as usize;
    let r1cs_receipt = reader.read_bytes(r1cs_len)?;
    if !reader.is_end() {
        return Err("SuperNova proof bytes trailing data".to_string());
    }

    Ok(SuperNovaProof {
        num_circuits,
        selector_index,
        running_instance_commitments,
        step_u,
        step_e_commitment,
        step_w_commitment,
        step_t_commitment,
        public_inputs,
        snark_proof,
        r1cs_receipt,
    })
}

/// Decode HyperNova CCS multi-folding proof from canonical bytes.
pub fn decode_hypernova_proof_bytes(bytes: &[u8]) -> Result<HyperNovaProof, String> {
    decode_hypernova_proof_bytes_owned(Bytes::copy_from_slice(bytes))
}

fn decode_hypernova_proof_bytes_owned(bytes: Bytes) -> Result<HyperNovaProof, String> {
    if !bytes.starts_with(IVC_HYPERNOVA_PROOF_DOMAIN) {
        return Err("HyperNova proof bytes missing domain tag".to_string());
    }
    let mut reader = ByteReaderBytes::from_bytes(bytes);
    reader.advance(IVC_HYPERNOVA_PROOF_DOMAIN.len())?;
    let version = reader.read_u16_be()?;
    if version != 2 {
        return Err(format!("HyperNova proof unsupported version={version}"));
    }
    let num_vars = reader.read_u32_be()?;
    let num_constraints = reader.read_u32_be()?;
    let degree = reader.read_u16_be()?;
    if degree == 0 {
        return Err("HyperNova degree must be > 0".to_string());
    }
    let ccs_commitment = reader.read_array_32()?;
    let sumcheck_len = reader.read_u32_be()? as usize;
    let sumcheck_proof = reader.read_bytes(sumcheck_len)?;
    let final_claim = reader.read_array_32()?;
    let pcs_len = reader.read_u32_be()? as usize;
    let pcs_opening = reader.read_bytes(pcs_len)?;
    let pi_len = reader.read_u32_be()? as usize;
    let mut public_inputs = Vec::with_capacity(pi_len);
    for _ in 0..pi_len {
        public_inputs.push(reader.read_array_32()?);
    }
    let snark_flag = reader.read_u8()?;
    let snark_proof = if snark_flag == 1 {
        let len = reader.read_u32_be()? as usize;
        Some(reader.read_bytes(len)?)
    } else if snark_flag == 0 {
        None
    } else {
        return Err("invalid snark flag".to_string());
    };
    let r1cs_len = reader.read_u32_be()? as usize;
    let r1cs_receipt = reader.read_bytes(r1cs_len)?;
    if !reader.is_end() {
        return Err("HyperNova proof bytes trailing data".to_string());
    }

    Ok(HyperNovaProof {
        num_vars,
        num_constraints,
        degree,
        ccs_commitment,
        sumcheck_proof,
        final_claim,
        pcs_opening,
        public_inputs,
        snark_proof,
        r1cs_receipt,
    })
}

/// Decode Sangria PLONKish folding proof from canonical bytes.
pub fn decode_sangria_proof_bytes(bytes: &[u8]) -> Result<SangriaProof, String> {
    decode_sangria_proof_bytes_owned(Bytes::copy_from_slice(bytes))
}

fn decode_sangria_proof_bytes_owned(bytes: Bytes) -> Result<SangriaProof, String> {
    if !bytes.starts_with(IVC_SANGRIA_PROOF_DOMAIN) {
        return Err("Sangria proof bytes missing domain tag".to_string());
    }
    let mut reader = ByteReaderBytes::from_bytes(bytes);
    reader.advance(IVC_SANGRIA_PROOF_DOMAIN.len())?;
    let version = reader.read_u16_be()?;
    if version != 2 {
        return Err(format!("Sangria proof unsupported version={version}"));
    }
    let num_wires = reader.read_u16_be()?;
    let wc_len = reader.read_u32_be()? as usize;
    if wc_len != num_wires as usize {
        return Err("Sangria wire_commitments length mismatch".to_string());
    }
    let mut wire_commitments = Vec::with_capacity(wc_len);
    for _ in 0..wc_len {
        wire_commitments.push(reader.read_array_32()?);
    }
    let acc_commitment = reader.read_array_32()?;
    let t_commitment = reader.read_array_32()?;
    let folding_challenge = reader.read_array_32()?;
    let op_len = reader.read_u32_be()? as usize;
    let opening_proof = reader.read_bytes(op_len)?;
    let pi_len = reader.read_u32_be()? as usize;
    let mut public_inputs = Vec::with_capacity(pi_len);
    for _ in 0..pi_len {
        public_inputs.push(reader.read_array_32()?);
    }
    let snark_flag = reader.read_u8()?;
    let snark_proof = if snark_flag == 1 {
        let len = reader.read_u32_be()? as usize;
        Some(reader.read_bytes(len)?)
    } else if snark_flag == 0 {
        None
    } else {
        return Err("invalid snark flag".to_string());
    };
    let r1cs_len = reader.read_u32_be()? as usize;
    let r1cs_receipt = reader.read_bytes(r1cs_len)?;
    if !reader.is_end() {
        return Err("Sangria proof bytes trailing data".to_string());
    }

    Ok(SangriaProof {
        num_wires,
        wire_commitments,
        acc_commitment,
        t_commitment,
        folding_challenge,
        opening_proof,
        public_inputs,
        snark_proof,
        r1cs_receipt,
    })
}

fn derive_glyph_artifact_from_basefold_pcs_opening(
    opening: &BaseFoldPcsOpeningProof,
) -> Result<([u8; 32], [u8; 32], u128), String> {
    verify_basefold_pcs_opening(opening)?;

    let commitment_tag = derive_basefold_commitment_tag(&opening.commitment);
    let point_tag = derive_basefold_point_tag(&commitment_tag, &opening.eval_point);
    let claim_u128 = opening.claimed_eval.to_underlier();
    Ok((commitment_tag, point_tag, claim_u128))
}

/// Derive GLYPH artifact from Nova folding proof.
///
/// The artifact is derived as:
/// - commitment_tag: keccak256(NOVA_COMMIT_DOMAIN || receipt_hash || acc_w_commitment || acc_e_commitment)
/// - point_tag: keccak256(NOVA_POINT_DOMAIN || receipt_hash || t_commitment || public_inputs...)
/// - claim128: keccak256(NOVA_CLAIM_DOMAIN || receipt_hash || acc_u || u)[0..16] interpreted as u128
fn derive_glyph_artifact_from_nova_proof(
    proof: &NovaFoldingProof,
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let (receipt, receipt_hash) = verify_r1cs_receipt_and_hash(proof.r1cs_receipt.as_ref())?;
    validate_nova_fields(proof, &receipt_hash)?;
    let snark_proof = proof
        .snark_proof
        .as_ref()
        .ok_or_else(|| "Nova external proof is required".to_string())?;
    verify_nova_external_proof_bytes(&receipt, snark_proof.as_ref())?;

    // Commitment tag: hash of accumulated witness and error commitments
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_NOVA_COMMIT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.acc_w_commitment);
    keccak.update(&proof.acc_e_commitment);
    let mut commitment_tag = [0u8; 32];
    keccak.finalize(&mut commitment_tag);

    // Point tag: hash of cross-term and public inputs
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_NOVA_POINT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.t_commitment);
    for pi in &proof.public_inputs {
        keccak.update(pi);
    }
    let mut point_tag = [0u8; 32];
    keccak.finalize(&mut point_tag);

    // Claim: truncated hash of scalar factors
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_NOVA_CLAIM_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.acc_u);
    keccak.update(&proof.u);
    let mut claim_hash = [0u8; 32];
    keccak.finalize(&mut claim_hash);
    let claim_u128 = u128::from_be_bytes(
        claim_hash[0..16]
            .try_into()
            .map_err(|_| "claim hash length mismatch".to_string())?,
    );

    Ok((commitment_tag, point_tag, claim_u128))
}

/// Derive GLYPH artifact from SuperNova non-uniform IVC proof.
///
/// The artifact is derived by hashing the running instance commitments and
/// the selected circuit's step proof, all bound to the receipt hash.
fn derive_glyph_artifact_from_supernova_proof(
    proof: &SuperNovaProof,
) -> Result<([u8; 32], [u8; 32], u128), String> {
    if proof.num_circuits == 0 {
        return Err("SuperNova num_circuits must be > 0".to_string());
    }
    if proof.running_instance_commitments.is_empty() {
        return Err("SuperNova must have running instance commitments".to_string());
    }

    let (receipt, receipt_hash) = verify_r1cs_receipt_and_hash(proof.r1cs_receipt.as_ref())?;
    validate_supernova_fields(proof, &receipt_hash)?;
    let snark_bytes = proof
        .snark_proof
        .as_ref()
        .ok_or_else(|| "SuperNova external proof required".to_string())?;
    verify_supernova_external(&receipt, snark_bytes.as_ref())?;

    // Commitment tag: hash of all running instance commitments
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_SUPERNOVA_COMMIT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    for c in &proof.running_instance_commitments {
        keccak.update(c);
    }
    let mut commitment_tag = [0u8; 32];
    keccak.finalize(&mut commitment_tag);

    // Point tag: hash of selector info and step proof data
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_SUPERNOVA_POINT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.num_circuits.to_be_bytes());
    keccak.update(&proof.selector_index.to_be_bytes());
    keccak.update(&proof.step_t_commitment);
    for pi in &proof.public_inputs {
        keccak.update(pi);
    }
    let mut point_tag = [0u8; 32];
    keccak.finalize(&mut point_tag);

    // Claim: hash of step_u and selected running instance
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_SUPERNOVA_CLAIM_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.step_u);
    if let Some(selected) = proof.running_instance_commitments.get(proof.selector_index as usize) {
        keccak.update(selected);
    }
    let mut claim_hash = [0u8; 32];
    keccak.finalize(&mut claim_hash);
    let claim_u128 = u128::from_be_bytes(
        claim_hash[0..16]
            .try_into()
            .map_err(|_| "claim hash length mismatch".to_string())?,
    );

    Ok((commitment_tag, point_tag, claim_u128))
}

#[cfg(feature = "ivc-supernova")]
fn verify_supernova_external(receipt: &R1csReceipt, bytes: &[u8]) -> Result<(), String> {
    crate::ivc_supernova::verify_supernova_external_proof_bytes(receipt, bytes)
}

#[cfg(not(feature = "ivc-supernova"))]
fn verify_supernova_external(_receipt: &R1csReceipt, _bytes: &[u8]) -> Result<(), String> {
    Err("SuperNova support disabled; enable feature ivc-supernova".to_string())
}

/// Derive GLYPH artifact from HyperNova CCS multi-folding proof.
///
/// Commitment, point, and claim tags are bound to the receipt hash.
fn derive_glyph_artifact_from_hypernova_proof(
    proof: &HyperNovaProof,
) -> Result<([u8; 32], [u8; 32], u128), String> {
    if proof.degree == 0 {
        return Err("HyperNova degree must be > 0".to_string());
    }
    let (receipt, receipt_hash) = verify_r1cs_receipt_and_hash(proof.r1cs_receipt.as_ref())?;
    validate_hypernova_fields(proof, &receipt, &receipt_hash)?;
    let snark_bytes = proof
        .snark_proof
        .as_ref()
        .ok_or_else(|| "HyperNova external proof required".to_string())?;
    verify_hypernova_external_proof_bytes(&receipt, snark_bytes.as_ref())?;

    // Commitment tag: hash of CCS commitment and constraints
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_HYPERNOVA_COMMIT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.ccs_commitment);
    keccak.update(&proof.num_vars.to_be_bytes());
    keccak.update(&proof.num_constraints.to_be_bytes());
    let mut commitment_tag = [0u8; 32];
    keccak.finalize(&mut commitment_tag);

    // Point tag: hash of sumcheck proof and final claim
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_HYPERNOVA_POINT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.sumcheck_proof);
    keccak.update(&proof.final_claim);
    for pi in &proof.public_inputs {
        keccak.update(pi);
    }
    let mut point_tag = [0u8; 32];
    keccak.finalize(&mut point_tag);

    // Claim: from final_claim
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_HYPERNOVA_CLAIM_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.final_claim);
    let mut claim_hash = [0u8; 32];
    keccak.finalize(&mut claim_hash);
    let claim_u128 = u128::from_be_bytes(
        claim_hash[0..16]
            .try_into()
            .map_err(|_| "claim hash length mismatch".to_string())?,
    );

    Ok((commitment_tag, point_tag, claim_u128))
}

/// Derive GLYPH artifact from Sangria PLONKish folding proof.
///
/// Commitment, point, and claim tags are bound to the receipt hash.
fn derive_glyph_artifact_from_sangria_proof(
    proof: &SangriaProof,
) -> Result<([u8; 32], [u8; 32], u128), String> {
    if proof.wire_commitments.is_empty() {
        return Err("Sangria must have wire commitments".to_string());
    }
    let (receipt, receipt_hash) = verify_r1cs_receipt_and_hash(proof.r1cs_receipt.as_ref())?;
    validate_sangria_fields(proof, &receipt_hash)?;
    let snark_bytes = proof
        .snark_proof
        .as_ref()
        .ok_or_else(|| "Sangria external proof required".to_string())?;
    verify_sangria_external_proof_bytes(&receipt, snark_bytes.as_ref())?;

    // Commitment tag: hash of all wire commitments and accumulator
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_SANGRIA_COMMIT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    for wc in &proof.wire_commitments {
        keccak.update(wc);
    }
    keccak.update(&proof.acc_commitment);
    let mut commitment_tag = [0u8; 32];
    keccak.finalize(&mut commitment_tag);

    // Point tag: hash of cross-term and challenge
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_SANGRIA_POINT_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.t_commitment);
    keccak.update(&proof.folding_challenge);
    for pi in &proof.public_inputs {
        keccak.update(pi);
    }
    let mut point_tag = [0u8; 32];
    keccak.finalize(&mut point_tag);

    // Claim: from folding challenge
    let mut keccak = Keccak::v256();
    keccak.update(GLYPH_IVC_SANGRIA_CLAIM_TAG_DOMAIN);
    keccak.update(&receipt_hash);
    keccak.update(&proof.folding_challenge);
    let mut claim_hash = [0u8; 32];
    keccak.finalize(&mut claim_hash);
    let claim_u128 = u128::from_be_bytes(
        claim_hash[0..16]
            .try_into()
            .map_err(|_| "claim hash length mismatch".to_string())?,
    );

    Ok((commitment_tag, point_tag, claim_u128))
}

pub fn derive_glyph_artifact_from_ivc_direct(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    crate::adapters::apply_ivc_profile_defaults();
    let vk = decode_ivc_vk_bytes(adapter_vk_bytes)?;
    let statement = decode_ivc_statement_bytes(adapter_statement_bytes)?;
    if vk.gkr_arity != 4 {
        return Err("ivc vk gkr_arity must be 4".to_string());
    }
    if vk.claim_bits != 128 {
        return Err("ivc vk claim_bits must be 128".to_string());
    }
    if vk.gkr_rounds == 0 {
        return Err("ivc vk gkr_rounds must be > 0".to_string());
    }
    if vk.proof_type != statement.proof_type {
        return Err("ivc vk proof_type mismatch with statement".to_string());
    }
    let proof = decode_ivc_proof_bytes(proof_bytes)?;
    let derived = match proof {
        IvcProof::BaseFold(opening)
            if vk.proof_type == crate::adapters::IvcProofType::BaseFoldTransparent =>
        {
            derive_glyph_artifact_from_basefold_pcs_opening(&opening)?
        }
        IvcProof::Nova(proof) if vk.proof_type == crate::adapters::IvcProofType::Nova => {
            derive_glyph_artifact_from_nova_proof(&proof)?
        }
        IvcProof::SuperNova(proof)
            if vk.proof_type == crate::adapters::IvcProofType::SuperNova =>
        {
            derive_glyph_artifact_from_supernova_proof(&proof)?
        }
        IvcProof::HyperNova(proof)
            if vk.proof_type == crate::adapters::IvcProofType::HyperNova =>
        {
            derive_glyph_artifact_from_hypernova_proof(&proof)?
        }
        IvcProof::Sangria(proof)
            if vk.proof_type == crate::adapters::IvcProofType::Sangria =>
        {
            derive_glyph_artifact_from_sangria_proof(&proof)?
        }
        _ => {
            return Err("ivc proof_type does not match proof payload".to_string());
        }
    };
    if derived.0 != statement.commitment_tag || derived.1 != statement.point_tag || derived.2 != statement.claim128 {
        return Err("ivc statement does not match derived artifact".to_string());
    }
    Ok(derived)
}
pub fn derive_glyph_artifact_from_ivc(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let ir = crate::adapter_ir::AdapterIr {
        version: crate::adapter_ir::ADAPTER_IR_VERSION,
        ops: vec![crate::adapter_ir::AdapterIrOp {
            kernel_id: kernel_id::IVC_VERIFY,
            args: Vec::new(),
        }],
    };
    let ir_bytes = ir.encode();
    crate::adapter_ir::derive_glyph_artifact_from_ivc_ir(
        &ir_bytes,
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{ivc_statement_bytes, ivc_vk_bytes};
    use crate::adapters::keccak256;
    use crate::ivc_r1cs::{encode_r1cs_receipt, R1csConstraint, R1csLinearCombination, R1csReceipt, R1csTerm};
    use crate::glyph_basefold::{derive_binius_eval_point, derive_basefold_weights};
    use crate::pcs_basefold::{BaseFoldConfig, BaseFoldProver};
    use ark_bn254::Fr;
    use ark_ff::Field as ArkField;
    use binius_field::Field as BiniusField;

    fn fake_opening(seed: &[u8]) -> Result<BaseFoldPcsOpeningProof, String> {
        let inst = keccak256(seed);
        let instance_digests = vec![inst];
        let weights = derive_basefold_weights(&instance_digests)?;
        let n_vars = 3usize;
        let eval_point = derive_binius_eval_point(seed, 0, n_vars);
        let evals: Vec<BinaryField128b> = (0..(1usize << n_vars))
            .map(|i| BinaryField128b::from_underlier((i as u128) + 1))
            .collect();
        let config = BaseFoldConfig::default();
        let prover = BaseFoldProver::commit(&evals, n_vars, config)
            .map_err(|err| format!("basefold commit: {err}"))?;
        let commitment = prover.commitment();
        let opening = prover
            .open(&eval_point)
            .map_err(|err| format!("basefold open: {err}"))?;
        Ok(BaseFoldPcsOpeningProof {
            instance_digests,
            weights,
            commitment,
            eval_point,
            claimed_eval: opening.eval,
            proofs: opening.proofs,
        })
    }

    fn fake_r1cs_receipt() -> R1csReceipt {
        let one = Fr::ONE;
        let two = one + one;
        let three = two + one;
        let six = three + three;
        let constraint = R1csConstraint {
            a: R1csLinearCombination {
                terms: vec![R1csTerm { var_idx: 1, coeff: one }],
            },
            b: R1csLinearCombination {
                terms: vec![R1csTerm { var_idx: 2, coeff: one }],
            },
            c: R1csLinearCombination {
                terms: vec![R1csTerm { var_idx: 3, coeff: one }],
            },
        };
        R1csReceipt {
            num_vars: 4,
            num_constraints: 1,
            constraints: vec![constraint],
            witness: vec![one, two, three, six],
            u: one,
            error: vec![Fr::ZERO],
        }
    }

    #[test]
    fn test_ivc_proof_roundtrip() {
        let opening = match fake_opening(b"ivc-roundtrip") {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "fake_opening: {err}");
                return;
            }
        };
        let bytes = match encode_ivc_basefold_proof_bytes(&opening) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "encode: {err}");
                return;
            }
        };
        let decoded = match decode_ivc_proof_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        match decoded {
            IvcProof::BaseFold(parsed) => {
                assert_eq!(parsed, opening);
            }
            other => {
                assert!(false, "unexpected ivc proof variant: {other:?}");
                return;
            }
        }
    }

    #[test]
    fn test_ivc_adapter_roundtrip() {
        let opening = match fake_opening(b"ivc-adapter") {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "fake_opening: {err}");
                return;
            }
        };
        let proof_bytes = match encode_ivc_basefold_proof_bytes(&opening) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "encode: {err}");
                return;
            }
        };
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_basefold_pcs_opening(&opening) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        let vk_bytes = ivc_vk_bytes(4, crate::adapters::IvcProofType::BaseFoldTransparent);
        let stmt_bytes = ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            claim128,
            crate::adapters::IvcProofType::BaseFoldTransparent,
        );

        let res =
            match derive_glyph_artifact_from_ivc(&vk_bytes, &stmt_bytes, &proof_bytes) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_eq!(res.0.len(), 32);
        assert_eq!(res.1.len(), 32);
        assert_ne!(res.0, [0u8; 32]);
        assert_ne!(res.1, [0u8; 32]);
        assert_ne!(res.2, 0u128);
        assert_eq!(commitment_tag.len(), 32);
        assert_eq!(point_tag.len(), 32);
        assert_eq!(claim128, opening.claimed_eval.to_underlier());
    }

    #[test]
    fn test_ivc_decode_rejects_zero_nvars() {
        let opening = match fake_opening(b"ivc-nvars") {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "fake_opening: {err}");
                return;
            }
        };
        let mut bytes = match encode_ivc_basefold_proof_bytes(&opening) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "encode: {err}");
                return;
            }
        };
        let offset = IVC_PROOF_DOMAIN.len() + 2;
        bytes[offset..offset + 4].copy_from_slice(&0u32.to_be_bytes());
        assert!(decode_ivc_proof_bytes(&bytes).is_err());
    }

    #[test]
    fn test_ivc_transparent_rejects_tampered_commitment() {
        let mut opening = match fake_opening(b"ivc-tamper-commit") {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "fake_opening: {err}");
                return;
            }
        };
        opening.commitment.root = [0u8; 32];
        assert!(derive_glyph_artifact_from_basefold_pcs_opening(&opening).is_err());
    }

    #[test]
    fn test_ivc_transparent_rejects_tampered_eval() {
        let mut opening = match fake_opening(b"ivc-tamper-eval") {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "fake_opening: {err}");
                return;
            }
        };
        opening.claimed_eval += BinaryField128b::ONE;
        assert!(derive_glyph_artifact_from_basefold_pcs_opening(&opening).is_err());
    }

    #[test]
    fn test_ivc_transparent_rejects_tampered_transcript() {
        let mut opening = match fake_opening(b"ivc-tamper-transcript") {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "fake_opening: {err}");
                return;
            }
        };
        if let Some(first) = opening.proofs.first_mut() {
            let last = first.transcript.len().saturating_sub(1);
            if !first.transcript.is_empty() {
                let mut bytes = first.transcript.to_vec();
                bytes[last] ^= 0x01;
                first.transcript = Bytes::from(bytes);
            }
        }
        assert!(derive_glyph_artifact_from_basefold_pcs_opening(&opening).is_err());
    }

    // Nova folding proof tests

    fn fake_nova_proof(seed: &[u8]) -> Result<NovaFoldingProof, String> {
        let receipt = fake_r1cs_receipt();
        let receipt_bytes = encode_r1cs_receipt(&receipt);
        let receipt_hash = keccak256(&receipt_bytes);
        let snark_proof = crate::ivc_nova::generate_nova_external_proof_bytes(&receipt)
            .map_err(|err| format!("nova external proof: {err}"))?;
        let _ = seed;
        Ok(NovaFoldingProof {
            u: derive_receipt_tag(GLYPH_IVC_NOVA_U_TAG_DOMAIN, &receipt_hash),
            e_commitment: derive_receipt_tag(GLYPH_IVC_NOVA_E_TAG_DOMAIN, &receipt_hash),
            w_commitment: derive_receipt_tag(GLYPH_IVC_NOVA_W_TAG_DOMAIN, &receipt_hash),
            public_inputs: Vec::new(),
            t_commitment: derive_receipt_tag(GLYPH_IVC_NOVA_T_TAG_DOMAIN, &receipt_hash),
            acc_u: derive_receipt_tag(GLYPH_IVC_NOVA_ACC_U_TAG_DOMAIN, &receipt_hash),
            acc_e_commitment: derive_receipt_tag(GLYPH_IVC_NOVA_ACC_E_TAG_DOMAIN, &receipt_hash),
            acc_w_commitment: derive_receipt_tag(GLYPH_IVC_NOVA_ACC_W_TAG_DOMAIN, &receipt_hash),
            snark_proof: Some(Bytes::from(snark_proof)),
            r1cs_receipt: Bytes::from(receipt_bytes),
        })
    }

    #[test]
    fn test_nova_proof_roundtrip() {
        let proof = match fake_nova_proof(b"nova-roundtrip") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_nova_proof: {err}");
                return;
            }
        };
        let bytes = encode_nova_proof_bytes(&proof);
        let decoded = match decode_nova_proof_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_nova_artifact_derivation() {
        let proof = match fake_nova_proof(b"nova-artifact") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_nova_proof: {err}");
                return;
            }
        };
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_nova_proof(&proof) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_nova_decode_rejects_zero_u() {
        let mut proof = match fake_nova_proof(b"nova-zero-u") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_nova_proof: {err}");
                return;
            }
        };
        proof.u = [0u8; 32];
        // Derivation should fail for mismatched u
        assert!(derive_glyph_artifact_from_nova_proof(&proof).is_err());
    }

    #[test]
    fn test_nova_external_proof_tamper_fails() {
        let mut proof = match fake_nova_proof(b"nova-external-tamper") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_nova_proof: {err}");
                return;
            }
        };
        let mut snark = match proof.snark_proof.as_ref() {
            Some(snark) => snark.to_vec(),
            None => {
                assert!(false, "snark proof");
                return;
            }
        };
        let idx = snark.len().saturating_sub(1);
        snark[idx] ^= 0x01;
        proof.snark_proof = Some(Bytes::from(snark));
        assert!(derive_glyph_artifact_from_nova_proof(&proof).is_err());
    }

    // SuperNova non-uniform IVC tests

    #[cfg(feature = "ivc-supernova")]
    fn fake_supernova_proof(seed: &[u8]) -> Result<SuperNovaProof, String> {
        let receipt = fake_r1cs_receipt();
        let receipt_bytes = encode_r1cs_receipt(&receipt);
        let receipt_hash = keccak256(&receipt_bytes);
        let _ = seed;
        let snark_proof = load_ivc_supernova_external_proof_fixture()
            .map(Ok)
            .unwrap_or_else(|| generate_and_store_ivc_supernova_external_proof_fixture(&receipt))?;
        Ok(SuperNovaProof {
            num_circuits: IVC_SUPERNOVA_NUM_CIRCUITS,
            selector_index: IVC_SUPERNOVA_SELECTOR_INDEX,
            running_instance_commitments: vec![
                derive_receipt_tag_indexed(GLYPH_IVC_SUPERNOVA_RIC_TAG_DOMAIN, &receipt_hash, 0),
            ],
            step_u: derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_U_TAG_DOMAIN, &receipt_hash),
            step_e_commitment: derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_E_TAG_DOMAIN, &receipt_hash),
            step_w_commitment: derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_W_TAG_DOMAIN, &receipt_hash),
            step_t_commitment: derive_receipt_tag(GLYPH_IVC_SUPERNOVA_STEP_T_TAG_DOMAIN, &receipt_hash),
            public_inputs: Vec::new(),
            snark_proof: Some(Bytes::from(snark_proof)),
            r1cs_receipt: Bytes::from(receipt_bytes),
        })
    }

    #[cfg(feature = "ivc-supernova")]
    fn load_ivc_supernova_external_proof_fixture() -> Option<Vec<u8>> {
        if std::env::var("UPDATE_SNAPSHOTS").ok().as_deref() == Some("1") {
            return None;
        }
        let path = "scripts/tools/fixtures/ivc_supernova_external_proof.txt";
        let raw = std::fs::read_to_string(path).ok()?;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("proof_hex=") {
                return hex::decode(rest.trim()).ok();
            }
        }
        None
    }

    #[cfg(feature = "ivc-supernova")]
    fn generate_and_store_ivc_supernova_external_proof_fixture(
        receipt: &crate::ivc_r1cs::R1csReceipt,
    ) -> Result<Vec<u8>, String> {
        let proof = crate::ivc_supernova::generate_supernova_external_proof_bytes(receipt)
            .map_err(|err| format!("supernova external proof: {err}"))?;
        let path = "scripts/tools/fixtures/ivc_supernova_external_proof.txt";
        if let Some(parent) = std::path::Path::new(path).parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                return Err(format!("create fixture dir: {err}"));
            }
        }
        let content = format!("proof_hex={}\n", hex::encode(&proof));
        if let Err(err) = std::fs::write(path, content) {
            return Err(format!("write supernova external proof fixture: {err}"));
        }
        Ok(proof)
    }

    fn load_ivc_hypernova_external_proof_fixture() -> Option<Vec<u8>> {
        if std::env::var("UPDATE_SNAPSHOTS").ok().as_deref() == Some("1") {
            return None;
        }
        let path = "scripts/tools/fixtures/ivc_hypernova_external_proof.txt";
        let raw = std::fs::read_to_string(path).ok()?;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("proof_hex=") {
                return hex::decode(rest.trim()).ok();
            }
        }
        None
    }

    fn generate_and_store_ivc_hypernova_external_proof_fixture(
        receipt: &crate::ivc_r1cs::R1csReceipt,
    ) -> Result<Vec<u8>, String> {
        let proof = crate::ivc_hypernova::generate_hypernova_external_proof_bytes(receipt)
            .map_err(|err| format!("hypernova external proof: {err}"))?;
        let path = "scripts/tools/fixtures/ivc_hypernova_external_proof.txt";
        if let Some(parent) = std::path::Path::new(path).parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                return Err(format!("create fixture dir: {err}"));
            }
        }
        let content = format!("proof_hex={}\n", hex::encode(&proof));
        if let Err(err) = std::fs::write(path, content) {
            return Err(format!("write hypernova external proof fixture: {err}"));
        }
        Ok(proof)
    }

    fn load_ivc_sangria_external_proof_fixture() -> Option<Vec<u8>> {
        if std::env::var("UPDATE_SNAPSHOTS").ok().as_deref() == Some("1") {
            return None;
        }
        let path = "scripts/tools/fixtures/ivc_sangria_external_proof.txt";
        let raw = std::fs::read_to_string(path).ok()?;
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("proof_hex=") {
                return hex::decode(rest.trim()).ok();
            }
        }
        None
    }

    fn generate_and_store_ivc_sangria_external_proof_fixture(
        receipt: &crate::ivc_r1cs::R1csReceipt,
    ) -> Result<Vec<u8>, String> {
        let proof = crate::ivc_sangria::generate_sangria_external_proof_bytes(receipt)
            .map_err(|err| format!("sangria external proof: {err}"))?;
        let path = "scripts/tools/fixtures/ivc_sangria_external_proof.txt";
        if let Some(parent) = std::path::Path::new(path).parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                return Err(format!("create fixture dir: {err}"));
            }
        }
        let content = format!("proof_hex={}\n", hex::encode(&proof));
        if let Err(err) = std::fs::write(path, content) {
            return Err(format!("write sangria external proof fixture: {err}"));
        }
        Ok(proof)
    }

    #[cfg(feature = "ivc-supernova")]
    #[test]
    fn test_supernova_proof_roundtrip() {
        let proof = match fake_supernova_proof(b"supernova-roundtrip") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_supernova_proof: {err}");
                return;
            }
        };
        let bytes = encode_supernova_proof_bytes(&proof);
        let decoded = match decode_supernova_proof_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(decoded, proof);
    }

    #[cfg(feature = "ivc-supernova")]
    #[test]
    fn test_supernova_artifact_derivation() {
        let proof = match fake_supernova_proof(b"supernova-artifact") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_supernova_proof: {err}");
                return;
            }
        };
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_supernova_proof(&proof) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[cfg(feature = "ivc-supernova")]
    #[test]
    fn test_supernova_external_proof_tamper_fails() {
        let mut proof = match fake_supernova_proof(b"supernova-external-tamper") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_supernova_proof: {err}");
                return;
            }
        };
        let mut snark = match proof.snark_proof.as_ref() {
            Some(snark) => snark.to_vec(),
            None => {
                assert!(false, "snark proof");
                return;
            }
        };
        let idx = snark.len().saturating_sub(1);
        snark[idx] ^= 0x01;
        proof.snark_proof = Some(Bytes::from(snark));
        assert!(derive_glyph_artifact_from_supernova_proof(&proof).is_err());
    }

    #[cfg(feature = "ivc-supernova")]
    #[test]
    fn test_supernova_decode_rejects_invalid_selector() {
        let mut proof = match fake_supernova_proof(b"supernova-selector") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_supernova_proof: {err}");
                return;
            }
        };
        proof.selector_index = proof.num_circuits; // Invalid: selector >= num_circuits
        let bytes = encode_supernova_proof_bytes(&proof);
        assert!(decode_supernova_proof_bytes(&bytes).is_err());
    }

    // HyperNova CCS multi-folding tests

    fn fake_hypernova_proof(seed: &[u8]) -> Result<HyperNovaProof, String> {
        let receipt = fake_r1cs_receipt();
        let receipt_bytes = encode_r1cs_receipt(&receipt);
        let receipt_hash = keccak256(&receipt_bytes);
        let _ = seed;
        let snark_proof = load_ivc_hypernova_external_proof_fixture()
            .map(Ok)
            .unwrap_or_else(|| generate_and_store_ivc_hypernova_external_proof_fixture(&receipt))?;
        Ok(HyperNovaProof {
            num_vars: receipt.num_vars,
            num_constraints: receipt.num_constraints,
            degree: IVC_HYPERNOVA_DEGREE,
            ccs_commitment: derive_receipt_tag(GLYPH_IVC_HYPERNOVA_CCS_TAG_DOMAIN, &receipt_hash),
            sumcheck_proof: Bytes::new(),
            final_claim: derive_receipt_tag(GLYPH_IVC_HYPERNOVA_CLAIM_TAG_DOMAIN, &receipt_hash),
            pcs_opening: Bytes::new(),
            public_inputs: Vec::new(),
            snark_proof: Some(Bytes::from(snark_proof)),
            r1cs_receipt: Bytes::from(receipt_bytes),
        })
    }

    #[test]
    fn test_hypernova_proof_roundtrip() {
        let proof = match fake_hypernova_proof(b"hypernova-roundtrip") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_hypernova_proof: {err}");
                return;
            }
        };
        let bytes = encode_hypernova_proof_bytes(&proof);
        let decoded = match decode_hypernova_proof_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_hypernova_artifact_derivation() {
        let proof = match fake_hypernova_proof(b"hypernova-artifact") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_hypernova_proof: {err}");
                return;
            }
        };
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_hypernova_proof(&proof) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_hypernova_external_proof_tamper_fails() {
        let mut proof = match fake_hypernova_proof(b"hypernova-external-tamper") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_hypernova_proof: {err}");
                return;
            }
        };
        let mut snark = match proof.snark_proof.as_ref() {
            Some(snark) => snark.to_vec(),
            None => {
                assert!(false, "snark proof");
                return;
            }
        };
        let idx = snark.len().saturating_sub(1);
        snark[idx] ^= 0x01;
        proof.snark_proof = Some(Bytes::from(snark));
        assert!(derive_glyph_artifact_from_hypernova_proof(&proof).is_err());
    }

    #[test]
    fn test_hypernova_decode_rejects_zero_degree() {
        let mut proof = match fake_hypernova_proof(b"hypernova-degree") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_hypernova_proof: {err}");
                return;
            }
        };
        proof.degree = 0;
        let bytes = encode_hypernova_proof_bytes(&proof);
        assert!(decode_hypernova_proof_bytes(&bytes).is_err());
    }

    // Sangria PLONKish folding tests

    fn fake_sangria_proof(seed: &[u8]) -> Result<SangriaProof, String> {
        let receipt = fake_r1cs_receipt();
        let receipt_bytes = encode_r1cs_receipt(&receipt);
        let receipt_hash = keccak256(&receipt_bytes);
        let _ = seed;
        let snark_proof = load_ivc_sangria_external_proof_fixture()
            .map(Ok)
            .unwrap_or_else(|| generate_and_store_ivc_sangria_external_proof_fixture(&receipt))?;
        Ok(SangriaProof {
            num_wires: IVC_SANGRIA_NUM_WIRES,
            wire_commitments: vec![
                derive_receipt_tag_indexed(GLYPH_IVC_SANGRIA_WIRE_TAG_DOMAIN, &receipt_hash, 0),
            ],
            acc_commitment: derive_receipt_tag(GLYPH_IVC_SANGRIA_ACC_TAG_DOMAIN, &receipt_hash),
            t_commitment: derive_receipt_tag(GLYPH_IVC_SANGRIA_T_TAG_DOMAIN, &receipt_hash),
            folding_challenge: derive_receipt_tag(GLYPH_IVC_SANGRIA_CHALLENGE_TAG_DOMAIN, &receipt_hash),
            opening_proof: Bytes::new(),
            public_inputs: Vec::new(),
            snark_proof: Some(Bytes::from(snark_proof)),
            r1cs_receipt: Bytes::from(receipt_bytes),
        })
    }

    #[test]
    fn test_sangria_proof_roundtrip() {
        let proof = match fake_sangria_proof(b"sangria-roundtrip") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_sangria_proof: {err}");
                return;
            }
        };
        let bytes = encode_sangria_proof_bytes(&proof);
        let decoded = match decode_sangria_proof_bytes(&bytes) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(decoded, proof);
    }

    #[test]
    fn test_sangria_artifact_derivation() {
        let proof = match fake_sangria_proof(b"sangria-artifact") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_sangria_proof: {err}");
                return;
            }
        };
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_sangria_proof(&proof) {
                Ok(values) => values,
                Err(err) => {
                    assert!(false, "artifact: {err}");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_sangria_external_proof_tamper_fails() {
        let mut proof = match fake_sangria_proof(b"sangria-external-tamper") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_sangria_proof: {err}");
                return;
            }
        };
        let mut snark = match proof.snark_proof.as_ref() {
            Some(snark) => snark.to_vec(),
            None => {
                assert!(false, "snark proof");
                return;
            }
        };
        let idx = snark.len().saturating_sub(1);
        snark[idx] ^= 0x01;
        proof.snark_proof = Some(Bytes::from(snark));
        assert!(derive_glyph_artifact_from_sangria_proof(&proof).is_err());
    }

    #[test]
    fn test_sangria_decode_rejects_wire_mismatch() {
        let mut proof = match fake_sangria_proof(b"sangria-wires") {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "fake_sangria_proof: {err}");
                return;
            }
        };
        proof.num_wires = 5; // Mismatch: num_wires != wire_commitments.len()
        let bytes = encode_sangria_proof_bytes(&proof);
        assert!(decode_sangria_proof_bytes(&bytes).is_err());
    }
}
