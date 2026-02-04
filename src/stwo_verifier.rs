//! Native Stwo commitment-scheme verifier and program decoding for STARK.
//! This path is used when the canonical STARK program bytes carry the STWO tag.

use serde::{Deserialize, Serialize};
use ark_std::Zero;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::ColumnVec;
use stwo::core::verifier::PREPROCESSED_TRACE_IDX;
#[cfg(feature = "stwo-prover")]
use rayon::prelude::*;

use crate::circle_stark::FIELD_M31_CIRCLE_ID;
use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

pub const HASH_BLAKE2S_ID: u8 = 0x03;
pub const VC_MERKLE_ID: u8 = 0x01;

pub const STWO_PROFILE_TAG: &[u8] = b"STWO_PROFILE";
pub const STWO_PROFILE_VERSION: u16 = 1;

pub const STWO_PROGRAM_TAG: &[u8] = b"STWO_PROGRAM";
pub const STWO_PROGRAM_VERSION: u16 = 1;
pub const STWO_TOOLCHAIN_ID: u16 = 0x5354; // "ST"
#[cfg(feature = "stwo-prover")]
const STWO_PAR_MIN_DEFAULT: usize = 1 << 10;

#[cfg(feature = "stwo-prover")]
fn stwo_par_min() -> usize {
    std::env::var("GLYPH_STWO_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(STWO_PAR_MIN_DEFAULT)
        .max(1)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StwoProfile {
    pub log_domain_size: u8,
    pub num_queries: u8,
    pub blowup_factor: u8,
    pub log_last_layer_degree_bound: u8,
    pub pow_bits: u8,
}

impl StwoProfile {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(STWO_PROFILE_TAG) {
            return Err("stwo profile tag mismatch".to_string());
        }
        let mut off = STWO_PROFILE_TAG.len();
        let version = read_u16_be(bytes, &mut off)?;
        if version != STWO_PROFILE_VERSION {
            return Err(format!("unsupported stwo profile version={version}"));
        }
        let log_domain_size = read_u8(bytes, &mut off)?;
        let num_queries = read_u8(bytes, &mut off)?;
        let blowup_factor = read_u8(bytes, &mut off)?;
        let log_last_layer_degree_bound = read_u8(bytes, &mut off)?;
        let pow_bits = read_u8(bytes, &mut off)?;
        let reserved = read_u8(bytes, &mut off)?;
        if reserved != 0 {
            return Err("stwo profile reserved field must be zero".to_string());
        }
        if off != bytes.len() {
            return Err("stwo profile trailing data".to_string());
        }
        if log_domain_size == 0 {
            return Err("stwo profile log_domain_size must be > 0".to_string());
        }
        if num_queries == 0 {
            return Err("stwo profile num_queries must be > 0".to_string());
        }
        if blowup_factor == 0 {
            return Err("stwo profile blowup_factor must be > 0".to_string());
        }
        Ok(Self {
            log_domain_size,
            num_queries,
            blowup_factor,
            log_last_layer_degree_bound,
            pow_bits,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(STWO_PROFILE_TAG.len() + 2 + 6);
        out.extend_from_slice(STWO_PROFILE_TAG);
        out.extend_from_slice(&STWO_PROFILE_VERSION.to_be_bytes());
        out.push(self.log_domain_size);
        out.push(self.num_queries);
        out.push(self.blowup_factor);
        out.push(self.log_last_layer_degree_bound);
        out.push(self.pow_bits);
        out.push(0u8);
        out
    }

    pub fn to_pcs_config(&self) -> Result<PcsConfig, String> {
        if self.num_queries == 0 {
            return Err("stwo profile num_queries must be > 0".to_string());
        }
        if self.blowup_factor == 0 {
            return Err("stwo profile blowup_factor must be > 0".to_string());
        }
        let fri_config = FriConfig {
            log_blowup_factor: self.blowup_factor as u32,
            log_last_layer_degree_bound: self.log_last_layer_degree_bound as u32,
            n_queries: self.num_queries as usize,
        };
        Ok(PcsConfig {
            pow_bits: self.pow_bits as u32,
            fri_config,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StwoProgram {
    pub toolchain_id: u16,
    pub trace_width: u16,
    pub log_trace_length: u32,
    pub constraints: Vec<StwoConstraint>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StwoConstraint {
    pub expr: StwoExpr,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StwoExpr {
    Const(u32),
    Col { col: u16, offset: i16 },
    Add(Box<StwoExpr>, Box<StwoExpr>),
    Mul(Box<StwoExpr>, Box<StwoExpr>),
    Neg(Box<StwoExpr>),
}

impl StwoProgram {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if !bytes.starts_with(STWO_PROGRAM_TAG) {
            return Err("stwo program tag mismatch".to_string());
        }
        let mut off = STWO_PROGRAM_TAG.len();
        let version = read_u16_be(bytes, &mut off)?;
        if version != STWO_PROGRAM_VERSION {
            return Err(format!("unsupported stwo program version={version}"));
        }
        let toolchain_id = read_u16_be(bytes, &mut off)?;
        if toolchain_id != STWO_TOOLCHAIN_ID {
            return Err(format!("unsupported stwo toolchain_id=0x{toolchain_id:04x}"));
        }
        let trace_width = read_u16_be(bytes, &mut off)?;
        let log_trace_length = read_u32_be(bytes, &mut off)?;
        let constraint_len = read_u32_be(bytes, &mut off)? as usize;
        let mut constraints = Vec::with_capacity(constraint_len);
        for _ in 0..constraint_len {
            constraints.push(StwoConstraint {
                expr: decode_expr(bytes, &mut off, 0)?,
            });
        }
        if off != bytes.len() {
            return Err("stwo program trailing data".to_string());
        }
        let program = Self {
            toolchain_id,
            trace_width,
            log_trace_length,
            constraints,
        };
        program.validate()?;
        Ok(program)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            STWO_PROGRAM_TAG.len() + 2 + 2 + 2 + 4 + 4 + self.constraints.len() * 8,
        );
        out.extend_from_slice(STWO_PROGRAM_TAG);
        out.extend_from_slice(&STWO_PROGRAM_VERSION.to_be_bytes());
        out.extend_from_slice(&self.toolchain_id.to_be_bytes());
        out.extend_from_slice(&self.trace_width.to_be_bytes());
        out.extend_from_slice(&self.log_trace_length.to_be_bytes());
        out.extend_from_slice(&(self.constraints.len() as u32).to_be_bytes());
        for constraint in &self.constraints {
            encode_expr(&constraint.expr, &mut out);
        }
        out
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.trace_width == 0 {
            return Err("stwo program trace_width must be > 0".to_string());
        }
        if self.log_trace_length == 0 {
            return Err("stwo program log_trace_length must be > 0".to_string());
        }
        if self.constraints.is_empty() {
            return Err("stwo program must include constraints".to_string());
        }
        for constraint in &self.constraints {
            constraint.expr.validate(self.trace_width as usize)?;
        }
        Ok(())
    }
}

impl StwoExpr {
    fn validate(&self, trace_width: usize) -> Result<(), String> {
        match self {
            StwoExpr::Const(_) => Ok(()),
            StwoExpr::Col { col, .. } => {
                if *col as usize >= trace_width {
                    return Err("stwo program column index out of range".to_string());
                }
                Ok(())
            }
            StwoExpr::Add(lhs, rhs) | StwoExpr::Mul(lhs, rhs) => {
                lhs.validate(trace_width)?;
                rhs.validate(trace_width)?;
                Ok(())
            }
            StwoExpr::Neg(inner) => inner.validate(trace_width),
        }
    }

    fn eval(&self, cols: &[Vec<(i16, SecureField)>]) -> SecureField {
        match self {
            StwoExpr::Const(v) => SecureField::from(*v),
            StwoExpr::Col { col, offset } => {
                let idx = *col as usize;
                let entries = match cols.get(idx) {
                    Some(entries) => entries,
                    None => {
                        debug_assert!(false, "stwo column out of range");
                        return SecureField::zero();
                    }
                };
                for (off, value) in entries {
                    if off == offset {
                        return *value;
                    }
                }
                debug_assert!(false, "stwo missing column offset");
                SecureField::zero()
            }
            StwoExpr::Add(lhs, rhs) => lhs.eval(cols) + rhs.eval(cols),
            StwoExpr::Mul(lhs, rhs) => lhs.eval(cols) * rhs.eval(cols),
            StwoExpr::Neg(inner) => -inner.eval(cols),
        }
    }
}

struct StwoConstraintComponent {
    trace_width: usize,
    log_trace_length: u32,
    log_eval_length: u32,
    constraints: Vec<StwoConstraint>,
    mask_offsets: Vec<Vec<i16>>,
}

impl StwoConstraintComponent {
    fn new(program: &StwoProgram, log_blowup_factor: u8) -> Result<Self, String> {
        program.validate()?;
        let log_eval_length = program
            .log_trace_length
            .checked_add(log_blowup_factor as u32)
            .ok_or_else(|| "stwo program log_trace_length overflow".to_string())?;
        let mut mask_offsets: Vec<Vec<i16>> = vec![Vec::new(); program.trace_width as usize];
        for constraint in &program.constraints {
            collect_offsets(&constraint.expr, &mut mask_offsets);
        }
        for offsets in &mut mask_offsets {
            offsets.sort_unstable();
            offsets.dedup();
        }
        Ok(Self {
            trace_width: program.trace_width as usize,
            log_trace_length: program.log_trace_length,
            log_eval_length,
            constraints: program.constraints.clone(),
            mask_offsets,
        })
    }
}

impl Component for StwoConstraintComponent {
    fn n_constraints(&self) -> usize {
        self.constraints.len()
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_eval_length
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<ColumnVec<u32>> {
        TreeVec::new(vec![
            Vec::new(),
            vec![self.log_trace_length; self.trace_width],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
    ) -> TreeVec<ColumnVec<Vec<CirclePoint<SecureField>>>> {
        let step = CanonicCoset::new(self.log_trace_length).step().into_ef();
        let mut columns = Vec::with_capacity(self.trace_width);
        for offsets in &self.mask_offsets {
            if offsets.is_empty() {
                columns.push(Vec::new());
                continue;
            }
            let mut points = Vec::with_capacity(offsets.len());
            for offset in offsets {
                points.push(point + step.mul_signed(*offset as isize));
            }
            columns.push(points);
        }
        TreeVec::new(vec![Vec::new(), columns])
    }

    fn preprocessed_column_indices(&self) -> ColumnVec<usize> {
        Vec::new()
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<ColumnVec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
    ) {
        let columns = match mask.get(PREPROCESSED_TRACE_IDX + 1) {
            Some(columns) => columns,
            None => {
                debug_assert!(false, "stwo component mask missing trace tree");
                return;
            }
        };
        if columns.len() != self.trace_width {
            debug_assert!(false, "stwo mask width mismatch");
            return;
        }
        let mut col_values: Vec<Vec<(i16, SecureField)>> = Vec::with_capacity(self.trace_width);
        for (col, offsets) in columns.iter().zip(self.mask_offsets.iter()) {
            if col.len() != offsets.len() {
                debug_assert!(false, "stwo mask width mismatch");
                return;
            }
            let mut entries = Vec::with_capacity(offsets.len());
            for (idx, offset) in offsets.iter().enumerate() {
                entries.push((*offset, col[idx]));
            }
            col_values.push(entries);
        }

        let denom_inv = coset_vanishing(
            CanonicCoset::new(self.log_trace_length).coset,
            point,
        )
        .inverse();
        for constraint in &self.constraints {
            let eval = constraint.expr.eval(&col_values);
            evaluation_accumulator.accumulate(denom_inv * eval);
        }
    }
}

pub fn is_stwo_program_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(STWO_PROGRAM_TAG)
}

pub fn verify_stwo_receipt(
    receipt: &CanonicalStarkReceipt,
    vk: &CanonicalStarkVk,
) -> Result<(), String> {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_stwo_receipt_inner(receipt, vk)
    }));
    match res {
        Ok(inner) => inner,
        Err(_) => Err("stwo receipt verification panicked".to_string()),
    }
}

fn verify_stwo_receipt_inner(
    receipt: &CanonicalStarkReceipt,
    vk: &CanonicalStarkVk,
) -> Result<(), String> {
    if vk.field_id != FIELD_M31_CIRCLE_ID {
        return Err(format!(
            "stwo receipt field_id mismatch (expected 0x{FIELD_M31_CIRCLE_ID:02x})"
        ));
    }
    if vk.hash_id != HASH_BLAKE2S_ID {
        return Err("stwo receipt hash_id mismatch".to_string());
    }
    if vk.commitment_scheme_id != VC_MERKLE_ID {
        return Err("stwo receipt commitment_scheme_id mismatch".to_string());
    }

    let profile = StwoProfile::decode(&vk.consts_bytes)?;
    let pcs_config = profile.to_pcs_config()?;
    let program = StwoProgram::decode(&vk.program_bytes)?;

    if program.log_trace_length != profile.log_domain_size as u32 {
        return Err("stwo program log_trace_length mismatch with profile".to_string());
    }

    let proof: StarkProof<Blake2sMerkleHasher> =
        serde_json::from_slice(&receipt.proof_bytes)
            .map_err(|e| format!("stwo proof json decode failed: {e}"))?;
    let proof_config = &proof.0.config;
    if proof_config.pow_bits != pcs_config.pow_bits
        || proof_config.fri_config.log_blowup_factor != pcs_config.fri_config.log_blowup_factor
        || proof_config.fri_config.log_last_layer_degree_bound
            != pcs_config.fri_config.log_last_layer_degree_bound
        || proof_config.fri_config.n_queries != pcs_config.fri_config.n_queries
    {
        return Err("stwo proof config mismatch with profile".to_string());
    }

    let component = StwoConstraintComponent::new(&program, profile.blowup_factor)?;
    let mut channel = Blake2sChannel::default();
    mix_public_inputs(&mut channel, &receipt.pub_inputs_bytes);

    let mut commitment_scheme =
        CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(pcs_config);

    if proof.commitments.is_empty() {
        return Err("stwo proof missing commitments".to_string());
    }

    let column_log_sizes = component.trace_log_degree_bounds();
    let expected_commitments = column_log_sizes.len() + 1;
    if proof.commitments.len() != expected_commitments {
        return Err("stwo proof commitment count mismatch".to_string());
    }

    for (root, log_sizes) in proof
        .commitments
        .iter()
        .take(proof.commitments.len() - 1)
        .zip(column_log_sizes.iter())
    {
        commitment_scheme.commit(*root, log_sizes, &mut channel);
    }

    let composition_log_size = component.max_constraint_log_degree_bound();
    if composition_log_size == 0 {
        return Err("stwo program composition_log_size invalid".to_string());
    }
    let random_coeff = channel.draw_secure_felt();
    let composition_root = *proof
        .commitments
        .last()
        .ok_or_else(|| "stwo proof missing composition commitment".to_string())?;
    let composition_log_sizes =
        vec![composition_log_size - 1; 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE];
    commitment_scheme.commit(composition_root, &composition_log_sizes, &mut channel);

    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
    let mut sample_points = component.mask_points(oods_point);
    sample_points
        .0
        .push(vec![vec![oods_point]; 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE]);

    let composition_oods_eval =
        extract_composition_oods_eval(&proof, oods_point, composition_log_size)?;
    let expected = stwo::core::air::Components {
        components: vec![&component],
        n_preprocessed_columns: 0,
    }
    .eval_composition_polynomial_at_point(
        oods_point,
        &proof.sampled_values,
        random_coeff,
    );
    if composition_oods_eval != expected {
        return Err("stwo proof OODS mismatch".to_string());
    }

    commitment_scheme
        .verify_values(sample_points, proof.0, &mut channel)
        .map_err(|e| format!("stwo proof verify failed: {e}"))?;

    Ok(())
}

fn extract_composition_oods_eval(
    proof: &StarkProof<Blake2sMerkleHasher>,
    oods_point: CirclePoint<SecureField>,
    composition_log_size: u32,
) -> Result<SecureField, String> {
    if composition_log_size < 2 {
        return Err("stwo composition_log_size too small".to_string());
    }
    let Some(left_and_right_mask) = proof.sampled_values.last() else {
        return Err("stwo proof missing composition mask".to_string());
    };
    let expected_len = 2 * stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    if left_and_right_mask.len() != expected_len {
        return Err("stwo proof composition mask width mismatch".to_string());
    }
    let mut evals = Vec::with_capacity(expected_len);
    for column in left_and_right_mask {
        let Some(&eval) = column.first() else {
            return Err("stwo proof composition mask missing eval".to_string());
        };
        if column.len() != 1 {
            return Err("stwo proof composition mask has extra evals".to_string());
        }
        evals.push(eval);
    }
    let left = &evals[..expected_len / 2];
    let right = &evals[expected_len / 2..];
    let left_eval = SecureField::from_partial_evals(
        left.try_into().map_err(|_| "stwo composition mask invalid".to_string())?,
    );
    let right_eval = SecureField::from_partial_evals(
        right.try_into().map_err(|_| "stwo composition mask invalid".to_string())?,
    );
    let x = oods_point.repeated_double(composition_log_size - 2).x;
    Ok(left_eval + x * right_eval)
}

fn mix_public_inputs(channel: &mut Blake2sChannel, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut words = Vec::with_capacity(bytes.len().div_ceil(4));
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        words.push(u32::from_le_bytes(word));
    }
    channel.mix_u32s(&words);
}

fn decode_expr(bytes: &[u8], off: &mut usize, depth: usize) -> Result<StwoExpr, String> {
    if depth > 512 {
        return Err("stwo program expr depth too large".to_string());
    }
    let tag = read_u8(bytes, off)?;
    match tag {
        0x00 => {
            let v = read_u32_be(bytes, off)?;
            Ok(StwoExpr::Const(v))
        }
        0x01 => {
            let col = read_u16_be(bytes, off)?;
            let offset = read_i16_be(bytes, off)?;
            Ok(StwoExpr::Col { col, offset })
        }
        0x02 => {
            let lhs = decode_expr(bytes, off, depth + 1)?;
            let rhs = decode_expr(bytes, off, depth + 1)?;
            Ok(StwoExpr::Add(Box::new(lhs), Box::new(rhs)))
        }
        0x03 => {
            let lhs = decode_expr(bytes, off, depth + 1)?;
            let rhs = decode_expr(bytes, off, depth + 1)?;
            Ok(StwoExpr::Mul(Box::new(lhs), Box::new(rhs)))
        }
        0x04 => {
            let inner = decode_expr(bytes, off, depth + 1)?;
            Ok(StwoExpr::Neg(Box::new(inner)))
        }
        _ => Err("stwo program expr tag invalid".to_string()),
    }
}

fn encode_expr(expr: &StwoExpr, out: &mut Vec<u8>) {
    match expr {
        StwoExpr::Const(v) => {
            out.push(0x00);
            out.extend_from_slice(&v.to_be_bytes());
        }
        StwoExpr::Col { col, offset } => {
            out.push(0x01);
            out.extend_from_slice(&col.to_be_bytes());
            out.extend_from_slice(&offset.to_be_bytes());
        }
        StwoExpr::Add(lhs, rhs) => {
            out.push(0x02);
            encode_expr(lhs, out);
            encode_expr(rhs, out);
        }
        StwoExpr::Mul(lhs, rhs) => {
            out.push(0x03);
            encode_expr(lhs, out);
            encode_expr(rhs, out);
        }
        StwoExpr::Neg(inner) => {
            out.push(0x04);
            encode_expr(inner, out);
        }
    }
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

fn read_i16_be(bytes: &[u8], off: &mut usize) -> Result<i16, String> {
    let s = bytes.get(*off..*off + 2).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(i16::from_be_bytes([s[0], s[1]]))
}

fn collect_offsets(expr: &StwoExpr, offsets: &mut [Vec<i16>]) {
    match expr {
        StwoExpr::Const(_) => {}
        StwoExpr::Col { col, offset } => {
            if let Some(entry) = offsets.get_mut(*col as usize) {
                entry.push(*offset);
            }
        }
        StwoExpr::Add(lhs, rhs) | StwoExpr::Mul(lhs, rhs) => {
            collect_offsets(lhs, offsets);
            collect_offsets(rhs, offsets);
        }
        StwoExpr::Neg(inner) => collect_offsets(inner, offsets),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stwo_program_roundtrip_and_offsets() {
        let program = StwoProgram {
            toolchain_id: STWO_TOOLCHAIN_ID,
            trace_width: 2,
            log_trace_length: 4,
            constraints: vec![StwoConstraint {
                expr: StwoExpr::Add(
                    Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                    Box::new(StwoExpr::Mul(
                        Box::new(StwoExpr::Col { col: 1, offset: 1 }),
                        Box::new(StwoExpr::Const(7)),
                    )),
                ),
            }],
        };
        let bytes = program.encode();
        let decoded = match StwoProgram::decode(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(program, decoded);

        let component = match StwoConstraintComponent::new(&decoded, 1) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "component");
                return;
            }
        };
        assert_eq!(component.mask_offsets.len(), 2);
        assert_eq!(component.mask_offsets[0], vec![0]);
        assert_eq!(component.mask_offsets[1], vec![1]);
    }

    #[cfg(feature = "stwo-prover")]
    mod stwo_prover_tests {
        use super::*;

        #[test]
        fn test_stwo_synthetic_receipt_e2e() {
            let profile = StwoProfile {
                log_domain_size: 3,
                num_queries: 2,
                blowup_factor: 1,
                log_last_layer_degree_bound: 1,
                pow_bits: 0,
            };
            let program = StwoProgram {
                toolchain_id: STWO_TOOLCHAIN_ID,
                trace_width: 1,
                log_trace_length: profile.log_domain_size as u32,
                constraints: vec![StwoConstraint {
                    expr: StwoExpr::Add(
                        Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                        Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
                    ),
                }],
            };

            let proof_bytes =
                match super::synthesize_stwo_proof_bytes(&program, &profile, &[]) {
                    Ok(value) => value,
                    Err(_) => {
                        assert!(false, "proof bytes");
                        return;
                    }
                };
            let vk = CanonicalStarkVk {
                version: 1,
                field_id: FIELD_M31_CIRCLE_ID,
                hash_id: HASH_BLAKE2S_ID,
                commitment_scheme_id: VC_MERKLE_ID,
                consts_bytes: profile.encode(),
                program_bytes: program.encode(),
            };
            let receipt = CanonicalStarkReceipt {
                proof_bytes,
                pub_inputs_bytes: Vec::new(),
                vk_bytes: vk.encode(),
            };

            let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "vk decode");
                    return;
                }
            };
            if let Err(_) = verify_stwo_receipt(&receipt, &decoded_vk) {
                assert!(false, "verify");
            }
        }
    }
}

#[cfg(feature = "stwo-prover")]
mod stwo_prover_support {
    use super::*;
    use serde_json;
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::constraints::coset_vanishing;
    use stwo::core::fields::FieldExpOps;
    use stwo::core::fields::m31::BaseField;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::utils::bit_reverse_index;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
    use stwo::prover::backend::{Col, CpuBackend};
    use stwo::prover::backend::ColumnOps;
    use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
    use stwo::prover::poly::BitReversedOrder;
    use stwo::prover::{
        prove, CommitmentSchemeProver, ComponentProver, DomainEvaluationAccumulator, Trace,
    };

    impl ComponentProver<CpuBackend> for StwoConstraintComponent {
        fn evaluate_constraint_quotients_on_domain(
            &self,
            trace: &Trace<'_, CpuBackend>,
            evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
        ) {
            if self.constraints.is_empty() {
                return;
            }

            let eval_domain = CanonicCoset::new(self.log_eval_length).circle_domain();
            let trace_coset = CanonicCoset::new(self.log_trace_length);
        let trace_tree = match trace.polys.get(PREPROCESSED_TRACE_IDX + 1) {
            Some(tree) => tree,
            None => {
                debug_assert!(false, "stwo trace tree missing");
                return;
            }
        };
            let step = trace_coset.step().into_ef();

            let [mut accum] = evaluation_accumulator
                .columns([(eval_domain.log_size(), self.n_constraints())]);
            accum.random_coeff_powers.reverse();

            let log_expand = eval_domain.log_size() - trace_coset.log_size();
            let mut denom_inv = (0..1 << log_expand)
                .map(|i| {
                    coset_vanishing(
                        trace_coset.coset,
                        eval_domain.at(i).into_ef::<SecureField>(),
                    )
                    .inverse()
                })
                .collect::<Vec<_>>();
            stwo::core::utils::bit_reverse(&mut denom_inv);
            let total_rows = 1usize << eval_domain.log_size();
            if total_rows >= stwo_par_min() && rayon::current_num_threads() > 1 {
                let row_res = (0..total_rows)
                    .into_par_iter()
                    .map(|row| {
                        let point: stwo::core::circle::CirclePoint<SecureField> =
                            eval_domain
                                .at(bit_reverse_index(row, eval_domain.log_size()))
                                .into_ef();
                        let mut col_values: Vec<Vec<(i16, SecureField)>> =
                            Vec::with_capacity(self.trace_width);
                        for (col_idx, offsets) in self.mask_offsets.iter().enumerate() {
                            let poly = match trace_tree.get(col_idx) {
                                Some(poly) => poly,
                                None => {
                                    debug_assert!(false, "stwo trace column missing");
                                    continue;
                                }
                            };
                            let mut entries = Vec::with_capacity(offsets.len());
                            for offset in offsets {
                                let mask_point = point + step.mul_signed(*offset as isize);
                                let value = poly.eval_at_point(mask_point, None);
                                entries.push((*offset, value));
                            }
                            col_values.push(entries);
                        }
                        let mut row_sum = SecureField::default();
                        let denom = denom_inv[row >> trace_coset.log_size()];
                        for (pow, constraint) in accum
                            .random_coeff_powers
                            .iter()
                            .zip(self.constraints.iter())
                        {
                            let eval = constraint.expr.eval(&col_values);
                            row_sum += *pow * (eval * denom);
                        }
                        row_sum
                    })
                    .collect::<Vec<_>>();

                for (row, row_sum) in row_res.into_iter().enumerate() {
                    let cur = accum.col.at(row);
                    accum.col.set(row, cur + row_sum);
                }
            } else {
                for row in 0..total_rows {
                    let point: stwo::core::circle::CirclePoint<SecureField> =
                        eval_domain
                            .at(bit_reverse_index(row, eval_domain.log_size()))
                            .into_ef();

                    let mut col_values: Vec<Vec<(i16, SecureField)>> =
                        Vec::with_capacity(self.trace_width);
                    for (col_idx, offsets) in self.mask_offsets.iter().enumerate() {
                        let poly = match trace_tree.get(col_idx) {
                            Some(poly) => poly,
                            None => {
                                debug_assert!(false, "stwo trace column missing");
                                continue;
                            }
                        };
                        let mut entries = Vec::with_capacity(offsets.len());
                        for offset in offsets {
                            let mask_point = point + step.mul_signed(*offset as isize);
                            let value = poly.eval_at_point(mask_point, None);
                            entries.push((*offset, value));
                        }
                        col_values.push(entries);
                    }

                    let mut row_res = SecureField::default();
                    for (pow, constraint) in accum
                        .random_coeff_powers
                        .iter()
                        .zip(self.constraints.iter())
                    {
                        let eval = constraint.expr.eval(&col_values);
                        row_res += *pow * (eval * denom_inv[row >> trace_coset.log_size()]);
                    }

                    let cur = accum.col.at(row);
                    accum.col.set(row, cur + row_res);
                }
            }
        }
    }

    pub fn synthesize_stwo_proof_bytes(
        program: &StwoProgram,
        profile: &StwoProfile,
        pub_inputs_bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        let pcs_config = profile.to_pcs_config()?;
        let log_blowup = pcs_config.fri_config.log_blowup_factor;
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(program.log_trace_length + log_blowup)
                .circle_domain()
                .half_coset,
        );

        let mut channel = Blake2sChannel::default();
        mix_public_inputs(&mut channel, pub_inputs_bytes);

        let mut commitment_scheme =
            CommitmentSchemeProver::<CpuBackend, Blake2sMerkleChannel>::new(pcs_config, &twiddles);
        commitment_scheme.set_store_polynomials_coefficients();

        let tree_builder = commitment_scheme.tree_builder();
        tree_builder.commit(&mut channel);

        let trace_domain = CanonicCoset::new(program.log_trace_length).circle_domain();
        let n_rows = 1usize << program.log_trace_length;
        let mut col: Col<CpuBackend, BaseField> = (0..n_rows)
            .map(|i| BaseField::from((i as u32) + 1))
            .collect();
        CpuBackend::bit_reverse_column(&mut col);
        let evals = CircleEvaluation::<CpuBackend, BaseField, BitReversedOrder>::new(
            trace_domain,
            col,
        );

        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals([evals]);
        tree_builder.commit(&mut channel);

        let component = StwoConstraintComponent::new(program, profile.blowup_factor)?;

        let proof = prove::<CpuBackend, Blake2sMerkleChannel>(
            &[&component],
            &mut channel,
            commitment_scheme,
        )
        .map_err(|e| format!("stwo proof generation failed: {e}"))?;
        serde_json::to_vec(&proof).map_err(|e| format!("proof json encode failed: {e}"))
    }
}

#[cfg(feature = "stwo-prover")]
pub use stwo_prover_support::synthesize_stwo_proof_bytes;
