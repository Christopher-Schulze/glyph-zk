//! Circle STARK verifier for M31 and Baby Bear domains with Circle FRI.

use crate::circle_fri::{CircleFriProof, verify_circle_fri};
use crate::circle_merkle;
use crate::stark_transcript::StarkTranscript;
use rayon::prelude::*;
use crate::baby_bear_field::{
    BABY_BEAR_MODULUS,
    baby_bear_add_mod,
    baby_bear_mul_mod,
    baby_bear_sub_mod,
    baby_bear_from_be_bytes_strict,
    baby_bear_from_hash,
};
use crate::koala_bear_field::{
    KOALA_BEAR_MODULUS,
    koala_bear_add_mod,
    koala_bear_mul_mod,
    koala_bear_sub_mod,
    koala_bear_from_be_bytes_strict,
    koala_bear_from_hash,
};
use crate::m31_field::{
    M31_MODULUS,
    m31_add_mod,
    m31_mul_mod,
    m31_sub_mod,
    m31_from_be_bytes_strict,
    m31_from_hash,
};
use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

pub const FIELD_M31_CIRCLE_ID: u8 = 0x03;
pub const FIELD_BABY_BEAR_CIRCLE_ID: u8 = 0x04;
pub const FIELD_KOALA_BEAR_CIRCLE_ID: u8 = 0x06;
pub const HASH_BLAKE3_ID: u8 = crate::stark_hash::HASH_BLAKE3_ID;
pub const HASH_SHA3_ID: u8 = crate::stark_hash::HASH_SHA3_ID;
pub const HASH_POSEIDON_ID: u8 = crate::stark_hash::HASH_POSEIDON_ID;
pub const HASH_RESCUE_ID: u8 = crate::stark_hash::HASH_RESCUE_ID;
pub const VC_MERKLE_ID: u8 = 0x01;

pub const CIRCLE_STARK_PROFILE_TAG: &[u8] = b"CIRCLE_STARK_PROFILE";
pub const CIRCLE_STARK_PROFILE_VERSION: u16 = 1;

pub const CIRCLE_STARK_SIMPLE_PROGRAM_TAG: &[u8] = b"CIRCLE_STARK_PROGRAM";
pub const CIRCLE_STARK_SIMPLE_PROGRAM_VERSION: u16 = 1;
pub const CIRCLE_STARK_EXPR_PROGRAM_TAG: &[u8] = b"CIRCLE_STARK_PROGRAM_ADVANCED";
pub const CIRCLE_STARK_EXPR_PROGRAM_VERSION: u16 = 2;

pub const CIRCLE_STARK_PROOF_TAG: &[u8] = b"CIRCLE_STARK_PROOF";
pub const CIRCLE_STARK_PROOF_VERSION: u16 = 1;

pub const CONSTRAINT_CUBE_PLUS_CONST: u8 = 1;
pub const CONSTRAINT_LINEAR_MIX: u8 = 2;
pub const CONSTRAINT_MUL_PLUS_CONST: u8 = 3;
pub const CONSTRAINT_LINEAR_COMBO: u8 = 4;
pub const CONSTRAINT_MUL_ADD: u8 = 5;

pub const CONSTRAINT_OUTPUT_NONE: u16 = 0xffff;

pub const CIRCLE_STARK_TRANSCRIPT: &[u8] = b"GLYPH_CIRCLE_STARK_TRANSCRIPT";
pub const DOMAIN_CIRCLE_STARK: &[u8] = b"CIRCLE_STARK";
const CIRCLE_STARK_PAR_MIN_DEFAULT: usize = 1 << 10;

fn circle_stark_par_min() -> usize {
    std::env::var("GLYPH_CIRCLE_STARK_PAR_MIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(CIRCLE_STARK_PAR_MIN_DEFAULT)
        .max(1)
}

fn tag_offset(bytes: &[u8], tag: &[u8]) -> Result<usize, String> {
    if !bytes.starts_with(tag) {
        return Err("circle tag mismatch".to_string());
    }
    let mut off = tag.len();
    if bytes.len() >= off + 3 && bytes[off] == b'_' && bytes[off + 1] == b'V' && bytes[off + 2].is_ascii_digit()
    {
        off += 2;
        while off < bytes.len() && bytes[off].is_ascii_digit() {
            off += 1;
        }
    }
    Ok(off)
}

#[derive(Clone, Copy)]
struct FieldOps {
    modulus: u32,
    add: fn(u32, u32) -> u32,
    sub: fn(u32, u32) -> u32,
    mul: fn(u32, u32) -> u32,
    from_be_bytes_strict: fn([u8; 4]) -> Result<u32, String>,
    from_hash: fn(&[u8; 32]) -> u32,
}

fn field_ops_for_id(field_id: u8) -> Result<FieldOps, String> {
    match field_id {
        FIELD_M31_CIRCLE_ID => Ok(FieldOps {
            modulus: M31_MODULUS,
            add: m31_add_mod,
            sub: m31_sub_mod,
            mul: m31_mul_mod,
            from_be_bytes_strict: m31_from_be_bytes_strict,
            from_hash: m31_from_hash,
        }),
        FIELD_BABY_BEAR_CIRCLE_ID => Ok(FieldOps {
            modulus: BABY_BEAR_MODULUS,
            add: baby_bear_add_mod,
            sub: baby_bear_sub_mod,
            mul: baby_bear_mul_mod,
            from_be_bytes_strict: baby_bear_from_be_bytes_strict,
            from_hash: baby_bear_from_hash,
        }),
        FIELD_KOALA_BEAR_CIRCLE_ID => Ok(FieldOps {
            modulus: KOALA_BEAR_MODULUS,
            add: koala_bear_add_mod,
            sub: koala_bear_sub_mod,
            mul: koala_bear_mul_mod,
            from_be_bytes_strict: koala_bear_from_be_bytes_strict,
            from_hash: koala_bear_from_hash,
        }),
        _ => Err("unsupported circle field_id".to_string()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleStarkProfile {
    pub version: u16,
    pub log_domain_size: u8,
    pub num_queries: u8,
    pub blowup_factor: u8,
}

impl CircleStarkProfile {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CIRCLE_STARK_PROFILE_TAG.len() + 2 + 3 + 1);
        out.extend_from_slice(CIRCLE_STARK_PROFILE_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.log_domain_size);
        out.push(self.num_queries);
        out.push(self.blowup_factor);
        out.push(0u8);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CIRCLE_STARK_PROFILE_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != CIRCLE_STARK_PROFILE_VERSION {
            return Err(format!("unsupported circle profile version={version}"));
        }
        let log_domain_size = read_u8(bytes, &mut off)?;
        let num_queries = read_u8(bytes, &mut off)?;
        let blowup_factor = read_u8(bytes, &mut off)?;
        let reserved = read_u8(bytes, &mut off)?;
        if reserved != 0 {
            return Err("circle profile reserved field must be zero".to_string());
        }
        if off != bytes.len() {
            return Err("circle profile trailing data".to_string());
        }
        if log_domain_size == 0 {
            return Err("circle profile log_domain_size must be > 0".to_string());
        }
        if num_queries == 0 {
            return Err("circle profile num_queries must be > 0".to_string());
        }
        Ok(Self {
            version,
            log_domain_size,
            num_queries,
            blowup_factor,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleStarkSimpleProgram {
    pub version: u16,
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    pub trace_width: u16,
    pub trace_length: u32,
    pub constraints: Vec<CircleConstraint>,
    pub air_id: Vec<u8>,
}

impl CircleStarkSimpleProgram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            CIRCLE_STARK_SIMPLE_PROGRAM_TAG.len()
                + 2
                + 3
                + 2
                + 4
                + 2
                + self.constraints.len() * (1 + 2 + 2 + 2 + 4)
                + 2
                + self.air_id.len(),
        );
        out.extend_from_slice(CIRCLE_STARK_SIMPLE_PROGRAM_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.extend_from_slice(&self.trace_width.to_be_bytes());
        out.extend_from_slice(&self.trace_length.to_be_bytes());
        out.extend_from_slice(&(self.constraints.len() as u16).to_be_bytes());
        for c in &self.constraints {
            out.push(c.id);
            out.extend_from_slice(&c.col.to_be_bytes());
            out.extend_from_slice(&c.a.to_be_bytes());
            out.extend_from_slice(&c.b.to_be_bytes());
            out.extend_from_slice(&c.constant.to_be_bytes());
        }
        out.extend_from_slice(&(self.air_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.air_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CIRCLE_STARK_SIMPLE_PROGRAM_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != CIRCLE_STARK_SIMPLE_PROGRAM_VERSION {
            return Err(format!("unsupported circle program version={version}"));
        }
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;
        let trace_width = read_u16_be(bytes, &mut off)?;
        let trace_length = read_u32_be(bytes, &mut off)?;
        let constraint_len = read_u16_be(bytes, &mut off)? as usize;
        let mut constraints = Vec::with_capacity(constraint_len);
        for _ in 0..constraint_len {
            let id = read_u8(bytes, &mut off)?;
            let col = read_u16_be(bytes, &mut off)?;
            let a = read_u16_be(bytes, &mut off)?;
            let b = read_u16_be(bytes, &mut off)?;
            let constant = read_u32_be(bytes, &mut off)?;
            constraints.push(CircleConstraint {
                id,
                col,
                a,
                b,
                constant,
            });
        }
        let air_len = read_u16_be(bytes, &mut off)? as usize;
        let air_id = read_vec(bytes, &mut off, air_len)?;
        if off != bytes.len() {
            return Err("circle program trailing data".to_string());
        }
        if trace_width == 0 {
            return Err("circle program trace_width must be > 0".to_string());
        }
        if trace_length == 0 {
            return Err("circle program trace_length must be > 0".to_string());
        }
        Ok(Self {
            version,
            field_id,
            hash_id,
            commitment_scheme_id,
            trace_width,
            trace_length,
            constraints,
            air_id,
        })
    }
}

impl CircleStarkExprProgram {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CIRCLE_STARK_EXPR_PROGRAM_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.extend_from_slice(&self.trace_width.to_be_bytes());
        out.extend_from_slice(&self.trace_length.to_be_bytes());
        out.extend_from_slice(&(self.constraints.len() as u16).to_be_bytes());
        for c in &self.constraints {
            out.push(c.id);
            out.extend_from_slice(&c.out_col.to_be_bytes());
            out.push(c.out_is_next);
            out.extend_from_slice(&c.a.to_be_bytes());
            out.push(c.a_is_next);
            out.extend_from_slice(&c.b.to_be_bytes());
            out.push(c.b_is_next);
            out.extend_from_slice(&c.constant.to_be_bytes());
            out.extend_from_slice(&(c.terms.len() as u16).to_be_bytes());
            for t in &c.terms {
                out.extend_from_slice(&t.col.to_be_bytes());
                out.extend_from_slice(&t.coeff.to_be_bytes());
                out.push(t.is_next);
            }
        }
        out.extend_from_slice(&(self.air_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.air_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CIRCLE_STARK_EXPR_PROGRAM_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != CIRCLE_STARK_EXPR_PROGRAM_VERSION {
            return Err(format!("unsupported circle program version={version}"));
        }
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;
        let trace_width = read_u16_be(bytes, &mut off)?;
        let trace_length = read_u32_be(bytes, &mut off)?;
        let constraint_len = read_u16_be(bytes, &mut off)? as usize;
        let mut constraints = Vec::with_capacity(constraint_len);
        for _ in 0..constraint_len {
            let id = read_u8(bytes, &mut off)?;
            let out_col = read_u16_be(bytes, &mut off)?;
            let out_is_next = read_u8(bytes, &mut off)?;
            let a = read_u16_be(bytes, &mut off)?;
            let a_is_next = read_u8(bytes, &mut off)?;
            let b = read_u16_be(bytes, &mut off)?;
            let b_is_next = read_u8(bytes, &mut off)?;
            let constant = read_u32_be(bytes, &mut off)?;
            let term_len = read_u16_be(bytes, &mut off)? as usize;
            let mut terms = Vec::with_capacity(term_len);
            for _ in 0..term_len {
                let col = read_u16_be(bytes, &mut off)?;
                let coeff = read_u32_be(bytes, &mut off)?;
                let is_next = read_u8(bytes, &mut off)?;
                terms.push(CircleConstraintTerm {
                    col,
                    coeff,
                    is_next,
                });
            }
            constraints.push(CircleExprConstraint {
                id,
                out_col,
                out_is_next,
                a,
                a_is_next,
                b,
                b_is_next,
                constant,
                terms,
            });
        }
        let air_len = read_u16_be(bytes, &mut off)? as usize;
        let air_id = read_vec(bytes, &mut off, air_len)?;
        if off != bytes.len() {
            return Err("circle program trailing data".to_string());
        }
        if trace_width == 0 {
            return Err("circle program trace_width must be > 0".to_string());
        }
        if trace_length == 0 {
            return Err("circle program trace_length must be > 0".to_string());
        }
        Ok(Self {
            version,
            field_id,
            hash_id,
            commitment_scheme_id,
            trace_width,
            trace_length,
            constraints,
            air_id,
        })
    }
}

pub fn decode_circle_stark_program(bytes: &[u8]) -> Result<CircleStarkProgram, String> {
    if bytes.starts_with(CIRCLE_STARK_EXPR_PROGRAM_TAG) {
        return Ok(CircleStarkProgram::Expr(CircleStarkExprProgram::decode(bytes)?));
    }
    if bytes.starts_with(CIRCLE_STARK_SIMPLE_PROGRAM_TAG) {
        return Ok(CircleStarkProgram::Simple(CircleStarkSimpleProgram::decode(bytes)?));
    }
    Err("unsupported circle program tag".to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleConstraint {
    pub id: u8,
    pub col: u16,
    pub a: u16,
    pub b: u16,
    pub constant: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleConstraintTerm {
    pub col: u16,
    pub coeff: u32,
    pub is_next: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleExprConstraint {
    pub id: u8,
    pub out_col: u16,
    pub out_is_next: u8,
    pub a: u16,
    pub a_is_next: u8,
    pub b: u16,
    pub b_is_next: u8,
    pub constant: u32,
    pub terms: Vec<CircleConstraintTerm>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleStarkExprProgram {
    pub version: u16,
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    pub trace_width: u16,
    pub trace_length: u32,
    pub constraints: Vec<CircleExprConstraint>,
    pub air_id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircleStarkProgram {
    Simple(CircleStarkSimpleProgram),
    Expr(CircleStarkExprProgram),
}

impl CircleStarkProgram {
    pub fn field_id(&self) -> u8 {
        match self {
            CircleStarkProgram::Simple(simple) => simple.field_id,
            CircleStarkProgram::Expr(expr) => expr.field_id,
        }
    }

    pub fn hash_id(&self) -> u8 {
        match self {
            CircleStarkProgram::Simple(simple) => simple.hash_id,
            CircleStarkProgram::Expr(expr) => expr.hash_id,
        }
    }

    pub fn commitment_scheme_id(&self) -> u8 {
        match self {
            CircleStarkProgram::Simple(simple) => simple.commitment_scheme_id,
            CircleStarkProgram::Expr(expr) => expr.commitment_scheme_id,
        }
    }

    pub fn trace_width(&self) -> u16 {
        match self {
            CircleStarkProgram::Simple(simple) => simple.trace_width,
            CircleStarkProgram::Expr(expr) => expr.trace_width,
        }
    }

    pub fn trace_length(&self) -> u32 {
        match self {
            CircleStarkProgram::Simple(simple) => simple.trace_length,
            CircleStarkProgram::Expr(expr) => expr.trace_length,
        }
    }

    pub fn constraints_len(&self) -> usize {
        match self {
            CircleStarkProgram::Simple(simple) => simple.constraints.len(),
            CircleStarkProgram::Expr(expr) => expr.constraints.len(),
        }
    }

    pub fn air_id(&self) -> &[u8] {
        match self {
            CircleStarkProgram::Simple(simple) => &simple.air_id,
            CircleStarkProgram::Expr(expr) => &expr.air_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleStarkTraceQuery {
    pub position: u32,
    pub row: Vec<u32>,
    pub next_row: Vec<u32>,
    pub row_proof: Vec<[u8; 32]>,
    pub next_row_proof: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleStarkProof {
    pub version: u16,
    pub trace_length: u32,
    pub trace_width: u16,
    pub trace_root: [u8; 32],
    pub first_row: Vec<u32>,
    pub first_row_proof: Vec<[u8; 32]>,
    pub last_row: Vec<u32>,
    pub last_row_proof: Vec<[u8; 32]>,
    pub queries: Vec<CircleStarkTraceQuery>,
    pub fri_proof: CircleFriProof,
}

impl CircleStarkProof {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        out.extend_from_slice(CIRCLE_STARK_PROOF_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.trace_length.to_be_bytes());
        out.extend_from_slice(&self.trace_width.to_be_bytes());
        out.extend_from_slice(&self.trace_root);
        encode_row(&mut out, self.trace_width, &self.first_row)?;
        encode_proof_vec(&mut out, &self.first_row_proof);
        encode_row(&mut out, self.trace_width, &self.last_row)?;
        encode_proof_vec(&mut out, &self.last_row_proof);
        out.extend_from_slice(&(self.queries.len() as u16).to_be_bytes());
        for q in &self.queries {
            out.extend_from_slice(&q.position.to_be_bytes());
            encode_row(&mut out, self.trace_width, &q.row)?;
            encode_row(&mut out, self.trace_width, &q.next_row)?;
            encode_proof_vec(&mut out, &q.row_proof);
            encode_proof_vec(&mut out, &q.next_row_proof);
        }
        let fri_bytes = self.fri_proof.encode();
        out.extend_from_slice(&(fri_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&fri_bytes);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CIRCLE_STARK_PROOF_TAG)?;
        let version = read_u16_be(bytes, &mut off)?;
        if version != CIRCLE_STARK_PROOF_VERSION {
            return Err(format!("unsupported circle proof version={version}"));
        }
        let trace_length = read_u32_be(bytes, &mut off)?;
        let trace_width = read_u16_be(bytes, &mut off)?;
        let trace_root = read_bytes32(bytes, &mut off)?;
        let first_row = decode_row(bytes, &mut off, trace_width)?;
        let first_row_proof = decode_proof_vec(bytes, &mut off)?;
        let last_row = decode_row(bytes, &mut off, trace_width)?;
        let last_row_proof = decode_proof_vec(bytes, &mut off)?;
        let q_len = read_u16_be(bytes, &mut off)? as usize;
        let mut queries = Vec::with_capacity(q_len);
        for _ in 0..q_len {
            let position = read_u32_be(bytes, &mut off)?;
            let row = decode_row(bytes, &mut off, trace_width)?;
            let next_row = decode_row(bytes, &mut off, trace_width)?;
            let row_proof = decode_proof_vec(bytes, &mut off)?;
            let next_row_proof = decode_proof_vec(bytes, &mut off)?;
            queries.push(CircleStarkTraceQuery {
                position,
                row,
                next_row,
                row_proof,
                next_row_proof,
            });
        }
        let fri_len = read_u32_be(bytes, &mut off)? as usize;
        let fri_bytes = read_vec(bytes, &mut off, fri_len)?;
        let fri_proof = CircleFriProof::decode(&fri_bytes)?;
        if off != bytes.len() {
            return Err("circle proof trailing data".to_string());
        }
        Ok(Self {
            version,
            trace_length,
            trace_width,
            trace_root,
            first_row,
            first_row_proof,
            last_row,
            last_row_proof,
            queries,
            fri_proof,
        })
    }
}

pub fn verify_circle_stark_receipt(
    receipt: &CanonicalStarkReceipt,
    vk: &CanonicalStarkVk,
    program: &CircleStarkProgram,
) -> Result<(), String> {
    let ops = field_ops_for_id(vk.field_id)?;
    if vk.hash_id != HASH_SHA3_ID
        && vk.hash_id != HASH_BLAKE3_ID
        && vk.hash_id != HASH_POSEIDON_ID
        && vk.hash_id != HASH_RESCUE_ID
    {
        return Err("circle receipt unsupported hash_id".to_string());
    }
    if vk.commitment_scheme_id != VC_MERKLE_ID {
        return Err("circle receipt commitment_scheme_id mismatch".to_string());
    }
    if program.constraints_len() == 0 {
        return Err("circle program requires constraints".to_string());
    }
    if program.field_id() != vk.field_id
        || program.hash_id() != vk.hash_id
        || program.commitment_scheme_id() != vk.commitment_scheme_id
    {
        return Err("circle program mismatch with vk".to_string());
    }
    let profile = CircleStarkProfile::decode(&vk.consts_bytes)?;
    let proof = CircleStarkProof::decode(&receipt.proof_bytes)?;
    if proof.trace_length != program.trace_length() || proof.trace_width != program.trace_width() {
        return Err("circle proof trace shape mismatch".to_string());
    }
    if proof.trace_length == 0 {
        return Err("circle proof trace_length must be > 0".to_string());
    }
    if proof.trace_length != (1u32 << profile.log_domain_size) {
        return Err("circle proof domain size mismatch".to_string());
    }
    if proof.fri_proof.log_domain_size != profile.log_domain_size {
        return Err("circle proof fri domain mismatch".to_string());
    }
    if proof.queries.len() != profile.num_queries as usize {
        return Err("circle proof query count mismatch".to_string());
    }
    let (start, result) = decode_pub_inputs(&receipt.pub_inputs_bytes, ops)?;

    let first_hash = hash_trace_row(vk.hash_id, 0, &proof.first_row)?;
    if !circle_merkle::verify_with_hash_id(
        &proof.trace_root,
        &first_hash,
        0,
        &proof.first_row_proof,
        vk.hash_id,
    )? {
        return Err("circle proof first row merkle mismatch".to_string());
    }
    let last_idx = proof.trace_length.saturating_sub(1) as usize;
    let last_hash = hash_trace_row(vk.hash_id, last_idx as u32, &proof.last_row)?;
    if !circle_merkle::verify_with_hash_id(
        &proof.trace_root,
        &last_hash,
        last_idx,
        &proof.last_row_proof,
        vk.hash_id,
    )? {
        return Err("circle proof last row merkle mismatch".to_string());
    }
    if proof.first_row.first().copied().unwrap_or(0) != start {
        return Err("circle proof start mismatch".to_string());
    }
    if proof.last_row.first().copied().unwrap_or(0) != result {
        return Err("circle proof result mismatch".to_string());
    }

    let mut transcript = StarkTranscript::with_label(vk.hash_id, CIRCLE_STARK_TRANSCRIPT)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &vk.program_bytes)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &vk.consts_bytes)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &receipt.pub_inputs_bytes)?;
    transcript.absorb_bytes32(DOMAIN_CIRCLE_STARK, &proof.trace_root)?;
    let beta_bytes = transcript.challenge_bytes32()?;
    let beta = (ops.from_hash)(&beta_bytes);

    let mut alphas = Vec::with_capacity(proof.fri_proof.layers.len());
    for layer in &proof.fri_proof.layers {
        transcript.absorb_bytes32(DOMAIN_CIRCLE_STARK, &layer.layer_root)?;
        let alpha_bytes = transcript.challenge_bytes32()?;
        let alpha = (ops.from_hash)(&alpha_bytes);
        alphas.push(alpha);
    }

    let expected_positions = derive_positions(
        &mut transcript,
        profile.num_queries,
        proof.trace_length.saturating_sub(1) as usize,
    )?;

    for (i, q) in proof.queries.iter().enumerate() {
        if q.position != expected_positions[i] {
            return Err("circle proof query position mismatch".to_string());
        }
        if q.position >= proof.trace_length {
            return Err("circle proof query position out of range".to_string());
        }
        if q.row.iter().any(|v| *v >= ops.modulus) {
            return Err("circle proof row not canonical".to_string());
        }
        if q.next_row.iter().any(|v| *v >= ops.modulus) {
            return Err("circle proof next row not canonical".to_string());
        }
        let row_hash = hash_trace_row(vk.hash_id, q.position, &q.row)?;
        if !circle_merkle::verify_with_hash_id(
            &proof.trace_root,
            &row_hash,
            q.position as usize,
            &q.row_proof,
            vk.hash_id,
        )? {
            return Err("circle proof row proof mismatch".to_string());
        }
        let next_idx = ((q.position as usize) + 1) % (proof.trace_length as usize);
        let next_hash = hash_trace_row(vk.hash_id, next_idx as u32, &q.next_row)?;
        if !circle_merkle::verify_with_hash_id(
            &proof.trace_root,
            &next_hash,
            next_idx,
            &q.next_row_proof,
            vk.hash_id,
        )? {
            return Err("circle proof next row proof mismatch".to_string());
        }
        let composition = compose_constraints(program, ops, beta, &q.row, &q.next_row)?;
        let layer0 = proof
            .fri_proof
            .layers
            .first()
            .ok_or_else(|| "circle proof missing fri layer".to_string())?;
        let fri_q = layer0.queries.get(i).ok_or_else(|| "circle proof missing fri query".to_string())?;
        if fri_q.value != composition {
            return Err("circle proof constraint binding mismatch".to_string());
        }
    }

    verify_circle_fri(
        &proof.fri_proof,
        &expected_positions,
        &alphas,
        vk.hash_id,
        ops.add,
        ops.mul,
    )?;
    Ok(())
}

fn select_row_value(
    row: &[u32],
    next_row: &[u32],
    col: u16,
    is_next: u8,
    width: usize,
) -> Result<u32, String> {
    let idx = col as usize;
    if idx >= width {
        return Err("circle constraint index out of range".to_string());
    }
    match is_next {
        0 => Ok(row[idx]),
        1 => Ok(next_row[idx]),
        _ => Err("circle constraint next flag invalid".to_string()),
    }
}

fn eval_circle_constraint(
    program: &CircleStarkSimpleProgram,
    ops: FieldOps,
    row: &[u32],
    next_row: &[u32],
    c: &CircleConstraint,
) -> Result<u32, String> {
    let width = program.trace_width as usize;
    if row.len() != width || next_row.len() != width {
        return Err("circle row width mismatch".to_string());
    }
    let col = c.col as usize;
    if col >= width {
        return Err("circle constraint col out of range".to_string());
    }
    let expected_next = match c.id {
        CONSTRAINT_CUBE_PLUS_CONST => {
            let cur = row[col];
            let cur_sq = (ops.mul)(cur, cur);
            let cur_cu = (ops.mul)(cur_sq, cur);
            (ops.add)(cur_cu, c.constant % ops.modulus)
        }
        CONSTRAINT_LINEAR_MIX => {
            let a_idx = c.a as usize;
            let b_idx = c.b as usize;
            if a_idx >= width || b_idx >= width {
                return Err("circle constraint index out of range".to_string());
            }
            let a = row[a_idx];
            let b = row[b_idx];
            let sum = (ops.add)(a, b);
            (ops.add)(sum, c.constant % ops.modulus)
        }
        CONSTRAINT_MUL_PLUS_CONST => {
            let a_idx = c.a as usize;
            let b_idx = c.b as usize;
            if a_idx >= width || b_idx >= width {
                return Err("circle constraint index out of range".to_string());
            }
            let a = row[a_idx];
            let b = row[b_idx];
            let prod = (ops.mul)(a, b);
            (ops.add)(prod, c.constant % ops.modulus)
        }
        _ => return Err("unsupported circle constraint id".to_string()),
    };
    Ok((ops.sub)(next_row[col], expected_next))
}

fn eval_constraint_expr(
    program: &CircleStarkExprProgram,
    ops: FieldOps,
    row: &[u32],
    next_row: &[u32],
    c: &CircleExprConstraint,
) -> Result<u32, String> {
    let width = program.trace_width as usize;
    if row.len() != width || next_row.len() != width {
        return Err("circle row width mismatch".to_string());
    }
    let mut expr = c.constant % ops.modulus;
    match c.id {
        CONSTRAINT_LINEAR_COMBO => {}
        CONSTRAINT_MUL_ADD => {
            let a = select_row_value(row, next_row, c.a, c.a_is_next, width)?;
            let b = select_row_value(row, next_row, c.b, c.b_is_next, width)?;
            expr = (ops.add)(expr, (ops.mul)(a, b));
        }
        _ => return Err("unsupported circle constraint id".to_string()),
    }
    for t in &c.terms {
        let coeff = t.coeff % ops.modulus;
        let val = select_row_value(row, next_row, t.col, t.is_next, width)?;
        expr = (ops.add)(expr, (ops.mul)(coeff, val));
    }
    if c.out_col == CONSTRAINT_OUTPUT_NONE {
        return Ok(expr);
    }
    let out_val = select_row_value(row, next_row, c.out_col, c.out_is_next, width)?;
    Ok((ops.sub)(out_val, expr))
}

fn compose_constraints(
    program: &CircleStarkProgram,
    ops: FieldOps,
    beta: u32,
    row: &[u32],
    next_row: &[u32],
) -> Result<u32, String> {
    let mut coeff = 1u32;
    let mut acc = 0u32;
    match program {
        CircleStarkProgram::Simple(simple) => {
            for c in &simple.constraints {
                let eval = eval_circle_constraint(simple, ops, row, next_row, c)?;
                acc = (ops.add)(acc, (ops.mul)(coeff, eval));
                coeff = (ops.mul)(coeff, beta);
            }
        }
        CircleStarkProgram::Expr(expr) => {
            for c in &expr.constraints {
                let eval = eval_constraint_expr(expr, ops, row, next_row, c)?;
                acc = (ops.add)(acc, (ops.mul)(coeff, eval));
                coeff = (ops.mul)(coeff, beta);
            }
        }
    }
    Ok(acc)
}

fn apply_circle_constraints(
    program: &CircleStarkSimpleProgram,
    ops: FieldOps,
    row: &[u32],
) -> Result<Vec<u32>, String> {
    let width = program.trace_width as usize;
    if row.len() != width {
        return Err("circle row width mismatch".to_string());
    }
    if program.constraints.is_empty() {
        return Err("circle program must include constraints".to_string());
    }
    let mut next = row.to_vec();
    for c in &program.constraints {
        let col = c.col as usize;
        if col >= width {
            return Err("circle constraint col out of range".to_string());
        }
        let out = match c.id {
            CONSTRAINT_CUBE_PLUS_CONST => {
                let cur = *row.get(col).ok_or_else(|| "circle row col missing".to_string())?;
                let cur_sq = (ops.mul)(cur, cur);
                let cur_cu = (ops.mul)(cur_sq, cur);
                (ops.add)(cur_cu, c.constant % ops.modulus)
            }
            CONSTRAINT_LINEAR_MIX => {
                let a_idx = c.a as usize;
                let b_idx = c.b as usize;
                let a = *row.get(a_idx).ok_or_else(|| "circle row a missing".to_string())?;
                let b = *row.get(b_idx).ok_or_else(|| "circle row b missing".to_string())?;
                let sum = (ops.add)(a, b);
                (ops.add)(sum, c.constant % ops.modulus)
            }
            CONSTRAINT_MUL_PLUS_CONST => {
                let a_idx = c.a as usize;
                let b_idx = c.b as usize;
                let a = *row.get(a_idx).ok_or_else(|| "circle row a missing".to_string())?;
                let b = *row.get(b_idx).ok_or_else(|| "circle row b missing".to_string())?;
                let prod = (ops.mul)(a, b);
                (ops.add)(prod, c.constant % ops.modulus)
            }
            _ => return Err("unsupported circle constraint id".to_string()),
        };
        next[col] = out;
    }
    Ok(next)
}

fn apply_constraints_expr(
    program: &CircleStarkExprProgram,
    ops: FieldOps,
    row: &[u32],
) -> Result<Vec<u32>, String> {
    let width = program.trace_width as usize;
    if row.len() != width {
        return Err("circle row width mismatch".to_string());
    }
    if program.constraints.is_empty() {
        return Err("circle program must include constraints".to_string());
    }
    let mut next = row.to_vec();
    for c in &program.constraints {
        if c.out_col == CONSTRAINT_OUTPUT_NONE || c.out_is_next != 1 {
            return Err("circle expr trace requires deterministic next-row constraints".to_string());
        }
        if c.a_is_next != 0 || c.b_is_next != 0 {
            return Err("circle expr trace cannot depend on next-row values".to_string());
        }
        if c.terms.iter().any(|t| t.is_next != 0) {
            return Err("circle expr trace cannot depend on next-row terms".to_string());
        }
        let mut expr = c.constant % ops.modulus;
        match c.id {
            CONSTRAINT_LINEAR_COMBO => {}
            CONSTRAINT_MUL_ADD => {
                let a_idx = c.a as usize;
                let b_idx = c.b as usize;
                if a_idx >= width || b_idx >= width {
                    return Err("circle constraint index out of range".to_string());
                }
                let a = row[a_idx];
                let b = row[b_idx];
                expr = (ops.add)(expr, (ops.mul)(a, b));
            }
            _ => return Err("unsupported circle constraint id".to_string()),
        }
        for t in &c.terms {
            let coeff = t.coeff % ops.modulus;
            let idx = t.col as usize;
            if idx >= width {
                return Err("circle constraint index out of range".to_string());
            }
            let val = row[idx];
            expr = (ops.add)(expr, (ops.mul)(coeff, val));
        }
        let out_idx = c.out_col as usize;
        if out_idx >= width {
            return Err("circle constraint out_col out of range".to_string());
        }
        next[out_idx] = expr;
    }
    Ok(next)
}

pub fn build_circle_stark_receipt(
    profile: &CircleStarkProfile,
    program: &CircleStarkSimpleProgram,
    start_row: Vec<u32>,
) -> Result<CanonicalStarkReceipt, String> {
    let ops = field_ops_for_id(program.field_id)?;
    if program.trace_length != (1u32 << profile.log_domain_size) {
        return Err("circle program trace_length mismatch with profile".to_string());
    }
    if start_row.len() != program.trace_width as usize {
        return Err("circle start_row width mismatch".to_string());
    }
    if start_row.iter().any(|v| *v >= ops.modulus) {
        return Err("circle start_row not canonical".to_string());
    }
    let trace = build_trace(program, ops, start_row)?;
    let trace_tree = build_trace_tree(program.hash_id, &trace)?;
    let trace_root = trace_tree.root();
    let last_row = trace.last().cloned().ok_or_else(|| "circle trace empty".to_string())?;
    let pub_inputs_bytes = encode_pub_inputs(&trace[0][0], &last_row[0]);

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: program.field_id,
        hash_id: program.hash_id,
        commitment_scheme_id: program.commitment_scheme_id,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };

    let mut transcript = StarkTranscript::with_label(program.hash_id, CIRCLE_STARK_TRANSCRIPT)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &vk.program_bytes)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &vk.consts_bytes)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &pub_inputs_bytes)?;
    transcript.absorb_bytes32(DOMAIN_CIRCLE_STARK, &trace_root)?;
    let beta_bytes = transcript.challenge_bytes32()?;
    let beta = (ops.from_hash)(&beta_bytes);

    let composition = compute_composition_evals_simple(program, ops, beta, &trace)?;
    let (fri_proof, positions) = build_circle_fri_proof(
        profile.log_domain_size,
        profile.num_queries,
        &composition,
        ops,
        program.hash_id,
        &mut transcript,
    )?;
    let trace_queries = build_trace_queries(&trace, &trace_tree, &positions);

    let proof = CircleStarkProof {
        version: CIRCLE_STARK_PROOF_VERSION,
        trace_length: program.trace_length,
        trace_width: program.trace_width,
        trace_root,
        first_row: trace[0].clone(),
        first_row_proof: trace_tree.proof(0),
        last_row: last_row.clone(),
        last_row_proof: trace_tree.proof(trace.len() - 1),
        queries: trace_queries,
        fri_proof,
    };

    Ok(CanonicalStarkReceipt {
        proof_bytes: proof.encode()?,
        pub_inputs_bytes,
        vk_bytes: vk.encode(),
    })
}

pub fn build_circle_stark_expr_receipt(
    profile: &CircleStarkProfile,
    program: &CircleStarkExprProgram,
    start_row: Vec<u32>,
) -> Result<CanonicalStarkReceipt, String> {
    let ops = field_ops_for_id(program.field_id)?;
    if program.trace_length != (1u32 << profile.log_domain_size) {
        return Err("circle program trace_length mismatch with profile".to_string());
    }
    if start_row.len() != program.trace_width as usize {
        return Err("circle start_row width mismatch".to_string());
    }
    if start_row.iter().any(|v| *v >= ops.modulus) {
        return Err("circle start_row not canonical".to_string());
    }
    let trace = build_trace_expr(program, ops, start_row)?;
    let trace_tree = build_trace_tree(program.hash_id, &trace)?;
    let trace_root = trace_tree.root();
    let last_row = trace.last().cloned().ok_or_else(|| "circle trace empty".to_string())?;
    let pub_inputs_bytes = encode_pub_inputs(&trace[0][0], &last_row[0]);

    let vk = CanonicalStarkVk {
        version: 1,
        field_id: program.field_id,
        hash_id: program.hash_id,
        commitment_scheme_id: program.commitment_scheme_id,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };

    let mut transcript = StarkTranscript::with_label(program.hash_id, CIRCLE_STARK_TRANSCRIPT)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &vk.program_bytes)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &vk.consts_bytes)?;
    transcript.absorb(DOMAIN_CIRCLE_STARK, &pub_inputs_bytes)?;
    transcript.absorb_bytes32(DOMAIN_CIRCLE_STARK, &trace_root)?;
    let beta_bytes = transcript.challenge_bytes32()?;
    let beta = (ops.from_hash)(&beta_bytes);

    let composition = compute_composition_evals_expr(program, ops, beta, &trace)?;
    let (fri_proof, positions) = build_circle_fri_proof(
        profile.log_domain_size,
        profile.num_queries,
        &composition,
        ops,
        program.hash_id,
        &mut transcript,
    )?;
    let trace_queries = build_trace_queries(&trace, &trace_tree, &positions);

    let proof = CircleStarkProof {
        version: CIRCLE_STARK_PROOF_VERSION,
        trace_length: program.trace_length,
        trace_width: program.trace_width,
        trace_root,
        first_row: trace[0].clone(),
        first_row_proof: trace_tree.proof(0),
        last_row: last_row.clone(),
        last_row_proof: trace_tree.proof(trace.len() - 1),
        queries: trace_queries,
        fri_proof,
    };

    Ok(CanonicalStarkReceipt {
        proof_bytes: proof.encode()?,
        pub_inputs_bytes,
        vk_bytes: vk.encode(),
    })
}

fn decode_pub_inputs(bytes: &[u8], ops: FieldOps) -> Result<(u32, u32), String> {
    if bytes.len() != 8 {
        return Err("circle public inputs must be 8 bytes".to_string());
    }
    let mut start_be = [0u8; 4];
    start_be.copy_from_slice(&bytes[0..4]);
    let mut result_be = [0u8; 4];
    result_be.copy_from_slice(&bytes[4..8]);
    let start = (ops.from_be_bytes_strict)(start_be)?;
    let result = (ops.from_be_bytes_strict)(result_be)?;
    Ok((start, result))
}

fn encode_pub_inputs(start: &u32, result: &u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&result.to_be_bytes());
    out
}

fn hash_trace_row(hash_id: u8, position: u32, row: &[u32]) -> Result<[u8; 32], String> {
    let mut data = Vec::with_capacity(row.len() * 4);
    for v in row {
        data.extend_from_slice(&v.to_be_bytes());
    }
    circle_merkle::hash_leaf_with_hash_id(hash_id, position, &data)
}

fn build_trace(
    program: &CircleStarkSimpleProgram,
    ops: FieldOps,
    start_row: Vec<u32>,
) -> Result<Vec<Vec<u32>>, String> {
    let n = program.trace_length as usize;
    let width = program.trace_width as usize;
    if n == 0 || width == 0 {
        return Err("circle trace shape invalid".to_string());
    }
    let mut trace = Vec::with_capacity(n);
    trace.push(start_row);
    for i in 1..n {
        let prev = trace[i - 1].clone();
        let next = apply_circle_constraints(program, ops, &prev)?;
        trace.push(next);
    }
    Ok(trace)
}

fn build_trace_expr(
    program: &CircleStarkExprProgram,
    ops: FieldOps,
    start_row: Vec<u32>,
) -> Result<Vec<Vec<u32>>, String> {
    let n = program.trace_length as usize;
    let width = program.trace_width as usize;
    if n == 0 || width == 0 {
        return Err("circle trace shape invalid".to_string());
    }
    let mut trace = Vec::with_capacity(n);
    trace.push(start_row);
    for i in 1..n {
        let prev = trace[i - 1].clone();
        let next = apply_constraints_expr(program, ops, &prev)?;
        trace.push(next);
    }
    Ok(trace)
}

fn build_trace_tree(
    hash_id: u8,
    trace: &[Vec<u32>],
) -> Result<circle_merkle::MerkleTree, String> {
    let mut leaves = vec![[0u8; 32]; trace.len()];
    if trace.len() >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
        leaves
            .par_iter_mut()
            .enumerate()
            .try_for_each(|(idx, slot)| -> Result<(), String> {
                *slot = hash_trace_row(hash_id, idx as u32, &trace[idx])?;
                Ok(())
            })?;
    } else {
        for (idx, row) in trace.iter().enumerate() {
            leaves[idx] = hash_trace_row(hash_id, idx as u32, row)?;
        }
    }
    circle_merkle::MerkleTree::build_with_hash_id(hash_id, leaves)
}

fn compute_composition_evals_simple(
    program: &CircleStarkSimpleProgram,
    ops: FieldOps,
    beta: u32,
    trace: &[Vec<u32>],
) -> Result<Vec<u32>, String> {
    let n = trace.len();
    let program = CircleStarkProgram::Simple(program.clone());
    if n >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
        (0..n)
            .into_par_iter()
            .map(|i| {
                let row = &trace[i];
                let next = &trace[(i + 1) % n];
                compose_constraints(&program, ops, beta, row, next)
            })
            .collect()
    } else {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let row = &trace[i];
            let next = &trace[(i + 1) % n];
            out.push(compose_constraints(&program, ops, beta, row, next)?);
        }
        Ok(out)
    }
}

fn compute_composition_evals_expr(
    program: &CircleStarkExprProgram,
    ops: FieldOps,
    beta: u32,
    trace: &[Vec<u32>],
) -> Result<Vec<u32>, String> {
    let n = trace.len();
    let program = CircleStarkProgram::Expr(program.clone());
    if n >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
        (0..n)
            .into_par_iter()
            .map(|i| {
                let row = &trace[i];
                let next = &trace[(i + 1) % n];
                compose_constraints(&program, ops, beta, row, next)
            })
            .collect()
    } else {
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let row = &trace[i];
            let next = &trace[(i + 1) % n];
            out.push(compose_constraints(&program, ops, beta, row, next)?);
        }
        Ok(out)
    }
}

#[allow(clippy::type_complexity)]
fn build_circle_fri_proof(
    log_domain_size: u8,
    num_queries: u8,
    evals: &[u32],
    ops: FieldOps,
    hash_id: u8,
    transcript: &mut StarkTranscript,
) -> Result<(CircleFriProof, Vec<u32>), String> {
    if log_domain_size == 0 {
        return Err("circle fri log_domain_size must be > 0".to_string());
    }
    let mut layers_data: Vec<(Vec<u32>, circle_merkle::MerkleTree, Vec<u32>, circle_merkle::MerkleTree, usize)> = Vec::new();
    let mut current = evals.to_vec();
    let mut domain = evals.len();
    for _ in 0..log_domain_size {
        let mut leaves = vec![[0u8; 32]; current.len()];
        if current.len() >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
            leaves
                .par_iter_mut()
                .enumerate()
                .try_for_each(|(idx, slot)| -> Result<(), String> {
                    *slot = circle_merkle::hash_leaf_with_hash_id(
                        hash_id,
                        idx as u32,
                        &current[idx].to_be_bytes(),
                    )?;
                    Ok(())
                })?;
        } else {
            for (idx, v) in current.iter().enumerate() {
                leaves[idx] = circle_merkle::hash_leaf_with_hash_id(
                    hash_id,
                    idx as u32,
                    &v.to_be_bytes(),
                )?;
            }
        }
        let tree = circle_merkle::MerkleTree::build_with_hash_id(hash_id, leaves)?;
        transcript.absorb_bytes32(DOMAIN_CIRCLE_STARK, &tree.root())?;
        let alpha_bytes = transcript.challenge_bytes32()?;
        let alpha = (ops.from_hash)(&alpha_bytes);
        let next_len = domain / 2;
        let mut next = vec![0u32; next_len];
        if next_len >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
            next
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, slot)| {
                    let left = current[i];
                    let right = current[i + next_len];
                    *slot = (ops.add)(left, (ops.mul)(alpha, right));
                });
        } else {
            for i in 0..next_len {
                let left = current[i];
                let right = current[i + next_len];
                next[i] = (ops.add)(left, (ops.mul)(alpha, right));
            }
        }
        let mut next_leaves = vec![[0u8; 32]; next.len()];
        if next.len() >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
            next_leaves
                .par_iter_mut()
                .enumerate()
                .try_for_each(|(idx, slot)| -> Result<(), String> {
                    *slot = circle_merkle::hash_leaf_with_hash_id(
                        hash_id,
                        idx as u32,
                        &next[idx].to_be_bytes(),
                    )?;
                    Ok(())
                })?;
        } else {
            for (idx, v) in next.iter().enumerate() {
                next_leaves[idx] = circle_merkle::hash_leaf_with_hash_id(
                    hash_id,
                    idx as u32,
                    &v.to_be_bytes(),
                )?;
            }
        }
        let next_tree = circle_merkle::MerkleTree::build_with_hash_id(hash_id, next_leaves)?;
        layers_data.push((current, tree, next.clone(), next_tree, domain));
        current = next;
        domain = next_len;
    }
    let positions = derive_positions(transcript, num_queries, evals.len().saturating_sub(1))?;
    let mut layers = Vec::new();
    for (current_vals, tree, next_vals, next_tree, domain) in layers_data.iter() {
        let next_len = domain / 2;
        let queries = if positions.len() >= circle_stark_par_min() && rayon::current_num_threads() > 1 {
            positions
                .par_iter()
                .map(|pos| {
                    let pos = (*pos as usize) & (domain - 1);
                    let pos_neg = pos ^ (domain / 2);
                    let pos_next = pos & (next_len - 1);
                    crate::circle_fri::CircleFriQuery {
                        position: pos as u32,
                        position_neg: pos_neg as u32,
                        value: current_vals[pos],
                        value_neg: current_vals[pos_neg],
                        next_value: next_vals[pos_next],
                        proof: tree.proof(pos),
                        proof_neg: tree.proof(pos_neg),
                        next_proof: next_tree.proof(pos_next),
                    }
                })
                .collect()
        } else {
            let mut queries = Vec::with_capacity(positions.len());
            for pos in &positions {
                let pos = (*pos as usize) & (domain - 1);
                let pos_neg = pos ^ (domain / 2);
                let pos_next = pos & (next_len - 1);
                queries.push(crate::circle_fri::CircleFriQuery {
                    position: pos as u32,
                    position_neg: pos_neg as u32,
                    value: current_vals[pos],
                    value_neg: current_vals[pos_neg],
                    next_value: next_vals[pos_next],
                    proof: tree.proof(pos),
                    proof_neg: tree.proof(pos_neg),
                    next_proof: next_tree.proof(pos_next),
                });
            }
            queries
        };
        layers.push(crate::circle_fri::CircleFriLayerProof {
            layer_root: tree.root(),
            next_root: next_tree.root(),
            queries,
        });
    }
    let proof = CircleFriProof {
        version: crate::circle_fri::CIRCLE_FRI_PROOF_VERSION,
        log_domain_size,
        layers,
        final_value: current[0],
    };
    Ok((proof, positions))
}

fn derive_positions(
    transcript: &mut StarkTranscript,
    num_queries: u8,
    bound: usize,
) -> Result<Vec<u32>, String> {
    let mut out = Vec::with_capacity(num_queries as usize);
    for _ in 0..num_queries {
        out.push(transcript.challenge_usize(bound)? as u32);
    }
    Ok(out)
}

fn build_trace_queries(
    trace: &[Vec<u32>],
    trace_tree: &circle_merkle::MerkleTree,
    positions: &[u32],
) -> Vec<CircleStarkTraceQuery> {
    if positions.len() >= 128 && rayon::current_num_threads() > 1 {
        positions
            .par_iter()
            .map(|pos| {
                let idx = (*pos as usize) % trace.len();
                let next_idx = (idx + 1) % trace.len();
                CircleStarkTraceQuery {
                    position: idx as u32,
                    row: trace[idx].clone(),
                    next_row: trace[next_idx].clone(),
                    row_proof: trace_tree.proof(idx),
                    next_row_proof: trace_tree.proof(next_idx),
                }
            })
            .collect()
    } else {
        let mut out = Vec::with_capacity(positions.len());
        for pos in positions {
            let idx = (*pos as usize) % trace.len();
            let next_idx = (idx + 1) % trace.len();
            out.push(CircleStarkTraceQuery {
                position: idx as u32,
                row: trace[idx].clone(),
                next_row: trace[next_idx].clone(),
                row_proof: trace_tree.proof(idx),
                next_row_proof: trace_tree.proof(next_idx),
            });
        }
        out
    }
}

fn encode_row(out: &mut Vec<u8>, trace_width: u16, row: &[u32]) -> Result<(), String> {
    if row.len() != trace_width as usize {
        return Err("circle row width mismatch".to_string());
    }
    for v in row {
        out.extend_from_slice(&v.to_be_bytes());
    }
    Ok(())
}

fn decode_row(bytes: &[u8], off: &mut usize, trace_width: u16) -> Result<Vec<u32>, String> {
    let mut row = Vec::with_capacity(trace_width as usize);
    for _ in 0..trace_width {
        let v = read_u32_be(bytes, off)?;
        row.push(v);
    }
    Ok(row)
}

fn encode_proof_vec(out: &mut Vec<u8>, proof: &[[u8; 32]]) {
    out.extend_from_slice(&(proof.len() as u16).to_be_bytes());
    for node in proof {
        out.extend_from_slice(node);
    }
}

fn decode_proof_vec(bytes: &[u8], off: &mut usize) -> Result<Vec<[u8; 32]>, String> {
    let len = read_u16_be(bytes, off)? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_bytes32(bytes, off)?);
    }
    Ok(out)
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

fn read_bytes32(bytes: &[u8], off: &mut usize) -> Result<[u8; 32], String> {
    let s = bytes.get(*off..*off + 32).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 32;
    let mut out = [0u8; 32];
    out.copy_from_slice(s);
    Ok(out)
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes.get(*off..*off + len).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stark_receipt::CanonicalStarkReceipt;

    fn decode_and_verify(receipt: &CanonicalStarkReceipt) {
        let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(receipt) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk decode");
                return;
            }
        };
        let decoded_program = match decode_circle_stark_program(&decoded_vk.program_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "program decode");
                return;
            }
        };
        if let Err(_) = verify_circle_stark_receipt(receipt, &decoded_vk, &decoded_program) {
            assert!(false, "circle verify");
        }
    }

    #[test]
    fn test_circle_stark_verify_roundtrip() {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let program = CircleStarkSimpleProgram {
            version: CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 2,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleConstraint {
                    id: CONSTRAINT_CUBE_PLUS_CONST,
                    col: 0,
                    a: 0,
                    b: 0,
                    constant: 42,
                },
                CircleConstraint {
                    id: CONSTRAINT_LINEAR_MIX,
                    col: 1,
                    a: 1,
                    b: 0,
                    constant: 7,
                },
            ],
            air_id: b"circle_do_work_expr:x^3+42,linear".to_vec(),
        };
        let receipt = match build_circle_stark_receipt(&profile, &program, vec![7u32, 11u32]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };
        decode_and_verify(&receipt);
    }

    #[test]
    fn test_circle_stark_verify_roundtrip_blake3() {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let program = CircleStarkSimpleProgram {
            version: CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_BLAKE3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 2,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleConstraint {
                    id: CONSTRAINT_CUBE_PLUS_CONST,
                    col: 0,
                    a: 0,
                    b: 0,
                    constant: 42,
                },
                CircleConstraint {
                    id: CONSTRAINT_LINEAR_MIX,
                    col: 1,
                    a: 1,
                    b: 0,
                    constant: 7,
                },
            ],
            air_id: b"circle_do_work_expr:x^3+42,linear".to_vec(),
        };
        let receipt = match build_circle_stark_receipt(&profile, &program, vec![7u32, 11u32]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };
        decode_and_verify(&receipt);
    }

    #[test]
    fn test_circle_stark_verify_roundtrip_poseidon() {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let program = CircleStarkSimpleProgram {
            version: CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_POSEIDON_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 2,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleConstraint {
                    id: CONSTRAINT_CUBE_PLUS_CONST,
                    col: 0,
                    a: 0,
                    b: 0,
                    constant: 42,
                },
                CircleConstraint {
                    id: CONSTRAINT_LINEAR_MIX,
                    col: 1,
                    a: 1,
                    b: 0,
                    constant: 7,
                },
            ],
            air_id: b"circle_do_work_expr:x^3+42,linear".to_vec(),
        };
        let receipt = match build_circle_stark_receipt(&profile, &program, vec![7u32, 11u32]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };
        decode_and_verify(&receipt);
    }

    #[test]
    fn test_circle_stark_verify_roundtrip_rescue() {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let program = CircleStarkSimpleProgram {
            version: CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_RESCUE_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 2,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleConstraint {
                    id: CONSTRAINT_CUBE_PLUS_CONST,
                    col: 0,
                    a: 0,
                    b: 0,
                    constant: 42,
                },
                CircleConstraint {
                    id: CONSTRAINT_LINEAR_MIX,
                    col: 1,
                    a: 1,
                    b: 0,
                    constant: 7,
                },
            ],
            air_id: b"circle_do_work_expr:x^3+42,linear".to_vec(),
        };
        let receipt = match build_circle_stark_receipt(&profile, &program, vec![7u32, 11u32]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };
        decode_and_verify(&receipt);
    }

    #[test]
    fn test_circle_stark_baby_bear_roundtrip() {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 3,
            num_queries: 2,
            blowup_factor: 1,
        };
        let program = CircleStarkSimpleProgram {
            version: CIRCLE_STARK_SIMPLE_PROGRAM_VERSION,
            field_id: FIELD_BABY_BEAR_CIRCLE_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 2,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleConstraint {
                    id: CONSTRAINT_CUBE_PLUS_CONST,
                    col: 0,
                    a: 0,
                    b: 0,
                    constant: 42,
                },
                CircleConstraint {
                    id: CONSTRAINT_LINEAR_MIX,
                    col: 1,
                    a: 1,
                    b: 0,
                    constant: 7,
                },
            ],
            air_id: b"circle_do_work_expr:x^3+42,linear".to_vec(),
        };
        let receipt = match build_circle_stark_receipt(&profile, &program, vec![7u32, 11u32]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };
        decode_and_verify(&receipt);
    }

    #[test]
    fn test_circle_stark_expr_verify_roundtrip() {
        let profile = CircleStarkProfile {
            version: CIRCLE_STARK_PROFILE_VERSION,
            log_domain_size: 6,
            num_queries: 4,
            blowup_factor: 2,
        };
        let program = CircleStarkExprProgram {
            version: CIRCLE_STARK_EXPR_PROGRAM_VERSION,
            field_id: FIELD_M31_CIRCLE_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            trace_width: 3,
            trace_length: 1u32 << profile.log_domain_size,
            constraints: vec![
                CircleExprConstraint {
                    id: CONSTRAINT_LINEAR_COMBO,
                    out_col: 0,
                    out_is_next: 1,
                    a: 0,
                    a_is_next: 0,
                    b: 0,
                    b_is_next: 0,
                    constant: 7,
                    terms: vec![
                        CircleConstraintTerm {
                            col: 0,
                            coeff: 3,
                            is_next: 0,
                        },
                        CircleConstraintTerm {
                            col: 1,
                            coeff: 5,
                            is_next: 0,
                        },
                    ],
                },
                CircleExprConstraint {
                    id: CONSTRAINT_MUL_ADD,
                    out_col: 1,
                    out_is_next: 1,
                    a: 0,
                    a_is_next: 0,
                    b: 2,
                    b_is_next: 0,
                    constant: 9,
                    terms: vec![CircleConstraintTerm {
                        col: 2,
                        coeff: 11,
                        is_next: 0,
                    }],
                },
                CircleExprConstraint {
                    id: CONSTRAINT_LINEAR_COMBO,
                    out_col: 2,
                    out_is_next: 1,
                    a: 0,
                    a_is_next: 0,
                    b: 0,
                    b_is_next: 0,
                    constant: 3,
                    terms: vec![CircleConstraintTerm {
                        col: 1,
                        coeff: 13,
                        is_next: 0,
                    }],
                },
            ],
            air_id: b"circle_expr_test".to_vec(),
        };
        let receipt = match build_circle_stark_expr_receipt(
            &profile,
            &program,
            vec![7u32, 11u32, 5u32],
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "receipt");
                return;
            }
        };
        decode_and_verify(&receipt);
    }
}
