//! UCIR: Universal Constraint IR for GLYPH-PROVER.
//!
//! Implements the constraint representation per Prover-Blueprint.md Section 4.
//! UCIR provides a unified intermediate representation for all adapter families.

use crate::adapters::AdapterFamily;
use crate::glyph_field_simd::Goldilocks;
use crate::adapter_gate;

// ============================================================
//                    CONSTANTS
// ============================================================

/// UCIR version
pub const UCIR_VERSION: u16 = 1;

/// Field ID for Goldilocks
pub const FIELD_ID_GOLDILOCKS: u8 = 0x01;

/// Gate type tags
pub const GATE_TAG_ARITHMETIC: u8 = 0x01;
pub const GATE_TAG_COPY: u8 = 0x02;
pub const GATE_TAG_CUSTOM_BASE: u8 = 0x80;

/// Standard table IDs
pub const TABLE_RANGE8: u32 = 1;
pub const TABLE_RANGE16: u32 = 2;
pub const TABLE_BIT: u32 = 3;
pub const TABLE_CHI5: u32 = 4;

/// Custom gate IDs
pub const CUSTOM_GATE_BN254_ADD: u16 = 0x0001;
pub const CUSTOM_GATE_BN254_SUB: u16 = 0x0002;
pub const CUSTOM_GATE_BN254_MUL: u16 = 0x0003;
pub const CUSTOM_GATE_KECCAK_MERGE: u16 = 0x0004;
pub const CUSTOM_GATE_IVC_VERIFY: u16 = 0x0010;
pub const CUSTOM_GATE_STARK_VERIFY: u16 = 0x0011;
pub const CUSTOM_GATE_IPA_VERIFY: u16 = 0x0012;
pub const CUSTOM_GATE_GROTH16_BLS12381_VERIFY: u16 = 0x0013;
pub const CUSTOM_GATE_KZG_BLS12381_VERIFY: u16 = 0x0014;
pub const CUSTOM_GATE_SP1_VERIFY: u16 = 0x0015;
pub const CUSTOM_GATE_PLONK_VERIFY: u16 = 0x0016;
pub const CUSTOM_GATE_BINIUS_VERIFY: u16 = 0x0017;

// ============================================================
//                    WITNESS LAYOUT (Blueprint 4.2)
// ============================================================

/// Witness segment layout per Blueprint Section 4.2
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WitnessLayout {
    /// Public inputs segment
    pub public_start: u32,
    pub public_len: u32,
    /// Intermediate wires segment
    pub wire_start: u32,
    pub wire_len: u32,
    /// Lookup multiplicities segment
    pub lookup_start: u32,
    pub lookup_len: u32,
    /// Blinding values segment (zk-mode only)
    pub blind_start: u32,
    pub blind_len: u32,
}

impl WitnessLayout {
    /// Create layout for fast-mode (no blinding)
    pub fn fast_mode(public_len: u32, wire_len: u32, lookup_len: u32) -> Self {
        let public_start = 0;
        let wire_start = public_len;
        let lookup_start = wire_start + wire_len;
        Self {
            public_start,
            public_len,
            wire_start,
            wire_len,
            lookup_start,
            lookup_len,
            blind_start: 0,
            blind_len: 0,
        }
    }

    /// Create layout for zk-mode (with blinding)
    pub fn zk_mode(public_len: u32, wire_len: u32, lookup_len: u32, blind_len: u32) -> Self {
        let public_start = 0;
        let wire_start = public_len;
        let lookup_start = wire_start + wire_len;
        let blind_start = lookup_start + lookup_len;
        Self {
            public_start,
            public_len,
            wire_start,
            wire_len,
            lookup_start,
            lookup_len,
            blind_start,
            blind_len,
        }
    }

    /// Total witness length
    pub fn total_len(&self) -> u32 {
        if self.blind_len > 0 {
            self.blind_start + self.blind_len
        } else if self.lookup_len > 0 {
            self.lookup_start + self.lookup_len
        } else if self.wire_len > 0 {
            self.wire_start + self.wire_len
        } else {
            self.public_len
        }
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&self.public_start.to_le_bytes());
        out.extend_from_slice(&self.public_len.to_le_bytes());
        out.extend_from_slice(&self.wire_start.to_le_bytes());
        out.extend_from_slice(&self.wire_len.to_le_bytes());
        out.extend_from_slice(&self.lookup_start.to_le_bytes());
        out.extend_from_slice(&self.lookup_len.to_le_bytes());
        out.extend_from_slice(&self.blind_start.to_le_bytes());
        out.extend_from_slice(&self.blind_len.to_le_bytes());
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        Some(Self {
            public_start: u32::from_le_bytes(data[0..4].try_into().ok()?),
            public_len: u32::from_le_bytes(data[4..8].try_into().ok()?),
            wire_start: u32::from_le_bytes(data[8..12].try_into().ok()?),
            wire_len: u32::from_le_bytes(data[12..16].try_into().ok()?),
            lookup_start: u32::from_le_bytes(data[16..20].try_into().ok()?),
            lookup_len: u32::from_le_bytes(data[20..24].try_into().ok()?),
            blind_start: u32::from_le_bytes(data[24..28].try_into().ok()?),
            blind_len: u32::from_le_bytes(data[28..32].try_into().ok()?),
        })
    }
}

// ============================================================
//                    WIRE REFERENCE
// ============================================================

/// Reference to a witness element
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WRef(pub u32);

impl WRef {
    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    pub fn from_bytes(data: &[u8; 4]) -> Self {
        Self(u32::from_le_bytes(*data))
    }
}

// ============================================================
//                    GATE TYPES (Blueprint 4.3)
// ============================================================

/// Arithmetic gate: q_mul*a*b + q_l*a + q_r*b + q_o*c + q_c = 0
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArithmeticGate {
    pub a: WRef,
    pub b: WRef,
    pub c: WRef,
    pub q_mul: Goldilocks,
    pub q_l: Goldilocks,
    pub q_r: Goldilocks,
    pub q_o: Goldilocks,
    pub q_c: Goldilocks,
}

impl ArithmeticGate {
    /// Create a multiplication gate: a * b = c
    pub fn mul(a: WRef, b: WRef, c: WRef) -> Self {
        Self {
            a,
            b,
            c,
            q_mul: Goldilocks::ONE,
            q_l: Goldilocks::ZERO,
            q_r: Goldilocks::ZERO,
            q_o: Goldilocks::ONE.neg(),
            q_c: Goldilocks::ZERO,
        }
    }

    /// Create an addition gate: a + b = c
    pub fn add(a: WRef, b: WRef, c: WRef) -> Self {
        Self {
            a,
            b,
            c,
            q_mul: Goldilocks::ZERO,
            q_l: Goldilocks::ONE,
            q_r: Goldilocks::ONE,
            q_o: Goldilocks::ONE.neg(),
            q_c: Goldilocks::ZERO,
        }
    }

    /// Create a constant gate: c = constant
    pub fn constant(c: WRef, val: Goldilocks) -> Self {
        Self {
            a: WRef(0),
            b: WRef(0),
            c,
            q_mul: Goldilocks::ZERO,
            q_l: Goldilocks::ZERO,
            q_r: Goldilocks::ZERO,
            q_o: Goldilocks::ONE,
            q_c: val.neg(),
        }
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(53);
        out.push(GATE_TAG_ARITHMETIC);
        out.extend_from_slice(&self.a.to_bytes());
        out.extend_from_slice(&self.b.to_bytes());
        out.extend_from_slice(&self.c.to_bytes());
        out.extend_from_slice(&self.q_mul.0.to_le_bytes());
        out.extend_from_slice(&self.q_l.0.to_le_bytes());
        out.extend_from_slice(&self.q_r.0.to_le_bytes());
        out.extend_from_slice(&self.q_o.0.to_le_bytes());
        out.extend_from_slice(&self.q_c.0.to_le_bytes());
        out
    }

    /// Serialized size in bytes
    pub const SIZE: usize = 1 + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 8; // 53
}

/// Copy gate: left == right
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyGate {
    pub left: WRef,
    pub right: WRef,
}

impl CopyGate {
    pub fn new(left: WRef, right: WRef) -> Self {
        Self { left, right }
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(GATE_TAG_COPY);
        out.extend_from_slice(&self.left.to_bytes());
        out.extend_from_slice(&self.right.to_bytes());
        out
    }

    /// Serialized size in bytes
    pub const SIZE: usize = 1 + 4 + 4; // 9
}

/// Custom gate with arbitrary payload
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomGate {
    pub custom_id: u16,
    pub payload: Vec<u8>,
}

impl CustomGate {
    pub fn new(custom_id: u16, payload: Vec<u8>) -> Self {
        Self { custom_id, payload }
    }

    fn legacy_tag(custom_id: u16) -> u8 {
        let hi = (custom_id >> 8) as u8;
        if hi < 0x80 {
            GATE_TAG_CUSTOM_BASE.wrapping_add(hi)
        } else {
            GATE_TAG_CUSTOM_BASE | (hi & 0x7F)
        }
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let tag = GATE_TAG_CUSTOM_BASE;
        let mut out = Vec::with_capacity(7 + self.payload.len());
        out.push(tag);
        out.extend_from_slice(&self.custom_id.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, String> {
    if *pos + 1 > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let v = data[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16_le(data: &[u8], pos: &mut usize) -> Result<u16, String> {
    if *pos + 2 > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let mut b = [0u8; 2];
    b.copy_from_slice(&data[*pos..*pos + 2]);
    *pos += 2;
    Ok(u16::from_le_bytes(b))
}

fn read_u32_le(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    if *pos + 4 > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(b))
}

fn read_u32_be(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    if *pos + 4 > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_be_bytes(b))
}

fn read_u64_le(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos + 8 > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(b))
}

fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], String> {
    if *pos + len > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let out = &data[*pos..*pos + len];
    *pos += len;
    Ok(out)
}

fn read_vec(data: &[u8], pos: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    if *pos + len > data.len() {
        return Err("ucir decode eof".to_string());
    }
    let out = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(out)
}

/// Encode payload for custom gates that reference three wire starts
pub fn encode_three_wref_payload(a_start: WRef, b_start: WRef, out_start: WRef) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&a_start.to_bytes());
    out.extend_from_slice(&b_start.to_bytes());
    out.extend_from_slice(&out_start.to_bytes());
    out
}

/// Decode payload for custom gates that reference three wire starts
pub fn decode_three_wref_payload(payload: &[u8]) -> Option<(WRef, WRef, WRef)> {
    if payload.len() != 12 {
        return None;
    }
    let a = WRef::from_bytes(&payload[0..4].try_into().ok()?);
    let b = WRef::from_bytes(&payload[4..8].try_into().ok()?);
    let c = WRef::from_bytes(&payload[8..12].try_into().ok()?);
    Some((a, b, c))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IvcVerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub adapter_vk_bytes: Vec<u8>,
    pub adapter_statement_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkVerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub seed_bytes: Vec<u8>,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaVerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub receipt_bytes: Vec<u8>,
}

pub struct Sp1VerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkVerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiniusVerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub adapter_vk_bytes: Vec<u8>,
    pub adapter_statement_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bls12381VerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgBls12381VerifyPayload {
    pub commitment_start: WRef,
    pub point_start: WRef,
    pub claim_start: WRef,
    pub receipt_bytes: Vec<u8>,
}

pub fn encode_ivc_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&commitment_start.to_bytes());
    out.extend_from_slice(&point_start.to_bytes());
    out.extend_from_slice(&claim_start.to_bytes());
    out.extend_from_slice(&(adapter_vk_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(adapter_statement_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(adapter_vk_bytes);
    out.extend_from_slice(adapter_statement_bytes);
    out.extend_from_slice(proof_bytes);
    out
}

pub fn decode_ivc_verify_payload(payload: &[u8]) -> Result<IvcVerifyPayload, String> {
    let mut off = 0usize;
    let read_wref = |bytes: &[u8], off: &mut usize| -> Result<WRef, String> {
        let slice = bytes.get(*off..*off + 4).ok_or_else(|| "ivc payload EOF".to_string())?;
        *off += 4;
        Ok(WRef::from_bytes(slice.try_into().map_err(|_| "ivc payload wref".to_string())?))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let slice = bytes.get(*off..*off + 4).ok_or_else(|| "ivc payload EOF".to_string())?;
        *off += 4;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_vec = |bytes: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        let slice = bytes.get(*off..*off + len).ok_or_else(|| "ivc payload EOF".to_string())?;
        *off += len;
        Ok(slice.to_vec())
    };

    let commitment_start = read_wref(payload, &mut off)?;
    let point_start = read_wref(payload, &mut off)?;
    let claim_start = read_wref(payload, &mut off)?;
    let vk_len = read_u32(payload, &mut off)? as usize;
    let stmt_len = read_u32(payload, &mut off)? as usize;
    let proof_len = read_u32(payload, &mut off)? as usize;
    let adapter_vk_bytes = read_vec(payload, &mut off, vk_len)?;
    let adapter_statement_bytes = read_vec(payload, &mut off, stmt_len)?;
    let proof_bytes = read_vec(payload, &mut off, proof_len)?;
    if off != payload.len() {
        return Err("ivc payload trailing bytes".to_string());
    }
    Ok(IvcVerifyPayload {
        commitment_start,
        point_start,
        claim_start,
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    })
}

pub fn encode_stark_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    seed_bytes: &[u8],
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&commitment_start.to_bytes());
    out.extend_from_slice(&point_start.to_bytes());
    out.extend_from_slice(&claim_start.to_bytes());
    out.extend_from_slice(&(seed_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(receipt_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(seed_bytes);
    out.extend_from_slice(receipt_bytes);
    out
}

pub fn decode_stark_verify_payload(payload: &[u8]) -> Result<StarkVerifyPayload, String> {
    let mut off = 0usize;
    let read_wref = |bytes: &[u8], off: &mut usize| -> Result<WRef, String> {
        let slice = bytes.get(*off..*off + 4).ok_or_else(|| "stark payload EOF".to_string())?;
        *off += 4;
        Ok(WRef::from_bytes(slice.try_into().map_err(|_| "stark payload wref".to_string())?))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let slice = bytes.get(*off..*off + 4).ok_or_else(|| "stark payload EOF".to_string())?;
        *off += 4;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_vec = |bytes: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        let slice = bytes.get(*off..*off + len).ok_or_else(|| "stark payload EOF".to_string())?;
        *off += len;
        Ok(slice.to_vec())
    };

    let commitment_start = read_wref(payload, &mut off)?;
    let point_start = read_wref(payload, &mut off)?;
    let claim_start = read_wref(payload, &mut off)?;
    let seed_len = read_u32(payload, &mut off)? as usize;
    let receipt_len = read_u32(payload, &mut off)? as usize;
    let seed_bytes = read_vec(payload, &mut off, seed_len)?;
    let receipt_bytes = read_vec(payload, &mut off, receipt_len)?;
    if off != payload.len() {
        return Err("stark payload trailing bytes".to_string());
    }
    Ok(StarkVerifyPayload {
        commitment_start,
        point_start,
        claim_start,
        seed_bytes,
        receipt_bytes,
    })
}

pub fn encode_ipa_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&commitment_start.to_bytes());
    out.extend_from_slice(&point_start.to_bytes());
    out.extend_from_slice(&claim_start.to_bytes());
    out.extend_from_slice(&(receipt_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(receipt_bytes);
    out
}

pub fn encode_sp1_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + 4 + receipt_bytes.len());
    out.extend_from_slice(&commitment_start.0.to_be_bytes());
    out.extend_from_slice(&point_start.0.to_be_bytes());
    out.extend_from_slice(&claim_start.0.to_be_bytes());
    out.extend_from_slice(&(receipt_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(receipt_bytes);
    out
}

pub fn encode_plonk_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + 4 + receipt_bytes.len());
    out.extend_from_slice(&commitment_start.0.to_be_bytes());
    out.extend_from_slice(&point_start.0.to_be_bytes());
    out.extend_from_slice(&claim_start.0.to_be_bytes());
    out.extend_from_slice(&(receipt_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(receipt_bytes);
    out
}

pub fn decode_ipa_verify_payload(payload: &[u8]) -> Result<IpaVerifyPayload, String> {
    let mut off = 0usize;
    let read_wref = |bytes: &[u8], off: &mut usize| -> Result<WRef, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "ipa payload EOF".to_string())?;
        *off += 4;
        Ok(WRef::from_bytes(
            slice
                .try_into()
                .map_err(|_| "ipa payload wref".to_string())?,
        ))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "ipa payload EOF".to_string())?;
        *off += 4;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_vec = |bytes: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        let slice = bytes
            .get(*off..*off + len)
            .ok_or_else(|| "ipa payload EOF".to_string())?;
        *off += len;
        Ok(slice.to_vec())
    };

    let commitment_start = read_wref(payload, &mut off)?;
    let point_start = read_wref(payload, &mut off)?;
    let claim_start = read_wref(payload, &mut off)?;
    let receipt_len = read_u32(payload, &mut off)? as usize;
    let receipt_bytes = read_vec(payload, &mut off, receipt_len)?;
    if off != payload.len() {
        return Err("ipa payload trailing bytes".to_string());
    }
    Ok(IpaVerifyPayload {
        commitment_start,
        point_start,
        claim_start,
        receipt_bytes,
    })
}

pub fn decode_sp1_verify_payload(payload: &[u8]) -> Result<Sp1VerifyPayload, String> {
    let mut off = 0usize;
    let commitment_start = read_u32_be(payload, &mut off)?;
    let point_start = read_u32_be(payload, &mut off)?;
    let claim_start = read_u32_be(payload, &mut off)?;
    let receipt_len = read_u32_be(payload, &mut off)? as usize;
    let receipt_bytes = read_vec(payload, &mut off, receipt_len)?;
    if off != payload.len() {
        return Err("sp1 payload trailing bytes".to_string());
    }
    Ok(Sp1VerifyPayload {
        commitment_start: WRef(commitment_start),
        point_start: WRef(point_start),
        claim_start: WRef(claim_start),
        receipt_bytes,
    })
}

pub fn decode_plonk_verify_payload(payload: &[u8]) -> Result<PlonkVerifyPayload, String> {
    let mut off = 0usize;
    let commitment_start = read_u32_be(payload, &mut off)?;
    let point_start = read_u32_be(payload, &mut off)?;
    let claim_start = read_u32_be(payload, &mut off)?;
    let receipt_len = read_u32_be(payload, &mut off)? as usize;
    let receipt_bytes = read_vec(payload, &mut off, receipt_len)?;
    if off != payload.len() {
        return Err("plonk payload trailing bytes".to_string());
    }
    Ok(PlonkVerifyPayload {
        commitment_start: WRef(commitment_start),
        point_start: WRef(point_start),
        claim_start: WRef(claim_start),
        receipt_bytes,
    })
}

pub fn encode_binius_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&commitment_start.to_bytes());
    out.extend_from_slice(&point_start.to_bytes());
    out.extend_from_slice(&claim_start.to_bytes());
    out.extend_from_slice(&(adapter_vk_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(adapter_statement_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(adapter_vk_bytes);
    out.extend_from_slice(adapter_statement_bytes);
    out.extend_from_slice(proof_bytes);
    out
}

pub fn decode_binius_verify_payload(payload: &[u8]) -> Result<BiniusVerifyPayload, String> {
    let mut off = 0usize;
    let read_wref = |bytes: &[u8], off: &mut usize| -> Result<WRef, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "binius payload EOF".to_string())?;
        *off += 4;
        Ok(WRef::from_bytes(
            slice
                .try_into()
                .map_err(|_| "binius payload wref".to_string())?,
        ))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "binius payload EOF".to_string())?;
        *off += 4;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_vec = |bytes: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        let slice = bytes
            .get(*off..*off + len)
            .ok_or_else(|| "binius payload EOF".to_string())?;
        *off += len;
        Ok(slice.to_vec())
    };

    let commitment_start = read_wref(payload, &mut off)?;
    let point_start = read_wref(payload, &mut off)?;
    let claim_start = read_wref(payload, &mut off)?;
    let vk_len = read_u32(payload, &mut off)? as usize;
    let stmt_len = read_u32(payload, &mut off)? as usize;
    let proof_len = read_u32(payload, &mut off)? as usize;
    let adapter_vk_bytes = read_vec(payload, &mut off, vk_len)?;
    let adapter_statement_bytes = read_vec(payload, &mut off, stmt_len)?;
    let proof_bytes = read_vec(payload, &mut off, proof_len)?;
    if off != payload.len() {
        return Err("binius payload trailing bytes".to_string());
    }
    Ok(BiniusVerifyPayload {
        commitment_start,
        point_start,
        claim_start,
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    })
}

pub fn encode_groth16_bls12381_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&commitment_start.to_bytes());
    out.extend_from_slice(&point_start.to_bytes());
    out.extend_from_slice(&claim_start.to_bytes());
    out.extend_from_slice(&(receipt_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(receipt_bytes);
    out
}

pub fn decode_groth16_bls12381_verify_payload(
    payload: &[u8],
) -> Result<Groth16Bls12381VerifyPayload, String> {
    let mut off = 0usize;
    let read_wref = |bytes: &[u8], off: &mut usize| -> Result<WRef, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "groth16 bls12381 payload EOF".to_string())?;
        *off += 4;
        Ok(WRef::from_bytes(
            slice
                .try_into()
                .map_err(|_| "groth16 bls12381 payload wref".to_string())?,
        ))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "groth16 bls12381 payload EOF".to_string())?;
        *off += 4;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_vec = |bytes: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        let slice = bytes
            .get(*off..*off + len)
            .ok_or_else(|| "groth16 bls12381 payload EOF".to_string())?;
        *off += len;
        Ok(slice.to_vec())
    };

    let commitment_start = read_wref(payload, &mut off)?;
    let point_start = read_wref(payload, &mut off)?;
    let claim_start = read_wref(payload, &mut off)?;
    let receipt_len = read_u32(payload, &mut off)? as usize;
    let receipt_bytes = read_vec(payload, &mut off, receipt_len)?;
    if off != payload.len() {
        return Err("groth16 bls12381 payload trailing bytes".to_string());
    }
    Ok(Groth16Bls12381VerifyPayload {
        commitment_start,
        point_start,
        claim_start,
        receipt_bytes,
    })
}

pub fn encode_kzg_bls12381_verify_payload(
    commitment_start: WRef,
    point_start: WRef,
    claim_start: WRef,
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&commitment_start.to_bytes());
    out.extend_from_slice(&point_start.to_bytes());
    out.extend_from_slice(&claim_start.to_bytes());
    out.extend_from_slice(&(receipt_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(receipt_bytes);
    out
}

pub fn decode_kzg_bls12381_verify_payload(
    payload: &[u8],
) -> Result<KzgBls12381VerifyPayload, String> {
    let mut off = 0usize;
    let read_wref = |bytes: &[u8], off: &mut usize| -> Result<WRef, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "kzg bls12381 payload EOF".to_string())?;
        *off += 4;
        Ok(WRef::from_bytes(
            slice
                .try_into()
                .map_err(|_| "kzg bls12381 payload wref".to_string())?,
        ))
    };
    let read_u32 = |bytes: &[u8], off: &mut usize| -> Result<u32, String> {
        let slice = bytes
            .get(*off..*off + 4)
            .ok_or_else(|| "kzg bls12381 payload EOF".to_string())?;
        *off += 4;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let read_vec = |bytes: &[u8], off: &mut usize, len: usize| -> Result<Vec<u8>, String> {
        let slice = bytes
            .get(*off..*off + len)
            .ok_or_else(|| "kzg bls12381 payload EOF".to_string())?;
        *off += len;
        Ok(slice.to_vec())
    };

    let commitment_start = read_wref(payload, &mut off)?;
    let point_start = read_wref(payload, &mut off)?;
    let claim_start = read_wref(payload, &mut off)?;
    let receipt_len = read_u32(payload, &mut off)? as usize;
    let receipt_bytes = read_vec(payload, &mut off, receipt_len)?;
    if off != payload.len() {
        return Err("kzg bls12381 payload trailing bytes".to_string());
    }
    Ok(KzgBls12381VerifyPayload {
        commitment_start,
        point_start,
        claim_start,
        receipt_bytes,
    })
}

pub fn ensure_custom_gate_enabled(custom_id: u16) -> Result<(), String> {
    match custom_id {
        CUSTOM_GATE_BN254_ADD | CUSTOM_GATE_BN254_SUB | CUSTOM_GATE_BN254_MUL => Ok(()),
        CUSTOM_GATE_IPA_VERIFY
        | CUSTOM_GATE_SP1_VERIFY
        | CUSTOM_GATE_PLONK_VERIFY
        | CUSTOM_GATE_GROTH16_BLS12381_VERIFY
        | CUSTOM_GATE_KZG_BLS12381_VERIFY => adapter_gate::ensure_family_enabled(AdapterFamily::Snark),
        CUSTOM_GATE_KECCAK_MERGE => adapter_gate::ensure_family_enabled(AdapterFamily::Hash),
        CUSTOM_GATE_IVC_VERIFY => adapter_gate::ensure_family_enabled(AdapterFamily::Ivc),
        CUSTOM_GATE_BINIUS_VERIFY => adapter_gate::ensure_family_enabled(AdapterFamily::Binius),
        CUSTOM_GATE_STARK_VERIFY => adapter_gate::ensure_any_stark_enabled(),
        _ => Err("unknown custom gate id".to_string()),
    }
}

pub fn custom_gate_wrefs(custom_id: u16, payload: &[u8]) -> Result<Vec<WRef>, String> {
    ensure_custom_gate_enabled(custom_id)?;
    match custom_id {
        CUSTOM_GATE_BN254_ADD | CUSTOM_GATE_BN254_SUB | CUSTOM_GATE_BN254_MUL | CUSTOM_GATE_KECCAK_MERGE => {
            let (a, b, c) = decode_three_wref_payload(payload)
                .ok_or_else(|| "custom gate payload invalid".to_string())?;
            Ok(vec![a, b, c])
        }
        CUSTOM_GATE_IVC_VERIFY => {
            let payload = decode_ivc_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_STARK_VERIFY => {
            let payload = decode_stark_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_IPA_VERIFY => {
            let payload = decode_ipa_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_SP1_VERIFY => {
            let payload = decode_sp1_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_PLONK_VERIFY => {
            let payload = decode_plonk_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_BINIUS_VERIFY => {
            let payload = decode_binius_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_GROTH16_BLS12381_VERIFY => {
            let payload = decode_groth16_bls12381_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        CUSTOM_GATE_KZG_BLS12381_VERIFY => {
            let payload = decode_kzg_bls12381_verify_payload(payload)?;
            let mut out = Vec::with_capacity(10);
            for i in 0..4 {
                out.push(WRef(payload.commitment_start.0 + i));
            }
            for i in 0..4 {
                out.push(WRef(payload.point_start.0 + i));
            }
            for i in 0..2 {
                out.push(WRef(payload.claim_start.0 + i));
            }
            Ok(out)
        }
        _ => Err("unknown custom gate id".to_string()),
    }
}

/// Unified gate enum
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    Arithmetic(ArithmeticGate),
    Copy(CopyGate),
    Custom(CustomGate),
}

impl Gate {
    /// Serialize gate to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Gate::Arithmetic(g) => g.to_bytes(),
            Gate::Copy(g) => g.to_bytes(),
            Gate::Custom(g) => g.to_bytes(),
        }
    }
}

// ============================================================
//                    LOOKUP (Blueprint 4.4)
// ============================================================

/// Lookup record: witness value must be in table
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lookup {
    pub value: WRef,
    pub table_id: u32,
}

impl Lookup {
    pub fn new(value: WRef, table_id: u32) -> Self {
        Self { value, table_id }
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.value.to_bytes());
        out.extend_from_slice(&self.table_id.to_le_bytes());
        out
    }

    /// Serialized size in bytes
    pub const SIZE: usize = 4 + 4; // 8
}

// ============================================================
//                    TABLE (Blueprint 4.5)
// ============================================================

/// Lookup table definition
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub table_id: u32,
    pub width: u8,
    pub values: Vec<Goldilocks>,
}

impl Table {
    pub fn new(table_id: u32, width: u8, values: Vec<Goldilocks>) -> Self {
        Self { table_id, width, values }
    }

    /// Create standard Range8 table (0..255)
    pub fn range8() -> Self {
        let values: Vec<Goldilocks> = (0..=255).map(|i| Goldilocks(i as u64)).collect();
        Self::new(TABLE_RANGE8, 1, values)
    }

    /// Create standard Range16 table (0..65535)
    pub fn range16() -> Self {
        let values: Vec<Goldilocks> = (0..=65535).map(|i| Goldilocks(i as u64)).collect();
        Self::new(TABLE_RANGE16, 1, values)
    }

    /// Create standard Bit table ({0, 1})
    pub fn bit() -> Self {
        Self::new(TABLE_BIT, 1, vec![Goldilocks::ZERO, Goldilocks::ONE])
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.values.len() * 8);
        out.extend_from_slice(&self.table_id.to_le_bytes());
        out.push(self.width);
        out.extend_from_slice(&(self.values.len() as u32).to_le_bytes());
        for v in &self.values {
            out.extend_from_slice(&v.0.to_le_bytes());
        }
        out
    }
}

// ============================================================
//                    UCIR STRUCTURE (Blueprint 4.1)
// ============================================================

/// Complete UCIR constraint system
#[derive(Clone, Debug, Default)]
pub struct Ucir2 {
    pub version: u16,
    pub field_id: u8,
    pub witness_layout: WitnessLayout,
    pub gates: Vec<Gate>,
    pub lookups: Vec<Lookup>,
    pub tables: Vec<Table>,
}

impl Ucir2 {
    /// Create a new empty UCIR for Goldilocks field
    pub fn new() -> Self {
        Self {
            version: UCIR_VERSION,
            field_id: FIELD_ID_GOLDILOCKS,
            witness_layout: WitnessLayout::default(),
            gates: Vec::new(),
            lookups: Vec::new(),
            tables: Vec::new(),
        }
    }

    /// Return table index for a given table id.
    #[inline(always)]
    pub fn table_index(&self, table_id: u32) -> Option<usize> {
        self.tables.iter().position(|t| t.table_id == table_id)
    }

    /// Return table reference for a given table id.
    #[inline(always)]
    pub fn table_by_id(&self, table_id: u32) -> Option<&Table> {
        self.tables.iter().find(|t| t.table_id == table_id)
    }

    /// Add an arithmetic gate
    pub fn add_arithmetic_gate(&mut self, gate: ArithmeticGate) {
        self.gates.push(Gate::Arithmetic(gate));
    }

    /// Add a copy gate
    pub fn add_copy_gate(&mut self, left: WRef, right: WRef) {
        self.gates.push(Gate::Copy(CopyGate::new(left, right)));
    }

    /// Add a custom gate
    pub fn add_custom_gate(&mut self, gate: CustomGate) {
        self.gates.push(Gate::Custom(gate));
    }

    /// Add a lookup
    pub fn add_lookup(&mut self, value: WRef, table_id: u32) {
        self.lookups.push(Lookup::new(value, table_id));
    }

    /// Add a table
    pub fn add_table(&mut self, table: Table) {
        self.tables.push(table);
    }

    /// Count gates by type
    pub fn gate_counts(&self) -> (usize, usize, usize) {
        let mut arith = 0;
        let mut copy = 0;
        let mut custom = 0;
        for g in &self.gates {
            match g {
                Gate::Arithmetic(_) => arith += 1,
                Gate::Copy(_) => copy += 1,
                Gate::Custom(_) => custom += 1,
            }
        }
        (arith, copy, custom)
    }

    /// Serialize to bytes per Appendix A
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Header
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.field_id);

        // Gate counts (we need to compute them)
        let (_arith_count, copy_count, _custom_count) = self.gate_counts();
        let gate_count = self.gates.len() as u32;
        out.extend_from_slice(&gate_count.to_le_bytes());
        out.extend_from_slice(&(self.lookups.len() as u32).to_le_bytes());
        out.extend_from_slice(&(copy_count as u32).to_le_bytes());
        out.extend_from_slice(&(self.tables.len() as u32).to_le_bytes());

        // Witness layout
        out.extend_from_slice(&self.witness_layout.to_bytes());

        // Gates (sorted by type per Blueprint 4.7) - single pass with pre-sorted buffers
        let mut arith_bytes = Vec::new();
        let mut copy_bytes = Vec::new();
        let mut custom_bytes = Vec::new();

        for g in &self.gates {
            match g {
                Gate::Arithmetic(ag) => arith_bytes.extend_from_slice(&ag.to_bytes()),
                Gate::Copy(cg) => copy_bytes.extend_from_slice(&cg.to_bytes()),
                Gate::Custom(cg) => custom_bytes.extend_from_slice(&cg.to_bytes()),
            }
        }

        out.extend_from_slice(&arith_bytes);
        out.extend_from_slice(&copy_bytes);
        out.extend_from_slice(&custom_bytes);

        // Lookups
        for l in &self.lookups {
            out.extend_from_slice(&l.to_bytes());
        }

        // Tables
        for t in &self.tables {
            out.extend_from_slice(&t.to_bytes());
        }

        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        let mut pos: usize = 0;

        let version = read_u16_le(data, &mut pos)?;
        if version != UCIR_VERSION {
            return Err(format!(
                "ucir version mismatch: got {} expected {}",
                version, UCIR_VERSION
            ));
        }
        let field_id = read_u8(data, &mut pos)?;
        if field_id != FIELD_ID_GOLDILOCKS {
            return Err(format!(
                "ucir field_id mismatch: got 0x{:02x} expected 0x{:02x}",
                field_id, FIELD_ID_GOLDILOCKS
            ));
        }

        let gate_count = read_u32_le(data, &mut pos)? as usize;
        let lookup_count = read_u32_le(data, &mut pos)? as usize;
        let copy_count = read_u32_le(data, &mut pos)? as usize;
        let table_count = read_u32_le(data, &mut pos)? as usize;

        let layout_bytes = read_bytes(data, &mut pos, 32)?;
        let witness_layout = WitnessLayout::from_bytes(layout_bytes)
            .ok_or_else(|| "ucir witness layout decode failed".to_string())?;
        let witness_total = witness_layout.total_len();

        if witness_layout.public_start != 0 {
            return Err("ucir witness layout invalid: public_start must be 0".to_string());
        }
        if witness_layout.wire_start != witness_layout.public_len {
            return Err("ucir witness layout invalid: wire_start mismatch".to_string());
        }
        if witness_layout.lookup_start != witness_layout.wire_start + witness_layout.wire_len {
            return Err("ucir witness layout invalid: lookup_start mismatch".to_string());
        }
        if witness_layout.blind_len == 0 {
            if witness_layout.blind_start != 0 {
                return Err(
                    "ucir witness layout invalid: blind_start must be 0 when blind_len=0"
                        .to_string(),
                );
            }
        } else if witness_layout.blind_start != witness_layout.lookup_start + witness_layout.lookup_len {
            return Err("ucir witness layout invalid: blind_start mismatch".to_string());
        }

        let mut gates = Vec::with_capacity(gate_count);
        let mut phase: u8 = 0;
        for _ in 0..gate_count {
            let tag = read_u8(data, &mut pos)?;
            match tag {
                GATE_TAG_ARITHMETIC => {
                    if phase > 0 {
                        return Err(
                            "ucir gate order invalid: arithmetic gate after non-arithmetic"
                                .to_string(),
                        );
                    }
                    let a = WRef(read_u32_le(data, &mut pos)?);
                    let b = WRef(read_u32_le(data, &mut pos)?);
                    let c = WRef(read_u32_le(data, &mut pos)?);
                    if witness_total > 0 {
                        if a.0 >= witness_total || b.0 >= witness_total || c.0 >= witness_total {
                            return Err("ucir invalid witness reference in arithmetic gate".to_string());
                        }
                    } else {
                        return Err("ucir witness length is zero but gates reference witness".to_string());
                    }

                    let q_mul = Goldilocks(read_u64_le(data, &mut pos)?);
                    let q_l = Goldilocks(read_u64_le(data, &mut pos)?);
                    let q_r = Goldilocks(read_u64_le(data, &mut pos)?);
                    let q_o = Goldilocks(read_u64_le(data, &mut pos)?);
                    let q_c = Goldilocks(read_u64_le(data, &mut pos)?);
                    if q_mul.0 >= crate::glyph_field_simd::GOLDILOCKS_MODULUS
                        || q_l.0 >= crate::glyph_field_simd::GOLDILOCKS_MODULUS
                        || q_r.0 >= crate::glyph_field_simd::GOLDILOCKS_MODULUS
                        || q_o.0 >= crate::glyph_field_simd::GOLDILOCKS_MODULUS
                        || q_c.0 >= crate::glyph_field_simd::GOLDILOCKS_MODULUS
                    {
                        return Err("ucir non-canonical Goldilocks coefficient".to_string());
                    }

                    gates.push(Gate::Arithmetic(ArithmeticGate {
                        a,
                        b,
                        c,
                        q_mul,
                        q_l,
                        q_r,
                        q_o,
                        q_c,
                    }));
                }
                GATE_TAG_COPY => {
                    if phase > 1 {
                        return Err("ucir gate order invalid: copy gate after custom".to_string());
                    }
                    phase = 1;
                    let left = WRef(read_u32_le(data, &mut pos)?);
                    let right = WRef(read_u32_le(data, &mut pos)?);
                    if witness_total > 0 {
                        if left.0 >= witness_total || right.0 >= witness_total {
                            return Err("ucir invalid witness reference in copy gate".to_string());
                        }
                    } else {
                        return Err("ucir witness length is zero but gates reference witness".to_string());
                    }
                    gates.push(Gate::Copy(CopyGate { left, right }));
                }
                GATE_TAG_CUSTOM_BASE..=0xFF => {
                    phase = 2;
                    let custom_id = read_u16_le(data, &mut pos)?;
                    let payload_len = read_u32_le(data, &mut pos)? as usize;
                    let payload = read_bytes(data, &mut pos, payload_len)?.to_vec();
                    let legacy = CustomGate::legacy_tag(custom_id);
                    if tag != GATE_TAG_CUSTOM_BASE && tag != legacy {
                        return Err("ucir custom gate tag mismatch".to_string());
                    }
                    gates.push(Gate::Custom(CustomGate { custom_id, payload }));
                }
                _ => return Err(format!("ucir gate tag invalid: 0x{:02x}", tag)),
            }
        }

        let mut lookups = Vec::with_capacity(lookup_count);
        for _ in 0..lookup_count {
            let value = WRef(read_u32_le(data, &mut pos)?);
            let table_id = read_u32_le(data, &mut pos)?;
            if witness_total > 0 {
                if value.0 >= witness_total {
                    return Err("ucir invalid witness reference in lookup".to_string());
                }
            } else {
                return Err("ucir witness length is zero but lookups reference witness".to_string());
            }
            lookups.push(Lookup { value, table_id });
        }

        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            let table_id = read_u32_le(data, &mut pos)?;
            let width = read_u8(data, &mut pos)?;
            let value_count = read_u32_le(data, &mut pos)? as usize;
            let mut values = Vec::with_capacity(value_count);
            for _ in 0..value_count {
                let v = Goldilocks(read_u64_le(data, &mut pos)?);
                if v.0 >= crate::glyph_field_simd::GOLDILOCKS_MODULUS {
                    return Err("ucir non-canonical Goldilocks table value".to_string());
                }
                values.push(v);
            }
            tables.push(Table {
                table_id,
                width,
                values,
            });
        }

        if pos != data.len() {
            return Err("ucir trailing bytes".to_string());
        }

        let actual_copy_count = gates.iter().filter(|g| matches!(g, Gate::Copy(_))).count();
        if actual_copy_count != copy_count {
            return Err("ucir copy_count mismatch".to_string());
        }

        Ok(Self {
            version,
            field_id,
            witness_layout,
            gates,
            lookups,
            tables,
        })
    }

    /// Compute UCIR hash for transcript
    pub fn hash(&self) -> [u8; 32] {
        crate::glyph_transcript::keccak256(&self.to_bytes())
    }
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const UCIR_HEADER_LEN: usize = 2 + 1 + 4 + 4 + 4 + 4 + 32;
    const MAX_WREF: u32 = 128;
    const MAX_GATES: usize = 12;
    const MAX_LOOKUPS: usize = 8;
    const MAX_TABLES: usize = 4;
    const MAX_TABLE_VALUES: usize = 16;
    const MAX_CUSTOM_PAYLOAD: usize = 64;

    fn arb_goldilocks() -> impl Strategy<Value = Goldilocks> {
        (0u64..crate::glyph_field_simd::GOLDILOCKS_MODULUS).prop_map(Goldilocks)
    }

    fn arb_wref_with_max(max: u32) -> impl Strategy<Value = WRef> {
        (0..=max).prop_map(WRef)
    }

    fn arb_witness_layout() -> impl Strategy<Value = WitnessLayout> {
        (0u32..4, 0u32..32, 0u32..8, 0u32..4).prop_map(
            |(public_len, wire_len, lookup_len, blind_len)| {
                if blind_len > 0 {
                    WitnessLayout::zk_mode(public_len, wire_len, lookup_len, blind_len)
                } else {
                    WitnessLayout::fast_mode(public_len, wire_len, lookup_len)
                }
            },
        )
    }

    fn arb_nonempty_witness_layout() -> impl Strategy<Value = WitnessLayout> {
        (0u32..4, 1u32..32, 0u32..8, 0u32..4).prop_map(
            |(public_len, wire_len, lookup_len, blind_len)| {
                if blind_len > 0 {
                    WitnessLayout::zk_mode(public_len, wire_len, lookup_len, blind_len)
                } else {
                    WitnessLayout::fast_mode(public_len, wire_len, lookup_len)
                }
            },
        )
    }

    fn arb_arithmetic_gate(max: u32) -> impl Strategy<Value = ArithmeticGate> {
        (
            arb_wref_with_max(max),
            arb_wref_with_max(max),
            arb_wref_with_max(max),
            arb_goldilocks(),
            arb_goldilocks(),
            arb_goldilocks(),
            arb_goldilocks(),
            arb_goldilocks(),
        )
            .prop_map(|(a, b, c, q_mul, q_l, q_r, q_o, q_c)| ArithmeticGate {
                a,
                b,
                c,
                q_mul,
                q_l,
                q_r,
                q_o,
                q_c,
            })
    }

    fn arb_copy_gate(max: u32) -> impl Strategy<Value = CopyGate> {
        (arb_wref_with_max(max), arb_wref_with_max(max)).prop_map(|(left, right)| {
            CopyGate::new(left, right)
        })
    }

    fn arb_custom_gate() -> impl Strategy<Value = CustomGate> {
        (
            any::<u16>(),
            prop::collection::vec(any::<u8>(), 0..(MAX_CUSTOM_PAYLOAD + 1)),
        )
            .prop_map(|(custom_id, payload)| CustomGate::new(custom_id, payload))
    }

    fn arb_gate_with_wref_max(max: u32) -> BoxedStrategy<Gate> {
        let arith = arb_arithmetic_gate(max).prop_map(Gate::Arithmetic);
        let copy = arb_copy_gate(max).prop_map(Gate::Copy);
        let custom = arb_custom_gate().prop_map(Gate::Custom);
        prop_oneof![arith, copy, custom].boxed()
    }

    fn arb_lookup_with_wref_max(max: u32) -> impl Strategy<Value = Lookup> {
        (arb_wref_with_max(max), any::<u32>()).prop_map(|(value, table_id)| Lookup {
            value,
            table_id,
        })
    }

    fn arb_table() -> impl Strategy<Value = Table> {
        (
            any::<u32>(),
            1u8..5,
            prop::collection::vec(arb_goldilocks(), 0..(MAX_TABLE_VALUES + 1)),
        )
            .prop_map(|(table_id, width, values)| Table {
                table_id,
                width,
                values,
            })
    }

    fn arb_ucir2() -> impl Strategy<Value = Ucir2> {
        arb_witness_layout().prop_flat_map(|layout| {
            let witness_total = layout.total_len();
            let wref_max = witness_total.saturating_sub(1);
            let gate_count_range = if witness_total == 0 { 0..=0 } else { 0..=MAX_GATES };
            let lookup_count_range = if witness_total == 0 { 0..=0 } else { 0..=MAX_LOOKUPS };
            let table_count_range = 0..=MAX_TABLES;
            (
                Just(layout),
                gate_count_range,
                lookup_count_range,
                table_count_range,
            )
                .prop_flat_map(move |(layout, gate_count, lookup_count, table_count)| {
                    let gates = prop::collection::vec(arb_gate_with_wref_max(wref_max), gate_count);
                    let lookups =
                        prop::collection::vec(arb_lookup_with_wref_max(wref_max), lookup_count);
                    let tables = prop::collection::vec(arb_table(), table_count);
                    (Just(layout), gates, lookups, tables).prop_map(
                        |(layout, gates, lookups, tables)| {
                            let mut ucir = Ucir2::new();
                            ucir.witness_layout = layout;
                            ucir.gates = gates;
                            ucir.lookups = lookups;
                            ucir.tables = tables;
                            ucir
                        },
                    )
                })
        })
    }

    fn arb_ucir2_with_lookup() -> impl Strategy<Value = Ucir2> {
        arb_nonempty_witness_layout().prop_flat_map(|layout| {
            let witness_total = layout.total_len();
            let wref_max = witness_total.saturating_sub(1);
            let gate_count_range = 0..=MAX_GATES;
            let lookup_count_range = 1..=MAX_LOOKUPS;
            let table_count_range = 0..=MAX_TABLES;
            (
                Just(layout),
                gate_count_range,
                lookup_count_range,
                table_count_range,
            )
                .prop_flat_map(move |(layout, gate_count, lookup_count, table_count)| {
                    let gates = prop::collection::vec(arb_gate_with_wref_max(wref_max), gate_count);
                    let lookups =
                        prop::collection::vec(arb_lookup_with_wref_max(wref_max), lookup_count);
                    let tables = prop::collection::vec(arb_table(), table_count);
                    (Just(layout), gates, lookups, tables).prop_map(
                        |(layout, gates, lookups, tables)| {
                            let mut ucir = Ucir2::new();
                            ucir.witness_layout = layout;
                            ucir.gates = gates;
                            ucir.lookups = lookups;
                            ucir.tables = tables;
                            ucir
                        },
                    )
                })
        })
    }

    fn arb_ucir2_with_gate_wref() -> impl Strategy<Value = Ucir2> {
        arb_nonempty_witness_layout().prop_flat_map(|layout| {
            let witness_total = layout.total_len();
            let wref_max = witness_total.saturating_sub(1);
            let leading_gate = prop_oneof![
                arb_arithmetic_gate(wref_max).prop_map(Gate::Arithmetic),
                arb_copy_gate(wref_max).prop_map(Gate::Copy),
            ];
            let extra_gates = prop::collection::vec(arb_gate_with_wref_max(wref_max), 0..MAX_GATES);
            let lookups = prop::collection::vec(arb_lookup_with_wref_max(wref_max), 0..MAX_LOOKUPS);
            let tables = prop::collection::vec(arb_table(), 0..MAX_TABLES);
            (
                Just(layout),
                leading_gate,
                extra_gates,
                lookups,
                tables,
            )
                .prop_map(|(layout, first_gate, mut rest, lookups, tables)| {
                    let mut gates = Vec::with_capacity(rest.len() + 1);
                    gates.push(first_gate);
                    gates.append(&mut rest);
                    let mut ucir = Ucir2::new();
                    ucir.witness_layout = layout;
                    ucir.gates = gates;
                    ucir.lookups = lookups;
                    ucir.tables = tables;
                    ucir
                })
        })
    }

    fn gate_encoded_len(gate: &Gate) -> usize {
        match gate {
            Gate::Arithmetic(_) => ArithmeticGate::SIZE,
            Gate::Copy(_) => CopyGate::SIZE,
            Gate::Custom(custom) => 1 + 2 + 4 + custom.payload.len(),
        }
    }

    impl Arbitrary for WRef {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            (0..=MAX_WREF).prop_map(WRef).boxed()
        }
    }

    impl Arbitrary for WitnessLayout {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_witness_layout().boxed()
        }
    }

    impl Arbitrary for ArithmeticGate {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_arithmetic_gate(MAX_WREF).boxed()
        }
    }

    impl Arbitrary for CopyGate {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_copy_gate(MAX_WREF).boxed()
        }
    }

    impl Arbitrary for CustomGate {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_custom_gate().boxed()
        }
    }

    impl Arbitrary for Gate {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_gate_with_wref_max(MAX_WREF).boxed()
        }
    }

    impl Arbitrary for Lookup {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_lookup_with_wref_max(MAX_WREF).boxed()
        }
    }

    impl Arbitrary for Table {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_table().boxed()
        }
    }

    impl Arbitrary for Ucir2 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            arb_ucir2().boxed()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            max_shrink_iters: 256,
            ..ProptestConfig::default()
        })]

        #[test]
        fn prop_ucir_roundtrip_bytes_stable(ucir in arb_ucir2()) {
            let bytes = ucir.to_bytes();
            let decoded = match Ucir2::from_bytes(&bytes) {
                Ok(value) => value,
                Err(_) => {
                    prop_assert!(false, "decode must succeed");
                    return Ok(());
                }
            };
            prop_assert_eq!(bytes, decoded.to_bytes());
        }

        #[test]
        fn prop_custom_gate_payload_size(custom_id in any::<u16>(), payload in prop::collection::vec(any::<u8>(), 0..(MAX_CUSTOM_PAYLOAD + 1))) {
            let gate = CustomGate::new(custom_id, payload.clone());
            prop_assert_eq!(gate.to_bytes().len(), 7 + payload.len());
        }

        #[test]
        fn prop_custom_gate_legacy_tag_accepts(custom_id in any::<u16>(), payload in prop::collection::vec(any::<u8>(), 0..(MAX_CUSTOM_PAYLOAD + 1))) {
            let gate = CustomGate::new(custom_id, payload);
            let mut ucir = Ucir2::new();
            ucir.witness_layout = WitnessLayout::fast_mode(0, 0, 0);
            ucir.add_custom_gate(gate);
            let mut bytes = ucir.to_bytes();
            let legacy = CustomGate::legacy_tag(custom_id);
            bytes[UCIR_HEADER_LEN] = legacy;
            let decoded = match Ucir2::from_bytes(&bytes) {
                Ok(value) => value,
                Err(_) => {
                    prop_assert!(false, "legacy tag decode must succeed");
                    return Ok(());
                }
            };
            match &decoded.gates[0] {
                Gate::Custom(custom) => prop_assert_eq!(custom.custom_id, custom_id),
                _ => prop_assert!(false, "expected custom gate"),
            }
        }

        #[test]
        fn prop_three_wref_payload_roundtrip(a in 0u32..1024, b in 0u32..1024, c in 0u32..1024) {
            let payload = encode_three_wref_payload(WRef(a), WRef(b), WRef(c));
            prop_assert_eq!(payload.len(), 12);
            let decoded = match decode_three_wref_payload(&payload) {
                Some(value) => value,
                None => {
                    prop_assert!(false, "decode must succeed");
                    return Ok(());
                }
            };
            prop_assert_eq!(decoded.0.0, a);
            prop_assert_eq!(decoded.1.0, b);
            prop_assert_eq!(decoded.2.0, c);
        }

        #[test]
        fn prop_gate_wref_out_of_range_rejected(ucir in arb_ucir2_with_gate_wref()) {
            let mut bytes = ucir.to_bytes();
            let witness_total = ucir.witness_layout.total_len();
            let write_at = UCIR_HEADER_LEN + 1;
            prop_assume!(bytes.len() >= write_at + 4);
            bytes[write_at..write_at + 4].copy_from_slice(&(witness_total as u32).to_le_bytes());
            prop_assert!(Ucir2::from_bytes(&bytes).is_err());
        }

        #[test]
        fn prop_lookup_wref_out_of_range_rejected(ucir in arb_ucir2_with_lookup()) {
            let mut bytes = ucir.to_bytes();
            let witness_total = ucir.witness_layout.total_len();
            let gate_bytes_len: usize = ucir.gates.iter().map(gate_encoded_len).sum();
            let lookup_offset = UCIR_HEADER_LEN + gate_bytes_len;
            prop_assume!(bytes.len() >= lookup_offset + 4);
            bytes[lookup_offset..lookup_offset + 4].copy_from_slice(&(witness_total as u32).to_le_bytes());
            prop_assert!(Ucir2::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn test_witness_layout_fast_mode() {
        let layout = WitnessLayout::fast_mode(10, 100, 20);
        assert_eq!(layout.public_start, 0);
        assert_eq!(layout.public_len, 10);
        assert_eq!(layout.wire_start, 10);
        assert_eq!(layout.wire_len, 100);
        assert_eq!(layout.lookup_start, 110);
        assert_eq!(layout.lookup_len, 20);
        assert_eq!(layout.blind_len, 0);
        assert_eq!(layout.total_len(), 130);
        println!("Witness layout fast-mode test passed.");
    }

    #[test]
    fn test_witness_layout_roundtrip() {
        let layout = WitnessLayout::zk_mode(5, 50, 10, 8);
        let bytes = layout.to_bytes();
        let decoded = match WitnessLayout::from_bytes(&bytes) {
            Some(value) => value,
            None => {
                assert!(false, "witness layout decode");
                return;
            }
        };
        assert_eq!(layout, decoded);
        println!("Witness layout roundtrip test passed.");
    }

    #[test]
    fn test_arithmetic_gate_mul() {
        let gate = ArithmeticGate::mul(WRef(0), WRef(1), WRef(2));
        assert_eq!(gate.q_mul, Goldilocks::ONE);
        assert_eq!(gate.q_o, Goldilocks::ONE.neg());
        let bytes = gate.to_bytes();
        assert_eq!(bytes[0], GATE_TAG_ARITHMETIC);
        println!("Arithmetic gate mul test passed.");
    }

    #[test]
    fn test_ucir2_basic() {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(2, 10, 5);

        // Add gates
        ucir.add_arithmetic_gate(ArithmeticGate::mul(WRef(0), WRef(1), WRef(2)));
        ucir.add_arithmetic_gate(ArithmeticGate::add(WRef(2), WRef(3), WRef(4)));
        ucir.add_copy_gate(WRef(0), WRef(5));

        // Add lookup
        ucir.add_lookup(WRef(3), TABLE_RANGE8);

        // Add table
        ucir.add_table(Table::bit());

        let (arith, copy, custom) = ucir.gate_counts();
        assert_eq!(arith, 2);
        assert_eq!(copy, 1);
        assert_eq!(custom, 0);

        let bytes = ucir.to_bytes();
        assert!(!bytes.is_empty());

        let hash = ucir.hash();
        assert_eq!(hash.len(), 32);

        println!("UCIR basic test passed.");
    }

    #[test]
    fn test_ucir2_roundtrip_and_tamper_fails() {
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(2, 10, 5);
        ucir.add_arithmetic_gate(ArithmeticGate::mul(WRef(0), WRef(1), WRef(2)));
        ucir.add_copy_gate(WRef(0), WRef(5));
        ucir.add_custom_gate(CustomGate::new(0x1234, vec![1, 2, 3]));
        ucir.add_lookup(WRef(3), TABLE_RANGE8);
        ucir.add_table(Table::bit());

        let bytes = ucir.to_bytes();
        let dec = match Ucir2::from_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        assert_eq!(dec.version, UCIR_VERSION);
        assert_eq!(dec.field_id, FIELD_ID_GOLDILOCKS);
        assert_eq!(dec.gates.len(), ucir.gates.len());
        assert_eq!(dec.lookups.len(), ucir.lookups.len());
        assert_eq!(dec.tables.len(), ucir.tables.len());

        let mut tampered = bytes.clone();
        tampered.push(0);
        assert!(Ucir2::from_bytes(&tampered).is_err());
    }

    #[test]
    fn test_custom_gate_tag_no_overflow_for_high_custom_id() {
        let g = CustomGate::new(0x8000, vec![9, 9, 9]);
        let enc = g.to_bytes();
        assert_eq!(enc[0], GATE_TAG_CUSTOM_BASE);
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 0, 0);
        ucir.add_custom_gate(g);
        let dec = match Ucir2::from_bytes(&ucir.to_bytes()) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        match &dec.gates[0] {
            Gate::Custom(cg) => assert_eq!(cg.custom_id, 0x8000),
            _ => assert!(false, "expected custom gate"),
        }
    }

    #[test]
    fn test_custom_gate_tag_legacy_decode() {
        let g = CustomGate::new(0x0102, vec![1, 2, 3, 4]);
        let mut enc = g.to_bytes();
        enc[0] = CustomGate::legacy_tag(0x0102);
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 0, 0);
        ucir.add_custom_gate(g);
        let mut bytes = ucir.to_bytes();
        let first_gate_offset = 2 + 1 + 4 + 4 + 4 + 4 + 32;
        bytes[first_gate_offset] = enc[0];
        let dec = match Ucir2::from_bytes(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "legacy tag decode must succeed");
                return;
            }
        };
        match &dec.gates[0] {
            Gate::Custom(cg) => assert_eq!(cg.custom_id, 0x0102),
            _ => assert!(false, "expected custom gate"),
        }
    }

    #[test]
    fn test_custom_gate_tag_mismatch_rejected() {
        let g = CustomGate::new(0x0102, vec![7, 7, 7]);
        let mut ucir = Ucir2::new();
        ucir.witness_layout = WitnessLayout::fast_mode(0, 0, 0);
        ucir.add_custom_gate(g);
        let mut bytes = ucir.to_bytes();
        let first_gate_offset = 2 + 1 + 4 + 4 + 4 + 4 + 32;
        bytes[first_gate_offset] = 0x90;
        assert!(Ucir2::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_standard_tables() {
        let bit = Table::bit();
        assert_eq!(bit.values.len(), 2);

        let range8 = Table::range8();
        assert_eq!(range8.values.len(), 256);

        // Don't create range16 in test - too large
        println!("Standard tables test passed.");
    }
}
