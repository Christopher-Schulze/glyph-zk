//! UCIR Compiler: Adapter compilation to UCIR.
//!
//! Implements adapter-to-UCIR compilation per Prover-Blueprint.md Section 5.
//! Each adapter family has a dedicated compilation path.

use crate::glyph_ir::{
    Ucir2, WitnessLayout, ArithmeticGate, Table, WRef,
    TABLE_RANGE8, TABLE_RANGE16, TABLE_BIT,
};
#[cfg(any(
    feature = "hash",
    feature = "ivc",
    feature = "binius",
    feature = "stark-babybear",
    feature = "stark-goldilocks",
    feature = "stark-m31",
    feature = "snark"
))]
use crate::glyph_ir::CustomGate;
#[cfg(any(feature = "snark", feature = "hash"))]
use crate::glyph_ir::encode_three_wref_payload;
#[cfg(feature = "hash")]
use crate::glyph_ir::CUSTOM_GATE_KECCAK_MERGE;
#[cfg(feature = "ivc")]
use crate::glyph_ir::{CUSTOM_GATE_IVC_VERIFY, encode_ivc_verify_payload};
#[cfg(feature = "binius")]
use crate::glyph_ir::{CUSTOM_GATE_BINIUS_VERIFY, encode_binius_verify_payload};
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
use crate::glyph_ir::{CUSTOM_GATE_STARK_VERIFY, encode_stark_verify_payload};
#[cfg(feature = "snark")]
use crate::glyph_ir::{CUSTOM_GATE_IPA_VERIFY, encode_ipa_verify_payload};
#[cfg(feature = "snark")]
use crate::glyph_ir::{CUSTOM_GATE_GROTH16_BLS12381_VERIFY, encode_groth16_bls12381_verify_payload};
#[cfg(feature = "snark")]
use crate::glyph_ir::{CUSTOM_GATE_KZG_BLS12381_VERIFY, encode_kzg_bls12381_verify_payload};
#[cfg(feature = "snark")]
use crate::glyph_ir::{CUSTOM_GATE_SP1_VERIFY, encode_sp1_verify_payload};
#[cfg(feature = "snark")]
use crate::glyph_ir::{CUSTOM_GATE_PLONK_VERIFY, encode_plonk_verify_payload};
use crate::glyph_field_simd::Goldilocks;
use crate::adapter_gate;
use crate::adapters::{AdapterFamily, SnarkKind, StarkField};
#[cfg(feature = "snark")]
use crate::bn254_pairing_trace::G1WnafPrecomp;
#[cfg(not(feature = "snark"))]
type G1WnafPrecomp = ();
#[cfg(feature = "snark")]
use ark_bn254::Fr;
#[cfg(feature = "snark")]
use ark_ff::{PrimeField, BigInteger};

#[cfg(feature = "snark")]
use crate::glyph_ir::{CUSTOM_GATE_BN254_ADD, CUSTOM_GATE_BN254_SUB, CUSTOM_GATE_BN254_MUL};

// ============================================================
//                    ADAPTER FAMILY IDS
// ============================================================

/// Hash merge
pub const ADAPTER_HASH: u32 = 1;
/// SNARK family (Groth16, KZG, PLONK, Halo2-KZG, IPA BN254/BLS12-381, SP1)
pub const ADAPTER_SNARK: u32 = 2;
/// STARK (Goldilocks-family)
pub const ADAPTER_STARK_GOLDILOCKS: u32 = 3;
/// STARK (BabyBear-family)
pub const ADAPTER_STARK_BABYBEAR: u32 = 4;
/// STARK (M31-family)
pub const ADAPTER_STARK_M31: u32 = 5;
/// IVC folding
pub const ADAPTER_IVC: u32 = 6;
/// Binius native proofs
pub const ADAPTER_BINIUS: u32 = 7;

/// Compilation error
#[derive(Debug)]
pub enum CompileError {
    InvalidInput(String),
    VerificationFailed(String),
    Unsupported(String),
}

fn gate_to_compile_error(err: String) -> CompileError {
    CompileError::Unsupported(err)
}

/// Compiled UCIR bundle
#[derive(Debug)]
pub struct CompiledUcir {
    pub ucir: Ucir2,
    pub public_inputs: Vec<Goldilocks>,
    pub wire_values: Vec<Goldilocks>,
}

#[cfg(feature = "snark")]
fn fr_to_goldilocks_limbs(fr: &Fr) -> [Goldilocks; 4] {
    let mut bytes = [0u8; 32];
    let mut be = fr.into_bigint().to_bytes_be();
    if be.len() > 32 {
        be = be[be.len() - 32..].to_vec();
    }
    bytes[32 - be.len()..].copy_from_slice(&be);
    let mut limbs = [Goldilocks::ZERO; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * 8;
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&bytes[start..start + 8]);
        *limb = Goldilocks(u64::from_be_bytes(limb_bytes));
    }
    limbs
}

#[cfg(feature = "snark")]
fn fr_vec_to_public_inputs(fr_list: &[Fr]) -> Vec<Goldilocks> {
    let mut out = Vec::with_capacity(fr_list.len() * 4);
    for fr in fr_list {
        out.extend_from_slice(&fr_to_goldilocks_limbs(fr));
    }
    out
}

fn append_binding_digests(public_inputs: &mut Vec<Goldilocks>, digests: &[[u8; 32]]) {
    for digest in digests {
        public_inputs.extend_from_slice(&embed_fq_limbs(digest));
    }
}

// ============================================================
//                    COMPILATION CONTEXT
// ============================================================

/// Compilation context for building UCIR
#[derive(Debug)]
pub struct CompileContext {
    pub ucir: Ucir2,
    /// Next available witness index
    next_wire: u32,
    /// Public input count
    pub_count: u32,
}

impl CompileContext {
    /// Create new compilation context with public input count
    pub fn new(public_count: u32) -> Self {
        Self {
            ucir: Ucir2::new(),
            next_wire: public_count,
            pub_count: public_count,
        }
    }

    /// Allocate a new witness wire, returning its reference
    pub fn alloc_wire(&mut self) -> WRef {
        let idx = self.next_wire;
        self.next_wire += 1;
        WRef(idx)
    }

    /// Allocate N new witness wires
    pub fn alloc_wires(&mut self, n: u32) -> Vec<WRef> {
        (0..n).map(|_| self.alloc_wire()).collect()
    }

    /// Allocate a new wire and push a value into the wire buffer
    pub fn alloc_wire_with_value(
        &mut self,
        wire_values: &mut Vec<Goldilocks>,
        val: Goldilocks,
    ) -> WRef {
        let idx = self.next_wire;
        self.next_wire += 1;
        wire_values.push(val);
        WRef(idx)
    }

    /// Allocate 4 wires for BN254 limb array
    pub fn alloc_fq_limbs(
        &mut self,
        wire_values: &mut Vec<Goldilocks>,
        limbs: [u64; 4],
    ) -> WRef {
        let start = self.next_wire;
        for limb in limbs {
            self.alloc_wire_with_value(wire_values, Goldilocks(limb));
        }
        WRef(start)
    }

    /// Add multiplication constraint: a * b = c (returns c)
    pub fn mul(&mut self, a: WRef, b: WRef) -> WRef {
        let c = self.alloc_wire();
        self.ucir.add_arithmetic_gate(ArithmeticGate::mul(a, b, c));
        c
    }

    /// Add addition constraint: a + b = c (returns c)
    pub fn add(&mut self, a: WRef, b: WRef) -> WRef {
        let c = self.alloc_wire();
        self.ucir.add_arithmetic_gate(ArithmeticGate::add(a, b, c));
        c
    }

    /// Add constant constraint: wire = val
    pub fn constant(&mut self, val: Goldilocks) -> WRef {
        let c = self.alloc_wire();
        self.ucir.add_arithmetic_gate(ArithmeticGate::constant(c, val));
        c
    }

    /// Add copy constraint: left == right
    pub fn copy(&mut self, left: WRef, right: WRef) {
        self.ucir.add_copy_gate(left, right);
    }

    /// Add Range8 lookup for a wire
    pub fn range8(&mut self, wire: WRef) {
        self.ucir.add_lookup(wire, TABLE_RANGE8);
    }

    /// Add Range16 lookup for a wire
    pub fn range16(&mut self, wire: WRef) {
        self.ucir.add_lookup(wire, TABLE_RANGE16);
    }

    /// Add Bit lookup for a wire
    pub fn bit(&mut self, wire: WRef) {
        self.ucir.add_lookup(wire, TABLE_BIT);
    }

    /// Finalize and return the UCIR
    pub fn finalize(mut self) -> Ucir2 {
        // Compute wire count
        let wire_count = self.next_wire - self.pub_count;
        let lookup_count = self.ucir.lookups.len() as u32;

        self.ucir.witness_layout = WitnessLayout::fast_mode(
            self.pub_count,
            wire_count,
            lookup_count,
        );

        // Add standard tables if lookups reference them
        let has_range8 = self.ucir.lookups.iter().any(|l| l.table_id == TABLE_RANGE8);
        let has_range16 = self.ucir.lookups.iter().any(|l| l.table_id == TABLE_RANGE16);
        let has_bit = self.ucir.lookups.iter().any(|l| l.table_id == TABLE_BIT);

        if has_bit {
            self.ucir.add_table(Table::bit());
        }
        if has_range8 {
            self.ucir.add_table(Table::range8());
        }
        if has_range16 {
            self.ucir.add_table(Table::range16());
        }

        self.ucir
    }
}

// ============================================================
//                    BN254 EMBEDDING (Blueprint 5.1)
// ============================================================

/// Embed a BN254 Fq element as 4 Goldilocks limbs (64-bit each)
/// Per Blueprint Section 5.1: little-endian limb order
pub fn embed_fq_limbs(fq_bytes: &[u8; 32]) -> [Goldilocks; 4] {
    let mut limbs = [Goldilocks::ZERO; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * 8;
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&fq_bytes[start..start + 8]);
        *limb = Goldilocks(u64::from_le_bytes(limb_bytes));
    }
    limbs
}

/// Add range16 constraints for all chunks of a limb
/// Per Blueprint 5.1: each limb decomposes into 4 16-bit chunks.
/// This helper only allocates chunk wires and range-checks them.
/// The caller must assign chunk values and enforce the reconstruction constraint.
pub fn constrain_limb_range16(ctx: &mut CompileContext, _limb: WRef) -> [WRef; 4] {
    let chunks = ctx.alloc_wires(4);
    for c in &chunks {
        ctx.range16(*c);
    }
    let limb = _limb;

    let mul_const = |ctx: &mut CompileContext, x: WRef, k: u64| -> WRef {
        let out = ctx.alloc_wire();
        ctx.ucir.add_arithmetic_gate(ArithmeticGate {
            a: x,
            b: WRef(0),
            c: out,
            q_mul: Goldilocks::ZERO,
            q_l: Goldilocks(k),
            q_r: Goldilocks::ZERO,
            q_o: Goldilocks::ONE.neg(),
            q_c: Goldilocks::ZERO,
        });
        out
    };

    let c1 = mul_const(ctx, chunks[1], 1u64 << 16);
    let c2 = mul_const(ctx, chunks[2], 1u64 << 32);
    let c3 = mul_const(ctx, chunks[3], 1u64 << 48);
    let s0 = ctx.add(chunks[0], c1);
    let s1 = ctx.add(s0, c2);
    let s2 = ctx.add(s1, c3);
    ctx.copy(s2, limb);

    [chunks[0], chunks[1], chunks[2], chunks[3]]
}

#[cfg(test)]
mod limb_tests {
    use super::*;

    #[test]
    fn test_constrain_limb_range16_includes_reconstruction_constraint() {
        let mut ctx = CompileContext::new(1);
        let limb = WRef(0);
        let _chunks = constrain_limb_range16(&mut ctx, limb);

        assert_eq!(ctx.ucir.lookups.len(), 4);
        assert!(ctx.ucir.lookups.iter().all(|l| l.table_id == TABLE_RANGE16));

        let has_copy = ctx.ucir.gates.iter().any(|g| match g {
            crate::glyph_ir::Gate::Copy(cg) => cg.right == limb || cg.left == limb,
            _ => false,
        });
        assert!(has_copy);
    }
}

// ============================================================
//                    HASH MERGE COMPILER (Blueprint 5.6)
// ============================================================

/// Compile hash merge adapter (with optional binding digests).
/// Verifies Keccak256(left || right) == expected and binds inputs as public.
#[cfg(feature = "hash")]
fn compile_hash_merge_with_bindings_impl(
    left: &[u8; 32],
    right: &[u8; 32],
    expected: &[u8; 32],
    bindings: &[[u8; 32]],
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_hash_profile_defaults();
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    let digest = crate::adapters::keccak256(&input);
    if &digest != expected {
        return Err(CompileError::VerificationFailed(
            "hash merge: expected digest mismatch".to_string(),
        ));
    }

    let mut public_inputs = Vec::with_capacity(12 + bindings.len() * 4);
    public_inputs.extend_from_slice(&embed_fq_limbs(left));
    public_inputs.extend_from_slice(&embed_fq_limbs(right));
    public_inputs.extend_from_slice(&embed_fq_limbs(expected));
    append_binding_digests(&mut public_inputs, bindings);

    let mut ctx = CompileContext::new(public_inputs.len() as u32);
    let left_start = WRef(0);
    let right_start = WRef(4);
    let out_start = WRef(8);

    let payload = encode_three_wref_payload(left_start, right_start, out_start);
    ctx.ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_KECCAK_MERGE, payload));

    let mut ucir = ctx.finalize();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);

    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

/// Compile hash merge adapter (no extra bindings).
pub fn compile_hash_merge(
    left: &[u8; 32],
    right: &[u8; 32],
    expected: &[u8; 32],
) -> Result<CompiledUcir, CompileError> {
    compile_hash_merge_with_bindings(left, right, expected, &[])
}

pub fn compile_hash_merge_with_bindings(
    left: &[u8; 32],
    right: &[u8; 32],
    expected: &[u8; 32],
    bindings: &[[u8; 32]],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Hash).map_err(gate_to_compile_error)?;
    #[cfg(feature = "hash")]
    {
        return compile_hash_merge_with_bindings_impl(left, right, expected, bindings);
    }
    #[cfg(not(feature = "hash"))]
    {
        let _ = (left, right, expected, bindings);
        Err(gate_to_compile_error(
            adapter_gate::ensure_family_enabled(AdapterFamily::Hash).unwrap_err(),
        ))
    }
}

// ============================================================
//                    ADAPTER COMPILERS
// ============================================================

/// Compile Groth16 BN254 with optional binding digests.
#[cfg(feature = "snark")]
#[allow(clippy::too_many_arguments)]
fn compile_groth16_bn254_with_bindings_impl(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
    bindings: &[[u8; 32]],
    beta_precomp: Option<&[u8]>,
    gamma_precomp: Option<&[u8]>,
    delta_precomp: Option<&[u8]>,
    ic_precomp: Option<&[G1WnafPrecomp]>,
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_groth16_bn254_profile_defaults();
    let vk = crate::bn254_groth16::decode_groth16_vk_bytes(vk_bytes)
        .map_err(CompileError::InvalidInput)?;
    let proof = crate::bn254_groth16::decode_groth16_proof_bytes(proof_bytes)
        .map_err(CompileError::InvalidInput)?;
    let inputs = crate::bn254_groth16::decode_groth16_public_inputs(public_inputs_bytes)
        .map_err(CompileError::InvalidInput)?;

    let events = crate::bn254_pairing_trace::record_groth16_pairing_ops_with_precomp(
        &vk,
        &proof,
        &inputs,
        beta_precomp,
        gamma_precomp,
        delta_precomp,
        ic_precomp,
    )
    .map_err(CompileError::InvalidInput)?;

    let mut public_inputs = fr_vec_to_public_inputs(&inputs);
    append_binding_digests(&mut public_inputs, bindings);
    let mut wire_values = Vec::new();
    let mut ctx = CompileContext::new(public_inputs.len() as u32);

    for event in events {
        let a_start = ctx.alloc_fq_limbs(&mut wire_values, event.a);
        let b_start = ctx.alloc_fq_limbs(&mut wire_values, event.b);
        let out_start = ctx.alloc_fq_limbs(&mut wire_values, event.out);
        let custom_id = match event.kind {
            crate::bn254_ops::Bn254OpKind::Add => CUSTOM_GATE_BN254_ADD,
            crate::bn254_ops::Bn254OpKind::Sub => CUSTOM_GATE_BN254_SUB,
            crate::bn254_ops::Bn254OpKind::Mul => CUSTOM_GATE_BN254_MUL,
        };
        let payload = encode_three_wref_payload(a_start, b_start, out_start);
        ctx.ucir.add_custom_gate(CustomGate::new(custom_id, payload));
    }

    let mut ucir = ctx.finalize();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, wire_values.len() as u32, 0);

    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values,
    })
}

/// Compile Groth16 BN254 (no extra bindings).
pub fn compile_groth16_bn254(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    compile_groth16_bn254_with_bindings(vk_bytes, proof_bytes, public_inputs_bytes, &[], None, None, None, None)
}

pub fn compile_groth16_bn254_with_bindings(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
    bindings: &[[u8; 32]],
    beta_precomp: Option<&[u8]>,
    gamma_precomp: Option<&[u8]>,
    delta_precomp: Option<&[u8]>,
    ic_precomp: Option<&[G1WnafPrecomp]>,
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254)
        .map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_groth16_bn254_with_bindings_impl(
            vk_bytes,
            proof_bytes,
            public_inputs_bytes,
            bindings,
            beta_precomp,
            gamma_precomp,
            delta_precomp,
            ic_precomp,
        );
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = (
            vk_bytes,
            proof_bytes,
            public_inputs_bytes,
            bindings,
            beta_precomp,
            gamma_precomp,
            delta_precomp,
            ic_precomp,
        );
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254).unwrap_err(),
        ))
    }
}

/// Compile KZG BN254 with optional binding digests.
#[cfg(feature = "snark")]
fn compile_kzg_bn254_with_bindings_impl(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
    bindings: &[[u8; 32]],
    g2s_precomp: Option<&[u8]>,
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_kzg_bn254_profile_defaults();
    let vk = crate::snark_kzg_bn254_adapter::decode_kzg_vk_bytes(vk_bytes)
        .map_err(CompileError::InvalidInput)?;
    let proof = crate::snark_kzg_bn254_adapter::decode_kzg_proof_bytes(proof_bytes)
        .map_err(CompileError::InvalidInput)?;
    let inputs = crate::snark_kzg_bn254_adapter::decode_kzg_public_inputs_bytes(public_inputs_bytes)
        .map_err(CompileError::InvalidInput)?;

    let events = crate::bn254_pairing_trace::record_kzg_pairing_ops_with_precomp(
        vk.g1,
        vk.g2,
        vk.g2_s,
        proof.commitment,
        proof.proof,
        inputs.z,
        inputs.y,
        g2s_precomp,
    )
    .map_err(CompileError::InvalidInput)?;

    let mut public_inputs = fr_vec_to_public_inputs(&[inputs.z, inputs.y]);
    append_binding_digests(&mut public_inputs, bindings);
    let mut wire_values = Vec::new();
    let mut ctx = CompileContext::new(public_inputs.len() as u32);

    for event in events {
        let a_start = ctx.alloc_fq_limbs(&mut wire_values, event.a);
        let b_start = ctx.alloc_fq_limbs(&mut wire_values, event.b);
        let out_start = ctx.alloc_fq_limbs(&mut wire_values, event.out);
        let custom_id = match event.kind {
            crate::bn254_ops::Bn254OpKind::Add => CUSTOM_GATE_BN254_ADD,
            crate::bn254_ops::Bn254OpKind::Sub => CUSTOM_GATE_BN254_SUB,
            crate::bn254_ops::Bn254OpKind::Mul => CUSTOM_GATE_BN254_MUL,
        };
        let payload = encode_three_wref_payload(a_start, b_start, out_start);
        ctx.ucir.add_custom_gate(CustomGate::new(custom_id, payload));
    }

    let mut ucir = ctx.finalize();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, wire_values.len() as u32, 0);

    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values,
    })
}

/// Compile KZG BN254 (no extra bindings).
pub fn compile_kzg_bn254(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    compile_kzg_bn254_with_bindings(vk_bytes, proof_bytes, public_inputs_bytes, &[], None)
}

pub fn compile_kzg_bn254_with_bindings(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
    bindings: &[[u8; 32]],
    g2s_precomp: Option<&[u8]>,
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254)
        .map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_kzg_bn254_with_bindings_impl(
            vk_bytes,
            proof_bytes,
            public_inputs_bytes,
            bindings,
            g2s_precomp,
        );
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = (vk_bytes, proof_bytes, public_inputs_bytes, bindings, g2s_precomp);
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).unwrap_err(),
        ))
    }
}

/// Compile IVC (GLYPH path)
#[cfg(feature = "ivc")]
fn compile_ivc_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_ivc_profile_defaults();
    let ir = crate::adapter_ir::AdapterIrView::decode(ir_bytes)
        .map_err(CompileError::InvalidInput)?;
    if ir.ops.len() != 1 {
        return Err(CompileError::InvalidInput(format!(
            "ivc requires exactly 1 op, got {}",
            ir.ops.len()
        )));
    }
    let op = &ir.ops[0];
    if op.kernel_id != crate::adapter_ir::kernel_id::IVC_VERIFY {
        return Err(CompileError::InvalidInput(format!(
            "ivc expected kernel_id=0x{:04x} got 0x{:04x}",
            crate::adapter_ir::kernel_id::IVC_VERIFY,
            op.kernel_id
        )));
    }
    if !op.args.is_empty() {
        return Err(CompileError::InvalidInput(
            "ivc op args must be empty".to_string(),
        ));
    }

    crate::adapters::apply_ivc_profile_defaults();
    let res = crate::ivc_adapter::derive_glyph_artifact_from_ivc_direct(
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    )
    .map_err(CompileError::VerificationFailed)?;

    // Bind the GLYPH artifact components as public inputs
    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&res.0));
    public_inputs.extend_from_slice(&embed_fq_limbs(&res.1));
    public_inputs.push(Goldilocks((res.2 >> 64) as u64));
    public_inputs.push(Goldilocks(res.2 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_ivc_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_IVC_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_ivc(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Ivc).map_err(gate_to_compile_error)?;
    #[cfg(feature = "ivc")]
    {
        return compile_ivc_impl(ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
    }
    #[cfg(not(feature = "ivc"))]
    {
        let _ = (ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
        Err(gate_to_compile_error(
            adapter_gate::ensure_family_enabled(AdapterFamily::Ivc).unwrap_err(),
        ))
    }
}

/// Compile Binius proofs (native constraint system receipts).
#[cfg(feature = "binius")]
fn compile_binius_impl(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_binius_profile_defaults();
    let (commitment_tag, point_tag, claim128) =
        crate::binius_adapter::derive_glyph_artifact_from_binius_receipt(
            adapter_vk_bytes,
            adapter_statement_bytes,
            proof_bytes,
        )
        .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_binius_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_BINIUS_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_binius(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Binius).map_err(gate_to_compile_error)?;
    #[cfg(feature = "binius")]
    {
        return compile_binius_impl(adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
    }
    #[cfg(not(feature = "binius"))]
    {
        let _ = (adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
        Err(gate_to_compile_error(
            adapter_gate::ensure_family_enabled(AdapterFamily::Binius).unwrap_err(),
        ))
    }
}

/// Compile IPA proofs (BN254 or BLS12-381 receipts).
#[cfg(feature = "snark")]
fn compile_ipa_impl(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_ipa_profile_defaults();
    let (commitment_tag, point_tag, claim128) =
        crate::ipa_adapter::derive_glyph_artifact_from_ipa_receipt(receipt_bytes)
            .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_ipa_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        receipt_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_IPA_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_ipa(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::IpaBn254).map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_ipa_impl(receipt_bytes);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = receipt_bytes;
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::IpaBn254).unwrap_err(),
        ))
    }
}

/// Compile SP1 proof receipts (Groth16/Plonk BN254).
#[cfg(feature = "snark")]
fn compile_sp1_impl(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_sp1_profile_defaults();
    let (commitment_tag, point_tag, claim128) =
        crate::sp1_adapter::derive_glyph_artifact_from_sp1_receipt(receipt_bytes)
            .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_sp1_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        receipt_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_SP1_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_sp1(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Sp1).map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_sp1_impl(receipt_bytes);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = receipt_bytes;
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::Sp1).unwrap_err(),
        ))
    }
}

/// Compile SNARK receipts (PLONK or Halo2 KZG).
#[cfg(feature = "snark")]
fn compile_plonk_impl(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_plonk_profile_defaults();
    let (commitment_tag, point_tag, claim128) =
        crate::plonk_halo2_adapter::derive_glyph_artifact_from_plonk_halo2_receipt(receipt_bytes)
            .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_plonk_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        receipt_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_PLONK_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_plonk(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Plonk).map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_plonk_impl(receipt_bytes);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = receipt_bytes;
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::Plonk).unwrap_err(),
        ))
    }
}

/// Compile Groth16 BLS12-381 receipt (off-chain verification).
#[cfg(feature = "snark")]
fn compile_groth16_bls12381_impl(
    receipt_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_groth16_bn254_profile_defaults();
    let (commitment_tag, point_tag, claim128) =
        crate::groth16_bls12381::derive_glyph_artifact_from_groth16_bls12381_receipt(
            receipt_bytes,
        )
        .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_groth16_bls12381_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        receipt_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_GROTH16_BLS12381_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_groth16_bls12381(
    receipt_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254)
        .map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_groth16_bls12381_impl(receipt_bytes);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = receipt_bytes;
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254).unwrap_err(),
        ))
    }
}

/// Compile KZG BLS12-381 receipt (off-chain verification).
#[cfg(feature = "snark")]
fn compile_kzg_bls12381_impl(
    receipt_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_kzg_bn254_profile_defaults();
    let (commitment_tag, point_tag, claim128) =
        crate::kzg_bls12381::derive_glyph_artifact_from_kzg_bls12381_receipt(
            receipt_bytes,
        )
        .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_kzg_bls12381_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        receipt_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_KZG_BLS12381_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_kzg_bls12381(
    receipt_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).map_err(gate_to_compile_error)?;
    #[cfg(feature = "snark")]
    {
        return compile_kzg_bls12381_impl(receipt_bytes);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = receipt_bytes;
        Err(gate_to_compile_error(
            adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).unwrap_err(),
        ))
    }
}


/// Compile generic STARK (canonical receipts)
#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
fn compile_stark_impl(
    receipt_bytes: &[u8],
    seed: &[u8],
) -> Result<CompiledUcir, CompileError> {
    crate::adapters::apply_stark_profile_defaults();
    let receipt = crate::stark_receipt::CanonicalStarkReceipt::decode(receipt_bytes)
        .map_err(CompileError::InvalidInput)?;
    let (commitment_tag, point_tag, claim128) =
        crate::stark_adapter::verified_canonical_stark_receipts_to_glyph_artifact(
            seed,
            &[receipt],
        )
        .map_err(CompileError::VerificationFailed)?;

    let mut public_inputs = Vec::new();
    public_inputs.extend_from_slice(&embed_fq_limbs(&commitment_tag));
    public_inputs.extend_from_slice(&embed_fq_limbs(&point_tag));
    public_inputs.push(Goldilocks((claim128 >> 64) as u64));
    public_inputs.push(Goldilocks(claim128 as u64));

    let mut ucir = Ucir2::new();
    ucir.witness_layout = WitnessLayout::fast_mode(public_inputs.len() as u32, 0, 0);
    let payload = encode_stark_verify_payload(
        WRef(0),
        WRef(4),
        WRef(8),
        seed,
        receipt_bytes,
    );
    ucir.add_custom_gate(CustomGate::new(CUSTOM_GATE_STARK_VERIFY, payload));
    Ok(CompiledUcir {
        ucir,
        public_inputs,
        wire_values: Vec::new(),
    })
}

pub fn compile_stark(
    receipt_bytes: &[u8],
    seed: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_any_stark_enabled().map_err(gate_to_compile_error)?;
    #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
    {
        return compile_stark_impl(receipt_bytes, seed);
    }
    #[cfg(not(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31")))]
    {
        let _ = (receipt_bytes, seed);
        Err(gate_to_compile_error(
            adapter_gate::ensure_any_stark_enabled().unwrap_err(),
        ))
    }
}

#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
fn compile_stark_with_validation_impl(
    family: AdapterFamily,
    receipt_bytes: &[u8],
    seed: &[u8],
    stark_field: Option<StarkField>,
) -> Result<CompiledUcir, CompileError> {
    let receipt = crate::stark_receipt::CanonicalStarkReceipt::decode(receipt_bytes)
        .map_err(CompileError::InvalidInput)?;
    let vk = crate::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&receipt)
        .map_err(CompileError::InvalidInput)?;
    if !stark_family_allows_field_id(family, vk.field_id) {
        return Err(CompileError::InvalidInput(
            "receipt field_id does not match selected --family stark-*".to_string(),
        ));
    }
    if let Some(field) = stark_field {
        let expected = field
            .field_id()
            .ok_or_else(|| CompileError::InvalidInput("selected --stark-field is not supported yet".to_string()))?;
        if vk.field_id != expected {
            return Err(CompileError::InvalidInput(
                "receipt field_id does not match --stark-field".to_string(),
            ));
        }
    }
    compile_stark(receipt_bytes, seed)
}

pub fn compile_stark_with_validation(
    family: AdapterFamily,
    receipt_bytes: &[u8],
    seed: &[u8],
    stark_field: Option<StarkField>,
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(family).map_err(gate_to_compile_error)?;
    #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
    {
        return compile_stark_with_validation_impl(family, receipt_bytes, seed, stark_field);
    }
    #[cfg(not(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31")))]
    {
        let _ = (family, receipt_bytes, seed, stark_field);
        Err(gate_to_compile_error(
            adapter_gate::ensure_any_stark_enabled().unwrap_err(),
        ))
    }
}

#[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
fn stark_family_allows_field_id(family: AdapterFamily, field_id: u8) -> bool {
    let matches = |field: StarkField| {
        field
            .field_id()
            .map(|id| id == field_id)
            .unwrap_or(false)
    };
    match family {
        AdapterFamily::StarkGoldilocks => {
            matches(StarkField::F128)
                || matches(StarkField::F64)
                || matches(StarkField::Goldilocks)
                || matches(StarkField::Plonky3Goldilocks)
                || matches(StarkField::MidenGoldilocks)
        }
        AdapterFamily::StarkBabyBear => {
            matches(StarkField::BabyBear)
                || matches(StarkField::Plonky3BabyBear)
                || matches(StarkField::BabyBearStd)
                || matches(StarkField::KoalaBear)
                || matches(StarkField::Plonky3KoalaBear)
        }
        AdapterFamily::StarkM31 => {
            matches(StarkField::CairoPrime)
                || matches(StarkField::M31)
                || matches(StarkField::Plonky3M31)
        }
        _ => false,
    }
}

// ============================================================
//                    TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_context_basic() {
        let mut ctx = CompileContext::new(2);

        let a = WRef(0); // public input
        let b = WRef(1); // public input
        let c = ctx.mul(a, b);
        let _d = ctx.add(c, a);

        let ucir = ctx.finalize();
        let (arith, copy, _) = ucir.gate_counts();
        assert_eq!(arith, 2); // mul + add
        assert_eq!(copy, 0);

        println!("Compile context basic test passed.");
    }

    #[test]
    #[cfg(feature = "hash")]
    fn test_compile_hash_merge() {
        let left = [0u8; 32];
        let right = [1u8; 32];
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&left);
        input[32..].copy_from_slice(&right);
        let expected = crate::adapters::keccak256(&input);

        let compiled = match compile_hash_merge(&left, &right, &expected) {
            Ok(compiled) => compiled,
            Err(err) => {
                assert!(false, "compile: {err:?}");
                return;
            }
        };
        assert_eq!(compiled.ucir.witness_layout.public_len as usize, compiled.public_inputs.len());

        println!("Hash merge compile test passed.");
    }

    #[test]
    fn test_embed_fq_limbs() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[8] = 2;
        bytes[16] = 3;
        bytes[24] = 4;

        let limbs = embed_fq_limbs(&bytes);
        assert_eq!(limbs[0].0, 1);
        assert_eq!(limbs[1].0, 2);
        assert_eq!(limbs[2].0, 3);
        assert_eq!(limbs[3].0, 4);

        println!("Embed Fq limbs test passed.");
    }

    #[test]
    #[cfg(feature = "snark")]
    fn test_groth16_bn254_precomp_reduces_custom_gates() {
        let _env_lock = crate::test_utils::lock_env();
        let _g2_auto = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_G2_PRECOMP_AUTO", "0");
        let _ic_auto = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_IC_PRECOMP_AUTO", "0");

        let (vk_bytes, proof_bytes, pub_bytes) =
            crate::snark_groth16_bn254_adapter::load_groth16_bn254_fixture_bytes()
                .map_err(|err| {
                    assert!(false, "fixture: {err}");
                })
                .ok()
                .unwrap_or_default();
        if vk_bytes.is_empty() {
            return;
        }
        let vk = match crate::bn254_groth16::decode_groth16_vk_bytes(&vk_bytes) {
            Ok(vk) => vk,
            Err(err) => {
                assert!(false, "vk decode: {err}");
                return;
            }
        };
        let beta_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.beta_g2);
        let gamma_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.gamma_g2);
        let delta_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.delta_g2);

        let compiled_no = match compile_groth16_bn254_with_bindings(
            &vk_bytes,
            &proof_bytes,
            &pub_bytes,
            &[],
            None,
            None,
            None,
            None,
        )
        {
            Ok(compiled) => compiled,
            Err(err) => {
                assert!(false, "compile without precomp: {err:?}");
                return;
            }
        };
        let compiled_pre = match compile_groth16_bn254_with_bindings(
            &vk_bytes,
            &proof_bytes,
            &pub_bytes,
            &[],
            Some(&beta_precomp),
            Some(&gamma_precomp),
            Some(&delta_precomp),
            None,
        )
        {
            Ok(compiled) => compiled,
            Err(err) => {
                assert!(false, "compile with precomp: {err:?}");
                return;
            }
        };

        let custom_no = compiled_no.ucir.gate_counts().2;
        let custom_pre = compiled_pre.ucir.gate_counts().2;
        assert!(custom_pre < custom_no);

    }
}
