use crate::adapter_gate;
use crate::adapters::{AdapterFamily, SnarkKind, StarkField};
use crate::glyph_ir_compiler::{
    compile_binius, compile_groth16_bls12381, compile_groth16_bn254, compile_hash_merge,
    compile_ivc, compile_kzg_bls12381, compile_kzg_bn254, compile_ipa, compile_plonk,
    compile_sp1, compile_stark_with_validation, CompiledUcir, CompileError,
};

fn gate_to_compile_error(err: String) -> CompileError {
    CompileError::Unsupported(err)
}

pub fn compile_groth16_bn254_checked(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254).map_err(gate_to_compile_error)?;
    compile_groth16_bn254(vk_bytes, proof_bytes, public_inputs_bytes)
}

pub fn compile_groth16_bls12381_checked(
    receipt_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254).map_err(gate_to_compile_error)?;
    compile_groth16_bls12381(receipt_bytes)
}

pub fn compile_kzg_bn254_checked(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).map_err(gate_to_compile_error)?;
    compile_kzg_bn254(vk_bytes, proof_bytes, public_inputs_bytes)
}

pub fn compile_kzg_bls12381_checked(
    receipt_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).map_err(gate_to_compile_error)?;
    compile_kzg_bls12381(receipt_bytes)
}

pub fn compile_ipa_checked(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::IpaBn254).map_err(gate_to_compile_error)?;
    compile_ipa(receipt_bytes)
}

pub fn compile_sp1_checked(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Sp1).map_err(gate_to_compile_error)?;
    compile_sp1(receipt_bytes)
}

pub fn compile_plonk_checked(receipt_bytes: &[u8]) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Plonk).map_err(gate_to_compile_error)?;
    compile_plonk(receipt_bytes)
}

pub fn compile_ivc_checked(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Ivc).map_err(gate_to_compile_error)?;
    compile_ivc(ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes)
}

pub fn compile_binius_checked(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Binius).map_err(gate_to_compile_error)?;
    compile_binius(adapter_vk_bytes, adapter_statement_bytes, proof_bytes)
}

pub fn compile_hash_merge_checked(
    left: &[u8; 32],
    right: &[u8; 32],
    expected: &[u8; 32],
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Hash).map_err(gate_to_compile_error)?;
    compile_hash_merge(left, right, expected)
}

pub fn compile_stark_checked(
    family: AdapterFamily,
    receipt_bytes: &[u8],
    seed: &[u8],
    stark_field: Option<StarkField>,
) -> Result<CompiledUcir, CompileError> {
    adapter_gate::ensure_family_enabled(family).map_err(gate_to_compile_error)?;
    if let Some(field) = stark_field {
        adapter_gate::ensure_stark_field_enabled(field).map_err(gate_to_compile_error)?;
        adapter_gate::ensure_stark_field_allowed(family, field).map_err(gate_to_compile_error)?;
    }
    compile_stark_with_validation(family, receipt_bytes, seed, stark_field)
}
