//! Canonical adapter IR for non-STARK families.
//!
//! This IR is intentionally small and kernel-oriented. It is a stable byte-level
//! interface for adapter kernels and is enforced by strict decoding rules.

pub const ADAPTER_IR_TAG: &[u8] = b"ADAPTER_IR";
pub const ADAPTER_IR_VERSION: u16 = 1;
use crate::adapter_gate;
use crate::adapters::{AdapterFamily, SnarkKind};
#[cfg(any(
    feature = "snark",
    feature = "ivc",
    feature = "hash"
))]
use rayon::prelude::*;

/// Kernel identifiers are stable protocol surface.
pub mod kernel_id {
    /// Hash: Keccak-256 merge of two 32-byte inputs.
    pub const HASH_SHA3_MERGE: u16 = 0x0101;
    /// Groth16 BN254 verification trace.
    pub const GROTH16_BN254_VERIFY: u16 = 0x0201;
    /// KZG BN254 opening verification trace.
    pub const KZG_BN254_VERIFY: u16 = 0x0202;
    /// IVC/Folding proof verification.
    pub const IVC_VERIFY: u16 = 0x0203;
    /// IPA verification (BN254 or BLS12-381).
    pub const IPA_VERIFY: u16 = 0x0204;
    /// STARK generic verification.
    pub const STARK_VERIFY: u16 = 0x0205;
    /// Binius native proof verification.
    pub const BINIUS_VERIFY: u16 = 0x0206;
    /// Winterfell SHA3 transcript kernel.
    pub const WINTERFELL_SHA3_TRANSCRIPT: u16 = 0x0301;
    /// Circle STARK transcript kernel.
    pub const CIRCLE_STARK_TRANSCRIPT: u16 = 0x0302;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIr {
    pub version: u16,
    pub ops: Vec<AdapterIrOp>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIrView<'a> {
    pub version: u16,
    pub ops: Vec<AdapterIrOpView<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIrOp {
    pub kernel_id: u16,
    pub args: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIrOpView<'a> {
    pub kernel_id: u16,
    pub args: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
struct AdapterIrCursor<'a> {
    bytes: &'a [u8],
    off: usize,
}

impl<'a> AdapterIrCursor<'a> {
    fn new(bytes: &'a [u8], off: usize) -> Self {
        Self { bytes, off }
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.off.checked_add(len).ok_or_else(|| "unexpected EOF".to_string())?;
        let slice = self
            .bytes
            .get(self.off..end)
            .ok_or_else(|| "unexpected EOF".to_string())?;
        self.off = end;
        Ok(slice)
    }

    fn read_u16_be(&mut self) -> Result<u16, String> {
        let s = self.read_slice(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_u32_be(&mut self) -> Result<u32, String> {
        let s = self.read_slice(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.off)
    }
}

impl AdapterIr {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ADAPTER_IR_TAG);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.ops.len() as u16).to_be_bytes());
        for op in self.ops.iter() {
            out.extend_from_slice(&op.kernel_id.to_be_bytes());
            out.extend_from_slice(&(op.args.len() as u32).to_be_bytes());
            out.extend_from_slice(&op.args);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        AdapterIrView::decode(bytes).map(|view| view.to_owned())
    }
}

impl<'a> AdapterIrView<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, String> {
        if !bytes.starts_with(ADAPTER_IR_TAG) {
            return Err("adapter ir bytes missing ADAPTER_IR_TAG prefix".to_string());
        }
        let mut cursor = AdapterIrCursor::new(bytes, ADAPTER_IR_TAG.len());
        let version = cursor.read_u16_be()?;
        if version != ADAPTER_IR_VERSION {
            return Err(format!(
                "unsupported adapter ir version={version} (expected {ADAPTER_IR_VERSION})"
            ));
        }
        let op_count = cursor.read_u16_be()? as usize;
        let mut ops = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            let kernel_id = cursor.read_u16_be()?;
            let args_len = cursor.read_u32_be()? as usize;
            let args = cursor.read_slice(args_len)?;
            ops.push(AdapterIrOpView { kernel_id, args });
        }
        if cursor.remaining() != 0 {
            return Err("adapter ir bytes have trailing data".to_string());
        }
        Ok(Self { version, ops })
    }

    pub fn to_owned(&self) -> AdapterIr {
        AdapterIr {
            version: self.version,
            ops: self
                .ops
                .iter()
                .map(|op| AdapterIrOp {
                    kernel_id: op.kernel_id,
                    args: op.args.to_vec(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HashSha3MergeResult {
    pub proof: crate::glyph_core::UniversalProof,
}

#[cfg(any(
    feature = "snark",
    feature = "ivc",
    feature = "hash",
    feature = "binius"
))]
fn prove_compiled_ucir(
    compiled: crate::glyph_ir_compiler::CompiledUcir,
) -> Result<crate::glyph_core::UniversalProof, String> {
    let mut config = crate::glyph_core::ProverConfig::default();
    if cfg!(test) {
        config.zk_seed = Some([0u8; 32]);
    }
    crate::glyph_core::prove_compiled(compiled, config)
        .map_err(|e| format!("glyph-prover failed: {e:?}"))
}

#[cfg(feature = "hash")]
fn execute_hash_sha3_merge_ir_impl(
    ir_bytes: &[u8],
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<HashSha3MergeResult, String> {
    crate::adapters::apply_hash_profile_defaults();
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "hash sha3 merge requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::HASH_SHA3_MERGE {
        return Err(format!(
            "execute_hash_sha3_merge_ir called with non-hash kernel_id={:04x} (expected {:04x})",
            op.kernel_id,
            kernel_id::HASH_SHA3_MERGE,
        ));
    }
    if !op.args.is_empty() {
        return Err("hash sha3 merge op args must be empty".to_string());
    }

    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    let expected = crate::adapters::keccak256(&input);
    let compiled = crate::glyph_ir_compiler::compile_hash_merge_with_bindings(
        left,
        right,
        &expected,
        &[],
    )
    .map_err(|e| format!("hash sha3 merge compile failed: {e:?}"))?;
    let proof = prove_compiled_ucir(compiled)?;

    Ok(HashSha3MergeResult { proof })
}

pub fn execute_hash_sha3_merge_ir(
    ir_bytes: &[u8],
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<HashSha3MergeResult, String> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Hash)?;
    #[cfg(feature = "hash")]
    {
        return execute_hash_sha3_merge_ir_impl(ir_bytes, left, right);
    }
    #[cfg(not(feature = "hash"))]
    {
        let _ = (ir_bytes, left, right);
        Err(adapter_gate::ensure_family_enabled(AdapterFamily::Hash).unwrap_err())
    }
}

pub fn derive_glyph_artifact_from_hash_ir(
    ir_bytes: &[u8],
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let res = execute_hash_sha3_merge_ir(ir_bytes, left, right)?;
    Ok((
        res.proof.artifact.commitment_tag,
        res.proof.artifact.point_tag,
        res.proof.artifact.claim128,
    ))
}

#[derive(Clone, Debug)]
pub struct Groth16Bn254Result {
    pub proof: crate::glyph_core::UniversalProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16Bn254BatchItem<'a> {
    pub adapter_statement_bytes: &'a [u8],
    pub raw_proof_bytes: &'a [u8],
    pub raw_public_inputs_bytes: &'a [u8],
}

#[cfg(feature = "snark")]
fn execute_groth16_bn254_ir_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<Groth16Bn254Result, String> {
    crate::adapters::apply_groth16_bn254_profile_defaults();
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "groth16 bn254 requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::GROTH16_BN254_VERIFY {
        return Err(format!(
            "execute_groth16_bn254_ir called with non-groth16 kernel_id={:04x} (expected {:04x})",
            op.kernel_id,
            kernel_id::GROTH16_BN254_VERIFY,
        ));
    }
    if !op.args.is_empty() {
        return Err("groth16 bn254 op args must be empty".to_string());
    }

    let adapter_vk = crate::adapters::decode_groth16_bn254_vk_bytes(adapter_vk_bytes)?;
    let adapter_statement =
        crate::adapters::decode_groth16_bn254_statement_bytes(adapter_statement_bytes)?;
    let (snark_id, curve_id, input_layout_hash, vk_hash_expected, beta_precomp, gamma_precomp, delta_precomp, ic_precomp) =
        match &adapter_vk {
            crate::adapters::Groth16Bn254Vk::Basic(basic) => (
                basic.snark_id,
                basic.curve_id,
                basic.input_layout_hash,
                basic.vk_hash,
                None,
                None,
                None,
                None,
            ),
            crate::adapters::Groth16Bn254Vk::G2Precomp(g2_precomp) => (
                g2_precomp.snark_id,
                g2_precomp.curve_id,
                g2_precomp.input_layout_hash,
                g2_precomp.vk_hash,
                Some(g2_precomp.beta_precomp.as_slice()),
                Some(g2_precomp.gamma_precomp.as_slice()),
                Some(g2_precomp.delta_precomp.as_slice()),
                None,
            ),
            crate::adapters::Groth16Bn254Vk::FullPrecomp(full_precomp) => (
                full_precomp.snark_id,
                full_precomp.curve_id,
                full_precomp.input_layout_hash,
                full_precomp.vk_hash,
                Some(full_precomp.beta_precomp.as_slice()),
                Some(full_precomp.gamma_precomp.as_slice()),
                Some(full_precomp.delta_precomp.as_slice()),
                Some((full_precomp.ic_precomp_window, full_precomp.ic_precomp.as_slice())),
            ),
        };
    if snark_id != crate::adapters::SNARK_GROTH16_BN254_ID {
        return Err("groth16 adapter vk snark_id mismatch".to_string());
    }
    if curve_id != crate::adapters::SNARK_GROTH16_BN254_CURVE_ID {
        return Err("groth16 adapter vk curve_id mismatch".to_string());
    }
    if input_layout_hash != adapter_statement.input_layout_hash {
        return Err("groth16 adapter input_layout_hash mismatch".to_string());
    }
    let raw_vk_hash = crate::adapters::keccak256(raw_vk_bytes);
    if raw_vk_hash != vk_hash_expected {
        return Err("groth16 adapter vk hash mismatch".to_string());
    }
    let raw_pub_hash = crate::adapters::keccak256(raw_public_inputs_bytes);
    if raw_pub_hash != adapter_statement.public_inputs_hash {
        return Err("groth16 adapter public inputs hash mismatch".to_string());
    }

    let _vk = crate::bn254_groth16::decode_groth16_vk_bytes(raw_vk_bytes)?;
    let _proof = crate::bn254_groth16::decode_groth16_proof_bytes(raw_proof_bytes)?;
    let _public_inputs =
        crate::bn254_groth16::decode_groth16_public_inputs(raw_public_inputs_bytes)?;

    let ic_precomp_tables = if let Some((window, entries)) = ic_precomp {
        let enabled = std::env::var("GLYPH_GROTH16_BN254_TRACE_IC_PRECOMP")
            .ok()
            .as_deref()
            .map(|v| v != "0")
            .unwrap_or(true);
        if enabled {
            let window = window as usize;
            let mut tables = Vec::with_capacity(entries.len());
            for entry in entries {
                let table = crate::bn254_pairing_trace::decode_g1_wnaf_precomp_pair(
                    window,
                    &entry.base_precomp,
                    &entry.phi_precomp,
                )?;
                tables.push(table);
            }
            Some(tables)
        } else {
            None
        }
    } else {
        None
    };

    let vk_hash = crate::adapters::vk_hash_from_bytes(
        crate::adapters::AdapterFamily::Snark,
        crate::adapters::SNARK_SUB_GROTH16_BN254,
        adapter_vk_bytes,
    );
    let statement_hash = crate::adapters::statement_hash_from_bytes(
        crate::adapters::AdapterFamily::Snark,
        crate::adapters::SNARK_SUB_GROTH16_BN254,
        adapter_statement_bytes,
    );
    let proof_hash = crate::adapters::keccak256(raw_proof_bytes);
    let pub_hash = crate::adapters::keccak256(raw_public_inputs_bytes);
    let bindings = [vk_hash, statement_hash, proof_hash, pub_hash];
    let compiled = crate::glyph_ir_compiler::compile_groth16_bn254_with_bindings(
        raw_vk_bytes,
        raw_proof_bytes,
        raw_public_inputs_bytes,
        &bindings,
        beta_precomp,
        gamma_precomp,
        delta_precomp,
        ic_precomp_tables.as_deref(),
    )
    .map_err(|e| format!("groth16 bn254 compile failed: {e:?}"))?;
    let proof = prove_compiled_ucir(compiled)?;

    Ok(Groth16Bn254Result { proof })
}

pub fn execute_groth16_bn254_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<Groth16Bn254Result, String> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254)?;
    #[cfg(feature = "snark")]
    {
        return execute_groth16_bn254_ir_impl(
            ir_bytes,
            adapter_vk_bytes,
            adapter_statement_bytes,
            raw_vk_bytes,
            raw_proof_bytes,
            raw_public_inputs_bytes,
        );
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = (
            ir_bytes,
            adapter_vk_bytes,
            adapter_statement_bytes,
            raw_vk_bytes,
            raw_proof_bytes,
            raw_public_inputs_bytes,
        );
        Err(adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254).unwrap_err())
    }
}

#[cfg(feature = "snark")]
fn execute_groth16_bn254_ir_batch_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    raw_vk_bytes: &[u8],
    items: &[Groth16Bn254BatchItem<'_>],
) -> Result<Vec<Groth16Bn254Result>, String> {
    crate::adapters::apply_groth16_bn254_profile_defaults();
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "groth16 bn254 batch requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::GROTH16_BN254_VERIFY {
        return Err(format!(
            "execute_groth16_bn254_ir_batch called with non-groth16 kernel_id={:04x} (expected {:04x})",
            op.kernel_id,
            kernel_id::GROTH16_BN254_VERIFY,
        ));
    }
    if !op.args.is_empty() {
        return Err("groth16 bn254 batch op args must be empty".to_string());
    }

    let adapter_vk = crate::adapters::decode_groth16_bn254_vk_bytes(adapter_vk_bytes)?;
    let (snark_id, curve_id, input_layout_hash, vk_hash_expected, beta_precomp, gamma_precomp, delta_precomp, ic_precomp) =
        match &adapter_vk {
            crate::adapters::Groth16Bn254Vk::Basic(basic) => (
                basic.snark_id,
                basic.curve_id,
                basic.input_layout_hash,
                basic.vk_hash,
                None,
                None,
                None,
                None,
            ),
            crate::adapters::Groth16Bn254Vk::G2Precomp(g2_precomp) => (
                g2_precomp.snark_id,
                g2_precomp.curve_id,
                g2_precomp.input_layout_hash,
                g2_precomp.vk_hash,
                Some(g2_precomp.beta_precomp.as_slice()),
                Some(g2_precomp.gamma_precomp.as_slice()),
                Some(g2_precomp.delta_precomp.as_slice()),
                None,
            ),
            crate::adapters::Groth16Bn254Vk::FullPrecomp(full_precomp) => (
                full_precomp.snark_id,
                full_precomp.curve_id,
                full_precomp.input_layout_hash,
                full_precomp.vk_hash,
                Some(full_precomp.beta_precomp.as_slice()),
                Some(full_precomp.gamma_precomp.as_slice()),
                Some(full_precomp.delta_precomp.as_slice()),
                Some((full_precomp.ic_precomp_window, full_precomp.ic_precomp.as_slice())),
            ),
        };
    if snark_id != crate::adapters::SNARK_GROTH16_BN254_ID {
        return Err("groth16 batch adapter vk snark_id mismatch".to_string());
    }
    if curve_id != crate::adapters::SNARK_GROTH16_BN254_CURVE_ID {
        return Err("groth16 batch adapter vk curve_id mismatch".to_string());
    }
    let raw_vk_hash = crate::adapters::keccak256(raw_vk_bytes);
    if raw_vk_hash != vk_hash_expected {
        return Err("groth16 batch adapter vk hash mismatch".to_string());
    }

    let ic_precomp_tables = if let Some((window, entries)) = ic_precomp {
        let enabled = std::env::var("GLYPH_GROTH16_BN254_TRACE_IC_PRECOMP")
            .ok()
            .as_deref()
            .map(|v| v != "0")
            .unwrap_or(true);
        if enabled {
            let window = window as usize;
            let mut tables = Vec::with_capacity(entries.len());
            for entry in entries {
                let table = crate::bn254_pairing_trace::decode_g1_wnaf_precomp_pair(
                    window,
                    &entry.base_precomp,
                    &entry.phi_precomp,
                )?;
                tables.push(table);
            }
            Some(tables)
        } else {
            None
        }
    } else {
        None
    };

    struct PreparedGroth16Bn254<'a> {
        statement_hash: [u8; 32],
        proof_hash: [u8; 32],
        pub_hash: [u8; 32],
        proof_bytes: &'a [u8],
        public_inputs_bytes: &'a [u8],
    }

    fn prepare_groth16_bn254_item<'a>(
        input_layout_hash: [u8; 32],
        item: &'a Groth16Bn254BatchItem<'a>,
    ) -> Result<PreparedGroth16Bn254<'a>, String> {
        let adapter_statement =
            crate::adapters::decode_groth16_bn254_statement_bytes(item.adapter_statement_bytes)?;
        let _proof = crate::bn254_groth16::decode_groth16_proof_bytes(item.raw_proof_bytes)?;
        let _public_inputs =
            crate::bn254_groth16::decode_groth16_public_inputs(item.raw_public_inputs_bytes)?;
        if input_layout_hash != adapter_statement.input_layout_hash {
            return Err("groth16 batch adapter input_layout_hash mismatch".to_string());
        }
        let raw_pub_hash = crate::adapters::keccak256(item.raw_public_inputs_bytes);
        if raw_pub_hash != adapter_statement.public_inputs_hash {
            return Err("groth16 batch adapter public inputs hash mismatch".to_string());
        }
        Ok(PreparedGroth16Bn254 {
            statement_hash: crate::adapters::statement_hash_from_bytes(
                crate::adapters::AdapterFamily::Snark,
                crate::adapters::SNARK_SUB_GROTH16_BN254,
                item.adapter_statement_bytes,
            ),
            proof_hash: crate::adapters::keccak256(item.raw_proof_bytes),
            pub_hash: raw_pub_hash,
            proof_bytes: item.raw_proof_bytes,
            public_inputs_bytes: item.raw_public_inputs_bytes,
        })
    }
    let prepared = if items.len() >= 8 {
        items
            .par_iter()
            .map(|item| prepare_groth16_bn254_item(input_layout_hash, item))
            .collect::<Result<Vec<_>, String>>()?
    } else {
        items
            .iter()
            .map(|item| prepare_groth16_bn254_item(input_layout_hash, item))
            .collect::<Result<Vec<_>, String>>()?
    };

    let vk_hash = crate::adapters::vk_hash_from_bytes(
        crate::adapters::AdapterFamily::Snark,
        crate::adapters::SNARK_SUB_GROTH16_BN254,
        adapter_vk_bytes,
    );
    let compile_item = |item: &PreparedGroth16Bn254<'_>| -> Result<Groth16Bn254Result, String> {
        let bindings = [vk_hash, item.statement_hash, item.proof_hash, item.pub_hash];
        let compiled = crate::glyph_ir_compiler::compile_groth16_bn254_with_bindings(
            raw_vk_bytes,
            item.proof_bytes,
            item.public_inputs_bytes,
            &bindings,
            beta_precomp,
            gamma_precomp,
            delta_precomp,
            ic_precomp_tables.as_deref(),
        )
        .map_err(|e| format!("groth16 bn254 compile failed: {e:?}"))?;
        let proof = prove_compiled_ucir(compiled)?;
        Ok(Groth16Bn254Result { proof })
    };
    if prepared.len() >= 4 {
        prepared.par_iter().map(compile_item).collect()
    } else {
        prepared.iter().map(compile_item).collect()
    }
}

pub fn execute_groth16_bn254_ir_batch(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    raw_vk_bytes: &[u8],
    items: &[Groth16Bn254BatchItem<'_>],
) -> Result<Vec<Groth16Bn254Result>, String> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254)?;
    #[cfg(feature = "snark")]
    {
        return execute_groth16_bn254_ir_batch_impl(ir_bytes, adapter_vk_bytes, raw_vk_bytes, items);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = (ir_bytes, adapter_vk_bytes, raw_vk_bytes, items);
        Err(adapter_gate::ensure_snark_kind_enabled(SnarkKind::Groth16Bn254).unwrap_err())
    }
}

pub fn derive_glyph_artifact_from_groth16_bn254_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let res = execute_groth16_bn254_ir(
        ir_bytes,
        adapter_vk_bytes,
        adapter_statement_bytes,
        raw_vk_bytes,
        raw_proof_bytes,
        raw_public_inputs_bytes,
    )?;
    Ok((
        res.proof.artifact.commitment_tag,
        res.proof.artifact.point_tag,
        res.proof.artifact.claim128,
    ))
}

#[derive(Clone, Debug)]
pub struct KzgBn254Result {
    pub proof: crate::glyph_core::UniversalProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgBn254BatchItem<'a> {
    pub adapter_statement_bytes: &'a [u8],
    pub raw_proof_bytes: &'a [u8],
    pub raw_public_inputs_bytes: &'a [u8],
}

#[cfg(feature = "snark")]
fn execute_kzg_bn254_ir_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<KzgBn254Result, String> {
    crate::adapters::apply_kzg_bn254_profile_defaults();
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "kzg bn254 requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::KZG_BN254_VERIFY {
        return Err(format!(
            "kzg bn254 expected kernel_id=0x{:04x} got 0x{:04x}",
            kernel_id::KZG_BN254_VERIFY,
            op.kernel_id
        ));
    }
    if !op.args.is_empty() {
        return Err("kzg bn254 op args must be empty".to_string());
    }

    let adapter_vk = crate::adapters::decode_kzg_bn254_vk_bytes(adapter_vk_bytes)?;
    let _adapter_statement =
        crate::adapters::decode_kzg_bn254_statement_bytes(adapter_statement_bytes)?;
    let (snark_id, curve_id, kzg_params_hash, vk_hash_expected, input_layout_hash, g2s_precomp) =
        match &adapter_vk {
            crate::adapters::KzgBn254Vk::Basic(basic) => (
                basic.snark_id,
                basic.curve_id,
                basic.kzg_params_hash,
                basic.vk_hash,
                basic.input_layout_hash,
                None,
            ),
            crate::adapters::KzgBn254Vk::G2Precomp(g2_precomp) => (
                g2_precomp.snark_id,
                g2_precomp.curve_id,
                g2_precomp.kzg_params_hash,
                g2_precomp.vk_hash,
                g2_precomp.input_layout_hash,
                Some(g2_precomp.g2_s_precomp.as_slice()),
            ),
        };
    if snark_id != crate::adapters::SNARK_KZG_PLONK_ID {
        return Err("kzg adapter vk snark_id mismatch".to_string());
    }
    if curve_id != crate::adapters::SNARK_KZG_BN254_CURVE_ID {
        return Err("kzg adapter vk curve_id mismatch".to_string());
    }
    if input_layout_hash != _adapter_statement.input_layout_hash {
        return Err("kzg adapter input_layout_hash mismatch".to_string());
    }

    let vk = crate::snark_kzg_bn254_adapter::decode_kzg_vk_bytes(raw_vk_bytes)?;
    let raw_vk_hash = crate::adapters::keccak256(raw_vk_bytes);
    if raw_vk_hash != vk_hash_expected {
        return Err("kzg adapter vk hash mismatch".to_string());
    }
    let params_hash = crate::snark_kzg_bn254_adapter::encode_kzg_params_bytes(&vk);
    let params_hash = crate::adapters::keccak256(&params_hash);
    if params_hash != kzg_params_hash {
        return Err("kzg adapter params hash mismatch".to_string());
    }
    let raw_pub_hash = crate::adapters::keccak256(raw_public_inputs_bytes);
    if raw_pub_hash != _adapter_statement.public_inputs_hash {
        return Err("kzg adapter public inputs hash mismatch".to_string());
    }

    let _proof = crate::snark_kzg_bn254_adapter::decode_kzg_proof_bytes(raw_proof_bytes)?;
    let _inputs =
        crate::snark_kzg_bn254_adapter::decode_kzg_public_inputs_bytes(raw_public_inputs_bytes)?;

    let vk_hash = crate::adapters::vk_hash_from_bytes(
        crate::adapters::AdapterFamily::Snark,
        crate::adapters::SNARK_SUB_KZG_BN254,
        adapter_vk_bytes,
    );
    let statement_hash = crate::adapters::statement_hash_from_bytes(
        crate::adapters::AdapterFamily::Snark,
        crate::adapters::SNARK_SUB_KZG_BN254,
        adapter_statement_bytes,
    );
    let proof_hash = crate::adapters::keccak256(raw_proof_bytes);
    let pub_hash = crate::adapters::keccak256(raw_public_inputs_bytes);
    let bindings = [vk_hash, statement_hash, proof_hash, pub_hash];
    let compiled = crate::glyph_ir_compiler::compile_kzg_bn254_with_bindings(
        raw_vk_bytes,
        raw_proof_bytes,
        raw_public_inputs_bytes,
        &bindings,
        g2s_precomp,
    )
    .map_err(|e| format!("kzg bn254 compile failed: {e:?}"))?;
    let proof = prove_compiled_ucir(compiled)?;

    Ok(KzgBn254Result { proof })
}

pub fn execute_kzg_bn254_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<KzgBn254Result, String> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254)?;
    #[cfg(feature = "snark")]
    {
        return execute_kzg_bn254_ir_impl(
            ir_bytes,
            adapter_vk_bytes,
            adapter_statement_bytes,
            raw_vk_bytes,
            raw_proof_bytes,
            raw_public_inputs_bytes,
        );
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = (
            ir_bytes,
            adapter_vk_bytes,
            adapter_statement_bytes,
            raw_vk_bytes,
            raw_proof_bytes,
            raw_public_inputs_bytes,
        );
        Err(adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).unwrap_err())
    }
}

#[cfg(feature = "snark")]
fn execute_kzg_bn254_ir_batch_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    raw_vk_bytes: &[u8],
    items: &[KzgBn254BatchItem<'_>],
) -> Result<Vec<KzgBn254Result>, String> {
    crate::adapters::apply_kzg_bn254_profile_defaults();
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "kzg bn254 batch requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::KZG_BN254_VERIFY {
        return Err(format!(
            "kzg bn254 batch expected kernel_id=0x{:04x} got 0x{:04x}",
            kernel_id::KZG_BN254_VERIFY,
            op.kernel_id
        ));
    }
    if !op.args.is_empty() {
        return Err("kzg bn254 batch op args must be empty".to_string());
    }

    let adapter_vk = crate::adapters::decode_kzg_bn254_vk_bytes(adapter_vk_bytes)?;
    let (snark_id, curve_id, kzg_params_hash, vk_hash_expected, input_layout_hash, g2s_precomp) =
        match &adapter_vk {
            crate::adapters::KzgBn254Vk::Basic(basic) => (
                basic.snark_id,
                basic.curve_id,
                basic.kzg_params_hash,
                basic.vk_hash,
                basic.input_layout_hash,
                None,
            ),
            crate::adapters::KzgBn254Vk::G2Precomp(g2_precomp) => (
                g2_precomp.snark_id,
                g2_precomp.curve_id,
                g2_precomp.kzg_params_hash,
                g2_precomp.vk_hash,
                g2_precomp.input_layout_hash,
                Some(g2_precomp.g2_s_precomp.as_slice()),
            ),
        };
    if snark_id != crate::adapters::SNARK_KZG_PLONK_ID {
        return Err("kzg batch adapter vk snark_id mismatch".to_string());
    }
    if curve_id != crate::adapters::SNARK_KZG_BN254_CURVE_ID {
        return Err("kzg batch adapter vk curve_id mismatch".to_string());
    }
    let vk = crate::snark_kzg_bn254_adapter::decode_kzg_vk_bytes(raw_vk_bytes)?;
    let raw_vk_hash = crate::adapters::keccak256(raw_vk_bytes);
    if raw_vk_hash != vk_hash_expected {
        return Err("kzg batch adapter vk hash mismatch".to_string());
    }
    let params_hash = crate::snark_kzg_bn254_adapter::encode_kzg_params_bytes(&vk);
    let params_hash = crate::adapters::keccak256(&params_hash);
    if params_hash != kzg_params_hash {
        return Err("kzg batch adapter params hash mismatch".to_string());
    }

    let _ = vk;

    struct PreparedKzgBn254<'a> {
        statement_hash: [u8; 32],
        proof_hash: [u8; 32],
        pub_hash: [u8; 32],
        proof_bytes: &'a [u8],
        public_inputs_bytes: &'a [u8],
    }

    fn prepare_kzg_bn254_item<'a>(
        input_layout_hash: [u8; 32],
        item: &'a KzgBn254BatchItem<'a>,
    ) -> Result<PreparedKzgBn254<'a>, String> {
        let adapter_statement =
            crate::adapters::decode_kzg_bn254_statement_bytes(item.adapter_statement_bytes)?;
        let _proof =
            crate::snark_kzg_bn254_adapter::decode_kzg_proof_bytes(item.raw_proof_bytes)?;
        let _inputs =
            crate::snark_kzg_bn254_adapter::decode_kzg_public_inputs_bytes(item.raw_public_inputs_bytes)?;
        if input_layout_hash != adapter_statement.input_layout_hash {
            return Err("kzg batch adapter input_layout_hash mismatch".to_string());
        }
        let raw_pub_hash = crate::adapters::keccak256(item.raw_public_inputs_bytes);
        if raw_pub_hash != adapter_statement.public_inputs_hash {
            return Err("kzg batch adapter public inputs hash mismatch".to_string());
        }
        Ok(PreparedKzgBn254 {
            statement_hash: crate::adapters::statement_hash_from_bytes(
                crate::adapters::AdapterFamily::Snark,
                crate::adapters::SNARK_SUB_KZG_BN254,
                item.adapter_statement_bytes,
            ),
            proof_hash: crate::adapters::keccak256(item.raw_proof_bytes),
            pub_hash: raw_pub_hash,
            proof_bytes: item.raw_proof_bytes,
            public_inputs_bytes: item.raw_public_inputs_bytes,
        })
    }
    let prepared = if items.len() >= 8 {
        items
            .par_iter()
            .map(|item| prepare_kzg_bn254_item(input_layout_hash, item))
            .collect::<Result<Vec<_>, String>>()?
    } else {
        items
            .iter()
            .map(|item| prepare_kzg_bn254_item(input_layout_hash, item))
            .collect::<Result<Vec<_>, String>>()?
    };

    let vk_hash = crate::adapters::vk_hash_from_bytes(
        crate::adapters::AdapterFamily::Snark,
        crate::adapters::SNARK_SUB_KZG_BN254,
        adapter_vk_bytes,
    );
    let compile_item = |item: &PreparedKzgBn254<'_>| -> Result<KzgBn254Result, String> {
        let bindings = [vk_hash, item.statement_hash, item.proof_hash, item.pub_hash];
        let compiled = crate::glyph_ir_compiler::compile_kzg_bn254_with_bindings(
            raw_vk_bytes,
            item.proof_bytes,
            item.public_inputs_bytes,
            &bindings,
            g2s_precomp,
        )
        .map_err(|e| format!("kzg bn254 compile failed: {e:?}"))?;
        let proof = prove_compiled_ucir(compiled)?;
        Ok(KzgBn254Result { proof })
    };
    if prepared.len() >= 4 {
        prepared.par_iter().map(compile_item).collect()
    } else {
        prepared.iter().map(compile_item).collect()
    }
}

pub fn execute_kzg_bn254_ir_batch(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    raw_vk_bytes: &[u8],
    items: &[KzgBn254BatchItem<'_>],
) -> Result<Vec<KzgBn254Result>, String> {
    adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254)?;
    #[cfg(feature = "snark")]
    {
        return execute_kzg_bn254_ir_batch_impl(ir_bytes, adapter_vk_bytes, raw_vk_bytes, items);
    }
    #[cfg(not(feature = "snark"))]
    {
        let _ = (ir_bytes, adapter_vk_bytes, raw_vk_bytes, items);
        Err(adapter_gate::ensure_snark_kind_enabled(SnarkKind::KzgBn254).unwrap_err())
    }
}

pub fn derive_glyph_artifact_from_kzg_bn254_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let res = execute_kzg_bn254_ir(
        ir_bytes,
        adapter_vk_bytes,
        adapter_statement_bytes,
        raw_vk_bytes,
        raw_proof_bytes,
        raw_public_inputs_bytes,
    )?;
    Ok((
        res.proof.artifact.commitment_tag,
        res.proof.artifact.point_tag,
        res.proof.artifact.claim128,
    ))
}

#[derive(Clone, Debug)]
pub struct IvcResult {
    pub proof: crate::glyph_core::UniversalProof,
}

#[cfg(feature = "ivc")]
fn execute_ivc_ir_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<IvcResult, String> {
    crate::adapters::apply_ivc_profile_defaults();
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "ivc requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::IVC_VERIFY {
        return Err(format!(
            "ivc expected kernel_id=0x{:04x} got 0x{:04x}",
            kernel_id::IVC_VERIFY,
            op.kernel_id
        ));
    }
    if !op.args.is_empty() {
        return Err("ivc op args must be empty".to_string());
    }
    let _vk = crate::adapters::decode_ivc_vk_bytes(adapter_vk_bytes)?;
    let _statement = crate::adapters::decode_ivc_statement_bytes(adapter_statement_bytes)?;
    let _proof = crate::ivc_adapter::decode_ivc_proof_bytes(proof_bytes)?;
    let compiled = crate::glyph_ir_compiler::compile_ivc(
        ir_bytes,
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    )
    .map_err(|e| format!("ivc compile failed: {e:?}"))?;
    let proof = prove_compiled_ucir(compiled)?;
    Ok(IvcResult { proof })
}

pub fn execute_ivc_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<IvcResult, String> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Ivc)?;
    #[cfg(feature = "ivc")]
    {
        return execute_ivc_ir_impl(ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
    }
    #[cfg(not(feature = "ivc"))]
    {
        let _ = (ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
        Err(adapter_gate::ensure_family_enabled(AdapterFamily::Ivc).unwrap_err())
    }
}

pub fn derive_glyph_artifact_from_ivc_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let res = execute_ivc_ir(ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes)?;
    Ok((
        res.proof.artifact.commitment_tag,
        res.proof.artifact.point_tag,
        res.proof.artifact.claim128,
    ))
}

#[derive(Clone, Debug)]
pub struct BiniusResult {
    pub proof: crate::glyph_core::UniversalProof,
}

#[cfg(feature = "binius")]
fn execute_binius_ir_impl(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<BiniusResult, String> {
    crate::adapters::apply_binius_profile_defaults();
    let ir = AdapterIrView::decode(ir_bytes)?;
    if ir.ops.len() != 1 {
        return Err(format!(
            "binius requires exactly 1 op, got {}",
            ir.ops.len()
        ));
    }
    let op = &ir.ops[0];
    if op.kernel_id != kernel_id::BINIUS_VERIFY {
        return Err(format!(
            "binius expected kernel_id=0x{:04x} got 0x{:04x}",
            kernel_id::BINIUS_VERIFY,
            op.kernel_id
        ));
    }
    if !op.args.is_empty() {
        return Err("binius op args must be empty".to_string());
    }
    let _vk = crate::adapters::decode_binius_vk_bytes(adapter_vk_bytes)?;
    let _statement = crate::adapters::decode_binius_statement_bytes(adapter_statement_bytes)?;
    let _proof = crate::binius_adapter::decode_binius_proof_bytes(proof_bytes)?;
    let compiled = crate::glyph_ir_compiler::compile_binius(
        adapter_vk_bytes,
        adapter_statement_bytes,
        proof_bytes,
    )
    .map_err(|e| format!("binius compile failed: {e:?}"))?;
    let proof = prove_compiled_ucir(compiled)?;
    Ok(BiniusResult { proof })
}

pub fn execute_binius_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<BiniusResult, String> {
    adapter_gate::ensure_family_enabled(AdapterFamily::Binius)?;
    #[cfg(feature = "binius")]
    {
        return execute_binius_ir_impl(ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
    }
    #[cfg(not(feature = "binius"))]
    {
        let _ = (ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes);
        Err(adapter_gate::ensure_family_enabled(AdapterFamily::Binius).unwrap_err())
    }
}

pub fn derive_glyph_artifact_from_binius_ir(
    ir_bytes: &[u8],
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    proof_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let res = execute_binius_ir(ir_bytes, adapter_vk_bytes, adapter_statement_bytes, proof_bytes)?;
    Ok((
        res.proof.artifact.commitment_tag,
        res.proof.artifact.point_tag,
        res.proof.artifact.claim128,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_field::underlier::WithUnderlier;
    use crate::pcs_basefold::{BaseFoldConfig, BaseFoldProver, derive_basefold_commitment_tag, derive_basefold_point_tag};

    #[test]
    fn test_adapter_ir_roundtrip_and_tamper_fails() {
        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![
                AdapterIrOp {
                    kernel_id: kernel_id::HASH_SHA3_MERGE,
                    args: vec![],
                },
                AdapterIrOp {
                    kernel_id: 0xDEAD,
                    args: vec![1, 2, 3],
                },
            ],
        };
        let enc = ir.encode();
        let view = match AdapterIrView::decode(&enc) {
            Ok(view) => view,
            Err(err) => {
                assert!(false, "decode must succeed: {err}");
                return;
            }
        };
        assert_eq!(view.to_owned(), ir);
        let args_ptr = view.ops[1].args.as_ptr() as usize;
        let enc_ptr = enc.as_ptr() as usize;
        let enc_end = enc_ptr + enc.len();
        assert!(args_ptr >= enc_ptr && args_ptr < enc_end);
        let decoded = match AdapterIr::decode(&enc) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode must succeed: {err}");
                return;
            }
        };
        assert_eq!(decoded, ir);

        let mut tampered = enc.clone();
        tampered.push(0);
        assert!(AdapterIr::decode(&tampered).is_err());
    }

    #[cfg(feature = "hash")]
    #[test]
    fn test_hash_sha3_merge_ir_roundtrip() {
        let left = crate::adapters::keccak256(b"adapter-ir-left");
        let right = crate::adapters::keccak256(b"adapter-ir-right");

        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: kernel_id::HASH_SHA3_MERGE,
                args: vec![],
            }],
        };
        let ir_bytes = ir.encode();

        let via_ir = match derive_glyph_artifact_from_hash_ir(&ir_bytes, &left, &right) {
            Ok(via_ir) => via_ir,
            Err(err) => {
                assert!(false, "ir hash artifact: {err}");
                return;
            }
        };
        assert_ne!(via_ir.0, [0u8; 32]);
        assert_ne!(via_ir.1, [0u8; 32]);
        assert_ne!(via_ir.2, 0u128);

        let bad_ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: 0xBEEF,
                args: vec![],
            }],
        };
        assert!(execute_hash_sha3_merge_ir(&bad_ir.encode(), &left, &right).is_err());
    }

    #[cfg(feature = "snark")]
    #[test]
    fn test_groth16_bn254_ir_rejects_wrong_kernel() {
        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: 0xBEEF,
                args: vec![],
            }],
        };
        assert!(execute_groth16_bn254_ir(&ir.encode(), &[], &[], &[], &[], &[]).is_err());
    }

    #[cfg(feature = "snark")]
    #[test]
    fn test_kzg_bn254_ir_rejects_wrong_kernel() {
        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: 0xBEEF,
                args: vec![],
            }],
        };
        assert!(execute_kzg_bn254_ir(&ir.encode(), &[], &[], &[], &[], &[]).is_err());
    }

    #[cfg(feature = "ivc")]
    #[test]
    fn test_ivc_ir_rejects_wrong_kernel() {
        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: 0xBEEF,
                args: vec![],
            }],
        };
        assert!(execute_ivc_ir(&ir.encode(), &[], &[], &[]).is_err());
    }

    #[cfg(feature = "ivc")]
    #[test]
    fn test_ivc_ir_roundtrip_smoke() {
        let inst = crate::adapters::keccak256(b"adapter-ir-ivc");
        let instance_digests = vec![inst];
        let weights = match crate::glyph_basefold::derive_basefold_weights(&instance_digests) {
            Ok(weights) => weights,
            Err(err) => {
                assert!(false, "weights: {err}");
                return;
            }
        };
        let n_vars = 3usize;
        let eval_point =
            crate::glyph_basefold::derive_binius_eval_point(b"adapter-ir-ivc", 0, n_vars);
        let evals: Vec<binius_field::BinaryField128b> = (0..(1usize << n_vars))
            .map(|i| binius_field::BinaryField128b::from_underlier((i as u128) + 1))
            .collect();
        let prover = match BaseFoldProver::commit(&evals, n_vars, BaseFoldConfig::default()) {
            Ok(prover) => prover,
            Err(err) => {
                assert!(false, "basefold commit: {err}");
                return;
            }
        };
        let commitment = prover.commitment();
        let opening = match prover.open(&eval_point) {
            Ok(opening) => opening,
            Err(err) => {
                assert!(false, "basefold open: {err}");
                return;
            }
        };
        let opening = crate::ivc_adapter::BaseFoldPcsOpeningProof {
            instance_digests,
            weights,
            commitment,
            eval_point,
            claimed_eval: opening.eval,
            proofs: opening.proofs,
        };
        let proof_bytes = match crate::ivc_adapter::encode_ivc_basefold_proof_bytes(&opening) {
            Ok(proof_bytes) => proof_bytes,
            Err(err) => {
                assert!(false, "encode: {err}");
                return;
            }
        };

        let commitment_tag = derive_basefold_commitment_tag(&opening.commitment);
        let point_tag = derive_basefold_point_tag(&commitment_tag, &opening.eval_point);
        let claim128 = opening.claimed_eval.to_underlier();
        let vk_bytes = crate::adapters::ivc_vk_bytes(
            4,
            crate::adapters::IvcProofType::BaseFoldTransparent,
        );
        let stmt_bytes = crate::adapters::ivc_statement_bytes(
            &commitment_tag,
            &point_tag,
            claim128,
            crate::adapters::IvcProofType::BaseFoldTransparent,
        );

        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: kernel_id::IVC_VERIFY,
                args: vec![],
            }],
        };
        let ir_bytes = ir.encode();

        let direct = match crate::ivc_adapter::derive_glyph_artifact_from_ivc_direct(
            &vk_bytes,
            &stmt_bytes,
            &proof_bytes,
        ) {
            Ok(direct) => direct,
            Err(err) => {
                assert!(false, "direct ivc artifact: {err}");
                return;
            }
        };
        let via_ir = match derive_glyph_artifact_from_ivc_ir(
            &ir_bytes,
            &vk_bytes,
            &stmt_bytes,
            &proof_bytes,
        ) {
            Ok(via_ir) => via_ir,
            Err(err) => {
                assert!(false, "ir ivc artifact: {err}");
                return;
            }
        };
        assert_ne!(direct.0, [0u8; 32]);
        assert_ne!(direct.1, [0u8; 32]);
        assert_ne!(direct.2, 0u128);
        assert_ne!(via_ir.0, [0u8; 32]);
        assert_ne!(via_ir.1, [0u8; 32]);
        assert_ne!(via_ir.2, 0u128);
    }

    #[cfg(all(feature = "dev-tools", feature = "snark"))]
    #[test]
    fn test_groth16_bn254_ir_roundtrip() {
        use ark_bn254::Fr;
        use ark_groth16::Groth16;
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError};
        use ark_snark::SNARK;
        use ark_std::rand::{rngs::StdRng, SeedableRng};

        #[derive(Clone)]
        struct MulCircuit {
            pub a: Fr,
            pub b: Fr,
            pub c: Fr,
        }

        impl ConstraintSynthesizer<Fr> for MulCircuit {
            fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
                let a_var = cs.new_witness_variable(|| Ok(self.a))?;
                let b_var = cs.new_witness_variable(|| Ok(self.b))?;
                let c_var = cs.new_input_variable(|| Ok(self.c))?;
                let lc_a = LinearCombination::from(a_var);
                let lc_b = LinearCombination::from(b_var);
                let lc_c = LinearCombination::from(c_var);
                cs.enforce_constraint(lc_a, lc_b, lc_c)?;
                Ok(())
            }
        }

        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let a = Fr::from(5u64);
        let b = Fr::from(7u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let (pk, vk) = match Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(res) => res,
            Err(err) => {
                assert!(false, "setup: {err:?}");
                return;
            }
        };
        let proof = match Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng) {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        };

        let raw_vk_bytes = {
            let vk = crate::bn254_groth16::Groth16VerifyingKey {
                alpha_g1: vk.alpha_g1,
                beta_g2: vk.beta_g2,
                gamma_g2: vk.gamma_g2,
                delta_g2: vk.delta_g2,
                ic: vk.gamma_abc_g1.clone(),
            };
            crate::bn254_groth16::encode_groth16_vk_bytes(&vk)
        };
        let raw_proof_bytes = {
            let proof = crate::bn254_groth16::Groth16Proof {
                a: proof.a,
                b: proof.b,
                c: proof.c,
            };
            crate::bn254_groth16::encode_groth16_proof_bytes(&proof).to_vec()
        };
        let raw_pub_bytes = crate::bn254_groth16::encode_groth16_public_inputs(&[c]);
        let input_layout_hash = crate::adapters::keccak256(b"groth16-ir-test-layout");
        let vk_hash = crate::adapters::keccak256(&raw_vk_bytes);
        let pub_hash = crate::adapters::keccak256(&raw_pub_bytes);
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes(
            crate::adapters::SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let ir = AdapterIr {
            version: ADAPTER_IR_VERSION,
            ops: vec![AdapterIrOp {
                kernel_id: kernel_id::GROTH16_BN254_VERIFY,
                args: vec![],
            }],
        };
        let ir_bytes = ir.encode();

        let res = match derive_glyph_artifact_from_groth16_bn254_ir(
            &ir_bytes,
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
        ) {
            Ok(res) => res,
            Err(err) => {
                assert!(false, "groth16 ir artifact: {err}");
                return;
            }
        };
        assert_ne!(res.0, [0u8; 32]);

        let mut tampered = raw_proof_bytes.clone();
        tampered[0] ^= 1;
        assert!(derive_glyph_artifact_from_groth16_bn254_ir(
            &ir_bytes,
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &tampered,
            &raw_pub_bytes
        )
        .is_err());
    }
}
