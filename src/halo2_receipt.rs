//! Halo2 KZG receipt adapter for GLYPH.
//!
//! Provides a canonical receipt format and strict verification for Halo2 KZG proofs.
//! Receipts are verified off-chain and bound into GLYPH artifact tags.

use crate::adapters::keccak256;
use crate::adapter_error::{wrap_stage};
use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        verify_proof_multi, vk_read, Advice, Circuit, Column, ConstraintSystem, ErrorFront, Fixed,
        Instance, VerifyingKey,
    },
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsVerifierKZG},
        multiopen::{VerifierGWC, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    poly::commitment::Params,
    SerdeFormat,
};
use halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr as Bn256Fr, G1Affine as Bn256G1Affine},
    bls12381::{Bls12381, Fr as Bls12381Fr, G1Affine as Bls12381G1Affine},
};
use halo2_middleware::circuit::{
    Any as Halo2Any, ChallengeMid, ColumnMid, ConstraintSystemMid, QueryMid, VarMid,
};
use halo2_middleware::expression::Expression;
use halo2_middleware::poly::Rotation as Halo2Rotation;
use halo2_middleware::{lookup, permutation, shuffle};
use std::collections::HashMap;
use std::io::Cursor;

pub const HALO2_RECEIPT_TAG: &[u8] = b"GLYPH_HALO2_RECEIPT";

pub const HALO2_COMMITMENT_TAG_DOMAIN: &[u8] = b"GLYPH_HALO2_COMMITMENT_TAG";
pub const HALO2_POINT_TAG_DOMAIN: &[u8] = b"GLYPH_HALO2_POINT_TAG";
pub const HALO2_CLAIM_DOMAIN: &[u8] = b"GLYPH_HALO2_CLAIM";

pub const HALO2_CURVE_BN256: u8 = 0x01;
pub const HALO2_CURVE_BLS12381: u8 = 0x02;

pub const HALO2_BACKEND_KZG_GWC: u8 = 0x01;
pub const HALO2_BACKEND_KZG_SHPLONK: u8 = 0x02;

pub const HALO2_TRANSCRIPT_BLAKE2B: u8 = 0x01;

pub const HALO2_CIRCUIT_STANDARD_PLONK: u8 = 0x01;
pub const HALO2_CIRCUIT_PARAMETRIC_PLONK: u8 = 0x02;
pub const HALO2_CIRCUIT_CUSTOM_PLONK: u8 = 0x03;

pub const HALO2_CIRCUIT_PARAMS_TAG: &[u8] = b"GLYPH_HALO2_CIRCUIT_PARAMS";
pub const HALO2_CIRCUIT_CUSTOM_TAG: &[u8] = b"GLYPH_HALO2_CIRCUIT_CUSTOM";
pub const HALO2_PARAM_MAX_ROWS: usize = 1 << 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Halo2Receipt {
    pub curve_id: u8,
    pub backend_id: u8,
    pub transcript_id: u8,
    pub circuit_id: u8,
    pub compress_selectors: bool,
    pub circuit_params_bytes: Vec<u8>,
    pub params_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
    pub instances_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct StandardPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    #[allow(dead_code)]
    instance: Column<Instance>,
}

impl StandardPlonkConfig {
    fn configure<F: PrimeField + From<u64>>(meta: &mut ConstraintSystem<F>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();

        for column in [a, b, c] {
            meta.enable_equality(column);
        }

        meta.create_gate(
            "q_a*a + q_b*b + q_c*c + q_ab*a*b + constant + instance = 0",
            |meta| {
                let [a, b, c] =
                    [a, b, c].map(|column| meta.query_advice(column, halo2_proofs::poly::Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|column| meta.query_fixed(column, halo2_proofs::poly::Rotation::cur()));
                let instance = meta.query_instance(instance, halo2_proofs::poly::Rotation::cur());
                Some(q_a * a.clone() + q_b * b.clone() + q_c * c + q_ab * a * b + constant + instance)
            },
        );

        StandardPlonkConfig {
            a,
            b,
            c,
            q_a,
            q_b,
            q_c,
            q_ab,
            constant,
            instance,
        }
    }
}

#[derive(Clone, Default)]
pub struct StandardPlonkCircuit<F: PrimeField + From<u64>>(pub F);

impl<F: PrimeField + From<u64>> Circuit<F> for StandardPlonkCircuit<F> {
    type Config = StandardPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        StandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "standard-plonk",
            |mut region| {
                region.assign_advice(|| "a0", config.a, 0, || Value::known(self.0))?;
                region.assign_fixed(|| "q_a0", config.q_a, 0, || Value::known(-F::ONE))?;

                region.assign_advice(|| "a1", config.a, 1, || Value::known(-F::from(5u64)))?;
                for (idx, column) in (1..).zip([
                    config.q_a,
                    config.q_b,
                    config.q_c,
                    config.q_ab,
                    config.constant,
                ]) {
                    region.assign_fixed(|| "q", column, 1, || Value::known(F::from(idx as u64)))?;
                }

                let a = region.assign_advice(|| "a2", config.a, 2, || Value::known(F::ONE))?;
                a.copy_advice(|| "b3", &mut region, config.b, 3)?;
                a.copy_advice(|| "c4", &mut region, config.c, 4)?;
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct ParametricPlonkParams {
    pub rows: usize,
    pub fixed_rows: Vec<[u64; 5]>,
}

pub fn encode_parametric_plonk_params(params: &ParametricPlonkParams) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(HALO2_CIRCUIT_PARAMS_TAG);
    out.extend_from_slice(&(params.rows as u32).to_be_bytes());
    for row in &params.fixed_rows {
        for value in row {
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
    out
}

pub fn decode_parametric_plonk_params(bytes: &[u8]) -> Result<ParametricPlonkParams, String> {
    if !bytes.starts_with(HALO2_CIRCUIT_PARAMS_TAG) {
        return Err("halo2 circuit params missing tag".to_string());
    }
    let mut off = HALO2_CIRCUIT_PARAMS_TAG.len();
    let rows = read_u32_be(bytes, &mut off)? as usize;
    if rows == 0 {
        return Err("halo2 circuit params rows must be nonzero".to_string());
    }
    if rows > HALO2_PARAM_MAX_ROWS {
        return Err("halo2 circuit params rows exceeds limit".to_string());
    }
    let remaining = bytes.len().saturating_sub(off);
    let expected = rows
        .checked_mul(5)
        .and_then(|v| v.checked_mul(8))
        .ok_or_else(|| "halo2 circuit params length overflow".to_string())?;
    if remaining != expected {
        return Err("halo2 circuit params length mismatch".to_string());
    }
    let mut fixed_rows = Vec::with_capacity(rows);
    for _ in 0..rows {
        let mut coeffs = [0u64; 5];
        for coeff in &mut coeffs {
            *coeff = read_u64_be(bytes, &mut off)?;
        }
        fixed_rows.push(coeffs);
    }
    if off != bytes.len() {
        return Err("halo2 circuit params trailing bytes".to_string());
    }
    Ok(ParametricPlonkParams { rows, fixed_rows })
}

pub fn encode_custom_circuit_params<F: PrimeField>(
    cs_mid: &ConstraintSystemMid<F>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(HALO2_CIRCUIT_CUSTOM_TAG);
    write_u32_be(&mut out, cs_mid.num_fixed_columns as u32);
    write_u32_be(&mut out, cs_mid.num_advice_columns as u32);
    write_u32_be(&mut out, cs_mid.num_instance_columns as u32);
    write_u32_be(&mut out, cs_mid.num_challenges as u32);

    write_u32_be(&mut out, cs_mid.unblinded_advice_columns.len() as u32);
    for idx in &cs_mid.unblinded_advice_columns {
        write_u32_be(&mut out, *idx as u32);
    }

    write_u32_be(&mut out, cs_mid.advice_column_phase.len() as u32);
    out.extend(cs_mid.advice_column_phase.iter().copied());

    write_u32_be(&mut out, cs_mid.challenge_phase.len() as u32);
    out.extend(cs_mid.challenge_phase.iter().copied());

    write_u32_be(&mut out, cs_mid.gates.len() as u32);
    for gate in &cs_mid.gates {
        write_string(&mut out, &gate.name);
        write_expression::<F>(&mut out, &gate.poly);
    }

    write_u32_be(&mut out, cs_mid.permutation.columns.len() as u32);
    for column in &cs_mid.permutation.columns {
        write_column(&mut out, column);
    }

    write_u32_be(&mut out, cs_mid.lookups.len() as u32);
    for lookup_arg in &cs_mid.lookups {
        write_string(&mut out, &lookup_arg.name);
        write_expression_vec::<F>(&mut out, &lookup_arg.input_expressions);
        write_expression_vec::<F>(&mut out, &lookup_arg.table_expressions);
    }

    write_u32_be(&mut out, cs_mid.shuffles.len() as u32);
    for shuffle_arg in &cs_mid.shuffles {
        write_string(&mut out, &shuffle_arg.name);
        write_expression_vec::<F>(&mut out, &shuffle_arg.input_expressions);
        write_expression_vec::<F>(&mut out, &shuffle_arg.shuffle_expressions);
    }

    let mut annotations: Vec<(&ColumnMid, &String)> =
        cs_mid.general_column_annotations.iter().collect();
    annotations.sort_by_key(|(col, _)| *col);
    write_u32_be(&mut out, annotations.len() as u32);
    for (column, label) in annotations {
        write_column(&mut out, column);
        write_string(&mut out, label);
    }

    match cs_mid.minimum_degree {
        Some(min_degree) => {
            out.push(1);
            write_u32_be(&mut out, min_degree as u32);
        }
        None => out.push(0),
    }

    out
}

pub fn decode_custom_circuit_params<F: PrimeField>(
    bytes: &[u8],
) -> Result<ConstraintSystemMid<F>, String> {
    if !bytes.starts_with(HALO2_CIRCUIT_CUSTOM_TAG) {
        return Err("halo2 custom circuit params missing tag".to_string());
    }
    let mut off = HALO2_CIRCUIT_CUSTOM_TAG.len();
    let num_fixed_columns = read_u32_be(bytes, &mut off)? as usize;
    let num_advice_columns = read_u32_be(bytes, &mut off)? as usize;
    let num_instance_columns = read_u32_be(bytes, &mut off)? as usize;
    let num_challenges = read_u32_be(bytes, &mut off)? as usize;

    let unblinded_len = read_u32_be(bytes, &mut off)? as usize;
    let mut unblinded_advice_columns = Vec::with_capacity(unblinded_len);
    for _ in 0..unblinded_len {
        let idx = read_u32_be(bytes, &mut off)? as usize;
        if idx >= num_advice_columns {
            return Err("halo2 custom circuit unblinded index out of range".to_string());
        }
        unblinded_advice_columns.push(idx);
    }

    let advice_phase_len = read_u32_be(bytes, &mut off)? as usize;
    if advice_phase_len != num_advice_columns {
        return Err("halo2 custom circuit advice phase length mismatch".to_string());
    }
    let mut advice_column_phase = Vec::with_capacity(advice_phase_len);
    for _ in 0..advice_phase_len {
        advice_column_phase.push(read_u8(bytes, &mut off)?);
    }

    let challenge_phase_len = read_u32_be(bytes, &mut off)? as usize;
    if challenge_phase_len != num_challenges {
        return Err("halo2 custom circuit challenge phase length mismatch".to_string());
    }
    let mut challenge_phase = Vec::with_capacity(challenge_phase_len);
    for _ in 0..challenge_phase_len {
        challenge_phase.push(read_u8(bytes, &mut off)?);
    }

    let gate_len = read_u32_be(bytes, &mut off)? as usize;
    let mut gates = Vec::with_capacity(gate_len);
    let bounds = CustomCircuitBounds {
        num_fixed_columns,
        num_advice_columns,
        num_instance_columns,
        num_challenges,
    };
    for _ in 0..gate_len {
        let name = read_string(bytes, &mut off)?;
        let poly = read_expression::<F>(bytes, &mut off, &bounds)?;
        gates.push(halo2_middleware::circuit::Gate { name, poly });
    }

    let perm_len = read_u32_be(bytes, &mut off)? as usize;
    let mut perm_columns = Vec::with_capacity(perm_len);
    for _ in 0..perm_len {
        perm_columns.push(read_column(bytes, &mut off, &bounds)?);
    }
    let permutation = permutation::ArgumentMid { columns: perm_columns };

    let lookup_len = read_u32_be(bytes, &mut off)? as usize;
    let mut lookups = Vec::with_capacity(lookup_len);
    for _ in 0..lookup_len {
        let name = read_string(bytes, &mut off)?;
        let input_expressions = read_expression_vec::<F>(bytes, &mut off, &bounds)?;
        let table_expressions = read_expression_vec::<F>(bytes, &mut off, &bounds)?;
        lookups.push(lookup::ArgumentMid {
            name,
            input_expressions,
            table_expressions,
        });
    }

    let shuffle_len = read_u32_be(bytes, &mut off)? as usize;
    let mut shuffles = Vec::with_capacity(shuffle_len);
    for _ in 0..shuffle_len {
        let name = read_string(bytes, &mut off)?;
        let input_expressions = read_expression_vec::<F>(bytes, &mut off, &bounds)?;
        let shuffle_expressions = read_expression_vec::<F>(bytes, &mut off, &bounds)?;
        shuffles.push(shuffle::ArgumentMid {
            name,
            input_expressions,
            shuffle_expressions,
        });
    }

    let annotation_len = read_u32_be(bytes, &mut off)? as usize;
    let mut general_column_annotations = HashMap::with_capacity(annotation_len);
    for _ in 0..annotation_len {
        let column = read_column(bytes, &mut off, &bounds)?;
        let label = read_string(bytes, &mut off)?;
        general_column_annotations.insert(column, label);
    }

    let minimum_degree = match read_u8(bytes, &mut off)? {
        0 => None,
        1 => Some(read_u32_be(bytes, &mut off)? as usize),
        _ => return Err("halo2 custom circuit minimum degree flag invalid".to_string()),
    };

    if off != bytes.len() {
        return Err("halo2 custom circuit params trailing bytes".to_string());
    }

    Ok(ConstraintSystemMid {
        num_fixed_columns,
        num_advice_columns,
        num_instance_columns,
        num_challenges,
        unblinded_advice_columns,
        advice_column_phase,
        challenge_phase,
        gates,
        permutation,
        lookups,
        shuffles,
        general_column_annotations,
        minimum_degree,
    })
}

#[derive(Clone)]
pub struct ParametricPlonkCircuit<F: PrimeField + From<u64>> {
    params: ParametricPlonkParams,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField + From<u64>> ParametricPlonkCircuit<F> {
    pub fn new(params: ParametricPlonkParams) -> Result<Self, String> {
        if params.rows == 0 {
            return Err("parametric plonk params rows must be nonzero".to_string());
        }
        if params.fixed_rows.len() != params.rows {
            return Err("parametric plonk fixed row count mismatch".to_string());
        }
        Ok(Self {
            params,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<F: PrimeField + From<u64>> Circuit<F> for ParametricPlonkCircuit<F> {
    type Config = StandardPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            params: self.params.clone(),
            _marker: std::marker::PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        StandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), ErrorFront> {
        let params = self.params.clone();
        layouter.assign_region(
            || "parametric-plonk",
            |mut region| {
                for (row, coeffs) in params.fixed_rows.iter().enumerate() {
                    region.assign_advice(|| "a", config.a, row, || Value::known(F::ZERO))?;
                    region.assign_advice(|| "b", config.b, row, || Value::known(F::ZERO))?;
                    region.assign_advice(|| "c", config.c, row, || Value::known(F::ZERO))?;
                    region.assign_fixed(|| "q_a", config.q_a, row, || Value::known(F::from(coeffs[0])))?;
                    region.assign_fixed(|| "q_b", config.q_b, row, || Value::known(F::from(coeffs[1])))?;
                    region.assign_fixed(|| "q_c", config.q_c, row, || Value::known(F::from(coeffs[2])))?;
                    region.assign_fixed(|| "q_ab", config.q_ab, row, || Value::known(F::from(coeffs[3])))?;
                    region.assign_fixed(|| "constant", config.constant, row, || Value::known(F::from(coeffs[4])))?;
                }
                Ok(())
            },
        )
    }
}

pub fn encode_halo2_receipt(receipt: &Halo2Receipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HALO2_RECEIPT_TAG.len()
            + 5
            + 4
            + receipt.circuit_params_bytes.len()
            + 4
            + receipt.params_bytes.len()
            + 4
            + receipt.vk_bytes.len()
            + 4
            + receipt.instances_bytes.len()
            + 4
            + receipt.proof_bytes.len(),
    );
    out.extend_from_slice(HALO2_RECEIPT_TAG);
    out.push(receipt.curve_id);
    out.push(receipt.backend_id);
    out.push(receipt.transcript_id);
    out.push(receipt.circuit_id);
    out.push(receipt.compress_selectors as u8);
    out.extend_from_slice(&(receipt.circuit_params_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.circuit_params_bytes);
    out.extend_from_slice(&(receipt.params_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.params_bytes);
    out.extend_from_slice(&(receipt.vk_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.vk_bytes);
    out.extend_from_slice(&(receipt.instances_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.instances_bytes);
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.proof_bytes);
    out
}

pub fn decode_halo2_receipt(bytes: &[u8]) -> Result<Halo2Receipt, String> {
    if !bytes.starts_with(HALO2_RECEIPT_TAG) {
        return Err("halo2 receipt missing tag".to_string());
    }
    let mut off = HALO2_RECEIPT_TAG.len();
    let curve_id = read_u8(bytes, &mut off)?;
    let backend_id = read_u8(bytes, &mut off)?;
    let transcript_id = read_u8(bytes, &mut off)?;
    let circuit_id = read_u8(bytes, &mut off)?;
    let compress_selectors = read_u8(bytes, &mut off)? != 0;
    let params_len = read_u32_be(bytes, &mut off)? as usize;
    let circuit_params_bytes = read_vec(bytes, &mut off, params_len)?;
    let params_len = read_u32_be(bytes, &mut off)? as usize;
    let params_bytes = read_vec(bytes, &mut off, params_len)?;
    let vk_len = read_u32_be(bytes, &mut off)? as usize;
    let vk_bytes = read_vec(bytes, &mut off, vk_len)?;
    let instances_len = read_u32_be(bytes, &mut off)? as usize;
    let instances_bytes = read_vec(bytes, &mut off, instances_len)?;
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_bytes = read_vec(bytes, &mut off, proof_len)?;
    if off != bytes.len() {
        return Err("halo2 receipt has trailing bytes".to_string());
    }
    Ok(Halo2Receipt {
        curve_id,
        backend_id,
        transcript_id,
        circuit_id,
        compress_selectors,
        circuit_params_bytes,
        params_bytes,
        vk_bytes,
        instances_bytes,
        proof_bytes,
    })
}

pub fn encode_halo2_instances<F: PrimeField>(instances: &[Vec<F>]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let column_count = u16::try_from(instances.len())
        .map_err(|_| "halo2 instance column count too large".to_string())?;
    out.extend_from_slice(&column_count.to_be_bytes());
    for column in instances {
        out.extend_from_slice(&(column.len() as u32).to_be_bytes());
        for value in column {
            let repr = value.to_repr();
            out.extend_from_slice(repr.as_ref());
        }
    }
    Ok(out)
}

pub fn decode_halo2_instances<F: PrimeField>(bytes: &[u8]) -> Result<Vec<Vec<F>>, String> {
    let mut off = 0usize;
    let column_count = read_u16_be(bytes, &mut off)? as usize;
    let mut out = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        let len = read_u32_be(bytes, &mut off)? as usize;
        let mut column = Vec::with_capacity(len);
        for _ in 0..len {
            let value = read_prime_field::<F>(bytes, &mut off)?;
            column.push(value);
        }
        out.push(column);
    }
    if off != bytes.len() {
        return Err("halo2 instances trailing bytes".to_string());
    }
    Ok(out)
}

pub fn verify_halo2_receipt(bytes: &[u8]) -> Result<Halo2Receipt, String> {
    let receipt = decode_halo2_receipt(bytes).map_err(|e| wrap_stage("halo2", "decode", e))?;
    verify_halo2_receipt_struct(&receipt).map_err(|e| wrap_stage("halo2", "verify", e))?;
    Ok(receipt)
}

pub(crate) fn verify_halo2_receipt_struct(receipt: &Halo2Receipt) -> Result<(), String> {
    if receipt.params_bytes.is_empty() {
        return Err("halo2 params bytes empty".to_string());
    }
    if receipt.vk_bytes.is_empty() {
        return Err("halo2 vk bytes empty".to_string());
    }
    if receipt.proof_bytes.is_empty() {
        return Err("halo2 proof bytes empty".to_string());
    }
    if receipt.transcript_id != HALO2_TRANSCRIPT_BLAKE2B {
        return Err("halo2 transcript id unsupported".to_string());
    }
    if receipt.circuit_id == HALO2_CIRCUIT_STANDARD_PLONK
        && !receipt.circuit_params_bytes.is_empty()
    {
        return Err("halo2 standard circuit does not accept params".to_string());
    }
    if receipt.circuit_id == HALO2_CIRCUIT_CUSTOM_PLONK
        && !receipt.circuit_params_bytes.starts_with(HALO2_CIRCUIT_CUSTOM_TAG)
    {
        return Err("halo2 custom circuit params missing tag".to_string());
    }
    if (receipt.circuit_id == HALO2_CIRCUIT_PARAMETRIC_PLONK
        || receipt.circuit_id == HALO2_CIRCUIT_CUSTOM_PLONK)
        && receipt.circuit_params_bytes.is_empty()
    {
        return Err("halo2 parametric circuit params missing".to_string());
    }

    match receipt.curve_id {
        HALO2_CURVE_BN256 => verify_halo2_kzg_bn256(receipt),
        HALO2_CURVE_BLS12381 => verify_halo2_kzg_bls12381(receipt),
        _ => Err("unsupported halo2 curve id".to_string()),
    }
}

pub fn derive_glyph_artifact_from_halo2_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_halo2_receipt(receipt_bytes)?;
    let proof_hash = keccak256(&receipt.proof_bytes);
    let pub_hash = keccak256(&receipt.instances_bytes);
    let vk_hash = keccak256(&receipt.vk_bytes);
    let params_hash = keccak256(&receipt.params_bytes);
    let meta_hash = halo2_meta_hash(&receipt);
    let base = keccak256_concat(&vk_hash, &params_hash);
    let vk_binding = keccak256_concat(&base, &meta_hash);

    let commitment_tag = keccak256_concat_domain(HALO2_COMMITMENT_TAG_DOMAIN, &proof_hash, &vk_binding);
    let point_tag = keccak256_concat_domain(HALO2_POINT_TAG_DOMAIN, &pub_hash, &vk_binding);
    let claim_hash = keccak256_concat_domain(HALO2_CLAIM_DOMAIN, &commitment_tag, &point_tag);
    let mut claim_bytes = [0u8; 16];
    claim_bytes.copy_from_slice(&claim_hash[..16]);
    let claim128 = u128::from_be_bytes(claim_bytes);
    Ok((commitment_tag, point_tag, claim128))
}

fn verify_halo2_kzg_bn256(receipt: &Halo2Receipt) -> Result<(), String> {
    let params = read_params_bn256(&receipt.params_bytes)?;
    let k = params.k();
    let instances = decode_halo2_instances::<Bn256Fr>(&receipt.instances_bytes)?;
    let mut transcript =
        Blake2bRead::<_, _, Challenge255<Bn256G1Affine>>::init(receipt.proof_bytes.as_slice());
    let vk = match receipt.circuit_id {
        HALO2_CIRCUIT_STANDARD_PLONK => {
            let circuit = StandardPlonkCircuit::<Bn256Fr>::default();
            read_vk_bn256(&receipt.vk_bytes, k, &circuit, receipt.compress_selectors)?
        }
        HALO2_CIRCUIT_PARAMETRIC_PLONK => {
            let params = decode_parametric_plonk_params(&receipt.circuit_params_bytes)?;
            let circuit = ParametricPlonkCircuit::<Bn256Fr>::new(params)?;
            read_vk_bn256(&receipt.vk_bytes, k, &circuit, receipt.compress_selectors)?
        }
        HALO2_CIRCUIT_CUSTOM_PLONK => {
            let cs_mid =
                decode_custom_circuit_params::<Bn256Fr>(&receipt.circuit_params_bytes)?;
            if instances.len() != cs_mid.num_instance_columns {
                return Err("halo2 custom instance column count mismatch".to_string());
            }
            read_vk_bn256_custom(&receipt.vk_bytes, cs_mid)?
        }
        _ => return Err("halo2 circuit id unsupported".to_string()),
    };

    let ok = match receipt.backend_id {
        HALO2_BACKEND_KZG_GWC => verify_proof_multi::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<Bn256>,
            Challenge255<Bn256G1Affine>,
            Blake2bRead<&[u8], Bn256G1Affine, Challenge255<Bn256G1Affine>>,
            SingleStrategy<Bn256>,
        >(&params, &vk, &[instances], &mut transcript),
        HALO2_BACKEND_KZG_SHPLONK => verify_proof_multi::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<Bn256>,
            Challenge255<Bn256G1Affine>,
            Blake2bRead<&[u8], Bn256G1Affine, Challenge255<Bn256G1Affine>>,
            SingleStrategy<Bn256>,
        >(&params, &vk, &[instances], &mut transcript),
        _ => return Err("halo2 backend id unsupported".to_string()),
    };
    if !ok {
        return Err("halo2 verify failed".to_string());
    }
    Ok(())
}

fn verify_halo2_kzg_bls12381(receipt: &Halo2Receipt) -> Result<(), String> {
    let params = read_params_bls12381(&receipt.params_bytes)?;
    let k = params.k();
    let instances = decode_halo2_instances::<Bls12381Fr>(&receipt.instances_bytes)?;
    let mut transcript = Blake2bRead::<_, _, Challenge255<Bls12381G1Affine>>::init(
        receipt.proof_bytes.as_slice(),
    );
    let vk = match receipt.circuit_id {
        HALO2_CIRCUIT_STANDARD_PLONK => {
            let circuit = StandardPlonkCircuit::<Bls12381Fr>::default();
            read_vk_bls12381(&receipt.vk_bytes, k, &circuit, receipt.compress_selectors)?
        }
        HALO2_CIRCUIT_PARAMETRIC_PLONK => {
            let params = decode_parametric_plonk_params(&receipt.circuit_params_bytes)?;
            let circuit = ParametricPlonkCircuit::<Bls12381Fr>::new(params)?;
            read_vk_bls12381(&receipt.vk_bytes, k, &circuit, receipt.compress_selectors)?
        }
        HALO2_CIRCUIT_CUSTOM_PLONK => {
            let cs_mid =
                decode_custom_circuit_params::<Bls12381Fr>(&receipt.circuit_params_bytes)?;
            if instances.len() != cs_mid.num_instance_columns {
                return Err("halo2 custom instance column count mismatch".to_string());
            }
            read_vk_bls12381_custom(&receipt.vk_bytes, cs_mid)?
        }
        _ => return Err("halo2 circuit id unsupported".to_string()),
    };
    let ok = match receipt.backend_id {
        HALO2_BACKEND_KZG_GWC => verify_proof_multi::<
            KZGCommitmentScheme<Bls12381>,
            VerifierGWC<Bls12381>,
            Challenge255<Bls12381G1Affine>,
            Blake2bRead<&[u8], Bls12381G1Affine, Challenge255<Bls12381G1Affine>>,
            SingleStrategy<Bls12381>,
        >(&params, &vk, &[instances], &mut transcript),
        HALO2_BACKEND_KZG_SHPLONK => verify_proof_multi::<
            KZGCommitmentScheme<Bls12381>,
            VerifierSHPLONK<Bls12381>,
            Challenge255<Bls12381G1Affine>,
            Blake2bRead<&[u8], Bls12381G1Affine, Challenge255<Bls12381G1Affine>>,
            SingleStrategy<Bls12381>,
        >(&params, &vk, &[instances], &mut transcript),
        _ => return Err("halo2 backend id unsupported".to_string()),
    };
    if !ok {
        return Err("halo2 verify failed".to_string());
    }
    Ok(())
}

fn read_params_bn256(bytes: &[u8]) -> Result<ParamsVerifierKZG<Bn256>, String> {
    let mut cursor = Cursor::new(bytes);
    let params = ParamsVerifierKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytes)
        .map_err(|e| format!("halo2 params decode failed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("halo2 params trailing bytes".to_string());
    }
    Ok(params)
}

fn read_params_bls12381(bytes: &[u8]) -> Result<ParamsVerifierKZG<Bls12381>, String> {
    let mut cursor = Cursor::new(bytes);
    let params = ParamsVerifierKZG::<Bls12381>::read_custom(&mut cursor, SerdeFormat::RawBytes)
        .map_err(|e| format!("halo2 params decode failed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("halo2 params trailing bytes".to_string());
    }
    Ok(params)
}

fn read_vk_bn256<C: Circuit<Bn256Fr>>(
    bytes: &[u8],
    k: u32,
    circuit: &C,
    compress_selectors: bool,
) -> Result<halo2_proofs::plonk::VerifyingKey<Bn256G1Affine>, String> {
    let mut cursor = Cursor::new(bytes);
    let vk = vk_read::<Bn256G1Affine, _, C>(
        &mut cursor,
        SerdeFormat::RawBytes,
        k,
        circuit,
        compress_selectors,
    )
    .map_err(|e| format!("halo2 vk decode failed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("halo2 vk trailing bytes".to_string());
    }
    Ok(vk)
}

fn read_vk_bls12381<C: Circuit<Bls12381Fr>>(
    bytes: &[u8],
    k: u32,
    circuit: &C,
    compress_selectors: bool,
) -> Result<halo2_proofs::plonk::VerifyingKey<Bls12381G1Affine>, String> {
    let mut cursor = Cursor::new(bytes);
    let vk = vk_read::<Bls12381G1Affine, _, C>(
        &mut cursor,
        SerdeFormat::RawBytes,
        k,
        circuit,
        compress_selectors,
    )
    .map_err(|e| format!("halo2 vk decode failed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("halo2 vk trailing bytes".to_string());
    }
    Ok(vk)
}

fn read_vk_bn256_custom(
    bytes: &[u8],
    cs_mid: ConstraintSystemMid<Bn256Fr>,
) -> Result<VerifyingKey<Bn256G1Affine>, String> {
    let mut cursor = Cursor::new(bytes);
    let cs_back = cs_mid.into();
    let vk = VerifyingKey::<Bn256G1Affine>::read(&mut cursor, SerdeFormat::RawBytes, cs_back)
        .map_err(|e| format!("halo2 vk decode failed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("halo2 vk trailing bytes".to_string());
    }
    Ok(vk)
}

fn read_vk_bls12381_custom(
    bytes: &[u8],
    cs_mid: ConstraintSystemMid<Bls12381Fr>,
) -> Result<VerifyingKey<Bls12381G1Affine>, String> {
    let mut cursor = Cursor::new(bytes);
    let cs_back = cs_mid.into();
    let vk = VerifyingKey::<Bls12381G1Affine>::read(&mut cursor, SerdeFormat::RawBytes, cs_back)
        .map_err(|e| format!("halo2 vk decode failed: {e}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err("halo2 vk trailing bytes".to_string());
    }
    Ok(vk)
}

fn read_prime_field<F: PrimeField>(bytes: &[u8], off: &mut usize) -> Result<F, String> {
    let mut repr = F::Repr::default();
    let repr_bytes = repr.as_mut();
    let slice = bytes
        .get(*off..*off + repr_bytes.len())
        .ok_or_else(|| "halo2 instances EOF".to_string())?;
    repr_bytes.copy_from_slice(slice);
    *off += repr_bytes.len();
    let value =
        Option::<F>::from(F::from_repr(repr)).ok_or_else(|| "halo2 instance not canonical".to_string())?;
    Ok(value)
}

fn keccak256_concat_domain(domain: &[u8], left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(domain);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    keccak256(&input)
}

fn keccak256_concat(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    keccak256(&input)
}

fn halo2_meta_hash(receipt: &Halo2Receipt) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"GLYPH_HALO2_META");
    input.push(receipt.curve_id);
    input.push(receipt.backend_id);
    input.push(receipt.transcript_id);
    input.push(receipt.circuit_id);
    input.push(receipt.compress_selectors as u8);
    let circuit_params_hash = keccak256(&receipt.circuit_params_bytes);
    input.extend_from_slice(&circuit_params_hash);
    keccak256(&input)
}

struct CustomCircuitBounds {
    num_fixed_columns: usize,
    num_advice_columns: usize,
    num_instance_columns: usize,
    num_challenges: usize,
}

const CUSTOM_EXPR_CONST: u8 = 0x00;
const CUSTOM_EXPR_VAR: u8 = 0x01;
const CUSTOM_EXPR_NEG: u8 = 0x02;
const CUSTOM_EXPR_SUM: u8 = 0x03;
const CUSTOM_EXPR_PRODUCT: u8 = 0x04;

const CUSTOM_VAR_QUERY: u8 = 0x00;
const CUSTOM_VAR_CHALLENGE: u8 = 0x01;

const CUSTOM_COL_INSTANCE: u8 = 0x00;
const CUSTOM_COL_ADVICE: u8 = 0x01;
const CUSTOM_COL_FIXED: u8 = 0x02;

fn write_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_i32_be(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u32_be(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn field_repr_len<F: PrimeField>() -> usize {
    let repr = F::Repr::default();
    repr.as_ref().len()
}

fn write_field<F: PrimeField>(out: &mut Vec<u8>, value: &F) {
    out.extend_from_slice(value.to_repr().as_ref());
}

fn write_column(out: &mut Vec<u8>, column: &ColumnMid) {
    let col_id = match column.column_type {
        Halo2Any::Instance => CUSTOM_COL_INSTANCE,
        Halo2Any::Advice => CUSTOM_COL_ADVICE,
        Halo2Any::Fixed => CUSTOM_COL_FIXED,
    };
    out.push(col_id);
    write_u32_be(out, column.index as u32);
}

fn write_var(out: &mut Vec<u8>, var: &VarMid) {
    match var {
        VarMid::Query(query) => {
            out.push(CUSTOM_VAR_QUERY);
            let column = ColumnMid {
                column_type: query.column_type,
                index: query.column_index,
            };
            write_column(out, &column);
            write_i32_be(out, query.rotation.0);
        }
        VarMid::Challenge(ch) => {
            out.push(CUSTOM_VAR_CHALLENGE);
            write_u32_be(out, ch.index as u32);
            out.push(ch.phase);
        }
    }
}

fn write_expression<F: PrimeField>(out: &mut Vec<u8>, expr: &Expression<F, VarMid>) {
    match expr {
        Expression::Constant(value) => {
            out.push(CUSTOM_EXPR_CONST);
            write_field(out, value);
        }
        Expression::Var(var) => {
            out.push(CUSTOM_EXPR_VAR);
            write_var(out, var);
        }
        Expression::Negated(inner) => {
            out.push(CUSTOM_EXPR_NEG);
            write_expression::<F>(out, inner);
        }
        Expression::Sum(left, right) => {
            out.push(CUSTOM_EXPR_SUM);
            write_expression::<F>(out, left);
            write_expression::<F>(out, right);
        }
        Expression::Product(left, right) => {
            out.push(CUSTOM_EXPR_PRODUCT);
            write_expression::<F>(out, left);
            write_expression::<F>(out, right);
        }
    }
}

fn write_expression_vec<F: PrimeField>(out: &mut Vec<u8>, exprs: &[Expression<F, VarMid>]) {
    write_u32_be(out, exprs.len() as u32);
    for expr in exprs {
        write_expression::<F>(out, expr);
    }
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let b = *bytes.get(*off).ok_or_else(|| "halo2 receipt EOF".to_string())?;
    *off += 1;
    Ok(b)
}

fn read_i32_be(bytes: &[u8], off: &mut usize) -> Result<i32, String> {
    let slice = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "halo2 receipt EOF".to_string())?;
    *off += 4;
    Ok(i32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let slice = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "halo2 receipt EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let slice = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "halo2 receipt EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_be(bytes: &[u8], off: &mut usize) -> Result<u64, String> {
    let slice = bytes
        .get(*off..*off + 8)
        .ok_or_else(|| "halo2 receipt EOF".to_string())?;
    *off += 8;
    Ok(u64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "halo2 receipt EOF".to_string())?;
    *off += len;
    Ok(slice.to_vec())
}

fn read_string(bytes: &[u8], off: &mut usize) -> Result<String, String> {
    let len = read_u32_be(bytes, off)? as usize;
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "halo2 custom circuit EOF".to_string())?;
    *off += len;
    let text =
        std::str::from_utf8(slice).map_err(|_| "halo2 custom circuit invalid utf8".to_string())?;
    Ok(text.to_string())
}

fn read_field<F: PrimeField>(bytes: &[u8], off: &mut usize) -> Result<F, String> {
    let len = field_repr_len::<F>();
    let slice = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "halo2 custom circuit EOF".to_string())?;
    *off += len;
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(slice);
    Option::<F>::from(F::from_repr(repr))
        .ok_or_else(|| "halo2 custom circuit field element not canonical".to_string())
}

fn read_column(
    bytes: &[u8],
    off: &mut usize,
    bounds: &CustomCircuitBounds,
) -> Result<ColumnMid, String> {
    let col_type = read_u8(bytes, off)?;
    let index = read_u32_be(bytes, off)? as usize;
    let column_type = match col_type {
        CUSTOM_COL_INSTANCE => {
            if index >= bounds.num_instance_columns {
                return Err("halo2 custom circuit instance column out of range".to_string());
            }
            Halo2Any::Instance
        }
        CUSTOM_COL_ADVICE => {
            if index >= bounds.num_advice_columns {
                return Err("halo2 custom circuit advice column out of range".to_string());
            }
            Halo2Any::Advice
        }
        CUSTOM_COL_FIXED => {
            if index >= bounds.num_fixed_columns {
                return Err("halo2 custom circuit fixed column out of range".to_string());
            }
            Halo2Any::Fixed
        }
        _ => return Err("halo2 custom circuit column type invalid".to_string()),
    };
    Ok(ColumnMid { column_type, index })
}

fn read_var(
    bytes: &[u8],
    off: &mut usize,
    bounds: &CustomCircuitBounds,
) -> Result<VarMid, String> {
    let tag = read_u8(bytes, off)?;
    match tag {
        CUSTOM_VAR_QUERY => {
            let column = read_column(bytes, off, bounds)?;
            let rotation = Halo2Rotation(read_i32_be(bytes, off)?);
            Ok(VarMid::Query(QueryMid::new(
                column.column_type,
                column.index,
                rotation,
            )))
        }
        CUSTOM_VAR_CHALLENGE => {
            let index = read_u32_be(bytes, off)? as usize;
            let phase = read_u8(bytes, off)?;
            if index >= bounds.num_challenges {
                return Err("halo2 custom circuit challenge index out of range".to_string());
            }
            Ok(VarMid::Challenge(ChallengeMid { index, phase }))
        }
        _ => Err("halo2 custom circuit var tag invalid".to_string()),
    }
}

fn read_expression<F: PrimeField>(
    bytes: &[u8],
    off: &mut usize,
    bounds: &CustomCircuitBounds,
) -> Result<Expression<F, VarMid>, String> {
    let tag = read_u8(bytes, off)?;
    match tag {
        CUSTOM_EXPR_CONST => Ok(Expression::Constant(read_field::<F>(bytes, off)?)),
        CUSTOM_EXPR_VAR => Ok(Expression::Var(read_var(bytes, off, bounds)?)),
        CUSTOM_EXPR_NEG => Ok(Expression::Negated(Box::new(read_expression::<F>(
            bytes, off, bounds,
        )?))),
        CUSTOM_EXPR_SUM => {
            let left = read_expression::<F>(bytes, off, bounds)?;
            let right = read_expression::<F>(bytes, off, bounds)?;
            Ok(Expression::Sum(Box::new(left), Box::new(right)))
        }
        CUSTOM_EXPR_PRODUCT => {
            let left = read_expression::<F>(bytes, off, bounds)?;
            let right = read_expression::<F>(bytes, off, bounds)?;
            Ok(Expression::Product(Box::new(left), Box::new(right)))
        }
        _ => Err("halo2 custom circuit expression tag invalid".to_string()),
    }
}

fn read_expression_vec<F: PrimeField>(
    bytes: &[u8],
    off: &mut usize,
    bounds: &CustomCircuitBounds,
) -> Result<Vec<Expression<F, VarMid>>, String> {
    let len = read_u32_be(bytes, off)? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_expression::<F>(bytes, off, bounds)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_frontend::circuit::compile_circuit;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk_custom};
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2_proofs::poly::kzg::multiopen::ProverGWC;
    use halo2_proofs::transcript::{Blake2bWrite, TranscriptWriterBuffer};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_halo2_receipt_roundtrip_and_verify_bn256() {
        let k = 4u32;
        let mut rng = StdRng::seed_from_u64(0x1234_5678);
        let circuit = StandardPlonkCircuit::<Bn256Fr>(Bn256Fr::from(7u64));
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let compress_selectors = true;
        let vk = match keygen_vk_custom(&params, &circuit, compress_selectors) {
            Ok(vk) => vk,
            Err(err) => {
                assert!(false, "vk: {err:?}");
                return;
            }
        };
        let pk = match keygen_pk(&params, vk.clone(), &circuit) {
            Ok(pk) => pk,
            Err(err) => {
                assert!(false, "pk: {err:?}");
                return;
            }
        };

        let instances: Vec<Vec<Vec<Bn256Fr>>> = vec![vec![vec![circuit.0]]];
        let mut transcript = Blake2bWrite::<_, _, Challenge255<Bn256G1Affine>>::init(vec![]);
        match create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<Bn256G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, Bn256G1Affine, Challenge255<Bn256G1Affine>>,
            _,
        >(&params, &pk, &[circuit], instances.as_slice(), &mut rng, &mut transcript)
        {
            Ok(()) => {}
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        }
        let proof_bytes = transcript.finalize();

        let mut params_bytes = Vec::new();
        if let Err(err) = params
            .verifier_params()
            .write_custom(&mut params_bytes, SerdeFormat::RawBytes)
        {
            assert!(false, "params write: {err}");
            return;
        }
        let mut vk_bytes = Vec::new();
        if let Err(err) = vk.write(&mut vk_bytes, SerdeFormat::RawBytes) {
            assert!(false, "vk write: {err}");
            return;
        }
        let instances_bytes = match encode_halo2_instances(&instances[0]) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "instances: {err}");
                return;
            }
        };

        let receipt = Halo2Receipt {
            curve_id: HALO2_CURVE_BN256,
            backend_id: HALO2_BACKEND_KZG_GWC,
            transcript_id: HALO2_TRANSCRIPT_BLAKE2B,
            circuit_id: HALO2_CIRCUIT_STANDARD_PLONK,
            compress_selectors,
            circuit_params_bytes: Vec::new(),
            params_bytes,
            vk_bytes,
            instances_bytes,
            proof_bytes,
        };
        let encoded = encode_halo2_receipt(&receipt);
        let decoded = match decode_halo2_receipt(&encoded) {
            Ok(decoded) => decoded,
            Err(err) => {
                assert!(false, "decode: {err}");
                return;
            }
        };
        assert_eq!(decoded, receipt);
        if let Err(err) = verify_halo2_receipt(&encoded) {
            assert!(false, "verify: {err}");
            return;
        }
    }

    #[test]
    fn test_halo2_parametric_plonk_receipt_bn256() {
        use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk_custom};
        use halo2_proofs::poly::kzg::commitment::ParamsKZG;
        use halo2_proofs::poly::kzg::multiopen::ProverGWC;
        use halo2_proofs::transcript::{Blake2bWrite, TranscriptWriterBuffer};

        let k = 4u32;
        let mut rng = StdRng::seed_from_u64(0x4455_6677);
        let params = ParametricPlonkParams {
            rows: 2,
            fixed_rows: vec![[1, 0, 0, 0, 0], [1, 0, 0, 0, 0]],
        };
        let circuit = match ParametricPlonkCircuit::<Bn256Fr>::new(params.clone()) {
            Ok(circuit) => circuit,
            Err(err) => {
                assert!(false, "circuit: {err}");
                return;
            }
        };
        let kzg_params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let compress_selectors = true;
        let vk = match keygen_vk_custom(&kzg_params, &circuit, compress_selectors) {
            Ok(vk) => vk,
            Err(err) => {
                assert!(false, "vk: {err:?}");
                return;
            }
        };
        let pk = match keygen_pk(&kzg_params, vk.clone(), &circuit) {
            Ok(pk) => pk,
            Err(err) => {
                assert!(false, "pk: {err:?}");
                return;
            }
        };

        let instances: Vec<Vec<Vec<Bn256Fr>>> =
            vec![vec![vec![Bn256Fr::from(0u64); params.rows]]];
        let mut transcript = Blake2bWrite::<_, _, Challenge255<Bn256G1Affine>>::init(vec![]);
        match create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<Bn256G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, Bn256G1Affine, Challenge255<Bn256G1Affine>>,
            _,
        >(
            &kzg_params,
            &pk,
            &[circuit],
            instances.as_slice(),
            &mut rng,
            &mut transcript,
        )
        {
            Ok(()) => {}
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        }
        let proof_bytes = transcript.finalize();

        let mut params_bytes = Vec::new();
        if let Err(err) = kzg_params
            .verifier_params()
            .write_custom(&mut params_bytes, SerdeFormat::RawBytes)
        {
            assert!(false, "params write: {err}");
            return;
        }
        let mut vk_bytes = Vec::new();
        if let Err(err) = vk.write(&mut vk_bytes, SerdeFormat::RawBytes) {
            assert!(false, "vk write: {err}");
            return;
        }
        let instances_bytes = match encode_halo2_instances(&instances[0]) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "instances: {err}");
                return;
            }
        };
        let circuit_params_bytes = encode_parametric_plonk_params(&params);

        let receipt = Halo2Receipt {
            curve_id: HALO2_CURVE_BN256,
            backend_id: HALO2_BACKEND_KZG_GWC,
            transcript_id: HALO2_TRANSCRIPT_BLAKE2B,
            circuit_id: HALO2_CIRCUIT_PARAMETRIC_PLONK,
            compress_selectors,
            circuit_params_bytes,
            params_bytes,
            vk_bytes,
            instances_bytes,
            proof_bytes,
        };
        let encoded = encode_halo2_receipt(&receipt);
        if let Err(err) = verify_halo2_receipt(&encoded) {
            assert!(false, "verify: {err}");
            return;
        }
    }

    #[test]
    fn test_halo2_custom_plonk_receipt_bn256() {
        #[derive(Clone, Default)]
        struct CustomCircuit<F: PrimeField + From<u64>>(F);

        #[derive(Clone, Copy)]
        struct CustomConfig {
            a: Column<Advice>,
            q: Column<Fixed>,
            instance: Column<Instance>,
        }

        impl CustomConfig {
            fn configure<F: PrimeField + From<u64>>(meta: &mut ConstraintSystem<F>) -> Self {
                let a = meta.advice_column();
                let q = meta.fixed_column();
                let instance = meta.instance_column();
                meta.enable_equality(a);
                meta.create_gate("custom-plonk", |meta| {
                    let a = meta.query_advice(a, halo2_proofs::poly::Rotation::cur());
                    let q = meta.query_fixed(q, halo2_proofs::poly::Rotation::cur());
                    let inst = meta.query_instance(instance, halo2_proofs::poly::Rotation::cur());
                    Some(q * a - inst)
                });
                CustomConfig { a, q, instance }
            }
        }

        impl<F: PrimeField + From<u64>> Circuit<F> for CustomCircuit<F> {
            type Config = CustomConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self(F::ZERO)
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                CustomConfig::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), ErrorFront> {
                let _ = config.instance;
                let witness = self.0;
                layouter.assign_region(
                    || "custom-plonk",
                    |mut region| {
                        region.assign_advice(|| "a0", config.a, 0, || Value::known(witness))?;
                        region.assign_fixed(|| "q0", config.q, 0, || Value::known(F::ONE))?;
                        Ok(())
                    },
                )
            }
        }

        let k = 4u32;
        let mut rng = StdRng::seed_from_u64(0x7788_9900);
        let circuit = CustomCircuit::<Bn256Fr>(Bn256Fr::from(11u64));
        let params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let compress_selectors = true;
        let vk = match keygen_vk_custom(&params, &circuit, compress_selectors) {
            Ok(vk) => vk,
            Err(err) => {
                assert!(false, "vk: {err:?}");
                return;
            }
        };
        let pk = match keygen_pk(&params, vk.clone(), &circuit) {
            Ok(pk) => pk,
            Err(err) => {
                assert!(false, "pk: {err:?}");
                return;
            }
        };

        let instances: Vec<Vec<Vec<Bn256Fr>>> = vec![vec![vec![circuit.0]]];
        let mut transcript =
            Blake2bWrite::<_, _, Challenge255<Bn256G1Affine>>::init(vec![]);
        match create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<Bn256G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, Bn256G1Affine, Challenge255<Bn256G1Affine>>,
            _,
        >(
            &params,
            &pk,
            std::slice::from_ref(&circuit),
            instances.as_slice(),
            &mut rng,
            &mut transcript,
        )
        {
            Ok(()) => {}
            Err(err) => {
                assert!(false, "proof: {err:?}");
                return;
            }
        }
        let proof_bytes = transcript.finalize();

        let mut params_bytes = Vec::new();
        if let Err(err) = params
            .verifier_params()
            .write_custom(&mut params_bytes, SerdeFormat::RawBytes)
        {
            assert!(false, "params write: {err}");
            return;
        }
        let mut vk_bytes = Vec::new();
        if let Err(err) = vk.write(&mut vk_bytes, SerdeFormat::RawBytes) {
            assert!(false, "vk write: {err}");
            return;
        }
        let instances_bytes = match encode_halo2_instances(&instances[0]) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "instances: {err}");
                return;
            }
        };

        let (compiled, _, _) = match compile_circuit(k, &circuit, compress_selectors) {
            Ok(compiled) => compiled,
            Err(err) => {
                assert!(false, "compile: {err:?}");
                return;
            }
        };
        let circuit_params_bytes = encode_custom_circuit_params(&compiled.cs);

        let receipt = Halo2Receipt {
            curve_id: HALO2_CURVE_BN256,
            backend_id: HALO2_BACKEND_KZG_GWC,
            transcript_id: HALO2_TRANSCRIPT_BLAKE2B,
            circuit_id: HALO2_CIRCUIT_CUSTOM_PLONK,
            compress_selectors,
            circuit_params_bytes,
            params_bytes,
            vk_bytes,
            instances_bytes,
            proof_bytes,
        };
        let encoded = encode_halo2_receipt(&receipt);
        if let Err(err) = verify_halo2_receipt(&encoded) {
            assert!(false, "halo2 custom verify: {err}");
            return;
        }
    }
}
