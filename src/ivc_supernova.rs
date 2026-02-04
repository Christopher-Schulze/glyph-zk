//! SuperNova external proof verification for IVC.
//!
//! This module verifies SuperNova RecursiveSNARK proofs against a canonical R1CS
//! receipt by compiling the receipt into a SuperNova StepCircuit.

use std::sync::Arc;

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use arecibo::provider::{Bn256Engine, GrumpkinEngine};
use arecibo::supernova::{NonUniformCircuit, PublicParams, RecursiveSNARK};
use arecibo::traits::circuit_supernova::{StepCircuit, TrivialSecondaryCircuit};
use arecibo::traits::{snark::default_ck_hint, Engine};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use bellpepper_core::num::AllocatedNum;
use bincode::Options;
use ff::{Field, PrimeField as AreciboPrimeField};
use rayon::prelude::*;

use crate::ivc_r1cs::{R1csConstraint, R1csLinearCombination, R1csReceipt};

pub const IVC_SUPERNOVA_EXTERNAL_DOMAIN: &[u8] = b"GLYPH_IVC_SUPERNOVA_EXTERNAL";
pub const IVC_SUPERNOVA_EXTERNAL_VERSION: u16 = 1;
const IVC_R1CS_CONVERT_PAR_THRESHOLD: usize = 256;

type SuperNovaScalar = <Bn256Engine as Engine>::Scalar;
type SuperNovaSecondaryScalar = <GrumpkinEngine as Engine>::Scalar;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuperNovaExternalProof {
    pub recursive_snark_bytes: Vec<u8>,
}

fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
}

pub fn encode_supernova_external_proof_bytes(proof: &SuperNovaExternalProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        IVC_SUPERNOVA_EXTERNAL_DOMAIN.len() + 2 + 4 + proof.recursive_snark_bytes.len(),
    );
    out.extend_from_slice(IVC_SUPERNOVA_EXTERNAL_DOMAIN);
    out.extend_from_slice(&IVC_SUPERNOVA_EXTERNAL_VERSION.to_be_bytes());
    out.extend_from_slice(&(proof.recursive_snark_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.recursive_snark_bytes);
    out
}

pub fn decode_supernova_external_proof_bytes(bytes: &[u8]) -> Result<SuperNovaExternalProof, String> {
    if !bytes.starts_with(IVC_SUPERNOVA_EXTERNAL_DOMAIN) {
        return Err("supernova external proof missing domain tag".to_string());
    }
    let mut off = IVC_SUPERNOVA_EXTERNAL_DOMAIN.len();
    let version = read_u16_be(bytes, &mut off)?;
    if version != IVC_SUPERNOVA_EXTERNAL_VERSION {
        return Err(format!("supernova external proof unsupported version={version}"));
    }
    let len = read_u32_be(bytes, &mut off)? as usize;
    let payload = read_vec(bytes, &mut off, len)?;
    if off != bytes.len() {
        return Err("supernova external proof trailing data".to_string());
    }
    Ok(SuperNovaExternalProof {
        recursive_snark_bytes: payload,
    })
}

pub fn generate_supernova_external_proof_bytes(receipt: &R1csReceipt) -> Result<Vec<u8>, String> {
    let recursive = generate_recursive_snark_bytes(receipt)?;
    let external = SuperNovaExternalProof {
        recursive_snark_bytes: recursive,
    };
    Ok(encode_supernova_external_proof_bytes(&external))
}

pub fn verify_supernova_external_proof_bytes(
    receipt: &R1csReceipt,
    bytes: &[u8],
) -> Result<(), String> {
    let external = decode_supernova_external_proof_bytes(bytes)?;
    verify_supernova_external_proof(receipt, &external)
}

fn verify_supernova_external_proof(
    receipt: &R1csReceipt,
    external: &SuperNovaExternalProof,
) -> Result<(), String> {
    let instance = convert_receipt(receipt)?;
    let program = SuperNovaR1csProgram::new(instance.clone());

    let ck_hint1 = default_ck_hint::<Bn256Engine>();
    let ck_hint2 = default_ck_hint::<GrumpkinEngine>();
    let pp = PublicParams::setup(&program, &*ck_hint1, &*ck_hint2);

    let recursive: RecursiveSNARK<Bn256Engine, GrumpkinEngine> = bincode_options()
        .deserialize(&external.recursive_snark_bytes)
        .map_err(|e| format!("supernova recursive snark decode failed: {e}"))?;

    let z0_primary = instance.witness.clone();
    let z0_secondary = vec![SuperNovaSecondaryScalar::ZERO];
    let (out_primary, _) = recursive
        .verify(&pp, &z0_primary, &z0_secondary)
        .map_err(|e| format!("supernova verify failed: {e:?}"))?;
    if out_primary != z0_primary {
        return Err("supernova output mismatch".to_string());
    }
    Ok(())
}

fn generate_recursive_snark_bytes(receipt: &R1csReceipt) -> Result<Vec<u8>, String> {
    let instance = convert_receipt(receipt)?;
    let program = SuperNovaR1csProgram::new(instance.clone());
    let primary = program.primary_circuit(0);
    let secondary = program.secondary_circuit();

    let ck_hint1 = default_ck_hint::<Bn256Engine>();
    let ck_hint2 = default_ck_hint::<GrumpkinEngine>();
    let pp = PublicParams::setup(&program, &*ck_hint1, &*ck_hint2);

    let z0_primary = instance.witness.clone();
    let z0_secondary = vec![SuperNovaSecondaryScalar::ZERO];
    let mut recursive = RecursiveSNARK::new(
        &pp,
        &program,
        &primary,
        &secondary,
        &z0_primary,
        &z0_secondary,
    )
    .map_err(|e| format!("supernova recursive snark init failed: {e:?}"))?;
    recursive
        .prove_step(&pp, &primary, &secondary)
        .map_err(|e| format!("supernova recursive snark prove failed: {e:?}"))?;

    bincode_options()
        .serialize(&recursive)
        .map_err(|e| format!("supernova recursive snark serialize failed: {e}"))
}

#[derive(Clone, Debug)]
struct SuperNovaR1csConstraint {
    a: Vec<(usize, SuperNovaScalar)>,
    b: Vec<(usize, SuperNovaScalar)>,
    c: Vec<(usize, SuperNovaScalar)>,
}

#[derive(Clone, Debug)]
struct SuperNovaR1csInstance {
    num_vars: usize,
    constraints: Arc<Vec<SuperNovaR1csConstraint>>,
    witness: Vec<SuperNovaScalar>,
    u: SuperNovaScalar,
    error: Arc<Vec<SuperNovaScalar>>,
}

#[derive(Clone, Debug)]
struct SuperNovaR1csStepCircuit {
    num_vars: usize,
    constraints: Arc<Vec<SuperNovaR1csConstraint>>,
    u: SuperNovaScalar,
    error: Arc<Vec<SuperNovaScalar>>,
}

impl StepCircuit<SuperNovaScalar> for SuperNovaR1csStepCircuit {
    fn arity(&self) -> usize {
        self.num_vars
    }

    fn circuit_index(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<SuperNovaScalar>>(
        &self,
        cs: &mut CS,
        _pc: Option<&AllocatedNum<SuperNovaScalar>>,
        z: &[AllocatedNum<SuperNovaScalar>],
    ) -> Result<(Option<AllocatedNum<SuperNovaScalar>>, Vec<AllocatedNum<SuperNovaScalar>>), SynthesisError>
    {
        if z.len() != self.num_vars {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self.error.len() != self.constraints.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        for (idx, constraint) in self.constraints.iter().enumerate() {
            for (var_idx, _) in constraint.a.iter().chain(&constraint.b).chain(&constraint.c) {
                if *var_idx >= z.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            let error = self.error[idx];
            let u = self.u;
            cs.enforce(
                || format!("supernova_r1cs_constraint_{idx}"),
                |lc| lc_from_terms(lc, &constraint.a, z),
                |lc| lc_from_terms(lc, &constraint.b, z),
                |lc| {
                    let mut lc = lc_from_terms_scaled(lc, &constraint.c, z, u);
                    lc = lc + (error, CS::one());
                    lc
                },
            );
        }
        Ok((_pc.cloned(), z.to_vec()))
    }
}

#[derive(Clone)]
struct SuperNovaR1csProgram {
    circuit: SuperNovaR1csStepCircuit,
}

impl SuperNovaR1csProgram {
    fn new(instance: SuperNovaR1csInstance) -> Self {
        Self {
            circuit: SuperNovaR1csStepCircuit {
                num_vars: instance.num_vars,
                constraints: instance.constraints,
                u: instance.u,
                error: instance.error,
            },
        }
    }
}

impl NonUniformCircuit<Bn256Engine, GrumpkinEngine, SuperNovaR1csStepCircuit, TrivialSecondaryCircuit<SuperNovaSecondaryScalar>>
    for SuperNovaR1csProgram
{
    fn num_circuits(&self) -> usize {
        1
    }

    fn primary_circuit(&self, circuit_index: usize) -> SuperNovaR1csStepCircuit {
        if circuit_index != 0 {
            debug_assert!(false, "supernova circuit index out of range");
        }
        self.circuit.clone()
    }

    fn secondary_circuit(&self) -> TrivialSecondaryCircuit<SuperNovaSecondaryScalar> {
        TrivialSecondaryCircuit::default()
    }
}

fn lc_from_terms<F: AreciboPrimeField>(
    mut lc: LinearCombination<F>,
    terms: &[(usize, F)],
    z: &[AllocatedNum<F>],
) -> LinearCombination<F> {
    for (idx, coeff) in terms {
        lc = lc + (*coeff, z[*idx].get_variable());
    }
    lc
}

fn lc_from_terms_scaled<F: AreciboPrimeField>(
    mut lc: LinearCombination<F>,
    terms: &[(usize, F)],
    z: &[AllocatedNum<F>],
    scale: F,
) -> LinearCombination<F> {
    for (idx, coeff) in terms {
        lc = lc + (*coeff * scale, z[*idx].get_variable());
    }
    lc
}

fn convert_receipt(receipt: &R1csReceipt) -> Result<SuperNovaR1csInstance, String> {
    let num_vars = receipt.num_vars as usize;
    if receipt.constraints.len() != receipt.num_constraints as usize {
        return Err("r1cs receipt constraint count mismatch".to_string());
    }
    if receipt.witness.len() != num_vars {
        return Err("r1cs receipt witness length mismatch".to_string());
    }
    if receipt.error.len() != receipt.num_constraints as usize {
        return Err("r1cs receipt error length mismatch".to_string());
    }
    let witness = if receipt.witness.len() >= IVC_R1CS_CONVERT_PAR_THRESHOLD
        && rayon::current_num_threads() > 1
    {
        receipt
            .witness
            .par_iter()
            .map(|w| ark_fr_to_supernova(*w))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        receipt
            .witness
            .iter()
            .map(|w| ark_fr_to_supernova(*w))
            .collect::<Result<Vec<_>, _>>()?
    };
    let u = ark_fr_to_supernova(receipt.u)?;
    let error = if receipt.error.len() >= IVC_R1CS_CONVERT_PAR_THRESHOLD
        && rayon::current_num_threads() > 1
    {
        receipt
            .error
            .par_iter()
            .map(|e| ark_fr_to_supernova(*e))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        receipt
            .error
            .iter()
            .map(|e| ark_fr_to_supernova(*e))
            .collect::<Result<Vec<_>, _>>()?
    };
    let constraints = if receipt.constraints.len() >= IVC_R1CS_CONVERT_PAR_THRESHOLD
        && rayon::current_num_threads() > 1
    {
        receipt
            .constraints
            .par_iter()
            .map(|c| convert_constraint(c, num_vars))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        receipt
            .constraints
            .iter()
            .map(|c| convert_constraint(c, num_vars))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(SuperNovaR1csInstance {
        num_vars,
        constraints: Arc::new(constraints),
        witness,
        u,
        error: Arc::new(error),
    })
}

fn convert_constraint(
    constraint: &R1csConstraint,
    num_vars: usize,
) -> Result<SuperNovaR1csConstraint, String> {
    Ok(SuperNovaR1csConstraint {
        a: convert_lc(&constraint.a, num_vars)?,
        b: convert_lc(&constraint.b, num_vars)?,
        c: convert_lc(&constraint.c, num_vars)?,
    })
}

fn convert_lc(
    lc: &R1csLinearCombination,
    num_vars: usize,
) -> Result<Vec<(usize, SuperNovaScalar)>, String> {
    let mut out = Vec::with_capacity(lc.terms.len());
    for term in &lc.terms {
        let idx = term.var_idx as usize;
        if idx >= num_vars {
            return Err("supernova r1cs term index out of bounds".to_string());
        }
        out.push((idx, ark_fr_to_supernova(term.coeff)?));
    }
    Ok(out)
}

fn ark_fr_to_supernova(fr: ArkFr) -> Result<SuperNovaScalar, String> {
    let bigint = fr.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut repr = <SuperNovaScalar as AreciboPrimeField>::Repr::default();
    let repr_bytes = repr.as_mut();
    if le_bytes.len() > repr_bytes.len() {
        return Err("supernova scalar byte length mismatch".to_string());
    }
    repr_bytes[..le_bytes.len()].copy_from_slice(&le_bytes);
    let scalar = SuperNovaScalar::from_repr(repr);
    scalar
        .into_option()
        .ok_or_else(|| "supernova scalar decode failed".to_string())
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes
        .get(*off..*off + 2)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}
