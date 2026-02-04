//! Nova external proof verification for IVC.
//!
//! This module verifies real Nova RecursiveSNARK proofs against a canonical R1CS
//! receipt by compiling the receipt into a Nova StepCircuit.

use std::sync::Arc;

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use bincode::Options;
use ff::PrimeField as NovaPrimeField;
use nova_snark::{
    frontend::{ConstraintSystem, LinearCombination, SynthesisError},
    frontend::gadgets::num::AllocatedNum,
    nova::{PublicParams, RecursiveSNARK},
    provider::{Bn256EngineIPA, GrumpkinEngine},
    traits::{circuit::StepCircuit, snark::default_ck_hint, Engine},
};
use rayon::prelude::*;

use crate::ivc_r1cs::{R1csConstraint, R1csLinearCombination, R1csReceipt};

pub const IVC_NOVA_EXTERNAL_DOMAIN: &[u8] = b"GLYPH_IVC_NOVA_EXTERNAL";
pub const IVC_NOVA_EXTERNAL_VERSION: u16 = 1;
const IVC_R1CS_CONVERT_PAR_THRESHOLD: usize = 256;

pub(crate) type NovaScalar = <Bn256EngineIPA as Engine>::Scalar;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NovaExternalProof {
    pub recursive_snark_bytes: Vec<u8>,
}

fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
}

pub fn encode_nova_external_proof_bytes(proof: &NovaExternalProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        IVC_NOVA_EXTERNAL_DOMAIN.len() + 2 + 4 + proof.recursive_snark_bytes.len(),
    );
    out.extend_from_slice(IVC_NOVA_EXTERNAL_DOMAIN);
    out.extend_from_slice(&IVC_NOVA_EXTERNAL_VERSION.to_be_bytes());
    out.extend_from_slice(&(proof.recursive_snark_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&proof.recursive_snark_bytes);
    out
}

pub fn decode_nova_external_proof_bytes(bytes: &[u8]) -> Result<NovaExternalProof, String> {
    if !bytes.starts_with(IVC_NOVA_EXTERNAL_DOMAIN) {
        return Err("nova external proof missing domain tag".to_string());
    }
    let mut off = IVC_NOVA_EXTERNAL_DOMAIN.len();
    let version = read_u16_be(bytes, &mut off)?;
    if version != IVC_NOVA_EXTERNAL_VERSION {
        return Err(format!("nova external proof unsupported version={version}"));
    }
    let len = read_u32_be(bytes, &mut off)? as usize;
    let payload = read_vec(bytes, &mut off, len)?;
    if off != bytes.len() {
        return Err("nova external proof trailing data".to_string());
    }
    Ok(NovaExternalProof {
        recursive_snark_bytes: payload,
    })
}

pub fn generate_nova_external_proof_bytes(receipt: &R1csReceipt) -> Result<Vec<u8>, String> {
    let recursive = generate_recursive_snark_bytes(receipt)?;
    let external = NovaExternalProof {
        recursive_snark_bytes: recursive,
    };
    Ok(encode_nova_external_proof_bytes(&external))
}

pub fn verify_nova_external_proof_bytes(
    receipt: &R1csReceipt,
    bytes: &[u8],
) -> Result<(), String> {
    let external = decode_nova_external_proof_bytes(bytes)?;
    verify_nova_external_proof(receipt, &external)
}

fn verify_nova_external_proof(
    receipt: &R1csReceipt,
    external: &NovaExternalProof,
) -> Result<(), String> {
    let nova_receipt = convert_receipt(receipt)?;
    let circuit = R1csStepCircuit::new(
        nova_receipt.num_vars,
        nova_receipt.constraints,
        nova_receipt.u,
        nova_receipt.error,
    );

    let ck_hint1 = default_ck_hint::<Bn256EngineIPA>();
    let ck_hint2 = default_ck_hint::<GrumpkinEngine>();
    let pp = PublicParams::setup(&circuit, &*ck_hint1, &*ck_hint2)
        .map_err(|e| format!("nova public params setup failed: {e:?}"))?;

    let recursive: RecursiveSNARK<Bn256EngineIPA, GrumpkinEngine, R1csStepCircuit> =
        bincode_options()
            .deserialize(&external.recursive_snark_bytes)
            .map_err(|e| format!("nova recursive snark decode failed: {e}"))?;
    let num_steps = recursive.num_steps();
    if num_steps != 1 {
        return Err("nova external proof must have num_steps=1".to_string());
    }
    recursive
        .verify(&pp, num_steps, &nova_receipt.witness)
        .map_err(|e| format!("nova verify failed: {e:?}"))?;
    if recursive.outputs() != nova_receipt.witness.as_slice() {
        return Err("nova output mismatch".to_string());
    }
    Ok(())
}

fn generate_recursive_snark_bytes(receipt: &R1csReceipt) -> Result<Vec<u8>, String> {
    let nova_receipt = convert_receipt(receipt)?;
    let circuit = R1csStepCircuit::new(
        nova_receipt.num_vars,
        nova_receipt.constraints,
        nova_receipt.u,
        nova_receipt.error,
    );
    let ck_hint1 = default_ck_hint::<Bn256EngineIPA>();
    let ck_hint2 = default_ck_hint::<GrumpkinEngine>();
    let pp = PublicParams::setup(&circuit, &*ck_hint1, &*ck_hint2)
        .map_err(|e| format!("nova public params setup failed: {e:?}"))?;
    let mut recursive = RecursiveSNARK::new(&pp, &circuit, &nova_receipt.witness)
        .map_err(|e| format!("nova recursive snark init failed: {e:?}"))?;
    recursive
        .prove_step(&pp, &circuit)
        .map_err(|e| format!("nova recursive snark prove failed: {e:?}"))?;
    bincode_options()
        .serialize(&recursive)
        .map_err(|e| format!("nova recursive snark serialize failed: {e}"))
}

#[derive(Clone, Debug)]
pub(crate) struct NovaR1csConstraint {
    a: Vec<(usize, NovaScalar)>,
    b: Vec<(usize, NovaScalar)>,
    c: Vec<(usize, NovaScalar)>,
}

#[derive(Clone, Debug)]
pub(crate) struct NovaR1csReceipt {
    pub(crate) num_vars: usize,
    pub(crate) constraints: Arc<Vec<NovaR1csConstraint>>,
    pub(crate) witness: Vec<NovaScalar>,
    pub(crate) u: NovaScalar,
    pub(crate) error: Arc<Vec<NovaScalar>>,
}

#[derive(Clone)]
pub(crate) struct R1csStepCircuit {
    num_vars: usize,
    constraints: Arc<Vec<NovaR1csConstraint>>,
    u: NovaScalar,
    error: Arc<Vec<NovaScalar>>,
}

impl R1csStepCircuit {
    pub(crate) fn new(
        num_vars: usize,
        constraints: Arc<Vec<NovaR1csConstraint>>,
        u: NovaScalar,
        error: Arc<Vec<NovaScalar>>,
    ) -> Self {
        Self {
            num_vars,
            constraints,
            u,
            error,
        }
    }
}

impl StepCircuit<NovaScalar> for R1csStepCircuit {
    fn arity(&self) -> usize {
        self.num_vars
    }

    fn synthesize<CS: ConstraintSystem<NovaScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<NovaScalar>],
    ) -> Result<Vec<AllocatedNum<NovaScalar>>, SynthesisError> {
        if z.len() != self.num_vars {
            return Err(SynthesisError::Unsatisfiable(
                "nova r1cs arity mismatch".to_string(),
            ));
        }
        if self.error.len() != self.constraints.len() {
            return Err(SynthesisError::Unsatisfiable(
                "nova r1cs error length mismatch".to_string(),
            ));
        }
        for (idx, constraint) in self.constraints.iter().enumerate() {
            for (var_idx, _) in constraint.a.iter().chain(&constraint.b).chain(&constraint.c) {
                if *var_idx >= z.len() {
                    return Err(SynthesisError::Unsatisfiable(format!(
                        "nova r1cs term index out of bounds: {var_idx}"
                    )));
                }
            }
            let error = self.error[idx];
            let u = self.u;
            cs.enforce(
                || format!("nova_r1cs_constraint_{idx}"),
                |lc| lc_from_terms(lc, &constraint.a, z),
                |lc| lc_from_terms(lc, &constraint.b, z),
                |lc| {
                    let mut lc = lc_from_terms_scaled(lc, &constraint.c, z, u);
                    lc = lc + (error, CS::one());
                    lc
                },
            );
        }
        Ok(z.to_vec())
    }
}

fn lc_from_terms<F: NovaPrimeField>(
    mut lc: LinearCombination<F>,
    terms: &[(usize, F)],
    z: &[AllocatedNum<F>],
) -> LinearCombination<F> {
    for (idx, coeff) in terms {
        lc = lc + (*coeff, z[*idx].get_variable());
    }
    lc
}

fn lc_from_terms_scaled<F: NovaPrimeField>(
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

pub(crate) fn convert_receipt(receipt: &R1csReceipt) -> Result<NovaR1csReceipt, String> {
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
            .map(|w| ark_fr_to_nova(*w))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        receipt
            .witness
            .iter()
            .map(|w| ark_fr_to_nova(*w))
            .collect::<Result<Vec<_>, _>>()?
    };
    let u = ark_fr_to_nova(receipt.u)?;
    let error = if receipt.error.len() >= IVC_R1CS_CONVERT_PAR_THRESHOLD
        && rayon::current_num_threads() > 1
    {
        receipt
            .error
            .par_iter()
            .map(|e| ark_fr_to_nova(*e))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        receipt
            .error
            .iter()
            .map(|e| ark_fr_to_nova(*e))
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
    Ok(NovaR1csReceipt {
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
) -> Result<NovaR1csConstraint, String> {
    Ok(NovaR1csConstraint {
        a: convert_lc(&constraint.a, num_vars)?,
        b: convert_lc(&constraint.b, num_vars)?,
        c: convert_lc(&constraint.c, num_vars)?,
    })
}

fn convert_lc(
    lc: &R1csLinearCombination,
    num_vars: usize,
) -> Result<Vec<(usize, NovaScalar)>, String> {
    let mut out = Vec::with_capacity(lc.terms.len());
    for term in &lc.terms {
        let idx = term.var_idx as usize;
        if idx >= num_vars {
            return Err("nova r1cs term index out of bounds".to_string());
        }
        out.push((idx, ark_fr_to_nova(term.coeff)?));
    }
    Ok(out)
}

fn ark_fr_to_nova(fr: ArkFr) -> Result<NovaScalar, String> {
    let bigint = fr.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut repr = <NovaScalar as NovaPrimeField>::Repr::default();
    let repr_bytes = repr.as_mut();
    if le_bytes.len() > repr_bytes.len() {
        return Err("nova scalar byte length mismatch".to_string());
    }
    repr_bytes[..le_bytes.len()].copy_from_slice(&le_bytes);
    let scalar = NovaScalar::from_repr(repr);
    scalar
        .into_option()
        .ok_or_else(|| "nova scalar decode failed".to_string())
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
