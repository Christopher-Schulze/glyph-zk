//! Compressed SNARK backend for IVC external proof verification.
//!
//! Uses Nova's CompressedSNARK (Spartan) over the canonical R1CS receipt.

use bincode::Options;
use nova_snark::{
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{Bn256EngineIPA, GrumpkinEngine},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    traits::snark::default_ck_hint,
};

use crate::ivc_nova::{convert_receipt, R1csStepCircuit};
use crate::ivc_r1cs::R1csReceipt;

type PrimaryEngine = Bn256EngineIPA;
type SecondaryEngine = GrumpkinEngine;
type PrimaryEE = EvaluationEngine<PrimaryEngine>;
type SecondaryEE = EvaluationEngine<SecondaryEngine>;
type PrimarySnark = RelaxedR1CSSNARK<PrimaryEngine, PrimaryEE>;
type SecondarySnark = RelaxedR1CSSNARK<SecondaryEngine, SecondaryEE>;
type Compressed =
    CompressedSNARK<PrimaryEngine, SecondaryEngine, R1csStepCircuit, PrimarySnark, SecondarySnark>;

fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_big_endian()
}

pub(crate) fn generate_compressed_snark_bytes(receipt: &R1csReceipt) -> Result<Vec<u8>, String> {
    let nova_receipt = convert_receipt(receipt)?;
    let circuit = R1csStepCircuit::new(
        nova_receipt.num_vars,
        nova_receipt.constraints,
        nova_receipt.u,
        nova_receipt.error,
    );

    let ck_hint1 = default_ck_hint::<PrimaryEngine>();
    let ck_hint2 = default_ck_hint::<SecondaryEngine>();
    let pp = PublicParams::setup(&circuit, &*ck_hint1, &*ck_hint2)
        .map_err(|e| format!("compressed public params setup failed: {e:?}"))?;

    let mut recursive: RecursiveSNARK<PrimaryEngine, SecondaryEngine, R1csStepCircuit> =
        RecursiveSNARK::new(&pp, &circuit, &nova_receipt.witness)
            .map_err(|e| format!("compressed recursive snark init failed: {e:?}"))?;
    recursive
        .prove_step(&pp, &circuit)
        .map_err(|e| format!("compressed recursive snark prove failed: {e:?}"))?;

    let (pk, _vk) = Compressed::setup(&pp)
        .map_err(|e| format!("compressed snark setup failed: {e:?}"))?;
    let compressed = Compressed::prove(&pp, &pk, &recursive)
        .map_err(|e| format!("compressed snark prove failed: {e:?}"))?;

    bincode_options()
        .serialize(&compressed)
        .map_err(|e| format!("compressed snark serialize failed: {e}"))
}

pub(crate) fn verify_compressed_snark_bytes(
    receipt: &R1csReceipt,
    bytes: &[u8],
) -> Result<(), String> {
    let nova_receipt = convert_receipt(receipt)?;
    let circuit = R1csStepCircuit::new(
        nova_receipt.num_vars,
        nova_receipt.constraints,
        nova_receipt.u,
        nova_receipt.error,
    );

    let ck_hint1 = default_ck_hint::<PrimaryEngine>();
    let ck_hint2 = default_ck_hint::<SecondaryEngine>();
    let pp = PublicParams::setup(&circuit, &*ck_hint1, &*ck_hint2)
        .map_err(|e| format!("compressed public params setup failed: {e:?}"))?;
    let (_pk, vk) = Compressed::setup(&pp)
        .map_err(|e| format!("compressed snark setup failed: {e:?}"))?;

    let compressed: Compressed = bincode_options()
        .deserialize(bytes)
        .map_err(|e| format!("compressed snark decode failed: {e}"))?;
    let num_steps = 1usize;
    let outputs = compressed
        .verify(&vk, num_steps, &nova_receipt.witness)
        .map_err(|e| format!("compressed snark verify failed: {e:?}"))?;
    if outputs != nova_receipt.witness {
        return Err("compressed snark output mismatch".to_string());
    }
    Ok(())
}
