//! Canonical Plonky2 receipt format (Goldilocks) for STARK.
//!
//! Verification behavior:
//! - Native Plonky2 verification is always enabled for STARK Goldilocks receipts.

use crate::stark_adapter::verified_canonical_stark_receipts_to_glyph_artifact;
use crate::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};
use crate::adapter_error::{wrap, wrap_stage};
use plonky2_field::types::PrimeField64;
use plonky2::util::serialization::{Buffer, DefaultGateSerializer, Read};

pub const PLONKY2_RECEIPT_TAG: &[u8] = b"PLONKY2_RECEIPT";
pub const FIELD_GOLDILOCKS_ID: u8 = 0x05;
pub const HASH_SHA3_ID: u8 = 0x02;
pub const VC_MERKLE_ID: u8 = 0x01;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPlonky2Receipt {
    pub proof_bytes: Vec<u8>,
    pub pub_inputs_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

impl CanonicalPlonky2Receipt {
    pub fn to_canonical_receipt(&self) -> CanonicalStarkReceipt {
        CanonicalStarkReceipt {
            proof_bytes: self.proof_bytes.clone(),
            pub_inputs_bytes: self.pub_inputs_bytes.clone(),
            vk_bytes: self.vk_bytes.clone(),
        }
    }
}

pub fn encode_plonky2_receipt(receipt: &CanonicalPlonky2Receipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PLONKY2_RECEIPT_TAG.len()
            + 4
            + receipt.proof_bytes.len()
            + 4
            + receipt.pub_inputs_bytes.len()
            + 4
            + receipt.vk_bytes.len(),
    );
    out.extend_from_slice(PLONKY2_RECEIPT_TAG);
    out.extend_from_slice(&(receipt.proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.proof_bytes);
    out.extend_from_slice(&(receipt.pub_inputs_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.pub_inputs_bytes);
    out.extend_from_slice(&(receipt.vk_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt.vk_bytes);
    out
}

pub fn decode_plonky2_receipt(bytes: &[u8]) -> Result<CanonicalPlonky2Receipt, String> {
    if !bytes.starts_with(PLONKY2_RECEIPT_TAG) {
        return Err("plonky2 receipt missing tag".to_string());
    }
    let mut off = PLONKY2_RECEIPT_TAG.len();
    let proof_len = read_u32_be(bytes, &mut off)? as usize;
    let proof_bytes = read_vec(bytes, &mut off, proof_len)?;
    let pub_len = read_u32_be(bytes, &mut off)? as usize;
    let pub_inputs_bytes = read_vec(bytes, &mut off, pub_len)?;
    let vk_len = read_u32_be(bytes, &mut off)? as usize;
    let vk_bytes = read_vec(bytes, &mut off, vk_len)?;
    if off != bytes.len() {
        return Err("plonky2 receipt has trailing bytes".to_string());
    }
    Ok(CanonicalPlonky2Receipt {
        proof_bytes,
        pub_inputs_bytes,
        vk_bytes,
    })
}

pub fn verify_plonky2_receipt(bytes: &[u8]) -> Result<CanonicalPlonky2Receipt, String> {
    let receipt = decode_plonky2_receipt(bytes).map_err(|e| wrap_stage("plonky2", "decode", e))?;
    if receipt.proof_bytes.is_empty() {
        return Err(wrap("plonky2", "receipt proof is empty"));
    }
    if receipt.pub_inputs_bytes.is_empty() {
        return Err(wrap("plonky2", "receipt pub_inputs is empty"));
    }
    if receipt.vk_bytes.is_empty() {
        return Err(wrap("plonky2", "receipt vk is empty"));
    }
    let vk = CanonicalStarkVk::decode(&receipt.vk_bytes)
        .map_err(|e| wrap_stage("plonky2", "vk decode", e))?;
    if vk.field_id != FIELD_GOLDILOCKS_ID {
        return Err(wrap("plonky2", "vk field_id mismatch"));
    }
    let pub_inputs = decode_plonky2_pub_inputs(&receipt.pub_inputs_bytes)
        .map_err(|e| wrap_stage("plonky2", "pub_inputs decode", e))?;
    verify_plonky2_proof_native(&vk.program_bytes, &receipt.proof_bytes, &pub_inputs)
        .map_err(|e| wrap_stage("plonky2", "verify", e))?;
    Ok(receipt)
}

pub fn decode_plonky2_pub_inputs(bytes: &[u8]) -> Result<Vec<u64>, String> {
    bincode::deserialize(bytes).map_err(|e| format!("plonky2 pub_inputs decode: {e}"))
}

pub fn verify_plonky2_proof_native(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    pub_inputs: &[u64],
) -> Result<(), String> {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::circuit_data::VerifierCircuitData;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    if vk_bytes.len() < 8 {
        return Err("plonky2 vk bytes too short".to_string());
    }
    let mut head = [0u8; 8];
    head.copy_from_slice(&vk_bytes[..8]);
    let cap_height = u64::from_le_bytes(head);
    if cap_height >= usize::BITS as u64 {
        return Err("plonky2 vk cap_height too large".to_string());
    }

    let gate_serializer = DefaultGateSerializer;
    let mut vk_buf = Buffer::new(vk_bytes);
    let vd: VerifierCircuitData<F, C, D> = vk_buf
        .read_verifier_circuit_data(&gate_serializer)
        .map_err(|_| "plonky2 vk decode failed".to_string())?;
    if vk_buf.pos() != vk_buf.bytes().len() {
        return Err("plonky2 vk trailing bytes".to_string());
    }

    let mut proof_buf = Buffer::new(proof_bytes);
    let proof: ProofWithPublicInputs<F, C, D> = proof_buf
        .read_proof_with_public_inputs(&vd.common)
        .map_err(|_| "plonky2 proof decode failed".to_string())?;
    if proof_buf.pos() != proof_buf.bytes().len() {
        return Err("plonky2 proof trailing bytes".to_string());
    }

    if proof.public_inputs.len() != pub_inputs.len() {
        return Err("plonky2 public input length mismatch".to_string());
    }
    for (proof_pi, src) in proof.public_inputs.iter().zip(pub_inputs.iter()) {
        if proof_pi.to_canonical_u64() != *src {
            return Err("plonky2 public input mismatch".to_string());
        }
    }
    vd.verify(proof).map_err(|e| format!("plonky2 verify failed: {e}"))
}

pub fn derive_glyph_artifact_from_plonky2_receipt(
    receipt_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    derive_glyph_artifact_from_plonky2_receipt_with_seed(receipt_bytes, b"glyph-plonky2-default")
}

pub fn derive_glyph_artifact_from_plonky2_receipt_with_seed(
    receipt_bytes: &[u8],
    seed: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let receipt = verify_plonky2_receipt(receipt_bytes)?;
    let canonical = receipt.to_canonical_receipt();
    verified_canonical_stark_receipts_to_glyph_artifact(seed, &[canonical])
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes
        .get(*off..*off + 4)
        .ok_or_else(|| "plonky2 receipt EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes
        .get(*off..*off + len)
        .ok_or_else(|| "plonky2 receipt EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

#[cfg(test)]
#[allow(dead_code)]
fn demo_plonky2_receipt() -> CanonicalPlonky2Receipt {
    let vk = CanonicalStarkVk {
        version: 1,
        field_id: FIELD_GOLDILOCKS_ID,
        hash_id: HASH_SHA3_ID,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: b"plonky2-consts".to_vec(),
        program_bytes: b"plonky2-program".to_vec(),
    };
    CanonicalPlonky2Receipt {
        proof_bytes: b"plonky2-proof".to_vec(),
        pub_inputs_bytes: b"plonky2-pub".to_vec(),
        vk_bytes: vk.encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::util::serialization::Write;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2_field::types::Field;

    fn build_valid_plonky2_receipt() -> Result<CanonicalPlonky2Receipt, String> {
        use plonky2::field::goldilocks_field::GoldilocksField;
        use plonky2::iop::witness::PartialWitness;
        use plonky2::plonk::circuit_builder::CircuitBuilder;
        use plonky2::plonk::circuit_data::CircuitConfig;
        use plonky2::plonk::config::PoseidonGoldilocksConfig;

        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let z = builder.mul(x, y);
        builder.register_public_input(z);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(3));
        pw.set_target(y, F::from_canonical_u64(5));
        let proof = data
            .prove(pw)
            .map_err(|e| format!("plonky2 prove failed: {e}"))?;
        let pub_inputs: Vec<u64> = proof
            .public_inputs
            .iter()
            .map(|v| v.to_canonical_u64())
            .collect();

        let gate_serializer = DefaultGateSerializer;
        let mut vk_program_bytes = Vec::new();
        vk_program_bytes
            .write_verifier_circuit_data(&data.verifier_data(), &gate_serializer)
            .map_err(|_| "plonky2 vk encode failed".to_string())?;
        let mut proof_bytes = Vec::new();
        proof_bytes
            .write_proof_with_public_inputs(&proof)
            .map_err(|_| "plonky2 proof encode failed".to_string())?;
        let pub_inputs_bytes = bincode::serialize(&pub_inputs)
            .map_err(|e| format!("plonky2 pub_inputs encode failed: {e}"))?;

        let vk = CanonicalStarkVk {
            version: 1,
            field_id: FIELD_GOLDILOCKS_ID,
            hash_id: HASH_SHA3_ID,
            commitment_scheme_id: VC_MERKLE_ID,
            consts_bytes: Vec::new(),
            program_bytes: vk_program_bytes,
        };
        Ok(CanonicalPlonky2Receipt {
            proof_bytes,
            pub_inputs_bytes,
            vk_bytes: vk.encode(),
        })
    }

    #[test]
    fn test_plonky2_receipt_roundtrip_and_artifact() {
        let receipt = match build_valid_plonky2_receipt() {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "valid receipt");
                return;
            }
        };
        let bytes = encode_plonky2_receipt(&receipt);
        let decoded = match decode_plonky2_receipt(&bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(decoded, receipt);
        if let Err(_) = verify_plonky2_receipt(&bytes) {
            assert!(false, "verify");
            return;
        }
        let (commitment_tag, point_tag, claim128) =
            match derive_glyph_artifact_from_plonky2_receipt_with_seed(&bytes, b"glyph-plonky2-test") {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "artifact");
                    return;
                }
            };
        assert_ne!(commitment_tag, [0u8; 32]);
        assert_ne!(point_tag, [0u8; 32]);
        assert_ne!(claim128, 0u128);
    }

    #[test]
    fn test_plonky2_receipt_fixture_emit() {
        let receipt = match build_valid_plonky2_receipt() {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "valid receipt");
                return;
            }
        };
        let bytes = encode_plonky2_receipt(&receipt);
        let payload = format!("receipt_hex={}\n", hex::encode(&bytes));
        let path = "scripts/tools/fixtures/fast_plonky2_goldilocks_receipt.txt";
        let target = if std::path::Path::new(path).exists() {
            format!("{path}.candidate")
        } else {
            path.to_string()
        };
        if let Err(_) = std::fs::write(&target, payload) {
            assert!(false, "fixture write");
        }
    }
}
