//! Adapter Groth16 BN254 bridge into GLYPH artifacts.
//!
//! This module wires strict Groth16 parsing and verification into the GLYPH artifact boundary.

use crate::adapter_ir::kernel_id;

pub const GLYPH_GROTH16_BN254_INSTANCE_DOMAIN: &[u8] = b"GLYPH_GROTH16_BN254_INSTANCE";

pub fn derive_glyph_artifact_from_groth16_bn254(
    adapter_vk_bytes: &[u8],
    adapter_statement_bytes: &[u8],
    raw_vk_bytes: &[u8],
    raw_proof_bytes: &[u8],
    raw_public_inputs_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    let ir = crate::adapter_ir::AdapterIr {
        version: 1,
        ops: vec![crate::adapter_ir::AdapterIrOp {
            kernel_id: kernel_id::GROTH16_BN254_VERIFY,
            args: Vec::new(),
        }],
    };
    crate::adapter_ir::derive_glyph_artifact_from_groth16_bn254_ir(
        &ir.encode(),
        adapter_vk_bytes,
        adapter_statement_bytes,
        raw_vk_bytes,
        raw_proof_bytes,
        raw_public_inputs_bytes,
    )
}

pub fn load_groth16_bn254_fixture_bytes() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let path = "scripts/tools/fixtures/groth16_bn254_fixture.txt";
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("fixture read failed: {e}"))?;
    let mut vk_hex = None;
    let mut proof_hex = None;
    let mut pub_hex = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("vk_hex=") {
            vk_hex = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("proof_hex=") {
            proof_hex = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("pub_inputs_hex=") {
            pub_hex = Some(rest.trim().to_string());
        }
    }
    let vk_hex = vk_hex.ok_or_else(|| "vk_hex missing".to_string())?;
    let proof_hex = proof_hex.ok_or_else(|| "proof_hex missing".to_string())?;
    let pub_hex = pub_hex.ok_or_else(|| "pub_inputs_hex missing".to_string())?;
    let vk = hex::decode(vk_hex).map_err(|e| format!("vk hex decode failed: {e}"))?;
    let proof = hex::decode(proof_hex).map_err(|e| format!("proof hex decode failed: {e}"))?;
    let pub_inputs = hex::decode(pub_hex).map_err(|e| format!("pub hex decode failed: {e}"))?;
    Ok((vk, proof, pub_inputs))
}

#[cfg(all(test, feature = "dev-tools"))]
mod tests {
    use super::*;
    #[cfg(feature = "dev-tools")]
    use crate::adapters::SNARK_GROTH16_BN254_ID;
    #[cfg(feature = "dev-tools")]
    use crate::adapters::keccak256;
    #[cfg(feature = "dev-tools")]
    use ark_snark::SNARK;
    #[cfg(feature = "dev-tools")]
    use ark_bn254::Fr;
    #[cfg(feature = "dev-tools")]
    use ark_groth16::Groth16;
    #[cfg(feature = "dev-tools")]
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError};
    #[cfg(feature = "dev-tools")]
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[cfg(feature = "dev-tools")]
    fn load_fixture_or_fail() -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        match load_groth16_bn254_fixture_bytes() {
            Ok(value) => Some(value),
            Err(_) => {
                assert!(false, "fixture");
                None
            }
        }
    }

    #[cfg(feature = "dev-tools")]
    fn decode_fixture_or_fail(
        vk_bytes: &[u8],
        proof_bytes: &[u8],
        pub_bytes: &[u8],
    ) -> Option<(
        crate::bn254_groth16::Groth16VerifyingKey,
        crate::bn254_groth16::Groth16Proof,
        Vec<ark_bn254::Fr>,
    )> {
        let vk = match crate::bn254_groth16::decode_groth16_vk_bytes(vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk decode");
                return None;
            }
        };
        let proof = match crate::bn254_groth16::decode_groth16_proof_bytes(proof_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof decode");
                return None;
            }
        };
        let pub_inputs = match crate::bn254_groth16::decode_groth16_public_inputs(pub_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "pub decode");
                return None;
            }
        };
        Some((vk, proof, pub_inputs))
    }

    #[cfg(feature = "dev-tools")]
    #[derive(Clone)]
    struct MulCircuit {
        pub a: Fr,
        pub b: Fr,
        pub c: Fr,
    }

    #[cfg(feature = "dev-tools")]
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

    #[cfg(feature = "dev-tools")]
    fn encode_vk_bytes(vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> Vec<u8> {
        let vk = crate::bn254_groth16::Groth16VerifyingKey {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            ic: vk.gamma_abc_g1.clone(),
        };
        crate::bn254_groth16::encode_groth16_vk_bytes(&vk)
    }

    #[cfg(feature = "dev-tools")]
    fn encode_proof_bytes(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> Vec<u8> {
        let proof = crate::bn254_groth16::Groth16Proof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        };
        crate::bn254_groth16::encode_groth16_proof_bytes(&proof).to_vec()
    }

    #[cfg(feature = "dev-tools")]
    fn encode_inputs(inputs: &[Fr]) -> Vec<u8> {
        crate::bn254_groth16::encode_groth16_public_inputs(inputs)
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_artifact_roundtrip() {
        let (raw_vk_bytes, raw_proof_bytes, raw_pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        let input_layout_hash = keccak256(b"groth16-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let res = derive_glyph_artifact_from_groth16_bn254(
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
        )
            .unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(res.0, [0u8; 32]);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_artifact_roundtrip_g2precomp() {
        let (raw_vk_bytes, raw_proof_bytes, raw_pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        let input_layout_hash = keccak256(b"groth16-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let vk = match crate::bn254_groth16::decode_groth16_vk_bytes(&raw_vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        let beta_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.beta_g2);
        let gamma_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.gamma_g2);
        let delta_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.delta_g2);
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes_g2_precomp(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
            &beta_precomp,
            &gamma_precomp,
            &delta_precomp,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let res = derive_glyph_artifact_from_groth16_bn254(
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
        )
            .unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(res.0, [0u8; 32]);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_artifact_roundtrip_full_precomp() {
        let _env_lock = crate::test_utils::lock_env();
        let _window = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_SCALAR_WINDOW", "6");
        let (raw_vk_bytes, raw_proof_bytes, raw_pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        let input_layout_hash = keccak256(b"groth16-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let vk = match crate::bn254_groth16::decode_groth16_vk_bytes(&raw_vk_bytes) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "vk");
                return;
            }
        };
        let beta_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.beta_g2);
        let gamma_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.gamma_g2);
        let delta_precomp = crate::bn254_pairing_trace::encode_g2_precomp_bytes(vk.delta_g2);
        let window = 6usize;
        let mut ic_precomp = Vec::with_capacity(vk.ic.len().saturating_sub(1));
        for ic in vk.ic.iter().skip(1) {
            let base_precomp = crate::bn254_pairing_trace::encode_g1_wnaf_precomp_bytes(*ic, window);
            let phi_precomp =
                crate::bn254_pairing_trace::encode_g1_wnaf_precomp_phi_bytes(*ic, window);
            ic_precomp.push(crate::adapters::Groth16Bn254IcPrecomp {
                base_precomp,
                phi_precomp,
            });
        }
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes_full_precomp(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
            &beta_precomp,
            &gamma_precomp,
            &delta_precomp,
            window as u8,
            &ic_precomp,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let res = derive_glyph_artifact_from_groth16_bn254(
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
        )
            .unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(res.0, [0u8; 32]);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_tamper_fails() {
        let (raw_vk_bytes, mut raw_proof_bytes, raw_pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        raw_proof_bytes[0] ^= 1;
        let input_layout_hash = keccak256(b"groth16-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        assert!(derive_glyph_artifact_from_groth16_bn254(
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes
        )
        .is_err());
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_trace_stats() {
        let _env_lock = crate::test_utils::lock_env();
        let _trace =
            crate::test_utils::EnvVarGuard::set("GLYPH_GROTH16_BN254_TRACE_STATS", "1");
        let (vk_bytes, proof_bytes, pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        let (vk_local, proof_local, pub_inputs) =
            match decode_fixture_or_fail(&vk_bytes, &proof_bytes, &pub_bytes) {
                Some(value) => value,
                None => return,
            };

        let _events = crate::bn254_pairing_trace::record_groth16_pairing_ops(
            &vk_local,
            &proof_local,
            &pub_inputs,
        )
        .unwrap_or_else(|_| {
            assert!(false, "pairing trace");
            Vec::new()
        });
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_trace_stats_ic_precomp() {
        let _env_lock = crate::test_utils::lock_env();
        let _trace =
            crate::test_utils::EnvVarGuard::set("GLYPH_GROTH16_BN254_TRACE_STATS", "1");
        let _window = crate::test_utils::EnvVarGuard::set("GLYPH_BN254_SCALAR_WINDOW", "6");
        let window = 6usize;
        let (vk_bytes, proof_bytes, pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        let (vk_local, proof_local, pub_inputs) =
            match decode_fixture_or_fail(&vk_bytes, &proof_bytes, &pub_bytes) {
                Some(value) => value,
                None => return,
            };
        let mut ic_precomp = Vec::with_capacity(vk_local.ic.len().saturating_sub(1));
        for ic in vk_local.ic.iter().skip(1) {
            let base_precomp =
                crate::bn254_pairing_trace::encode_g1_wnaf_precomp_bytes(*ic, window);
            let phi_precomp =
                crate::bn254_pairing_trace::encode_g1_wnaf_precomp_phi_bytes(*ic, window);
            let table = match crate::bn254_pairing_trace::decode_g1_wnaf_precomp_pair(
                window,
                &base_precomp,
                &phi_precomp,
            ) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "ic precomp");
                    return;
                }
            };
            ic_precomp.push(table);
        }

        let _events = crate::bn254_pairing_trace::record_groth16_pairing_ops_with_precomp(
            &vk_local,
            &proof_local,
            &pub_inputs,
            None,
            None,
            None,
            Some(&ic_precomp),
        )
        .unwrap_or_else(|_| {
            assert!(false, "pairing trace");
            Vec::new()
        });
    }

    #[test]
    fn test_groth16_bn254_trace_event_consistency() {
        let (vk_bytes, proof_bytes, pub_bytes) = match load_fixture_or_fail() {
            Some(value) => value,
            None => return,
        };
        let (vk_local, proof_local, pub_inputs) =
            match decode_fixture_or_fail(&vk_bytes, &proof_bytes, &pub_bytes) {
                Some(value) => value,
                None => return,
            };

        let events = crate::bn254_pairing_trace::record_groth16_pairing_ops(
            &vk_local,
            &proof_local,
            &pub_inputs,
        )
        .unwrap_or_else(|_| {
            assert!(false, "pairing trace");
            Vec::new()
        });
        if let Err(_) = crate::bn254_ops::validate_bn254_op_trace_batch(&events) {
            assert!(false, "trace batch validate");
        }
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_trace_full() {
        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let a = Fr::from(5u64);
        let b = Fr::from(7u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let (pk, vk) = match Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "setup");
                return;
            }
        };
        let proof = match Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };

        let raw_vk_bytes = encode_vk_bytes(&vk);
        let raw_proof_bytes = encode_proof_bytes(&proof);
        let raw_pub_bytes = encode_inputs(&[c]);
        let input_layout_hash = keccak256(b"groth16-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        let res = derive_glyph_artifact_from_groth16_bn254(
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
        )
            .unwrap_or_else(|_| {
                assert!(false, "artifact");
                ([0u8; 32], [0u8; 32], 0u128)
            });
        assert_ne!(res.0, [0u8; 32]);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_trace_tamper_fails() {
        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let a = Fr::from(5u64);
        let b = Fr::from(7u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let (pk, vk) = match Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "setup");
                return;
            }
        };
        let proof = match Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };

        let raw_vk_bytes = encode_vk_bytes(&vk);
        let mut raw_proof_bytes = encode_proof_bytes(&proof);
        let raw_pub_bytes = encode_inputs(&[c]);
        raw_proof_bytes[0] ^= 1;
        let input_layout_hash = keccak256(b"groth16-bn254-test-layout");
        let vk_hash = keccak256(&raw_vk_bytes);
        let pub_hash = keccak256(&raw_pub_bytes);
        let adapter_vk_bytes = crate::adapters::groth16_bn254_vk_bytes(
            SNARK_GROTH16_BN254_ID,
            &vk_hash,
            &input_layout_hash,
        );
        let adapter_statement_bytes =
            crate::adapters::groth16_bn254_statement_bytes(&input_layout_hash, &pub_hash);

        assert!(derive_glyph_artifact_from_groth16_bn254(
            &adapter_vk_bytes,
            &adapter_statement_bytes,
            &raw_vk_bytes,
            &raw_proof_bytes,
            &raw_pub_bytes,
        )
        .is_err());
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_verify_smoke() {
        use crate::bn254_groth16::verify_groth16_proof;
        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let a = Fr::from(5u64);
        let b = Fr::from(7u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let (pk, vk) = match Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "setup");
                return;
            }
        };
        let proof = match Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };
        let vk_local = crate::bn254_groth16::Groth16VerifyingKey {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            ic: vk.gamma_abc_g1.clone(),
        };
        let proof_local = crate::bn254_groth16::Groth16Proof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        };
        let ok = match verify_groth16_proof(&vk_local, &proof_local, &[c]) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "verify");
                return;
            }
        };
        assert!(ok);
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn test_groth16_bn254_fixture_dump() {
        let mut rng = StdRng::seed_from_u64(0xface_cafe);
        let a = Fr::from(5u64);
        let b = Fr::from(7u64);
        let c = a * b;
        let circuit = MulCircuit { a, b, c };
        let (pk, vk) = match Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
            circuit.clone(),
            &mut rng,
        ) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "setup");
                return;
            }
        };
        let proof = match Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "proof");
                return;
            }
        };

        let vk_local = crate::bn254_groth16::Groth16VerifyingKey {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            ic: vk.gamma_abc_g1.clone(),
        };
        let proof_local = crate::bn254_groth16::Groth16Proof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        };

        let vk_bytes = crate::bn254_groth16::encode_groth16_vk_bytes(&vk_local);
        let proof_bytes = crate::bn254_groth16::encode_groth16_proof_bytes(&proof_local);
        let pub_bytes = crate::bn254_groth16::encode_groth16_public_inputs(&[c]);

        println!("vk_hex={}", hex::encode(vk_bytes));
        println!("proof_hex={}", hex::encode(proof_bytes));
        println!("pub_inputs_hex={}", hex::encode(pub_bytes));
    }
}
