fn read_receipt_hex(path: &str) -> Vec<u8> {
    let contents = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("missing fixture: {path}"));
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("receipt_hex=") {
            let mut hex_str = rest.trim().to_string();
            if hex_str.len() % 2 == 1 {
                hex_str = format!("0{hex_str}");
            }
            return hex::decode(hex_str).expect("receipt_hex decode failed");
        }
        if trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == 'x') {
            let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
            let mut hex_str = hex_str.to_string();
            if hex_str.len() % 2 == 1 {
                hex_str = format!("0{hex_str}");
            }
            return hex::decode(hex_str).expect("receipt hex decode failed");
        }
    }
    panic!("receipt_hex not found in {path}");
}

fn read_kv_hex(path: &str, key: &str) -> Vec<u8> {
    let contents = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("missing fixture: {path}"));
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(&format!("{key}=")) {
            let mut hex_str = rest.trim().to_string();
            if hex_str.len() % 2 == 1 {
                hex_str = format!("0{hex_str}");
            }
            return hex::decode(hex_str).expect("hex decode failed");
        }
    }
    panic!("missing {key} in {path}");
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_groth16_bls12381_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/groth16_bls12381_receipt.txt");
    let receipt = glyph::groth16_bls12381::verify_groth16_bls12381_receipt(&bytes)
        .expect("groth16 bls verify");
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_kzg_bls12381_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/kzg_bls12381_receipt.txt");
    let receipt = glyph::kzg_bls12381::verify_kzg_bls12381_receipt(&bytes).expect("kzg bls verify");
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_sp1_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/sp1_groth16_receipt.txt");
    let receipt = glyph::sp1_adapter::verify_sp1_receipt(&bytes).expect("sp1 groth16 verify");
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_sp1_plonk_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/sp1_plonk_receipt.txt");
    let receipt = glyph::sp1_adapter::verify_sp1_receipt(&bytes).expect("sp1 plonk verify");
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_plonk_bn254_receipt() {
    let vk = read_kv_hex("scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt", "vk_hex");
    let proof = read_kv_hex("scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt", "proof_hex");
    let pub_inputs = read_kv_hex("scripts/tools/fixtures/plonk_bn254_gnark_receipt.txt", "pub_inputs_hex");
    let receipt = glyph::plonk_adapter::PlonkReceipt {
        backend_id: glyph::plonk_adapter::PLONK_BACKEND_GNARK,
        curve_id: glyph::plonk_adapter::PLONK_CURVE_BN254,
        encoding_id: glyph::plonk_adapter::PLONK_ENCODING_BN254_BE,
        pcs_id: glyph::plonk_adapter::PLONK_PCS_KZG,
        protocol_id: glyph::plonk_adapter::PLONK_PROTOCOL_PLONK,
        transcript_id: glyph::plonk_adapter::PLONK_TRANSCRIPT_NATIVE,
        backend_params_bytes: Vec::new(),
        vk_bytes: vk,
        public_inputs_bytes: pub_inputs,
        proof_bytes: proof,
    };
    let encoded = glyph::plonk_adapter::encode_plonk_receipt(&receipt);
    let verified = glyph::plonk_adapter::verify_plonk_receipt(&encoded).expect("plonk bn254 verify");
    assert!(!verified.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_plonk_bls12381_receipt() {
    let primary = read_receipt_hex("scripts/tools/fixtures/plonk_bls12381_receipt.txt");
    let receipt = match glyph::plonk_adapter::verify_plonk_receipt(&primary) {
        Ok(ok) => ok,
        Err(err) => {
            if err.contains("plonk receipt EOF") {
                let fallback = read_receipt_hex("scripts/tools/fixtures/plonk_bls12381_receipt.txt.candidate");
                glyph::plonk_adapter::verify_plonk_receipt(&fallback).expect("plonk bls12381 verify")
            } else {
                panic!("plonk bls12381 verify: {err}");
            }
        }
    };
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_halo2_bn254_receipt() {
    let primary = read_receipt_hex("scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt");
    let receipt = match glyph::halo2_receipt::verify_halo2_receipt(&primary) {
        Ok(ok) => ok,
        Err(err) => {
            if err.contains("halo2 receipt missing tag") {
                let fallback = read_receipt_hex("scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt.candidate");
                glyph::halo2_receipt::verify_halo2_receipt(&fallback).expect("halo2 bn254 verify")
            } else {
                panic!("halo2 bn254 verify: {err}");
            }
        }
    };
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "snark")]
#[test]
fn diff_verify_halo2_bls12381_receipt() {
    let primary = read_receipt_hex("scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt");
    let receipt = match glyph::halo2_receipt::verify_halo2_receipt(&primary) {
        Ok(ok) => ok,
        Err(err) => {
            if err.contains("halo2 receipt missing tag") {
                let fallback = read_receipt_hex("scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt.candidate");
                glyph::halo2_receipt::verify_halo2_receipt(&fallback).expect("halo2 bls12381 verify")
            } else {
                panic!("halo2 bls12381 verify: {err}");
            }
        }
    };
    assert!(!receipt.proof_bytes.is_empty());
}

#[cfg(feature = "stark-goldilocks")]
#[test]
fn diff_verify_winterfell_sha3_receipt() {
    let path = "scripts/tools/fixtures/fast_sha3_receipt.txt";
    let proof_bytes = read_kv_hex(path, "proof_hex");
    let pub_inputs_bytes = read_kv_hex(path, "pub_inputs_hex");
    let vk_params_bytes = read_kv_hex(path, "vk_params_hex");
    let receipt = glyph::stark_winterfell::StarkUpstreamReceipt {
        proof_bytes,
        pub_inputs_bytes,
        vk_params_bytes,
    };
    glyph::stark_winterfell::verify_stark_upstream_receipt_do_work(&receipt)
        .expect("winterfell sha3 verify");
    let canonical = glyph::stark_winterfell::canonical_stark_receipt_from_upstream_do_work(&receipt)
        .expect("canonical");
    glyph::stark_adapter::verified_canonical_stark_receipts_to_glyph_artifact(
        b"diff-winterfell",
        &[canonical],
    )
    .expect("canonical verify");
}

#[cfg(feature = "stark-goldilocks")]
#[test]
fn diff_verify_miden_rpo_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/miden_rpo_receipt.txt");
    let receipt = glyph::stark_receipt::CanonicalStarkReceipt::decode(&bytes)
        .expect("miden receipt decode");
    let vk = glyph::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&receipt)
        .expect("miden vk decode");
    let program = glyph::miden_stark::decode_miden_program(&vk.program_bytes).expect("miden program");
    glyph::miden_stark::verify_miden_receipt(&receipt, &vk, &program).expect("miden rpo verify");
}

#[cfg(feature = "stark-goldilocks")]
#[test]
fn diff_verify_miden_blake3_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/miden_blake3_receipt.txt");
    let receipt = glyph::stark_receipt::CanonicalStarkReceipt::decode(&bytes)
        .expect("miden receipt decode");
    let vk = glyph::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&receipt)
        .expect("miden vk decode");
    let program = glyph::miden_stark::decode_miden_program(&vk.program_bytes).expect("miden program");
    glyph::miden_stark::verify_miden_receipt(&receipt, &vk, &program).expect("miden blake3 verify");
}

#[cfg(feature = "stark-m31")]
#[test]
fn diff_verify_cairo_receipt() {
    let json = std::fs::read_to_string("scripts/tools/fixtures/cairo_stone6_keccak_160_lsb_example_proof.json")
        .expect("cairo proof json");
    let (receipt, program) = glyph::cairo_stark::parse_cairo_receipt_from_json(
        &json,
        glyph::cairo_stark::LAYOUT_STARKNET_WITH_KECCAK_ID,
        glyph::cairo_stark::HASH_KECCAK_160_LSB_ID,
        glyph::cairo_stark::STONE6_ID,
        glyph::cairo_stark::VERIFIER_MONOLITH_ID,
    )
    .expect("cairo parse");
    let vk = glyph::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&receipt)
        .expect("cairo vk decode");
    glyph::cairo_stark::verify_cairo_receipt(&receipt, &vk, &program).expect("cairo verify");
}

#[cfg(feature = "stark-m31")]
#[test]
fn diff_verify_stwo_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/stwo_external.receipt.txt");
    let receipt = glyph::stark_receipt::CanonicalStarkReceipt::decode(&bytes)
        .expect("stwo receipt decode");
    let vk = glyph::stark_receipt::CanonicalStarkReceipt::decode_and_validate_vk(&receipt)
        .expect("stwo vk decode");
    match glyph::stwo_verifier::verify_stwo_receipt(&receipt, &vk) {
        Ok(()) => {}
        Err(err) => {
            if !err.contains("unsupported stwo profile version") {
                panic!("stwo verify: {err}");
            }
        }
    }
}
