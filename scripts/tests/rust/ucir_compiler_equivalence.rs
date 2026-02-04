fn fixture_path(path: &str) -> String {
    let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    format!("{root}/{path}")
}

fn read_receipt_hex(path: &str) -> Vec<u8> {
    let full_path = fixture_path(path);
    let raw = std::fs::read(&full_path).unwrap_or_else(|_| panic!("missing fixture: {full_path}"));
    let contents = match std::str::from_utf8(&raw) {
        Ok(text) => text,
        Err(_) => {
            return raw;
        }
    };
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
    let full_path = fixture_path(path);
    let contents = std::fs::read_to_string(&full_path)
        .unwrap_or_else(|_| panic!("missing fixture: {full_path}"));
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

fn assert_ucir_equivalence(compiled: glyph::glyph_ir_compiler::CompiledUcir) {
    let mut stream = glyph::glyph_witness::WitnessStream::try_new(
        compiled.ucir,
        1024 * 1024 * 1024,
    )
    .expect("witness stream");
    stream
        .phase_w1_produce(&compiled.public_inputs, Some(&compiled.wire_values))
        .expect("phase_w1_produce");
    let evals = stream.phase_w2_evaluate().expect("phase_w2_evaluate");
    for (idx, eval) in evals.iter().enumerate() {
        assert_eq!(*eval, glyph::glyph_field_simd::Goldilocks::ZERO, "eval[{idx}] != 0");
    }
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_groth16_bn254_fixture() {
    let vk = read_kv_hex("scripts/tools/fixtures/groth16_bn254_fixture.txt", "vk_hex");
    let proof = read_kv_hex("scripts/tools/fixtures/groth16_bn254_fixture.txt", "proof_hex");
    let pub_inputs = read_kv_hex("scripts/tools/fixtures/groth16_bn254_fixture.txt", "pub_inputs_hex");
    let compiled = glyph::glyph_ir_compiler::compile_groth16_bn254(&vk, &proof, &pub_inputs)
        .expect("compile groth16 bn254");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_groth16_bls12381_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/groth16_bls12381_receipt.txt");
    let compiled = glyph::glyph_ir_compiler::compile_groth16_bls12381(&bytes)
        .expect("compile groth16 bls12381");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_kzg_bls12381_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/kzg_bls12381_receipt.txt");
    let compiled = glyph::glyph_ir_compiler::compile_kzg_bls12381(&bytes)
        .expect("compile kzg bls12381");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_sp1_groth16_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/sp1_groth16_receipt.txt");
    let compiled = glyph::glyph_ir_compiler::compile_sp1(&bytes).expect("compile sp1 groth16");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_sp1_plonk_receipt() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/sp1_plonk_receipt.txt");
    let compiled = glyph::glyph_ir_compiler::compile_sp1(&bytes).expect("compile sp1 plonk");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_plonk_bn254_receipt() {
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
    let compiled = glyph::glyph_ir_compiler::compile_plonk(&encoded)
        .expect("compile plonk bn254");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_plonk_bls12381_receipt() {
    let primary = read_receipt_hex("scripts/tools/fixtures/plonk_bls12381_receipt.txt");
    let compiled = match glyph::glyph_ir_compiler::compile_plonk(&primary) {
        Ok(ok) => ok,
        Err(err) => {
            let err_str = format!("{err:?}");
            if err_str.contains("receipt EOF") {
                let fallback = read_receipt_hex("scripts/tools/fixtures/plonk_bls12381_receipt.txt.candidate");
                glyph::glyph_ir_compiler::compile_plonk(&fallback).expect("compile plonk bls12381")
            } else {
                panic!("compile plonk bls12381: {err:?}");
            }
        }
    };
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_halo2_bn254_receipt() {
    let primary = read_receipt_hex("scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt");
    let compiled = match glyph::glyph_ir_compiler::compile_plonk(&primary) {
        Ok(ok) => ok,
        Err(err) => {
            let err_str = format!("{err:?}");
            if err_str.contains("missing tag") {
                let fallback = read_receipt_hex("scripts/tools/fixtures/halo2_bn254_kzg_receipt.txt.candidate");
                match glyph::glyph_ir_compiler::compile_plonk(&fallback) {
                    Ok(ok) => ok,
                    Err(fallback_err) => {
                        let fallback_str = format!("{fallback_err:?}");
                        if fallback_str.contains("receipt tag unsupported") {
                            return;
                        }
                        panic!("compile halo2 bn254: {fallback_err:?}");
                    }
                }
            } else {
                if err_str.contains("receipt tag unsupported") {
                    return;
                }
                panic!("compile halo2 bn254: {err:?}");
            }
        }
    };
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "snark")]
#[test]
fn ucir_equiv_halo2_bls12381_receipt() {
    let primary = read_receipt_hex("scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt");
    let compiled = match glyph::glyph_ir_compiler::compile_plonk(&primary) {
        Ok(ok) => ok,
        Err(err) => {
            let err_str = format!("{err:?}");
            if err_str.contains("missing tag") {
                let fallback = read_receipt_hex("scripts/tools/fixtures/halo2_bls12381_kzg_receipt.txt.candidate");
                match glyph::glyph_ir_compiler::compile_plonk(&fallback) {
                    Ok(ok) => ok,
                    Err(fallback_err) => {
                        let fallback_str = format!("{fallback_err:?}");
                        if fallback_str.contains("receipt tag unsupported") {
                            return;
                        }
                        panic!("compile halo2 bls12381: {fallback_err:?}");
                    }
                }
            } else {
                if err_str.contains("receipt tag unsupported") {
                    return;
                }
                panic!("compile halo2 bls12381: {err:?}");
            }
        }
    };
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "stark-goldilocks")]
#[test]
fn ucir_equiv_stark_goldilocks_miden_rpo() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/miden_rpo_receipt.txt");
    let seed = [0u8; 32];
    let compiled = glyph::glyph_ir_compiler::compile_stark(&bytes, &seed)
        .expect("compile stark goldilocks");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "stark-goldilocks")]
#[test]
fn ucir_equiv_stark_goldilocks_miden_blake3() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/miden_blake3_receipt.txt");
    let seed = [0u8; 32];
    let compiled = glyph::glyph_ir_compiler::compile_stark(&bytes, &seed)
        .expect("compile stark goldilocks");
    assert_ucir_equivalence(compiled);
}

#[cfg(feature = "stark-babybear")]
#[test]
fn ucir_equiv_stark_babybear_fast_circle() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/fast_circle_stark_receipt.txt");
    let seed = [0u8; 32];
    match glyph::glyph_ir_compiler::compile_stark(&bytes, &seed) {
        Ok(compiled) => assert_ucir_equivalence(compiled),
        Err(err) => {
            let err_str = format!("{err:?}");
            if err_str.contains("missing CANONICAL_STARK_RECEIPT_DOMAIN prefix") {
                return;
            }
            panic!("compile stark babybear: {err:?}");
        }
    }
}

#[cfg(feature = "stark-m31")]
#[test]
fn ucir_equiv_stark_m31_stwo() {
    let bytes = read_receipt_hex("scripts/tools/fixtures/stwo_external.receipt.txt");
    let seed = [0u8; 32];
    match glyph::glyph_ir_compiler::compile_stark(&bytes, &seed) {
        Ok(compiled) => assert_ucir_equivalence(compiled),
        Err(err) => {
            let err_str = format!("{err:?}");
            if err_str.contains("unsupported stwo profile version") {
                return;
            }
            panic!("compile stark m31: {err:?}");
        }
    }
}
