#[cfg(feature = "stwo-prover")]
use glyph::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};
#[cfg(feature = "stwo-prover")]
use glyph::stwo_verifier::{
    synthesize_stwo_proof_bytes, verify_stwo_receipt, StwoConstraint, StwoExpr, StwoProfile,
    StwoProgram, HASH_BLAKE2S_ID, STWO_TOOLCHAIN_ID, VC_MERKLE_ID,
};

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_e2e() {
    let profile = StwoProfile {
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let proof_bytes = match synthesize_stwo_proof_bytes(&program, &profile, &[]) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "proof bytes");
            return;
        }
    };
    let vk = CanonicalStarkVk {
        version: 1,
        field_id: glyph::circle_stark::FIELD_M31_CIRCLE_ID,
        hash_id: HASH_BLAKE2S_ID,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes: Vec::new(),
        vk_bytes: vk.encode(),
    };
    let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "vk decode");
            return;
        }
    };
    if let Err(_) = verify_stwo_receipt(&receipt, &decoded_vk) {
        assert!(false, "verify");
    }
}

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_rejects_invalid_profile() {
    let profile = StwoProfile {
        log_domain_size: 2,
        num_queries: 0,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Const(1),
        }],
    };
    if synthesize_stwo_proof_bytes(&program, &profile, &[]).is_ok() {
        assert!(false, "synthesize should fail");
    }
}

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_verify_rejects_bad_vk() {
    let profile = StwoProfile {
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let proof_bytes = match synthesize_stwo_proof_bytes(&program, &profile, &[]) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "proof bytes");
            return;
        }
    };
    let mut vk = CanonicalStarkVk {
        version: 1,
        field_id: glyph::circle_stark::FIELD_M31_CIRCLE_ID,
        hash_id: HASH_BLAKE2S_ID,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    vk.hash_id ^= 0x01;
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes: Vec::new(),
        vk_bytes: vk.encode(),
    };
    let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "vk decode");
            return;
        }
    };
    if verify_stwo_receipt(&receipt, &decoded_vk).is_ok() {
        assert!(false, "verify should fail");
    }
}

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_rejects_program_profile_mismatch() {
    let profile = StwoProfile {
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let mut program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let proof_bytes = match synthesize_stwo_proof_bytes(&program, &profile, &[]) {
        Ok(value) => value,
        Err(err) => panic!("proof bytes: {err}"),
    };
    program.log_trace_length = program.log_trace_length.saturating_add(1);
    let vk = CanonicalStarkVk {
        version: 1,
        field_id: glyph::circle_stark::FIELD_M31_CIRCLE_ID,
        hash_id: HASH_BLAKE2S_ID,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes: Vec::new(),
        vk_bytes: vk.encode(),
    };
    let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "vk decode");
            return;
        }
    };
    if verify_stwo_receipt(&receipt, &decoded_vk).is_ok() {
        assert!(false, "verify should fail");
    }
}

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_rejects_bad_toolchain_id() {
    let profile = StwoProfile {
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let proof_bytes = match synthesize_stwo_proof_bytes(&program, &profile, &[]) {
        Ok(value) => value,
        Err(err) => panic!("proof bytes: {err}"),
    };
    let bad_program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID ^ 0x01,
        ..program
    };
    let vk = CanonicalStarkVk {
        version: 1,
        field_id: glyph::circle_stark::FIELD_M31_CIRCLE_ID,
        hash_id: HASH_BLAKE2S_ID,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: profile.encode(),
        program_bytes: bad_program.encode(),
    };
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes: Vec::new(),
        vk_bytes: vk.encode(),
    };
    if verify_stwo_receipt(&receipt, &vk).is_ok() {
        assert!(false, "verify should fail");
    }
}

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_rejects_bad_commitment_scheme() {
    let profile = StwoProfile {
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let proof_bytes = match synthesize_stwo_proof_bytes(&program, &profile, &[]) {
        Ok(value) => value,
        Err(err) => panic!("proof bytes: {err}"),
    };
    let vk = CanonicalStarkVk {
        version: 1,
        field_id: glyph::circle_stark::FIELD_M31_CIRCLE_ID,
        hash_id: HASH_BLAKE2S_ID,
        commitment_scheme_id: VC_MERKLE_ID ^ 0x01,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes: Vec::new(),
        vk_bytes: vk.encode(),
    };
    if verify_stwo_receipt(&receipt, &vk).is_ok() {
        assert!(false, "verify should fail");
    }
}

#[cfg(feature = "stwo-prover")]
#[test]
fn test_stwo_prover_rejects_tampered_proof() {
    let profile = StwoProfile {
        log_domain_size: 3,
        num_queries: 2,
        blowup_factor: 1,
        log_last_layer_degree_bound: 1,
        pow_bits: 0,
    };
    let program = StwoProgram {
        toolchain_id: STWO_TOOLCHAIN_ID,
        trace_width: 1,
        log_trace_length: profile.log_domain_size as u32,
        constraints: vec![StwoConstraint {
            expr: StwoExpr::Add(
                Box::new(StwoExpr::Col { col: 0, offset: 0 }),
                Box::new(StwoExpr::Neg(Box::new(StwoExpr::Col { col: 0, offset: 0 }))),
            ),
        }],
    };
    let mut proof_bytes = match synthesize_stwo_proof_bytes(&program, &profile, &[]) {
        Ok(value) => value,
        Err(err) => panic!("proof bytes: {err}"),
    };
    if let Some(last) = proof_bytes.last_mut() {
        *last ^= 0x5a;
    }
    let vk = CanonicalStarkVk {
        version: 1,
        field_id: glyph::circle_stark::FIELD_M31_CIRCLE_ID,
        hash_id: HASH_BLAKE2S_ID,
        commitment_scheme_id: VC_MERKLE_ID,
        consts_bytes: profile.encode(),
        program_bytes: program.encode(),
    };
    let receipt = CanonicalStarkReceipt {
        proof_bytes,
        pub_inputs_bytes: Vec::new(),
        vk_bytes: vk.encode(),
    };
    let decoded_vk = match CanonicalStarkReceipt::decode_and_validate_vk(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "vk decode");
            return;
        }
    };
    if verify_stwo_receipt(&receipt, &decoded_vk).is_ok() {
        assert!(false, "verify should fail");
    }
}
