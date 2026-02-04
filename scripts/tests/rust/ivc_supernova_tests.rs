#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
use ark_bn254::Fr;
#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
use ark_ff::Field;
#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
use glyph::ivc_r1cs::{
    verify_relaxed_r1cs, R1csConstraint, R1csLinearCombination, R1csReceipt, R1csTerm,
};
#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
use glyph::ivc_supernova::{
    decode_supernova_external_proof_bytes, generate_supernova_external_proof_bytes,
    verify_supernova_external_proof_bytes, IVC_SUPERNOVA_EXTERNAL_DOMAIN,
    IVC_SUPERNOVA_EXTERNAL_VERSION,
};

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
fn sample_receipt() -> R1csReceipt {
    let one = Fr::ONE;
    let two = one + one;
    let constraint = R1csConstraint {
        a: R1csLinearCombination {
            terms: vec![
                R1csTerm { var_idx: 0, coeff: one },
                R1csTerm { var_idx: 1, coeff: one },
            ],
        },
        b: R1csLinearCombination {
            terms: vec![R1csTerm { var_idx: 2, coeff: one }],
        },
        c: R1csLinearCombination {
            terms: vec![R1csTerm { var_idx: 3, coeff: one }],
        },
    };
    R1csReceipt {
        num_vars: 4,
        num_constraints: 1,
        constraints: vec![constraint],
        witness: vec![one, two, two, six()],
        u: Fr::ONE,
        error: vec![Fr::ZERO],
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
fn six() -> Fr {
    let one = Fr::ONE;
    one + one + one + one + one + one
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_roundtrip() {
    let receipt = sample_receipt();
    if let Err(_) = verify_relaxed_r1cs(&receipt) {
        assert!(false, "r1cs verify");
        return;
    }
    let bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    let decoded = match decode_supernova_external_proof_bytes(&bytes) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "decode");
            return;
        }
    };
    assert!(!decoded.recursive_snark_bytes.is_empty());
    if let Err(_) = verify_supernova_external_proof_bytes(&receipt, &bytes) {
        assert!(false, "verify");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_rejects_bad_tag() {
    let receipt = sample_receipt();
    let bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    let mut bad = bytes.clone();
    if let Some(first) = bad.first_mut() {
        *first ^= 0x01;
    }
    if decode_supernova_external_proof_bytes(&bad).is_ok() {
        assert!(false, "decode should fail");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_rejects_bad_version() {
    let receipt = sample_receipt();
    let bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    let mut bad = bytes.clone();
    let tag_len = IVC_SUPERNOVA_EXTERNAL_DOMAIN.len();
    if bad.len() < tag_len + 2 {
        assert!(false, "bytes too short");
        return;
    }
    let bad_version = IVC_SUPERNOVA_EXTERNAL_VERSION.wrapping_add(1);
    bad[tag_len..tag_len + 2].copy_from_slice(&bad_version.to_be_bytes());
    if decode_supernova_external_proof_bytes(&bad).is_ok() {
        assert!(false, "decode should fail");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_rejects_trailing_data() {
    let receipt = sample_receipt();
    let mut bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    bytes.push(0u8);
    if decode_supernova_external_proof_bytes(&bytes).is_ok() {
        assert!(false, "decode should fail");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_verify_rejects_tamper() {
    let receipt = sample_receipt();
    let bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    let mut bad = bytes.clone();
    if let Some(last) = bad.last_mut() {
        *last ^= 0x5a;
    }
    if verify_supernova_external_proof_bytes(&receipt, &bad).is_ok() {
        assert!(false, "verify should fail");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_rejects_bad_length_header() {
    let receipt = sample_receipt();
    let bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    let mut bad = bytes.clone();
    let tag_len = IVC_SUPERNOVA_EXTERNAL_DOMAIN.len();
    if bad.len() < tag_len + 2 + 4 {
        assert!(false, "bytes too short");
        return;
    }
    let len_off = tag_len + 2;
    let declared = u32::from_be_bytes([
        bad[len_off],
        bad[len_off + 1],
        bad[len_off + 2],
        bad[len_off + 3],
    ]);
    let bumped = declared.saturating_add(1);
    bad[len_off..len_off + 4].copy_from_slice(&bumped.to_be_bytes());
    if decode_supernova_external_proof_bytes(&bad).is_ok() {
        assert!(false, "decode should fail");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_verify_rejects_mismatched_receipt() {
    let receipt = sample_receipt();
    let bytes = match generate_supernova_external_proof_bytes(&receipt) {
        Ok(value) => value,
        Err(_) => {
            assert!(false, "generate");
            return;
        }
    };
    let mut bad_receipt = receipt.clone();
    if let Some(w) = bad_receipt.witness.get_mut(1) {
        *w += Fr::ONE;
    }
    if verify_supernova_external_proof_bytes(&bad_receipt, &bytes).is_ok() {
        assert!(false, "verify should fail");
    }
}

#[cfg(all(feature = "ivc", feature = "ivc-supernova"))]
#[test]
fn test_supernova_external_proof_generate_rejects_invalid_receipt() {
    let mut receipt = sample_receipt();
    receipt.num_constraints = receipt.num_constraints.saturating_add(1);
    if generate_supernova_external_proof_bytes(&receipt).is_ok() {
        assert!(false, "generate should fail");
    }
}
