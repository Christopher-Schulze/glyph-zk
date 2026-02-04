//! Canonical STARK adapter entrypoint (GLYPH path).
//!
//! Verifies canonical STARK receipts natively and derives the GLYPH artifact tags
//! via BaseFold hashing without legacy kernels.

use binius_field::{BinaryField128b, underlier::WithUnderlier};
use rayon::prelude::*;
use crate::stark_program::WinterfellStarkProgram;
use crate::stark_receipt::CanonicalStarkReceipt;
use crate::glyph_basefold::{
    fold_instance_evals_to_folded_oracle_eval,
    derive_glyph_artifact_from_folded_oracle_eval,
};

pub fn verified_canonical_stark_receipts_to_glyph_artifact(
    seed: &[u8],
    receipts: &[CanonicalStarkReceipt],
) -> Result<([u8; 32], [u8; 32], u128), String> {
    if receipts.is_empty() {
        return Err("need at least one canonical receipt".to_string());
    }
    if receipts.len() > 64 {
        return Err("max 64 receipts for folding".to_string());
    }

    let prepare_receipt = |idx: usize, receipt: &CanonicalStarkReceipt| -> Result<([u8; 32], BinaryField128b), String> {
        let vk = CanonicalStarkReceipt::decode_and_validate_vk(receipt)
            .map_err(|e| format!("receipt[{idx}] vk decode failed: {e}"))?;
        match vk.field_id {
            crate::stark_winterfell::FIELD_F128_ID => {
                let program = WinterfellStarkProgram::decode(&vk.program_bytes)
                    .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                if program.impl_id != *crate::stark_winterfell::WINTERFELL_IMPL_ID {
                    return Err(format!("receipt[{idx}] unsupported program impl_id"));
                }
                let is_do_work = program.air_id.as_slice() == crate::stark_winterfell::DO_WORK_AIR_ID;
                let is_fibonacci = program.air_id.as_slice() == crate::stark_winterfell::FIB_AIR_ID;
                let is_tribonacci = program.air_id.as_slice() == crate::stark_winterfell::TRIB_AIR_ID;
                if !is_do_work && !is_fibonacci && !is_tribonacci {
                    return Err(format!("receipt[{idx}] unsupported air_id"));
                }
                if vk.commitment_scheme_id != crate::stark_winterfell::VC_MERKLE_ID {
                    return Err(format!("receipt[{idx}] unsupported commitment_scheme_id"));
                }
                match vk.hash_id {
                    crate::stark_winterfell::HASH_SHA3_ID => {
                        if is_do_work {
                            crate::stark_winterfell::verify_do_work_sha3_from_bytes(
                                &receipt.proof_bytes,
                                &receipt.pub_inputs_bytes,
                            )
                            .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e}"))?;
                        } else if is_tribonacci {
                            crate::stark_winterfell::verify_tribonacci_sha3_from_bytes(
                                &receipt.proof_bytes,
                                &receipt.pub_inputs_bytes,
                            )
                            .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e}"))?;
                        } else {
                            crate::stark_winterfell::verify_fibonacci_sha3_from_bytes(
                                &receipt.proof_bytes,
                                &receipt.pub_inputs_bytes,
                            )
                            .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e}"))?;
                        }
                    }
                    crate::stark_winterfell::HASH_BLAKE3_ID => {
                        if is_do_work {
                            crate::stark_winterfell::verify_do_work_from_bytes(
                                &receipt.proof_bytes,
                                &receipt.pub_inputs_bytes,
                            )
                            .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e}"))?;
                        } else if is_tribonacci {
                            crate::stark_winterfell::verify_tribonacci_from_bytes(
                                &receipt.proof_bytes,
                                &receipt.pub_inputs_bytes,
                            )
                            .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e}"))?;
                        } else {
                            crate::stark_winterfell::verify_fibonacci_from_bytes(
                                &receipt.proof_bytes,
                                &receipt.pub_inputs_bytes,
                            )
                            .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e}"))?;
                        }
                    }
                    _ => {
                        return Err(format!("receipt[{idx}] unsupported hash_id"));
                    }
                }
            }
            crate::stark_winterfell_f64::FIELD_F64_ID => {
                let program = WinterfellStarkProgram::decode(&vk.program_bytes)
                    .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                if program.impl_id != *crate::stark_winterfell::WINTERFELL_IMPL_ID {
                    return Err(format!("receipt[{idx}] unsupported program impl_id"));
                }
                let is_do_work = program.air_id.as_slice() == crate::stark_winterfell::DO_WORK_AIR_ID;
                let is_fibonacci = program.air_id.as_slice() == crate::stark_winterfell::FIB_AIR_ID;
                let is_tribonacci = program.air_id.as_slice() == crate::stark_winterfell::TRIB_AIR_ID;
                if !is_do_work && !is_fibonacci && !is_tribonacci {
                    return Err(format!("receipt[{idx}] unsupported air_id"));
                }
                if vk.commitment_scheme_id != crate::stark_winterfell::VC_MERKLE_ID {
                    return Err(format!("receipt[{idx}] unsupported commitment_scheme_id"));
                }
                let proof = winterfell::Proof::from_bytes(&receipt.proof_bytes)
                    .map_err(|e| format!("receipt[{idx}] proof deserialization failed: {e:?}"))?;
                if is_do_work {
                    let pub_inputs = crate::stark_winterfell_f64::do_work_public_inputs_from_bytes(
                        &receipt.pub_inputs_bytes,
                    )
                    .ok_or_else(|| format!("receipt[{idx}] public inputs must be 16 bytes (start||result)"))?;
                    match vk.hash_id {
                        crate::stark_winterfell_f64::HASH_SHA3_ID => {
                            crate::stark_winterfell_f64::verify_do_work_sha3(proof, pub_inputs)
                                .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e:?}"))?;
                        }
                        crate::stark_winterfell_f64::HASH_BLAKE3_ID => {
                            crate::stark_winterfell_f64::verify_do_work_blake3(proof, pub_inputs)
                                .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e:?}"))?;
                        }
                        _ => {
                            return Err(format!("receipt[{idx}] unsupported hash_id"));
                        }
                    }
                } else if is_tribonacci {
                    let pub_inputs = crate::stark_winterfell_f64::tribonacci_public_inputs_from_bytes(
                        &receipt.pub_inputs_bytes,
                    )
                    .ok_or_else(|| format!("receipt[{idx}] public inputs must be 32 bytes (a||b||c||result)"))?;
                    match vk.hash_id {
                        crate::stark_winterfell_f64::HASH_SHA3_ID => {
                            crate::stark_winterfell_f64::verify_tribonacci_sha3(proof, pub_inputs)
                                .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e:?}"))?;
                        }
                        crate::stark_winterfell_f64::HASH_BLAKE3_ID => {
                            crate::stark_winterfell_f64::verify_tribonacci_blake3(proof, pub_inputs)
                                .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e:?}"))?;
                        }
                        _ => {
                            return Err(format!("receipt[{idx}] unsupported hash_id"));
                        }
                    }
                } else {
                    let pub_inputs = crate::stark_winterfell_f64::fibonacci_public_inputs_from_bytes(
                        &receipt.pub_inputs_bytes,
                    )
                    .ok_or_else(|| format!("receipt[{idx}] public inputs must be 24 bytes (a||b||result)"))?;
                    match vk.hash_id {
                        crate::stark_winterfell_f64::HASH_SHA3_ID => {
                            crate::stark_winterfell_f64::verify_fibonacci_sha3(proof, pub_inputs)
                                .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e:?}"))?;
                        }
                        crate::stark_winterfell_f64::HASH_BLAKE3_ID => {
                            crate::stark_winterfell_f64::verify_fibonacci_blake3(proof, pub_inputs)
                                .map_err(|e| format!("receipt[{idx}] winterfell verify failed: {e:?}"))?;
                        }
                        _ => {
                            return Err(format!("receipt[{idx}] unsupported hash_id"));
                        }
                    }
                }
            }
            #[cfg(any(feature = "stark-babybear", feature = "stark-goldilocks", feature = "stark-m31"))]
            crate::cairo_stark::FIELD_CAIRO_PRIME_ID => {
                let program = crate::cairo_stark::decode_cairo_program(&vk.program_bytes)
                    .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                crate::cairo_stark::verify_cairo_receipt(receipt, &vk, &program)
                    .map_err(|e| format!("receipt[{idx}] cairo verify failed: {e}"))?;
            }
            crate::miden_stark::FIELD_MIDEN_GOLDILOCKS_ID => {
                let program = crate::miden_stark::decode_miden_program(&vk.program_bytes)
                    .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                crate::miden_stark::verify_miden_receipt(receipt, &vk, &program)
                    .map_err(|e| format!("receipt[{idx}] miden verify failed: {e}"))?;
            }
            crate::plonky3_stark::FIELD_P3_M31_ID
            | crate::plonky3_stark::FIELD_P3_BABY_BEAR_ID
            | crate::plonky3_stark::FIELD_P3_KOALA_BEAR_ID
            | crate::plonky3_stark::FIELD_P3_GOLDILOCKS_ID => {
                let program = crate::plonky3_stark::decode_plonky3_program(&vk.program_bytes)
                    .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                crate::plonky3_stark::verify_plonky3_receipt(receipt, &vk, &program)
                    .map_err(|e| format!("receipt[{idx}] plonky3 verify failed: {e}"))?;
            }
            crate::plonky2_receipt::FIELD_GOLDILOCKS_ID => {
                if receipt.proof_bytes.is_empty() {
                    return Err(format!("receipt[{idx}] plonky2 proof is empty"));
                }
                if receipt.pub_inputs_bytes.is_empty() {
                    return Err(format!("receipt[{idx}] plonky2 pub_inputs is empty"));
                }
                if vk.program_bytes.is_empty() {
                    return Err(format!("receipt[{idx}] plonky2 program is empty"));
                }
                if vk.commitment_scheme_id != crate::plonky2_receipt::VC_MERKLE_ID {
                    return Err(format!(
                        "receipt[{idx}] unsupported commitment_scheme_id"
                    ));
                }
                if vk.hash_id != crate::plonky2_receipt::HASH_SHA3_ID {
                    return Err(format!("receipt[{idx}] unsupported hash_id"));
                }
                let pub_inputs = crate::plonky2_receipt::decode_plonky2_pub_inputs(
                    &receipt.pub_inputs_bytes,
                )
                .map_err(|e| format!("receipt[{idx}] plonky2 pub_inputs decode failed: {e}"))?;
                crate::plonky2_receipt::verify_plonky2_proof_native(
                    &vk.program_bytes,
                    &receipt.proof_bytes,
                    &pub_inputs,
                )
                .map_err(|e| format!("receipt[{idx}] plonky2 verify failed: {e}"))?;
            }
            crate::standard_stark::FIELD_BABY_BEAR_STD_ID => {
                let program = crate::standard_stark::decode_standard_stark_program(
                    &vk.program_bytes,
                )
                .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                crate::standard_stark::verify_standard_stark_receipt(receipt, &vk, &program)
                    .map_err(|e| format!("receipt[{idx}] standard verify failed: {e}"))?;
            }
            crate::circle_stark::FIELD_M31_CIRCLE_ID
            | crate::circle_stark::FIELD_BABY_BEAR_CIRCLE_ID
            | crate::circle_stark::FIELD_KOALA_BEAR_CIRCLE_ID => {
                if vk.field_id == crate::circle_stark::FIELD_M31_CIRCLE_ID
                    && crate::stwo_verifier::is_stwo_program_bytes(&vk.program_bytes)
                {
                    crate::stwo_verifier::verify_stwo_receipt(receipt, &vk)
                        .map_err(|e| format!("receipt[{idx}] stwo verify failed: {e}"))?;
                } else {
                    let program = crate::circle_stark::decode_circle_stark_program(&vk.program_bytes)
                        .map_err(|e| format!("receipt[{idx}] program decode failed: {e}"))?;
                    crate::circle_stark::verify_circle_stark_receipt(receipt, &vk, &program)
                        .map_err(|e| format!("receipt[{idx}] circle verify failed: {e}"))?;
                }
            }
            other => {
                return Err(format!("receipt[{idx}] unsupported field_id=0x{other:02x}"));
            }
        }

        let digest = receipt.digest();
        let mut claim_bytes = [0u8; 16];
        claim_bytes.copy_from_slice(&digest[0..16]);
        let claim = BinaryField128b::from_underlier(u128::from_le_bytes(claim_bytes));
        Ok((digest, claim))
    };

    let pairs = if receipts.len() >= 4 {
        receipts
            .par_iter()
            .enumerate()
            .map(|(idx, receipt)| prepare_receipt(idx, receipt))
            .collect::<Result<Vec<_>, String>>()?
    } else {
        receipts
            .iter()
            .enumerate()
            .map(|(idx, receipt)| prepare_receipt(idx, receipt))
            .collect::<Result<Vec<_>, String>>()?
    };

    let mut instance_digests = Vec::with_capacity(pairs.len());
    let mut per_instance_claims = Vec::with_capacity(pairs.len());
    for (digest, claim) in pairs {
        instance_digests.push(digest);
        per_instance_claims.push(claim);
    }

    crate::adapters::apply_stark_profile_defaults();
    let folded = fold_instance_evals_to_folded_oracle_eval(
        seed,
        0,
        4,
        instance_digests,
        per_instance_claims,
    )?;
    derive_glyph_artifact_from_folded_oracle_eval(&folded)
}

pub fn prove_canonical_stark_receipt_with_glyph(
    seed: &[u8],
    receipt_bytes: &[u8],
) -> Result<crate::glyph_core::UniversalProof, String> {
    let compiled = crate::glyph_ir_compiler::compile_stark(receipt_bytes, seed)
        .map_err(|e| format!("stark compile failed: {e:?}"))?;
    let config = crate::glyph_core::ProverConfig::default();
    crate::glyph_core::prove_compiled(compiled, config)
        .map_err(|e| format!("glyph-prover failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verified_canonical_stark_receipt_roundtrip() {
        let seed = b"glyph-stark-adapter-test";
        let trace_length = 256usize;
        let receipts =
            match crate::stark_winterfell::seeded_do_work_receipts_sha3(seed, trace_length, 1) {
                Ok(receipts) => receipts,
                Err(err) => {
                    assert!(false, "receipts: {err}");
                    return;
                }
            };
        let cr = match crate::stark_winterfell::canonical_stark_receipt_from_upstream_do_work(&receipts[0]) {
            Ok(cr) => cr,
            Err(err) => {
                assert!(false, "receipt: {err}");
                return;
            }
        };
        let res = match verified_canonical_stark_receipts_to_glyph_artifact(seed, &[cr]) {
            Ok(res) => res,
            Err(err) => {
                assert!(false, "artifact: {err}");
                return;
            }
        };
        assert_ne!(res.0, [0u8; 32]);
        assert_ne!(res.1, [0u8; 32]);
        assert_ne!(res.2, 0u128);
    }

    #[test]
    fn test_verified_canonical_stark_receipt_roundtrip_blake3() {
        let seed = b"glyph-stark-adapter-test-blake3";
        let trace_length = 256usize;
        let receipts =
            match crate::stark_winterfell::seeded_do_work_receipts(seed, trace_length, 1) {
                Ok(receipts) => receipts,
                Err(err) => {
                    assert!(false, "receipts: {err}");
                    return;
                }
            };
        let cr = match crate::stark_winterfell::canonical_stark_receipt_from_upstream_do_work(&receipts[0]) {
            Ok(cr) => cr,
            Err(err) => {
                assert!(false, "receipt: {err}");
                return;
            }
        };
        let res = match verified_canonical_stark_receipts_to_glyph_artifact(seed, &[cr]) {
            Ok(res) => res,
            Err(err) => {
                assert!(false, "artifact: {err}");
                return;
            }
        };
        assert_ne!(res.0, [0u8; 32]);
        assert_ne!(res.1, [0u8; 32]);
        assert_ne!(res.2, 0u128);
    }

    #[test]
    fn test_verified_canonical_stark_receipt_roundtrip_fibonacci_sha3() {
        let seed = b"glyph-stark-adapter-fib-sha3";
        let trace_length = 128usize;
        let receipts =
            match crate::stark_winterfell::seeded_fibonacci_receipts_sha3(seed, trace_length, 1) {
                Ok(receipts) => receipts,
                Err(err) => {
                    assert!(false, "receipts: {err}");
                    return;
                }
            };
        let cr = match crate::stark_winterfell::canonical_stark_receipt_from_upstream_fibonacci(&receipts[0]) {
            Ok(cr) => cr,
            Err(err) => {
                assert!(false, "receipt: {err}");
                return;
            }
        };
        let res = match verified_canonical_stark_receipts_to_glyph_artifact(seed, &[cr]) {
            Ok(res) => res,
            Err(err) => {
                assert!(false, "artifact: {err}");
                return;
            }
        };
        assert_ne!(res.0, [0u8; 32]);
        assert_ne!(res.1, [0u8; 32]);
        assert_ne!(res.2, 0u128);
    }

    #[test]
    fn test_verified_canonical_stark_receipt_roundtrip_fibonacci_blake3_f64() {
        let seed = b"glyph-stark-adapter-fib-blake3-f64";
        let trace_length = 64usize;
        let receipts = match crate::stark_winterfell_f64::seeded_fibonacci_receipts_blake3(
            seed,
            trace_length,
            1,
        ) {
            Ok(receipts) => receipts,
            Err(err) => {
                assert!(false, "receipts: {err}");
                return;
            }
        };
        let cr = match crate::stark_winterfell_f64::canonical_stark_receipt_from_upstream_fibonacci(&receipts[0]) {
            Ok(cr) => cr,
            Err(err) => {
                assert!(false, "receipt: {err}");
                return;
            }
        };
        let res = match verified_canonical_stark_receipts_to_glyph_artifact(seed, &[cr]) {
            Ok(res) => res,
            Err(err) => {
                assert!(false, "artifact: {err}");
                return;
            }
        };
        assert_ne!(res.0, [0u8; 32]);
        assert_ne!(res.1, [0u8; 32]);
        assert_ne!(res.2, 0u128);
    }
}
