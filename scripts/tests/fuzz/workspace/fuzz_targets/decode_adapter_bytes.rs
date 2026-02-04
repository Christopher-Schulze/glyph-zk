#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise adapter byte decoders with structurally valid encodings.
    // This hits domain-tag checks, version fields, length parsing, and reserved field rules.
    use glyph::adapters::*;

    let sel = data.get(0).copied().unwrap_or(0) % 7;

    let mut b0 = [0u8; 32];
    let mut b1 = [0u8; 32];
    if data.len() >= 65 {
        b0.copy_from_slice(&data[1..33]);
        b1.copy_from_slice(&data[33..65]);
    } else {
        b0[31] = data.get(1).copied().unwrap_or(0);
        b1[31] = data.get(2).copied().unwrap_or(0);
    }

    match sel {
        0 => {
            let bytes = groth16_bn254_vk_bytes(SNARK_GROTH16_BN254_ID, &b0, &b1);
            let _ = decode_groth16_bn254_vk_bytes(&bytes);
        }
        1 => {
            let beta = vec![data.get(3).copied().unwrap_or(0); (data.get(4).copied().unwrap_or(0) as usize).min(32)];
            let gamma = vec![data.get(5).copied().unwrap_or(0); (data.get(6).copied().unwrap_or(0) as usize).min(32)];
            let delta = vec![data.get(7).copied().unwrap_or(0); (data.get(8).copied().unwrap_or(0) as usize).min(32)];
            let bytes = groth16_bn254_vk_bytes_g2_precomp(SNARK_GROTH16_BN254_ID, &b0, &b1, &beta, &gamma, &delta);
            let _ = decode_groth16_bn254_vk_bytes(&bytes);
        }
        2 => {
            let beta = vec![data.get(3).copied().unwrap_or(0); (data.get(4).copied().unwrap_or(0) as usize).min(16)];
            let gamma = vec![data.get(5).copied().unwrap_or(0); (data.get(6).copied().unwrap_or(0) as usize).min(16)];
            let delta = vec![data.get(7).copied().unwrap_or(0); (data.get(8).copied().unwrap_or(0) as usize).min(16)];
            let ic_precomp: Vec<Groth16Bn254IcPrecomp> = Vec::new();
            let bytes = groth16_bn254_vk_bytes_full_precomp(SNARK_GROTH16_BN254_ID, &b0, &b1, &beta, &gamma, &delta, 4, &ic_precomp);
            let _ = decode_groth16_bn254_vk_bytes(&bytes);
        }
        3 => {
            let bytes = groth16_bn254_statement_bytes(&b0, &b1);
            let _ = decode_groth16_bn254_statement_bytes(&bytes);
        }
        4 => {
            let bytes = kzg_bn254_vk_bytes(SNARK_KZG_PLONK_ID, &b0, &b1, &b0);
            let _ = decode_kzg_bn254_vk_bytes(&bytes);
        }
        5 => {
            let g2 = vec![data.get(9).copied().unwrap_or(0); (data.get(10).copied().unwrap_or(0) as usize).min(64)];
            let bytes = kzg_bn254_vk_bytes_g2s_precomp(SNARK_KZG_PLONK_ID, &b0, &b1, &b0, &g2);
            let _ = decode_kzg_bn254_vk_bytes(&bytes);
        }
        _ => {
            let msg_len = data.get(11).copied().unwrap_or(0) as u32;
            let bytes = hash_vk_bytes(HASH_SHA3_256_ID, msg_len);
            let _ = bytes;
        }
    }
});
