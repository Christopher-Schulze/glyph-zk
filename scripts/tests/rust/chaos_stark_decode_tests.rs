//! Deterministic chaos tests for Stark receipt and VK decoding.

use glyph::stark_receipt::{
    CanonicalStarkReceipt, CanonicalStarkVk, CANONICAL_STARK_VK_DOMAIN,
};

fn sample_vk() -> CanonicalStarkVk {
    CanonicalStarkVk {
        version: 1,
        field_id: 0x01,
        hash_id: 0x02,
        commitment_scheme_id: 0x01,
        consts_bytes: vec![0xAA; 5],
        program_bytes: vec![0xBB; 7],
    }
}

fn sample_receipt() -> CanonicalStarkReceipt {
    let vk_bytes = sample_vk().encode();
    CanonicalStarkReceipt {
        proof_bytes: vec![1, 2, 3, 4, 5],
        pub_inputs_bytes: vec![9, 8, 7],
        vk_bytes,
    }
}

#[test]
fn receipt_decode_rejects_bad_tag() {
    let enc = sample_receipt().encode_for_hash();
    let mut tampered = enc.clone();
    tampered[0] ^= 0x01;
    assert!(CanonicalStarkReceipt::decode(&tampered).is_err());
}

#[test]
fn receipt_decode_rejects_trailing_data() {
    let mut enc = sample_receipt().encode_for_hash();
    enc.extend_from_slice(&[0, 1, 2, 3]);
    assert!(CanonicalStarkReceipt::decode(&enc).is_err());
}

#[test]
fn receipt_decode_rejects_truncation() {
    let enc = sample_receipt().encode_for_hash();
    for cut in 1..=8 {
        let truncated = &enc[..enc.len() - cut];
        assert!(CanonicalStarkReceipt::decode(truncated).is_err());
    }
}

#[test]
fn vk_decode_rejects_bad_tag() {
    let enc = sample_vk().encode();
    for i in 0..CANONICAL_STARK_VK_DOMAIN.len() {
        let mut tampered = enc.clone();
        tampered[i] ^= 0x01;
        assert!(CanonicalStarkVk::decode(&tampered).is_err());
    }
}

#[test]
fn vk_decode_rejects_truncation() {
    let enc = sample_vk().encode();
    for cut in 1..=8 {
        let truncated = &enc[..enc.len() - cut];
        assert!(CanonicalStarkVk::decode(truncated).is_err());
    }
}
