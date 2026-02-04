//! Property-based testing suite for GLYPH.
//!
//! This integration test runs deep randomized tests on core data structures and arithmetic.
//! Note: This is an integration test, not a binary.
//! Usage: cargo test --test prop_test_suite

use proptest::prelude::*;
use glyph::stark_receipt::{CanonicalStarkReceipt, CanonicalStarkVk};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn test_receipt_roundtrip(receipt in any_valid_receipt()) {
        let encoded = receipt.encode_for_hash();
        let decoded = glyph::stark_receipt::CanonicalStarkReceipt::decode(&encoded)
            .expect("canonical receipt valid decode");
        prop_assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_receipt_vk_roundtrip(receipt in any_valid_receipt()) {
        let encoded = receipt.encode_for_hash();
        let decoded = glyph::stark_receipt::CanonicalStarkReceipt::decode(&encoded)
            .expect("canonical receipt valid decode");
        let vk = glyph::stark_receipt::CanonicalStarkVk::decode(&decoded.vk_bytes)
            .expect("canonical vk decode");
        prop_assert_eq!(decoded.vk_bytes, vk.encode());
    }

    #[test]
    fn test_vk_roundtrip(vk in any_valid_vk()) {
        let encoded = vk.encode();
        let decoded = glyph::stark_receipt::CanonicalStarkVk::decode(&encoded)
            .expect("canonical vk decode");
        prop_assert_eq!(vk, decoded);
    }

    #[test]
    fn test_vk_tamper_rejects(vk in any_valid_vk()) {
        let mut encoded = vk.encode();
        prop_assume!(!encoded.is_empty());
        encoded[0] ^= 1;
        prop_assert!(glyph::stark_receipt::CanonicalStarkVk::decode(&encoded).is_err());
    }
}

// Strategies

prop_compose! {
    fn any_u8_vec()(size in 0..1024usize)(vec in proptest::collection::vec(any::<u8>(), size)) -> Vec<u8> {
        vec
    }
}

prop_compose! {
    fn any_valid_vk()(
        version in 1..2u16,
        field_id in 1..10u8,
        hash_id in 1..10u8,
        cs_id in 1..10u8,
        consts in any_u8_vec(),
        program in any_u8_vec()
    ) -> CanonicalStarkVk {
        CanonicalStarkVk {
            version,
            field_id,
            hash_id,
            commitment_scheme_id: cs_id,
            consts_bytes: consts,
            program_bytes: program,
        }
    }
}

prop_compose! {
    fn any_valid_receipt()(
        proof in any_u8_vec(),
        pub_inputs in any_u8_vec(),
        vk in any_valid_vk()
    ) -> CanonicalStarkReceipt {
        CanonicalStarkReceipt {
            proof_bytes: proof,
            pub_inputs_bytes: pub_inputs,
            vk_bytes: vk.encode(),
        }
    }
}
