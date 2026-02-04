//! Property-based tests for BN254 emulation.
//!
//! Usage: cargo test --test bn254_emulation_property_tests

use ark_bn254::Fq;
use ark_ff::{One, UniformRand, Zero};
use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

use glyph::bn254_field::{
    bn254_add_mod,
    bn254_inv_mod,
    bn254_mul_mod,
    bn254_sub_mod,
    fq_from_limbs,
    is_canonical_limbs,
    limbs_from_fq,
    BN254_FQ_MODULUS_LIMBS,
};

prop_compose! {
    fn any_fq()(seed in any::<u64>()) -> Fq {
        let mut rng = StdRng::seed_from_u64(seed);
        Fq::rand(&mut rng)
    }
}

prop_compose! {
    fn any_fq_pair()(seed_a in any::<u64>(), seed_b in any::<u64>()) -> (Fq, Fq) {
        let mut rng_a = StdRng::seed_from_u64(seed_a);
        let mut rng_b = StdRng::seed_from_u64(seed_b);
        (Fq::rand(&mut rng_a), Fq::rand(&mut rng_b))
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn bn254_add_matches_ark((a, b) in any_fq_pair()) {
        let a_limbs = limbs_from_fq(a);
        let b_limbs = limbs_from_fq(b);
        prop_assert!(is_canonical_limbs(a_limbs));
        prop_assert!(is_canonical_limbs(b_limbs));
        let out = bn254_add_mod(a_limbs, b_limbs).expect("add");
        let expected = limbs_from_fq(a + b);
        prop_assert_eq!(out, expected);
    }

    #[test]
    fn bn254_sub_matches_ark((a, b) in any_fq_pair()) {
        let a_limbs = limbs_from_fq(a);
        let b_limbs = limbs_from_fq(b);
        let out = bn254_sub_mod(a_limbs, b_limbs).expect("sub");
        let expected = limbs_from_fq(a - b);
        prop_assert_eq!(out, expected);
    }

    #[test]
    fn bn254_mul_matches_ark((a, b) in any_fq_pair()) {
        let a_limbs = limbs_from_fq(a);
        let b_limbs = limbs_from_fq(b);
        let out = bn254_mul_mod(a_limbs, b_limbs).expect("mul");
        let expected = limbs_from_fq(a * b);
        prop_assert_eq!(out, expected);
    }

    #[test]
    fn bn254_inv_roundtrip(a in any_fq()) {
        prop_assume!(!a.is_zero());
        let a_limbs = limbs_from_fq(a);
        let inv = bn254_inv_mod(a_limbs).expect("inv");
        let prod = bn254_mul_mod(a_limbs, inv).expect("mul");
        let one = limbs_from_fq(Fq::one());
        prop_assert_eq!(prod, one);
    }
}

#[test]
fn bn254_non_canonical_rejected() {
    assert!(!is_canonical_limbs(BN254_FQ_MODULUS_LIMBS));
    assert!(bn254_add_mod(BN254_FQ_MODULUS_LIMBS, [0u64; 4]).is_none());
    assert!(bn254_sub_mod(BN254_FQ_MODULUS_LIMBS, [0u64; 4]).is_none());
    assert!(bn254_mul_mod(BN254_FQ_MODULUS_LIMBS, [0u64; 4]).is_none());
    assert!(bn254_inv_mod(BN254_FQ_MODULUS_LIMBS).is_none());
    assert!(bn254_inv_mod([0u64; 4]).is_none());
    assert!(fq_from_limbs(BN254_FQ_MODULUS_LIMBS).is_none());
}
