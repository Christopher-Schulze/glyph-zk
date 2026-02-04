use glyph::glyph_field_simd::{Goldilocks, GOLDILOCKS_MODULUS};
use glyph::glyph_transcript::{Transcript, DOMAIN_SUMCHECK};
use proptest::prelude::*;

proptest! {
    #[test]
    fn transcript_challenge_within_field(seed in any::<[u8; 32]>()) {
        let mut t = Transcript::with_label(&seed);
        for i in 0..8u64 {
            t.absorb_goldilocks(DOMAIN_SUMCHECK, Goldilocks(i));
        }
        let c = t.challenge_goldilocks().0;
        prop_assert!(c < GOLDILOCKS_MODULUS);
    }
}
