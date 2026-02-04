#![no_main]
use libfuzzer_sys::fuzz_target;

use glyph::glyph_field_simd::Goldilocks;
use glyph::glyph_transcript::{
    Transcript, DOMAIN_ARTIFACT, DOMAIN_LOOKUP, DOMAIN_PCS, DOMAIN_SUMCHECK, DOMAIN_UCIR,
};

fuzz_target!(|data: &[u8]| {
    let mut t = Transcript::new();
    let mut i = 0usize;
    while i < data.len() {
        let tag = data[i] % 6;
        i = i.saturating_add(1);
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        i = i.saturating_add(1);
        let end = (i + len).min(data.len());
        let chunk = &data[i..end];
        i = end;
        match tag {
            0 => t.absorb(DOMAIN_UCIR, chunk),
            1 => t.absorb(DOMAIN_LOOKUP, chunk),
            2 => t.absorb(DOMAIN_PCS, chunk),
            3 => {
                if chunk.len() >= 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&chunk[..8]);
                    t.absorb_goldilocks(DOMAIN_SUMCHECK, Goldilocks(u64::from_le_bytes(bytes)));
                } else {
                    t.absorb(DOMAIN_SUMCHECK, chunk);
                }
            }
            4 => {
                if chunk.len() >= 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&chunk[..32]);
                    t.absorb_bytes32(DOMAIN_ARTIFACT, &bytes);
                } else {
                    t.absorb(DOMAIN_ARTIFACT, chunk);
                }
            }
            _ => t.absorb(DOMAIN_UCIR, chunk),
        }
    }

    let _ = t.challenge_goldilocks();
    let _ = t.challenge_goldilocks_n((data.len() % 8) as usize);
    let _ = t.challenge_usize((data.len() % 64) as usize);
});
