use std::collections::HashSet;

#[test]
fn transcript_domain_tags_unique_and_non_empty() {
    let tags: &[&[u8]] = &[
        glyph::glyph_transcript::DOMAIN_UCIR,
        glyph::glyph_transcript::DOMAIN_LOOKUP,
        glyph::glyph_transcript::DOMAIN_SUMCHECK,
        glyph::glyph_transcript::DOMAIN_SUMCHECK_MIX,
        glyph::glyph_transcript::DOMAIN_PCS,
        glyph::glyph_transcript::DOMAIN_PCS_BASEFOLD_COMMIT,
        glyph::glyph_transcript::DOMAIN_PCS_BASEFOLD_OPEN,
        glyph::glyph_transcript::DOMAIN_PCS_RING_SWITCH,
        glyph::glyph_transcript::DOMAIN_PCS_ZK_MASK,
        glyph::glyph_transcript::DOMAIN_ARTIFACT,
    ];

    let mut set = HashSet::new();
    for tag in tags {
        assert!(!tag.is_empty(), "domain tag must not be empty");
        assert!(set.insert(tag), "domain tag duplicate: {:?}", std::str::from_utf8(tag).ok());
    }
}
