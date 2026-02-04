use crate::adapters::{keccak256, keccak256_concat};

pub const L2_STATE_DOMAIN: &[u8] = b"GLYPH_L2_STATE";
pub const L2_COMMIT_DOMAIN: &[u8] = b"GLYPH_L2_COMMIT";
pub const L2_POINT_DOMAIN: &[u8] = b"GLYPH_L2_POINT";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2StatementTags {
    pub statement_hash: [u8; 32],
    pub commitment_tag: [u8; 32],
    pub point_tag: [u8; 32],
    pub artifact_tag: [u8; 32],
}

pub fn statement_hash_minimal(
    chainid: u64,
    contract_addr: [u8; 20],
    old_root: [u8; 32],
    new_root: [u8; 32],
    da_commitment: [u8; 32],
    batch_id: u64,
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        L2_STATE_DOMAIN.len() + 32 + 20 + 32 * 3 + 8,
    );
    buf.extend_from_slice(L2_STATE_DOMAIN);
    buf.extend_from_slice(&u64_to_u256_be(chainid));
    buf.extend_from_slice(&contract_addr);
    buf.extend_from_slice(&old_root);
    buf.extend_from_slice(&new_root);
    buf.extend_from_slice(&da_commitment);
    buf.extend_from_slice(&batch_id.to_be_bytes());
    keccak256(&buf)
}

#[allow(clippy::too_many_arguments)]
pub fn statement_hash_extended(
    chainid: u64,
    contract_addr: [u8; 20],
    old_root: [u8; 32],
    new_root: [u8; 32],
    da_commitment: [u8; 32],
    batch_id: u64,
    extra_commitment: [u8; 32],
    extra_schema_id: [u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        L2_STATE_DOMAIN.len() + 32 + 20 + 32 * 5 + 8,
    );
    buf.extend_from_slice(L2_STATE_DOMAIN);
    buf.extend_from_slice(&u64_to_u256_be(chainid));
    buf.extend_from_slice(&contract_addr);
    buf.extend_from_slice(&old_root);
    buf.extend_from_slice(&new_root);
    buf.extend_from_slice(&da_commitment);
    buf.extend_from_slice(&batch_id.to_be_bytes());
    buf.extend_from_slice(&extra_commitment);
    buf.extend_from_slice(&extra_schema_id);
    keccak256(&buf)
}

pub fn tags_for_statement(statement_hash: [u8; 32]) -> L2StatementTags {
    let commitment_tag = keccak256_concat(&[L2_COMMIT_DOMAIN, &statement_hash]);
    let point_tag = keccak256_concat(&[L2_POINT_DOMAIN, &commitment_tag]);
    let artifact_tag = keccak256_concat(&[&commitment_tag, &point_tag]);
    L2StatementTags {
        statement_hash,
        commitment_tag,
        point_tag,
        artifact_tag,
    }
}

pub fn claim_from_statement_hash(statement_hash: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&statement_hash[16..32]);
    out
}

fn u64_to_u256_be(x: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&x.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statement_hash_minimal_tags() {
        let chainid = 31337u64;
        let contract_addr = [0x11u8; 20];
        let old_root = [0x11u8; 32];
        let new_root = [0x22u8; 32];
        let da_commitment = [0x33u8; 32];
        let batch_id = 0u64;

        let statement_hash = statement_hash_minimal(
            chainid,
            contract_addr,
            old_root,
            new_root,
            da_commitment,
            batch_id,
        );
        let tags = tags_for_statement(statement_hash);
        let claim = claim_from_statement_hash(statement_hash);

        let expected_hash = hex_to_bytes32(
            "aa50bbae67af844553594565f5601dbed773c1832aa1fc9eafe7bcb489fae97a",
        );
        let expected_commitment = hex_to_bytes32(
            "aac53ea5d174acc44b836f45df0fc185c7b4c0191b1d82522d31da5dbfe38976",
        );
        let expected_point = hex_to_bytes32(
            "6803337352ef2419e31719f5a3c4e30a46b63c5ec414ef46b92714a196834571",
        );
        let expected_artifact = hex_to_bytes32(
            "fda7d45ee004235e731138ef2dcbedc0042ea4d273a2ff8431098afe8df7a1d5",
        );
        let expected_claim = hex_to_bytes32(
            "00000000000000000000000000000000d773c1832aa1fc9eafe7bcb489fae97a",
        );

        assert_eq!(statement_hash, expected_hash);
        assert_eq!(tags.commitment_tag, expected_commitment);
        assert_eq!(tags.point_tag, expected_point);
        assert_eq!(tags.artifact_tag, expected_artifact);
        assert_eq!(claim, expected_claim);
    }

    #[test]
    fn test_statement_hash_extended_tags() {
        let chainid = 31337u64;
        let contract_addr = [0x11u8; 20];
        let old_root = [0x11u8; 32];
        let new_root = [0x22u8; 32];
        let da_commitment = [0x33u8; 32];
        let batch_id = 0u64;
        let extra_commitment = [0x44u8; 32];
        let extra_schema_id = [0x55u8; 32];

        let statement_hash = statement_hash_extended(
            chainid,
            contract_addr,
            old_root,
            new_root,
            da_commitment,
            batch_id,
            extra_commitment,
            extra_schema_id,
        );
        let tags = tags_for_statement(statement_hash);
        let claim = claim_from_statement_hash(statement_hash);

        let expected_hash = hex_to_bytes32(
            "2d28367c9266f1de3f07543cbd1c6774f5bcab6e0e47cac846a824b02b65f699",
        );
        let expected_commitment = hex_to_bytes32(
            "7f68ff5e9ebb743ef6aa53a2b917d3234ac72ac4072f9427d0e35aa869883974",
        );
        let expected_point = hex_to_bytes32(
            "db2b28497be772affc86f6432ea6f25e60fedd4f08613d92b7e5433a9ad38708",
        );
        let expected_artifact = hex_to_bytes32(
            "a2921b9c85da87889bdb49147e44e906c868040679516f2d0820c2d87115fbfa",
        );
        let expected_claim = hex_to_bytes32(
            "00000000000000000000000000000000f5bcab6e0e47cac846a824b02b65f699",
        );

        assert_eq!(statement_hash, expected_hash);
        assert_eq!(tags.commitment_tag, expected_commitment);
        assert_eq!(tags.point_tag, expected_point);
        assert_eq!(tags.artifact_tag, expected_artifact);
        assert_eq!(claim, expected_claim);
    }

    fn hex_to_bytes32(hex_str: &str) -> [u8; 32] {
        let bytes = match hex::decode(hex_str) {
            Ok(bytes) => bytes,
            Err(_) => {
                assert!(false, "valid hex");
                return [0u8; 32];
            }
        };
        if bytes.len() != 32 {
            assert!(false, "bytes32 length mismatch");
            return [0u8; 32];
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}
