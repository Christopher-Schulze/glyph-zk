use glyph::da::{
    extract_artifact_tag, hex_0x, keccak256, DaCommitment, DaEnvelope, DaPayload, DaPayloadParts,
    DaProfile, PayloadMode,
};

#[test]
fn test_da_payload_roundtrip() {
    let payload = DaPayload {
        version: 1,
        parts: DaPayloadParts {
            artifact_bytes: vec![1u8; 96],
            upstream_proof_bytes: Some(vec![2u8; 4]),
            vk_bytes: Some(vec![3u8; 8]),
        },
    };
    let encoded = payload.encode();
    let decoded = DaPayload::decode(&encoded).expect("decode");
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.parts.artifact_bytes.len(), 96);
    assert_eq!(
        decoded
            .parts
            .upstream_proof_bytes
            .expect("upstream proof bytes")
            .len(),
        4
    );
    assert_eq!(
        decoded.parts.vk_bytes.expect("vk bytes").len(),
        8
    );
}

#[test]
fn test_da_envelope_hash_stable() {
    let artifact = vec![0u8; 96];
    let tag = extract_artifact_tag(&artifact).expect("tag");
    let payload = DaPayload {
        version: 1,
        parts: DaPayloadParts {
            artifact_bytes: artifact,
            upstream_proof_bytes: None,
            vk_bytes: None,
        },
    };
    let payload_hash = hex_0x(&keccak256(&payload.encode()));

    let mut envelope = DaEnvelope {
        version: 1,
        profile_id: DaProfile::VerifierOnly.as_str().to_string(),
        payload_mode: PayloadMode::Minimal.as_str().to_string(),
        created_at_utc: "2026-01-19T00:00:00Z".to_string(),
        artifact_tag: hex_0x(&tag),
        artifact_bytes_hash: hex_0x(&keccak256(&payload.parts.artifact_bytes)),
        payload_hash,
        upstream_proof_hash: None,
        vk_hash: None,
        chain_id: None,
        verifier_address: None,
        commitments: Vec::new(),
        meta: Default::default(),
        envelope_hash: None,
    };

    let h1 = envelope.compute_envelope_hash().expect("hash");
    envelope.envelope_hash = Some(h1.clone());
    let h2 = envelope.compute_envelope_hash().expect("hash");
    assert_eq!(h1, h2);
}

#[test]
fn test_da_envelope_eigenda_pending_roundtrip() {
    let envelope = DaEnvelope {
        version: 1,
        profile_id: DaProfile::BlobEigenDaArweave.as_str().to_string(),
        payload_mode: PayloadMode::Minimal.as_str().to_string(),
        created_at_utc: "2026-01-19T00:00:00Z".to_string(),
        artifact_tag: "0x00".to_string(),
        artifact_bytes_hash: "0x01".to_string(),
        payload_hash: "0x02".to_string(),
        upstream_proof_hash: None,
        vk_hash: None,
        chain_id: None,
        verifier_address: None,
        commitments: vec![DaCommitment::EigenDa {
            blob_key: None,
            certificate_hash: None,
            request_id: Some("0xdeadbeef".to_string()),
            status: Some("pending".to_string()),
            disperser_url: Some("disperser-testnet-sepolia.eigenda.xyz:443".to_string()),
        }],
        meta: Default::default(),
        envelope_hash: None,
    };

    let json = serde_json::to_string(&envelope).expect("serialize");
    let parsed: DaEnvelope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.commitments.len(), 1);
    match &parsed.commitments[0] {
        DaCommitment::EigenDa { request_id, status, .. } => {
            assert_eq!(request_id.as_deref(), Some("0xdeadbeef"));
            assert_eq!(status.as_deref(), Some("pending"));
        }
        _ => panic!("unexpected commitment"),
    }
}

#[test]
fn test_da_envelope_eigenda_v2_blobkey_roundtrip() {
    let envelope = DaEnvelope {
        version: 1,
        profile_id: DaProfile::BlobEigenDaArweave.as_str().to_string(),
        payload_mode: PayloadMode::Minimal.as_str().to_string(),
        created_at_utc: "2026-01-19T00:00:00Z".to_string(),
        artifact_tag: "0x00".to_string(),
        artifact_bytes_hash: "0x01".to_string(),
        payload_hash: "0x02".to_string(),
        upstream_proof_hash: None,
        vk_hash: None,
        chain_id: None,
        verifier_address: None,
        commitments: vec![DaCommitment::EigenDa {
            blob_key: Some("0xabc123:0".to_string()),
            certificate_hash: None,
            request_id: None,
            status: Some("complete".to_string()),
            disperser_url: Some("disperser-testnet-sepolia.eigenda.xyz:443".to_string()),
        }],
        meta: Default::default(),
        envelope_hash: None,
    };

    let json = serde_json::to_string(&envelope).expect("serialize");
    let parsed: DaEnvelope = serde_json::from_str(&json).expect("deserialize");
    match &parsed.commitments[0] {
        DaCommitment::EigenDa { blob_key, status, .. } => {
            assert_eq!(blob_key.as_deref(), Some("0xabc123:0"));
            assert_eq!(status.as_deref(), Some("complete"));
        }
        _ => panic!("unexpected commitment"),
    }
}
