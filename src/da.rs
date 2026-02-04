use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaProfile {
    VerifierOnly,
    BlobOnly,
    BlobArweave,
    BlobEigenDaArweave,
}

impl DaProfile {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "verifier-only" => Some(Self::VerifierOnly),
            "blob-only" => Some(Self::BlobOnly),
            "blob-arweave" => Some(Self::BlobArweave),
            "blob-eigenda-arweave" => Some(Self::BlobEigenDaArweave),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifierOnly => "verifier-only",
            Self::BlobOnly => "blob-only",
            Self::BlobArweave => "blob-arweave",
            Self::BlobEigenDaArweave => "blob-eigenda-arweave",
        }
    }

    pub fn providers(&self) -> &'static [DaProvider] {
        match self {
            Self::VerifierOnly => &[],
            Self::BlobOnly => &[DaProvider::Blob],
            Self::BlobArweave => &[DaProvider::Blob, DaProvider::Arweave],
            Self::BlobEigenDaArweave => &[DaProvider::Blob, DaProvider::EigenDa, DaProvider::Arweave],
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    Minimal,
    Full,
}

impl PayloadMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "minimal" => Some(Self::Minimal),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Full => "full",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaProvider {
    Blob,
    Arweave,
    EigenDa,
}

impl DaProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Arweave => "arweave",
            Self::EigenDa => "eigenda",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaEnvelope {
    pub version: u32,
    pub profile_id: String,
    pub payload_mode: String,
    pub created_at_utc: String,
    pub artifact_tag: String,
    pub artifact_bytes_hash: String,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_proof_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vk_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_address: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub commitments: Vec<DaCommitment>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub meta: BTreeMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hash: Option<String>,
}

impl DaEnvelope {
    pub fn canonical_json_for_hash(&self) -> Result<String, String> {
        let mut clone = self.clone();
        clone.envelope_hash = None;
        serde_json::to_string(&clone).map_err(|err| err.to_string())
    }

    pub fn compute_envelope_hash(&self) -> Result<String, String> {
        let json = self.canonical_json_for_hash()?;
        Ok(hex_0x(&keccak256(json.as_bytes())))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum DaCommitment {
    Blob {
        tx_hash: String,
        versioned_hashes: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        chain_id: Option<u64>,
    },
    Arweave {
        tx_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        gateway_url: Option<String>,
    },
    EigenDa {
        #[serde(skip_serializing_if = "Option::is_none")]
        blob_key: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        certificate_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        disperser_url: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct DaPayloadParts {
    pub artifact_bytes: Vec<u8>,
    pub upstream_proof_bytes: Option<Vec<u8>>,
    pub vk_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct DaPayload {
    pub version: u8,
    pub parts: DaPayloadParts,
}

impl DaPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        let mut flags = 0u8;
        if self.parts.upstream_proof_bytes.is_some() {
            flags |= 1;
        }
        if self.parts.vk_bytes.is_some() {
            flags |= 2;
        }
        out.push(flags);
        out.extend_from_slice(&(self.parts.artifact_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.parts.artifact_bytes);
        if let Some(proof) = &self.parts.upstream_proof_bytes {
            out.extend_from_slice(&(proof.len() as u32).to_be_bytes());
            out.extend_from_slice(proof);
        }
        if let Some(vk) = &self.parts.vk_bytes {
            out.extend_from_slice(&(vk.len() as u32).to_be_bytes());
            out.extend_from_slice(vk);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<DaPayload, String> {
        if bytes.len() < 2 {
            return Err("payload too short".to_string());
        }
        let version = bytes[0];
        let flags = bytes[1];
        let mut cursor = 2usize;

        let read_u32 = |data: &[u8], pos: &mut usize| -> Result<u32, String> {
            if *pos + 4 > data.len() {
                return Err("payload length underflow".to_string());
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&data[*pos..*pos + 4]);
            *pos += 4;
            Ok(u32::from_be_bytes(buf))
        };

        let read_vec = |data: &[u8], pos: &mut usize, len: usize| -> Result<Vec<u8>, String> {
            if *pos + len > data.len() {
                return Err("payload length underflow".to_string());
            }
            let out = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(out)
        };

        let artifact_len = read_u32(bytes, &mut cursor)? as usize;
        let artifact_bytes = read_vec(bytes, &mut cursor, artifact_len)?;

        let proof = if flags & 1 == 1 {
            let proof_len = read_u32(bytes, &mut cursor)? as usize;
            Some(read_vec(bytes, &mut cursor, proof_len)?)
        } else {
            None
        };

        let vk = if flags & 2 == 2 {
            let vk_len = read_u32(bytes, &mut cursor)? as usize;
            Some(read_vec(bytes, &mut cursor, vk_len)?)
        } else {
            None
        };

        if cursor != bytes.len() {
            return Err("payload has trailing bytes".to_string());
        }

        Ok(DaPayload {
            version,
            parts: DaPayloadParts {
                artifact_bytes,
                upstream_proof_bytes: proof,
                vk_bytes: vk,
            },
        })
    }
}

pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("read failed for {}: {}", path.display(), err))
}

pub fn extract_artifact_tag(artifact_bytes: &[u8]) -> Result<[u8; 32], String> {
    if artifact_bytes.len() < 32 {
        return Err("artifact bytes must be at least 32 bytes".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&artifact_bytes[..32]);
    Ok(out)
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut out);
    out
}

pub fn hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn parse_hex_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(s).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_envelope() -> DaEnvelope {
        DaEnvelope {
            version: 1,
            profile_id: DaProfile::BlobEigenDaArweave.as_str().to_string(),
            payload_mode: PayloadMode::Minimal.as_str().to_string(),
            created_at_utc: "2026-01-20T00:00:00Z".to_string(),
            artifact_tag: "0x00".to_string(),
            artifact_bytes_hash: "0x01".to_string(),
            payload_hash: "0x02".to_string(),
            upstream_proof_hash: None,
            vk_hash: None,
            chain_id: Some(1),
            verifier_address: Some("0xdeadbeef".to_string()),
            commitments: vec![],
            meta: BTreeMap::new(),
            envelope_hash: None,
        }
    }

    #[test]
    fn envelope_hash_ignores_self_field() {
        let env = sample_envelope();
        let hash = match env.compute_envelope_hash() {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "hash");
                return;
            }
        };
        let mut with_hash = env.clone();
        with_hash.envelope_hash = Some(hash.clone());
        let hash2 = match with_hash.compute_envelope_hash() {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "hash");
                return;
            }
        };
        assert_eq!(hash, hash2);
    }

    #[test]
    fn payload_roundtrip_minimal() {
        let payload = DaPayload {
            version: 1,
            parts: DaPayloadParts {
                artifact_bytes: vec![1, 2, 3, 4],
                upstream_proof_bytes: None,
                vk_bytes: None,
            },
        };
        let encoded = payload.encode();
        let decoded = match DaPayload::decode(&encoded) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode");
                return;
            }
        };
        assert_eq!(decoded.parts.artifact_bytes, payload.parts.artifact_bytes);
        assert!(decoded.parts.upstream_proof_bytes.is_none());
        assert!(decoded.parts.vk_bytes.is_none());
    }

    #[test]
    fn payload_decode_rejects_trailing_bytes() {
        let payload = DaPayload {
            version: 1,
            parts: DaPayloadParts {
                artifact_bytes: vec![1, 2, 3, 4],
                upstream_proof_bytes: Some(vec![9, 9]),
                vk_bytes: None,
            },
        };
        let mut encoded = payload.encode();
        encoded.extend_from_slice(&[0xaa, 0xbb]);
        let err = DaPayload::decode(&encoded).unwrap_err();
        assert_eq!(err, "payload has trailing bytes");
    }

    proptest! {
        #[test]
        fn prop_payload_roundtrip(
            artifact in proptest::collection::vec(any::<u8>(), 0..256),
            proof in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..128)),
            vk in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..128)),
        ) {
            let payload = DaPayload {
                version: 1,
                parts: DaPayloadParts {
                    artifact_bytes: artifact.clone(),
                    upstream_proof_bytes: proof.clone(),
                    vk_bytes: vk.clone(),
                },
            };
            let encoded = payload.encode();
            let decoded = match DaPayload::decode(&encoded) {
                Ok(value) => value,
                Err(_) => {
                    prop_assert!(false, "decode");
                    return Ok(());
                }
            };
            prop_assert_eq!(decoded.parts.artifact_bytes, artifact);
            prop_assert_eq!(decoded.parts.upstream_proof_bytes, proof);
            prop_assert_eq!(decoded.parts.vk_bytes, vk);
        }
    }

    #[test]
    fn parse_hex_bytes_accepts_prefix() {
        let raw = match parse_hex_bytes("0x0102") {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "hex");
                return;
            }
        };
        assert_eq!(raw, vec![1u8, 2u8]);
        let raw2 = match parse_hex_bytes("0102") {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "hex");
                return;
            }
        };
        assert_eq!(raw2, vec![1u8, 2u8]);
    }
}
