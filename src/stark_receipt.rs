//! Canonical STARK receipt format.
//!
//! Goal: one STARK adapter entry point which is self-describing and binds the verifier program
//! into the receipt digest, so trustless validity can be proved inside GLYPH without hardcoding
//! upstream verifier logic per STARK system in Rust.
//!
//! This module only defines canonical encoding and binding primitives. It does not implement
//! full validity yet.

use crate::adapters::keccak256;

pub const CANONICAL_STARK_RECEIPT_DOMAIN: &[u8] = b"CANONICAL_STARK_RECEIPT";
pub const CANONICAL_STARK_VK_DOMAIN: &[u8] = b"CANONICAL_STARK_VK";
pub const CANONICAL_STARK_VK_PROGRAM_DOMAIN: &[u8] = b"CANONICAL_STARK_VK_PROGRAM";

fn tag_offset(bytes: &[u8], tag: &[u8]) -> Result<usize, String> {
    if !bytes.starts_with(tag) {
        return Err("canonical tag mismatch".to_string());
    }
    let mut off = tag.len();
    if bytes.len() >= off + 3 && bytes[off] == b'_' && bytes[off + 1] == b'V' && bytes[off + 2].is_ascii_digit()
    {
        off += 2;
        while off < bytes.len() && bytes[off].is_ascii_digit() {
            off += 1;
        }
    }
    Ok(off)
}

fn tag_version_suffix(bytes: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < tag.len() + 3 || !bytes.starts_with(tag) {
        return None;
    }
    let off = tag.len();
    if bytes[off] != b'_' || bytes[off + 1] != b'V' || !bytes[off + 2].is_ascii_digit() {
        return None;
    }
    let mut idx = off + 2;
    let mut digits = Vec::new();
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        digits.push(bytes[idx]);
        idx += 1;
    }
    if digits.is_empty() {
        None
    } else {
        Some(digits)
    }
}

fn suffix_from_tag_prefix(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut idx = 0;
    while idx < bytes.len() {
        let b = bytes[idx];
        let is_tag = b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_';
        if !is_tag {
            break;
        }
        idx += 1;
    }
    if idx == 0 {
        return None;
    }
    let tag = &bytes[..idx];
    let end = tag.len();
    let mut start = end;
    while start > 0 && tag[start - 1].is_ascii_digit() {
        start -= 1;
    }
    if start == end {
        return None;
    }
    if start < 2 || tag[start - 2] != b'_' || tag[start - 1] != b'V' {
        return None;
    }
    Some(tag[start..end].to_vec())
}

fn domain_with_suffix(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + 2 + suffix.len());
    out.extend_from_slice(base);
    out.extend_from_slice(b"_V");
    out.extend_from_slice(suffix);
    out
}

fn matches_program_hash(domain: &[u8], program_bytes: &[u8], program_hash: &[u8; 32]) -> bool {
    let mut input = Vec::with_capacity(domain.len() + program_bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(program_bytes);
    if keccak256(&input) == *program_hash {
        return true;
    }
    let domain_hash = keccak256(domain);
    let mut input2 = Vec::with_capacity(32 + program_bytes.len());
    input2.extend_from_slice(&domain_hash);
    input2.extend_from_slice(program_bytes);
    keccak256(&input2) == *program_hash
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalStarkVk {
    pub version: u16,
    pub field_id: u8,
    pub hash_id: u8,
    pub commitment_scheme_id: u8,
    /// Canonical, system-defined constants blob. Interpreted by the verifier program.
    pub consts_bytes: Vec<u8>,
    /// Canonical verifier program bytecode (IR). Must be bound via `program_hash`.
    pub program_bytes: Vec<u8>,
}

impl CanonicalStarkVk {
    pub fn program_hash(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(CANONICAL_STARK_VK_PROGRAM_DOMAIN.len() + self.program_bytes.len());
        input.extend_from_slice(CANONICAL_STARK_VK_PROGRAM_DOMAIN);
        input.extend_from_slice(&self.program_bytes);
        keccak256(&input)
    }

    pub fn encode(&self) -> Vec<u8> {
        let program_hash = self.program_hash();
        let mut out = Vec::with_capacity(
            CANONICAL_STARK_VK_DOMAIN.len()
                + 2
                + 3
                + 4
                + self.consts_bytes.len()
                + 4
                + self.program_bytes.len()
                + 32,
        );
        out.extend_from_slice(CANONICAL_STARK_VK_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.field_id);
        out.push(self.hash_id);
        out.push(self.commitment_scheme_id);
        out.extend_from_slice(&(self.consts_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.consts_bytes);
        out.extend_from_slice(&(self.program_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.program_bytes);
        out.extend_from_slice(&program_hash);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CANONICAL_STARK_VK_DOMAIN)
            .map_err(|_| "vk bytes missing CANONICAL_STARK_VK_DOMAIN prefix".to_string())?;

        let version = read_u16_be(bytes, &mut off)?;
        let field_id = read_u8(bytes, &mut off)?;
        let hash_id = read_u8(bytes, &mut off)?;
        let commitment_scheme_id = read_u8(bytes, &mut off)?;

        let consts_len = read_u32_be(bytes, &mut off)? as usize;
        let consts_bytes = read_vec(bytes, &mut off, consts_len)?;

        let program_len = read_u32_be(bytes, &mut off)? as usize;
        let program_bytes = read_vec(bytes, &mut off, program_len)?;

        let program_hash = read_bytes32(bytes, &mut off)?;

        if off != bytes.len() {
            return Err("vk bytes have trailing data".to_string());
        }

        let vk = Self {
            version,
            field_id,
            hash_id,
            commitment_scheme_id,
            consts_bytes,
            program_bytes,
        };
        let expected = vk.program_hash();
        if expected != program_hash {
            let mut matched = false;
            if let Some(suffix) = tag_version_suffix(bytes, CANONICAL_STARK_VK_DOMAIN) {
                let domain = domain_with_suffix(CANONICAL_STARK_VK_PROGRAM_DOMAIN, &suffix);
                if matches_program_hash(&domain, &vk.program_bytes, &program_hash) {
                    matched = true;
                }
            }
            if !matched {
                if let Some(suffix) = suffix_from_tag_prefix(&vk.program_bytes) {
                    let domain = domain_with_suffix(CANONICAL_STARK_VK_PROGRAM_DOMAIN, &suffix);
                    if matches_program_hash(&domain, &vk.program_bytes, &program_hash) {
                        matched = true;
                    }
                }
            }
            if !matched
                && (tag_version_suffix(bytes, CANONICAL_STARK_VK_DOMAIN).is_some()
                    || suffix_from_tag_prefix(&vk.program_bytes).is_some())
                && keccak256(&vk.program_bytes) == program_hash
            {
                matched = true;
            }
            if !matched {
                return Err("vk program_hash mismatch".to_string());
            }
        }

        Ok(vk)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalStarkReceipt {
    pub proof_bytes: Vec<u8>,
    pub pub_inputs_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

impl CanonicalStarkReceipt {
    pub fn encode_for_hash(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            CANONICAL_STARK_RECEIPT_DOMAIN.len()
                + 4
                + self.proof_bytes.len()
                + 4
                + self.pub_inputs_bytes.len()
                + 4
                + self.vk_bytes.len(),
        );
        out.extend_from_slice(CANONICAL_STARK_RECEIPT_DOMAIN);
        out.extend_from_slice(&(self.proof_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.proof_bytes);
        out.extend_from_slice(&(self.pub_inputs_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.pub_inputs_bytes);
        out.extend_from_slice(&(self.vk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.vk_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut off = tag_offset(bytes, CANONICAL_STARK_RECEIPT_DOMAIN)
            .map_err(|_| "receipt bytes missing CANONICAL_STARK_RECEIPT_DOMAIN prefix".to_string())?;

        let proof_len = read_u32_be(bytes, &mut off)? as usize;
        let proof_bytes = read_vec(bytes, &mut off, proof_len)?;

        let pub_inputs_len = read_u32_be(bytes, &mut off)? as usize;
        let pub_inputs_bytes = read_vec(bytes, &mut off, pub_inputs_len)?;

        let vk_len = read_u32_be(bytes, &mut off)? as usize;
        let vk_bytes = read_vec(bytes, &mut off, vk_len)?;

        if off != bytes.len() {
            return Err("receipt bytes have trailing data".to_string());
        }

        Ok(Self {
            proof_bytes,
            pub_inputs_bytes,
            vk_bytes,
        })
    }

    pub fn digest(&self) -> [u8; 32] {
        keccak256(&self.encode_for_hash())
    }

    pub fn decode_and_validate_vk(bytes: &CanonicalStarkReceipt) -> Result<CanonicalStarkVk, String> {
        CanonicalStarkVk::decode(&bytes.vk_bytes)
    }
}

fn read_u8(bytes: &[u8], off: &mut usize) -> Result<u8, String> {
    let v = bytes.get(*off).copied().ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 1;
    Ok(v)
}

fn read_u16_be(bytes: &[u8], off: &mut usize) -> Result<u16, String> {
    let s = bytes.get(*off..*off + 2).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 2;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Result<u32, String> {
    let s = bytes.get(*off..*off + 4).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 4;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_vec(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let s = bytes.get(*off..*off + len).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += len;
    Ok(s.to_vec())
}

fn read_bytes32(bytes: &[u8], off: &mut usize) -> Result<[u8; 32], String> {
    let s = bytes.get(*off..*off + 32).ok_or_else(|| "unexpected EOF".to_string())?;
    *off += 32;
    let mut out = [0u8; 32];
    out.copy_from_slice(s);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vk_roundtrip_and_program_hash_binding() {
        let vk = CanonicalStarkVk {
            version: 1,
            field_id: 0x01,
            hash_id: 0x02,
            commitment_scheme_id: 0x01,
            consts_bytes: b"consts".to_vec(),
            program_bytes: b"program".to_vec(),
        };
        let enc = vk.encode();
        let dec = match CanonicalStarkVk::decode(&enc) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "decode must succeed");
                return;
            }
        };
        assert_eq!(vk, dec);

        let mut tampered = enc.clone();
        // Flip one bit in program bytes area.
        let program_pos = CANONICAL_STARK_VK_DOMAIN.len() + 2 + 3 + 4 + vk.consts_bytes.len() + 4;
        tampered[program_pos] ^= 1;
        assert!(CanonicalStarkVk::decode(&tampered).is_err());
    }

    #[test]
    fn test_receipt_digest_changes_on_any_component_change() {
        let vk = CanonicalStarkVk {
            version: 1,
            field_id: 0x01,
            hash_id: 0x02,
            commitment_scheme_id: 0x01,
            consts_bytes: vec![0xAA; 5],
            program_bytes: vec![0xBB; 7],
        };
        let vk_bytes = vk.encode();

        let r = CanonicalStarkReceipt {
            proof_bytes: vec![1, 2, 3],
            pub_inputs_bytes: vec![4, 5],
            vk_bytes: vk_bytes.clone(),
        };
        let d0 = r.digest();

        let mut r1 = r.clone();
        r1.proof_bytes[0] ^= 1;
        assert_ne!(d0, r1.digest());

        let mut r2 = r.clone();
        r2.pub_inputs_bytes[0] ^= 1;
        assert_ne!(d0, r2.digest());

        let mut vk2 = vk_bytes.clone();
        let last = vk2.len() - 1;
        vk2[last] ^= 1;
        let r3 = CanonicalStarkReceipt {
            proof_bytes: r.proof_bytes.clone(),
            pub_inputs_bytes: r.pub_inputs_bytes.clone(),
            vk_bytes: vk2,
        };
        assert_ne!(d0, r3.digest());
    }
}
