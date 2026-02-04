//! Hash utilities for STARK receipts.
//!
//! Supports SHA3 (Keccak256), BLAKE3, and Poseidon for Merkle and transcript hashing.

use tiny_keccak::{Hasher, Keccak};
use starknet_crypto::{poseidon_hash_many, Felt};
use winter_crypto::hashers::Rp64_256;
use winter_crypto::ElementHasher;
use winter_math::fields::f64::BaseElement;

pub const HASH_BLAKE3_ID: u8 = 0x01;
pub const HASH_SHA3_ID: u8 = 0x02;
pub const HASH_POSEIDON_ID: u8 = 0x04;
pub const HASH_RESCUE_ID: u8 = 0x05;

pub fn ensure_hash_id(hash_id: u8) -> Result<(), String> {
    match hash_id {
        HASH_SHA3_ID | HASH_BLAKE3_ID | HASH_POSEIDON_ID | HASH_RESCUE_ID => Ok(()),
        _ => Err("unsupported hash_id".to_string()),
    }
}

pub fn hash_multi(hash_id: u8, slices: &[&[u8]]) -> Result<[u8; 32], String> {
    match hash_id {
        HASH_SHA3_ID => {
            let mut hasher = Keccak::v256();
            for slice in slices {
                hasher.update(slice);
            }
            let mut out = [0u8; 32];
            hasher.finalize(&mut out);
            Ok(out)
        }
        HASH_BLAKE3_ID => {
            let mut hasher = blake3::Hasher::new();
            for slice in slices {
                hasher.update(slice);
            }
            let out = hasher.finalize();
            Ok(*out.as_bytes())
        }
        HASH_POSEIDON_ID => {
            let total_len: usize = slices.iter().map(|s| s.len()).sum();
            let mut buf = Vec::with_capacity(total_len);
            for slice in slices {
                buf.extend_from_slice(slice);
            }
            poseidon_hash_bytes(&buf)
        }
        HASH_RESCUE_ID => {
            let total_len: usize = slices.iter().map(|s| s.len()).sum();
            let mut buf = Vec::with_capacity(total_len);
            for slice in slices {
                buf.extend_from_slice(slice);
            }
            rescue_hash_bytes(&buf)
        }
        _ => Err("unsupported hash_id".to_string()),
    }
}

pub fn hash_bytes(hash_id: u8, data: &[u8]) -> Result<[u8; 32], String> {
    hash_multi(hash_id, &[data])
}

pub fn hash_domain(hash_id: u8, domain: &[u8], data: &[u8]) -> Result<[u8; 32], String> {
    let len_bytes = (data.len() as u64).to_le_bytes();
    hash_multi(hash_id, &[domain, &len_bytes, data])
}

fn poseidon_hash_bytes(data: &[u8]) -> Result<[u8; 32], String> {
    if data.is_empty() {
        let digest = poseidon_hash_many(&[]);
        return Ok(digest.to_bytes_be());
    }
    let mut felts = Vec::with_capacity(data.len().div_ceil(31));
    for chunk in data.chunks(31) {
        let felt = Felt::from_bytes_be_slice(chunk);
        felts.push(felt);
    }
    let digest = poseidon_hash_many(&felts);
    Ok(digest.to_bytes_be())
}

fn rescue_hash_bytes(data: &[u8]) -> Result<[u8; 32], String> {
    if data.is_empty() {
        let digest = <Rp64_256 as ElementHasher>::hash_elements::<BaseElement>(&[]);
        return Ok(digest.into());
    }
    let num_elements = data.len().div_ceil(7);
    let mut elements = Vec::with_capacity(num_elements);
    for (index, chunk) in data.chunks(7).enumerate() {
        let is_last = index + 1 == num_elements;
        let mut buf = [0u8; 8];
        if is_last {
            let chunk_len = chunk.len();
            buf[..chunk_len].copy_from_slice(chunk);
            buf[chunk_len] = 1;
        } else {
            buf[..7].copy_from_slice(chunk);
        }
        elements.push(BaseElement::new(u64::from_le_bytes(buf)));
    }
    let digest = <Rp64_256 as ElementHasher>::hash_elements(&elements);
    Ok(digest.into())
}
