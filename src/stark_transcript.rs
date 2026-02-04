//! Hash-id aware transcript for STARK verifiers.
//!
//! Mirrors the GLYPH transcript style but supports multiple hash functions
//! for Circle and Standard STARK profiles.

use crate::stark_hash::{ensure_hash_id, hash_bytes, hash_multi};

const TRANSCRIPT_INIT_LABEL: &[u8] = b"GLYPH_STARK_TRANSCRIPT";

#[derive(Clone, Debug)]
pub struct StarkTranscript {
    hash_id: u8,
    state: [u8; 32],
}

impl StarkTranscript {
    pub fn new(hash_id: u8) -> Result<Self, String> {
        ensure_hash_id(hash_id)?;
        let state = hash_bytes(hash_id, TRANSCRIPT_INIT_LABEL)?;
        Ok(Self { hash_id, state })
    }

    pub fn with_label(hash_id: u8, label: &[u8]) -> Result<Self, String> {
        let mut t = Self::new(hash_id)?;
        t.absorb_raw(label)?;
        Ok(t)
    }

    fn absorb_raw(&mut self, data: &[u8]) -> Result<(), String> {
        self.state = hash_multi(self.hash_id, &[&self.state, data])?;
        Ok(())
    }

    pub fn absorb(&mut self, domain: &[u8], data: &[u8]) -> Result<(), String> {
        let len_bytes = (data.len() as u64).to_le_bytes();
        self.state = hash_multi(self.hash_id, &[&self.state, domain, &len_bytes, data])?;
        Ok(())
    }

    pub fn absorb_bytes32(&mut self, domain: &[u8], bytes: &[u8; 32]) -> Result<(), String> {
        self.absorb(domain, bytes)
    }

    pub fn challenge_bytes32(&mut self) -> Result<[u8; 32], String> {
        let hash = self.hash_with_counter(0)?;
        self.state = hash;
        Ok(hash)
    }

    pub fn challenge_usize(&mut self, bound: usize) -> Result<usize, String> {
        if bound <= 1 {
            return Ok(0);
        }
        let bound_u128 = bound as u128;
        let limit = u128::MAX - (u128::MAX % bound_u128);
        let mut counter: u64 = 0;
        loop {
            let hash = self.hash_with_counter(counter)?;
            let mut b0 = [0u8; 16];
            b0.copy_from_slice(&hash[0..16]);
            let candidate = u128::from_le_bytes(b0);
            if candidate < limit {
                self.state = hash;
                return Ok((candidate % bound_u128) as usize);
            }
            counter = counter.wrapping_add(1);
        }
    }

    fn hash_with_counter(&self, counter: u64) -> Result<[u8; 32], String> {
        if counter == 0 {
            hash_multi(self.hash_id, &[&self.state])
        } else {
            let counter_bytes = counter.to_le_bytes();
            hash_multi(self.hash_id, &[&self.state, &counter_bytes])
        }
    }
}
