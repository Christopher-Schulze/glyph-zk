//! GLYPH IPA implementation on BN254.
//!
//! Core prover/verifier for the Inner Product Argument with generator hints.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use sha2::{Digest, Sha256};

use crate::glv::shamir_triple_mul;
use crate::glyph_field_simd::simd_inner_product;

#[inline]
pub fn pippenger_msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Projective, IPAError> {
    G1Projective::msm(bases, scalars).map_err(|_| IPAError::MsmFailed)
}
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IPAError {
    ZeroChallenge,
    MsmFailed,
}

fn invert_challenge(x: Fr) -> Result<Fr, IPAError> {
    x.inverse().ok_or(IPAError::ZeroChallenge)
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CompressedG1(pub G1Affine);

impl CompressedG1 {
    pub fn to_bytes_compressed(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        let x_bytes = self.0.x.into_bigint().to_bytes_be();
        bytes[0..32].copy_from_slice(&x_bytes);
        let y_is_odd = self.0.y.into_bigint().0[0] & 1 == 1;
        bytes[32] = if y_is_odd { 1 } else { 0 };
        bytes
    }
}

#[derive(Clone)]
pub struct IPAParams {
    pub g: Vec<G1Affine>,
    pub h: Vec<G1Affine>,
    pub u: G1Affine,
    pub n: usize,
}

impl IPAParams {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two());
        let g: Vec<_> = (0..n).map(|i| hash_to_g1_indexed("GLYPH_G", i as u64)).collect();
        let h: Vec<_> = (0..n).map(|i| hash_to_g1_indexed("GLYPH_H", i as u64)).collect();
        let u = hash_to_g1_indexed("GLYPH_U", 0);
        Self { g, h, u, n }
    }
    
}

#[derive(Clone, Debug)]
pub struct IPAProof {
    pub l_vec: Vec<CompressedG1>,
    pub r_vec: Vec<CompressedG1>,
    pub a: Fr,
    pub b: Fr,
}

impl IPAProof {
    pub fn size(&self) -> usize {
        4 + self.l_vec.len() * 33 * 2 + 64
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.l_vec.len() as u32).to_be_bytes());
        for l in &self.l_vec { bytes.extend_from_slice(&l.to_bytes_compressed()); }
        for r in &self.r_vec { bytes.extend_from_slice(&r.to_bytes_compressed()); }
        bytes.extend_from_slice(&self.a.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.b.into_bigint().to_bytes_be());
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct IPAProofOptimized {
    pub l_vec: Vec<CompressedG1>,
    pub r_vec: Vec<CompressedG1>,
    pub a: Fr,
    pub b: Fr,
    pub g_final: CompressedG1,
    pub h_final: CompressedG1,
}

impl IPAProofOptimized {
    pub fn size(&self) -> usize {
        4 + self.l_vec.len() * 33 * 2 + 64 + 66
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.l_vec.len() as u32).to_be_bytes());
        for l in &self.l_vec { bytes.extend_from_slice(&l.to_bytes_compressed()); }
        for r in &self.r_vec { bytes.extend_from_slice(&r.to_bytes_compressed()); }
        bytes.extend_from_slice(&self.a.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.b.into_bigint().to_bytes_be());
        bytes.extend_from_slice(&self.g_final.to_bytes_compressed());
        bytes.extend_from_slice(&self.h_final.to_bytes_compressed());
        bytes
    }
}

/// Compute the inner product ⟨a, b⟩ = Σ aᵢ·bᵢ.
///
/// Delegates to SIMD-accelerated implementation which automatically selects
/// the optimal backend (AVX-512, AVX2, NEON, or scalar fallback) based on
/// hardware capabilities. For small vectors (n ≤ 64), performance is similar
/// to scalar; for larger vectors, SIMD provides measurable speedup.
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    simd_inner_product(a, b)
}

pub struct IPAProver<'a> {
    pub params: &'a IPAParams,
}

impl<'a> IPAProver<'a> {
    pub fn prove(&self, a: &[Fr], b: &[Fr]) -> Result<(G1Projective, Fr, IPAProof), IPAError> {
        // Enforce vector length matches public parameters
        assert_eq!(a.len(), self.params.n, "IPAProver::prove: length(a) must equal params.n");
        assert_eq!(b.len(), self.params.n, "IPAProver::prove: length(b) must equal params.n");
        let c = inner_product(a, b);
        let p = pippenger_msm(&self.params.g, a)?
              + pippenger_msm(&self.params.h, b)?
              + self.params.u * c;
        
        let mut a = a.to_vec();
        let mut b = b.to_vec();
        let mut g = self.params.g.clone();
        let mut h = self.params.h.clone();
        
        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();
        
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        while a.len() > 1 {
            let half = a.len() / 2;
            let (a_lo, a_hi) = (&a[..half], &a[half..]);
            let (b_lo, b_hi) = (&b[..half], &b[half..]);
            let (g_lo, g_hi) = (&g[..half], &g[half..]);
            let (h_lo, h_hi) = (&h[..half], &h[half..]);
            
            let c_l = inner_product(a_lo, b_hi);
            let l = pippenger_msm(g_hi, a_lo)?
                  + pippenger_msm(h_lo, b_hi)?
                  + self.params.u * c_l;
            
            let c_r = inner_product(a_hi, b_lo);
            let r = pippenger_msm(g_lo, a_hi)?
                  + pippenger_msm(h_hi, b_lo)?
                  + self.params.u * c_r;
            
            let l_aff = l.into_affine();
            let r_aff = r.into_affine();
            
            l_vec.push(CompressedG1(l_aff));
            r_vec.push(CompressedG1(r_aff));
            
            transcript.append_point(&l_aff);
            transcript.append_point(&r_aff);
            let x = transcript.challenge_scalar();
            let x_inv = invert_challenge(x)?;
            
            a = a_lo.iter().zip(a_hi).map(|(lo, hi)| *lo * x + *hi * x_inv).collect();
            b = b_lo.iter().zip(b_hi).map(|(lo, hi)| *lo * x_inv + *hi * x).collect();
            g = g_lo.iter().zip(g_hi).map(|(lo, hi)| 
                (lo.into_group() * x_inv + hi.into_group() * x).into_affine()
            ).collect();
            h = h_lo.iter().zip(h_hi).map(|(lo, hi)| 
                (lo.into_group() * x + hi.into_group() * x_inv).into_affine()
            ).collect();
        }
        
        Ok((p, c, IPAProof { l_vec, r_vec, a: a[0], b: b[0] }))
    }
    
    /// Optimized: includes G_final and H_final hints
    pub fn prove_optimized(&self, a: &[Fr], b: &[Fr]) -> Result<(G1Projective, Fr, IPAProofOptimized), IPAError> {
        // Enforce vector length matches public parameters
        assert_eq!(a.len(), self.params.n, "IPAProver::prove_optimized: length(a) must equal params.n");
        assert_eq!(b.len(), self.params.n, "IPAProver::prove_optimized: length(b) must equal params.n");
        let c = inner_product(a, b);
        let p = pippenger_msm(&self.params.g, a)?
              + pippenger_msm(&self.params.h, b)?
              + self.params.u * c;
        
        let mut a = a.to_vec();
        let mut b = b.to_vec();
        let mut g = self.params.g.clone();
        let mut h = self.params.h.clone();
        
        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();
        
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        while a.len() > 1 {
            let half = a.len() / 2;
            let (a_lo, a_hi) = (&a[..half], &a[half..]);
            let (b_lo, b_hi) = (&b[..half], &b[half..]);
            let (g_lo, g_hi) = (&g[..half], &g[half..]);
            let (h_lo, h_hi) = (&h[..half], &h[half..]);
            
            let c_l = inner_product(a_lo, b_hi);
            let l = pippenger_msm(g_hi, a_lo)?
                  + pippenger_msm(h_lo, b_hi)?
                  + self.params.u * c_l;
            
            let c_r = inner_product(a_hi, b_lo);
            let r = pippenger_msm(g_lo, a_hi)?
                  + pippenger_msm(h_hi, b_lo)?
                  + self.params.u * c_r;
            
            let l_aff = l.into_affine();
            let r_aff = r.into_affine();
            
            l_vec.push(CompressedG1(l_aff));
            r_vec.push(CompressedG1(r_aff));
            
            transcript.append_point(&l_aff);
            transcript.append_point(&r_aff);
            let x = transcript.challenge_scalar();
            let x_inv = invert_challenge(x)?;
            
            a = a_lo.iter().zip(a_hi).map(|(lo, hi)| *lo * x + *hi * x_inv).collect();
            b = b_lo.iter().zip(b_hi).map(|(lo, hi)| *lo * x_inv + *hi * x).collect();
            g = g_lo.iter().zip(g_hi).map(|(lo, hi)| 
                (lo.into_group() * x_inv + hi.into_group() * x).into_affine()
            ).collect();
            h = h_lo.iter().zip(h_hi).map(|(lo, hi)| 
                (lo.into_group() * x + hi.into_group() * x_inv).into_affine()
            ).collect();
        }
        
        let g_final = CompressedG1(g[0]);
        let h_final = CompressedG1(h[0]);
        
        Ok((p, c, IPAProofOptimized {
            l_vec,
            r_vec,
            a: a[0],
            b: b[0],
            g_final,
            h_final,
        }))
    }

    pub fn prove_optimized_with_statement(
        &self,
        a: &[Fr],
        b: &[Fr],
        statement: &[u8],
    ) -> Result<(G1Projective, Fr, IPAProofOptimized), IPAError> {
        assert_eq!(a.len(), self.params.n, "IPAProver::prove_optimized_with_statement: length(a) must equal params.n");
        assert_eq!(b.len(), self.params.n, "IPAProver::prove_optimized_with_statement: length(b) must equal params.n");
        let c = inner_product(a, b);
        let p = pippenger_msm(&self.params.g, a)?
              + pippenger_msm(&self.params.h, b)?
              + self.params.u * c;

        let mut a = a.to_vec();
        let mut b = b.to_vec();
        let mut g = self.params.g.clone();
        let mut h = self.params.h.clone();

        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();

        let mut transcript = Transcript::new_onchain();
        transcript.append_bytes(statement);
        transcript.append_point(&p.into_affine());

        while a.len() > 1 {
            let half = a.len() / 2;
            let (a_lo, a_hi) = (&a[..half], &a[half..]);
            let (b_lo, b_hi) = (&b[..half], &b[half..]);
            let (g_lo, g_hi) = (&g[..half], &g[half..]);
            let (h_lo, h_hi) = (&h[..half], &h[half..]);

            let c_l = inner_product(a_lo, b_hi);
            let l = pippenger_msm(g_hi, a_lo)?
                  + pippenger_msm(h_lo, b_hi)?
                  + self.params.u * c_l;

            let c_r = inner_product(a_hi, b_lo);
            let r = pippenger_msm(g_lo, a_hi)?
                  + pippenger_msm(h_hi, b_lo)?
                  + self.params.u * c_r;

            let l_aff = l.into_affine();
            let r_aff = r.into_affine();

            l_vec.push(CompressedG1(l_aff));
            r_vec.push(CompressedG1(r_aff));

            transcript.append_point(&l_aff);
            transcript.append_point(&r_aff);
            let x = transcript.challenge_scalar();
            let x_inv = invert_challenge(x)?;

            a = a_lo.iter().zip(a_hi).map(|(lo, hi)| *lo * x + *hi * x_inv).collect();
            b = b_lo.iter().zip(b_hi).map(|(lo, hi)| *lo * x_inv + *hi * x).collect();
            g = g_lo.iter().zip(g_hi).map(|(lo, hi)|
                (lo.into_group() * x_inv + hi.into_group() * x).into_affine()
            ).collect();
            h = h_lo.iter().zip(h_hi).map(|(lo, hi)|
                (lo.into_group() * x + hi.into_group() * x_inv).into_affine()
            ).collect();
        }

        let g_final = CompressedG1(g[0]);
        let h_final = CompressedG1(h[0]);

        Ok((p, c, IPAProofOptimized {
            l_vec,
            r_vec,
            a: a[0],
            b: b[0],
            g_final,
            h_final,
        }))
    }
}

pub struct IPAVerifier<'a> {
    pub params: &'a IPAParams,
}

impl<'a> IPAVerifier<'a> {
    /// Standard verification (computes MSM - expensive)
    pub fn verify(&self, p: &G1Projective, _c: Fr, proof: &IPAProof) -> Result<bool, IPAError> {
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        let mut challenges = Vec::new();
        let mut p_prime = *p;
        
        for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
            transcript.append_point(&l.0);
            transcript.append_point(&r.0);
            
            let x = transcript.challenge_scalar();
            challenges.push(x);
            
            let x_sq = x * x;
            let x_inv_sq = invert_challenge(x_sq)?;
            
            p_prime = l.0.into_group() * x_sq + p_prime + r.0.into_group() * x_inv_sq;
        }
        
        let (g_final, h_final) = self.compute_final_generators(&challenges)?;
        // Use Shamir's trick for combined scalar multiplication
        let ab = proof.a * proof.b;
        let expected = shamir_triple_mul(
            &proof.a, &g_final.into_affine(),
            &proof.b, &h_final.into_affine(),
            &ab, &self.params.u
        );
        
        Ok(p_prime == expected)
    }
    
    pub fn verify_optimized(&self, p: &G1Projective, _c: Fr, proof: &IPAProofOptimized) -> Result<bool, IPAError> {
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        let mut challenges = Vec::new();
        let mut p_prime = *p;
        
        for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
            transcript.append_point(&l.0);
            transcript.append_point(&r.0);
            
            let x = transcript.challenge_scalar();
            challenges.push(x);
            
            let x_sq = x * x;
            let x_inv_sq = invert_challenge(x_sq)?;
            p_prime = l.0.into_group() * x_sq + p_prime + r.0.into_group() * x_inv_sq;
        }
        
        let g_hint = proof.g_final.0.into_group();
        let h_hint = proof.h_final.0.into_group();
        
        let (g_calc, h_calc) = self.compute_final_generators(&challenges)?;
        if g_calc != g_hint || h_calc != h_hint {
            return Ok(false);
        }

        // Use Shamir's trick for combined scalar multiplication
        let ab = proof.a * proof.b;
        let expected = shamir_triple_mul(
            &proof.a, &g_hint.into_affine(),
            &proof.b, &h_hint.into_affine(),
            &ab, &self.params.u
        );
        if p_prime != expected {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn verify_optimized_with_statement(
        &self,
        p: &G1Projective,
        _c: Fr,
        proof: &IPAProofOptimized,
        statement: &[u8],
    ) -> Result<bool, IPAError> {
        let mut transcript = Transcript::new_onchain();
        transcript.append_bytes(statement);
        transcript.append_point(&p.into_affine());

        let mut challenges = Vec::new();
        let mut p_prime = *p;

        for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
            transcript.append_point(&l.0);
            transcript.append_point(&r.0);

            let x = transcript.challenge_scalar();
            challenges.push(x);

            let x_sq = x * x;
            let x_inv_sq = invert_challenge(x_sq)?;
            p_prime = l.0.into_group() * x_sq + p_prime + r.0.into_group() * x_inv_sq;
        }

        let g_hint = proof.g_final.0.into_group();
        let h_hint = proof.h_final.0.into_group();

        let (g_calc, h_calc) = self.compute_final_generators(&challenges)?;
        if g_calc != g_hint || h_calc != h_hint {
            return Ok(false);
        }

        let ab = proof.a * proof.b;
        let expected = shamir_triple_mul(
            &proof.a, &g_hint.into_affine(),
            &proof.b, &h_hint.into_affine(),
            &ab, &self.params.u
        );
        if p_prime != expected {
            return Ok(false);
        }

        Ok(true)
    }
    
    pub fn verify_with_trusted_hints(&self, p: &G1Projective, proof: &IPAProofOptimized) -> Result<bool, IPAError> {
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        let mut p_prime = *p;
        
        for (l, r) in proof.l_vec.iter().zip(proof.r_vec.iter()) {
            transcript.append_point(&l.0);
            transcript.append_point(&r.0);
            
            let x = transcript.challenge_scalar();
            let x_sq = x * x;
            let x_inv_sq = invert_challenge(x_sq)?;
            
            p_prime = l.0.into_group() * x_sq + p_prime + r.0.into_group() * x_inv_sq;
        }
        
        // Use Shamir's trick for combined scalar multiplication
        let ab = proof.a * proof.b;
        let expected = shamir_triple_mul(
            &proof.a, &proof.g_final.0,
            &proof.b, &proof.h_final.0,
            &ab, &self.params.u
        );
        
        Ok(p_prime == expected)
    }
    
    fn compute_final_generators(&self, challenges: &[Fr]) -> Result<(G1Projective, G1Projective), IPAError> {
        let n = self.params.n;
        let k = challenges.len();
        
        let mut s_g = vec![Fr::one(); n];
        let mut s_h = vec![Fr::one(); n];
        
        for (j, x) in challenges.iter().enumerate() {
            let x_inv = invert_challenge(*x)?;
            for i in 0..n {
                let bit = (i >> (k - 1 - j)) & 1;
                if bit == 1 {
                    s_g[i] *= *x;
                    s_h[i] *= x_inv;
                } else {
                    s_g[i] *= x_inv;
                    s_h[i] *= *x;
                }
            }
        }
        
        Ok((
            G1Projective::msm(&self.params.g, &s_g).map_err(|_| IPAError::MsmFailed)?,
            G1Projective::msm(&self.params.h, &s_h).map_err(|_| IPAError::MsmFailed)?,
        ))
    }
}

fn domain_tag() -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(b"GLYPH_IPA_TRANSCRIPT");
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

pub struct Transcript {
    seed: [u8; 32],
    domain_tag: [u8; 32],
}

impl Transcript {
    /// Create a new transcript with GLYPH domain separation
    pub fn new(label: &[u8]) -> Self {
        let domain_tag = domain_tag();
        let mut keccak = Keccak::v256();
        keccak.update(&domain_tag);
        keccak.update(label);
        let mut seed = [0u8; 32];
        keccak.finalize(&mut seed);
        Self { seed, domain_tag }
    }

    /// Create a transcript seeded exactly like the on-chain verifier
    /// (seed = 0, domain separation only).
    pub fn new_onchain() -> Self {
        let domain_tag = domain_tag();
        let seed = [0u8; 32];
        Self { seed, domain_tag }
    }

    fn keccak256_with_domain(&self, data: &[u8]) -> [u8; 32] {
        let mut keccak = Keccak::v256();
        // Domain separation: D_transcript || data
        keccak.update(&self.domain_tag);
        keccak.update(data);
        let mut out = [0u8; 32];
        keccak.finalize(&mut out);
        out
    }

    /// Append an affine point to the transcript:
    /// seed = H(D_transcript || seed || P_x || P_y)
    pub fn append_point(&mut self, point: &G1Affine) {
        let x_bytes = point.x.into_bigint().to_bytes_be();
        let y_bytes = point.y.into_bigint().to_bytes_be();

        let mut input = [0u8; 96];
        input[0..32].copy_from_slice(&self.seed);
        input[32..64].copy_from_slice(&x_bytes);
        input[64..96].copy_from_slice(&y_bytes);

        self.seed = self.keccak256_with_domain(&input);
    }

    /// Append arbitrary bytes to the transcript:
    /// seed = H(D_transcript || seed || data)
    pub fn append_bytes(&mut self, data: &[u8]) {
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(data);
        self.seed = self.keccak256_with_domain(&input);
    }

    /// Derive a non-zero scalar challenge from the transcript:
    /// x = seed mod 2^128, if x=0 then x=1
    pub fn challenge_scalar(&mut self) -> Fr {
        // Match Solidity: take low 128 bits via AND with 2^128-1 by zeroing upper 16 bytes
        let mut bytes = self.seed;
        bytes[..16].fill(0);

        let mut x = Fr::from_be_bytes_mod_order(&bytes);
        if x.is_zero() {
            x = Fr::one();
        }
        x
    }
    
    /// Update seed after extracting challenge (for next round)
    pub fn advance(&mut self) {
        self.seed = self.keccak256_with_domain(&self.seed);
    }
}

/// Hash-to-curve used by GLYPH: HashToG1(label, i)
/// Input: ASCII label, 64-bit index i encoded big-endian
fn hash_to_g1_indexed(label: &str, index: u64) -> G1Affine {
    let mut counter = 0u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update(index.to_be_bytes());
        hasher.update(counter.to_be_bytes());
        let hash = hasher.finalize();
        let x = ark_bn254::Fq::from_be_bytes_mod_order(&hash);
        if let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) {
            if point.is_on_curve() && !point.is_zero() {
                return point;
            }
        }
        counter += 1;
    }
}

// ============================================================================
//                               TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;

    #[test]
    fn test_roundtrip_small_n() {
        let params = IPAParams::new(4);
        let mut rng = test_rng();

        let a: Vec<Fr> = (0..params.n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..params.n).map(|_| Fr::rand(&mut rng)).collect();

        let prover = IPAProver { params: &params };
        let (p, c, proof) = match prover.prove_optimized(&a, &b) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "prove");
                return;
            }
        };

        let verifier = IPAVerifier { params: &params };
        let verified = verifier.verify_optimized(&p, c, &proof).unwrap_or_else(|_| {
            assert!(false, "verify");
            false
        });
        assert!(verified);
        let verified_hint = verifier.verify_with_trusted_hints(&p, &proof).unwrap_or_else(|_| {
            assert!(false, "verify");
            false
        });
        assert!(verified_hint);
    }

    #[test]
    fn test_soundness_rejects_wrong_commitment() {
        let params = IPAParams::new(4);
        let mut rng = test_rng();

        let a: Vec<Fr> = (0..params.n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..params.n).map(|_| Fr::rand(&mut rng)).collect();

        let prover = IPAProver { params: &params };
        let (p, c, proof) = match prover.prove_optimized(&a, &b) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "prove");
                return;
            }
        };

        let verifier = IPAVerifier { params: &params };
        let verified = verifier.verify_optimized(&p, c, &proof).unwrap_or_else(|_| {
            assert!(false, "verify");
            false
        });
        assert!(verified);

        let wrong_p = p + params.u;
        let rejected = verifier.verify_optimized(&wrong_p, c, &proof).unwrap_or_else(|_| {
            assert!(false, "verify");
            false
        });
        assert!(!rejected);
    }

    #[test]
    fn test_verifier_consistency_across_n() {
        for &n in &[4usize, 8, 16] {
            let params = IPAParams::new(n);
            let mut rng = test_rng();

            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

            let prover = IPAProver { params: &params };
            let (p_std, c_std, proof_std) = match prover.prove(&a, &b) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "prove");
                    return;
                }
            };
            let (p_opt, c_opt, proof_opt) = match prover.prove_optimized(&a, &b) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "prove");
                    return;
                }
            };

            let verifier = IPAVerifier { params: &params };

            let verified = verifier.verify(&p_std, c_std, &proof_std).unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            });
            assert!(verified);
            let verified_opt = verifier.verify_optimized(&p_opt, c_opt, &proof_opt).unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            });
            assert!(verified_opt);
            let verified_hint = verifier.verify_with_trusted_hints(&p_opt, &proof_opt).unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            });
            assert!(verified_hint);

            assert_eq!(p_std, p_opt);
            assert_eq!(c_std, c_opt);
        }
    }

    /// Test domain separation tag
    #[test]
    fn test_domain_separation() {
        let tag = domain_tag();
        // D_transcript = keccak256("GLYPH_IPA_TRANSCRIPT")
        assert_ne!(tag, [0u8; 32], "Domain tag must not be zero");
        
        // Verify deterministic
        let tag2 = domain_tag();
        assert_eq!(tag, tag2, "Domain tag must be deterministic");
        
        println!("Domain tag: 0x{}", hex::encode(tag));
    }

    #[test]
    fn test_transcript_label_initialization() {
        let mut t1 = Transcript::new(b"glyph_ipa");
        let mut t2 = Transcript::new(b"glyph_ipa_alt");
        let c1 = t1.challenge_scalar();
        let c2 = t2.challenge_scalar();
        assert_ne!(c1, c2, "Transcript label must affect initialization");
    }

    #[test]
    fn test_challenge_scalar_nonzero_on_onchain_seed() {
        let mut transcript = Transcript::new_onchain();
        let x = transcript.challenge_scalar();
        assert!(!x.is_zero(), "challenge scalar must be non-zero");
    }

    #[test]
    fn test_invert_challenge_zero_returns_error() {
        let err = invert_challenge(Fr::zero()).err();
        assert!(err.is_some(), "zero challenge must return error");
    }
    
    /// Stress test with many random proof generations
    #[test]
    fn test_fuzz_proofs() {
        let n = 4usize;
        let params = IPAParams::new(n);
        let prover = IPAProver { params: &params };
        let verifier = IPAVerifier { params: &params };
        let mut rng = test_rng();
        
        const NUM_PROOFS: usize = 64;
        let mut valid_count = 0;
        let mut invalid_count = 0;
        
        println!("\n=== FUZZ TEST: {} random proofs ===", NUM_PROOFS);
        
        for i in 0..NUM_PROOFS {
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            
            let (p, c, proof) = match prover.prove_optimized(&a, &b) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "prove");
                    return;
                }
            };
            
            // Valid proof
            if verifier.verify_optimized(&p, c, &proof).unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            }) {
                valid_count += 1;
            }
            
            // Tampered proof (modify a slightly)
            let mut tampered_proof = proof.clone();
            tampered_proof.a += Fr::one();
            if !verifier.verify_optimized(&p, c, &tampered_proof).unwrap_or_else(|_| {
                assert!(false, "verify");
                false
            }) {
                invalid_count += 1;
            }
            
            if i % 5 == 0 {
                println!("  Progress: {}/{}", i + 1, NUM_PROOFS);
            }
        }
        
        assert_eq!(valid_count, NUM_PROOFS, "All valid proofs must verify");
        assert_eq!(invalid_count, NUM_PROOFS, "All tampered proofs must fail");
        
        println!("  Valid proofs: {}/{}", valid_count, NUM_PROOFS);
        println!("  Tampered rejected: {}/{}", invalid_count, NUM_PROOFS);
        println!("=== FUZZ TEST PASSED ===\n");
    }
}
