//! SIMD-Accelerated Parallel Prover
//!
//! Combines SIMD-optimized field operations from `glyph_field_simd` with Rayon-based
//! parallelization for multi-threaded MSM and vector operations. Performance
//! gains scale with both SIMD width (AVX-512 > AVX2 > NEON > scalar) and
//! available CPU cores.

use crate::ipa_bn254::{IPAParams, IPAProofOptimized, CompressedG1, Transcript, pippenger_msm, IPAError};
use crate::glyph_field_simd::simd_inner_product;
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use rayon::prelude::*;

/// SIMD-Optimized IPA Prover
pub struct SimdProver<'a> {
    pub params: &'a IPAParams,
}

impl<'a> SimdProver<'a> {
    /// Prove with maximum SIMD acceleration
    /// Uses same algorithm as standard prover for compatibility
    pub fn prove_simd(&self, a: &[Fr], b: &[Fr]) -> Result<(G1Projective, Fr, IPAProofOptimized), IPAError> {
        let n = a.len();
        assert_eq!(n, b.len());
        assert!(n.is_power_of_two());
        
        // Use SIMD for inner product
        let c = simd_inner_product(a, b);
        
        // Commitment: P = <a, G> + <b, H> + c * U (parallel)
        let p = self.compute_commitment_parallel(a, b, &c)?;
        
        // Initialize mutable vectors for folding
        let mut a_vec = a.to_vec();
        let mut b_vec = b.to_vec();
        let mut g = self.params.g.clone();
        let mut h = self.params.h.clone();
        
        let mut l_vec = Vec::new();
        let mut r_vec = Vec::new();
        
        // Use same transcript as standard prover!
        let mut transcript = Transcript::new_onchain();
        transcript.append_point(&p.into_affine());
        
        while a_vec.len() > 1 {
            let half = a_vec.len() / 2;
            
            // Split vectors
            let (a_lo, a_hi) = (&a_vec[..half], &a_vec[half..]);
            let (b_lo, b_hi) = (&b_vec[..half], &b_vec[half..]);
            let (g_lo, g_hi) = (&g[..half], &g[half..]);
            let (h_lo, h_hi) = (&h[..half], &h[half..]);
            
            // L = <a_lo, G_hi> + <b_hi, H_lo> + <a_lo, b_hi> * U
            // (Same as standard prover!)
            let c_l = simd_inner_product(a_lo, b_hi);
            let l = self.compute_lr_parallel(a_lo, g_hi, b_hi, h_lo, &c_l)?;
            
            // R = <a_hi, G_lo> + <b_lo, H_hi> + <a_hi, b_lo> * U
            let c_r = simd_inner_product(a_hi, b_lo);
            let r = self.compute_lr_parallel(a_hi, g_lo, b_lo, h_hi, &c_r)?;
            
            let l_aff = l.into_affine();
            let r_aff = r.into_affine();
            
            l_vec.push(CompressedG1(l_aff));
            r_vec.push(CompressedG1(r_aff));
            
            // Same transcript operations
            transcript.append_point(&l_aff);
            transcript.append_point(&r_aff);
            let x = transcript.challenge_scalar();
            let x_inv = x.inverse().ok_or(IPAError::ZeroChallenge)?;
            
            // Fold vectors (same as standard prover equations)
            // a' = a_lo * x + a_hi * x_inv
            a_vec = a_lo.par_iter().zip(a_hi.par_iter())
                .map(|(lo, hi)| *lo * x + *hi * x_inv)
                .collect();
            
            // b' = b_lo * x_inv + b_hi * x
            b_vec = b_lo.par_iter().zip(b_hi.par_iter())
                .map(|(lo, hi)| *lo * x_inv + *hi * x)
                .collect();
            
            // g' = g_lo * x_inv + g_hi * x
            g = g_lo.par_iter().zip(g_hi.par_iter())
                .map(|(lo, hi)| (lo.into_group() * x_inv + hi.into_group() * x).into_affine())
                .collect();
            
            // h' = h_lo * x + h_hi * x_inv
            h = h_lo.par_iter().zip(h_hi.par_iter())
                .map(|(lo, hi)| (lo.into_group() * x + hi.into_group() * x_inv).into_affine())
                .collect();
        }
        
        let proof = IPAProofOptimized {
            l_vec,
            r_vec,
            a: a_vec[0],
            b: b_vec[0],
            g_final: CompressedG1(g[0]),
            h_final: CompressedG1(h[0]),
        };
        
        Ok((p, c, proof))
    }
    
    /// Parallel commitment computation
    fn compute_commitment_parallel(&self, a: &[Fr], b: &[Fr], c: &Fr) -> Result<G1Projective, IPAError> {
        let (ag, bh) = rayon::join(
            || pippenger_msm(&self.params.g, a),
            || pippenger_msm(&self.params.h, b),
        );

        Ok(ag? + bh? + self.params.u * c)
    }
    
    /// Parallel L/R computation
    fn compute_lr_parallel(
        &self,
        a: &[Fr], g: &[G1Affine],
        b: &[Fr], h: &[G1Affine],
        scalar: &Fr
    ) -> Result<G1Projective, IPAError> {
        let (ag, bh) = rayon::join(
            || pippenger_msm(g, a),
            || pippenger_msm(h, b),
        );

        Ok(ag? + bh? + self.params.u * scalar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipa_bn254::{IPAProver, IPAVerifier};
    use crate::glyph_field_simd::SimdBackend;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use std::time::Instant;
    
    #[test]
    fn test_simd_prover_correctness() {
        let mut rng = test_rng();
        let n = 64;
        
        let params = IPAParams::new(n);
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // SIMD prover
        let simd_prover = SimdProver { params: &params };
        let (p, ip, proof) = match simd_prover.prove_simd(&a, &b) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "prove");
                return;
            }
        };
        
        // Verify with standard verifier
        let verifier = IPAVerifier { params: &params };
        let valid = match verifier.verify_with_trusted_hints(&p, &proof) {
            Ok(value) => value,
            Err(_) => {
                assert!(false, "verify");
                return;
            }
        };
        
        assert!(valid, "SIMD proof verification failed");
        
        // Check inner product
        let expected_ip: Fr = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).sum();
        assert_eq!(ip, expected_ip, "Inner product mismatch");
        
        println!("SIMD prover correctness test passed.");
    }
    
    #[test]
    fn benchmark_simd_vs_standard() {
        let mut rng = test_rng();
        let sizes = [64, 256, 1024];
        
        println!("\n=== SIMD PROVER BENCHMARK ===");
        println!("Backend: {:?}\n", SimdBackend::detect_cpu());
        
        for n in sizes {
            let params = IPAParams::new(n);
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            
            // Standard prover
            let std_prover = IPAProver { params: &params };
            let start = Instant::now();
            let _ = match std_prover.prove_optimized(&a, &b) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "prove");
                    return;
                }
            };
            let std_time = start.elapsed();
            
            // SIMD prover
            let simd_prover = SimdProver { params: &params };
            let start = Instant::now();
            let _ = match simd_prover.prove_simd(&a, &b) {
                Ok(value) => value,
                Err(_) => {
                    assert!(false, "prove");
                    return;
                }
            };
            let simd_time = start.elapsed();
            
            let speedup = std_time.as_secs_f64() / simd_time.as_secs_f64();
            
            println!("N={:5} | Standard: {:>8.2?} | SIMD: {:>8.2?} | Speedup: {:.2}×",
                     n, std_time, simd_time, speedup);
        }
    }
}
