//! Parallel IPA prover using Rayon.

use crate::ipa_bn254::{IPAParams, IPAProofOptimized, CompressedG1, Transcript, pippenger_msm, IPAError};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use rayon::prelude::*;

pub struct ParallelProver<'a> {
    pub params: &'a IPAParams,
}

impl<'a> ParallelProver<'a> {
    fn parallel_msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Projective, IPAError> {
        let chunk_size = (bases.len() / rayon::current_num_threads()).max(64);
        bases
            .par_chunks(chunk_size)
            .zip(scalars.par_chunks(chunk_size))
            .map(|(b, s)| pippenger_msm(b, s))
            .try_reduce(|| G1Projective::zero(), |a, b| Ok(a + b))
    }
    
    fn parallel_inner_product(a: &[Fr], b: &[Fr]) -> Fr {
        a.par_iter()
            .zip(b.par_iter())
            .map(|(ai, bi)| *ai * *bi)
            .reduce(Fr::zero, |acc, x| acc + x)
    }
    
    fn parallel_fold_vectors(lo: &[Fr], hi: &[Fr], x: Fr, x_inv: Fr) -> Vec<Fr> {
        lo.par_iter()
            .zip(hi.par_iter())
            .map(|(l, h)| *l * x + *h * x_inv)
            .collect()
    }
    
    fn parallel_fold_generators(lo: &[G1Affine], hi: &[G1Affine], x: Fr, x_inv: Fr) -> Vec<G1Affine> {
        lo.par_iter()
            .zip(hi.par_iter())
            .map(|(l, h)| {
                (l.into_group() * x_inv + h.into_group() * x).into_affine()
            })
            .collect()
    }
    
    pub fn prove_parallel(&self, a: &[Fr], b: &[Fr]) -> Result<(G1Projective, Fr, IPAProofOptimized), IPAError> {
        let c = Self::parallel_inner_product(a, b);
        
        // Parallel commitment
        let p = Self::parallel_msm(&self.params.g, a)?
              + Self::parallel_msm(&self.params.h, b)?
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
            let (a_lo, a_hi) = a.split_at(half);
            let (b_lo, b_hi) = b.split_at(half);
            let (g_lo, g_hi) = g.split_at(half);
            let (h_lo, h_hi) = h.split_at(half);
            
            let (l_res, r_res) = rayon::join(
                || {
                    let c_l = Self::parallel_inner_product(a_lo, b_hi);
                    let l = Self::parallel_msm(g_hi, a_lo)?
                        + Self::parallel_msm(h_lo, b_hi)?
                        + self.params.u * c_l;
                    Ok(l)
                },
                || {
                    let c_r = Self::parallel_inner_product(a_hi, b_lo);
                    let r = Self::parallel_msm(g_lo, a_hi)?
                        + Self::parallel_msm(h_hi, b_lo)?
                        + self.params.u * c_r;
                    Ok(r)
                }
            );

            let l = l_res?;
            let r = r_res?;
            
            let l_aff = l.into_affine();
            let r_aff = r.into_affine();
            
            l_vec.push(CompressedG1(l_aff));
            r_vec.push(CompressedG1(r_aff));
            
            transcript.append_point(&l_aff);
            transcript.append_point(&r_aff);
            let x = transcript.challenge_scalar();
            let x_inv = x.inverse().ok_or(IPAError::ZeroChallenge)?;
            
            let ((new_a, new_b), (new_g, new_h)) = rayon::join(
                || rayon::join(
                    || Self::parallel_fold_vectors(a_lo, a_hi, x, x_inv),
                    || Self::parallel_fold_vectors(b_lo, b_hi, x_inv, x)
                ),
                || rayon::join(
                    || Self::parallel_fold_generators(g_lo, g_hi, x, x_inv),
                    || Self::parallel_fold_generators(h_lo, h_hi, x_inv, x)
                )
            );
            
            a = new_a;
            b = new_b;
            g = new_g;
            h = new_h;
        }
        
        let g_final = CompressedG1(g[0]);
        let h_final = CompressedG1(h[0]);
        
        Ok((p, c, IPAProofOptimized {
            l_vec, r_vec,
            a: a[0], b: b[0],
            g_final, h_final
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use crate::ipa_bn254::{IPAProver, IPAVerifier};
    use std::time::Instant;
    
    #[test]
    fn test_parallel_prover() {
        let n = 64;
        let params = IPAParams::new(n);
        
        let mut rng = test_rng();
        let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Sequential prover
        let seq_prover = IPAProver { params: &params };
        let start = Instant::now();
        let (p1, c1, _proof1) = match seq_prover.prove_optimized(&a, &b) {
            Ok(out) => out,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };
        let seq_time = start.elapsed();
        
        // Parallel prover
        let par_prover = ParallelProver { params: &params };
        let start = Instant::now();
        let (p2, c2, proof2) = match par_prover.prove_parallel(&a, &b) {
            Ok(out) => out,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };
        let par_time = start.elapsed();
        
        // Verify parallel proof
        let verifier = IPAVerifier { params: &params };
        let valid = match verifier.verify_with_trusted_hints(&p2, &proof2) {
            Ok(valid) => valid,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        
        println!("=== PARALLEL PROVER BENCHMARK ===");
        println!("Sequential: {:?}", seq_time);
        println!("Parallel:   {:?}", par_time);
        println!("Speedup:    {:.2}x", seq_time.as_secs_f64() / par_time.as_secs_f64());
        println!("Valid:      {}", if valid { "true" } else { "false" });
        
        assert!(valid);
        assert_eq!(p1, p2);
        assert_eq!(c1, c2);
    }
    
    #[test]
    fn benchmark_large_n() {
        for n in [64, 256, 1024] {
            let params = IPAParams::new(n);
            
            let mut rng = test_rng();
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            
            let par_prover = ParallelProver { params: &params };
            let start = Instant::now();
            if let Err(err) = par_prover.prove_parallel(&a, &b) {
                assert!(false, "prove: {err:?}");
                return;
            }
            let time = start.elapsed();
            
            println!("N={}: {:?}", n, time);
        }
    }
}
