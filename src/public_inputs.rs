//! Public inputs extension for IPA proofs.

use crate::ipa_bn254::{IPAParams, IPAProver, IPAProofOptimized, IPAVerifier, IPAError};
use ark_bn254::{Fr, G1Projective};
use ark_ff::{Zero, One};

#[derive(Clone, Debug)]
pub struct PublicProof {
    pub public_inputs: Vec<Fr>,
    pub ipa_proof: IPAProofOptimized,
    pub commitment: G1Projective,
}

impl PublicProof {
    pub fn size(&self) -> usize {
        self.public_inputs.len() * 32 + self.ipa_proof.size() + 64
    }
}

pub struct PublicProver<'a> {
    pub params: &'a IPAParams,
    pub num_public: usize,
}

impl<'a> PublicProver<'a> {
    pub fn prove(&self, witness: &[Fr]) -> Result<PublicProof, IPAError> {
        assert!(witness.len() >= self.num_public);
        assert!(witness.len() <= self.params.n);
        
        let public_inputs: Vec<Fr> = witness[..self.num_public].to_vec();
        let mut a = witness.to_vec();
        a.resize(self.params.n, Fr::zero());
        
        let b: Vec<Fr> = vec![Fr::one(); self.params.n];
        let ipa_prover = IPAProver { params: self.params };
        let (commitment, _c, ipa_proof) = ipa_prover.prove_optimized(&a, &b)?;
        
        Ok(PublicProof {
            public_inputs,
            ipa_proof,
            commitment,
        })
    }
}

pub struct PublicVerifier<'a> {
    pub params: &'a IPAParams,
    pub num_public: usize,
}

impl<'a> PublicVerifier<'a> {
    pub fn verify(&self, proof: &PublicProof, expected_public: &[Fr]) -> Result<bool, IPAError> {
        if proof.public_inputs.len() != expected_public.len() {
            return Ok(false);
        }
        
        for (got, expected) in proof.public_inputs.iter().zip(expected_public) {
            if got != expected {
                return Ok(false);
            }
        }
        
        let ipa_verifier = IPAVerifier { params: self.params };
        ipa_verifier.verify_optimized(&proof.commitment, Fr::one(), &proof.ipa_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    
    #[test]
    fn test_public_inputs() {
        let n = 16;
        let num_public = 4;
        
        let params = IPAParams::new(n);
        let prover = PublicProver { params: &params, num_public };
        let verifier = PublicVerifier { params: &params, num_public };
        
        // Create witness with public inputs
        let mut rng = test_rng();
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        let proof = match prover.prove(&witness) {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };
        
        println!("Public inputs: {:?}", proof.public_inputs.len());
        println!("Proof size: {} bytes", proof.size());
        
        // Verify with correct public inputs
        let valid = match verifier.verify(&proof, &witness[..num_public]) {
            Ok(valid) => valid,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        assert!(valid, "Proof should be valid with correct public inputs");
        
        // Verify fails with wrong public inputs
        let mut wrong_public = witness[..num_public].to_vec();
        wrong_public[0] = Fr::from(12345u64);
        let invalid = match verifier.verify(&proof, &wrong_public) {
            Ok(invalid) => invalid,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        assert!(!invalid, "Proof should be invalid with wrong public inputs");
        
        println!("Public inputs test passed.");
    }
    
    #[test]
    fn stress_test_large_witness() {
        let n = 256;
        let num_public = 10;
        
        let params = IPAParams::new(n);
        let prover = PublicProver { params: &params, num_public };
        let verifier = PublicVerifier { params: &params, num_public };
        
        let mut rng = test_rng();
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        use std::time::Instant;
        
        let start = Instant::now();
        let proof = match prover.prove(&witness) {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };
        let prove_time = start.elapsed();
        
        let start = Instant::now();
        let valid = match verifier.verify(&proof, &witness[..num_public]) {
            Ok(valid) => valid,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        let verify_time = start.elapsed();
        
        assert!(valid);
        
        println!("=== STRESS TEST N=256 ===");
        println!("Prove time:  {:?}", prove_time);
        println!("Verify time: {:?}", verify_time);
        println!("Proof size:  {} bytes", proof.size());
    }

    #[test]
    fn test_public_inputs_length_mismatch() {
        let n = 16;
        let num_public = 4;

        let params = IPAParams::new(n);
        let prover = PublicProver { params: &params, num_public };
        let verifier = PublicVerifier { params: &params, num_public };

        let mut rng = test_rng();
        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let proof = match prover.prove(&witness) {
            Ok(proof) => proof,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };

        // shorter expected_public
        let short = &witness[..num_public - 1];
        let short_ok = match verifier.verify(&proof, short) {
            Ok(ok) => ok,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        assert!(!short_ok);

        // longer expected_public
        let mut long = witness[..num_public].to_vec();
        long.push(Fr::one());
        let long_ok = match verifier.verify(&proof, &long) {
            Ok(ok) => ok,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        assert!(!long_ok);
    }

    #[test]
    fn test_public_inputs_zero_and_all_public() {
        let n = 8;
        let params = IPAParams::new(n);
        let mut rng = test_rng();

        let witness: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // zero public
        let prover0 = PublicProver { params: &params, num_public: 0 };
        let verifier0 = PublicVerifier { params: &params, num_public: 0 };
        let proof0 = match prover0.prove(&witness) {
            Ok(proof0) => proof0,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };
        assert!(proof0.public_inputs.is_empty());
        let ok0 = match verifier0.verify(&proof0, &[]) {
            Ok(ok0) => ok0,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        assert!(ok0);

        // all elements public
        let prover_all = PublicProver { params: &params, num_public: n };
        let verifier_all = PublicVerifier { params: &params, num_public: n };
        let proof_all = match prover_all.prove(&witness) {
            Ok(proof_all) => proof_all,
            Err(err) => {
                assert!(false, "prove: {err:?}");
                return;
            }
        };
        assert_eq!(proof_all.public_inputs.len(), n);
        let ok_all = match verifier_all.verify(&proof_all, &witness[..]) {
            Ok(ok_all) => ok_all,
            Err(err) => {
                assert!(false, "verify: {err:?}");
                return;
            }
        };
        assert!(ok_all);
    }
}
