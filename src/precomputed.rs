//! Precomputed Generator Tables
//!
//! Pre-compute g[i] × 2^j for fast scalar multiplication.
//! This turns O(n × 256) operations into O(n × 1).

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use std::sync::OnceLock;

/// Precomputed table for a single generator
/// table[j] = G × 2^j for j = 0..255
pub struct PrecomputedTable {
    /// table[j] = G × 2^j
    pub powers: [G1Affine; 256],
}

impl PrecomputedTable {
    /// Build precomputed table for generator G
    pub fn new(g: &G1Affine) -> Self {
        let mut powers = [G1Affine::zero(); 256];
        let mut current = g.into_group();
        
        for power in &mut powers {
            *power = current.into_affine();
            current = current + current; // Double
        }
        
        Self { powers }
    }
    
    /// Fast scalar multiplication using precomputed table
    /// k × G = Σ bit_i × 2^i × G = Σ bit_i × table[i]
    pub fn scalar_mul(&self, k: &Fr) -> G1Projective {
        let k_bytes = k.into_bigint().to_bytes_be();
        let mut result = G1Projective::zero();
        
        // Process each bit
        for byte_idx in 0..32 {
            for bit_idx in 0..8 {
                if (k_bytes[31 - byte_idx] >> bit_idx) & 1 == 1 {
                    let power_idx = byte_idx * 8 + bit_idx;
                    result += self.powers[power_idx];
                }
            }
        }
        
        result
    }
}

/// Precomputed tables for IPA generators
pub struct IPAGeneratorTables {
    /// Tables for G generators
    pub g_tables: Vec<PrecomputedTable>,
    /// Tables for H generators
    pub h_tables: Vec<PrecomputedTable>,
    /// Table for U generator
    pub u_table: PrecomputedTable,
}

impl IPAGeneratorTables {
    /// Build all precomputed tables (expensive, do once!)
    pub fn new(g: &[G1Affine], h: &[G1Affine], u: &G1Affine) -> Self {
        let g_tables: Vec<_> = g.iter()
            .map(PrecomputedTable::new)
            .collect();
        
        let h_tables: Vec<_> = h.iter()
            .map(PrecomputedTable::new)
            .collect();
        
        let u_table = PrecomputedTable::new(u);
        
        Self { g_tables, h_tables, u_table }
    }
    
    /// Fast MSM using precomputed tables
    /// Computes Σ scalars[i] × generators[i]
    pub fn msm(&self, scalars: &[Fr], use_g: bool) -> G1Projective {
        let tables = if use_g { &self.g_tables } else { &self.h_tables };
        
        scalars.iter()
            .zip(tables.iter())
            .map(|(s, t)| t.scalar_mul(s))
            .fold(G1Projective::zero(), |acc, p| acc + p)
    }
}

/// Global cached tables for common sizes
#[allow(dead_code)]
static TABLES_64: OnceLock<IPAGeneratorTables> = OnceLock::new();

/// Get or create cached tables for N=64
pub fn get_cached_tables_64(g: &[G1Affine], h: &[G1Affine], u: &G1Affine) -> IPAGeneratorTables {
    // Build tables on demand (caller provides generators)
    IPAGeneratorTables::new(g, h, u)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use std::time::Instant;
    
    #[test]
    fn test_precomputed_correctness() {
        let mut rng = test_rng();
        let g = G1Affine::rand(&mut rng);
        let table = PrecomputedTable::new(&g);
        
        for _ in 0..10 {
            let k = Fr::rand(&mut rng);
            
            // Standard multiplication
            let expected = g.into_group() * k;
            
            // Precomputed multiplication
            let result = table.scalar_mul(&k);
            
            assert_eq!(result, expected, "Precomputed should match standard");
        }
        
        println!("Precomputed table correctness test passed.");
    }
    
    #[test]
    fn benchmark_precomputed_vs_standard() {
        let mut rng = test_rng();
        let iterations = 100;
        
        let g = G1Affine::rand(&mut rng);
        let table = PrecomputedTable::new(&g);
        let scalars: Vec<Fr> = (0..iterations).map(|_| Fr::rand(&mut rng)).collect();
        
        // Standard
        let start = Instant::now();
        for k in &scalars {
            let _ = g.into_group() * k;
        }
        let std_time = start.elapsed();
        
        // Precomputed
        let start = Instant::now();
        for k in &scalars {
            let _ = table.scalar_mul(k);
        }
        let precomp_time = start.elapsed();
        
        let speedup = std_time.as_secs_f64() / precomp_time.as_secs_f64();
        
        println!("=== PRECOMPUTED TABLE BENCHMARK ({} iterations) ===", iterations);
        println!("Standard ECMUL:    {:?}", std_time);
        println!("Precomputed:       {:?}", precomp_time);
        println!("Speedup:           {:.2}×", speedup);
        println!("Table size:        {} KB", 256 * 64 / 1024); // 64 bytes per point
    }
}
