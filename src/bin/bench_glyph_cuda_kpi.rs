use std::time::Instant;

use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;

use glyph::glyph_field_simd::{
    Goldilocks, SimdBackend,
    goldilocks_add_batch, goldilocks_sub_batch, goldilocks_mul_batch,
    goldilocks_scalar_mul_batch, goldilocks_sum, goldilocks_inner_product,
    cuda_inner_product, cuda_pairwise_product, cuda_sumcheck_even_odd, cuda_sumcheck_next_layer,
    cuda_col_combinations_row_major, cuda_keccak256_batch_64, cuda_keccak256_rows_domain,
};
use glyph::glyph_transcript::keccak256_batch_64;
use tiny_keccak::Hasher;

#[derive(Clone, Debug)]
struct BenchResult {
    name: &'static str,
    n: usize,
    used_cuda: bool,
    ms: u128,
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn cuda_min_elems() -> usize {
    env_usize("GLYPH_CUDA_MIN_ELEMS", 1 << 14).max(1)
}

fn bench<F: FnOnce()>(name: &'static str, n: usize, used_cuda: bool, f: F) -> BenchResult {
    let start = Instant::now();
    f();
    BenchResult {
        name,
        n,
        used_cuda,
        ms: start.elapsed().as_millis(),
    }
}

fn main() {
    let n = env_usize("GLYPH_CUDA_KPI_N", 1 << 20);
    let rows = env_usize("GLYPH_CUDA_KPI_ROWS", 1 << 10);
    let cols = env_usize("GLYPH_CUDA_KPI_COLS", 1 << 10);
    let hash_count = env_usize("GLYPH_CUDA_KPI_HASHES", 1 << 14);
    let seed = env_u64("GLYPH_CUDA_KPI_SEED", 0xC0DE_CAFE);
    let min_elems = cuda_min_elems();

    let backend = SimdBackend::detect();
    let cuda_requested = std::env::var("GLYPH_CUDA")
        .ok()
        .map(|v| v != "0" && v != "false")
        .unwrap_or(false);
    let cuda_available = matches!(backend, SimdBackend::Cuda);

    let mut rng = StdRng::seed_from_u64(seed);

    let mut a = vec![Goldilocks::ZERO; n];
    let mut b = vec![Goldilocks::ZERO; n];
    for i in 0..n {
        a[i] = Goldilocks::new(rng.next_u64());
        b[i] = Goldilocks::new(rng.next_u64());
    }

    let mut checksum: u64 = 0;
    let mut results = Vec::new();

    let used_cuda_batch = cuda_available && n >= min_elems;
    results.push(bench("goldilocks_add_batch", n, used_cuda_batch, || {
        let out = goldilocks_add_batch(&a, &b);
        checksum ^= out[0].0;
    }));
    results.push(bench("goldilocks_sub_batch", n, used_cuda_batch, || {
        let out = goldilocks_sub_batch(&a, &b);
        checksum ^= out[1].0;
    }));
    results.push(bench("goldilocks_mul_batch", n, used_cuda_batch, || {
        let out = goldilocks_mul_batch(&a, &b);
        checksum ^= out[2].0;
    }));
    results.push(bench("goldilocks_scalar_mul_batch", n, used_cuda_batch, || {
        let out = goldilocks_scalar_mul_batch(Goldilocks::new(7), &a);
        checksum ^= out[3].0;
    }));
    results.push(bench("goldilocks_sum", n, used_cuda_batch, || {
        let v = goldilocks_sum(&a);
        checksum ^= v.0;
    }));
    results.push(bench("goldilocks_inner_product", n, used_cuda_batch, || {
        let v = match cuda_inner_product(&a, &b) {
            Some(v) => v,
            None => goldilocks_inner_product(&a, &b),
        };
        checksum ^= v.0;
    }));

    let pair_n = (n / 2).max(1) * 2;
    let mut pair_out = vec![Goldilocks::ZERO; pair_n / 2];
    results.push(bench("pairwise_product", pair_n, cuda_available && pair_n >= min_elems, || {
        let used = cuda_pairwise_product(&a[..pair_n], &mut pair_out);
        if !used {
            for i in 0..pair_n / 2 {
                pair_out[i] = a[2 * i] * a[2 * i + 1];
            }
        }
        checksum ^= pair_out[0].0;
    }));

    results.push(bench("sumcheck_even_odd", pair_n, cuda_available && pair_n >= min_elems, || {
        let res = cuda_sumcheck_even_odd(&a[..pair_n]);
        let (y0, y1) = match res {
            Some(v) => v,
            None => {
                let mut y0 = Goldilocks::ZERO;
                let mut y1 = Goldilocks::ZERO;
                for i in 0..(pair_n / 2) {
                    y0 = y0 + a[2 * i];
                    y1 = y1 + a[2 * i + 1];
                }
                (y0, y1)
            }
        };
        checksum ^= y0.0 ^ y1.0;
    }));

    let mut next_layer = vec![Goldilocks::ZERO; pair_n / 2];
    let r = Goldilocks::new(17);
    results.push(bench("sumcheck_next_layer", pair_n, cuda_available && pair_n >= min_elems, || {
        let used = cuda_sumcheck_next_layer(&a[..pair_n], r, &mut next_layer);
        if !used {
            let one_minus = Goldilocks::ONE - r;
            for i in 0..(pair_n / 2) {
                let lo = a[2 * i];
                let hi = a[2 * i + 1];
                next_layer[i] = lo * one_minus + hi * r;
            }
        }
        checksum ^= next_layer[0].0;
    }));

    let matrix_len = rows.saturating_mul(cols).max(1);
    let mut matrix = vec![Goldilocks::ZERO; matrix_len];
    for v in &mut matrix {
        *v = Goldilocks::new(rng.next_u64());
    }
    let mut rho = vec![Goldilocks::ZERO; cols.max(1)];
    for v in &mut rho {
        *v = Goldilocks::new(rng.next_u64());
    }
    let mut col_out = vec![Goldilocks::ZERO; rows.max(1)];
    results.push(bench("pcs_col_combinations", matrix_len, cuda_available && cols >= min_elems, || {
        let used = cuda_col_combinations_row_major(&matrix, rows, cols, &rho, &mut col_out);
        if !used {
            for (r_idx, out) in col_out.iter_mut().enumerate().take(rows) {
                let mut acc = Goldilocks::ZERO;
                let base = r_idx * cols;
                for c in 0..cols {
                    acc = acc + matrix[base + c] * rho[c];
                }
                *out = acc;
            }
        }
        checksum ^= col_out[0].0;
    }));

    let mut hash_inputs = Vec::with_capacity(hash_count);
    for _ in 0..hash_count {
        let mut block = [0u8; 64];
        rng.fill_bytes(&mut block);
        hash_inputs.push(block);
    }
    results.push(bench("keccak256_batch_64", hash_count, cuda_available && hash_count >= min_elems, || {
        let hashes = match cuda_keccak256_batch_64(&hash_inputs) {
            Some(v) => v,
            None => keccak256_batch_64(&hash_inputs),
        };
        checksum ^= hashes[0][0] as u64;
    }));

    let prefix = b"GLYPH_PCS_ROW".to_vec();
    results.push(bench("keccak256_rows_domain", rows, cuda_available && rows >= min_elems, || {
        let hashes = match cuda_keccak256_rows_domain(&matrix, rows, cols, &prefix) {
            Some(v) => v,
            None => {
                let mut out = vec![[0u8; 32]; rows];
                for i in 0..rows {
                    let mut hasher = tiny_keccak::Keccak::v256();
                    hasher.update(&prefix);
                    for v in &matrix[i * cols..(i + 1) * cols] {
                        hasher.update(&v.0.to_le_bytes());
                    }
                    hasher.finalize(&mut out[i]);
                }
                out
            }
        };
        checksum ^= hashes[0][0] as u64;
    }));

    let mut results_json = String::new();
    for (idx, r) in results.iter().enumerate() {
        if idx > 0 {
            results_json.push(',');
        }
        results_json.push_str(&format!(
            "{{\"name\":\"{}\",\"n\":{},\"cuda\":{},\"ms\":{}}}",
            r.name, r.n, r.used_cuda, r.ms
        ));
    }

    println!(
        "{{\"backend\":\"{:?}\",\"cuda_requested\":{},\"cuda_min_elems\":{},\"results\":[{}],\"checksum\":{}}}",
        backend, cuda_requested, min_elems, results_json, checksum
    );
}
