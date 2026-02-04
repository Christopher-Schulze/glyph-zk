//! BN254 op events for GLYPH-PROVER compilation.

use crate::bn254_field::{
    bn254_add_mod_batch_cpu,
    bn254_add_mod_batch_with_min,
    bn254_cuda_min_elems,
    bn254_mul_mod_batch_cpu,
    bn254_mul_mod_batch_with_min,
    bn254_sub_mod_batch_cpu,
    bn254_sub_mod_batch_with_min,
    is_canonical_limbs,
};
use rayon::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bn254OpKind {
    Add,
    Sub,
    Mul,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254OpTraceEvent {
    pub kind: Bn254OpKind,
    pub a: [u64; 4],
    pub b: [u64; 4],
    pub out: [u64; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254TraceBatchKpi {
    pub add_count: usize,
    pub sub_count: usize,
    pub mul_count: usize,
    pub add_cuda: bool,
    pub sub_cuda: bool,
    pub mul_cuda: bool,
}

#[derive(Default)]
struct TraceBatchScratch {
    add_a: Vec<[u64; 4]>,
    add_b: Vec<[u64; 4]>,
    add_out: Vec<[u64; 4]>,
    add_idx: Vec<usize>,
    sub_a: Vec<[u64; 4]>,
    sub_b: Vec<[u64; 4]>,
    sub_out: Vec<[u64; 4]>,
    sub_idx: Vec<usize>,
    mul_a: Vec<[u64; 4]>,
    mul_b: Vec<[u64; 4]>,
    mul_out: Vec<[u64; 4]>,
    mul_idx: Vec<usize>,
    scratch: Vec<[u64; 4]>,
}

thread_local! {
    static TRACE_BATCH_SCRATCH: std::cell::RefCell<TraceBatchScratch> =
        std::cell::RefCell::new(TraceBatchScratch::default());
}

pub fn validate_bn254_op_trace_batch(events: &[Bn254OpTraceEvent]) -> Result<(), String> {
    validate_bn254_op_trace_batch_kpi(events, None).map(|_| ())
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn trace_cuda_window(chunk_len: usize, cuda_window: Option<usize>, cuda_min: usize) -> usize {
    let mut window = cuda_window.unwrap_or(chunk_len.saturating_mul(4));
    if window < chunk_len {
        window = chunk_len;
    }
    if env_bool("BN254_TRACE_CUDA_WINDOW_POW2") {
        window = window.next_power_of_two();
    }
    if window < cuda_min {
        window = cuda_min;
    }
    window
}

#[allow(clippy::type_complexity)]
fn cpu_batch_validate(
    label: &'static str,
    a: &[[u64; 4]],
    b: &[[u64; 4]],
    expected: &[[u64; 4]],
    idxs: &[usize],
    scratch_buf: &mut [[u64; 4]],
    batch_fn: fn(&[[u64; 4]], &[[u64; 4]], &mut [[u64; 4]]) -> Result<(), String>,
) -> Result<(), String> {
    let n = a.len();
    if n == 0 {
        return Ok(());
    }
    let threads = rayon::current_num_threads().max(1);
    let chunk = n.div_ceil(threads).max(256);
    if threads == 1 || n < 4096 {
        batch_fn(a, b, scratch_buf)?;
        for (pos, exp) in expected.iter().enumerate() {
            if scratch_buf[pos] != *exp {
                return Err(format!("bn254 trace {label} mismatch at index {}", idxs[pos]));
            }
        }
        return Ok(());
    }
    scratch_buf
        .par_chunks_mut(chunk)
        .enumerate()
        .try_for_each(|(chunk_idx, out_chunk)| {
            let start = chunk_idx * chunk;
            let end = start + out_chunk.len();
            batch_fn(&a[start..end], &b[start..end], out_chunk)?;
            for (pos, exp) in expected[start..end].iter().enumerate() {
                if out_chunk[pos] != *exp {
                    return Err(format!("bn254 trace {label} mismatch at index {}", idxs[start + pos]));
                }
            }
            Ok(())
        })
}

pub fn validate_bn254_op_trace_batch_kpi(
    events: &[Bn254OpTraceEvent],
    cuda_min_override: Option<usize>,
) -> Result<Bn254TraceBatchKpi, String> {
    TRACE_BATCH_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        scratch.add_a.clear();
        scratch.add_b.clear();
        scratch.add_out.clear();
        scratch.add_idx.clear();
        scratch.sub_a.clear();
        scratch.sub_b.clear();
        scratch.sub_out.clear();
        scratch.sub_idx.clear();
        scratch.mul_a.clear();
        scratch.mul_b.clear();
        scratch.mul_out.clear();
        scratch.mul_idx.clear();

        for (idx, ev) in events.iter().enumerate() {
            if !is_canonical_limbs(ev.a)
                || !is_canonical_limbs(ev.b)
                || !is_canonical_limbs(ev.out)
            {
                return Err(format!("bn254 trace non-canonical limbs at index {idx}"));
            }
            match ev.kind {
                Bn254OpKind::Add => {
                    scratch.add_a.push(ev.a);
                    scratch.add_b.push(ev.b);
                    scratch.add_out.push(ev.out);
                    scratch.add_idx.push(idx);
                }
                Bn254OpKind::Sub => {
                    scratch.sub_a.push(ev.a);
                    scratch.sub_b.push(ev.b);
                    scratch.sub_out.push(ev.out);
                    scratch.sub_idx.push(idx);
                }
                Bn254OpKind::Mul => {
                    scratch.mul_a.push(ev.a);
                    scratch.mul_b.push(ev.b);
                    scratch.mul_out.push(ev.out);
                    scratch.mul_idx.push(idx);
                }
            }
        }

        let mut add_cuda = false;
        let mut sub_cuda = false;
        let mut mul_cuda = false;
        let chunk = env_usize("BN254_TRACE_VALIDATE_CHUNK").filter(|v| *v > 0);
        let cuda_window = env_usize("BN254_TRACE_CUDA_WINDOW").filter(|v| *v > 0);
        let cuda_min = cuda_min_override
            .or_else(|| env_usize("BN254_TRACE_CUDA_MIN_ELEMS"))
            .unwrap_or_else(bn254_cuda_min_elems);

    if !scratch.add_a.is_empty() {
        let add_len = scratch.add_a.len();
        let mut scratch_buf = std::mem::take(&mut scratch.scratch);
        scratch_buf.resize(add_len, [0u64; 4]);
        let cuda_full = env_bool("BN254_TRACE_CUDA_FULL");
        if let Some(chunk_len) = chunk {
            let mut used_cuda = false;
            let mut offset = 0usize;
            let cuda_window = trace_cuda_window(chunk_len, cuda_window, cuda_min);
            if cuda_full && add_len >= cuda_min {
                used_cuda = bn254_add_mod_batch_with_min(
                    &scratch.add_a,
                    &scratch.add_b,
                    &mut scratch_buf,
                    cuda_min,
                )?;
                for (pos, expected) in scratch.add_out.iter().enumerate() {
                    if scratch_buf[pos] != *expected {
                        return Err(format!(
                            "bn254 trace add mismatch at index {}",
                            scratch.add_idx[pos]
                        ));
                    }
                }
                add_cuda = used_cuda;
            } else {
                while offset < add_len {
                    let remaining = add_len - offset;
                    let use_cuda = remaining >= cuda_min && cuda_window >= cuda_min;
                    let window_len = if use_cuda {
                        remaining.min(cuda_window)
                    } else {
                        remaining.min(chunk_len)
                    };
                    let end = offset + window_len;
                    let range = offset..end;
                    let chunk_slice = range.clone();
                    if use_cuda {
                        used_cuda |= bn254_add_mod_batch_with_min(
                            &scratch.add_a[chunk_slice.clone()],
                            &scratch.add_b[chunk_slice.clone()],
                            &mut scratch_buf[chunk_slice.clone()],
                            cuda_min,
                        )?;
                    } else {
                        bn254_add_mod_batch_cpu(
                            &scratch.add_a[chunk_slice.clone()],
                            &scratch.add_b[chunk_slice.clone()],
                            &mut scratch_buf[chunk_slice.clone()],
                        )?;
                    }
                    for (pos, expected) in scratch.add_out[range.clone()].iter().enumerate() {
                        if scratch_buf[offset + pos] != *expected {
                            return Err(format!(
                                "bn254 trace add mismatch at index {}",
                                scratch.add_idx[offset + pos]
                            ));
                        }
                    }
                    offset = end;
                }
                add_cuda = used_cuda;
            }
        } else if add_len >= cuda_min {
            add_cuda = bn254_add_mod_batch_with_min(
                &scratch.add_a,
                &scratch.add_b,
                &mut scratch_buf,
                cuda_min,
            )?;
            for (pos, expected) in scratch.add_out.iter().enumerate() {
                if scratch_buf[pos] != *expected {
                    return Err(format!(
                        "bn254 trace add mismatch at index {}",
                        scratch.add_idx[pos]
                    ));
                }
            }
            scratch.scratch = scratch_buf;
        } else {
            cpu_batch_validate(
                "add",
                &scratch.add_a,
                &scratch.add_b,
                &scratch.add_out,
                &scratch.add_idx,
                &mut scratch_buf,
                bn254_add_mod_batch_cpu,
            )?;
            scratch.scratch = scratch_buf;
        }
    }

    if !scratch.sub_a.is_empty() {
        let sub_len = scratch.sub_a.len();
        let mut scratch_buf = std::mem::take(&mut scratch.scratch);
        scratch_buf.resize(sub_len, [0u64; 4]);
        let cuda_full = env_bool("BN254_TRACE_CUDA_FULL");
        if let Some(chunk_len) = chunk {
            let mut used_cuda = false;
            let mut offset = 0usize;
            let cuda_window = trace_cuda_window(chunk_len, cuda_window, cuda_min);
            if cuda_full && sub_len >= cuda_min {
                used_cuda = bn254_sub_mod_batch_with_min(
                    &scratch.sub_a,
                    &scratch.sub_b,
                    &mut scratch_buf,
                    cuda_min,
                )?;
                for (pos, expected) in scratch.sub_out.iter().enumerate() {
                    if scratch_buf[pos] != *expected {
                        return Err(format!(
                            "bn254 trace sub mismatch at index {}",
                            scratch.sub_idx[pos]
                        ));
                    }
                }
                sub_cuda = used_cuda;
            } else {
                while offset < sub_len {
                    let remaining = sub_len - offset;
                    let use_cuda = remaining >= cuda_min && cuda_window >= cuda_min;
                    let window_len = if use_cuda {
                        remaining.min(cuda_window)
                    } else {
                        remaining.min(chunk_len)
                    };
                    let end = offset + window_len;
                    let range = offset..end;
                    let chunk_slice = range.clone();
                    if use_cuda {
                        used_cuda |= bn254_sub_mod_batch_with_min(
                            &scratch.sub_a[chunk_slice.clone()],
                            &scratch.sub_b[chunk_slice.clone()],
                            &mut scratch_buf[chunk_slice.clone()],
                            cuda_min,
                        )?;
                    } else {
                        bn254_sub_mod_batch_cpu(
                            &scratch.sub_a[chunk_slice.clone()],
                            &scratch.sub_b[chunk_slice.clone()],
                            &mut scratch_buf[chunk_slice.clone()],
                        )?;
                    }
                    for (pos, expected) in scratch.sub_out[range.clone()].iter().enumerate() {
                        if scratch_buf[offset + pos] != *expected {
                            return Err(format!(
                                "bn254 trace sub mismatch at index {}",
                                scratch.sub_idx[offset + pos]
                            ));
                        }
                    }
                    offset = end;
                }
                sub_cuda = used_cuda;
            }
        } else if sub_len >= cuda_min {
            sub_cuda = bn254_sub_mod_batch_with_min(
                &scratch.sub_a,
                &scratch.sub_b,
                &mut scratch_buf,
                cuda_min,
            )?;
            for (pos, expected) in scratch.sub_out.iter().enumerate() {
                if scratch_buf[pos] != *expected {
                    return Err(format!(
                        "bn254 trace sub mismatch at index {}",
                        scratch.sub_idx[pos]
                    ));
                }
            }
            scratch.scratch = scratch_buf;
        } else {
            cpu_batch_validate(
                "sub",
                &scratch.sub_a,
                &scratch.sub_b,
                &scratch.sub_out,
                &scratch.sub_idx,
                &mut scratch_buf,
                bn254_sub_mod_batch_cpu,
            )?;
            scratch.scratch = scratch_buf;
        }
    }

    if !scratch.mul_a.is_empty() {
        let mul_len = scratch.mul_a.len();
        let mut scratch_buf = std::mem::take(&mut scratch.scratch);
        scratch_buf.resize(mul_len, [0u64; 4]);
        let cuda_full = env_bool("BN254_TRACE_CUDA_FULL");
        if let Some(chunk_len) = chunk {
            let mut used_cuda = false;
            let mut offset = 0usize;
            let cuda_window = trace_cuda_window(chunk_len, cuda_window, cuda_min);
            if cuda_full && mul_len >= cuda_min {
                used_cuda = bn254_mul_mod_batch_with_min(
                    &scratch.mul_a,
                    &scratch.mul_b,
                    &mut scratch_buf,
                    cuda_min,
                )?;
                for (pos, expected) in scratch.mul_out.iter().enumerate() {
                    if scratch_buf[pos] != *expected {
                        return Err(format!(
                            "bn254 trace mul mismatch at index {}",
                            scratch.mul_idx[pos]
                        ));
                    }
                }
                mul_cuda = used_cuda;
            } else {
                while offset < mul_len {
                    let remaining = mul_len - offset;
                    let use_cuda = remaining >= cuda_min && cuda_window >= cuda_min;
                    let window_len = if use_cuda {
                        remaining.min(cuda_window)
                    } else {
                        remaining.min(chunk_len)
                    };
                    let end = offset + window_len;
                    let range = offset..end;
                    let chunk_slice = range.clone();
                    if use_cuda {
                        used_cuda |= bn254_mul_mod_batch_with_min(
                            &scratch.mul_a[chunk_slice.clone()],
                            &scratch.mul_b[chunk_slice.clone()],
                            &mut scratch_buf[chunk_slice.clone()],
                            cuda_min,
                        )?;
                    } else {
                        bn254_mul_mod_batch_cpu(
                            &scratch.mul_a[chunk_slice.clone()],
                            &scratch.mul_b[chunk_slice.clone()],
                            &mut scratch_buf[chunk_slice.clone()],
                        )?;
                    }
                    for (pos, expected) in scratch.mul_out[range.clone()].iter().enumerate() {
                        if scratch_buf[offset + pos] != *expected {
                            return Err(format!(
                                "bn254 trace mul mismatch at index {}",
                                scratch.mul_idx[offset + pos]
                            ));
                        }
                    }
                    offset = end;
                }
                mul_cuda = used_cuda;
            }
        } else if mul_len >= cuda_min {
            mul_cuda = bn254_mul_mod_batch_with_min(
                &scratch.mul_a,
                &scratch.mul_b,
                &mut scratch_buf,
                cuda_min,
            )?;
            for (pos, expected) in scratch.mul_out.iter().enumerate() {
                if scratch_buf[pos] != *expected {
                    return Err(format!(
                        "bn254 trace mul mismatch at index {}",
                        scratch.mul_idx[pos]
                    ));
                }
            }
            scratch.scratch = scratch_buf;
        } else {
            cpu_batch_validate(
                "mul",
                &scratch.mul_a,
                &scratch.mul_b,
                &scratch.mul_out,
                &scratch.mul_idx,
                &mut scratch_buf,
                bn254_mul_mod_batch_cpu,
            )?;
            scratch.scratch = scratch_buf;
        }
    }

    Ok(Bn254TraceBatchKpi {
            add_count: scratch.add_a.len(),
            sub_count: scratch.sub_a.len(),
            mul_count: scratch.mul_a.len(),
            add_cuda,
            sub_cuda,
            mul_cuda,
        })
    })
}
