use super::types::SumcheckRound;
use crate::glyph_field_simd::{
    Goldilocks,
    ensure_two_thread_pool,
    goldilocks_mul_batch_into,
    goldilocks_sum,
    with_goldilocks_scratch,
};
use rand::{RngCore, rngs::StdRng};
use rayon::prelude::*;

pub(crate) const INV2: Goldilocks = Goldilocks(0x7fffffff80000001);
pub(crate) const INV6: Goldilocks = Goldilocks(0xd555555480000001);

pub(crate) fn interpolate_cubic_from_values(
    y0: Goldilocks,
    y1: Goldilocks,
    y2: Goldilocks,
    y3: Goldilocks,
) -> SumcheckRound {
    // Newton forward differences
    let d1 = y1 - y0;
    let d2 = y2 - y1;
    let d3 = y3 - y2;
    let dd1 = d2 - d1;
    let dd2 = d3 - d2;
    let ddd = dd2 - dd1;

    let inv3 = INV6 + INV6;

    let c0 = y0;
    let c1 = d1 - dd1 * INV2 + ddd * inv3;
    let c2 = dd1 * INV2 - ddd * INV2;
    let c3 = ddd * INV6;

    SumcheckRound { c0, c1, c2, c3 }
}

pub(crate) const GOLDILOCKS_TWO: Goldilocks = Goldilocks(2);
pub(crate) const GOLDILOCKS_THREE: Goldilocks = Goldilocks(3);

pub(crate) fn sample_nonzero_goldilocks(rng: &mut StdRng) -> Goldilocks {
    loop {
        let v = Goldilocks::new(rng.next_u64());
        if v != Goldilocks::ZERO {
            return v;
        }
    }
}

pub(crate) fn mix_evals_in_place(evals: &mut [Goldilocks], alpha: Goldilocks) {
    if evals.is_empty() {
        return;
    }
    let alpha = if alpha == Goldilocks::ZERO {
        Goldilocks::ONE
    } else {
        alpha
    };
    let chunk = 2048usize;
    if evals.len() >= (1 << 16) {
        ensure_two_thread_pool();
        let chunks = evals.len().div_ceil(chunk);
        let alpha_chunk = alpha.pow(chunk as u64);
        let mut pow_starts = vec![Goldilocks::ZERO; chunks];
        pow_starts[0] = Goldilocks::ONE;
        for i in 1..chunks {
            pow_starts[i] = pow_starts[i - 1] * alpha_chunk;
        }
        evals
            .par_chunks_mut(chunk)
            .enumerate()
            .for_each(|(chunk_idx, window)| {
                let len = window.len();
                let mut pow = pow_starts[chunk_idx];
                with_goldilocks_scratch(len, |powers| {
                    with_goldilocks_scratch(len, |out| {
                        for slot in powers.iter_mut().take(len) {
                            *slot = pow;
                            pow = pow * alpha;
                        }
                        goldilocks_mul_batch_into(window, powers, out);
                        window.copy_from_slice(&out[..len]);
                    });
                });
            });
        return;
    }
    let mut pow = Goldilocks::ONE;
    let mut powers = vec![Goldilocks::ZERO; chunk];
    let mut out = vec![Goldilocks::ZERO; chunk];

    for window in evals.chunks_mut(chunk) {
        let len = window.len();
        for slot in powers.iter_mut().take(len) {
            *slot = pow;
            pow = pow * alpha;
        }
        goldilocks_mul_batch_into(window, &powers[..len], &mut out[..len]);
        window.copy_from_slice(&out[..len]);
    }
}

pub(crate) fn sum_scalar(v: &[Goldilocks]) -> Goldilocks {
    goldilocks_sum(v)
}

pub(crate) const SUMCHECK_PAGE_SIZE: usize = 1 << 18;

#[derive(Clone, Debug)]
pub(crate) struct PagedLayer {
    pub(crate) len: usize,
    page_size: usize,
    pages: Vec<Vec<Goldilocks>>,
}

impl PagedLayer {
    pub(crate) fn new(len: usize, page_size: usize) -> Self {
        let pages = len.div_ceil(page_size);
        let mut out = Vec::with_capacity(pages);
        for i in 0..pages {
            let start = i * page_size;
            let end = (start + page_size).min(len);
            out.push(vec![Goldilocks::ZERO; end - start]);
        }
        Self { len, page_size, pages: out }
    }

    pub(crate) fn from_slice(slice: &[Goldilocks], page_size: usize) -> Self {
        let mut layer = Self::new(slice.len(), page_size);
        for (i, v) in slice.iter().enumerate() {
            layer.set(i, *v);
        }
        layer
    }

    pub(crate) fn reset(&mut self, len: usize) {
        self.len = len;
        let pages = len.div_ceil(self.page_size);
        if self.pages.len() < pages {
            while self.pages.len() < pages {
                let start = self.pages.len() * self.page_size;
                let end = (start + self.page_size).min(len);
                self.pages.push(vec![Goldilocks::ZERO; end - start]);
            }
        } else {
            self.pages.truncate(pages);
        }
        for (i, page) in self.pages.iter_mut().enumerate() {
            let start = i * self.page_size;
            let end = (start + self.page_size).min(len);
            if page.len() != end - start {
                page.resize(end - start, Goldilocks::ZERO);
            } else {
                for v in page.iter_mut() {
                    *v = Goldilocks::ZERO;
                }
            }
        }
    }

    #[inline]
    pub(crate) fn get(&self, idx: usize) -> Goldilocks {
        let page = idx / self.page_size;
        let offset = idx % self.page_size;
        self.pages[page][offset]
    }

    #[inline]
    pub(crate) fn set(&mut self, idx: usize, val: Goldilocks) {
        let page = idx / self.page_size;
        let offset = idx % self.page_size;
        self.pages[page][offset] = val;
    }

    #[inline]
    pub(crate) fn ptr_at(&self, idx: usize) -> *const Goldilocks {
        let page = idx / self.page_size;
        let offset = idx % self.page_size;
        self.pages[page].as_ptr().wrapping_add(offset)
    }
}

pub(crate) fn sum_paged(layer: &PagedLayer) -> Goldilocks {
    let pages = layer.pages.len();
    if pages >= 4 && layer.len >= (1 << 14) {
        ensure_two_thread_pool();
        return layer
            .pages
            .par_iter()
            .map(|page| if page.is_empty() { Goldilocks::ZERO } else { goldilocks_sum(page) })
            .reduce(|| Goldilocks::ZERO, |a, b| a + b);
    }
    let mut acc = Goldilocks::ZERO;
    for page in &layer.pages {
        if !page.is_empty() {
            acc = acc + goldilocks_sum(page);
        }
    }
    acc
}
