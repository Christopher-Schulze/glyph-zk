//! Simple bump arena for reusable scratch buffers.
//!
//! Provides deterministic, zero-fragmentation allocation for hot paths.

#[derive(Clone, Debug)]
pub struct Arena<T: Copy + Default> {
    buf: Vec<T>,
    offset: usize,
}

impl<T: Copy + Default> Arena<T> {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: vec![T::default(); cap],
            offset: 0,
        }
    }

    pub fn reset(&mut self) {
        self.offset = 0;
    }

    pub fn alloc_slice(&mut self, len: usize) -> &mut [T] {
        let start = self.offset;
        let end = start + len;
        if end > self.buf.len() {
            self.buf.resize(end, T::default());
        }
        self.offset = end;
        &mut self.buf[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;

    #[test]
    fn test_arena_alloc_reset_reuse() {
        let mut arena = Arena::<u64>::with_capacity(4);
        let a = arena.alloc_slice(3);
        a.copy_from_slice(&[1, 2, 3]);
        let b = arena.alloc_slice(2);
        b.copy_from_slice(&[4, 5]);
        assert_eq!(arena.alloc_slice(0).len(), 0);
        arena.reset();
        let c = arena.alloc_slice(5);
        assert_eq!(c.len(), 5);
        assert_eq!(c[0], 1, "arena should reuse underlying buffer");
    }
}
