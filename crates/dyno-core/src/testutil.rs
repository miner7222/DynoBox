//! Deterministic input mutation for parser robustness tests.
//!
//! Enabled with the `testutil` feature, which crates pull in only as a
//! dev-dependency. Each parser keeps a test that feeds thousands of mutated
//! copies of a valid synthetic input through its entry point: returning an
//! error is fine, panicking (out-of-bounds slice, overflow, `unwrap`) is not.
//! The mutation stream is seeded, so a failure reproduces exactly.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// Boundary values that tend to break length / offset arithmetic.
const INTERESTING: [u64; 10] = [
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFF_FFFF,
    0xFFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
    u64::MAX,
];

/// Seeded xorshift64* byte-string mutator.
pub struct Mutator {
    state: u64,
}

impl Mutator {
    pub fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// One mutated copy of `input`: a truncation, a few random byte
    /// overwrites, or a boundary integer written over a random offset in a
    /// random width and endianness.
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.to_vec();
        if out.is_empty() {
            return out;
        }
        match self.below(4) {
            0 => out.truncate(self.below(out.len())),
            1 => {
                for _ in 0..=self.below(8) {
                    let at = self.below(out.len());
                    out[at] = self.next_u64() as u8;
                }
            }
            _ => {
                let width = [2usize, 4, 8][self.below(3)];
                let value = INTERESTING[self.below(INTERESTING.len())];
                // Low `width` bytes of `value`, little- or big-endian.
                let le = value.to_le_bytes();
                let be = value.to_be_bytes();
                let bytes = if self.below(2) == 0 {
                    &le[..width]
                } else {
                    &be[8 - width..]
                };
                let at = self.below(out.len());
                let end = (at + width).min(out.len());
                out[at..end].copy_from_slice(&bytes[..end - at]);
            }
        }
        out
    }
}

/// Feed `iterations` mutations of `seed_input` to `check`. A panic inside
/// `check` is re-raised after printing the iteration and input length so the
/// failing case can be replayed with the same `rng_seed`.
///
/// `DYNOBOX_FUZZ_ITERATIONS` overrides the count for a deeper local run.
pub fn for_each_mutation(
    seed_input: &[u8],
    rng_seed: u64,
    iterations: usize,
    mut check: impl FnMut(&[u8]),
) {
    let iterations = std::env::var("DYNOBOX_FUZZ_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(iterations);
    let mut mutator = Mutator::new(rng_seed);
    for iteration in 0..iterations {
        let input = mutator.mutate(seed_input);
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| check(&input))) {
            eprintln!(
                "parser panicked on mutation #{iteration} (rng_seed {rng_seed}, {} bytes)",
                input.len()
            );
            resume_unwind(panic);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_are_deterministic_and_vary() {
        let seed = vec![0xAAu8; 64];
        let first: Vec<_> = {
            let mut m = Mutator::new(7);
            (0..32).map(|_| m.mutate(&seed)).collect()
        };
        let second: Vec<_> = {
            let mut m = Mutator::new(7);
            (0..32).map(|_| m.mutate(&seed)).collect()
        };
        assert_eq!(first, second);
        assert!(first.iter().any(|m| m != &seed));
        assert!(first.iter().any(|m| m.len() < seed.len()));
    }
}
