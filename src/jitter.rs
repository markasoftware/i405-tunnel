// Ill be very obvious to any network observer than I405 is being run, so our goal isn't to try
// and emulate any other type of network jitter. Rather, our goal is to make it hard to detect if
// any single packet is dispatched early or late. A uniform distribution is good in the sense that
// the packets, when not delayed, get spread out over a wide range of interval timings, which means
// a high variance and hence anomalous packets are harder to detect. However, if the uniform
// distribution picks a time near the top of the range, and then it gets delayed, the packet will be
// outside the specified range, and it will be obvious to a network observer that a true delay
// occurred. As a result, there is some benefit to making the distribution a little more
// center-heavy, so that if a packet gets delayed, it's less likely the delay will put it entirely
// outside the range of timestamps the jitterator can generate.

// I don't feel like trying to formalize this problem or coming up with any sort of optimal solution, so instead we do a really silly distribution where the

use rand_chacha::rand_core::{RngCore, SeedableRng};

const EXTRA_INNER_INTERVAL_LIKELIHOOD: u64 = 3;

pub(crate) struct Jitterator {
    // all generated intervals will be within this (inclusive) range:
    min: u64,
    interval_width: u64,
    // the packet will be 4x as likely to lie within this inner range, though:
    min_inner: u64,
    inner_interval_width: u64,
    rng_modulus: u64,

    rng: rand_chacha::ChaCha12Rng,
}

impl Jitterator {
    pub(crate) fn new(min: u64, max: u64) -> Jitterator {
        assert!(min <= max);

        let interval_width = max - min;
        let inner_interval_width = interval_width * 3 / 4;

        let inner_outer_difference = interval_width - inner_interval_width;
        let min_inner = min + inner_outer_difference / 2;

        let rng_modulus = inner_interval_width * EXTRA_INNER_INTERVAL_LIKELIHOOD + interval_width;

        Jitterator {
            min,
            interval_width,
            min_inner,
            inner_interval_width,
            rng_modulus,

            rng: rand_chacha::ChaCha12Rng::from_os_rng(),
        }
    }

    pub(crate) fn next_interval(&mut self) -> u64 {
        let random = self.rng.next_u64() % self.rng_modulus;
        if random < self.interval_width {
            self.min + random
        } else {
            self.min_inner + (random - self.interval_width) % self.inner_interval_width
        }
    }
}

#[cfg(test)]
mod test {
    use super::Jitterator;

    #[test]
    fn jitterator_in_range() {
        let mut jitterator = Jitterator::new(2424, 4242);
        let outer = 2424..=4242;
        let inner = 2651..=4014;
        let num_iters: u64 = 100_000;
        let mut num_inners: u64 = 0;
        for _ in 0..num_iters {
            let rng = jitterator.next_interval();
            assert!(outer.contains(&rng));
            if inner.contains(&rng) {
                num_inners += 1;
            }
        }
        let fraction_in_inner = num_inners as f32 / num_iters as f32;
        assert!(
            (0.88..0.96).contains(&fraction_in_inner),
            "Wrong fraction in inner interval: {}",
            fraction_in_inner
        );
    }
}
