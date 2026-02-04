const MODULUS: u128 = (1u128 << 64) - (1u128 << 32) + 1;
const INV2: u128 = 0x7fffffff80000001;
const INV6: u128 = 0xd555555480000001;

fn mod_add(a: u128, b: u128) -> u128 {
    let sum = a + b;
    if sum >= MODULUS {
        sum - MODULUS
    } else {
        sum
    }
}

fn mod_sub(a: u128, b: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        MODULUS - (b - a)
    }
}

fn mod_mul(a: u128, b: u128) -> u128 {
    (a * b) % MODULUS
}

fn interpolate_cubic(y0: u128, y1: u128, y2: u128, y3: u128) -> (u128, u128, u128, u128) {
    let d1 = mod_sub(y1, y0);
    let d2 = mod_sub(y2, y1);
    let d3 = mod_sub(y3, y2);
    let dd1 = mod_sub(d2, d1);
    let dd2 = mod_sub(d3, d2);
    let ddd = mod_sub(dd2, dd1);
    let inv3 = mod_add(INV6, INV6);
    let c0 = y0;
    let c1 = mod_add(mod_sub(d1, mod_mul(dd1, INV2)), mod_mul(ddd, inv3));
    let c2 = mod_sub(mod_mul(dd1, INV2), mod_mul(ddd, INV2));
    let c3 = mod_mul(ddd, INV6);
    (c0, c1, c2, c3)
}

fn eval_poly(c0: u128, c1: u128, c2: u128, c3: u128, t: u128) -> u128 {
    let t2 = mod_mul(t, t);
    let t3 = mod_mul(t2, t);
    let acc = mod_add(c0, mod_mul(c1, t));
    let acc = mod_add(acc, mod_mul(c2, t2));
    mod_add(acc, mod_mul(c3, t3))
}

struct Mt19937 {
    mt: [u32; 624],
    idx: usize,
}

impl Mt19937 {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            let prev = mt[i - 1];
            mt[i] = 1812433253u32
                .wrapping_mul(prev ^ (prev >> 30))
                .wrapping_add(i as u32);
        }
        Self { mt, idx: 624 }
    }

    fn twist(&mut self) {
        const MATRIX_A: u32 = 0x9908b0df;
        const UPPER_MASK: u32 = 0x80000000;
        const LOWER_MASK: u32 = 0x7fffffff;

        for i in 0..624 {
            let x = (self.mt[i] & UPPER_MASK) | (self.mt[(i + 1) % 624] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x & 1 != 0 {
                x_a ^= MATRIX_A;
            }
            self.mt[i] = self.mt[(i + 397) % 624] ^ x_a;
        }
        self.idx = 0;
    }

    fn next_u32(&mut self) -> u32 {
        if self.idx >= 624 {
            self.twist();
        }
        let mut y = self.mt[self.idx];
        self.idx += 1;

        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        y
    }

    fn getrandbits64(&mut self) -> u64 {
        let hi = self.next_u32() as u64;
        let lo = self.next_u32() as u64;
        (hi << 32) | lo
    }

    fn rand_mod(&mut self) -> u128 {
        loop {
            let r = self.getrandbits64() as u128;
            if r < MODULUS {
                return r;
            }
        }
    }
}

fn main() {
    let mut rng = Mt19937::new(1);
    for _ in 0..1000 {
        let y0 = rng.rand_mod();
        let y1 = rng.rand_mod();
        let y2 = rng.rand_mod();
        let y3 = rng.rand_mod();
        let (c0, c1, c2, c3) = interpolate_cubic(y0, y1, y2, y3);
        if eval_poly(c0, c1, c2, c3, 0) != y0 {
            eprintln!("fail at t=0");
            std::process::exit(1);
        }
        if eval_poly(c0, c1, c2, c3, 1) != y1 {
            eprintln!("fail at t=1");
            std::process::exit(1);
        }
        if eval_poly(c0, c1, c2, c3, 2) != y2 {
            eprintln!("fail at t=2");
            std::process::exit(1);
        }
        if eval_poly(c0, c1, c2, c3, 3) != y3 {
            eprintln!("fail at t=3");
            std::process::exit(1);
        }
    }
    println!("sumcheck invariants ok");
}
