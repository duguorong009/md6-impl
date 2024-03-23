extern crate alloc;

use core::mem::size_of;
use core::num::Wrapping as W;

type Wu64 = W<u64>;
type Md6Word = Wu64;

/* MD6 constants independent of mode of operation */
const MD6_DEFAULT_L: usize = 64; // large so that MD6 is fully hierarchical
const w: usize = 64; // md6_w: bits in a word
const n: usize = 89; // md6_n: # words in compression input
const c: usize = 16; // md6_c: # words in compression output

/* MD6 constants related to standard mode of operation         */
const q: usize = 15; // md6_q: # Q words in compression block (>=0)
const k: usize = 8; // md6_k: # key words per compression block (>=0)
const u: usize = 64 / w; // md6_u: # words for unique node ID (0 or 64/w)
const v: usize = 64 / w; // md6_v: # words for control word (0 or 64/w)
const b: usize = 64; // md6_b: # data words per compression block (>0)

const md6_max_stack_height: usize = 29;

const S0: Md6Word = W(0x0123456789abcdef);
const Smask: Md6Word = W(0x7311c2812425cfa0);

/* "Tap positions" for feedback shift-register */
const t0: usize = 17; /* index for linear feedback */
const t1: usize = 18; /* index for first input to first and */
const t2: usize = 21; /* index for second input to first and */
const t3: usize = 31; /* index for first input to second and */
const t4: usize = 67; /* index for second input to second and */
const t5: usize = 89; /* last tap */

/* MD6 Constant Vector Q
** Q = initial 960 bits of fractional part of sqrt(6)
*/
const Q: [Md6Word; 15] = [
    W(0x7311c2812425cfa0),
    W(0x6432286434aac8e7),
    W(0xb60450e9ef68b7c1),
    W(0xe8fb23908d9f06f1),
    W(0xdd2e76cba691e5bf),
    W(0x0cd0d63b2c30bc41),
    W(0x1f8ccf6823058f8a),
    W(0x54e5ed5b88e3775d),
    W(0x4ad12aae0a6d6031),
    W(0x3e7f16bb88222e0d),
    W(0x8af8671d3fb50c2c),
    W(0x995ad1178bd25c31),
    W(0xc878c1dd04c4b633),
    W(0x3b72066c7a1552ac),
    W(0x0d6f3522631effcb),
];

const md6_n: usize = 89;
const md6_max_r: usize = 255;

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub(crate) struct MD6State {
    d: usize,          /* desired hash bit length. 1 <= d <= 512. */

    hashval: [u8; c * (w / 8)],
    /* e.g. unsigned char hashval[128]                           */
    /* contains hashval after call to md6_final                  */
    /* hashval appears in first floor(d/8) bytes, with           */
    /* remaining (d mod 8) bits (if any) appearing in            */
    /* high-order bit positions of hashval[1+floor(d/8)].        */
    hexhashval: [char; c * (w / 8) + 1],
    /* e.g. unsigned char hexhashval[129];                       */
    /* zero-terminated string representing hex value of hashval  */
    initialized: bool,        /* false, then true after md6_init called */
    bits_processed: usize,    /* bits processed so far */
    compression_calls: usize, /* compression function calls made */
    finalized: bool,          /* false, then true after md6_final called */

    K: [Md6Word; k], /* k-word (8 word) key (aka "salt") for this instance of md6 */

    keylen: usize, /* number of bytes in key K. 0<=keylen<=k*(w/8)              */

    L: usize, /* md6 mode specification parameter. 0 <= L <= 255           */
    /* L == 0 means purely sequential (Merkle-Damgaard)          */
    /* L >= 29 means purely tree-based                           */
    /* Default is MD6_DEFAULT_L = 64 (hierarchical)              */
    r: usize,
    /* Number of rounds. 0 <= r <= 255                           */
    top: usize,
    /* index of block corresponding to top of stack              */
    B: [[Md6Word; b]; md6_max_stack_height],
    /* md6_word B[29][64]                                        */
    /* stack of 29 64-word partial blocks waiting to be          */
    /* completed and compressed.                                 */
    /* B[1] is for compressing text data (input);                */
    /* B[ell] corresponds to node at level ell in the tree.      */
    bits: [usize; md6_max_stack_height],
    /* bits[ell] =                                               */
    /*    number of bits already placed in B[ell]                */
    /*    for 1 <= ell < max_stack_height                        */
    /* 0 <= bits[ell] <= b*w                                     */
    i_for_level: [u64; md6_max_stack_height],
    /* i_for_level[ell] =                                        */
    /*    index of the node B[ ell ] on this level (0,1,...)     */
    /* when it is output   */
}

impl MD6State {
    pub fn init(d: usize) -> Self {
        Self::full_init(d, None, 0, MD6_DEFAULT_L, md6_default_r(d, 0))
    }

    pub fn full_init(d: usize, key: Option<&[u8]>, keylen: usize, L: usize, r: usize) -> Self {
        if key.is_some() {
            assert!(keylen <= k * (w / 8), "bad keylen");
        }
        assert!(!(d < 1 || d > 512 || d > w * c / 2), "bad hashlen");

        let (K, keylen) = if key.is_some() && keylen > 0 {
            let key = key.unwrap();
            let mut k_bytes = [0x00; 64];
            for i in 0..64.min(keylen) {
                k_bytes[i] = key[i];
            }
            let mut k_words = [W(0); 64 / 8];
            bytes_to_words(&k_bytes, &mut k_words);

            (k_words, keylen)
        } else {
            ([W(0); 8], 0)
        };

        assert!(L <= 255, "bad L");
        assert!(r <= 255, "bad r");

        let initialized = true;
        let finalized = false;
        let compression_calls = 0;
        let bits_processed = 0;
        let hexhashval = ['\n'; c * (w / 8) + 1];
        let hashval = [0; c * (w / 8)];
        let top = 1;

        let mut bits = [0; md6_max_stack_height];
        if L == 0 {
            bits[1] = c * w
        };

        let B = [[W(0); b]; md6_max_stack_height];
        let i_for_level = [0; md6_max_stack_height];

        MD6State {
            d,
            hashval,
            hexhashval,
            initialized,
            bits_processed,
            compression_calls,
            finalized,
            K,
            keylen,
            L,
            r,
            top,
            B,
            bits,
            i_for_level,
        }
    }

    pub fn update(&mut self, data: &[u8], databitlen: usize) {
        assert!(self.initialized, "state not init");
        assert!(!data.is_empty(), "null data");

        let mut j = 0;
        while j < databitlen {
            let portion_size = (databitlen - j).min(b * w - self.bits[1]);

            if (portion_size % 8 == 0) && (self.bits[1] % 8 == 0) && (j % 8 == 0) {
                for (i, &byte) in data[(j / 8)..(j / 8 + portion_size / 8)].iter().enumerate() {
                    let index_u64 = i / 8; // determine the index in the u64 array
                    let shift_amount = (7 - i % 8) * 8; // big endian shifting
                    self.B[1][(self.bits[1] / 64) + index_u64] |= (byte as u64) << shift_amount;
                }
            } else {
                unreachable!("handle messy case when shifting is needed");
            }

            j += portion_size;
            self.bits[1] += portion_size;
            self.bits_processed += portion_size;

            if self.bits[1] == b * w && j < databitlen {
                self.process(1, false);
            }
        }
    }

    pub fn finalize(&mut self, hashval: &mut [u8]) {
        // check that input values are sensible
        if !self.initialized {
            panic!("state not init");
        }

        // "finalize" was previously called
        if self.finalized {
            return;
        }

        let mut ell;
        // force any processing that needs doing
        if self.top == 1 {
            ell = 1;
        } else {
            ell = 1;
            while ell <= self.top {
                if self.bits[ell] > 0 {
                    break;
                }
                ell += 1;
            }
        }

        // process starting at level ell, up to root
        self.process(ell, true);

        // "process" has saved final chaining value in self.hashval
        self.trim_hashval();

        if hashval == [0x00; c * w / 8] {
            hashval.copy_from_slice(&self.hashval);
        }

        self.compute_hex_hashval();

        self.finalized = true;
    }

    fn standard_compress(
        &mut self,
        C: &mut [Md6Word],
        K: [Md6Word; k],
        ell: usize,
        i: u64,
        r: usize,
        L: usize,
        z: usize,
        p: usize,
        keylen: usize,
        d: usize,
        B: [Md6Word; b],
    ) {
        let mut N: [Md6Word; md6_n] = [W(0); md6_n];
        let mut A: [Md6Word; 5000] = [W(0); 5000];

        // check that input values are sensible
        assert!(!C.is_empty());
        assert!(!B.is_empty());
        assert!(r < md6_max_r);
        assert!(L < 255);
        assert!(ell < 255);
        assert!(p < b * w);
        assert!(d <= c * w / 2);
        assert!(!K.is_empty());
        assert!(!Q.is_empty());

        /* pack components into N for compression */
        md6_pack(&mut N, K, ell, i, r, L, z, p, keylen, d, B);

        md6_compress(C, &mut N, r, &mut A);
    }

    fn compress_block(&mut self, C: &mut [Wu64], ell: usize, z: usize) {
        // check that input values are sensible
        if !self.initialized {
            panic!("Not init");
        }
        assert!(ell < md6_max_stack_height + 1, "stackoverflow");

        self.compression_calls += 1;

        let p = b * w - self.bits[ell]; /* number of pad bits */

        self.standard_compress(
            C,
            self.K,
            ell,
            self.i_for_level[ell],
            self.r,
            self.L,
            z,
            p,
            self.keylen,
            self.d,
            self.B[ell],
        );

        self.bits[ell] = 0; /* clear bits used count this level */
        self.i_for_level[ell] += 1;

        self.B[ell] = [W(0); w]; /* clear B[ell] */
    }

    fn process(&mut self, ell: usize, is_final: bool) {
        if !self.initialized {
            panic!("Not initialized");
        }

        if !is_final {
            if self.bits[ell] < b * w {
                return;
            }
        } else {
            if ell == self.top {
                if ell == self.L + 1 {
                    /* SEQ mode */
                    if self.bits[ell] == c * w && self.i_for_level[ell] > 0 {
                        return;
                    }
                } else {
                    if ell > 1 && self.bits[ell] == c * w {
                        return;
                    }
                }
            }
        }

        /* compress block at this level; result goes into C */
        /* first set z to 1 iff this is the very last compression */
        let mut C = [W(0); c];
        let z = if is_final && ell == self.top { 1 } else { 0 };

        self.compress_block(&mut C, ell, z);

        if z == 1 {
            /* save final chaining value in st->hashval */
            words_to_bytes(&C, &mut self.hashval);
            return;
        }

        /* where should result go? To "next level" */
        let next_level = (ell + 1).min(self.L + 1);

        /* Start sequential mode with IV=0 at that level if necessary
         ** (All that is needed is to set bits[next_level] to c*w,
         ** since the bits themselves are already zeroed, either
         ** initially, or at the end of md6_compress_block.)
         */
        if next_level == self.L + 1
            && self.i_for_level[next_level] == 0
            && self.bits[next_level] == 0
        {
            self.bits[next_level] = c * w;
        }

        /* now copy C onto next level */
        self.B[next_level][..c].copy_from_slice(&C);
        self.bits[next_level] += c * w;

        if next_level > self.top {
            self.top = next_level;
        }

        self.process(next_level, is_final);
    }

    fn compute_hex_hashval(&mut self) {
        let hex_digits = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];

        for i in 0..((self.d + 7) / 8) {
            self.hexhashval[2 * i] = hex_digits[((self.hashval[i] >> 4) & 0xf) as usize];
            self.hexhashval[2 * i + 1] = hex_digits[((self.hashval[i]) & 0xf) as usize];
        }

        self.hexhashval[(self.d + 3) / 4] = '\n';
    }

    fn trim_hashval(&mut self) {
        let full_or_partial_bytes = (self.d + 7) / 8;
        let bits = self.d % 8;

        for i in 0..full_or_partial_bytes {
            self.hashval[i] = self.hashval[c * (w / 8) - full_or_partial_bytes + i];
        }

        for i in full_or_partial_bytes..(c * (w / 8)) {
            self.hashval[i] = 0;
        }

        if bits > 0 {
            for i in 0..full_or_partial_bytes {
                self.hashval[i] <<= 8 - bits;
                if (i + 1) < c * (w / 8) {
                    self.hashval[i] |= self.hashval[i + 1] >> bits;
                }
            }
        }
    }
}

// Default number of rounds
// (as a function of digest size d and keylen
fn md6_default_r(d: usize, keylen: usize) -> usize {
    let mut r = 40 + (d / 4);
    if keylen > 0 {
        r = 80.max(r);
    }
    r
}

// Convert u8 slice to u64 slice
fn bytes_to_words(bytes: &[u8], output: &mut [Wu64]) -> usize {
    let mut bytes_len = bytes.len();

    // Ensure input slice is not empty
    assert!(bytes_len != 0, "Input slice should not be null");

    // Ensure output capacity is enough to store all u64 values
    assert!(
        output.len() * size_of::<u64>() >= bytes_len,
        "Output slice is too small."
    );

    // Calculate the number of u64 values we can write
    let words_to_write = if bytes_len % size_of::<u64>() != 0 {
        bytes_len / size_of::<u64>() + 1
    } else {
        bytes_len / size_of::<u64>()
    };

    // Iterate over the input bytes in chunks of u64 size
    for i in 0..words_to_write {
        // Convert the chunk to a u64 using big-endian byte order
        let mut word: Wu64 = W(0);
        for j in 0..core::cmp::min(size_of::<u64>(), bytes_len) {
            word |= u64::from(bytes[i * size_of::<u64>() + j]) << (8 * (size_of::<u64>() - 1 - j));
        }
        // Write the u64 value to the output slice
        output[i] = word;

        if i != words_to_write - 1 {
            bytes_len -= size_of::<u64>();
        }
    }

    // Return the number of words written
    words_to_write
}

// Convert u64 slice to u8 slice
fn words_to_bytes(words: &[Wu64], output: &mut [u8]) {
    // Ensure the output slice has enough capacity
    assert!(
        output.len() == words.len() * 8,
        "Output slice is too small."
    );

    // Iterate over the u64 values in the words slice
    for (i, &word) in words.iter().enumerate() {
        // Extract bytes from the u64 value in big-endian order
        for shift in (0..8).rev() {
            let byte = (word >> (shift * 8)).0 as u8;
            output[i * 8 + (7 - shift)] = byte;
        }
    }
}

fn md6_make_nodeID(ell: usize, i: u64) -> Wu64 {
    W((ell as u64) << 56 | i)
}

fn md6_make_control_word(r: usize, L: usize, z: usize, p: usize, keylen: usize, d: usize) -> u64 {
    (r as u64) << 48
        | (L as u64) << 40
        | (z as u64) << 36
        | (p as u64) << 20
        | (keylen as u64) << 12
        | (d as u64)
}

fn md6_pack(
    N: &mut [Wu64],
    K: [Md6Word; k],
    ell: usize,
    i: u64,
    r: usize,
    L: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
    B: [Md6Word; 64],
) {
    let mut ni = 0;

    for j in 0..q {
        N[ni] = Q[j];
        ni += 1;
    }

    for j in 0..k {
        N[ni] = K[j];
        ni += 1;
    }

    let U = md6_make_nodeID(ell, i);
    N[ni] = U;
    ni += u;

    let V = md6_make_control_word(r, L, z, p, keylen, d);
    N[ni] += V;
    ni += v;

    for j in 0..b {
        N[ni] = B[j];
        ni += 1;
    }
}

fn md6_compress(C: &mut [Md6Word], N: &mut [Md6Word], r: usize, A: &mut [Md6Word]) {
    assert!(!N.is_empty());
    assert!(!C.is_empty());
    assert!(r <= md6_max_r);
    assert!(!A.is_empty());

    for i in 0..N.len() {
        A[i] = N[i];
    }

    md6_main_compression_loop(A, r);

    for i in 0..c {
        C[i] = A[i + ((r - 1) * c + n)];
    }
}

fn md6_main_compression_loop(A: &mut [Md6Word], r: usize) {
    macro_rules! loop_body {
        ($rs: expr, $ls: expr, $step: expr, $S: expr, $i: expr) => {
            let mut x = $S;
            x ^= A[$i + $step - t5];
            x ^= A[$i + $step - t0];
            x ^= (A[$i + $step - t1] & A[$i + $step - t2]);
            x ^= (A[$i + $step - t3] & A[$i + $step - t4]);
            x ^= x >> $rs;
            A[$i + $step] = x ^ (x << $ls);
        };
    }

    let mut S = S0;
    let mut i = n;
    let mut j = 0;
    while j < r * c {
        loop_body!(10, 11, 0, S, i);
        loop_body!(10, 11, 0, S, i);
        loop_body!(5, 24, 1, S, i);
        loop_body!(13, 9, 2, S, i);
        loop_body!(10, 16, 3, S, i);
        loop_body!(11, 15, 4, S, i);
        loop_body!(12, 9, 5, S, i);
        loop_body!(2, 27, 6, S, i);
        loop_body!(7, 15, 7, S, i);
        loop_body!(14, 6, 8, S, i);
        loop_body!(15, 2, 9, S, i);
        loop_body!(7, 29, 10, S, i);
        loop_body!(13, 8, 11, S, i);
        loop_body!(11, 15, 12, S, i);
        loop_body!(7, 5, 13, S, i);
        loop_body!(6, 31, 14, S, i);
        loop_body!(12, 9, 15, S, i);

        S = (S << 1) ^ (S >> (w - 1)) ^ (S & Smask);
        i += 16;
        j += c;
    }
}
