type md6_word = u64;

/* MD6 constants independent of mode of operation (from md6.h) */
const md6_default_L: usize = 64;
const w: usize = 64; // md6_w: bits in a word
const n: usize = 89; // md6_n: # words in compression input
const c: usize = 16; // md6_c: # words in compression output

/* MD6 constants needed for mode of operation                  */
const q: usize = 15; // md6_q: # words in Q
const k: usize = 8; // md6_k: # words in key (aka salt)
const u: usize = 1; // md6_u: # words in unique node ID
const v: usize = 1; // md6_v: # words in control word
const b: usize = 64; // md6_b: # data words per compression block

const md6_max_stack_height: usize = 29;

/* MD6 Constant Vector Q
** Q = initial 960 bits of fractional part of sqrt(6)
*/
const Q: [md6_word; 15] = [
    0x7311c2812425cfa0,
    0x6432286434aac8e7,
    0xb60450e9ef68b7c1,
    0xe8fb23908d9f06f1,
    0xdd2e76cba691e5bf,
    0x0cd0d63b2c30bc41,
    0x1f8ccf6823058f8a,
    0x54e5ed5b88e3775d,
    0x4ad12aae0a6d6031,
    0x3e7f16bb88222e0d,
    0x8af8671d3fb50c2c,
    0x995ad1178bd25c31,
    0xc878c1dd04c4b633,
    0x3b72066c7a1552ac,
    0x0d6f3522631effcb,
];

#[allow(non_snake_case)]
#[derive(Debug)]
struct MD6State {
    d: usize,          /* desired hash bit length. 1 <= d <= 512.      */
    hashbitlen: usize, /* hashbitlen is the same as d; for NIST API  */

    hashval: [u8; c * (w / 8)],
    /* e.g. unsigned char hashval[128]                           */
    /* contains hashval after call to md6_final                  */
    /* hashval appears in first floor(d/8) bytes, with           */
    /* remaining (d mod 8) bits (if any) appearing in            */
    /* high-order bit positions of hashval[1+floor(d/8)].        */
    hexhashval: [u8; c * (w / 8) + 1],
    /* e.g. unsigned char hexhashval[129];                       */
    /* zero-terminated string representing hex value of hashval  */
    initialized: bool,        /* zero, then one after md6_init called */
    bits_processed: usize,    /* bits processed so far */
    compression_calls: usize, /* compression function calls made */
    finalized: bool,          /* zero, then one after md6_final called */

    K: [md6_word; k], /* k-word (8 word) key (aka "salt") for this instance of md6 */

    keylen: usize, /* number of bytes in key K. 0<=keylen<=k*(w/8)              */

    L: usize, /* md6 mode specification parameter. 0 <= L <= 255           */
    /* L == 0 means purely sequential (Merkle-Damgaard)          */
    /* L >= 29 means purely tree-based                           */
    /* Default is md6_default_L = 64 (hierarchical)              */
    r: usize,
    /* Number of rounds. 0 <= r <= 255                           */
    top: usize,
    /* index of block corresponding to top of stack              */
    B: [[md6_word; b]; md6_max_stack_height],
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
        Self::full_init(d, None, 0, md6_default_L, md6_default_r(d, 0))
    }

    pub fn full_init(d: usize, key: Option<Vec<u8>>, keylen: usize, L: usize, r: usize) -> Self {
        if key.is_some() {
            assert!(keylen <= 8 * (64 / 8), "bad keylen");
        }
        assert!(d < 1 || d > 512 || d > 64 * 16 / 2, "bad hashlen");

        let (K, keylen) = if key.is_some() && keylen > 0 {
            let key = key.unwrap();
            let mut k_bytes = vec![0x00; 64];
            for i in 0..64.min(keylen) {
                k_bytes[i] = key[i];
            }
            let k_words = bytes_to_words(&k_bytes);

            (k_words.try_into().unwrap(), keylen)
        } else {
            ([0u64; 8], 0)
        };

        assert!(L <= 255, "bad L");
        assert!(r <= 255, "bad r");

        let initialized = true;
        let finalized = false;
        let compression_calls = 0;
        let bits_processed = 0;
        let hexhashval = [0; 129];
        let hashval = [0; 128];
        let hashbitlen = 0;
        let top = 1;

        let mut bits = [0; 29];
        if L == 0 {
            bits[1] = c * w
        };

        let B = [[0; 64]; 29];
        let i_for_level = [0; 29];

        MD6State {
            d,
            hashbitlen,
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

    pub fn update(&mut self, data: Vec<u8>, databitlen: usize) {
        assert!(self.initialized, "state not init");
        assert!(!data.is_empty(), "null data");

        let mut portion_size = 0;
        let mut j = 0;
        while j < databitlen {
            portion_size = (databitlen - j).min(b * w - self.bits[1]);
            if portion_size % 8 == 0 && self.bits[1] % 8 == 0 && j % 8 == 0 {
                todo!()
            }
        }
    }

    pub fn finalize(&mut self, hashval: &mut Vec<u8>) {
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
                if self.bits[ell as usize] > 0 {
                    break;
                }
                ell += 1;
            }
        }

        // process starting at level ell, up to root
        self.process(ell, true);

        // "process" has saved final chaining value in self.hashval
        self.trim_hashval();

        if !hashval.is_empty() {
            // todo
            //   if (hashval != NULL) memcpy( hashval, st->hashval, (st->d+7)/8 );
        }

        self.compute_hex_hashval();

        self.finalized = true;
    }

    fn standard_compress(
        &mut self,
        C: &mut Vec<md6_word>,
        K: [md6_word; k],
        ell: usize,
        i: u64,
        r: usize,
        L: usize,
        z: usize,
        p: usize,
        keylen: usize,
        d: usize,
        B: [md6_word; b],
    ) {
        todo!()
    }

    fn compress_block(&mut self, C: &mut Vec<u64>, ell: usize, z: usize) {
        // check that input values are sensible
        if !self.initialized {
            panic!("Not init");
        }
        assert!(ell < md6_max_stack_height + 1, "stackoverflow");

        self.compression_calls += 1;

        if ell == 1 {
            /* leaf; hashing data; reverse bytes if nec. */
            if ell < self.L + 1 {
                /* PAR (tree) node */
                self.B[ell].reverse();
            } else {
                /* SEQ (sequential) node; don't reverse chaining vars */
                self.B[ell][c..].reverse();
            }
        }

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

        self.B[ell] = [0; w]; /* clear B[ell] */
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
        let mut C = vec![];
        let z = if is_final && ell == self.top { 1 } else { 0 };

        self.compress_block(&mut C, ell, z);

        if z == 1 {
            /* save final chaining value in st->hashval */
            self.hashval = words_to_bytes(&C).try_into().unwrap();
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
        self.B[next_level] = C.try_into().unwrap(); // TODO: check "memcpy" later
        self.bits[next_level] += c * w;

        if next_level > self.top {
            self.top = next_level;
        }

        self.process(next_level, is_final);
    }

    fn compute_hex_hashval(&mut self) {
        let hex_digits = vec![
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];

        for i in 0..((self.d + 7) / 8) {
            self.hexhashval[2 * i] = hex_digits[((self.hashval[i] >> 4) & 0xf) as usize] as u8;
            self.hexhashval[2 * i + 1] = hex_digits[((self.hashval[i]) & 0xf) as usize] as u8;
        }

        self.hexhashval[((self.d + 3) / 4) as usize] = 0;
    }

    fn trim_hashval(&mut self) {
        let full_or_partial_bytes = (self.d + 7) / 8;
        let bits = self.d % 8;

        for i in 0..full_or_partial_bytes {
            self.hashval[i] = self.hashval[(c * (w / 8) - full_or_partial_bytes + i) as usize];
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

pub fn md6_full_hash(
    d: usize,
    data: Vec<u8>,
    databitlen: usize,
    key: Option<Vec<u8>>,
    keylen: usize,
    L: usize,
    r: usize,
    hashval: &mut Vec<u8>,
) {
    let mut st = MD6State::full_init(d, key, keylen, L, r);
    st.update(data, databitlen);
    st.finalize(hashval);
}

pub fn md6_hash(d: usize, data: Vec<u8>, databitlen: usize, hashval: &mut Vec<u8>) {
    md6_full_hash(
        d,
        data,
        databitlen,
        None,
        0,
        md6_default_L,
        md6_default_r(d, 0),
        hashval,
    );
}

fn md6_default_r(d: usize, keylen: usize) -> usize {
    let mut r = 40 + (d / 4);
    if keylen > 0 {
        r = 80.max(r);
    }
    r
}

fn bytes_to_words(bytes: &[u8]) -> Vec<u64> {
    // Ensure the input length is a multiple of 8
    assert_eq!(bytes.len() % 8, 0, "Input length must be a multiple of 8");

    // Create an empty vector to store the u64 values
    let mut words = Vec::with_capacity(bytes.len() / 8);

    // Iterate over the input bytes in chunks of 8
    for chunk in bytes.chunks_exact(8) {
        // Convert the chunk to a u64 using big-endian byte order
        let value = chunk
            .iter()
            .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte));

        // Push the u64 value to the result vector
        words.push(value);
    }

    words
}

fn words_to_bytes(words: &[u64]) -> Vec<u8> {
    // Create an empty vector to store the u8 values
    let mut bytes = Vec::with_capacity(words.len() * 8);

    // Iterate over the u64 values in the words vector
    for &word in words {
        // Extract bytes from the u64 value in big-endian order
        for shift in (0..8).rev() {
            let byte = (word >> (shift * 8)) as u8;
            bytes.push(byte);
        }
    }

    bytes
}
