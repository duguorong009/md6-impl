const MD6_DEFAULT_L: usize = 64;

#[allow(non_snake_case)]
struct MD6State {
    d: usize,          /* desired hash bit length. 1 <= d <= 512.      */
    hashbitlen: usize, /* hashbitlen is the same as d; for NIST API  */

    hashval: [u8; 128],
    /* e.g. unsigned char hashval[128]                           */
    /* contains hashval after call to md6_final                  */
    /* hashval appears in first floor(d/8) bytes, with           */
    /* remaining (d mod 8) bits (if any) appearing in            */
    /* high-order bit positions of hashval[1+floor(d/8)].        */
    hexhashval: [u8; 129],
    /* e.g. unsigned char hexhashval[129];                       */
    /* zero-terminated string representing hex value of hashval  */
    initialized: bool,       /* zero, then one after md6_init called */
    bits_processed: u128,    /* bits processed so far */
    compression_calls: u128, /* compression function calls made */
    finalized: bool,         /* zero, then one after md6_final called */

    K: [u64; 8], /* k-word (8 word) key (aka "salt") for this instance of md6 */

    keylen: usize, /* number of bytes in key K. 0<=keylen<=k*(w/8)              */

    L: usize, /* md6 mode specification parameter. 0 <= L <= 255           */
    /* L == 0 means purely sequential (Merkle-Damgaard)          */
    /* L >= 29 means purely tree-based                           */
    /* Default is md6_default_L = 64 (hierarchical)              */
    r: usize,
    /* Number of rounds. 0 <= r <= 255                           */
    top: usize,
    /* index of block corresponding to top of stack              */
    B: [[u64; 64]; 29],
    /* md6_word B[29][64]                                        */
    /* stack of 29 64-word partial blocks waiting to be          */
    /* completed and compressed.                                 */
    /* B[1] is for compressing text data (input);                */
    /* B[ell] corresponds to node at level ell in the tree.      */
    bits: [usize; 29],
    /* bits[ell] =                                               */
    /*    number of bits already placed in B[ell]                */
    /*    for 1 <= ell < max_stack_height                        */
    /* 0 <= bits[ell] <= b*w                                     */
    i_for_level: [u64; 29],
    /* i_for_level[ell] =                                        */
    /*    index of the node B[ ell ] on this level (0,1,...)     */
    /* when it is output   */
}

impl MD6State {
    pub fn init(d: usize) -> Self {
        Self::full_init(d, None, 0, MD6_DEFAULT_L, md6_default_r(d, 0))
    }

    pub fn full_init(d: usize, key: Option<Vec<u8>>, keylen: usize, L: usize, r: usize) -> Self {
        todo!()
    }

    pub fn update(&mut self, data: Vec<u8>, databitlen: u128) {
        todo!()
    }

    pub fn finalize(&self, hashval: &mut Vec<u8>) {
        todo!()
    }
}

fn md6_default_r(d: usize, keylen: usize) -> usize {
    let mut r = 40 + (d / 4);
    if keylen > 0 {
        r = 80.max(r);
    }
    r
}
