fn main() {
    println!("Hello, world!");
}

const b: u64 = 512;
const c: u64 = 128;
const n: u64 = 89;

const S0: u64 = 0x0123456789abcdef;
const Sm: u64 = 0x7311c2812425cfa0;

const Q: [u64; 15] = [
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

const t: [u64; 6] = [17, 18, 21, 31, 67, 89];
const rs: [u64; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
const ls: [u64; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];

fn to_word(bytes: &[u8]) -> Vec<u64> {
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

fn from_word(words: &[u64]) -> Vec<u8> {
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

fn crop(size: usize, mut data: Vec<u8>, right: bool) -> Vec<u8> {
    let length = (size + 7) / 8;
    let remain = size % 8;

    if right {
        let start_index = data.len().saturating_sub(length);
        data = data.drain(start_index..).collect();
    } else {
        data.truncate(length);
    }

    if remain > 0 {
        let last_index = length.saturating_sub(1);
        data[last_index] &= (0xff << (8 - remain)) & 0xff;
    }

    data
}

fn f(N: Vec<u64>, r: u64) -> Vec<u64> {
    let mut S = S0;
    let mut A = N;

    let mut j = 0;
    let mut i = n;

    while j < r {
        for s in 0..16 {
            let mut x = S;
            x ^= A[(i + s - t[5]) as usize];
            x ^= A[(i + s - t[0]) as usize];
            x ^= A[(i + s - t[1]) as usize] & A[(i + s - t[2]) as usize];
            x ^= A[(i + s - t[3]) as usize] & A[(i + s - t[4]) as usize];
            x ^= x >> rs[s as usize];

            if A.len() <= (i + s) as usize {
                while A.len() <= (i + s) as usize {
                    A.push(0x00);
                }
            }

            A[(i + s) as usize] = x ^ ((x << ls[s as usize]) & 0xffffffffffffffff);
        }

        S = (((S << 1) & 0xffffffffffffffff) ^ (S >> 63)) ^ (S & Sm);

        j += 1;
        i += 16;
    }
    A[(A.len() - 16)..].to_vec()
}

fn mid(
    B: Vec<u64>,
    C: Vec<u64>,
    i: u64,
    p: u64,
    z: u64,
    r: u64, /* rounds */
    ell: u64, /* ??? */
    L: u64, /* levels */
    k: u64, /* key len */
    d: u64, /* size */
    K: Vec<u64>, /* key vector(8 words) */
) -> Vec<u64> {
    let U = ((ell & 0xff) << 56) | i & 0xffffffffffffff;
    let V = ((r & 0xfff) << 48)
        | ((L & 0xff) << 40)
        | ((z & 0xf) << 36)
        | ((p & 0xffff) << 20)
        | ((k & 0xff) << 12)
        | (d & 0xfff);

    let mut res = vec![];
    res.extend(Q);
    res.extend(K);
    res.push(U);
    res.push(V);
    res.extend(C);
    res.extend(B);
    f(res, r)
}

fn par(mut M: Vec<u8>) -> Vec<u8> {
    let mut P = 0;
    let mut B: Vec<Vec<u64>> = vec![];
    let mut C = vec![];
    let z = if M.len() > b { 0 } else { 1 };

    while M.len() < 1 || (M.len() % b) > 0 {
        M.push(0x00);
        P += 8;
    }

    let mut M = to_word(&M);

    while M.len() > 0 {
        B.push(M[..(b / 8)].to_vec());
        M = M[(b / 8)..].to_vec();
    }

    let mut i = 0;
    let mut p = 0;
    let l = B.len();

    while i < l {
        p = if i == B.len() - 1 { P } else { 0 };
        let res = mid(B[i].clone(), vec![], i as u64, p, z);
        C.extend(res);

        i += 1;
        p = 0;
    }

    from_word(&C)
}

fn seq(mut M: Vec<u8>) -> Vec<u8> {
    let mut P = 0;
    let mut B: Vec<Vec<u64>> = vec![];
    let mut C = vec![
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    while M.len() < 1 || (M.len() % (b - c)) > 0 {
        M.push(0x00);
        P += 8;
    }

    let mut M = to_word(&M);

    while M.len() > 0 {
        B.push(M[..((b - c) / 8)].to_vec());
        M = M[((b - c) / 8)..].to_vec();
    }

    let mut i = 0;
    let mut p = 0;
    let l = B.len();

    while i < l {
        p = if i == B.len() - 1 { P } else { 0 };
        let z = if i == B.len() - 1 { 1 } else { 0 };
        C = mid(B[i].clone(), C, i as u64, p, z);

        i += 1;
        p = 0;
    }

    from_word(&C)
}

fn hash(size: usize, data: &[u8], key: &[u8], levels: usize) -> Vec<u8> {
    let d = size as u64;
    let mut M = data.to_vec();

    let k = key.len();

    let K = {
        let mut temp = vec![0x00; 64];
        for i in 0..64.min(k) {
            temp[i] = key[i];
        }
        temp
    };

    let K = to_word(&K);

    let r = {
        let a = if k != 0 { 80 } else { 0 };
        let b = 40 + d / 4;
        a.max(b) as u64
    };

    let L = levels as u64;
    let mut ell = 0;

    loop {
        ell += 1;
        M = if ell > L { seq(M) } else { par(M) };

        if M.len() == c as usize {
            break;
        };
    }

    crop(d as usize, M, true)
}
