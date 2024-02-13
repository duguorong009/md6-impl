use std::cmp;

fn main() {
    println!("Hello, world!");
}

const BLOCK_BYTES: u64 = 512;
const SEQ_CHAIN_BYTES: u64 = 128;
const COMPRESS_INPUT_WORDS: u64 = 89;

const ROUND_CONSTANTS_S0: u64 = 0x0123456789abcdef;
const ROUND_CONSTANTS_MASK: u64 = 0x7311c2812425cfa0;

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

const OPTIMIZE_DIFFUSION: [u64; 6] = [17, 18, 21, 31, 67, 89];
const RIGHT_SHIFT_AMOUNTS: [u64; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
const LEFT_SHIFT_AMOUNTS: [u64; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];

const DEFAULT_DIGEST_SIZE: usize = 512; // bits
const DEFAULT_LEVELS: usize = 64;

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

fn compress(
    input: Vec<u64>, /* input block(89 words) */
    r: u64,          /* rounds */
) -> Vec<u64> {
    assert!(
        input.len() == COMPRESS_INPUT_WORDS as usize,
        "Input should be 89 words"
    );

    let mut S = ROUND_CONSTANTS_S0;
    let mut output = input;

    let mut j = 0;
    let mut i = COMPRESS_INPUT_WORDS;

    while j < r {
        for s in 0..16 {
            let mut x = S;
            x ^= output[(i + s - OPTIMIZE_DIFFUSION[5]) as usize];
            x ^= output[(i + s - OPTIMIZE_DIFFUSION[0]) as usize];
            x ^= output[(i + s - OPTIMIZE_DIFFUSION[1]) as usize]
                & output[(i + s - OPTIMIZE_DIFFUSION[2]) as usize];
            x ^= output[(i + s - OPTIMIZE_DIFFUSION[3]) as usize]
                & output[(i + s - OPTIMIZE_DIFFUSION[4]) as usize];
            x ^= x >> RIGHT_SHIFT_AMOUNTS[s as usize];

            if output.len() <= (i + s) as usize {
                while output.len() <= (i + s) as usize {
                    output.push(0x00);
                }
            }

            output[(i + s) as usize] =
                x ^ ((x << LEFT_SHIFT_AMOUNTS[s as usize]) & 0xffffffffffffffff);
        }

        S = (((S << 1) & 0xffffffffffffffff) ^ (S >> 63)) ^ (S & ROUND_CONSTANTS_MASK);

        j += 1;
        i += 16;
    }
    output[(output.len() - 16)..].to_vec()
}

fn mid(
    block: &[u64],         /* a block for compress input */
    chain_words: Vec<u64>, /* chaining variable, 0 for par, 15 for seq mode */
    i: u64,
    p: u64,
    z: u64,
    d: u64,       /* digest size */
    r: u64,       /* rounds */
    level: u64,   /* level number */
    levels: u64,  /* levels */
    key_len: u64, /* key len */
    key: &[u64],  /* key vector(8 words) */
) -> Vec<u64> {
    let u = ((level & 0xff) << 56) | i & 0xffffffffffffff;
    let v = ((r & 0xfff) << 48)
        | ((levels & 0xff) << 40)
        | ((z & 0xf) << 36)
        | ((p & 0xffff) << 20)
        | ((key_len & 0xff) << 12)
        | (d & 0xfff);

    let compress_input = Q
        .into_iter()
        .chain(key.iter().copied())
        .chain(std::iter::once(u))
        .chain(std::iter::once(v))
        .chain(chain_words)
        .chain(block.iter().copied())
        .collect();

    compress(compress_input, r)
}

fn par(
    mut state_bytes: Vec<u8>,
    d: u64,       /* digest size */
    r: u64,       /* rounds */
    level: u64,   /* level number */
    levels: u64,  /* levels */
    key_len: u64, /* key len */
    key: &[u64],  /* key vector(8 words) */
) -> Vec<u8> {
    let mut P = 0;
    let mut blocks: Vec<Vec<u64>> = vec![];
    let mut c = vec![];
    let z = if state_bytes.len() > BLOCK_BYTES as usize {
        0
    } else {
        1
    };

    while state_bytes.len() < 1 || (state_bytes.len() % BLOCK_BYTES as usize) > 0 {
        state_bytes.push(0x00);
        P += 8;
    }

    let mut state_words = bytes_to_words(&state_bytes);

    while state_words.len() > 0 {
        blocks.push(state_words[..(BLOCK_BYTES as usize / 8)].to_vec());
        state_words = state_words[(BLOCK_BYTES as usize / 8)..].to_vec();
    }

    let mut i = 0;
    let l = blocks.len();

    while i < l {
        let p = if i == blocks.len() - 1 { P } else { 0 };
        let res = mid(
            &blocks[i],
            vec![],
            i as u64,
            p,
            z,
            d,
            r,
            level,
            levels,
            key_len,
            key,
        );
        c.extend(res);

        i += 1;
    }

    words_to_bytes(&c)
}

fn seq(
    mut state_bytes: Vec<u8>,
    d: u64,       /* digest size */
    r: u64,       /* rounds */
    level: u64,   /* level number */
    levels: u64,  /* levels */
    key_len: u64, /* key len */
    key: &[u64],  /* key vector(8 words) */
) -> Vec<u8> {
    let mut P: u64 = 0;
    let mut blocks: Vec<Vec<u64>> = vec![];
    let mut c = vec![
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];

    while state_bytes.len() < 1
        || (state_bytes.len() % (BLOCK_BYTES - SEQ_CHAIN_BYTES) as usize) > 0
    {
        state_bytes.push(0x00);
        P += 8;
    }

    let mut state_words = bytes_to_words(&state_bytes);

    while state_words.len() > 0 {
        blocks.push(state_words[..((BLOCK_BYTES - SEQ_CHAIN_BYTES) as usize / 8)].to_vec());
        state_words = state_words[((BLOCK_BYTES - SEQ_CHAIN_BYTES) as usize / 8)..].to_vec();
    }

    let mut i = 0;
    let l = blocks.len();

    while i < l {
        let p = if i == blocks.len() - 1 { P } else { 0 };
        let z = if i == blocks.len() - 1 { 1 } else { 0 };
        c = mid(
            &blocks[i], c, i as u64, p, z, d, r, level, levels, key_len, key,
        );

        i += 1;
    }

    words_to_bytes(&c)
}

fn hash(digest_size: usize, data: &[u8], key: &[u8], levels: usize) -> Vec<u8> {
    let d = digest_size as u64;
    let mut state_bytes = data.to_vec();

    let key_bytes_len = key.len();

    let key_bytes: Vec<u8> = {
        let mut temp = vec![0x00; 64];
        for i in 0..64.min(key_bytes_len) {
            temp[i] = key[i];
        }
        temp
    };

    let key_words = bytes_to_words(&key_bytes);

    let rounds = {
        let a = if key_bytes_len != 0 { 80 } else { 0 };
        let rounds = 40 + d / 4;
        a.max(rounds) as u64
    };

    let levels = levels as u64;
    let mut level = 0;

    loop {
        level += 1;
        state_bytes = if level > levels {
            seq(
                state_bytes,
                d,
                rounds,
                level,
                levels,
                key_bytes_len as u64,
                &key_words,
            )
        } else {
            par(
                state_bytes,
                d,
                rounds,
                level,
                levels,
                key_bytes_len as u64,
                &key_words,
            )
        };

        if state_bytes.len() == SEQ_CHAIN_BYTES as usize {
            break;
        };
    }

    crop(d as usize, state_bytes, true)
}

fn prehash(msg: String, digest_size: usize, key: String, levels: usize) -> Vec<u8> {
    let msg_bytes = msg.into_bytes();
    let key_bytes = key.into_bytes();
    let digest_size = cmp::max(1, cmp::min(digest_size, DEFAULT_DIGEST_SIZE));

    hash(digest_size, &msg_bytes, &key_bytes, levels)
}

fn hash_hex(
    msg: Option<String>,
    digest_size: Option<usize>,
    key: Option<String>,
    levels: Option<usize>,
) -> String {
    let msg = msg.unwrap_or_default();
    let digest_size = digest_size.unwrap_or(DEFAULT_DIGEST_SIZE);
    let key = key.unwrap_or_default();
    let levels = levels.unwrap_or(DEFAULT_LEVELS);

    let digest = prehash(msg, digest_size, key, levels);

    let hex_string: String = digest
        .iter()
        .map(|byte| format!("{:02x}", byte)) // Convert each byte to a two-digit hexadecimal string
        .collect::<Vec<String>>()
        .join(""); // Concatenate all hexadecimal strings into one string

    hex_string
}

fn hash_raw(
    msg: Option<String>,
    digest_size: Option<usize>,
    key: Option<String>,
    levels: Option<usize>,
) -> Vec<u8> {
    let msg = msg.unwrap_or_default();
    let digest_size = digest_size.unwrap_or(DEFAULT_DIGEST_SIZE);
    let key = key.unwrap_or_default();
    let levels = levels.unwrap_or(DEFAULT_LEVELS);

    prehash(msg, digest_size, key, levels)
}

#[cfg(test)]
mod tests {
    use crate::hash_hex;

    #[test]
    fn test_md6() {
        // Reference: https://github.com/Richienb/md6-hash/blob/master/test.js
        const TEST_VECTORS: [(&str, usize, &str); 132] = [
            ("a", 64, "32d13030a6815e95"),
            ("aa", 64, "af7966908a5d9c13"),
            ("aaa", 64, "3d8a4ff7a21eb0c6"),
            ("aaaa", 64, "5aafda0f42635bbe"),
            ("aaaaa", 64, "c370f6eceefb2c04"),
            ("aaaaaa", 64, "453f31fe99e3365d"),
            ("aaaaaaa", 64, "9d52c725c926756b"),
            ("aaaaaaaa", 64, "836d56b5756bd4d3"),
            ("aaaaaaaaa", 64, "2d27ed075595d38f"),
            ("aaaaaaaaaa", 64, "e31280f1a2fc2528"),
            ("0", 64, "17d073d4d38b5400"),
            ("1", 64, "870f87ac0bd00aee"),
            ("2", 64, "0d70630287b9031a"),
            ("3", 64, "f60aa0d9fa94116d"),
            ("4", 64, "1e6b0691ef4d4705"),
            ("5", 64, "6305b39e912c144b"),
            ("6", 64, "b47486289e236138"),
            ("7", 64, "dd018e6e7363124a"),
            ("8", 64, "eb456a3ae7348bf8"),
            ("9", 64, "15bc9eac62570fe7"),
            ("md6", 64, "b2f36109e52bd99f"),
            ("md6 FTW", 64, "47cda109418592ca"),
            ("a", 128, "bb691c1bfa4b4345292eb35f364919ea"),
            ("aa", 128, "19487e566f9ae2584d62628af2795f8c"),
            ("aaa", 128, "319f1b026f76f9caf62320b4e2e79e29"),
            ("aaaa", 128, "eb94dae524df4b84ba4a14115c3d0448"),
            ("aaaaa", 128, "07d01330b8af7013284b9b339378aac1"),
            ("aaaaaa", 128, "5638b2a1b7c5b66e963ea7744d1c9876"),
            ("aaaaaaa", 128, "2ad627c7c0e089c28824a354841e9215"),
            ("aaaaaaaa", 128, "1f7d2461fcfe705a7afadfabc9c95eb6"),
            ("aaaaaaaaa", 128, "aa74a4962cdc8b3ae4bacf8995e9fa68"),
            ("aaaaaaaaaa", 128, "623522019a5e40188a3b8956d44ea57d"),
            ("0", 128, "7464cb2427a4b04bc0ca92653711e3a5"),
            ("1", 128, "84a229d23cf5f380527c7dd9a887a384"),
            ("2", 128, "44bf1a90a89c4bf3d6668e7886226127"),
            ("3", 128, "cad8b9e548056c8ffd19cf469d1ac1ee"),
            ("4", 128, "78746de94a7ff50fa11d22119a3d6545"),
            ("5", 128, "ccc274bde4ebb8a38b6f19a8e0c022c0"),
            ("6", 128, "b19533319a23aa00af9d143db6655041"),
            ("7", 128, "3c049e4e57a5661b66c5235a07393bd1"),
            ("8", 128, "ba73bb10cf0fee5758f3f8b37cd9fdd4"),
            ("9", 128, "cc5f60133f81e505343174fa672d9f96"),
            ("md6", 128, "98b4a2b7363159f810a60432df277b7c"),
            ("md6 FTW", 128, "e866b430fa07b5bea28981db1f9b24a6"),
            ("a", 224, "05de8792a96e024c806eb815f9f30053cf9f1b50661047a4934121b7"),
            ("aa", 224, "a03a918a4d15e30c70b64a46374d8f3d97ac46bcd70176cc47fc6864"),
            ("aaa", 224, "bb30c438e8aad6ba79c826542087a82e8d0d233c50c945a2071abb25"),
            ("aaaa", 224, "bd4ecd894231f31df590f9e819600e363352b683b0acf0c84f69ede4"),
            ("aaaaa", 224, "3a01ad0af963adefdff3d4f19b18fc409dbc371f52183125ea35409a"),
            ("aaaaaa", 224, "b25d4fef8fef6de11074578de58c79da670dbfe2384c31e75b467be8"),
            ("aaaaaaa", 224, "972c4efe175501a60a5ae668969317006640c8a79af596b6388f80c9"),
            ("aaaaaaaa", 224, "d51f874f6ecc64526baf3d9acf1fdaaf25e5d7b0dd7a046cc5362a2d"),
            ("aaaaaaaaa", 224, "a9713653a744b7198ac66744488de95b67ed4f97a0eff17dc5b9f0ad"),
            ("aaaaaaaaaa", 224, "5672369481389de3fc4e5a678b071d328f2ff400b22c2aa226e72035"),
            ("0", 224, "61ac9c7608a733ae06b37ebd729dbd2395e08aa3e08c2e645f996e0c"),
            ("1", 224, "cbed1f15034d1a64e8ac4e4b61b20a1af88ce6b5975a66a31854f4b5"),
            ("2", 224, "94efb1ddb684213949647ed2b7fc7cfed3c39bb7e6e7a206ce96a12d"),
            ("3", 224, "74b69557a1caad60a0ff05605482c7683437a8cd84644b0ab511d629"),
            ("4", 224, "8986a064f4fc94675f32f278984a472d70898267063eae0efb46b5aa"),
            ("5", 224, "f42f6a4e12109d78a4fb1d701ea9447be6263bbdc7270c6da10fb78e"),
            ("6", 224, "55bfa088f6d6f63579a6e79ea9b5a17101d46821ce7624b03aeed66d"),
            ("7", 224, "48e4bbdb81eafab004a3067591765f75e10b835b04797912ce4ac6c9"),
            ("8", 224, "4c690ad845a62e6c6f765cb58b5707f19d01af419c122b0118c8223c"),
            ("9", 224, "a2ac8d05145172d6450806d84065211d14c712f3995dfbfbd05924a4"),
            ("md6", 224, "577f5287cf2d8e515d5f22fefb730ba4e8e0607fc7705c5b123036cc"),
            ("md6 FTW", 224, "7952f429ebbe134d302939817eff92e099b16273a2c3b0741614d8ad"),
            ("a", 256, "2b0a697a081c21269514640aab4d74ffafeb3c0212df68ce92922087c69b0a77"),
            ("aa", 256, "dc62c2f369d0d0a8de1d3239e312e12ac8c92d77d64262eb1fc209f8a2aaa48a"),
            ("aaa", 256, "84610026b18ef3019a73be33f9b084194ce6ef4cd7348ae5a390b2d20d3b45fe"),
            ("aaaa", 256, "28c490c3d4b0ad1809f59160b522ccd99c5a7565499b53af94bc311b3581a9f6"),
            ("aaaaa", 256, "40f8bab5ef49065851f602e062b7fa819497ea9e1aa9419ba70b3730f108d42f"),
            ("aaaaaa", 256, "ff01d77b95f1aa6dafa4813c75d5ba2900cbe399505097f9c4fb1d1e9b0a1ba0"),
            ("aaaaaaa", 256, "0107532d1a2c5028124135df7783c5177bc520d622c5bac3001e2c2e90011741"),
            ("aaaaaaaa", 256, "44e7e33cf46bc248a0476332f6d24c59252412d8db037470142eb66f1afdae11"),
            ("aaaaaaaaa", 256, "261ac535cae8a76b2e70c2b6f24e3fe5acf32f3d5db5662c8f933c90f84cfed1"),
            ("aaaaaaaaaa", 256, "3c74f2b9d89cf806cf0b529773ef09b8ed0b393afe166fa759f53d2cb6dfb40b"),
            ("0", 256, "d979642b9060ce2dc24183bf3ac6d9ae4b54f144d3af24935e9b8bc907a72b4e"),
            ("1", 256, "7fe3b063c891feb631ed0988895cfaf8a90fcb5a7d43c25f9dd1e1c21f896711"),
            ("2", 256, "1595783f79211f1d954c181f3573025020f9495f5763934ee25954ee7c2a83cc"),
            ("3", 256, "edae30bbeb946b55333732d7c5ad872da6ece3ba28cece17d14c2302b4f98a51"),
            ("4", 256, "8a1cb9446a2791e600879d214e50ab9f255c763f02043df556f3aad6e41d2b41"),
            ("5", 256, "632a4ef13a940fec5c41cadd550dcd41d491024da37cfc686cea53026a39c2e7"),
            ("6", 256, "bfed808c85097bd8bd45fe1b0223eb3a15c013af38c4a09a2e81f5eb2c2f6d43"),
            ("7", 256, "662e1312173e2bf826439e234367ceaab3b0d98af400907742ea2c01fec70d2a"),
            ("8", 256, "3edd4058e60c3e85c56341aaf8d037e3f3e5ff9233d17a66880616f3151de9ad"),
            ("9", 256, "6c9f735d57a9b12493b5c5c0ec9733b459f13e7e996edd090dda164ebfe43d54"),
            ("md6", 256, "cbe8da56ff91be9bc299ed4c1da6159f9a41ab380f565db0a5ef08895aed4f7d"),
            ("md6 FTW", 256, "7bfaa624f661a683be2a3b2007493006a30a7845ee1670e499927861a8e74cce"),
            ("a", 384, "a40c8d059495a278fadd30b96e3b2227758090c759b934197265bf632cabf8547a7429e5316d496c2a1ddae8d27e87ee"),
            ("aa", 384, "330547441b6518e7693ea01bfc55158bcfc084853fa1960a9e8999f98b57cea7d8b0564bf192b6ab1eb7638939dc9bbf"),
            ("aaa", 384, "f43bb4e108ec31e0cf8ded506f79373e69cddcd8c7c46298f1bd475401132e4c255c08e378c9db988f0de97131cbe36c"),
            ("aaaa", 384, "b848065d437013c8fda2493bbf240587ef5fd82a178416613e5c0077541c1ca33f205e58d49387d4d9e3cd62d2d104f6"),
            ("aaaaa", 384, "20ba7998f75c67dd1371cec629e0606739514cdfb32a17b94fa8ad4c4ec7a06a09821c93a16c863ff7ff72631b5ad02b"),
            ("aaaaaa", 384, "4930a7f1d619e219a12ca118f1a2f6dd9b23b32b366014b5d14976a927d4252e89d927b7c1d1e796aec3d2f3fd294287"),
            ("aaaaaaa", 384, "cf15b1b738f91476f2a139dda60e59f5e7422d7e99cb35d9bbb96f85c52a8e6542d4b08070c0855474946d86cc99fba3"),
            ("aaaaaaaa", 384, "7f9dba3ca2c4442eefd377877b168a2283576abd157c87cda401aa86c484669aa17326fe1e4a50dcca8cbe5bb5a0e947"),
            ("aaaaaaaaa", 384, "067d6be27eef07c654254a62275daa41630b9fd5d074badb2d16f0cf5e9621026ef0506649efebcf3a18bdf2b6a17a3a"),
            ("aaaaaaaaaa", 384, "f1fc124cbfa55170d508a26bdad017978bac8be6899f1a99f420c94bd1ef8d5547bf36488e8824215cf5da878041cf76"),
            ("0", 384, "9a97b926552bb7bc61015e43e9430e3c49a76724c6d6e0b31c14f9c5bb4c7dbf78d5c583401976da7139819dc16c5934"),
            ("1", 384, "103644563cda42ea432d325fed2b0977f0d767f475b4794322916b7d82b24308c11389a6fe2acf6cade70ddf990da337"),
            ("2", 384, "dcfdb3807231f3c5d0da945e0cc83f1d2368479f059c46841b112796bca717b4acce887877062e60f3af0276a43eb13d"),
            ("3", 384, "37e21bffcc21b6de5d3bbae971d9e889670e9c77ad8f42558caea4e59fea1efb7b3392ca53a294b862b04893cdf0a4f6"),
            ("4", 384, "aaf0b2fd043fc3f2e247f02ab1618b1450db799174bf6fae883822b7cf145d7080c5b70899c10ebb7a4221c9ab36070b"),
            ("5", 384, "4d59a67f4c321eb971d7bd26a0c8e3ff7a023bb7c15097aa9b13a94fce91b24cf82ce09acac63f63f1da708ecfe49427"),
            ("6", 384, "36886709330eae549c25558ac0d4ae2b7082261e76d33d589379d3ada613eb31943bf8dda1e92fbc7001fa6f407b025e"),
            ("7", 384, "9124c888a99743a90daa8a3032014c6542f0e4ed949e950e3a2ff4945ae9f7c648dc6bf712a5556edaed50e7dc299007"),
            ("8", 384, "41b469911cebb00f5ab173e5238fe4e6aa1737f21159f550913b7b30c99d8c2c1ecd2c431f0baa992eccc5a9cfddf782"),
            ("9", 384, "9211ce0b1ae366def2d9337c34e4b1ea75ac93efab88c273ce691ed7d20da8d0bd8cbd8d2341e7a619705fcb4eeda311"),
            ("md6", 384, "1aa5bb36a472fdb3d19ae8b3aa84773ab9a8e7e13d0fde914488bba066d64d5309155ea5b7a3b33b4d9d6855fa9050b1"),
            ("md6 FTW", 384, "7a4e8ecd1035ccdf00567595c15aa5a382fef2b6a4ec4bc609e0c655887b1c05e10eee223dd6c0ba5fa4a46159c70757"),
            ("a", 512, "c0e4e18acb69cd1a7e5a20981fe6cc6f7b5b70e814d3a13b05ac292aba74c0d8c9d34c211414e7ab755a9559c27211cd749fc3eb09ae670e138881743b8d5051"),
            ("aa", 512, "2afa253b05702770343e5c46e9d47231812a741d7bba479539a3c5484a412ea419f0d0ca96e124ba92e4ca506ca12684579323051d9d52fe5a669d079a226683"),
            ("aaa", 512, "56b0131875d458f6d30ed1c594991df1efa8d6cae0c8abb36a9b811df23ac476c58e36d9adbe845e840d3de9175a8ceda11235144c3222587af108b902ce0fc5"),
            ("aaaa", 512, "26a0bbf7df198fef1aa1945ebb91e7a9436e0892f4cdd5ee18e8dfe533f45da50c36debe4d98d0eae21925403e0d37603ea67f136b3076a1e053421052971480"),
            ("aaaaa", 512, "86da00c33edf5d1daff144312af7e1a37f6441fc9905feb8caf4023fb6b34951464dc276a29925e3ad796cbdb7a09febd7d985c21702cc1b1c849e604de6580b"),
            ("aaaaaa", 512, "7e67f0540f2afd27a17ff7a8be74039b79ff060a69b6f8fb98e3afc8e0a828fffb35aff2f3e20569933ef7c418fb3a8d7cfc7c17f3360a6ecca2a800c6657592"),
            ("aaaaaaa", 512, "08d8eb85e5fe6b8e0f81841e9373de9ed18f14e911506a81cbd4e388535632edc425c88c1acbaefd61e98ea59fcda024acf662f79791acb3d15e935aa482dfef"),
            ("aaaaaaaa", 512, "2db495253418869d64c3be65f304f0f73f87da659d1aa3ad457fa437e9370bf24f88b5c28c3c0dd4e67b351499ea380b60cb0010ffd28ac2449d5361925c8ce7"),
            ("aaaaaaaaa", 512, "6d12438e615b0c1171678d262ba429a6ee58a87e24eb7b2fa0d5bec70bba1ea2e43acef122b1ca5de1a414153b0a12d795abed88cf3e88f26bf59a3222b04b99"),
            ("aaaaaaaaaa", 512, "c4451dcd12d3847e1f2408ed3c9cc2f79a179ddf5a0a9246b68adcf918bbcea67f6c8721cc226599d587313895b8a8d53881061014b6444f3d3464b03602ecc2"),
            ("0", 512, "057e1c40468ab5661defdbcd3bf671d398116373db2e7ab0adc6b0871d603eda39cf7255361ca456543157fbe09847b501586d701d53564fab651bd2f49dcda4"),
            ("1", 512, "0f19bc75955c2e405620d5a69d3ce7078c11c3805523cbd5ff834704af67d40c65e9f011fdd3723fea365eb6fa744b981fc9cd53928edae43eaa942158a649d5"),
            ("2", 512, "5f68d3c677d9cde81417f92889287e94141ff212080b1bb8d4485b01061dc0bccd8eed96fe728ea5ff3596201225337ebbf06ae6cf6162290843dfd226f7d647"),
            ("3", 512, "f4243d7945b667900c78b894d83a343b2e8865ff62cef11e51a20472600df8a17a026d3ce09cb85925540a1515b34210bdd8eed76b8fe37f35cdc5350bb7bd19"),
            ("4", 512, "8a1b250daf9fc0b2b5878504991b8950ed7c621e0b9163fbcb5f34b363f22fd6be96ed4a9c5aacbc9d6e30de4e97090a5758f89b6ae61b45658b2f79ec26fc51"),
            ("5", 512, "ad6fa2a0f8e35189d5d070559124bd6cbb1170969356165dfda720b4ded83fd14ee8d81a2ef30d918ebcfc01d668950ba681bedcc3e1180b76c06a55e9a11497"),
            ("6", 512, "2e2bb4d681f61821c6c470064b83b924cf691de74ed05bd8610cef5397d7e2c4aeda1930446f306dece4bbefe4fc87168d7a15ab80c890672b676a532739bc67"),
            ("7", 512, "adb9009ae9abf8444d45a62b7adafcaef48c6ee7c48fa65d206d7a58ac3a5993e2eb81120d45338b9f9aa1b100365e2a98cd59fd7062783e5d23088b562176c3"),
            ("8", 512, "516315942af5bbd028a533420a6496b77ca707a0b5dd0b473359d9bb74bdd00a59987a881c774a59dd2c62f1759f570713b881a622a70894ff319881e07cfd34"),
            ("9", 512, "b98f4b7c5cecda77117180a38be5bda00bf72b7e4106c0d00137d269a0d48eb571004a8069f25fab4c2b4b16ab118af881eb904f9f32331dc726c1a404489604"),
            ("md6", 512, "e94595891b2b3e2b2e3ae6943c17a34703c4230296f12f1689264e46518e0e1b0106996387ad6d8ec9b9c86e54301a71e6f4dab6e7369db4e503daae64f2e0a1"),
            ("md6 FTW", 512, "75df3b6031e8241ef59d01628b093b05906f1a2d80c43908cb2883f7db6fbdd1cadffd7d643505c20b9529b6a5d19f8b6ff1623cabbc14a606caa7bcb239611a"),
        ];

        for (text, size, expected_hash) in TEST_VECTORS {
            let hash = hash_hex(Some(text.to_string()), Some(size), None, None);
            assert!(hash == expected_hash);
        }
    }
}
