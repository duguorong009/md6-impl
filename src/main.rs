fn main() {
    println!("Hello, world!");
}

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

fn crop(size: usize, mut data: Vec<u64>, right: bool) -> Vec<u64> {
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
