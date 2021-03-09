//! An implementation of the Blakeout hash function.
//!
//! # Usage
//!
//! `Blakeout` can be used in the following way:
//!
//! ```rust
//! use crypto::digest::Digest;
//! use blakeout::Blakeout;
//!
//! // create a Blakeout object, it will hash your bytes for you
//! let mut hasher = Blakeout::default();
//!
//! // write input message
//! hasher.input(b"hello world");
//!
//! // read hash digest and consume hasher
//! let res = hasher.result_str();
//! assert_eq!(res, "6cc4bddb52416711be65e4b0201106fda4ceb0de48dfdce7e3a136e490d8586f");
//! ```

use crypto::digest::Digest;
use crypto::blake2s::Blake2s;

const DEFAULT_HASH_SIZE: usize = 32;
const DEFAULT_HASH_COUNT: usize = 65536;

pub struct Blakeout {
    buffer: Vec<u8>,
    digest: Blake2s,
}

impl Default for Blakeout {
    fn default() -> Self {
        let digest = Blake2s::new(DEFAULT_HASH_SIZE);
        let mut buffer = Vec::new();
        buffer.resize(digest.output_bytes() * DEFAULT_HASH_COUNT, 0u8);
        Blakeout { buffer, digest }
    }
}

impl Digest for Blakeout {
    fn input(&mut self, input: &[u8]) {
        process_input(&mut self.digest, &mut self.buffer, input);
    }

    fn result(&mut self, out: &mut [u8]) {
        self.digest.result(out)
    }

    fn reset(&mut self) {
        self.digest.reset()
    }

    fn output_bits(&self) -> usize {
        self.digest.output_bits()
    }

    fn block_size(&self) -> usize {
        self.digest.output_bytes()
    }
}

fn process_input(digest: &mut dyn Digest, buffer: &mut Vec<u8>, data: &[u8]) {
    let hash_size = digest.output_bytes();
    let hash_count = buffer.len() / hash_size;

    // Preparing the scratchpad
    digest.input(data);
    digest.result(&mut buffer.as_mut_slice()[0..hash_size]);
    let double_size = hash_size * 2;
    for x in (hash_size..hash_size * hash_count).step_by(hash_size) {
        let start = if x >= double_size { x - double_size } else { 0 };
        digest.reset();
        digest.input(&buffer[start..x]);
        digest.result(&mut buffer.as_mut_slice()[x..(x + hash_size)]);
    }
    // Hashing whole buffer one way and another
    digest.reset();
    digest.input(&buffer);
    buffer.reverse();
    digest.input(&buffer);
}

#[cfg(test)]
mod tests {
    use crate::Blakeout;
    use crypto::digest::Digest;

    #[test]
    fn single_input() {
        let mut digest = Blakeout::default();
        digest.input_str("Science is poetry of reality!");
        assert_eq!("4be892daff5d5432b43bf05c9d2ea4769daf2dd1ec482c23839ce5d6950e9e62", &digest.result_str());
    }

    #[test]
    fn double_input() {
        let mut digest = Blakeout::default();
        digest.input_str("Science is poetry of reality!");
        digest.input_str("Science is poetry of reality!");
        assert_eq!("2b9a0cf5f0f4bf9d87a9905c96b5b21e1f73f14362c2a3810cb9a3e13932a84a", &digest.result_str());
    }
}
