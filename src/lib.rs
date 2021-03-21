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
//! hasher.update(b"hello world");
//!
//! // read hash digest and consume hasher
//! let res = hasher.result_str();
//! assert_eq!(res, "6cc4bddb52416711be65e4b0201106fda4ceb0de48dfdce7e3a136e490d8586f");
//! ```

use digest::Digest;
use blake2::Blake2s;

const DEFAULT_HASH_SIZE: usize = 32;
const DEFAULT_HASH_COUNT: usize = 65536;

pub struct Blakeout {
    buffer: Vec<u8>,
    result: Vec<u8>,
    dirty: bool,
}

impl Default for Blakeout {
    fn default() -> Self {
        let mut buffer = Vec::new();
        buffer.resize(DEFAULT_HASH_SIZE * DEFAULT_HASH_COUNT, 0u8);
        Blakeout { buffer, result: Vec::new(), dirty: false }
    }
}

impl Blakeout {
    pub fn new() -> Self {
        let mut buffer = Vec::new();
        buffer.resize(DEFAULT_HASH_SIZE * DEFAULT_HASH_COUNT, 0u8);
        Blakeout { buffer, result: Vec::new(), dirty: false }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.process_input(data.as_ref());
    }

    pub fn input(&mut self, data: impl AsRef<[u8]>) {
        self.update(data);
    }

    pub fn reset(&mut self) {
        self.buffer.resize(0, 0u8);
        self.buffer.resize(DEFAULT_HASH_SIZE * DEFAULT_HASH_COUNT, 0u8);
        self.dirty = false;
    }

    pub fn output_size() -> usize {
        DEFAULT_HASH_SIZE
    }

    pub fn finalize(self) -> Vec<u8> {
        self.result.clone()
    }

    fn process_input(&mut self, data: &[u8]) {
        let hash_size = DEFAULT_HASH_SIZE;
        let hash_count = self.buffer.len() / hash_size;
        let mut digest = Blake2s::default();

        if self.dirty {
            digest.update(&self.result);
        }
        // Preparing the scratchpad
        digest.update(data);
        Self::finalize_to(digest, &mut self.buffer.as_mut_slice()[0..hash_size]);
        let double_size = hash_size * 2;
        for x in (hash_size..hash_size * hash_count).step_by(hash_size) {
            let mut digest = Blake2s::default();
            let start = if x >= double_size { x - double_size } else { 0 };
            digest.update(&self.buffer[start..x]);
            Self::finalize_to(digest, &mut self.buffer.as_mut_slice()[x..(x + hash_size)]);
        }
        // Hashing whole buffer one way and another
        let mut digest = Blake2s::default();
        digest.update(&self.buffer);
        self.buffer.reverse();
        digest.update(&self.buffer);
        self.result.resize(DEFAULT_HASH_SIZE, 0u8);
        Self::finalize_to(digest, self.result.as_mut_slice());
        self.dirty = true;
    }

    fn finalize_to(digest: Blake2s, slice: &mut[u8]) {
        let buf = Digest::finalize(digest);
        slice.copy_from_slice(&buf[..]);
    }
}

#[cfg(test)]
mod tests {
    use crate::Blakeout;
    const DATA: &[u8; 29] = b"Science is poetry of reality!";

    #[test]
    fn single_input() {
        let mut digest = Blakeout::default();
        digest.update(DATA);
        assert_eq!("4be892daff5d5432b43bf05c9d2ea4769daf2dd1ec482c23839ce5d6950e9e62", to_hex(&digest.finalize()));
    }

    #[test]
    fn double_input() {
        let mut digest = Blakeout::default();
        digest.update(DATA);
        digest.update(DATA);
        assert_eq!("a1b6cd16c9e718b876afb7bf4d61b64291a98a3dea0f20731da663b0358e68b9", to_hex(&digest.finalize()));
    }

    /// Convert bytes array to HEX format
    pub fn to_hex(buf: &[u8]) -> String {
        let mut result = String::new();
        for x in buf.iter() {
            result.push_str(&format!("{:01$x}", x, 2));
        }
        result
    }
}
