# Blakeout
Memory hard hashing algorithm based on Blake2s

# Usage

`Blakeout` can be used in the following way:

```rust
use crypto::digest::Digest;
use blakeout::Blakeout;

// create a Blakeout object, it will hash your bytes for you
let mut hasher = Blakeout::default();

// write input message
hasher.input(b"hello world");

// read hash digest and consume hasher
let res = hasher.result_str();
assert_eq!(res, "6cc4bddb52416711be65e4b0201106fda4ceb0de48dfdce7e3a136e490d8586f");
 ```
