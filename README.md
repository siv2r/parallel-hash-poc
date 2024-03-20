## Description
This is a proof of concept for the ParallelHash function in [this issue](https://github.com/RustCrypto/hashes/issues/1), which uses [RustCrypto's cSHAKE](https://github.com/RustCrypto/hashes/pull/355) function internally to hash the inputs.

I made the following design decisions to cut down the implementation time:
- only _ParallelHash128_ is implemented
  - The [spec](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) also details: _ParallelHash256_, _ParallelHashXOF128_, and _ParallelHashXOF256_.
  - avoided impl a genralized _ParallelHash_ macro using `macro_rules!`
- used a custom [Hasher trait](src/utils.rs) rather than RustCrypto's traits defined in their [digest crate](https://github.com/RustCrypto/traits/tree/master/digest).

**Note:** This proof of concept (PoC) is intended to demonstrate the ParallelHash algorithm. The final implementation will adhere to RustCrypto's style for implementing hash functions, which includes using a generalized macro to implement _ParallelHash128_ and _ParallelHash256_ functions as part of the [sha3 crate](https://github.com/RustCrypto/hashes/tree/master/sha3). It will also implement the Update, ExtendableOutput, and XofReader traits to support arbitrary output length.


## API Details
- Initializing the hasher object
```rust
fn new(block_size: usize) -> ParallelHash
```
- Adding inputs to the hasher
```rust
fn update(&mut self, input: &[u8]);
```
- Creates a 32-byte (256-bit) hash digest
```rust
fn finalize(self, output: &mut [u8]);
```

## Example
```rust
use parallel_hash_poc::{ParallelHash, utils::Hasher};

let mut digest = [0u8; 32];
let block_size = 5;
let mut hasher = ParallelHash::new(block_size);
hasher.update(b"msg to hash");
hasher.finalize(&mut digest);
println!("Hash Digest: {}", hex::encode(digest));
```

## Build Instructions
To build & run:
```
cargo run
```