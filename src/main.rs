use parallel_hash_poc::{ParallelHash, utils::Hasher};

fn main() {
    let mut result = [0u8; 32];
    let block_size = 5;
    let mut hasher = ParallelHash::new(block_size);
    hasher.update(b"msg to hash");
    hasher.finalize(&mut result);
    println!("Hash Digest: {}", hex::encode(result));
}