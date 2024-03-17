// use hex_literal::hex;
use sha3::{CShake128, CShake128Core, Shake128};
use digest::{Update, ExtendableOutput, XofReader};

fn main() {
    let mut result = [0u8; 32];
    let mut hasher1 = Shake128::default();
    hasher1.update(b"abc");
    let mut reader1 = hasher1.finalize_xof();
    reader1.read(&mut result);
    println!("shake output = {}", hex::encode(result));

    let mut hasher2 = CShake128::from_core(CShake128Core::new(b"def"));
    hasher2.update(b"abc");
    let mut reader2 = hasher2.finalize_xof();
    reader2.read(&mut result);
    println!("cshake output = {}", hex::encode(result));
}