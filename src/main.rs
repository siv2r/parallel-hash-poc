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

    let mut b1: [u8; 9] = [0u8; 9];
    let mut b2: [u8; 9] = [0u8; 9];
    let lencode = left_encode(450000, &mut b1);
    let rencode = right_encode(450000, &mut b2);
    println!("left encoding = {}", hex::encode(lencode));
    println!("left encoding = {}", hex::encode(rencode));
}

fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[1..].copy_from_slice(&val.to_be_bytes());
    let i = b[1..8].iter().take_while(|&&a| a == 0).count();
    b[i] = (8 - i) as u8;
    &b[i..]
}

fn right_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[..8].copy_from_slice(&val.to_be_bytes());
    let i = b[0..8].iter().take_while(|&&a| a == 0).count();
    b[8] = (8 - i) as u8;
    &b[i..]
}

pub struct ParallelHash {
    state: CShake128,
    blocks: usize,
    block_size: usize,
    is_unfinshed: bool,
}

impl ParallelHash {

    fn new(custom_string: &[u8], block_size: usize) -> ParallelHash {
        let mut state = CShake128::from_core(CShake128Core::new_with_function_name(b"ParallelHash", custom_string));
        let mut enc_block_size = [0u8; 9];
        state.update(left_encode(block_size as u64, &mut enc_block_size));
        ParallelHash {
            state,
            block_size,
            blocks: 0,
            is_unfinshed: false,
        }
    }

}

pub trait Hasher {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]);

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]);
}

