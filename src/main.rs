// use hex_literal::hex;
use sha3::{CShake128, CShake128Core};
use digest::{Update, ExtendableOutput, XofReader};

fn main() {
    let mut result = [0u8; 32];
    let mut hasher = ParallelHash::new(5);
    hasher.update(b"msg to hash");
    hasher.finalize(&mut result);
    println!("Hash Digest: {}", hex::encode(result));

}

/// Coverts integer to a big endian byte-array with its length as first byte
fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[1..].copy_from_slice(&val.to_be_bytes());
    let i = b[1..8].iter().take_while(|&&a| a == 0).count();
    b[i] = (8 - i) as u8;
    &b[i..]
}

/// Coverts integer to a big endian byte-array with its length as last byte
fn right_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[..8].copy_from_slice(&val.to_be_bytes());
    let i = b[0..8].iter().take_while(|&&a| a == 0).count();
    b[8] = (8 - i) as u8;
    &b[i..]
}

/// Stores a partial-block whose length is less than `block_size``
pub struct IncompleteState {
    state: CShake128,
    absorbed: usize,
}

/// The `ParallelHash` hash functions defined in [`SP800-185`].
///
/// The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by
/// taking advantage of the parallelism available in modern processors. This version supports
/// only [`128-bit`] security strength.
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
pub struct ParallelHash {
    state: CShake128,
    blocks: usize,
    block_size: usize,
    has_partial_block: Option<IncompleteState>,
}

impl ParallelHash {
    /// Creates an instance of the ParallelHash
    fn new(block_size: usize) -> ParallelHash {
        Self::new_with_custom_string(&[], block_size)
    }

    fn new_with_custom_string(custom_string: &[u8], block_size: usize) -> ParallelHash {
        let mut state = CShake128::from_core(CShake128Core::new_with_function_name(b"ParallelHash", custom_string));
        let mut enc_block_size = [0u8; 9];
        state.update(left_encode(block_size as u64, &mut enc_block_size));
        ParallelHash {
            state,
            block_size,
            blocks: 0,
            has_partial_block: None,
        }
    }
}

pub trait Hasher {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]);

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]);
}

impl Hasher for ParallelHash {
    fn update(&mut self, mut input: &[u8]) {
        // if previous input block was incomplete, combine it with upcoming input
        // to create a complete block with length `block_size`
        if let Some(mut partial) = self.has_partial_block.take() {
            let to_absorb = self.block_size - partial.absorbed;
            if input.len() >= to_absorb {
                partial.state.update(&input[..to_absorb]);
                input = &input[to_absorb..];

                let mut temp_out = [0u8; 32];
                let mut reader = partial.state.finalize_xof();
                reader.read(&mut temp_out);
                self.blocks += 1;
            } else {
                partial.state.update(input);
                partial.absorbed += input.len();
                self.has_partial_block = Some(partial);
                return;
            }
        }

        // break the given input into complete-blocks and pass them to cSHAKE128
        // to create a new input
        let input_blocks_cnt = input.len() / self.block_size * self.block_size;
        let input_blocks = &input[..input_blocks_cnt];
        let input_end = &input[input_blocks_cnt..];
        let parts = input_blocks.chunks(self.block_size).map(|chunk| {
            let mut temp_out = [0u8; 32];
            let mut state = CShake128::from_core(CShake128Core::new(&[]));
            state.update(chunk);
            let mut reader = state.finalize_xof();
            reader.read(&mut temp_out);

            temp_out
        });

        // hash the new input with cSHAKE128
        for part in parts {
            self.state.update(&part);
            self.blocks += 1;
        }

        // if there exists a partial input block, store it in `IncompleteState`
        if !input_end.is_empty() {
            assert!(self.has_partial_block.is_none());
            let mut state = CShake128::from_core(CShake128Core::new(&[]));
            state.update(input_end);
            self.has_partial_block = Some(IncompleteState {
                state,
                absorbed: input_end.len(),
            });
        }
    }

    fn finalize(mut self, output: &mut [u8]) {
        // if self contains any partial block, hash it using cSHAKE128
        if let Some(partial) = self.has_partial_block.take() {
            let mut temp_out = [0u8; 32];
            let mut reader = partial.state.finalize_xof();
            reader.read(&mut temp_out);

            self.state.update(&temp_out);
            self.blocks += 1;
        }

        let mut block_enc = [0u8; 9];
        let mut outlen_enc = [0u8; 9];
        self.state.update(right_encode(self.blocks as u64, &mut block_enc));
        self.state.update(right_encode((output.len() * 8) as u64, &mut outlen_enc));
        let mut reader = self.state.finalize_xof();
        reader.read(output);
    }
}