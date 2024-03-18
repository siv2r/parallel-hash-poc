pub mod utils;

use sha3::{CShake128, CShake128Core};
use digest::{Update, ExtendableOutput, XofReader};
use utils::{Hasher, left_encode, right_encode};

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
    pub fn new(block_size: usize) -> ParallelHash {
        Self::new_with_custom_string(&[], block_size)
    }

    pub fn new_with_custom_string(custom_string: &[u8], block_size: usize) -> ParallelHash {
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