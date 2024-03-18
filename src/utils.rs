/// Coverts integer to a big endian byte-array with its length as first byte
pub fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[1..].copy_from_slice(&val.to_be_bytes());
    let i = b[1..8].iter().take_while(|&&a| a == 0).count();
    b[i] = (8 - i) as u8;
    &b[i..]
}

/// Coverts integer to a big endian byte-array with its length as last byte
pub fn right_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[..8].copy_from_slice(&val.to_be_bytes());
    let i = b[0..8].iter().take_while(|&&a| a == 0).count();
    b[8] = (8 - i) as u8;
    &b[i..]
}

pub trait Hasher {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]);

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]);
}