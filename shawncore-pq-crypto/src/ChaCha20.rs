#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Bare-metal ChaCha20 stream cipher.
//! Hardware-agnostic implementation for MarTac USVs.
//! Replaces the weak XOR-shift PRNG for cryptographically secure DRFM barrage jamming.
//! Defeats adversary ECCM (Electronic Counter-Countermeasures) modeling.
//! CHACHA20 NONCE OVERLAP resolved by reverting to a strict 32-bit counter in `state[12]`.
//! The 96-bit nonce MUST occupy `state[13]`, `state[14]`, and `state[15]`.

use crate::error::CryptoError;
use crate::zeroize::secure_zeroize;

/// ChaCha20 state size in 32-bit words.
const STATE_WORDS: usize = 16;
/// ChaCha20 block size in bytes.
const BLOCK_SIZE: usize = 64;

/// ChaCha20 stream cipher state.
/// Maintains the internal state matrix and keystream buffer.
#[repr(C, align(64))]
pub struct ChaCha20 {
    state: [u32; STATE_WORDS],
    buffer: [u8; BLOCK_SIZE],
    buffer_pos: usize,
    exhausted: bool,
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        // # Safety
        // Spatial: Arrays are fixed size.
        // Temporal: Valid for drop duration.
        // Alignment: Byte-level zeroization.
        unsafe {
            let state_ptr = self.state.as_mut_ptr() as *mut u8;
            secure_zeroize(core::slice::from_raw_parts_mut(state_ptr, STATE_WORDS * 4));
        }
        secure_zeroize(&mut self.buffer);
        self.buffer_pos = 0;
    }
}

impl ChaCha20 {
    /// Initializes a new ChaCha20 cipher with a 32-byte key and 12-byte nonce.
    ///
    /// Sets up the initial 4x4 state matrix according to RFC 8439.
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; STATE_WORDS];

        // Constants: "expand 32-byte k"
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;

        // Key
        for i in 0..8 {
            let start = i * 4;
            state[4 + i] =
                u32::from_le_bytes([key[start], key[start + 1], key[start + 2], key[start + 3]]);
        }

        // Counter
        state[12] = 0; // Strict 32-bit counter

        // Nonce (96-bit)
        for i in 0..3 {
            let start = i * 4;
            state[13 + i] = u32::from_le_bytes([
                nonce[start],
                nonce[start + 1],
                nonce[start + 2],
                nonce[start + 3],
            ]);
        }

        Self {
            state,
            buffer: [0u8; BLOCK_SIZE],
            buffer_pos: BLOCK_SIZE, // Force immediate block generation on first use
            exhausted: false,
        }
    }

    #[inline(always)]
    fn quarter_round(state: &mut [u32; STATE_WORDS], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Generates the next 64-byte block of keystream.
    fn generate_block(&mut self) -> Result<(), CryptoError> {
        if self.exhausted {
            return Err(CryptoError::InvalidLength);
        }
        let mut working_state = self.state;

        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working_state, 0, 4, 8, 12);
            Self::quarter_round(&mut working_state, 1, 5, 9, 13);
            Self::quarter_round(&mut working_state, 2, 6, 10, 14);
            Self::quarter_round(&mut working_state, 3, 7, 11, 15);

            // Diagonal rounds
            Self::quarter_round(&mut working_state, 0, 5, 10, 15);
            Self::quarter_round(&mut working_state, 1, 6, 11, 12);
            Self::quarter_round(&mut working_state, 2, 7, 8, 13);
            Self::quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        for i in 0..STATE_WORDS {
            working_state[i] = working_state[i].wrapping_add(self.state[i]);
            let bytes = working_state[i].to_le_bytes();
            let start = i * 4;
            self.buffer[start] = bytes[0];
            self.buffer[start + 1] = bytes[1];
            self.buffer[start + 2] = bytes[2];
            self.buffer[start + 3] = bytes[3];
        }

        // Strict 32-bit counter increment.
        if self.state[12] == u32::MAX {
            self.exhausted = true;
        } else {
            self.state[12] += 1;
        }
        self.buffer_pos = 0;
        Ok(())
    }

    /// Applies the ChaCha20 keystream to the provided data (XOR).
    ///
    /// Mutates the `data` slice in place.
    pub fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        let mut i = 0;
        let len = data.len();

        while i < len {
            if self.buffer_pos >= BLOCK_SIZE {
                self.generate_block()?;
            }

            let take = core::cmp::min(len - i, BLOCK_SIZE - self.buffer_pos);

            for j in 0..take {
                data[i + j] ^= self.buffer[self.buffer_pos + j];
            }

            i += take;
            self.buffer_pos += take;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ChaCha20;
    use crate::error::CryptoError;

    #[test]
    fn rejects_keystream_after_counter_exhaustion() {
        let mut cipher = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
        cipher.state[12] = u32::MAX;
        cipher.buffer_pos = 64;

        cipher.apply_keystream(&mut [0u8; 64]).unwrap();
        assert_eq!(
            cipher.apply_keystream(&mut [0u8; 1]),
            Err(CryptoError::InvalidLength)
        );
    }
}
