#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Constant-time Authenticated Encryption with Associated Data (AEAD) utilities.
//! Provides side-channel resistant tag verification, HMAC, HKDF expansion, and
//! a robust Encrypt-then-MAC AEAD construction.
//! Hardware-agnostic implementation for MarTac USVs.

use crate::chacha20::ChaCha20;
use crate::error::CryptoError;
use crate::zeroize::{secure_cache_flush, secure_zeroize};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha384;

/// Size of the AEAD key in bytes.
pub const AEAD_KEY_SIZE: usize = 32;
/// Size of the AEAD nonce in bytes.
pub const AEAD_NONCE_SIZE: usize = 12;
/// Size of the AEAD tag in bytes.
pub const AEAD_TAG_SIZE: usize = 48;

/// Verifies two AEAD tags in strict constant time using bitwise operations to prevent branch
/// prediction leaks.
///
/// This function guarantees that the execution time depends only on the length of the tags,
/// not on their contents, preventing timing side-channel attacks.
#[must_use]
#[inline(never)]
pub fn verify_tag_constant_time(a: &[u8; AEAD_TAG_SIZE], b: &[u8; AEAD_TAG_SIZE]) -> bool {
    let mut result = 0u8;

    for i in 0..AEAD_TAG_SIZE {
        // Bitwise OR accumulates any differences without branching
        result |= a[i] ^ b[i];
    }

    // Ensure the compiler does not optimize the loop into an early-return memcmp
    core::hint::black_box(result) == 0
}

/// Computes an HMAC-SHA384 tag over the provided data.
///
/// Returns a 48-byte MAC or a `CryptoError` if the internal state is invalid.
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; AEAD_TAG_SIZE], CryptoError> {
    let mut mac = Hmac::<Sha384>::new_from_slice(key).map_err(|_| CryptoError::InvalidState)?;
    mac.update(data);
    let result_bytes = mac.finalize().into_bytes();

    let mut output = [0u8; AEAD_TAG_SIZE];
    output.copy_from_slice(&result_bytes);
    secure_cache_flush(output.as_ptr(), output.len());

    Ok(output)
}

/// Expands a pseudorandom key using HKDF-SHA384 to an arbitrary length.
///
/// Populates the `out` buffer with the expanded key material.
pub fn hkdf_expand_sha384(
    prk: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let hkdf = Hkdf::<Sha384>::from_prk(prk).map_err(|_| CryptoError::InvalidLength)?;
    let res = hkdf.expand(info, out);

    if res.is_err() {
        secure_zeroize(out);
        return Err(CryptoError::HkdfError);
    }

    secure_cache_flush(out.as_ptr(), out.len());
    Ok(())
}

/// Performs Authenticated Encryption with Associated Data (AEAD) using ChaCha20 and HMAC-SHA384.
///
/// Implements a strict Encrypt-then-MAC construction. The MAC is calculated over an unambiguous,
/// length-prefixed encoding of the AAD, ciphertext, and nonce to prevent canonicalization attacks.
///
/// # Arguments
/// * `enc_key` - The 32-byte key used for ChaCha20 encryption.
/// * `mac_key` - The 32-byte key used for HMAC-SHA384 authentication.
/// * `nonce` - The 12-byte nonce.
/// * `aad` - Additional Authenticated Data (not encrypted, but authenticated).
/// * `plaintext` - The data to encrypt.
/// * `ciphertext` - The output buffer for the encrypted data (must match plaintext length).
/// * `out_mac` - The output buffer for the 48-byte authentication tag.
pub fn aead_encrypt(
    enc_key: &[u8; AEAD_KEY_SIZE],
    mac_key: &[u8; AEAD_KEY_SIZE],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    out_mac: &mut [u8; AEAD_TAG_SIZE],
) -> Result<(), CryptoError> {
    if plaintext.len() != ciphertext.len() {
        return Err(CryptoError::InvalidLength);
    }

    // 1. Encrypt the plaintext into the ciphertext buffer
    // # Safety: Lengths are verified equal above.
    unsafe {
        core::ptr::copy_nonoverlapping(plaintext.as_ptr(), ciphertext.as_mut_ptr(), plaintext.len());
    }
    let mut cipher = ChaCha20::new(enc_key, nonce);
    cipher.apply_keystream(ciphertext);

    // 2. Compute the MAC over the unambiguous encoding:
    // MAC(mac_key, AAD_len || Ciphertext_len || Nonce || AAD || Ciphertext)
    let mut mac_engine = Hmac::<Sha384>::new_from_slice(mac_key).map_err(|_| CryptoError::InvalidState)?;
    
    mac_engine.update(&(aad.len() as u64).to_le_bytes());
    mac_engine.update(&(ciphertext.len() as u64).to_le_bytes());
    mac_engine.update(nonce);
    mac_engine.update(aad);
    mac_engine.update(ciphertext);

    let result_bytes = mac_engine.finalize().into_bytes();
    out_mac.copy_from_slice(&result_bytes);

    secure_cache_flush(ciphertext.as_ptr(), ciphertext.len());
    secure_cache_flush(out_mac.as_ptr(), out_mac.len());

    Ok(())
}

/// Performs Authenticated Decryption with Associated Data (AEAD) using ChaCha20 and HMAC-SHA384.
///
/// Verifies the MAC in strict constant time before attempting decryption.
///
/// # Arguments
/// * `enc_key` - The 32-byte key used for ChaCha20 decryption.
/// * `mac_key` - The 32-byte key used for HMAC-SHA384 authentication.
/// * `nonce` - The 12-byte nonce.
/// * `aad` - Additional Authenticated Data.
/// * `ciphertext` - The encrypted data.
/// * `mac` - The 48-byte authentication tag to verify.
/// * `plaintext` - The output buffer for the decrypted data (must match ciphertext length).
pub fn aead_decrypt(
    enc_key: &[u8; AEAD_KEY_SIZE],
    mac_key: &[u8; AEAD_KEY_SIZE],
    nonce: &[u8; AEAD_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
    mac: &[u8; AEAD_TAG_SIZE],
    plaintext: &mut [u8],
) -> Result<(), CryptoError> {
    if plaintext.len() != ciphertext.len() {
        return Err(CryptoError::InvalidLength);
    }

    // 1. Compute the expected MAC over the unambiguous encoding
    let mut mac_engine = Hmac::<Sha384>::new_from_slice(mac_key).map_err(|_| CryptoError::InvalidState)?;
    
    mac_engine.update(&(aad.len() as u64).to_le_bytes());
    mac_engine.update(&(ciphertext.len() as u64).to_le_bytes());
    mac_engine.update(nonce);
    mac_engine.update(aad);
    mac_engine.update(ciphertext);

    let expected_mac_bytes = mac_engine.finalize().into_bytes();
    let mut expected_mac = [0u8; AEAD_TAG_SIZE];
    expected_mac.copy_from_slice(&expected_mac_bytes);

    // 2. Verify the MAC in constant time
    if !verify_tag_constant_time(mac, &expected_mac) {
        secure_zeroize(plaintext);
        return Err(CryptoError::VerificationFailed);
    }

    // 3. Decrypt the ciphertext into the plaintext buffer
    // # Safety: Lengths are verified equal above.
    unsafe {
        core::ptr::copy_nonoverlapping(ciphertext.as_ptr(), plaintext.as_mut_ptr(), ciphertext.len());
    }
    let mut cipher = ChaCha20::new(enc_key, nonce);
    cipher.apply_keystream(plaintext);

    secure_cache_flush(plaintext.as_ptr(), plaintext.len());

    Ok(())
}
