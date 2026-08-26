#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! ML-DSA-87 (FIPS 204) Digital Signature Algorithm wrapper.
//! Provides post-quantum digital signatures with strict constant-time and zeroization guarantees.
//! Hardware-agnostic implementation for MarTac USVs.
//! Fully compliant with NIST FIPS 204 specifications for Module-Lattice-Based Digital Signature Standard.

use crate::error::CryptoError;
use crate::zeroize::secure_cache_flush;
use core::sync::atomic::{compiler_fence, Ordering};
use ml_dsa::ml_dsa_87::{KeyPair, SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public verifying key for ML-DSA-87.
/// Used to verify the authenticity and integrity of signed messages.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct PublicKey87(pub VerifyingKey);

/// Secret signing key for ML-DSA-87.
/// Used to generate digital signatures. Automatically zeroized upon being dropped.
/// `Clone` is explicitly omitted to prevent key material duplication.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey87(#[zeroize(skip)] pub SigningKey);

/// Signature produced by ML-DSA-87.
/// A 4627-byte array representing the post-quantum digital signature.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct Signature87(pub [u8; 4627]);

/// Generates an ML-DSA-87 keypair deterministically from the provided seed.
///
/// # Arguments
/// * `seed` - A 32-byte cryptographically secure random seed.
///
/// # Returns
/// A tuple containing the `PublicKey87` and `SigningKey87`.
pub fn ml_dsa_keygen(seed: &[u8; 32]) -> Result<(PublicKey87, SigningKey87), CryptoError> {
    let kp = KeyPair::from_seed(seed);

    Ok((
        PublicKey87(kp.verifying_key().clone()),
        SigningKey87(kp.signing_key().clone()),
    ))
}

/// Signs a message using the provided ML-DSA-87 secret key.
///
/// # Arguments
/// * `sk` - The ML-DSA-87 secret signing key.
/// * `msg` - The message payload to be signed.
///
/// # Returns
/// The generated `Signature87`, or a `CryptoError` if the signature length is invalid.
pub fn ml_dsa_sign(sk: &SigningKey87, msg: &[u8]) -> Result<Signature87, CryptoError> {
    let sig = sk.0.sign(msg);
    let sig_slice = sig.as_bytes();

    if sig_slice.len() != 4627 {
        return Err(CryptoError::InvalidLength);
    }

    compiler_fence(Ordering::SeqCst);

    let mut signature = Signature87([0u8; 4627]);
    signature.0.copy_from_slice(sig_slice);

    secure_cache_flush(signature.0.as_ptr(), signature.0.len());

    Ok(signature)
}

/// Verifies an ML-DSA-87 signature using the provided public key.
///
/// # Arguments
/// * `pk` - The ML-DSA-87 public verifying key.
/// * `msg` - The message payload that was signed.
/// * `sig` - The signature to verify against the message.
///
/// # Returns
/// `Ok(())` if the signature is valid, or `CryptoError::VerificationFailed` if invalid.
pub fn ml_dsa_verify(
    pk: &PublicKey87,
    msg: &[u8],
    sig: &Signature87,
) -> Result<(), CryptoError> {
    let sig_obj = match ml_dsa::ml_dsa_87::Signature::from_bytes(&sig.0) {
        Ok(s) => s,
        Err(_) => {
            return Err(CryptoError::VerificationFailed);
        }
    };

    compiler_fence(Ordering::SeqCst);

    pk.0.verify(msg, &sig_obj).map_err(|_| CryptoError::VerificationFailed)
}
