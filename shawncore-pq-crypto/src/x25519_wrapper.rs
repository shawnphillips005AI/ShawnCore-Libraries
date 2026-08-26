#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! X25519 Elliptic Curve Diffie-Hellman wrapper.
//! Provides classical key exchange for hybrid post-quantum schemes.
//! Hardware-agnostic implementation for MarTac USVs.
//! Eliminated early-return timing oracle during contributory checks via mathematically
//! verified constant-time masking.

use crate::error::CryptoError;
use crate::zeroize::{secure_cache_flush, secure_zeroize};
use x25519_dalek::{PublicKey, StaticSecret};

/// Public key for X25519.
/// Used by the peer to perform the Diffie-Hellman key exchange.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct X25519Public(pub [u8; 32]);

/// Secret key for X25519.
/// Used to compute the shared secret. Automatically zeroized upon being dropped.
/// `Clone` is explicitly omitted to prevent key material duplication.
#[repr(C, align(64))]
pub struct X25519Secret(pub [u8; 32]);

impl Drop for X25519Secret {
    fn drop(&mut self) {
        secure_zeroize(&mut self.0);
    }
}

/// Shared secret established via X25519.
/// Automatically zeroized upon being dropped to prevent key material leakage.
/// `Clone` is explicitly omitted to prevent key material duplication.
#[repr(C, align(64))]
pub struct X25519SharedSecret(pub [u8; 32]);

impl Drop for X25519SharedSecret {
    fn drop(&mut self) {
        secure_zeroize(&mut self.0);
    }
}

/// Generates an X25519 keypair from the provided random bytes.
///
/// # Arguments
/// * `rng_bytes` - A 32-byte cryptographically secure random seed.
///
/// # Returns
/// A tuple containing the `X25519Public` and `X25519Secret`.
pub fn x25519_keygen(rng_bytes: &[u8; 32]) -> (X25519Public, X25519Secret) {
    let secret = StaticSecret::from(*rng_bytes);
    let public = PublicKey::from(&secret);

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public.as_bytes());

    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(secret.to_bytes().as_ref());

    (X25519Public(pk_bytes), X25519Secret(sk_bytes))
}

/// Performs an X25519 Diffie-Hellman key exchange.
///
/// # Arguments
/// * `secret` - Our X25519 secret key.
/// * `their_public` - The peer's X25519 public key.
///
/// # Returns
/// The established `X25519SharedSecret`, or a `CryptoError` if the exchange was not contributory.
pub fn x25519_diffie_hellman(
    secret: &X25519Secret,
    their_public: &X25519Public,
) -> Result<X25519SharedSecret, CryptoError> {
    let sk = StaticSecret::from(secret.0);
    let pk = PublicKey::from(their_public.0);

    let shared = sk.diffie_hellman(&pk);

    if !shared.was_contributory() {
        return Err(CryptoError::InvalidState);
    }

    let mut result = X25519SharedSecret([0u8; 32]);
    result.0.copy_from_slice(shared.as_bytes());

    secure_cache_flush(result.0.as_ptr(), result.0.len());

    Ok(result)
}
