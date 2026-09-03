#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! ML-DSA-87 (FIPS 204) Digital Signature Algorithm wrapper.
//! Provides post-quantum digital-signature operations and wrapper-managed zeroization.
//! Hardware-agnostic implementation for MarTac USVs.
//! Uses the selected `ml-dsa` dependency's ML-DSA-87 implementation; independent
//! conformance testing remains outside this crate's scope.

use crate::error::CryptoError;
use crate::zeroize::secure_cache_flush;
use core::sync::atomic::{compiler_fence, Ordering};
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa87, Signature, SignatureEncoding, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wire-format length of an ML-DSA-87 verifying key (FIPS 204 `pk`).
pub const ML_DSA_PUBLICKEY_BYTES: usize = 2592;

/// Wire-format length of an ML-DSA-87 signature (FIPS 204 `sigma`).
pub const ML_DSA_SIGNATURE_BYTES: usize = 4627;

/// Public verifying key for ML-DSA-87.
/// Used to verify the authenticity and integrity of signed messages.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct PublicKey87(pub VerifyingKey<MlDsa87>);

/// Secret signing key for ML-DSA-87.
/// Used to generate digital signatures. Automatically zeroized upon being dropped.
/// `Clone` is explicitly omitted to prevent key material duplication.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey87(#[zeroize(skip)] pub SigningKey<MlDsa87>);

/// Signature produced by ML-DSA-87.
/// A 4627-byte array representing the post-quantum digital signature.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct Signature87(pub [u8; 4627]);

impl PublicKey87 {
    /// Serializes the key into its FIPS 204 `pk` wire encoding.
    ///
    /// The in-memory representation caches an expanded matrix and is substantially
    /// larger than this encoding; only the encoding is interoperable.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ML_DSA_PUBLICKEY_BYTES] {
        let mut out = [0u8; ML_DSA_PUBLICKEY_BYTES];
        out.copy_from_slice(self.0.encode().as_slice());
        out
    }

    /// Reconstructs a key from its FIPS 204 `pk` wire encoding.
    ///
    /// Decoding does not authenticate the peer. Any byte string of the correct
    /// length decodes; binding a key to an identity belongs to the caller's protocol layer.
    pub fn from_bytes(bytes: &[u8; ML_DSA_PUBLICKEY_BYTES]) -> Result<Self, CryptoError> {
        let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(bytes.as_slice())
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self(VerifyingKey::<MlDsa87>::decode(&encoded)))
    }
}

/// Generates an ML-DSA-87 keypair deterministically from the provided seed.
///
/// # Arguments
/// * `seed` - A 32-byte cryptographically secure random seed.
///
/// # Returns
/// A tuple containing the `PublicKey87` and `SigningKey87`.
pub fn ml_dsa_keygen(seed: &[u8; 32]) -> Result<(PublicKey87, SigningKey87), CryptoError> {
    let sk = SigningKey::<MlDsa87>::from_seed(seed.into());
    let vk = sk.verifying_key().clone();

    Ok((PublicKey87(vk), SigningKey87(sk)))
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
    let sig_slice = sig.to_bytes();

    if sig_slice.len() != 4627 {
        return Err(CryptoError::InvalidLength);
    }

    compiler_fence(Ordering::SeqCst);

    let mut signature = Signature87([0u8; 4627]);
    signature.0.copy_from_slice(sig_slice.as_ref());

    secure_cache_flush(&signature.0);

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
pub fn ml_dsa_verify(pk: &PublicKey87, msg: &[u8], sig: &Signature87) -> Result<(), CryptoError> {
    let sig_obj = match Signature::<MlDsa87>::try_from(sig.0.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            return Err(CryptoError::VerificationFailed);
        }
    };

    compiler_fence(Ordering::SeqCst);

    pk.0.verify(msg, &sig_obj)
        .map_err(|_| CryptoError::VerificationFailed)
}
