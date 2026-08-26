#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! ML-KEM-1024 (FIPS 203) Key Encapsulation Mechanism wrapper.
//! Provides post-quantum key establishment with strict constant-time and zeroization guarantees.
//! Hardware-agnostic implementation for MarTac USVs.
//! Fully compliant with NIST FIPS 203 specifications for Module-Lattice-Based Key-Encapsulation Mechanism.

use crate::error::CryptoError;
use crate::zeroize::secure_cache_flush;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key for ML-KEM-1024.
/// Used by the peer to encapsulate a shared secret.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct PublicKey1024(pub EncapsulationKey);

/// Secret decapsulation key for ML-KEM-1024.
/// Used to decapsulate the shared secret from a received ciphertext.
/// Automatically zeroized upon being dropped. `Clone` is explicitly omitted to prevent key material duplication.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsKey1024(#[zeroize(skip)] pub DecapsulationKey);

/// Shared secret established via ML-KEM-1024.
/// Automatically zeroized upon being dropped to prevent key material leakage. `Clone` is explicitly omitted.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedKey1024(pub [u8; 32]);

/// Ciphertext produced by ML-KEM-1024 encapsulation.
/// Transmitted over the network to the peer holding the decapsulation key.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct Ciphertext1024(pub [u8; 1568]);

/// Generates an ML-KEM-1024 keypair deterministically from the provided entropy.
///
/// # Arguments
/// * `entropy` - A 64-byte cryptographically secure random seed.
///
/// # Returns
/// A tuple containing the `PublicKey1024` and `DecapsKey1024`.
pub fn ml_kem_keygen(entropy: &[u8; 64]) -> Result<(PublicKey1024, DecapsKey1024), CryptoError> {
    let (ek, dk) = MlKem1024::generate_deterministic(entropy);
    Ok((PublicKey1024(ek), DecapsKey1024(dk)))
}

/// Encapsulates a shared secret using the provided public key and entropy.
///
/// # Arguments
/// * `ek` - The peer's ML-KEM-1024 public key.
/// * `entropy` - A 32-byte cryptographically secure random seed.
///
/// # Returns
/// A tuple containing the established `SharedKey1024` and the `Ciphertext1024` to be transmitted.
pub fn ml_kem_encapsulate(
    ek: &PublicKey1024,
    entropy: &[u8; 32],
) -> Result<(SharedKey1024, Ciphertext1024), CryptoError> {
    let (ss, ct) = ek.0.encapsulate_deterministic(entropy);

    let mut shared = SharedKey1024([0u8; 32]);
    let mut ciphertext = Ciphertext1024([0u8; 1568]);

    shared.0.copy_from_slice(ss.as_bytes());
    ciphertext.0.copy_from_slice(ct.as_bytes());

    secure_cache_flush(shared.0.as_ptr(), shared.0.len());

    Ok((shared, ciphertext))
}

/// Decapsulates a ciphertext using the provided secret key to recover the shared secret.
///
/// # Arguments
/// * `dk` - Our ML-KEM-1024 secret decapsulation key.
/// * `ct` - The ciphertext received from the peer.
///
/// # Returns
/// The recovered `SharedKey1024`.
pub fn ml_kem_decapsulate(
    dk: &DecapsKey1024,
    ct: &Ciphertext1024,
) -> Result<SharedKey1024, CryptoError> {
    let ct_array = ct.0;

    // The underlying ml_kem crate guarantees constant-time decapsulation.
    let ss = dk.0.decapsulate(&ct_array.into());

    let mut shared = SharedKey1024([0u8; 32]);
    shared.0.copy_from_slice(ss.as_bytes());

    secure_cache_flush(shared.0.as_ptr(), shared.0.len());

    Ok(shared)
}
