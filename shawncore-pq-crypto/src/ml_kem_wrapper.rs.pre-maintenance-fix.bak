#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! ML-KEM-1024 (FIPS 203) Key Encapsulation Mechanism wrapper.
//! Provides post-quantum key establishment with wrapper-managed zeroization.
//! Hardware-agnostic implementation for MarTac USVs.
//! Uses the selected `ml-kem` dependency's ML-KEM-1024 implementation; independent
//! conformance testing remains outside this crate's scope. Constant-time behavior
//! is a property of that dependency and has not been independently measured here.

use crate::error::CryptoError;
use crate::zeroize::secure_cache_flush;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wire-format length of an ML-KEM-1024 encapsulation key (FIPS 203 `ek`).
pub const ML_KEM_PUBLICKEY_BYTES: usize = 1568;

/// Wire-format length of an ML-KEM-1024 ciphertext (FIPS 203 `c`).
pub const ML_KEM_CIPHERTEXT_BYTES: usize = 1568;

/// Public key for ML-KEM-1024.
/// Used by the peer to encapsulate a shared secret.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct PublicKey1024(pub ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>);

/// Secret decapsulation key for ML-KEM-1024.
/// Used to decapsulate the shared secret from a received ciphertext.
/// The inner `ml_kem` key is skipped by this derive because it already implements
/// `ZeroizeOnDrop` itself; `Clone` is explicitly omitted to prevent key material duplication.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsKey1024(
    #[zeroize(skip)] pub ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>,
);

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

impl PublicKey1024 {
    /// Serializes the key into its FIPS 203 `ek` wire encoding.
    ///
    /// The in-memory representation is an expanded form and is larger than this
    /// encoding; only the encoding is interoperable.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ML_KEM_PUBLICKEY_BYTES] {
        let mut out = [0u8; ML_KEM_PUBLICKEY_BYTES];
        out.copy_from_slice(self.0.as_bytes().as_slice());
        out
    }

    /// Reconstructs a key from its FIPS 203 `ek` wire encoding.
    ///
    /// Decoding does not authenticate the peer. Any byte string of the correct
    /// length decodes; binding a key to an identity belongs to the caller's protocol layer.
    pub fn from_bytes(bytes: &[u8; ML_KEM_PUBLICKEY_BYTES]) -> Result<Self, CryptoError> {
        let encoded = Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>>::try_from(
            bytes.as_slice(),
        )
        .map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self(ml_kem::kem::EncapsulationKey::from_bytes(&encoded)))
    }
}

/// Generates an ML-KEM-1024 keypair deterministically from the provided entropy.
///
/// # Arguments
/// * `entropy` - A 64-byte cryptographically secure random seed.
///
/// # Returns
/// A tuple containing the `PublicKey1024` and `DecapsKey1024`.
pub fn ml_kem_keygen(entropy: &[u8; 64]) -> Result<(PublicKey1024, DecapsKey1024), CryptoError> {
    // Both conversions are infallible: `entropy` is a fixed 64-byte array split at 32.
    let d: [u8; 32] = entropy[..32].try_into().unwrap();
    let z: [u8; 32] = entropy[32..].try_into().unwrap();
    let (dk, ek) = <MlKem1024 as KemCore>::generate_deterministic(&d.into(), &z.into());
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
    let m: [u8; 32] = *entropy;
    let (ct, ss) = ml_kem::EncapsulateDeterministic::encapsulate_deterministic(&ek.0, &m.into())
        .map_err(|_| CryptoError::InvalidState)?;

    let mut shared = SharedKey1024([0u8; 32]);
    let mut ciphertext = Ciphertext1024([0u8; 1568]);

    shared.0.copy_from_slice(ss.as_ref());
    ciphertext.0.copy_from_slice(ct.as_ref());

    secure_cache_flush(&shared.0);

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
    // Decapsulation timing behavior is a property of the selected `ml-kem`
    // dependency and has not been independently measured here.
    let ss = ml_kem::kem::Decapsulate::decapsulate(&dk.0, &ct.0.into())
        .map_err(|_| CryptoError::InvalidState)?;

    let mut shared = SharedKey1024([0u8; 32]);
    shared.0.copy_from_slice(ss.as_ref());

    secure_cache_flush(&shared.0);

    Ok(shared)
}
