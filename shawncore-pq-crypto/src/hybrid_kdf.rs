#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! NIST SP 800-56C Rev. 2 Hybrid Key Derivation Function.
//! Combines classical and post-quantum shared secrets into a single key.
//! Hardware-agnostic implementation for MarTac USVs.
//! Designed as a building block for hybrid security architectures. Platform
//! approval and independent review remain outside this crate's scope.

use crate::error::CryptoError;
use crate::zeroize::{secure_cache_flush, secure_zeroize};
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroize;

/// Size of the post-quantum shared secret in bytes.
pub const PQ_SHARED_SECRET_SIZE: usize = 32;
/// Size of the classical shared secret in bytes.
pub const CLASSICAL_SHARED_SECRET_SIZE: usize = 32;
/// Size of the derived hybrid key in bytes.
pub const HYBRID_OUTPUT_SIZE: usize = 128;

/// Derives a hybrid key from post-quantum and classical shared secrets.
///
/// Implements the two-step Extract-and-Expand Key Derivation Function (HKDF)
/// as specified in NIST SP 800-56C Rev. 2.
///
/// # Arguments
/// * `pq_secret` - The 32-byte shared secret from the post-quantum KEM (e.g., ML-KEM-1024).
/// * `classical_secret` - The 32-byte shared secret from the classical KEX (e.g., X25519).
/// * `salt` - Optional salt value for the HKDF extraction phase.
/// * `info` - Context and application specific information for the HKDF expansion phase.
///
/// # Returns
/// A 128-byte derived hybrid key, or a `CryptoError` if derivation fails.
///
/// # Security
/// The input secrets (`pq_secret` and `classical_secret`) are securely zeroized
/// immediately after the extraction phase, regardless of whether the expansion succeeds or fails.
pub fn derive_hybrid_key(
    pq_secret: &mut [u8; PQ_SHARED_SECRET_SIZE],
    classical_secret: &mut [u8; CLASSICAL_SHARED_SECRET_SIZE],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; HYBRID_OUTPUT_SIZE], CryptoError> {
    let mut combined_entropy = [0u8; PQ_SHARED_SECRET_SIZE + CLASSICAL_SHARED_SECRET_SIZE];
    let mut derived_key = [0u8; HYBRID_OUTPUT_SIZE];

    combined_entropy[..PQ_SHARED_SECRET_SIZE].copy_from_slice(pq_secret);
    combined_entropy[PQ_SHARED_SECRET_SIZE..].copy_from_slice(classical_secret);

    let hkdf = Hkdf::<Sha384>::new(Some(salt), &combined_entropy);
    let res = hkdf.expand(info, &mut derived_key);

    // Zeroize inputs immediately after expand and before cache flush, regardless of error
    secure_zeroize(pq_secret);
    secure_zeroize(classical_secret);
    combined_entropy.zeroize();

    res.map_err(|_| CryptoError::HkdfError)?;

    secure_cache_flush(&derived_key);

    Ok(derived_key)
}
