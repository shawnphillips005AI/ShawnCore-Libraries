// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! NIST SP 800-56C Rev. 2 Hybrid Key Derivation Function.
//! Combines classical and post-quantum shared secrets into a single key.
//! Hardware-agnostic implementation for autonomous surface vehicles.
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

/// HKDF info prefix of the confirmation-key expansion; the session keys use no such prefix.
pub const KEY_CONFIRMATION_INFO_LABEL: &[u8] = b"ShawnCore-auth-v2 key confirmation";

/// Length of the confirmation HKDF info: the label, a zero separator, then a 48-byte transcript.
pub const CONFIRMATION_INFO_LEN: usize = KEY_CONFIRMATION_INFO_LABEL.len() + 1 + 48;

/// HKDF info for the confirmation expansion: the label, a zero separator byte, then the inner
/// handshake transcript that is also the session-key info.
#[must_use]
pub fn confirmation_info(inner_transcript: &[u8; 48]) -> [u8; CONFIRMATION_INFO_LEN] {
    let mut out = [0u8; CONFIRMATION_INFO_LEN];
    out[..KEY_CONFIRMATION_INFO_LABEL.len()].copy_from_slice(KEY_CONFIRMATION_INFO_LABEL);
    out[KEY_CONFIRMATION_INFO_LABEL.len() + 1..].copy_from_slice(inner_transcript);
    out
}

/// Size of the key-confirmation material derived next to the session keys.
pub const CONFIRMATION_OUTPUT_SIZE: usize = 96;

/// [`derive_hybrid_key`] plus an independent key-confirmation expansion from the same PRK.
///
/// The first 128 bytes are byte-identical to `derive_hybrid_key(.., info)`. The second output is
/// `HKDF-Expand(PRK, confirmation_info, 96)`; the caller must make `confirmation_info` differ
/// from `info` (a distinct label prefix) so the two outputs are independent. Because the PRK is
/// `HMAC(salt, pq_secret || classical_secret)`, whoever computes the confirmation material has
/// the same salt and the same two shared secrets, and therefore the same session keys.
///
/// Inputs are zeroized on every path, as in [`derive_hybrid_key`].
pub fn derive_hybrid_key_with_confirmation(
    pq_secret: &mut [u8; PQ_SHARED_SECRET_SIZE],
    classical_secret: &mut [u8; CLASSICAL_SHARED_SECRET_SIZE],
    salt: &[u8],
    info: &[u8],
    confirmation_info: &[u8],
) -> Result<([u8; HYBRID_OUTPUT_SIZE], [u8; CONFIRMATION_OUTPUT_SIZE]), CryptoError> {
    let mut combined_entropy = [0u8; PQ_SHARED_SECRET_SIZE + CLASSICAL_SHARED_SECRET_SIZE];
    let mut derived_key = [0u8; HYBRID_OUTPUT_SIZE];
    let mut confirmation = [0u8; CONFIRMATION_OUTPUT_SIZE];

    combined_entropy[..PQ_SHARED_SECRET_SIZE].copy_from_slice(pq_secret);
    combined_entropy[PQ_SHARED_SECRET_SIZE..].copy_from_slice(classical_secret);

    let hkdf = Hkdf::<Sha384>::new(Some(salt), &combined_entropy);
    let session_res = hkdf.expand(info, &mut derived_key);
    let confirmation_res = hkdf.expand(confirmation_info, &mut confirmation);

    secure_zeroize(pq_secret);
    secure_zeroize(classical_secret);
    combined_entropy.zeroize();

    if session_res.is_err() || confirmation_res.is_err() {
        derived_key.zeroize();
        confirmation.zeroize();
        return Err(CryptoError::HkdfError);
    }

    secure_cache_flush(&derived_key);
    secure_cache_flush(&confirmation);

    Ok((derived_key, confirmation))
}

#[cfg(test)]
mod confirmation_tests {
    use super::*;

    fn secrets() -> ([u8; 32], [u8; 32]) {
        ([0x11; 32], [0x22; 32])
    }

    fn derive(salt: &[u8], info: &[u8]) -> ([u8; 128], [u8; 96]) {
        crate::test_support::install_callbacks();
        let (mut pq, mut classical) = secrets();
        derive_hybrid_key_with_confirmation(
            &mut pq,
            &mut classical,
            salt,
            info,
            &confirmation_info(&[0x33; 48]),
        )
        .unwrap()
    }

    #[test]
    fn session_keys_are_identical_to_the_legacy_derivation() {
        crate::test_support::install_callbacks();
        let (mut pq, mut classical) = secrets();
        let legacy = derive_hybrid_key(&mut pq, &mut classical, b"salt", &[0x33; 48]).unwrap();
        let (session, _) = derive(b"salt", &[0x33; 48]);
        assert_eq!(session, legacy);
    }

    #[test]
    fn confirmation_keys_are_distinct_and_independent_of_the_session_keys() {
        let (session, confirmation) = derive(b"salt", &[0x33; 48]);
        let (encapsulator, keygen) = confirmation.split_at(48);
        assert_ne!(encapsulator, keygen, "one key per role");
        for window in session.windows(48) {
            assert_ne!(window, encapsulator);
            assert_ne!(window, keygen);
        }
    }

    #[test]
    fn a_different_salt_changes_every_confirmation_key() {
        let (_, a) = derive(b"salt A", &[0x33; 48]);
        let (_, b) = derive(b"salt B", &[0x33; 48]);
        assert_ne!(a[..48], b[..48]);
        assert_ne!(a[48..], b[48..]);
    }

    #[test]
    fn confirmation_info_has_a_distinct_label_and_a_separator() {
        let info = confirmation_info(&[0x44; 48]);
        assert!(info.starts_with(KEY_CONFIRMATION_INFO_LABEL));
        assert_eq!(info[KEY_CONFIRMATION_INFO_LABEL.len()], 0);
        assert_eq!(&info[KEY_CONFIRMATION_INFO_LABEL.len() + 1..], &[0x44; 48]);
        assert_eq!(info.len(), CONFIRMATION_INFO_LEN);
    }

    #[test]
    fn inputs_are_zeroized() {
        crate::test_support::install_callbacks();
        let (mut pq, mut classical) = secrets();
        derive_hybrid_key_with_confirmation(
            &mut pq,
            &mut classical,
            b"salt",
            &[0x33; 48],
            &confirmation_info(&[0x33; 48]),
        )
        .unwrap();
        assert_eq!((pq, classical), ([0; 32], [0; 32]));
    }
}
