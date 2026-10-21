// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Transcript encoding for the authenticated handshake.
//!
//! The authenticated handshake composes existing primitives in the signed-transcript pattern
//! used by TLS 1.3 and SIGMA: the hybrid ML-KEM-1024 + X25519 exchange is unchanged, and each
//! side then signs a hash of the whole exchange with its long-term ML-DSA-87 identity key
//! under a role-specific FIPS 204 context string. The peer verifies that signature against a
//! trust anchor (a verifying key) it was provisioned with out of band.
//!
//! ```text
//! key-generating side                                   encapsulating side
//!   initiate_handshake  ---------- ek, xK ---------->
//!                                                       encapsulate_authenticated
//!   finalize_authenticated  <--- ct, xE, sigma_E ----   (session keys derived, UNCONFIRMED)
//!   (verifies sigma_E, then keys are live)
//!                       ---------- sigma_K --------->   confirm_peer (keys become usable)
//! ```
//!
//! `binding` (everything known before the encapsulation) is also passed to the existing
//! handshake as its `info`, so the derived keys depend on it; `transcript` additionally covers
//! the ciphertext and the encapsulating side's X25519 key. Both signatures cover `transcript`.
//! Role contexts prevent a signature from one side being replayed as the other.
//!
//! This module defines encodings only. It has not been formally analyzed or independently
//! reviewed; see SECURITY.md before relying on it.

use crate::error::CryptoError;
use crate::ml_dsa_wrapper::PublicKey87;
use crate::ml_kem_wrapper::{Ciphertext1024, PublicKey1024};
use crate::x25519_wrapper::X25519Public;
use sha2::{Digest, Sha384};

/// Protocol version bound into every transcript.
pub const AUTH_PROTOCOL_VERSION: u8 = 1;

/// Suite identifier bound into every transcript; there is no negotiation.
pub const AUTH_SUITE: &[u8] = b"ML-KEM-1024+X25519;HKDF-SHA384;ChaCha20+HMAC-SHA384;ML-DSA-87";

/// FIPS 204 context string for the encapsulating side's signature.
pub const CONTEXT_ENCAPSULATING_SIDE: &[u8] = b"ShawnCore-auth-v1 encapsulating side";

/// FIPS 204 context string for the key-generating side's signature.
pub const CONTEXT_KEYGEN_SIDE: &[u8] = b"ShawnCore-auth-v1 key-generating side";

/// Length in bytes of an identity fingerprint, a binding or a transcript hash (SHA-384).
pub const AUTH_HASH_LEN: usize = 48;

const IDENTITY_LABEL: &[u8] = b"ShawnCore-auth-v1 identity";
const BINDING_LABEL: &[u8] = b"ShawnCore-auth-v1 binding";
const TRANSCRIPT_LABEL: &[u8] = b"ShawnCore-auth-v1 transcript";

/// SHA-384 of the identity label and the FIPS 204 encoding of a verifying key.
///
/// Both identities are bound into the transcript so a signature cannot be re-attributed to a
/// different pair of parties (an unknown-key-share attack).
#[must_use]
pub fn identity_fingerprint(verifying_key: &PublicKey87) -> [u8; AUTH_HASH_LEN] {
    let mut hasher = Sha384::new();
    hasher.update(IDENTITY_LABEL);
    hasher.update(verifying_key.to_bytes());
    let mut out = [0u8; AUTH_HASH_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Hash of everything known before encapsulation: the key-generating side's public keys, both
/// identities, the protocol version and suite, and the caller's `app_info`.
///
/// `app_info` is length-prefixed; it may be at most `u32::MAX` bytes.
pub fn handshake_binding(
    keygen_ml_kem_pk: &PublicKey1024,
    keygen_x25519_pk: &X25519Public,
    keygen_identity: &[u8; AUTH_HASH_LEN],
    encapsulator_identity: &[u8; AUTH_HASH_LEN],
    app_info: &[u8],
) -> Result<[u8; AUTH_HASH_LEN], CryptoError> {
    let app_info_len = u32::try_from(app_info.len()).map_err(|_| CryptoError::InvalidLength)?;
    let mut hasher = Sha384::new();
    hasher.update(BINDING_LABEL);
    hasher.update([AUTH_PROTOCOL_VERSION]);
    hasher.update((AUTH_SUITE.len() as u16).to_be_bytes());
    hasher.update(AUTH_SUITE);
    hasher.update(keygen_ml_kem_pk.to_bytes());
    hasher.update(keygen_x25519_pk.0);
    hasher.update(keygen_identity);
    hasher.update(encapsulator_identity);
    hasher.update(app_info_len.to_be_bytes());
    hasher.update(app_info);
    let mut out = [0u8; AUTH_HASH_LEN];
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// Hash that both signatures cover: the binding plus the ciphertext and the encapsulating
/// side's X25519 public key.
#[must_use]
pub fn transcript_hash(
    binding: &[u8; AUTH_HASH_LEN],
    ciphertext: &Ciphertext1024,
    encapsulator_x25519_pk: &X25519Public,
) -> [u8; AUTH_HASH_LEN] {
    let mut hasher = Sha384::new();
    hasher.update(TRANSCRIPT_LABEL);
    hasher.update(binding);
    hasher.update(ciphertext.0);
    hasher.update(encapsulator_x25519_pk.0);
    let mut out = [0u8; AUTH_HASH_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}
