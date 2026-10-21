// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Transcript, confirmation and signing encodings for the authenticated handshake (version 2).
//!
//! The authenticated handshake composes existing primitives in the signed-transcript pattern
//! used by TLS 1.3 and SIGMA and adds explicit key confirmation. The hybrid ML-KEM-1024 +
//! X25519 exchange is the unauthenticated one, unchanged. Four properties are provided by four
//! different mechanisms and are **not interchangeable**:
//!
//! | Property | Mechanism |
//! | --- | --- |
//! | Identity authentication | ML-DSA-87 signature under a role-specific FIPS 204 context, verified against a trust anchor |
//! | Key agreement | The hybrid KEM + X25519 exchange and HKDF-SHA384; the signed `binding` is its `info` |
//! | Key confirmation | HMAC-SHA384 under a confirmation key expanded from the same PRK with its own label |
//! | Application-data authorization | A session accepts traffic only after the steps above succeeded on that side |
//!
//! ```text
//! key-generating side (K)                               encapsulating side (E)
//!   initiate_handshake  ---------- ek, xK ---------->
//!                                                       encapsulate_authenticated
//!                       <--- ct, xE, sigma_E, tag_E --- (keys derived, UNCONFIRMED)
//!   finalize_authenticated
//!     verify sigma_E, derive keys, verify tag_E, install keys
//!                       ---------- sigma_K, tag_K ---->   confirm_peer
//!                                                         verify sigma_K, verify tag_K, open
//! ```
//!
//! Each signature covers the preceding transcript **and** the same side's confirmation tag, so
//! any alteration of a message is an unauthenticated-input rejection that consumes no state.
//! `salt` is deliberately not part of the transcript: it may be a secret pre-shared key. It
//! enters the PRK, so a salt mismatch changes the confirmation keys and is caught by the tags.
//!
//! This module defines encodings only. The design has not been formally analyzed or
//! independently reviewed; see SECURITY.md before relying on it.

use crate::aead_wrapper::{hmac_sha384, verify_tag_constant_time};
use crate::error::CryptoError;
use crate::ml_dsa_wrapper::PublicKey87;
use crate::ml_kem_wrapper::{Ciphertext1024, PublicKey1024};
use crate::x25519_wrapper::X25519Public;
use sha2::{Digest, Sha384};

/// Protocol version bound into every transcript. Version 1 (signatures only, no key
/// confirmation) is not supported and does not interoperate.
pub const AUTH_PROTOCOL_VERSION: u8 = 2;

/// Suite identifier bound into every transcript; there is no negotiation.
pub const AUTH_SUITE: &[u8] =
    b"ML-KEM-1024+X25519;HKDF-SHA384;ChaCha20+HMAC-SHA384;ML-DSA-87;HMAC-SHA384-KC";

/// FIPS 204 context string for the encapsulating side's signature.
pub const CONTEXT_ENCAPSULATING_SIDE: &[u8] = b"ShawnCore-auth-v2 encapsulating side";

/// FIPS 204 context string for the key-generating side's signature.
pub const CONTEXT_KEYGEN_SIDE: &[u8] = b"ShawnCore-auth-v2 key-generating side";

/// MAC label for the encapsulating side's key-confirmation tag.
pub const CONFIRM_LABEL_ENCAPSULATING_SIDE: &[u8] = b"ShawnCore-auth-v2 confirm encapsulating side";

/// MAC label for the key-generating side's key-confirmation tag.
pub const CONFIRM_LABEL_KEYGEN_SIDE: &[u8] = b"ShawnCore-auth-v2 confirm key-generating side";

/// Length in bytes of an identity fingerprint, a binding, a digest or a confirmation tag (SHA-384).
pub const AUTH_HASH_LEN: usize = 48;

/// Length in bytes of a key-confirmation tag (HMAC-SHA384).
pub const CONFIRMATION_TAG_LEN: usize = 48;

/// Length of one confirmation key; the 96-byte expansion is `key_E || key_K`.
pub const CONFIRMATION_KEY_LEN: usize = 48;

pub use crate::hybrid_kdf::{
    confirmation_info, CONFIRMATION_INFO_LEN, KEY_CONFIRMATION_INFO_LABEL,
};

const IDENTITY_LABEL: &[u8] = b"ShawnCore-auth-v2 identity";
const BINDING_LABEL: &[u8] = b"ShawnCore-auth-v2 binding";
const TRANSCRIPT_LABEL: &[u8] = b"ShawnCore-auth-v2 transcript";
const ENCAPSULATOR_DIGEST_LABEL: &[u8] = b"ShawnCore-auth-v2 encapsulator digest";
const KEYGEN_DIGEST_LABEL: &[u8] = b"ShawnCore-auth-v2 key-generator digest";

fn sha384(parts: &[&[u8]]) -> [u8; AUTH_HASH_LEN] {
    let mut hasher = Sha384::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; AUTH_HASH_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// SHA-384 of the identity label and the FIPS 204 encoding of a verifying key.
///
/// Both identities are bound into the transcript so a signature cannot be re-attributed to a
/// different pair of parties (an unknown-key-share attack).
#[must_use]
pub fn identity_fingerprint(verifying_key: &PublicKey87) -> [u8; AUTH_HASH_LEN] {
    sha384(&[IDENTITY_LABEL, &verifying_key.to_bytes()])
}

/// Hash of everything known before encapsulation: the key-generating side's public keys, both
/// identities, the protocol version and suite, and the caller's `app_info`.
///
/// `app_info` is length-prefixed; it may be at most `u32::MAX` bytes. The HKDF `salt` is not an
/// input (see the module documentation).
pub fn handshake_binding(
    keygen_ml_kem_pk: &PublicKey1024,
    keygen_x25519_pk: &X25519Public,
    keygen_identity: &[u8; AUTH_HASH_LEN],
    encapsulator_identity: &[u8; AUTH_HASH_LEN],
    app_info: &[u8],
) -> Result<[u8; AUTH_HASH_LEN], CryptoError> {
    let app_info_len = u32::try_from(app_info.len()).map_err(|_| CryptoError::InvalidLength)?;
    Ok(sha384(&[
        BINDING_LABEL,
        &[AUTH_PROTOCOL_VERSION],
        &(AUTH_SUITE.len() as u16).to_be_bytes(),
        AUTH_SUITE,
        &keygen_ml_kem_pk.to_bytes(),
        &keygen_x25519_pk.0,
        keygen_identity,
        encapsulator_identity,
        &app_info_len.to_be_bytes(),
        app_info,
    ]))
}

/// Hash of the binding plus the ciphertext and the encapsulating side's X25519 public key.
/// Both key-confirmation tags are computed over values derived from it.
#[must_use]
pub fn transcript_hash(
    binding: &[u8; AUTH_HASH_LEN],
    ciphertext: &Ciphertext1024,
    encapsulator_x25519_pk: &X25519Public,
) -> [u8; AUTH_HASH_LEN] {
    sha384(&[
        TRANSCRIPT_LABEL,
        binding,
        &ciphertext.0,
        &encapsulator_x25519_pk.0,
    ])
}

/// What the encapsulating side's tag is computed over and what its signature covers:
/// the transcript and its own confirmation tag.
#[must_use]
pub fn encapsulator_digest(
    transcript: &[u8; AUTH_HASH_LEN],
    encapsulator_tag: &[u8; CONFIRMATION_TAG_LEN],
) -> [u8; AUTH_HASH_LEN] {
    sha384(&[ENCAPSULATOR_DIGEST_LABEL, transcript, encapsulator_tag])
}

/// What the key-generating side's signature covers: the encapsulator digest and its own tag.
#[must_use]
pub fn keygen_digest(
    encapsulator_digest: &[u8; AUTH_HASH_LEN],
    keygen_tag: &[u8; CONFIRMATION_TAG_LEN],
) -> [u8; AUTH_HASH_LEN] {
    sha384(&[KEYGEN_DIGEST_LABEL, encapsulator_digest, keygen_tag])
}

/// `HMAC-SHA384(key, label || digest)`: a key-confirmation tag.
///
/// Each role uses its own key and its own label, so a tag from one role or direction cannot
/// verify as the other.
pub fn confirmation_tag(
    key: &[u8; CONFIRMATION_KEY_LEN],
    label: &[u8],
    digest: &[u8; AUTH_HASH_LEN],
) -> Result<[u8; CONFIRMATION_TAG_LEN], CryptoError> {
    let mut message = [0u8; 128];
    let used = label.len() + AUTH_HASH_LEN;
    if used > message.len() {
        return Err(CryptoError::InvalidLength);
    }
    message[..label.len()].copy_from_slice(label);
    message[label.len()..used].copy_from_slice(digest);
    hmac_sha384(key, &message[..used])
}

/// Constant-time comparison of two confirmation tags.
#[must_use]
pub fn confirmation_tags_equal(
    expected: &[u8; CONFIRMATION_TAG_LEN],
    presented: &[u8; CONFIRMATION_TAG_LEN],
) -> bool {
    verify_tag_constant_time(expected, presented)
}
