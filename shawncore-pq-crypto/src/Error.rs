#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Cryptographic error types.
//! Provides standard error enumerations for the post-quantum cryptographic stack.

/// Cryptographic errors for the post-quantum stack.
/// Maps directly to C-compatible FFI error codes for host OS integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid state encountered during cryptographic operations.
    InvalidState,
    /// Invalid length provided for keys, nonces, or tags.
    InvalidLength,
    /// HKDF expansion or extraction error.
    HkdfError,
    /// Cryptographic signature or MAC verification failed.
    VerificationFailed,
    /// Entropy pool starvation.
    EntropyStarvation,
}
