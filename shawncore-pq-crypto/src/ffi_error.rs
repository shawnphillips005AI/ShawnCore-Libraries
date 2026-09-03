#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! FFI Error Handling and Panic Safety.
//! Provides C-compatible error codes and a panic hook registry to prevent
//! cross-boundary unwinding Undefined Behavior (UB).

use core::sync::atomic::{AtomicPtr, Ordering};

/// C-compatible error codes for the ShawnCore Crypto library.
/// Ensures safe error propagation across the FFI boundary.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShawncoreCryptoErr {
    /// Operation completed successfully.
    Success = 0,
    /// Invalid state encountered.
    InvalidState = 1,
    /// Invalid length provided.
    InvalidLength = 2,
    /// HKDF expansion or extraction error.
    HkdfError = 3,
    /// Cryptographic signature or MAC verification failed.
    VerificationFailed = 4,
    /// Entropy pool starvation.
    EntropyStarvation = 5,
    /// A panic occurred within the Rust boundary.
    Panic = 99,
}

impl From<crate::error::CryptoError> for ShawncoreCryptoErr {
    fn from(err: crate::error::CryptoError) -> Self {
        match err {
            crate::error::CryptoError::InvalidState => Self::InvalidState,
            crate::error::CryptoError::InvalidLength => Self::InvalidLength,
            crate::error::CryptoError::HkdfError => Self::HkdfError,
            crate::error::CryptoError::VerificationFailed => Self::VerificationFailed,
            crate::error::CryptoError::EntropyStarvation => Self::EntropyStarvation,
        }
    }
}

/// Type definition for the host OS panic callback.
pub type PanicCallback = extern "C" fn();

/// Global registry for the host OS panic callback.
static PANIC_CALLBACK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Registers a host OS callback to be invoked upon a Rust panic.
/// This prevents unwinding across the FFI boundary.
///
/// # Safety
/// When present, `cb` must be a valid C-ABI function for every possible call.
/// Registration and replacement must not race with callback invocation.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_register_panic_hook(cb: Option<PanicCallback>) {
    PANIC_CALLBACK.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
}

/// Invokes the registered panic callback.
/// Designed to be called from the global `#[panic_handler]` in the final binary
/// or during unrecoverable internal state corruption.
pub fn invoke_panic_hook() {
    let cb_ptr = PANIC_CALLBACK.load(Ordering::Acquire);

    if !cb_ptr.is_null() {
        // # Safety
        // Spatial: N/A.
        // Temporal: The host OS guarantees the callback remains valid for the lifetime of the program.
        // Alignment: N/A.
        unsafe {
            let cb: PanicCallback = core::mem::transmute(cb_ptr);
            cb();
        }
    }
}
