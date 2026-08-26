#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! ShawnCore Post-Quantum Cryptography Library
//! Hardware-agnostic CNSA 2.0 compliant cryptographic stack for MarTac USVs.
//! Designed for seamless C/C++ host OS integration via FFI.

pub mod aead_wrapper;
pub mod chacha20;
pub mod entropy_pool;
pub mod entropy_queue;
pub mod error;
pub mod ffi;
pub mod ffi_callbacks;
pub mod ffi_error;
pub mod hybrid_kdf;
pub mod ml_dsa_wrapper;
pub mod ml_kem_wrapper;
pub mod session_manager;
pub mod x25519_wrapper;
pub mod zeroize;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Trigger the host OS panic callback to prevent cross-boundary unwinding UB.
    crate::ffi_error::invoke_panic_hook();
    
    // If the host OS callback returns (it shouldn't), halt the thread safely.
    loop {
        core::hint::spin_loop();
    }
}
