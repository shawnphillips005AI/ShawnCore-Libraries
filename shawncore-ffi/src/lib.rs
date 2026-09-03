#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! C-linkable facade for the ShawnCore component libraries.
//!
//! This crate owns the single panic handler required by a `no_std` static
//! library. The component crates retain ownership of their existing exported
//! C ABI functions, which are linked into this archive through these exports.

#[cfg(not(test))]
use core::panic::PanicInfo;

/// Retains the crypto FFI symbols in the static archive.
pub use shawncore_pq_crypto as crypto;
/// Retains the RTOS FFI symbols in the static archive.
pub use shawncore_rtos_sync as rtos;

/// Satisfies compiler metadata when this abort-on-panic archive is linked by C.
///
/// The facade's panic handler never unwinds, so this symbol must not be invoked.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    shawncore_pq_crypto::ffi_error::invoke_panic_hook();
    shawncore_rtos_sync::ffi_error::invoke_panic_hook();
    loop {
        core::hint::spin_loop();
    }
}
