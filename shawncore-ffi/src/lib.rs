// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

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
use core::sync::atomic::{AtomicBool, Ordering};

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
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Returns true only for the first caller, so a panic raised by a host hook halts instead of recursing.
fn begin_panic(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::AcqRel)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    if begin_panic(&PANIC_IN_PROGRESS) {
        shawncore_pq_crypto::ffi_error::invoke_panic_hook();
        shawncore_rtos_sync::ffi_error::invoke_panic_hook();
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_first_panic_runs_the_host_hooks() {
        let flag = AtomicBool::new(false);
        assert!(begin_panic(&flag));
        assert!(!begin_panic(&flag));
        assert!(!begin_panic(&flag));
    }
}
