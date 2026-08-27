#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Hardware-Agnostic Callbacks for Cryptography.
//! Allows the host OS (C/C++) to inject its own hardware-specific implementations
//! for interrupt management, cache flushing, and stack wiping.

use crate::ffi_error::invoke_panic_hook;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Trait for architecture-specific interrupt management.
pub trait InterruptContext {
    /// Disables interrupts and returns the previous interrupt state/flags.
    fn disable_and_save() -> usize;
    /// Restores the interrupt state/flags.
    fn restore(flags: usize);
}

/// Type definition for the host OS callback to disable interrupts and save state.
pub type DisableInterruptsCb = extern "C" fn() -> usize;
/// Type definition for the host OS callback to restore interrupt state.
pub type RestoreInterruptsCb = extern "C" fn(usize);
/// Type definition for the host OS callback to flush data cache to main memory.
pub type CacheFlushCb = extern "C" fn(*const u8, usize);

static DISABLE_INTERRUPTS_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static RESTORE_INTERRUPTS_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CACHE_FLUSH_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Registers the host OS callback for disabling interrupts.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_register_disable_interrupts(cb: DisableInterruptsCb) {
    DISABLE_INTERRUPTS_CB.store(cb as *mut (), Ordering::SeqCst);
}

/// Registers the host OS callback for restoring interrupts.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_register_restore_interrupts(cb: RestoreInterruptsCb) {
    RESTORE_INTERRUPTS_CB.store(cb as *mut (), Ordering::SeqCst);
}

/// Registers the host OS callback for cache flushing.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_register_cache_flush(cb: CacheFlushCb) {
    CACHE_FLUSH_CB.store(cb as *mut (), Ordering::SeqCst);
}

/// A concrete implementation of `InterruptContext` that delegates to the registered host OS callbacks.
pub struct HostInterruptContext;

impl InterruptContext for HostInterruptContext {
    fn disable_and_save() -> usize {
        let cb_ptr = DISABLE_INTERRUPTS_CB.load(Ordering::Acquire);

        if cb_ptr.is_null() {
            invoke_panic_hook();
            loop {
                core::hint::spin_loop();
            } // Halt on silent concurrency failure
        }

        // # Safety
        // Spatial: N/A.
        // Temporal: The host OS guarantees the callback remains valid.
        // Alignment: N/A.
        unsafe {
            let cb: DisableInterruptsCb = core::mem::transmute(cb_ptr);
            cb()
        }
    }

    fn restore(flags: usize) {
        let cb_ptr = RESTORE_INTERRUPTS_CB.load(Ordering::Acquire);

        if cb_ptr.is_null() {
            invoke_panic_hook();
            loop {
                core::hint::spin_loop();
            }
        }

        // # Safety
        // Spatial: N/A.
        // Temporal: The host OS guarantees the callback remains valid.
        // Alignment: N/A.
        unsafe {
            let cb: RestoreInterruptsCb = core::mem::transmute(cb_ptr);
            cb(flags);
        }
    }
}

/// Flushes the cache using the registered host OS callback.
pub fn host_cache_flush(ptr: *const u8, len: usize) {
    let cb_ptr = CACHE_FLUSH_CB.load(Ordering::Acquire);

    if cb_ptr.is_null() {
        invoke_panic_hook();
        loop {
            core::hint::spin_loop();
        }
    }

    // # Safety
    // Spatial: `ptr` and `len` are validated by the caller.
    // Temporal: The host OS guarantees the callback remains valid.
    // Alignment: N/A.
    unsafe {
        let cb: CacheFlushCb = core::mem::transmute(cb_ptr);
        cb(ptr, len);
    }
}
