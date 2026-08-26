#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Hardware-Agnostic Time & Interrupt Registry.
//!
//! Allows the host OS (C/C++) to inject its own hardware-specific implementations
//! for interrupt management and monotonic clock reads, ensuring the Rust core
//! remains completely architecture-agnostic.

use crate::ffi_error::invoke_panic_hook;
use crate::interrupt_spinlock::InterruptContext;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Type definition for the host OS callback to disable interrupts and save state.
/// Returns an opaque `usize` representing the saved interrupt flags/state.
pub type DisableInterruptsCb = extern "C" fn() -> usize;

/// Type definition for the host OS callback to restore interrupt state.
/// Accepts the opaque `usize` previously returned by `DisableInterruptsCb`.
pub type RestoreInterruptsCb = extern "C" fn(usize);

/// Type definition for the host OS callback to read a monotonic hardware clock.
/// Returns a `u64` representing the current timestamp (e.g., TSC, generic timer).
pub type ReadMonotonicClockCb = extern "C" fn() -> u64;

/// Global registry for the disable interrupts callback.
static DISABLE_INTERRUPTS_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Global registry for the restore interrupts callback.
static RESTORE_INTERRUPTS_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Global registry for the monotonic clock callback.
static READ_MONOTONIC_CLOCK_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Registers the host OS callback for disabling interrupts.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_disable_interrupts(cb: DisableInterruptsCb) {
    DISABLE_INTERRUPTS_CB.store(cb as *mut (), Ordering::SeqCst);
}

/// Registers the host OS callback for restoring interrupts.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_restore_interrupts(cb: RestoreInterruptsCb) {
    RESTORE_INTERRUPTS_CB.store(cb as *mut (), Ordering::SeqCst);
}

/// Registers the host OS callback for reading the monotonic clock.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_read_monotonic_clock(cb: ReadMonotonicClockCb) {
    READ_MONOTONIC_CLOCK_CB.store(cb as *mut (), Ordering::SeqCst);
}

/// A concrete implementation of `InterruptContext` that delegates to the registered
/// host OS callbacks. This is used by `InterruptSafeSpinlock` to prevent ISR deadlocks.
pub struct HostInterruptContext;

impl InterruptContext for HostInterruptContext {
    fn disable_and_save() -> usize {
        let cb_ptr = DISABLE_INTERRUPTS_CB.load(Ordering::Acquire);

        if cb_ptr.is_null() {
            // Critical Flaw Fix: Prevent silent concurrency failure.
            // If the host OS failed to register the callback, we cannot safely acquire spinlocks.
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
            let cb: DisableInterruptsCb = core::mem::transmute(cb_ptr);
            cb()
        }
    }

    fn restore(flags: usize) {
        let cb_ptr = RESTORE_INTERRUPTS_CB.load(Ordering::Acquire);

        if cb_ptr.is_null() {
            // Critical Flaw Fix: Prevent silent concurrency failure.
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

/// Reads the monotonic clock using the registered host OS callback.
/// Used by `LatencyTracker` and `StateMachine` for hardware-agnostic timing.
#[must_use]
pub fn host_read_monotonic_clock() -> u64 {
    let cb_ptr = READ_MONOTONIC_CLOCK_CB.load(Ordering::Acquire);

    if cb_ptr.is_null() {
        // Critical Flaw Fix: Prevent silent timing failure.
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
        let cb: ReadMonotonicClockCb = core::mem::transmute(cb_ptr);
        cb()
    }
}
