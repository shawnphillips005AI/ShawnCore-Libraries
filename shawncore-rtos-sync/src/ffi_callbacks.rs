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

/// Type definition for the host OS callback to invalidate a cache range.
pub type CacheInvalidateCb = extern "C" fn(*const u8, usize);

/// Type definition for the host OS callback to flush a cache range.
pub type CacheFlushCb = extern "C" fn(*const u8, usize);
/// Type definition for the host OS callback to pet the hardware watchdog.
pub type PetWatchdogCb = extern "C" fn();

/// Global registry for the disable interrupts callback.
static DISABLE_INTERRUPTS_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Global registry for the restore interrupts callback.
static RESTORE_INTERRUPTS_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Global registry for the monotonic clock callback.
static READ_MONOTONIC_CLOCK_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CACHE_INVALIDATE_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CACHE_FLUSH_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static PET_WATCHDOG_CB: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Registers the host OS callback for disabling interrupts.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_disable_interrupts(
    cb: Option<DisableInterruptsCb>,
) {
    DISABLE_INTERRUPTS_CB.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
}

/// Registers the host OS callback for restoring interrupts.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_restore_interrupts(
    cb: Option<RestoreInterruptsCb>,
) {
    RESTORE_INTERRUPTS_CB.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
}

/// Registers the host OS callback for reading the monotonic clock.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_read_monotonic_clock(
    cb: Option<ReadMonotonicClockCb>,
) {
    READ_MONOTONIC_CLOCK_CB.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
}

/// Registers the host OS callback for invalidating a cache range.
/// It is invoked before the CPU-side consumer reads a slot that a device may have written.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_cache_invalidate(cb: Option<CacheInvalidateCb>) {
    CACHE_INVALIDATE_CB.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
}

/// Registers the host OS callback for flushing a cache range.
/// It is invoked after the CPU-side producer writes a slot that a device may read.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_cache_flush(cb: Option<CacheFlushCb>) {
    CACHE_FLUSH_CB.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
}

/// Registers the host OS callback for petting the hardware watchdog.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_pet_watchdog(cb: Option<PetWatchdogCb>) {
    PET_WATCHDOG_CB.store(
        cb.map_or(core::ptr::null_mut(), |callback| callback as *mut ()),
        Ordering::SeqCst,
    );
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

/// Invalidates a host cache range before the consumer reads a DMA slot.
pub(crate) fn host_cache_invalidate(ptr: *const u8, len: usize) {
    let cb_ptr = CACHE_INVALIDATE_CB.load(Ordering::Acquire);
    if cb_ptr.is_null() {
        invoke_panic_hook();
        loop {
            core::hint::spin_loop();
        }
    }
    unsafe {
        let cb: CacheInvalidateCb = core::mem::transmute(cb_ptr);
        cb(ptr, len);
    }
}

/// Flushes a host cache range after the CPU-side producer writes a slot.
pub(crate) fn host_cache_flush(ptr: *const u8, len: usize) {
    let cb_ptr = CACHE_FLUSH_CB.load(Ordering::Acquire);
    if cb_ptr.is_null() {
        invoke_panic_hook();
        loop {
            core::hint::spin_loop();
        }
    }
    unsafe {
        let cb: CacheFlushCb = core::mem::transmute(cb_ptr);
        cb(ptr, len);
    }
}

/// Pets the hardware watchdog using the registered host callback.
pub fn host_pet_watchdog() {
    let cb_ptr = PET_WATCHDOG_CB.load(Ordering::Acquire);
    if cb_ptr.is_null() {
        invoke_panic_hook();
        loop {
            core::hint::spin_loop();
        }
    }
    unsafe {
        let cb: PetWatchdogCb = core::mem::transmute(cb_ptr);
        cb();
    }
}
