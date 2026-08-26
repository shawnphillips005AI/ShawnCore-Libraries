#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Interrupt-Safe Spinlocks for RTOS Synchronization.
//!
//! Prevents ISR (Interrupt Service Routine) deadlocks by safely disabling
//! interrupts across the FFI boundary before acquiring the lock.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

/// Trait for architecture-specific interrupt management.
pub trait InterruptContext {
    /// Disables interrupts and returns the previous state flags.
    fn disable_and_save() -> usize;
    /// Restores the interrupt state flags.
    fn restore(flags: usize);
}

/// A local, interrupt-safe spinlock to prevent ISR deadlocks.
#[repr(C, align(64))]
pub struct InterruptSafeSpinlock<T, C: InterruptContext> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
    _marker: PhantomData<C>,
}

// # Safety
// Spinlock securely synchronizes access to the underlying `T` using atomic operations.
unsafe impl<T: Send, C: InterruptContext> Send for InterruptSafeSpinlock<T, C> {}
unsafe impl<T: Send, C: InterruptContext> Sync for InterruptSafeSpinlock<T, C> {}

impl<T, C: InterruptContext> InterruptSafeSpinlock<T, C> {
    /// Creates a new `InterruptSafeSpinlock`.
    #[must_use]
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
            _marker: PhantomData,
        }
    }

    /// Blocks until the lock can be acquired, disabling interrupts to prevent ISR deadlocks.
    #[must_use]
    pub fn lock(&self) -> SpinlockGuard<'_, T, C> {
        let saved_flags = C::disable_and_save();

        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }

        SpinlockGuard {
            lock: self,
            saved_flags,
        }
    }
}

/// A guard providing exclusive access to the `InterruptSafeSpinlock` data.
pub struct SpinlockGuard<'a, T, C: InterruptContext> {
    lock: &'a InterruptSafeSpinlock<T, C>,
    saved_flags: usize,
}

impl<T, C: InterruptContext> core::ops::Deref for SpinlockGuard<'_, T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        // # Safety
        // Spatial: `data.get()` returns a valid pointer.
        // Temporal: Protected by the acquired mutex.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T, C: InterruptContext> core::ops::DerefMut for SpinlockGuard<'_, T, C> {
    fn deref_mut(&mut self) -> &mut T {
        // # Safety
        // Spatial: `data.get()` returns a valid pointer.
        // Temporal: Protected by the acquired mutex.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T, C: InterruptContext> Drop for SpinlockGuard<'_, T, C> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        C::restore(self.saved_flags);
    }
}
