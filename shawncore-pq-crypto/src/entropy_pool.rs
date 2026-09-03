#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Fortuna-style asynchronous entropy pool.
//!
//! Hardware-agnostic implementation for MarTac USVs.
//! Mitigates RNG exhaustion DoS vectors by providing a continuously
//! seeded background accumulator fed by the host OS via the `EntropyQueue`.
//! Integrates with the host OS interrupt context to prevent ISR deadlocks.
//! Uses domain-separated output and state evolution after the host has supplied
//! entropy. Input entropy quality remains a host and hardware responsibility.

use crate::entropy_queue::{EntropyQueue, ENTROPY_CHUNK_SIZE};
use crate::error::CryptoError;
use crate::ffi_callbacks::{HostInterruptContext, InterruptContext};
use crate::zeroize::{secure_cache_flush_raw, secure_zeroize};
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sha2::{Digest, Sha384};

/// A local, interrupt-safe spinlock to prevent ISR deadlocks.
///
/// Uses the host OS interrupt context to safely disable/restore interrupts
/// across the FFI boundary before acquiring the lock.
#[repr(C, align(64))]
pub struct CryptoSpinlock<T, C: InterruptContext> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
    _marker: PhantomData<C>,
}

// # Safety
// Spinlock securely synchronizes access to the underlying `T` using atomic operations.
unsafe impl<T: Send, C: InterruptContext> Send for CryptoSpinlock<T, C> {}
unsafe impl<T: Send, C: InterruptContext> Sync for CryptoSpinlock<T, C> {}

impl<T, C: InterruptContext> CryptoSpinlock<T, C> {
    /// Creates a new `CryptoSpinlock`.
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
    pub fn lock(&self) -> CryptoSpinlockGuard<'_, T, C> {
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

        CryptoSpinlockGuard {
            lock: self,
            saved_flags,
        }
    }
}

/// A guard providing exclusive access to the `CryptoSpinlock` data.
pub struct CryptoSpinlockGuard<'a, T, C: InterruptContext> {
    lock: &'a CryptoSpinlock<T, C>,
    saved_flags: usize,
}

impl<T, C: InterruptContext> core::ops::Deref for CryptoSpinlockGuard<'_, T, C> {
    type Target = T;

    fn deref(&self) -> &T {
        // # Safety
        // Spatial: `data.get()` returns a pointer to the inner data.
        // Temporal: The data is protected by the mutex.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T, C: InterruptContext> core::ops::DerefMut for CryptoSpinlockGuard<'_, T, C> {
    fn deref_mut(&mut self) -> &mut T {
        // # Safety
        // Spatial: `data.get()` returns a pointer to the inner data.
        // Temporal: The data is protected by the mutex.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T, C: InterruptContext> Drop for CryptoSpinlockGuard<'_, T, C> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        C::restore(self.saved_flags);
    }
}

/// Global asynchronous entropy queue fed by the host OS.
pub static GLOBAL_ENTROPY_QUEUE: EntropyQueue = EntropyQueue::new();

/// Global asynchronous entropy pool.
pub static GLOBAL_ENTROPY_POOL: EntropyPool = EntropyPool::new();

/// Fortuna-style entropy accumulator.
///
/// Mixes incoming entropy chunks from the `GLOBAL_ENTROPY_QUEUE` into a
/// SHA-384 digest state, providing a continuous stream of cryptographically
/// secure pseudorandom bytes.
pub struct EntropyPool {
    pool: CryptoSpinlock<[u8; 48], HostInterruptContext>,
    reseed_count: AtomicU64,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyPool {
    /// Creates a new, empty entropy pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pool: CryptoSpinlock::new([0u8; 48]),
            reseed_count: AtomicU64::new(0),
        }
    }

    /// Drains the global entropy queue and mixes it into the pool.
    ///
    /// This function is called automatically during `extract_entropy`, but can
    /// also be triggered manually by the host OS via FFI to ensure the pool
    /// is continuously seeded during idle periods.
    pub fn mix_entropy(&self) {
        let mut chunk = [0u8; ENTROPY_CHUNK_SIZE];
        let mixed = {
            let mut guard = self.pool.lock();
            let mut hasher = Sha384::new();
            hasher.update(*guard);

            let mut mixed = false;
            while unsafe { GLOBAL_ENTROPY_QUEUE.pop(&mut chunk) } {
                hasher.update(chunk);
                secure_zeroize(&mut chunk);
                mixed = true;
            }

            if mixed {
                let result = hasher.finalize();
                guard.copy_from_slice(&result);
            }
            mixed
        };

        if mixed {
            unsafe {
                secure_cache_flush_raw(
                    self.pool.data.get().cast(),
                    core::mem::size_of::<[u8; 48]>(),
                )
            };
            self.reseed_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Extracts entropy from the accumulator.
    ///
    /// Automatically mixes any pending entropy from the queue before extraction.
    /// Uses distinct `0x00` and `0x01` prefixes for output and state evolution.
    /// This is not a statement about entropy-source quality, which must be
    /// established by the host and target hardware.
    ///
    /// # Arguments
    /// * `out` - A mutable byte slice to be filled with pseudorandom data.
    ///
    /// # Returns
    /// `Ok(())` if successful, or `CryptoError::EntropyStarvation` if the pool
    /// has never been seeded by the host OS.
    pub fn extract_entropy(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        self.mix_entropy();

        if self.reseed_count.load(Ordering::Acquire) == 0 {
            return Err(CryptoError::EntropyStarvation);
        }

        {
            let mut guard = self.pool.lock();
            let mut offset = 0;

            while offset < out.len() {
                // Forward Secrecy: Domain separation for output generation
                let mut out_hasher = Sha384::new();
                out_hasher.update([0x00]); // Domain separator for output
                out_hasher.update(*guard);
                let out_result = out_hasher.finalize();

                // Forward Secrecy: Domain separation for internal state update
                let mut state_hasher = Sha384::new();
                state_hasher.update([0x01]); // Domain separator for state update
                state_hasher.update(*guard);
                let state_result = state_hasher.finalize();

                let copy_len = core::cmp::min(48, out.len() - offset);
                out[offset..offset + copy_len].copy_from_slice(&out_result[..copy_len]);

                // Update pool state to the new forward-secret hash
                guard.copy_from_slice(&state_result);

                offset += copy_len;
            }
        }

        unsafe {
            secure_cache_flush_raw(
                self.pool.data.get().cast(),
                core::mem::size_of::<[u8; 48]>(),
            )
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_callbacks::{
        shawncore_crypto_register_cache_flush, shawncore_crypto_register_disable_interrupts,
        shawncore_crypto_register_restore_interrupts,
    };
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    static REENTRY_TEST_POOL: EntropyPool = EntropyPool::new();
    static REENTRY_CACHE_RANGE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
    static REENTERED: AtomicBool = AtomicBool::new(false);

    extern "C" fn disable_interrupts() -> usize {
        0
    }

    extern "C" fn restore_interrupts(_: usize) {}

    extern "C" fn reentrant_cache_flush(ptr: *const u8, _: usize) {
        if ptr != REENTRY_CACHE_RANGE.load(Ordering::Acquire)
            || REENTERED.swap(true, Ordering::AcqRel)
        {
            return;
        }
        REENTRY_TEST_POOL.mix_entropy();
    }

    #[test]
    fn cache_callback_can_reenter_entropy_mixing_without_deadlocking() {
        unsafe {
            shawncore_crypto_register_disable_interrupts(Some(disable_interrupts));
            shawncore_crypto_register_restore_interrupts(Some(restore_interrupts));
            shawncore_crypto_register_cache_flush(Some(reentrant_cache_flush));
        }
        REENTERED.store(false, Ordering::Release);
        REENTRY_CACHE_RANGE.store(REENTRY_TEST_POOL.pool.data.get().cast(), Ordering::Release);

        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            unsafe { GLOBAL_ENTROPY_QUEUE.push(&[0x42; ENTROPY_CHUNK_SIZE]) }.unwrap();
            REENTRY_TEST_POOL.mix_entropy();
            sender
                .send(REENTRY_TEST_POOL.reseed_count.load(Ordering::Acquire))
                .unwrap();
        });

        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        handle.join().unwrap();
        assert!(REENTERED.load(Ordering::Acquire));
        REENTRY_CACHE_RANGE.store(ptr::null_mut(), Ordering::Release);
    }
}
