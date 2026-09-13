// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Fortuna-style asynchronous entropy pool.
//!
//! Hardware-agnostic implementation for autonomous surface vehicles.
//! Mitigates RNG exhaustion DoS vectors by providing a continuously
//! seeded background accumulator fed by the host OS via the `EntropyQueue`.
//! Integrates with the host OS interrupt context to prevent ISR deadlocks.
//! Uses domain-separated output and state evolution after the host has supplied
//! entropy. Input entropy quality remains a host and hardware responsibility.

use crate::entropy_queue::{EntropyQueue, ENTROPY_CHUNK_SIZE};

/// Upper bound on entropy chunks mixed by one invocation. Keeping this bounded
/// prevents an unexpectedly full queue from turning one host/ISR call into an
/// unbounded amount of hashing work. Remaining chunks are left queued for a
/// later invocation.
pub const MAX_MIX_CHUNKS_PER_CALL: usize = 8;
/* PATCH: entropy operation gate unifies mix/extract transaction */
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

/// Releases high-level entropy-operation ownership when dropped.
struct EntropyOperationGuard<'a>(&'a AtomicBool);

impl Drop for EntropyOperationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Global asynchronous entropy queue fed by the host OS.
pub static GLOBAL_ENTROPY_QUEUE: EntropyQueue = EntropyQueue::new();

/// Process-wide gate protecting the single-consumer side of `GLOBAL_ENTROPY_QUEUE`.
///
/// `EntropyPool` instances can be constructed independently, but the queue they
/// consume is global and SPSC. Therefore its consumer ownership must also be
/// global; a per-instance `EntropyPool::mixing` flag is insufficient.
static GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE: AtomicBool = AtomicBool::new(false);

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
    /// Serializes mutating operations on this pool instance.
    ///
    /// This does not own the global queue consumer; that role is protected by
    /// `GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE`.
    mixing: AtomicBool,
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
            mixing: AtomicBool::new(false),
        }
    }

    /// Mixes up to eight queued entropy chunks into the pool per invocation.
    /// Remaining chunks stay queued for subsequent invocations so queue backlog
    /// cannot turn one call into an unbounded amount of SHA-384 work.
    ///
    /// The per-pool operation gate is acquired before any pool mutation. The
    /// global queue-consumer gate separately serializes consumption of the
    /// process-wide SPSC entropy queue.
    pub fn mix_entropy(&self) {
        if self
            .mixing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _operation_guard = EntropyOperationGuard(&self.mixing);
        self.mix_entropy_under_gate();
    }

    /// Mixes queued entropy while the caller owns this pool's operation gate.
    ///
    /// This private helper is shared by `mix_entropy` and `extract_entropy` so
    /// extraction cannot snapshot the pool while a manual mixer changes it.
    fn mix_entropy_under_gate(&self) {
        // GLOBAL_ENTROPY_QUEUE is SPSC. Its consumer gate must therefore be
        // process-wide rather than per-EntropyPool: multiple independent pool
        // instances can otherwise enter this function concurrently.
        if GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let _queue_guard = EntropyOperationGuard(&GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE);
        let mut chunk = [0u8; ENTROPY_CHUNK_SIZE];
        let mut queue_hasher = Sha384::new();
        let mut mixed = false;

        // Keep the expensive hash work outside the interrupt-masked lock and
        // bound the amount of work performed by one call. Any remaining queue
        // entries are deliberately left for a later invocation.
        let mut mixed_chunks = 0usize;
        while mixed_chunks < MAX_MIX_CHUNKS_PER_CALL
            && unsafe { GLOBAL_ENTROPY_QUEUE.pop(&mut chunk) }
        {
            queue_hasher.update(chunk);
            secure_zeroize(&mut chunk);
            mixed = true;
            mixed_chunks += 1;
        }

        if mixed {
            let mut queue_digest = queue_hasher.finalize();

            // Only the fixed-size pool state transition is protected here.
            let mut guard = self.pool.lock();
            let mut pool_hasher = Sha384::new();
            pool_hasher.update(*guard);
            pool_hasher.update(queue_digest);
            let mut result = pool_hasher.finalize();
            guard.copy_from_slice(&result);
            drop(guard);

            secure_zeroize(queue_digest.as_mut_slice());
            secure_zeroize(result.as_mut_slice());

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
        // `mixing` is a non-blocking high-level ownership gate for the entire
        // extraction transaction, including any queued-entropy mixing. A caller
        // that loses the gate returns a retryable error rather than spinning.
        if self
            .mixing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(CryptoError::EntropyBusy);
        }
        let _operation_guard = EntropyOperationGuard(&self.mixing);

        // Mix only while this pool's operation gate is owned. This prevents a
        // concurrent/manual mixer from changing pool state between snapshot and
        // commit, while the helper's global queue gate preserves SPSC ownership.
        self.mix_entropy_under_gate();

        if self.reseed_count.load(Ordering::Acquire) == 0 {
            return Err(CryptoError::EntropyStarvation);
        }

        let mut offset = 0usize;
        while offset < out.len() {
            // Snapshot the 48-byte pool state under the short interrupt-masked
            // lock. The high-level ownership gate prevents another entropy
            // operation from changing the pool until this block commits.
            let mut state_snapshot = {
                let guard = self.pool.lock();
                *guard
            };

            // Expensive hashing remains outside `CryptoSpinlock`, keeping
            // interrupts enabled during variable-sized extraction.
            let mut out_hasher = Sha384::new();
            out_hasher.update([0x00]);
            out_hasher.update(state_snapshot);
            let mut out_result = out_hasher.finalize();

            let mut state_hasher = Sha384::new();
            state_hasher.update([0x01]);
            state_hasher.update(state_snapshot);
            let mut state_result = state_hasher.finalize();

            let copy_len = core::cmp::min(48, out.len() - offset);
            out[offset..offset + copy_len].copy_from_slice(&out_result[..copy_len]);

            // Commit the new forward-secret state under the short lock.
            {
                let mut guard = self.pool.lock();
                guard.copy_from_slice(&state_result);
            }

            secure_zeroize(&mut out_result);
            secure_zeroize(&mut state_result);
            secure_zeroize(&mut state_snapshot);
            offset += copy_len;
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
    static ENTROPY_TEST_SERIAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    fn concurrent_mixer_is_rejected_while_another_mixer_owns_the_queue() {
        let _entropy_test_guard = ENTROPY_TEST_SERIAL_LOCK
            .lock()
            .expect("entropy test lock poisoned");
        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok());

        REENTRY_TEST_POOL.mix_entropy();
        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.load(Ordering::Acquire));

        GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.store(false, Ordering::Release);
    }

    #[test]
    fn independent_pools_share_one_global_queue_consumer_gate() {
        let _entropy_test_guard = ENTROPY_TEST_SERIAL_LOCK
            .lock()
            .expect("entropy test lock poisoned");
        let pool_a = EntropyPool::new();
        let pool_b = EntropyPool::new();

        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok());

        pool_a.mix_entropy();
        pool_b.mix_entropy();
        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.load(Ordering::Acquire));

        GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.store(false, Ordering::Release);
    }

    #[test]
    fn extract_does_not_bypass_pool_gate_or_consume_queue() {
        let _entropy_test_guard = ENTROPY_TEST_SERIAL_LOCK
            .lock()
            .expect("entropy test lock poisoned");
        let pool = EntropyPool::new();
        pool.mixing.store(true, Ordering::Release);
        let mut chunk = [0x5Au8; ENTROPY_CHUNK_SIZE];
        let pushed = unsafe { GLOBAL_ENTROPY_QUEUE.push(&chunk) }.is_ok();
        secure_zeroize(&mut chunk);

        let mut out = [0u8; 1];
        assert_eq!(pool.extract_entropy(&mut out), Err(CryptoError::EntropyBusy));

        // The busy path must not enter the global queue consumer. If we managed
        // to push a test chunk, it should still be available to a later consumer.
        if pushed {
            assert!(unsafe { GLOBAL_ENTROPY_QUEUE.pop(&mut chunk) });
            secure_zeroize(&mut chunk);
        }
        pool.mixing.store(false, Ordering::Release);
    }

    #[test]
    fn extract_reports_busy_without_waiting_for_an_active_mixer() {
        let _entropy_test_guard = ENTROPY_TEST_SERIAL_LOCK
            .lock()
            .expect("entropy test lock poisoned");
        let pool = EntropyPool::new();
        pool.reseed_count.store(1, Ordering::Release);
        pool.mixing.store(true, Ordering::Release);

        let mut out = [0u8; 1];
        assert_eq!(
            pool.extract_entropy(&mut out),
            Err(CryptoError::EntropyBusy)
        );
        pool.mixing.store(false, Ordering::Release);
    }

    #[test]
    fn mix_entropy_is_bounded_per_invocation() {
        let pool = EntropyPool::new();
        let mut pushed = 0usize;
        for value in 0u8..=8u8 {
            let chunk = [value; ENTROPY_CHUNK_SIZE];
            if unsafe { GLOBAL_ENTROPY_QUEUE.push(&chunk) }.is_ok() {
                pushed += 1;
            }
        }
        assert!(pushed > MAX_MIX_CHUNKS_PER_CALL);

        pool.mix_entropy();
        assert_eq!(pool.reseed_count.load(Ordering::Acquire), 1);
        pool.mix_entropy();
        assert_eq!(pool.reseed_count.load(Ordering::Acquire), 2);
    }

    #[test]
    fn cache_callback_can_reenter_entropy_mixing_without_deadlocking() {
        let _entropy_test_guard = ENTROPY_TEST_SERIAL_LOCK
            .lock()
            .expect("entropy test lock poisoned");
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
