#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Lock-free Single-Producer Single-Consumer (SPSC) ring buffer.
//!
//! Hardware-agnostic implementation for MarTac USVs.
//! Refactored to accept host-provided, page-aligned memory buffers via `init()`.
//! Supports Peek-Allocate-Pop semantics for zero-attrition EW command processing.
//!
//! # Concurrency Safety & Memory Ordering
//! This queue relies on strict `Acquire` and `Release` memory ordering semantics
//! to guarantee that data written by the producer is fully visible to the consumer
//! before the index is updated, preventing data races and torn reads across cores.

use crate::error::IpcError;
use crate::spsc_queue::{CacheAlignedIndex, CacheAlignedSlot};
use core::cell::UnsafeCell;
use core::sync::atomic::{compiler_fence, fence, AtomicBool, AtomicUsize, Ordering};

/// A lock-free, single-producer, single-consumer ring buffer.
///
/// Designed to be initialized by the C/C++ host OS with a pre-allocated,
/// page-aligned memory region to ensure strict DMA pinning.
#[repr(C, align(64))]
pub struct RingBuffer<T: Copy + Default, const N: usize> {
    /// Pointer to the host-provided buffer storing the elements.
    ///
    /// Written exactly once during `init()`, then read directly (no atomic load)
    /// by `push()`/`pop()`/`peek()`: the `Acquire` load of `is_initialized`
    /// performed by every caller already synchronizes with the `Release` store
    /// at the end of `init()`, so an additional atomic load here would only
    /// cost cycles on the RTOS hot path without adding any further guarantee.
    buffer: UnsafeCell<*mut CacheAlignedSlot<T>>,
    /// The atomic index representing the head (write position).
    pub head: CacheAlignedIndex,
    /// The atomic index representing the tail (read position).
    pub tail: CacheAlignedIndex,
    /// Initialization flag.
    is_initialized: AtomicBool,
    /// Prevents concurrent initialization attempts.
    is_initializing: AtomicBool,
}

// # Safety
// RingBuffer is safe to share across threads as long as there is strictly one producer and one consumer.
unsafe impl<T: Copy + Default + Send, const N: usize> Sync for RingBuffer<T, N> {}
unsafe impl<T: Copy + Default + Send, const N: usize> Send for RingBuffer<T, N> {}

impl<T: Copy + Default, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> RingBuffer<T, N> {
    /// Creates a new, uninitialized `RingBuffer`.
    #[must_use]
    pub const fn new() -> Self {
        const { assert!(N.is_power_of_two(), "Queue size must be a power of 2") };
        Self {
            buffer: UnsafeCell::new(core::ptr::null_mut()),
            head: CacheAlignedIndex(AtomicUsize::new(0)),
            tail: CacheAlignedIndex(AtomicUsize::new(0)),
            is_initialized: AtomicBool::new(false),
            is_initializing: AtomicBool::new(false),
        }
    }

    /// Initializes the RingBuffer with a host-provided, page-aligned memory buffer.
    ///
    /// # Arguments
    /// * `base_ptr` - Raw pointer to the host-allocated memory region.
    /// * `size_in_bytes` - Total size of the provided memory region.
    ///
    /// # Returns
    /// `Ok(())` on success, or an `IpcError` if the memory is invalid or unaligned.
    ///
    /// This operation is one-shot. The ring buffer must be destroyed before its
    /// object storage is reused for another initialization, and producers and
    /// consumers must be stopped before destruction or reuse.
    ///
    /// # Safety
    /// `base_ptr` must point to writable storage for `N` initialized
    /// `CacheAlignedSlot<T>` values and remain valid until destruction.
    pub unsafe fn init(
        &self,
        base_ptr: *mut CacheAlignedSlot<T>,
        size_in_bytes: usize,
    ) -> Result<(), IpcError> {
        if base_ptr.is_null() {
            return Err(IpcError::InvalidMemory);
        }

        let required_size = N
            .checked_mul(core::mem::size_of::<CacheAlignedSlot<T>>())
            .ok_or(IpcError::InvalidMemory)?;
        if size_in_bytes < required_size {
            return Err(IpcError::InvalidMemory);
        }

        // Enforce 4096-byte (page) alignment for DMA
        if (base_ptr as usize) % 4096 != 0 {
            return Err(IpcError::InvalidMemory);
        }

        // Ordering::SeqCst ensures that the initialization state is globally visible
        // before any producer or consumer attempts to access the queue.
        if self.is_initialized.load(Ordering::Acquire)
            || self
                .is_initializing
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return Err(IpcError::AlreadyInitialized);
        }

        if self.is_initialized.load(Ordering::Acquire) {
            self.is_initializing.store(false, Ordering::Release);
            return Err(IpcError::AlreadyInitialized);
        }

        // # Safety
        // Spatial: N/A, this is a plain pointer-sized write.
        // Temporal: `is_initializing`'s compare-exchange above guarantees no other
        // caller can be inside `init()` concurrently.
        // Alignment: N/A.
        unsafe {
            *self.buffer.get() = base_ptr;
        }
        for index in 0..N {
            unsafe {
                core::ptr::write(
                    core::ptr::addr_of_mut!((*base_ptr.add(index)).sequence_counter),
                    AtomicUsize::new(0),
                );
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.is_initialized.store(true, Ordering::Release);
        self.is_initializing.store(false, Ordering::Release);

        Ok(())
    }

    /// Returns whether the ring buffer has been initialized with a host buffer.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.is_initialized.load(Ordering::Acquire)
    }

    /// Pushes a single item into the queue. Returns an error if the queue is full.
    ///
    /// # Memory Ordering
    /// * `head` is loaded with `Relaxed` because only the producer modifies it.
    /// * `tail` is loaded with `Acquire` to synchronize with the consumer's `Release` store.
    /// * `head` is stored with `Release` to guarantee data visibility.
    pub fn push(&self, item: T) -> Result<(), IpcError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(IpcError::NotInitialized);
        }

        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);

        if head.wrapping_sub(tail) >= N {
            return Err(IpcError::QueueFull);
        }

        let idx = head % N;

        compiler_fence(Ordering::SeqCst);

        // # Safety
        // Spatial: N/A.
        // Temporal: The `Acquire` load of `is_initialized` above synchronizes with
        // the `Release` store at the end of `init()`, so this plain read is
        // guaranteed to observe the initialized buffer pointer.
        let base_ptr = unsafe { *self.buffer.get() };

        // # Safety
        // Spatial: `idx` is masked by `N`, ensuring it is strictly within bounds.
        // Temporal: The producer has exclusive write access to the `head` index.
        // Alignment: The host OS guarantees page alignment via `init()`.
        unsafe {
            let slot_ptr = base_ptr.add(idx);
            *(*slot_ptr).data.get() = item;
        }

        // Hardware Memory Barrier via Release semantics
        // Prevents CPU from reordering the buffer write after the head update.
        fence(Ordering::Release);
        self.head.0.store(head.wrapping_add(1), Ordering::Release);

        Ok(())
    }

    /// Pops a single item from the queue. Returns `None` if the queue is empty.
    ///
    /// # Memory Ordering
    /// * `tail` is loaded with `Relaxed` because only the consumer modifies it.
    /// * `head` is loaded with `Acquire` to synchronize with the producer's `Release` store.
    /// * `tail` is stored with `Release` to guarantee data read completion.
    pub fn pop(&self) -> Option<T> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return None;
        }

        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        // SPSC Queue Memory Reordering Fix
        // Execute Acquire fence *before* reading the item to prevent speculative reads of stale data.
        fence(Ordering::Acquire);

        let idx = tail % N;

        compiler_fence(Ordering::SeqCst);

        // # Safety
        // Spatial: N/A.
        // Temporal: The `Acquire` load of `is_initialized` above synchronizes with
        // the `Release` store at the end of `init()`, so this plain read is
        // guaranteed to observe the initialized buffer pointer.
        let base_ptr = unsafe { *self.buffer.get() };

        // # Safety
        // Spatial: `idx` is masked by `N`, ensuring it is strictly within bounds.
        // Temporal: The consumer has exclusive read access to the `tail` index.
        // Alignment: The host OS guarantees page alignment via `init()`.
        let item = unsafe {
            let slot_ptr = base_ptr.add(idx);
            *(*slot_ptr).data.get()
        };

        // Restore a valid value before making the slot available to the producer.
        // Raw zeroing is not valid for every `T: Default` (for example, `NonZeroU8`).
        unsafe {
            let slot_ptr = base_ptr.add(idx);
            *(*slot_ptr).data.get() = T::default();
        }

        compiler_fence(Ordering::SeqCst);

        // Hardware Memory Barrier via Release semantics
        fence(Ordering::Release);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);

        Some(item)
    }

    /// Peeks at the next item in the queue without removing it.
    /// Shawncore Mandate: Peek-Allocate-Pop Semantics support.
    ///
    /// # Memory Ordering
    /// Uses `Acquire` semantics to ensure the data is fully visible before reading,
    /// but does NOT update the `tail` index, leaving the item in the queue.
    pub fn peek(&self) -> Option<T> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return None;
        }

        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        // SPSC Queue Memory Reordering Fix
        fence(Ordering::Acquire);

        let idx = tail % N;

        compiler_fence(Ordering::SeqCst);

        // # Safety
        // Spatial: N/A.
        // Temporal: The `Acquire` load of `is_initialized` above synchronizes with
        // the `Release` store at the end of `init()`, so this plain read is
        // guaranteed to observe the initialized buffer pointer.
        let base_ptr = unsafe { *self.buffer.get() };

        // # Safety
        // Spatial: `idx` is masked by `N`.
        // Temporal: The consumer has exclusive read access to the `tail` index.
        // Alignment: The host OS guarantees page alignment via `init()`.
        let item = unsafe {
            let slot_ptr = base_ptr.add(idx);
            *(*slot_ptr).data.get()
        };

        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheAlignedSlot, RingBuffer};
    use crate::error::IpcError;
    use core::mem::MaybeUninit;

    #[repr(C, align(4096))]
    struct AlignedSlots<const N: usize>(MaybeUninit<[CacheAlignedSlot<u32>; N]>);

    #[test]
    fn init_rejects_invalid_memory_without_initializing() {
        let buffer = RingBuffer::<u32, 4>::new();

        assert_eq!(
            unsafe { buffer.init(core::ptr::null_mut(), 0) },
            Err(IpcError::InvalidMemory)
        );
        assert!(!buffer.is_initialized());
    }

    #[test]
    fn init_is_one_shot_and_peek_does_not_remove_items() {
        let buffer = RingBuffer::<u32, 4>::new();
        let mut storage = AlignedSlots::<4>(MaybeUninit::uninit());
        let storage_ptr = storage.0.as_mut_ptr().cast::<CacheAlignedSlot<u32>>();
        let storage_size = core::mem::size_of::<[CacheAlignedSlot<u32>; 4]>();

        unsafe { buffer.init(storage_ptr, storage_size) }.unwrap();
        assert_eq!(
            unsafe { buffer.init(storage_ptr, storage_size) },
            Err(IpcError::AlreadyInitialized)
        );

        buffer.push(7).unwrap();
        assert_eq!(buffer.peek(), Some(7));
        assert_eq!(buffer.pop(), Some(7));
        assert_eq!(buffer.pop(), None);
    }
}
