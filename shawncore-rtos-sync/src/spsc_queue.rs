#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Lock-free Single-Producer Single-Consumer (SPSC) queue.
//!
//! Hardware-agnostic implementation for MarTac USVs.
//! Refactored to accept host-provided, page-aligned memory buffers via `init()`
//! to guarantee DMA memory pinning and ownership by the host OS.
//!
//! # Concurrency Safety & Memory Ordering
//! This queue relies on strict `Acquire` and `Release` memory ordering semantics
//! to guarantee that data written by the producer is fully visible to the consumer
//! before the index is updated, preventing data races and torn reads across cores.

use crate::error::IpcError;
use core::cell::UnsafeCell;
use core::sync::atomic::{compiler_fence, fence, AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// A cache-line aligned atomic index to prevent false sharing between producer and consumer cores.
#[repr(C, align(64))]
pub struct CacheAlignedIndex(pub AtomicUsize);

/// A cache-line aligned slot to prevent false sharing between queue elements.
#[repr(C, align(64))]
pub struct CacheAlignedSlot<T> {
    /// The underlying data cell.
    pub data: UnsafeCell<T>,
}

/// A lock-free, single-producer, single-consumer queue optimized for cross-core telemetry.
///
/// Designed to be initialized by the C/C++ host OS with a pre-allocated,
/// page-aligned memory region to ensure strict DMA pinning.
#[repr(C, align(64))]
pub struct SpscQueue<T: Copy + Default, const N: usize> {
    /// Pointer to the host-provided buffer storing the elements.
    buffer: AtomicPtr<CacheAlignedSlot<T>>,
    /// The atomic index representing the head (write position).
    head: CacheAlignedIndex,
    /// The atomic index representing the tail (read position).
    tail: CacheAlignedIndex,
    /// Initialization flag.
    is_initialized: AtomicBool,
    /// Prevents concurrent initialization attempts.
    is_initializing: AtomicBool,
}

// # Safety
// SPSC queue is safe to share across threads as long as there is strictly one producer and one consumer.
unsafe impl<T: Copy + Default + Send, const N: usize> Sync for SpscQueue<T, N> {}
unsafe impl<T: Copy + Default + Send, const N: usize> Send for SpscQueue<T, N> {}

impl<T: Copy + Default, const N: usize> Default for SpscQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + Default, const N: usize> SpscQueue<T, N> {
    /// Creates a new, uninitialized `SpscQueue`.
    #[must_use]
    pub const fn new() -> Self {
        const { assert!(N.is_power_of_two(), "Queue size must be a power of 2") };
        Self {
            buffer: AtomicPtr::new(core::ptr::null_mut()),
            head: CacheAlignedIndex(AtomicUsize::new(0)),
            tail: CacheAlignedIndex(AtomicUsize::new(0)),
            is_initialized: AtomicBool::new(false),
            is_initializing: AtomicBool::new(false),
        }
    }

    /// Initializes the SPSC queue with a host-provided, page-aligned memory buffer.
    ///
    /// # Arguments
    /// * `base_ptr` - Raw pointer to the host-allocated memory region.
    /// * `size_in_bytes` - Total size of the provided memory region.
    ///
    /// # Returns
    /// `Ok(())` on success, or an `IpcError` if the memory is invalid or unaligned.
    ///
    /// This operation is one-shot. The queue must be destroyed before its object
    /// storage is reused for another initialization, and producers and consumers
    /// must be stopped before destruction or reuse.
    pub fn init(
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

        // The host contract requires page alignment, while Rust also requires the
        // allocation to satisfy the slot type's alignment.
        let required_alignment = core::mem::align_of::<CacheAlignedSlot<T>>();
        if (base_ptr as usize) % 4096 != 0 || (base_ptr as usize) % required_alignment != 0 {
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

        self.buffer.store(base_ptr, Ordering::SeqCst);
        compiler_fence(Ordering::SeqCst);
        self.is_initialized.store(true, Ordering::Release);
        self.is_initializing.store(false, Ordering::Release);

        Ok(())
    }

    /// Returns whether the queue has been initialized with a host buffer.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.is_initialized.load(Ordering::Acquire)
    }

    /// Pushes a single item into the queue. Returns an error if the queue is full.
    ///
    /// # Memory Ordering
    /// * `head` is loaded with `Relaxed` because only the producer modifies it.
    /// * `tail` is loaded with `Acquire` to synchronize with the consumer's `Release` store,
    ///   ensuring we see the most up-to-date read position.
    /// * `head` is stored with `Release` to guarantee that the data written to the buffer
    ///   is globally visible before the consumer sees the updated head index.
    pub fn push(&self, item: T) -> Result<(), IpcError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(IpcError::NotInitialized);
        }

        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);

        if head.wrapping_sub(tail) >= N {
            return Err(IpcError::QueueFull);
        }

        let index = head % N;

        // Hardware-agnostic compiler fence to prevent instruction reordering prior to the write.
        compiler_fence(Ordering::SeqCst);

        let base_ptr = self.buffer.load(Ordering::Acquire);

        // # Safety
        // Spatial: `index` is masked by `N`, ensuring it is strictly within bounds.
        // Temporal: The producer has exclusive write access to the `head` index.
        // Alignment: The host OS guarantees page alignment via `init()`.
        unsafe {
            let slot_ptr = base_ptr.add(index);
            *(*slot_ptr).data.get() = item;
        }

        // Hardware Memory Barrier via Release semantics.
        // This fence strictly guarantees that the payload write completes in physical memory
        // BEFORE the head index is incremented, preventing the consumer from reading garbage data.
        fence(Ordering::Release);
        self.head.0.store(head.wrapping_add(1), Ordering::Release);

        Ok(())
    }

    /// Pops a single item from the queue. Returns `None` if the queue is empty.
    ///
    /// # Memory Ordering
    /// * `tail` is loaded with `Relaxed` because only the consumer modifies it.
    /// * `head` is loaded with `Acquire` to synchronize with the producer's `Release` store,
    ///   ensuring all data writes to the buffer are visible before we read them.
    /// * `tail` is stored with `Release` to guarantee that the data read is complete
    ///   before the producer sees the freed slot.
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
        // This pairs with the producer's Release fence.
        fence(Ordering::Acquire);

        let index = tail % N;

        compiler_fence(Ordering::SeqCst);

        let base_ptr = self.buffer.load(Ordering::Acquire);

        // # Safety
        // Spatial: `index` is masked by `N`, ensuring it is strictly within bounds.
        // Temporal: The consumer has exclusive read access to the `tail` index.
        // Alignment: The host OS guarantees page alignment via `init()`.
        let item = unsafe {
            let slot_ptr = base_ptr.add(index);
            *(*slot_ptr).data.get()
        };

        // Restore a valid value before making the slot available to the producer.
        // Raw zeroing is not valid for every `T: Default` (for example, `NonZeroU8`).
        unsafe {
            let slot_ptr = base_ptr.add(index);
            *(*slot_ptr).data.get() = T::default();
        }

        compiler_fence(Ordering::SeqCst);

        // Hardware Memory Barrier via Release semantics.
        // Ensures the zeroization is complete before the producer is allowed to overwrite the slot.
        fence(Ordering::Release);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);

        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheAlignedSlot, SpscQueue};
    use crate::error::IpcError;
    use core::mem::MaybeUninit;

    #[repr(C, align(4096))]
    struct AlignedSlots<const N: usize>(MaybeUninit<[CacheAlignedSlot<u32>; N]>);

    #[test]
    fn init_rejects_invalid_memory_without_initializing() {
        let queue = SpscQueue::<u32, 4>::new();

        assert_eq!(
            queue.init(core::ptr::null_mut(), 0),
            Err(IpcError::InvalidMemory)
        );
        assert!(!queue.is_initialized());
    }

    #[test]
    fn init_rejects_insufficient_or_unaligned_memory_without_initializing() {
        let queue = SpscQueue::<u32, 4>::new();
        let mut storage = AlignedSlots::<4>(MaybeUninit::uninit());
        let storage_ptr = storage.0.as_mut_ptr().cast::<CacheAlignedSlot<u32>>();
        let storage_size = core::mem::size_of::<[CacheAlignedSlot<u32>; 4]>();

        assert_eq!(
            queue.init(storage_ptr, storage_size - 1),
            Err(IpcError::InvalidMemory)
        );
        assert_eq!(
            queue.init(storage_ptr.wrapping_byte_add(1), storage_size),
            Err(IpcError::InvalidMemory)
        );
        assert!(!queue.is_initialized());
    }

    #[test]
    fn init_is_one_shot_and_queue_preserves_fifo_order() {
        let queue = SpscQueue::<u32, 4>::new();
        let mut storage = AlignedSlots::<4>(MaybeUninit::uninit());
        let storage_ptr = storage.0.as_mut_ptr().cast::<CacheAlignedSlot<u32>>();
        let storage_size = core::mem::size_of::<[CacheAlignedSlot<u32>; 4]>();

        queue.init(storage_ptr, storage_size).unwrap();
        assert_eq!(
            queue.init(storage_ptr, storage_size),
            Err(IpcError::AlreadyInitialized)
        );

        for value in 1..=4 {
            queue.push(value).unwrap();
        }
        assert_eq!(queue.push(5), Err(IpcError::QueueFull));
        for value in 1..=4 {
            assert_eq!(queue.pop(), Some(value));
        }
        assert_eq!(queue.pop(), None);
        drop(storage);
    }

    #[test]
    fn queue_reuses_slots_after_wraparound() {
        let queue = SpscQueue::<u32, 4>::new();
        let mut storage = AlignedSlots::<4>(MaybeUninit::uninit());
        let storage_ptr = storage.0.as_mut_ptr().cast::<CacheAlignedSlot<u32>>();
        let storage_size = core::mem::size_of::<[CacheAlignedSlot<u32>; 4]>();

        queue.init(storage_ptr, storage_size).unwrap();
        for value in 0..128 {
            queue.push(value).unwrap();
            assert_eq!(queue.pop(), Some(value));
        }
    }
}
