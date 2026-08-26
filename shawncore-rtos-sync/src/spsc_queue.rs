#![no_std]
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

use core::cell::UnsafeCell;
use core::sync::atomic::{compiler_fence, fence, AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use crate::error::IpcError;

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
    pub fn init(&self, base_ptr: *mut CacheAlignedSlot<T>, size_in_bytes: usize) -> Result<(), IpcError> {
        if base_ptr.is_null() {
            return Err(IpcError::InvalidMemory);
        }

        let required_size = N.checked_mul(core::mem::size_of::<CacheAlignedSlot<T>>()).ok_or(IpcError::InvalidMemory)?;
        if size_in_bytes < required_size {
            return Err(IpcError::InvalidMemory);
        }

        // Enforce 4096-byte (page) alignment for DMA
        if (base_ptr as usize) % 4096 != 0 {
            return Err(IpcError::InvalidMemory);
        }

        // Ordering::SeqCst ensures that the initialization state is globally visible
        // before any producer or consumer attempts to access the queue.
        if self.is_initialized.swap(true, Ordering::SeqCst) {
            return Err(IpcError::AlreadyInitialized);
        }

        self.buffer.store(base_ptr, Ordering::SeqCst);
        compiler_fence(Ordering::SeqCst);

        Ok(())
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

        // Dynamic memory zeroization of the popped slot
        // # Safety
        // Spatial: `ptr` and `len` are derived directly from the valid array slot.
        // Temporal: The slot is exclusively owned by the consumer before advancing tail.
        // Alignment: `u8` has no strict alignment requirements.
        unsafe {
            let slot_ptr = base_ptr.add(index);
            let ptr = (*slot_ptr).data.get() as *mut u8;
            let len = core::mem::size_of::<T>();
            
            core::ptr::write_bytes(ptr, 0, len);
            // Volatile write loop to prevent Dead Store Elimination (DSE)
            for i in 0..len {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
        }

        compiler_fence(Ordering::SeqCst);

        // Hardware Memory Barrier via Release semantics.
        // Ensures the zeroization is complete before the producer is allowed to overwrite the slot.
        fence(Ordering::Release);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);

        Some(item)
    }
}
