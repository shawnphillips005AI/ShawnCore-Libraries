#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
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

use core::cell::UnsafeCell;
use core::sync::atomic::{compiler_fence, fence, AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use crate::error::IpcError;
use crate::spsc_queue::{CacheAlignedIndex, CacheAlignedSlot};

/// A lock-free, single-producer, single-consumer ring buffer.
///
/// Designed to be initialized by the C/C++ host OS with a pre-allocated,
/// page-aligned memory region to ensure strict DMA pinning.
#[repr(C, align(64))]
pub struct RingBuffer<T: Copy + Default, const N: usize> {
    /// Pointer to the host-provided buffer storing the elements.
    buffer: AtomicPtr<CacheAlignedSlot<T>>,
    /// The atomic index representing the head (write position).
    pub head: CacheAlignedIndex,
    /// The atomic index representing the tail (read position).
    pub tail: CacheAlignedIndex,
    /// Initialization flag.
    is_initialized: AtomicBool,
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
            buffer: AtomicPtr::new(core::ptr::null_mut()),
            head: CacheAlignedIndex(AtomicUsize::new(0)),
            tail: CacheAlignedIndex(AtomicUsize::new(0)),
            is_initialized: AtomicBool::new(false),
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

        let base_ptr = self.buffer.load(Ordering::Acquire);

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

        let base_ptr = self.buffer.load(Ordering::Acquire);

        // # Safety
        // Spatial: `idx` is masked by `N`, ensuring it is strictly within bounds.
        // Temporal: The consumer has exclusive read access to the `tail` index.
        // Alignment: The host OS guarantees page alignment via `init()`.
        let item = unsafe {
            let slot_ptr = base_ptr.add(idx);
            *(*slot_ptr).data.get()
        };

        // Dynamic memory zeroization of the popped slot
        // # Safety
        // Spatial: `ptr` and `len` are derived directly from the valid array slot.
        // Temporal: The slot is exclusively owned by the consumer before advancing tail.
        // Alignment: `u8` has no strict alignment requirements.
        unsafe {
            let slot_ptr = base_ptr.add(idx);
            let ptr = (*slot_ptr).data.get() as *mut u8;
            let len = core::mem::size_of::<T>();
            
            core::ptr::write_bytes(ptr, 0, len);
            for i in 0..len {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
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

        let base_ptr = self.buffer.load(Ordering::Acquire);

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
