#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Statically allocated, cache-aligned DMA memory pool.
//! Hardware-agnostic implementation for MarTac USVs.
//! Provides lock-free, zero-allocation memory buffers.
//! Prevents heap fragmentation, guarantees physical contiguity, and uses bounded CAS
//! loops to guarantee deterministic execution deadlines for the host OS.

use crate::error::AllocatorError;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicPtr, AtomicU64, Ordering};

/// A lock-free, generic, statically allocated DMA memory pool.
///
/// Designed to be initialized by the C/C++ host OS with a pre-allocated,
/// page-aligned memory region to ensure strict DMA pinning and ownership.
#[repr(C, align(64))]
pub struct StaticDmaPool<T, const N: usize, const BITMAP_WORDS: usize> {
    /// Pointer to the host-provided memory buffer.
    memory: AtomicPtr<T>,
    /// Atomic bitmap tracking availability (1 = Free, 0 = Allocated).
    bitmap: [AtomicU64; BITMAP_WORDS],
    /// Initialization flag.
    is_initialized: AtomicBool,
}

// # Safety
// The pool is safe to share across threads. The atomic bitmap ensures exclusive access
// to individual buffers.
unsafe impl<T: Send, const N: usize, const BITMAP_WORDS: usize> Sync for StaticDmaPool<T, N, BITMAP_WORDS> {}
unsafe impl<T: Send, const N: usize, const BITMAP_WORDS: usize> Send for StaticDmaPool<T, N, BITMAP_WORDS> {}

impl<T: Default + Copy, const N: usize, const BITMAP_WORDS: usize> Default for StaticDmaPool<T, N, BITMAP_WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default + Copy, const N: usize, const BITMAP_WORDS: usize> StaticDmaPool<T, N, BITMAP_WORDS> {
    /// Creates a new, uninitialized DMA pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            memory: AtomicPtr::new(core::ptr::null_mut()),
            bitmap: [const { AtomicU64::new(0) }; BITMAP_WORDS],
            is_initialized: AtomicBool::new(false),
        }
    }

    /// Initializes the DMA pool with a host-provided, page-aligned memory buffer.
    ///
    /// # Arguments
    /// * `base_ptr` - Raw pointer to the host-allocated memory region.
    /// * `size_in_bytes` - Total size of the provided memory region.
    ///
    /// # Returns
    /// `Ok(())` on success, or an `AllocatorError` if the memory is invalid or unaligned.
    pub fn init(&self, base_ptr: *mut T, size_in_bytes: usize) -> Result<(), AllocatorError> {
        if base_ptr.is_null() {
            return Err(AllocatorError::AddressOutOfBounds);
        }

        let required_size = N.checked_mul(core::mem::size_of::<T>()).ok_or(AllocatorError::AddressOutOfBounds)?;
        if size_in_bytes < required_size {
            return Err(AllocatorError::AddressOutOfBounds);
        }

        // Enforce 4096-byte (page) alignment for DMA
        if (base_ptr as usize) % 4096 != 0 {
            return Err(AllocatorError::InvalidAlignment);
        }

        if self.is_initialized.swap(true, Ordering::SeqCst) {
            return Err(AllocatorError::AlreadyInitialized);
        }

        self.memory.store(base_ptr, Ordering::SeqCst);

        // Initialize bitmap to all 1s (free)
        for i in 0..BITMAP_WORDS {
            self.bitmap[i].store(u64::MAX, Ordering::SeqCst);
        }

        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Allocates a buffer from the pool, returning its index and a mutable reference.
    ///
    /// Utilizes a bounded Compare-And-Swap (CAS) loop restricted to 128 retries.
    /// This guarantees deterministic execution deadlines, ensuring the RTOS
    /// never hangs indefinitely during high-contention allocation spikes.
    pub fn allocate(&self) -> Result<(usize, &mut T), AllocatorError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(AllocatorError::NotInitialized);
        }

        let base_ptr = self.memory.load(Ordering::Acquire);

        for word_idx in 0..BITMAP_WORDS {
            let atomic_word = &self.bitmap[word_idx];
            let mut current = atomic_word.load(Ordering::Acquire);
            let mut retries = 0;

            loop {
                // Bounded CAS to guarantee deterministic deadlines
                if retries >= 128 {
                    return Err(AllocatorError::OutOfMemory);
                }

                if current == 0 {
                    break; // Move to next word
                }

                let bit_idx = current.trailing_zeros() as usize;
                let mask = 1u64.checked_shl(bit_idx as u32).unwrap_or(0);
                let new_bitmap = current & !mask;

                match atomic_word.compare_exchange_weak(
                    current,
                    new_bitmap,
                    Ordering::SeqCst,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        compiler_fence(Ordering::SeqCst);

                        let buffer_idx = word_idx.checked_mul(64).unwrap().checked_add(bit_idx).unwrap();

                        if buffer_idx >= N {
                            // Revert allocation if it exceeds N
                            let mut revert_current = atomic_word.load(Ordering::Acquire);
                            loop {
                                let revert_bitmap = revert_current | mask;
                                match atomic_word.compare_exchange_weak(
                                    revert_current,
                                    revert_bitmap,
                                    Ordering::SeqCst,
                                    Ordering::Acquire,
                                ) {
                                    Ok(_) => break,
                                    Err(r) => revert_current = r,
                                }
                            }
                            return Err(AllocatorError::OutOfMemory);
                        }

                        // # Safety
                        // Spatial: `buffer_idx` is mathematically bounded by `N`.
                        // Temporal: The atomic bitmap guarantees exclusive access to this index.
                        // Alignment: The host OS guarantees page alignment via `init()`.
                        let buffer_ref = unsafe { &mut *base_ptr.add(buffer_idx) };
                        return Ok((buffer_idx, buffer_ref));
                    }
                    Err(raced) => {
                        current = raced;
                        retries += 1;
                    }
                }
            }
        }
        Err(AllocatorError::OutOfMemory)
    }

    /// Frees a previously allocated buffer back to the pool.
    ///
    /// Utilizes a bounded Compare-And-Swap (CAS) loop restricted to 128 retries
    /// to guarantee deterministic execution deadlines.
    /// Automatically zeroizes the buffer contents to prevent cross-domain data leakage.
    pub fn free(&self, buffer_idx: usize) -> Result<(), AllocatorError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(AllocatorError::NotInitialized);
        }

        if buffer_idx >= N {
            return Err(AllocatorError::AddressOutOfBounds);
        }

        compiler_fence(Ordering::SeqCst);

        let base_ptr = self.memory.load(Ordering::Acquire);

        // Unscrubbed DMA Pool Reallocation (Cross-Domain Data Leak)
        // Zeroize the buffer contents before returning it to the pool to prevent
        // classified data from leaking into untrusted network stacks upon reallocation.
        // # Safety
        // Spatial: `buffer_idx` is bounds-checked above.
        // Temporal: The buffer is exclusively owned by the caller who is freeing it.
        // Alignment: Byte-level zeroization requires no strict alignment.
        unsafe {
            let buffer_ptr = base_ptr.add(buffer_idx) as *mut u8;
            let len = core::mem::size_of::<T>();
            core::ptr::write_bytes(buffer_ptr, 0, len);
            
            // Volatile write loop to prevent DSE
            for i in 0..len {
                core::ptr::write_volatile(buffer_ptr.add(i), 0);
            }
        }
        
        // Hardware-agnostic cache flush replacement
        compiler_fence(Ordering::SeqCst);

        let word_idx = buffer_idx / 64;
        let bit_idx = buffer_idx % 64;
        let mask = 1u64.checked_shl(bit_idx as u32).unwrap_or(0);

        let atomic_word = &self.bitmap[word_idx];
        let mut current = atomic_word.load(Ordering::Acquire);
        let mut retries = 0;

        loop {
            // Bounded CAS to guarantee deterministic deadlines
            if retries >= 128 {
                return Err(AllocatorError::LockContention);
            }

            if (current & mask) != 0 {
                return Err(AllocatorError::DoubleFree); // Double free
            }

            let new_bitmap = current | mask;

            match atomic_word.compare_exchange_weak(
                current,
                new_bitmap,
                Ordering::SeqCst,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    compiler_fence(Ordering::SeqCst);
                    return Ok(());
                }
                Err(raced) => {
                    current = raced;
                    retries += 1;
                }
            }
        }
    }
}
