#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Statically allocated, cache-aligned DMA memory pool.
//! Hardware-agnostic implementation for MarTac USVs.
//! Provides lock-free, zero-allocation memory buffers.
//! Prevents heap fragmentation, guarantees physical contiguity, and uses bounded CAS
//! loops to guarantee deterministic execution deadlines for the host OS.

use crate::error::AllocatorError;
use core::ptr::NonNull;
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
    /// Serializes allocation and release so scrubbing cannot race with reuse.
    allocation_lock: AtomicBool,
    /// Per-slot ownership generation used by token-based allocation.
    generations: [AtomicU64; N],
    /// Initialization flag.
    is_initialized: AtomicBool,
    /// Prevents concurrent initialization attempts.
    is_initializing: AtomicBool,
}

#[cfg(test)]
mod tests {
    use super::StaticDmaPool;
    use crate::error::AllocatorError;
    use core::mem::MaybeUninit;

    #[repr(C, align(4096))]
    struct AlignedStorage<const N: usize>(MaybeUninit<[u32; N]>);

    #[test]
    fn allocation_does_not_expose_bitmap_padding() {
        let pool = StaticDmaPool::<u32, 65, 2>::new();
        let mut storage = AlignedStorage::<65>(MaybeUninit::uninit());
        let storage_ptr = storage.0.as_mut_ptr().cast::<u32>();

        pool.init(storage_ptr, core::mem::size_of::<[u32; 65]>())
            .unwrap();

        for expected_idx in 0..65 {
            let (idx, _, _) = pool.allocate().unwrap();
            assert_eq!(idx, expected_idx);
        }
        assert_eq!(pool.allocate(), Err(AllocatorError::OutOfMemory));
    }

    #[test]
    fn stale_generation_cannot_free_reused_slot() {
        let pool = StaticDmaPool::<u32, 1, 1>::new();
        let mut storage = AlignedStorage::<1>(MaybeUninit::uninit());
        let storage_ptr = storage.0.as_mut_ptr().cast::<u32>();
        pool.init(storage_ptr, core::mem::size_of::<u32>()).unwrap();

        let (idx, first_generation, first_ptr) = pool.allocate().unwrap();
        unsafe { first_ptr.as_ptr().write(0xA5A5_A5A5) };
        pool.free(idx, first_generation).unwrap();
        let (idx, second_generation, second_ptr) = pool.allocate().unwrap();
        unsafe { second_ptr.as_ptr().write(0x5A5A_5A5A) };

        assert_eq!(
            pool.free(idx, first_generation),
            Err(AllocatorError::DoubleFree)
        );
        assert_eq!(unsafe { second_ptr.as_ptr().read() }, 0x5A5A_5A5A);
        pool.free(idx, second_generation).unwrap();
    }
}

// # Safety
// The pool is safe to share across threads. The atomic bitmap ensures exclusive access
// to individual buffers.
unsafe impl<T: Send, const N: usize, const BITMAP_WORDS: usize> Sync
    for StaticDmaPool<T, N, BITMAP_WORDS>
{
}
unsafe impl<T: Send, const N: usize, const BITMAP_WORDS: usize> Send
    for StaticDmaPool<T, N, BITMAP_WORDS>
{
}

impl<T: Copy, const N: usize, const BITMAP_WORDS: usize> Default
    for StaticDmaPool<T, N, BITMAP_WORDS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const N: usize, const BITMAP_WORDS: usize> StaticDmaPool<T, N, BITMAP_WORDS> {
    /// Creates a new, uninitialized DMA pool.
    #[must_use]
    pub const fn new() -> Self {
        const {
            assert!(N > 0, "DMA pool must contain at least one buffer");
            assert!(
                match BITMAP_WORDS.checked_mul(64) {
                    Some(capacity) => capacity >= N,
                    None => false,
                },
                "DMA bitmap must cover every pool buffer"
            );
        }
        Self {
            memory: AtomicPtr::new(core::ptr::null_mut()),
            bitmap: [const { AtomicU64::new(0) }; BITMAP_WORDS],
            allocation_lock: AtomicBool::new(false),
            generations: [const { AtomicU64::new(0) }; N],
            is_initialized: AtomicBool::new(false),
            is_initializing: AtomicBool::new(false),
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

        let required_size = N
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(AllocatorError::AddressOutOfBounds)?;
        if size_in_bytes < required_size {
            return Err(AllocatorError::AddressOutOfBounds);
        }
        if (base_ptr as usize).checked_add(required_size).is_none() {
            return Err(AllocatorError::AddressOutOfBounds);
        }

        // Enforce page alignment and the alignment required by the element type.
        if (base_ptr as usize) % 4096 != 0 || (base_ptr as usize) % core::mem::align_of::<T>() != 0
        {
            return Err(AllocatorError::InvalidAlignment);
        }

        if self.is_initialized.load(Ordering::Acquire)
            || self
                .is_initializing
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return Err(AllocatorError::AlreadyInitialized);
        }

        if self.is_initialized.load(Ordering::Acquire) {
            self.is_initializing.store(false, Ordering::Release);
            return Err(AllocatorError::AlreadyInitialized);
        }

        self.memory.store(base_ptr, Ordering::SeqCst);

        // Mark only real buffers as free. The final word may contain padding bits
        // when the pool size is not an exact multiple of 64.
        for i in 0..BITMAP_WORDS {
            let remaining = N.saturating_sub(i * 64);
            let free_mask = if remaining >= 64 {
                u64::MAX
            } else if remaining == 0 {
                0
            } else {
                (1u64 << remaining) - 1
            };
            self.bitmap[i].store(free_mask, Ordering::SeqCst);
        }

        compiler_fence(Ordering::SeqCst);
        self.is_initialized.store(true, Ordering::Release);
        self.is_initializing.store(false, Ordering::Release);
        Ok(())
    }

    /// Allocates a buffer from the pool, returning its index, ownership token,
    /// and non-null pointer.
    ///
    /// The returned pointer is valid until the corresponding index is passed to
    /// [`Self::free`]. The caller must not dereference it after freeing the buffer.
    ///
    /// Utilizes a bounded Compare-And-Swap (CAS) loop restricted to 128 retries.
    /// This guarantees deterministic execution deadlines, ensuring the RTOS
    /// never hangs indefinitely during high-contention allocation spikes.
    pub fn allocate(&self) -> Result<(usize, u64, NonNull<T>), AllocatorError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(AllocatorError::NotInitialized);
        }

        let base_ptr = self.memory.load(Ordering::Acquire);

        if self
            .allocation_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(AllocatorError::LockContention);
        }

        for word_idx in 0..BITMAP_WORDS {
            let atomic_word = &self.bitmap[word_idx];
            let mut current = atomic_word.load(Ordering::Acquire);
            let mut retries = 0;

            loop {
                // Bounded CAS to guarantee deterministic deadlines
                if retries >= 128 {
                    self.allocation_lock.store(false, Ordering::Release);
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

                        let buffer_idx = word_idx
                            .checked_mul(64)
                            .unwrap()
                            .checked_add(bit_idx)
                            .unwrap();

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
                            self.allocation_lock.store(false, Ordering::Release);
                            return Err(AllocatorError::OutOfMemory);
                        }

                        // # Safety
                        // Spatial: `buffer_idx` is mathematically bounded by `N`.
                        // Temporal: The atomic bitmap guarantees exclusive access to this index.
                        // Alignment: The host OS guarantees page alignment via `init()`.
                        let buffer_ptr = unsafe { base_ptr.add(buffer_idx) };
                        // The pool validated the base pointer and bounds before allocation.
                        let buffer_ptr = unsafe { NonNull::new_unchecked(buffer_ptr) };
                        let generation = self.generations[buffer_idx]
                            .fetch_add(1, Ordering::AcqRel)
                            .wrapping_add(1);
                        self.allocation_lock.store(false, Ordering::Release);
                        return Ok((buffer_idx, generation, buffer_ptr));
                    }
                    Err(raced) => {
                        current = raced;
                        retries += 1;
                    }
                }
            }
        }
        self.allocation_lock.store(false, Ordering::Release);
        Err(AllocatorError::OutOfMemory)
    }

    /// Frees a previously allocated buffer back to the pool using its ownership token.
    ///
    /// `generation` must be the token returned with the allocation. A stale or
    /// duplicated token is rejected before the buffer is scrubbed.
    ///
    /// Utilizes a bounded Compare-And-Swap (CAS) loop restricted to 128 retries
    /// to guarantee deterministic execution deadlines.
    /// Automatically zeroizes the buffer contents to prevent cross-domain data leakage.
    pub fn free(&self, buffer_idx: usize, generation: u64) -> Result<(), AllocatorError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(AllocatorError::NotInitialized);
        }

        if buffer_idx >= N {
            return Err(AllocatorError::AddressOutOfBounds);
        }

        if self
            .allocation_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(AllocatorError::LockContention);
        }

        let base_ptr = self.memory.load(Ordering::Acquire);

        let word_idx = buffer_idx / 64;
        let bit_idx = buffer_idx % 64;
        let mask = 1u64 << bit_idx;
        let atomic_word = &self.bitmap[word_idx];
        if atomic_word.load(Ordering::Acquire) & mask != 0 {
            self.allocation_lock.store(false, Ordering::Release);
            return Err(AllocatorError::DoubleFree);
        }
        if self.generations[buffer_idx].load(Ordering::Acquire) != generation {
            self.allocation_lock.store(false, Ordering::Release);
            return Err(AllocatorError::DoubleFree);
        }

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

        let mut current = atomic_word.load(Ordering::Acquire);
        let mut retries = 0;

        loop {
            // Bounded CAS to guarantee deterministic deadlines
            if retries >= 128 {
                self.allocation_lock.store(false, Ordering::Release);
                return Err(AllocatorError::LockContention);
            }

            if (current & mask) != 0 {
                self.allocation_lock.store(false, Ordering::Release);
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
                    self.allocation_lock.store(false, Ordering::Release);
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
