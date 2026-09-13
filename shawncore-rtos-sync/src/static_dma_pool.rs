// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Statically allocated, cache-aligned DMA memory pool.
//!
//! The free list is an ABA-tagged Treiber stack. Push and pop are lock-free and
//! have O(1) expected work. The free-list ABA tag is 32 bits and can wrap after
//! $2^{32}$ free-list mutations; target deployments must bound operational lifetime
//! below that limit or provide external reinitialization. Per-slot ownership uses
//! one atomic 64-bit word: the high bit records allocation and the low 63 bits
//! form the ownership generation, making generation validation and release one
//! atomic compare-exchange operation. Ownership generation wraps only after
//! $2^{63}$ allocations of the same slot.

use crate::error::AllocatorError;
use crate::ffi_callbacks::host_cache_flush;
use core::ptr::NonNull;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

const FREE_LIST_EMPTY: u32 = u32::MAX;
const OWNERSHIP_ALLOCATED_BIT: u64 = 1u64 << 63;
const OWNERSHIP_GENERATION_MASK: u64 = OWNERSHIP_ALLOCATED_BIT - 1;

/// A lock-free, generic, statically allocated DMA memory pool.
#[repr(C, align(64))]
pub struct StaticDmaPool<T, const N: usize, const BITMAP_WORDS: usize> {
    /// Pointer to the host-provided memory buffer.
    memory: AtomicPtr<T>,
    /// Packed free-list head: index in the low 32 bits and ABA generation in the high 32 bits.
    free_list_head: AtomicUsize,
    /// Packed next index and reserved generation field for each free-list node.
    next: [AtomicUsize; N],
    /// Per-slot ownership state: high bit is allocated, low 63 bits are the
    /// generation returned to callers as a free token. Ownership validation and
    /// release use one atomic compare-exchange so a stale free cannot clear a
    /// newer allocation after the generation check.
    ownership: [AtomicU64; N],
    /// Initialization flag.
    is_initialized: AtomicBool,
    /// Prevents concurrent initialization attempts.
    is_initializing: AtomicBool,
}

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
            assert!(N <= u32::MAX as usize, "DMA pool index must fit in 32 bits");
            assert!(
                usize::BITS >= 64,
                "DMA free-list head requires a 64-bit target"
            );
        }
        Self {
            memory: AtomicPtr::new(core::ptr::null_mut()),
            free_list_head: AtomicUsize::new(pack_head(0, 0)),
            next: [const { AtomicUsize::new(FREE_LIST_EMPTY as usize) }; N],
            ownership: [const { AtomicU64::new(0) }; N],
            is_initialized: AtomicBool::new(false),
            is_initializing: AtomicBool::new(false),
        }
    }

    /// Initializes the pool with a page-aligned host DMA region.
    ///
    /// `T` is a storage layout and alignment descriptor, not initialized Rust data.
    /// Allocations are uninitialized raw storage; callers must initialize a `T` value
    /// before reading it and must not use the allocation after `free` succeeds.
    ///
    /// # Safety
    /// `base_ptr` must identify writable storage for at least `N` consecutive `T`
    /// layouts, be valid for the pool's entire initialized lifetime, and not be
    /// concurrently accessed outside an allocation returned by this pool.
    pub unsafe fn init(
        &self,
        base_ptr: *mut T,
        size_in_bytes: usize,
    ) -> Result<(), AllocatorError> {
        if core::mem::size_of::<T>() == 0 {
            return Err(AllocatorError::AddressOutOfBounds);
        }
        if base_ptr.is_null() {
            return Err(AllocatorError::AddressOutOfBounds);
        }
        let required_size = N
            .checked_mul(core::mem::size_of::<T>())
            .ok_or(AllocatorError::AddressOutOfBounds)?;
        if size_in_bytes < required_size || (base_ptr as usize).checked_add(required_size).is_none()
        {
            return Err(AllocatorError::AddressOutOfBounds);
        }
        if (base_ptr as usize) % 4096 != 0 || (base_ptr as usize) % core::mem::align_of::<T>() != 0
        {
            return Err(AllocatorError::InvalidAlignment);
        }
        let required_bitmap_words = N.div_ceil(usize::BITS as usize);
        if BITMAP_WORDS != required_bitmap_words {
            return Err(AllocatorError::AddressOutOfBounds);
        }
        if self.is_initialized.load(Ordering::Acquire)
            || self
                .is_initializing
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return Err(AllocatorError::AlreadyInitialized);
        }
        self.memory.store(base_ptr, Ordering::Relaxed);
        for index in 0..N {
            let next_index = if index + 1 < N {
                index + 1
            } else {
                FREE_LIST_EMPTY as usize
            };
            self.next[index].store(next_index, Ordering::Relaxed);
            self.ownership[index].store(0, Ordering::Relaxed);
        }
        self.free_list_head
            .store(pack_head(0, 0), Ordering::Release);
        self.is_initialized.store(true, Ordering::Release);
        self.is_initializing.store(false, Ordering::Release);
        Ok(())
    }

    /// Allocates a buffer, returning its index, ownership generation, and pointer.
    pub fn allocate(&self) -> Result<(usize, u64, NonNull<T>), AllocatorError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(AllocatorError::NotInitialized);
        }
        let base_ptr = self.memory.load(Ordering::Acquire);
        let mut observed = self.free_list_head.load(Ordering::Acquire);
        loop {
            let (index, generation) = unpack_head(observed);
            if index == FREE_LIST_EMPTY {
                return Err(AllocatorError::OutOfMemory);
            }
            let next_index = self.next[index as usize].load(Ordering::Acquire) as u32;
            let replacement = pack_head(next_index, generation.wrapping_add(1));
            match self.free_list_head.compare_exchange_weak(
                observed,
                replacement,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let slot = index as usize;
                    let observed_state = self.ownership[slot].load(Ordering::Acquire);
                    debug_assert_eq!(observed_state & OWNERSHIP_ALLOCATED_BIT, 0);
                    let next_generation = (observed_state & OWNERSHIP_GENERATION_MASK)
                        .wrapping_add(1)
                        & OWNERSHIP_GENERATION_MASK;
                    let claimed_state = OWNERSHIP_ALLOCATED_BIT | next_generation;
                    if self.ownership[slot]
                        .compare_exchange(
                            observed_state,
                            claimed_state,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        // A slot removed from the free list must not be concurrently
                        // owned by another caller. Treat an unexpected state change
                        // as allocator corruption instead of publishing an untracked
                        // allocation.
                        return Err(AllocatorError::DoubleFree);
                    }
                    let token = next_generation;
                    let pointer = unsafe { NonNull::new_unchecked(base_ptr.add(slot)) };
                    return Ok((slot, token, pointer));
                }
                Err(current) => observed = current,
            }
        }
    }

    /// Frees a buffer using the generation returned by its allocation.
    pub fn free(&self, buffer_idx: usize, generation: u64) -> Result<(), AllocatorError> {
        if !self.is_initialized.load(Ordering::Acquire) {
            return Err(AllocatorError::NotInitialized);
        }
        if buffer_idx >= N {
            return Err(AllocatorError::AddressOutOfBounds);
        }
        if generation > OWNERSHIP_GENERATION_MASK {
            return Err(AllocatorError::DoubleFree);
        }
        let expected_state = OWNERSHIP_ALLOCATED_BIT | generation;
        if self.ownership[buffer_idx]
            .compare_exchange(
                expected_state,
                generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(AllocatorError::DoubleFree);
        }

        let base_ptr = self.memory.load(Ordering::Acquire);
        // # Safety
        // Spatial: `buffer_idx` is bounds-checked and `T` has nonzero size after `init`.
        // Temporal: ownership was atomically transitioned from this exact allocation
        // token to the free state. A stale token cannot clear a newer allocation.
        // The slot is not reachable from the free-list until zeroization and
        // cache publication complete below.
        // Alignment: byte writes require no alignment and do not assume initialized `T` data.
        unsafe {
            let pointer = base_ptr.add(buffer_idx).cast::<u8>();
            let length = core::mem::size_of::<T>();
            let word_size = core::mem::size_of::<u64>();
            let align = core::mem::align_of::<u64>();
            let mut offset = 0usize;

            // Clear a byte prefix only when T's address is not already u64-aligned.
            // The pool's backing storage is required to be suitably aligned for T,
            // so this prefix is at most 7 bytes.
            while offset < length && ((pointer as usize + offset) & (align - 1)) != 0 {
                core::ptr::write_volatile(pointer.add(offset), 0u8);
                offset += 1;
            }

            // Clear aligned words with volatile stores. This preserves the
            // compiler-visible wipe while reducing operations by up to 8x.
            while offset + word_size <= length {
                core::ptr::write_volatile(pointer.add(offset).cast::<u64>(), 0u64);
                offset += word_size;
            }

            // Clear any trailing bytes.
            while offset < length {
                core::ptr::write_volatile(pointer.add(offset), 0u8);
                offset += 1;
            }

            host_cache_flush(pointer, length);
        }
        compiler_fence(Ordering::Release);

        let mut observed = self.free_list_head.load(Ordering::Acquire);
        loop {
            let (_, head_generation) = unpack_head(observed);
            self.next[buffer_idx].store(observed as u32 as usize, Ordering::Relaxed);
            let replacement = pack_head(buffer_idx as u32, head_generation.wrapping_add(1));
            match self.free_list_head.compare_exchange_weak(
                observed,
                replacement,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => observed = current,
            }
        }
    }
}

const fn pack_head(index: u32, generation: u32) -> usize {
    ((generation as usize) << 32) | index as usize
}

fn unpack_head(value: usize) -> (u32, u32) {
    (value as u32, (value >> 32) as u32)
}

#[cfg(test)]
mod tests {
    use super::StaticDmaPool;
    use crate::error::AllocatorError;
    use crate::ffi_callbacks::shawncore_rtos_register_cache_flush;
    use core::mem::MaybeUninit;

    #[repr(C, align(4096))]
    struct AlignedStorage<const N: usize>(MaybeUninit<[u32; N]>);

    extern "C" fn test_cache_flush(_: *const u8, _: usize) {}

    fn install_test_callback() {
        unsafe { shawncore_rtos_register_cache_flush(Some(test_cache_flush)) };
    }

    #[test]
    fn free_list_allocates_every_slot_once() {
        let pool = StaticDmaPool::<u32, 65, 2>::new();
        let mut storage = AlignedStorage::<65>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<u32>();
        unsafe { pool.init(pointer, core::mem::size_of::<[u32; 65]>()) }.unwrap();

        for expected in 0..65 {
            let (index, _, _) = pool.allocate().unwrap();
            assert_eq!(index, expected);
        }
        assert_eq!(pool.allocate(), Err(AllocatorError::OutOfMemory));
    }

    #[test]
    fn stale_generation_cannot_free_reused_slot() {
        install_test_callback();
        let pool = StaticDmaPool::<u32, 1, 1>::new();
        let mut storage = AlignedStorage::<1>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<u32>();
        unsafe { pool.init(pointer, core::mem::size_of::<u32>()) }.unwrap();

        let (index, first_generation, first_pointer) = pool.allocate().unwrap();
        unsafe { first_pointer.as_ptr().write(0xA5A5_A5A5) };
        pool.free(index, first_generation).unwrap();
        let (index, second_generation, second_pointer) = pool.allocate().unwrap();
        unsafe { second_pointer.as_ptr().write(0x5A5A_5A5A) };

        assert_eq!(
            pool.free(index, first_generation),
            Err(AllocatorError::DoubleFree)
        );
        assert_eq!(unsafe { second_pointer.as_ptr().read() }, 0x5A5A_5A5A);
        pool.free(index, second_generation).unwrap();
    }

    #[test]
    fn stale_free_never_clears_a_newer_atomic_ownership_state() {
        install_test_callback();
        let pool = StaticDmaPool::<u32, 1, 1>::new();
        let mut storage = AlignedStorage::<1>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<u32>();
        unsafe { pool.init(pointer, core::mem::size_of::<u32>()) }.unwrap();

        let (index, first_generation, first_allocation) = pool.allocate().unwrap();
        unsafe { first_allocation.as_ptr().write(0x1111_2222) };
        pool.free(index, first_generation).unwrap();

        let (index, second_generation, second_allocation) = pool.allocate().unwrap();
        assert_ne!(first_generation, second_generation);
        unsafe { second_allocation.as_ptr().write(0x3333_4444) };

        assert_eq!(
            pool.free(index, first_generation),
            Err(AllocatorError::DoubleFree)
        );
        assert_eq!(unsafe { second_allocation.as_ptr().read() }, 0x3333_4444);
        pool.free(index, second_generation).unwrap();
    }

    #[test]
    fn rapid_reuse_rejects_every_stale_generation() {
        install_test_callback();
        let pool = StaticDmaPool::<u32, 1, 1>::new();
        let mut storage = AlignedStorage::<1>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<u32>();
        unsafe { pool.init(pointer, core::mem::size_of::<u32>()) }.unwrap();

        let (index, mut stale_generation, mut allocation) = pool.allocate().unwrap();
        for expected_generation in 1u64..=64u64 {
            unsafe { allocation.as_ptr().write(expected_generation as u32) };
            pool.free(index, stale_generation).unwrap();
            let (next_index, next_generation, next_allocation) = pool.allocate().unwrap();
            assert_eq!(next_index, index);
            assert_ne!(next_generation, stale_generation);
            assert_eq!(
                pool.free(index, stale_generation),
                Err(AllocatorError::DoubleFree)
            );
            stale_generation = next_generation;
            allocation = next_allocation;
        }
        pool.free(index, stale_generation).unwrap();
    }

    #[test]
    fn free_zeroizes_raw_storage_before_reuse() {
        install_test_callback();
        let pool = StaticDmaPool::<[u8; 8], 1, 1>::new();
        let mut storage = AlignedStorage::<2>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<[u8; 8]>();
        unsafe { pool.init(pointer, core::mem::size_of::<[u8; 8]>()) }.unwrap();

        let (index, generation, allocation) = pool.allocate().unwrap();
        unsafe { allocation.as_ptr().write([0xA5; 8]) };
        pool.free(index, generation).unwrap();
        assert_eq!(unsafe { allocation.as_ptr().read() }, [0u8; 8]);
    }

    #[test]
    fn init_rejects_zero_sized_storage_descriptors() {
        let pool = StaticDmaPool::<(), 1, 1>::new();
        assert_eq!(
            unsafe { pool.init(core::ptr::NonNull::<()>::dangling().as_ptr(), 0) },
            Err(AllocatorError::AddressOutOfBounds)
        );
    }
}
