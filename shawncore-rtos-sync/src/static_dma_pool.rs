#![allow(clippy::items_after_test_module)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Statically allocated, cache-aligned DMA memory pool.
//!
//! The free list is an ABA-tagged Treiber stack. Push and pop are lock-free and
//! have O(1) expected work; callers must still handle `LockContention` only if
//! another operation wins the bounded hardware scheduling window.

use crate::error::AllocatorError;
use core::ptr::NonNull;
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use zeroize::Zeroize;

const FREE_LIST_EMPTY: u32 = u32::MAX;

/// A lock-free, generic, statically allocated DMA memory pool.
#[repr(C, align(64))]
pub struct StaticDmaPool<T, const N: usize, const BITMAP_WORDS: usize> {
    /// Pointer to the host-provided memory buffer.
    memory: AtomicPtr<T>,
    /// Packed free-list head: index in the low 32 bits and ABA generation in the high 32 bits.
    free_list_head: AtomicUsize,
    /// Packed next index and reserved generation field for each free-list node.
    next: [AtomicUsize; N],
    /// Per-slot ownership generation returned to callers as a free token.
    generations: [AtomicU64; N],
    /// Per-slot allocation state used to reject duplicate and stale frees.
    allocated: [AtomicBool; N],
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
    fn free_list_allocates_every_slot_once() {
        let pool = StaticDmaPool::<u32, 65, 2>::new();
        let mut storage = AlignedStorage::<65>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<u32>();
        pool.init(pointer, core::mem::size_of::<[u32; 65]>())
            .unwrap();

        for expected in 0..65 {
            let (index, _, _) = pool.allocate().unwrap();
            assert_eq!(index, expected);
        }
        assert_eq!(pool.allocate(), Err(AllocatorError::OutOfMemory));
    }

    #[test]
    fn stale_generation_cannot_free_reused_slot() {
        let pool = StaticDmaPool::<u32, 1, 1>::new();
        let mut storage = AlignedStorage::<1>(MaybeUninit::uninit());
        let pointer = storage.0.as_mut_ptr().cast::<u32>();
        pool.init(pointer, core::mem::size_of::<u32>()).unwrap();

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
            generations: [const { AtomicU64::new(0) }; N],
            allocated: [const { AtomicBool::new(false) }; N],
            is_initialized: AtomicBool::new(false),
            is_initializing: AtomicBool::new(false),
        }
    }

    /// Initializes the pool with a page-aligned host DMA region.
    pub fn init(&self, base_ptr: *mut T, size_in_bytes: usize) -> Result<(), AllocatorError> {
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
            self.generations[index].store(0, Ordering::Relaxed);
            self.allocated[index].store(false, Ordering::Relaxed);
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
                    let token = self.generations[slot]
                        .fetch_add(1, Ordering::AcqRel)
                        .wrapping_add(1);
                    self.allocated[slot].store(true, Ordering::Release);
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
        if self.generations[buffer_idx].load(Ordering::Acquire) != generation {
            return Err(AllocatorError::DoubleFree);
        }
        if self.allocated[buffer_idx]
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(AllocatorError::DoubleFree);
        }

        let base_ptr = self.memory.load(Ordering::Acquire);
        // # Safety
        // Spatial: `buffer_idx` is bounds-checked above.
        // Temporal: `allocated[buffer_idx]` was just transitioned from true to false,
        // so this task has exclusive ownership of the slot.
        // Alignment: The host OS guarantees `T`-alignment via `init()`.
        unsafe {
            let pointer = base_ptr.add(buffer_idx).cast::<u8>();
            let length = core::mem::size_of::<T>();
            core::slice::from_raw_parts_mut(pointer, length).zeroize();
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
