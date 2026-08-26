#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Secure memory zeroization and cache flushing wrappers.
//! Hardware-agnostic implementation for MarTac integration.

use core::sync::atomic::{compiler_fence, Ordering};
use crate::ffi_callbacks::{host_cache_flush, host_stack_wipe};

/// Securely zeroizes a memory buffer, defeating compiler Dead Store Elimination (DSE).
///
/// This function uses volatile writes to ensure that the compiler does not optimize
/// away the zeroization process, which is critical for clearing cryptographic secrets.
#[inline(never)]
pub fn secure_zeroize(data: &mut [u8]) {
    let ptr = data.as_mut_ptr();
    let len = data.len();

    // # Safety
    // Spatial: `ptr` and `len` are derived directly from the safe slice `data`.
    // Temporal: `data` is valid for the duration of this function.
    // Alignment: Byte-level zeroization requires no strict alignment.
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);

        // Volatile write loop to prevent DSE
        for i in 0..len {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
    }

    // Single compiler fence to ensure zeroization is not reordered past subsequent operations.
    compiler_fence(Ordering::SeqCst);
}

/// Flushes a memory region from the CPU caches to main memory.
///
/// Delegates to the host OS to execute architecture-specific cache flush instructions
/// (e.g., `dc civac` on ARM or `clflushopt` on x86_64) to ensure DMA coherency.
#[inline(always)]
pub fn secure_cache_flush(ptr: *const u8, len: usize) {
    host_cache_flush(ptr, len);
}

/// Wipes the current thread's stack from the current stack pointer down to the given `stack_base`.
///
/// Delegates to the host OS to safely execute assembly-level stack wiping, preventing
/// Undefined Behavior (UB) that would occur if attempted in pure Rust.
#[inline(never)]
pub fn secure_stack_wipe(stack_base: u64) {
    host_stack_wipe(stack_base);
}
