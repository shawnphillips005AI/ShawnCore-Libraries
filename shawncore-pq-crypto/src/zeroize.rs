#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Secure memory zeroization and cache flushing wrappers.
//! Hardware-agnostic implementation for MarTac integration.

use crate::ffi_callbacks::host_cache_flush;
use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Securely zeroizes a memory buffer, defeating compiler Dead Store Elimination (DSE).
///
/// Delegates to the `zeroize` crate's volatile clearing implementation and uses a
/// compiler fence to prevent reordering past subsequent operations.
#[inline(never)]
pub fn secure_zeroize(data: &mut [u8]) {
    data.zeroize();

    // Single compiler fence to ensure zeroization is not reordered past subsequent operations.
    compiler_fence(Ordering::SeqCst);
}

/// Flushes a memory region from the CPU caches to main memory.
///
/// Delegates to the host OS to execute architecture-specific cache maintenance.
/// Rust ordering does not establish DMA visibility; platform integration and target
/// validation determine the required flush, invalidate, and barrier sequence.
#[inline(always)]
pub(crate) fn secure_cache_flush(data: &[u8]) {
    // SAFETY: A slice always denotes a valid live memory range.
    unsafe { secure_cache_flush_raw(data.as_ptr(), data.len()) };
}

/// Flushes a valid live raw memory range from the CPU caches to main memory.
///
/// # Safety
/// `ptr` must be valid for reads of `len` bytes throughout the callback invocation.
#[inline(always)]
pub(crate) unsafe fn secure_cache_flush_raw(ptr: *const u8, len: usize) {
    host_cache_flush(ptr, len);
}
