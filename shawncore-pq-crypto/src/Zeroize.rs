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
    host_cache_flush(data.as_ptr(), data.len());
}
