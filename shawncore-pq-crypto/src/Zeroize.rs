#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Secure memory zeroization and cache flushing wrappers.
//! Hardware-agnostic implementation for MarTac integration.

use crate::ffi_callbacks::host_cache_flush;
use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Securely zeroizes a memory buffer, defeating compiler Dead Store Elimination (DSE).
///
/// Delegates to the audited `zeroize` crate, which clears the whole buffer with a
/// single volatile write rather than a byte-by-byte loop, keeping this call cheap
/// enough for RTOS deadline budgets while still preventing the compiler from
/// optimizing away the clear.
#[inline(never)]
pub fn secure_zeroize(data: &mut [u8]) {
    data.zeroize();

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
