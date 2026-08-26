#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! FFI Error Handling and Panic Safety.
//!
//! Provides C-compatible error codes and a panic hook registry to prevent
//! cross-boundary unwinding Undefined Behavior (UB).

use core::sync::atomic::{compiler_fence, AtomicPtr, Ordering};

/// C-compatible error codes for the ShawnCore RTOS Sync library.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShawncoreRtosErr {
    /// Operation completed successfully.
    Success = 0,
    /// Out of memory or pool exhausted.
    OutOfMemory = 1,
    /// Address out of bounds or invalid memory region.
    AddressOutOfBounds = 2,
    /// Invalid alignment for DMA memory.
    InvalidAlignment = 3,
    /// Lock contention during CAS loop.
    LockContention = 4,
    /// Double free detected.
    DoubleFree = 5,
    /// Pool or queue is not initialized.
    NotInitialized = 6,
    /// Pool or queue is already initialized.
    AlreadyInitialized = 7,
    /// Queue is full.
    QueueFull = 8,
    /// Invalid memory provided to queue.
    InvalidMemory = 9,
    /// Task fault in scheduler.
    TaskFault = 10,
    /// A panic occurred within the Rust boundary.
    Panic = 99,
}

impl From<crate::static_dma_pool::AllocatorError> for ShawncoreRtosErr {
    fn from(err: crate::static_dma_pool::AllocatorError) -> Self {
        match err {
            crate::static_dma_pool::AllocatorError::OutOfMemory => Self::OutOfMemory,
            crate::static_dma_pool::AllocatorError::AddressOutOfBounds => Self::AddressOutOfBounds,
            crate::static_dma_pool::AllocatorError::InvalidAlignment => Self::InvalidAlignment,
            crate::static_dma_pool::AllocatorError::LockContention => Self::LockContention,
            crate::static_dma_pool::AllocatorError::DoubleFree => Self::DoubleFree,
            crate::static_dma_pool::AllocatorError::NotInitialized => Self::NotInitialized,
            crate::static_dma_pool::AllocatorError::AlreadyInitialized => Self::AlreadyInitialized,
        }
    }
}

impl From<crate::spsc_queue::IpcError> for ShawncoreRtosErr {
    fn from(err: crate::spsc_queue::IpcError) -> Self {
        match err {
            crate::spsc_queue::IpcError::QueueFull => Self::QueueFull,
            crate::spsc_queue::IpcError::NotInitialized => Self::NotInitialized,
            crate::spsc_queue::IpcError::AlreadyInitialized => Self::AlreadyInitialized,
            crate::spsc_queue::IpcError::InvalidMemory => Self::InvalidMemory,
        }
    }
}

impl From<crate::error::SchedulerError> for ShawncoreRtosErr {
    fn from(err: crate::error::SchedulerError) -> Self {
        match err {
            crate::error::SchedulerError::TaskFault => Self::TaskFault,
        }
    }
}

/// Type definition for the host OS panic callback.
pub type PanicCallback = extern "C" fn();

/// Global registry for the host OS panic callback.
static PANIC_CALLBACK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Registers a host OS callback to be invoked upon a Rust panic.
/// This prevents unwinding across the FFI boundary.
///
/// # Safety
/// `cb` must be a valid function pointer to a C-ABI compatible function.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_register_panic_hook(cb: PanicCallback) {
    PANIC_CALLBACK.store(cb as *mut (), Ordering::SeqCst);
}

/// Invokes the registered panic callback.
/// Designed to be called from the global `#[panic_handler]` in the final binary
/// or during unrecoverable internal state corruption.
pub fn invoke_panic_hook() {
    compiler_fence(Ordering::SeqCst);
    let cb_ptr = PANIC_CALLBACK.load(Ordering::Acquire);
    
    if !cb_ptr.is_null() {
        // # Safety
        // Spatial: N/A.
        // Temporal: The host OS guarantees the callback remains valid for the lifetime of the program.
        // Alignment: N/A.
        unsafe {
            let cb: PanicCallback = core::mem::transmute(cb_ptr);
            cb();
        }
    }
}
