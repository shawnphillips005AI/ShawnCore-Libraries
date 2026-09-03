#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! RTOS Synchronization error types.
//! Provides standard error enumerations for the deterministic execution stack.
//! These map directly to C-compatible FFI error codes for host OS integration.

/// Memory Allocator errors.
/// Returned by DMA pools and other static memory management structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorError {
    /// Out of memory or pool exhausted.
    OutOfMemory,
    /// Address out of bounds or invalid memory region.
    AddressOutOfBounds,
    /// Invalid alignment for DMA memory.
    InvalidAlignment,
    /// Lock contention during CAS loop.
    LockContention,
    /// Double free detected.
    DoubleFree,
    /// Pool is not initialized.
    NotInitialized,
    /// Pool is already initialized.
    AlreadyInitialized,
}

/// IPC and Queue errors.
/// Returned by lock-free queues (SPSC, RingBuffer) during cross-core communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Queue is full.
    QueueFull,
    /// Queue is not initialized.
    NotInitialized,
    /// Queue is already initialized.
    AlreadyInitialized,
    /// Invalid memory alignment or size provided by the host OS.
    InvalidMemory,
}

/// Scheduler errors.
/// Returned by the O(1) bitmap scheduler during task management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    /// Task fault or unrecoverable execution error requiring a micro-reboot.
    TaskFault,
}

/// Internal state validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// The provided state transition is invalid.
    InvalidState,
}
