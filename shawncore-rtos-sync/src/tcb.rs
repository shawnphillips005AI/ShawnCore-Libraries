#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Task Control Block (TCB) for the O(1) Bitmap Scheduler.
//!
//! Hardware-agnostic implementation for MarTac USVs.
//! Tracks the stack pointer for true preemptive context switching and
//! maintains a cryptographic stack canary to detect stack overflows.

/// Task Control Block.
///
/// Maintains the execution state, priority, and security metadata of a single scheduled task.
/// Aligned to 64 bytes to prevent false sharing across CPU caches when accessed by the host OS.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct Tcb {
    /// Entry point of the task (function pointer address).
    pub entry_point: u64,
    /// Base physical or virtual address of the task's stack.
    pub stack_base: u64,
    /// Size of the task's stack in bytes.
    pub stack_size: usize,
    /// Current stack pointer (saved during context switch).
    pub rsp: u64,
    /// Priority of the task (0 is highest, 15 is lowest).
    pub priority: u8,
    /// Cryptographically random canary placed at the bottom of the stack to detect overflows.
    pub stack_canary: u64,
}

impl Default for Tcb {
    fn default() -> Self {
        Self::new()
    }
}

impl Tcb {
    /// Creates a new, empty TCB.
    ///
    /// Defaults to the lowest priority (15), typically reserved for the idle task.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entry_point: 0,
            stack_base: 0,
            stack_size: 0,
            rsp: 0,
            priority: 15, // Lowest priority (Idle task)
            stack_canary: 0,
        }
    }

    /// Creates a new active TCB.
    ///
    /// # Arguments
    /// * `entry_point` - The memory address of the task's entry function.
    /// * `stack_base` - The base address of the allocated stack.
    /// * `stack_size` - The size of the allocated stack.
    /// * `initial_rsp` - The initial stack pointer, pre-configured by the host OS.
    /// * `priority` - The task priority (0-15).
    #[must_use]
    pub const fn new_task(
        entry_point: u64,
        stack_base: u64,
        stack_size: usize,
        initial_rsp: u64,
        priority: u8,
    ) -> Self {
        Self {
            entry_point,
            stack_base,
            stack_size,
            rsp: initial_rsp,
            priority,
            stack_canary: 0, // Will be populated by the scheduler during registration
        }
    }
}
