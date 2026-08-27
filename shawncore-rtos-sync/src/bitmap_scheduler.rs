#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! O(1) Partitioned Bitmap Scheduler.
//!
//! Hardware-agnostic implementation for MarTac USVs.
//! Implements a mathematically sound O(1) bitmap-based priority scheduler.
//!
//! # Architectural Notes
//! * **APIC Core ID Removal:** Hardware-specific APIC core ID checks and inline assembly
//!   context switches have been completely stripped out. The host OS is now responsible
//!   for maintaining per-core scheduler instances and injecting hardware-specific behaviors.
//! * **O(1) Selection:** Perfectly preserves the O(1) partitioned runqueue logic utilizing
//!   the `trailing_zeros()` hardware-accelerated selection against a 16-bit ready bitmap.
//! * **Stack Overflow Protection:** Integrates stack canary verification on every context switch.

use crate::error::SchedulerError;
use crate::ffi_callbacks::host_pet_watchdog;
use crate::tcb::Tcb;
use core::sync::atomic::{compiler_fence, Ordering};

/// Maximum number of tasks supported per core scheduler instance.
pub const MAX_TASKS: usize = 16;

/// Per-Core Scheduler state.
///
/// Manages up to 16 tasks using a 16-bit ready bitmap for O(1) scheduling.
/// Aligned to 64 bytes to prevent false sharing when multiple schedulers
/// are allocated contiguously by the host OS.
#[repr(C, align(64))]
pub struct PerCoreScheduler {
    /// Array of Task Control Blocks.
    pub tasks: [Tcb; MAX_TASKS],
    /// O(1) Ready Bitmap. Each bit represents a task's readiness (1 = ready, 0 = blocked).
    pub ready_bitmap: u16,
    /// Index of the currently executing task.
    pub current_task: usize,
    /// Bits for critical tasks that checked in during the current watchdog window.
    pub watchdog_matrix: u16,
    /// Tasks required to check in before the watchdog may be petted.
    pub critical_task_mask: u16,
}

impl Default for PerCoreScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCoreScheduler {
    /// Creates a new, empty per-core scheduler.
    ///
    /// Initializes all 16 task slots with empty TCBs and sets the current task to 15 (Idle).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tasks: [
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
                Tcb::new(),
            ],
            ready_bitmap: 0,
            current_task: 15, // Default to idle task
            watchdog_matrix: 0,
            critical_task_mask: 0,
        }
    }

    /// Registers a new task with the scheduler and injects the stack canary.
    ///
    /// The host OS is responsible for initializing the task's stack frame
    /// and providing the `initial_rsp` within the TCB before calling this function.
    ///
    /// # Arguments
    /// * `tcb` - The Task Control Block to register.
    /// * `canary_value` - A cryptographically secure random 64-bit integer provided by the host OS.
    ///
    /// # Returns
    /// `Ok(())` if the task was registered successfully, or `SchedulerError::TaskFault` if the priority is out of bounds.
    pub fn create_task(&mut self, mut tcb: Tcb, canary_value: u64) -> Result<(), SchedulerError> {
        let stack_end = tcb.stack_base.checked_add(tcb.stack_size as u64);
        let valid_stack = tcb.stack_base == 0
            || (tcb.stack_base % core::mem::align_of::<u64>() as u64 == 0
                && tcb.stack_size >= core::mem::size_of::<u64>()
                && stack_end.is_some_and(|end| tcb.rsp >= tcb.stack_base && tcb.rsp <= end));

        if tcb.priority >= 16 || !valid_stack {
            return Err(SchedulerError::TaskFault);
        }

        tcb.stack_canary = canary_value;

        if tcb.stack_base != 0 {
            // # Safety
            // Spatial: `stack_base` is provided by the host OS and assumed to be valid.
            // Temporal: The stack memory is valid for the lifetime of the task.
            // Alignment: `stack_base` must be 8-byte aligned.
            unsafe {
                let canary_ptr = tcb.stack_base as *mut u64;
                core::ptr::write_volatile(canary_ptr, canary_value);
            }
        }

        let idx = tcb.priority as usize;
        self.tasks[idx] = tcb;
        self.ready_bitmap |= 1 << idx;

        Ok(())
    }

    /// Marks a task as ready to run.
    ///
    /// Sets the corresponding bit in the `ready_bitmap`.
    ///
    /// # Arguments
    /// * `priority` - The priority index of the task to mark as ready.
    pub fn set_ready(&mut self, priority: u8) {
        if priority < 16 {
            self.ready_bitmap |= 1 << priority;
        }
    }

    /// Marks a task as blocked or waiting.
    ///
    /// Clears the corresponding bit in the `ready_bitmap`.
    ///
    /// # Arguments
    /// * `priority` - The priority index of the task to block.
    pub fn clear_ready(&mut self, priority: u8) {
        if priority < 16 {
            self.ready_bitmap &= !(1 << priority);
        }
    }

    /// Records a critical task check-in for the current watchdog window.
    pub fn task_check_in(&mut self, priority: u8) {
        if priority < 16 {
            self.watchdog_matrix |= 1 << priority;
        }
    }

    /// The core scheduling logic (Preemptive & Cooperative).
    ///
    /// Implements O(1) Lock-Free Partitioned Scheduling.
    /// Takes the current stack pointer, saves it to the active task, verifies the stack canary,
    /// selects the next highest priority task using `trailing_zeros()`, and returns the new stack pointer.
    ///
    /// # Arguments
    /// * `current_rsp` - The stack pointer of the currently executing task, provided by the host OS ISR.
    ///
    /// # Returns
    /// The stack pointer of the next task to execute. Returns `0` if a stack overflow (canary corruption) is detected.
    #[must_use]
    pub fn schedule_tick(&mut self, current_rsp: u64) -> u64 {
        if self.critical_task_mask != 0
            && (self.watchdog_matrix & self.critical_task_mask) == self.critical_task_mask
        {
            host_pet_watchdog();
            self.watchdog_matrix = 0;
        }
        let current_idx = self.current_task;

        // Save the current task's stack pointer and verify its canary
        if current_idx < MAX_TASKS {
            self.tasks[current_idx].rsp = current_rsp;

            let tcb = &self.tasks[current_idx];
            if tcb.stack_base != 0 {
                if tcb.stack_base % core::mem::align_of::<u64>() as u64 != 0
                    || tcb.stack_size < core::mem::size_of::<u64>()
                {
                    return 0;
                }

                // # Safety
                // Spatial: `stack_base` is provided by the host OS and assumed to be valid.
                // Temporal: The stack memory is valid for the lifetime of the task.
                // Alignment: `stack_base` must be 8-byte aligned.
                let current_canary = unsafe {
                    let canary_ptr = tcb.stack_base as *const u64;
                    core::ptr::read_volatile(canary_ptr)
                };

                if current_canary != tcb.stack_canary {
                    // Stack overflow detected. Return 0 to signal a catastrophic fault to the host OS.
                    return 0;
                }
            }
        }

        // O(1) Priority Queue: Find the lowest bit set in the ready_bitmap using hardware trailing_zeros.
        // This guarantees deterministic execution time regardless of the number of tasks.
        let mut next_idx = self.ready_bitmap.trailing_zeros() as usize;

        // Fallback to idle task (priority 15) if no tasks are ready
        if next_idx >= MAX_TASKS {
            next_idx = 15;
        }

        self.current_task = next_idx;

        // Ensure the updated TCB state is visible before returning the new RSP to the host OS.
        compiler_fence(Ordering::SeqCst);

        self.tasks[next_idx].rsp
    }
}

#[cfg(test)]
mod tests {
    use super::PerCoreScheduler;
    use crate::ffi_callbacks::shawncore_rtos_register_pet_watchdog;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static WATCHDOG_PETS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count_watchdog_pet() {
        WATCHDOG_PETS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn watchdog_pets_only_after_all_critical_tasks_check_in() {
        unsafe { shawncore_rtos_register_pet_watchdog(count_watchdog_pet) };
        WATCHDOG_PETS.store(0, Ordering::Relaxed);
        let mut scheduler = PerCoreScheduler::new();
        scheduler.critical_task_mask = (1 << 2) | (1 << 5);

        scheduler.task_check_in(2);
        let _ = scheduler.schedule_tick(0);
        assert_eq!(WATCHDOG_PETS.load(Ordering::Relaxed), 0);

        scheduler.task_check_in(5);
        let _ = scheduler.schedule_tick(0);
        assert_eq!(WATCHDOG_PETS.load(Ordering::Relaxed), 1);
        assert_eq!(scheduler.watchdog_matrix, 0);
    }
}
