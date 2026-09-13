// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! O(1) Partitioned Bitmap Scheduler.
//!
//! Hardware-agnostic implementation for autonomous surface vehicles.
//! Implements a mathematically sound O(1) bitmap-based priority scheduler.
//!
//! # Architectural Notes
//! * **APIC Core ID Removal:** Hardware-specific APIC core ID checks and inline assembly
//!   context switches have been completely stripped out. The host OS is now responsible
//!   for maintaining per-core scheduler instances and injecting hardware-specific behaviors.
//! * **O(1) Selection:** Perfectly preserves the O(1) partitioned runqueue logic utilizing
//!   the `trailing_zeros()` hardware-accelerated selection against a 16-bit ready bitmap.
//! * **Stack Overflow Protection:** Integrates stack canary verification on every context switch.
//! * **Stack Layout Contract:** The host must provision each task stack so the reserved
//!   canary word at `stack_base` is outside the initial stack frame and consistent with
//!   the target architecture's stack-growth direction.

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

fn valid_stack_pointer(tcb: &Tcb, rsp: u64) -> bool {
    let Some(stack_end) = tcb.stack_base.checked_add(tcb.stack_size as u64) else {
        return false;
    };
    tcb.stack_base != 0
        && tcb.stack_base % core::mem::align_of::<u64>() as u64 == 0
        && tcb.stack_size >= core::mem::size_of::<u64>()
        && rsp >= tcb.stack_base + core::mem::size_of::<u64>() as u64
        && rsp <= stack_end
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
    ///
    /// # Safety
    /// `tcb.stack_base..stack_base + stack_size` must be mapped writable memory
    /// for the lifetime of the task, exclusively owned by the task, and contain
    /// the initial stack pointer. The scheduler writes and later reads the first
    /// aligned `u64` in that range as its canary.
    pub unsafe fn create_task(
        &mut self,
        mut tcb: Tcb,
        canary_value: u64,
    ) -> Result<(), SchedulerError> {
        let valid_stack = valid_stack_pointer(&tcb, tcb.rsp);

        if tcb.entry_point == 0
            || tcb.priority >= 16
            || !valid_stack
            || self.tasks[tcb.priority as usize].stack_base != 0
        {
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
    ///
    /// Check-ins from priorities that are not currently registered are ignored.
    /// A task is considered registered once its TCB has a non-zero stack base,
    /// which is the same registration marker used by task creation/scheduling.
    pub fn task_check_in(&mut self, priority: u8) {
        if priority < 16 && self.tasks[priority as usize].stack_base != 0 {
            self.watchdog_matrix |= 1 << priority;
        }
    }

    /// Configures the tasks required to check in before the watchdog is petted.
    ///
    /// Only currently registered task priorities are retained in the mask.
    /// This prevents nonexistent task slots from becoming impossible watchdog
    /// obligations and prevents a check-in from an unregistered priority from
    /// satisfying the watchdog gate.
    pub fn set_critical_task_mask(&mut self, critical_task_mask: u16) {
        let registered_mask = self.tasks.iter().enumerate().fold(0u16, |mask, (idx, tcb)| {
            if tcb.stack_base != 0 {
                mask | (1u16 << idx)
            } else {
                mask
            }
        });
        self.critical_task_mask = critical_task_mask & registered_mask;
        self.watchdog_matrix &= self.critical_task_mask;
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
    ///
    /// # Safety
    /// Every registered task stack must continue to satisfy `create_task`'s
    /// mapped-memory, lifetime, and ownership contract until it is removed.
    pub unsafe fn schedule_tick(&mut self, current_rsp: u64) -> u64 {
        let current_idx = self.current_task;

        // A zero RSP means the host has no current task context to save (for example,
        // scheduler entry from an idle/boot path). Preserve that established behavior.
        if current_idx < MAX_TASKS && current_rsp != 0 && self.tasks[current_idx].stack_base != 0 {
            let canary_ok = {
                let tcb = &self.tasks[current_idx];
                if !valid_stack_pointer(tcb, current_rsp) {
                    false
                } else {
                    // # Safety
                    // The host OS contract guarantees the task stack remains mapped,
                    // writable, aligned, and exclusively owned for the task lifetime.
                    let current_canary = unsafe {
                        let canary_ptr = tcb.stack_base as *const u64;
                        core::ptr::read_volatile(canary_ptr)
                    };
                    current_canary == tcb.stack_canary
                }
            };

            if !canary_ok {
                return 0;
            }

            self.tasks[current_idx].rsp = current_rsp;
        }

        // O(1) priority selection using the ready bitmap.
        let mut next_idx = self.ready_bitmap.trailing_zeros() as usize;
        if next_idx >= MAX_TASKS {
            next_idx = 15;
        }

        // A ready task must have a registered stack and a saved RSP within that stack.
        // An empty idle slot is valid when the scheduler falls back to priority 15.
        if self.tasks[next_idx].stack_base != 0 {
            let next_tcb = &self.tasks[next_idx];
            if !valid_stack_pointer(next_tcb, next_tcb.rsp) {
                return 0;
            }
            // # Safety
            // The host OS contract guarantees the task stack remains mapped, writable,
            // aligned, and exclusively owned for the task lifetime.
            let next_canary = unsafe {
                let canary_ptr = next_tcb.stack_base as *const u64;
                core::ptr::read_volatile(canary_ptr)
            };
            if next_canary != next_tcb.stack_canary {
                return 0;
            }
        } else if next_idx != 15 || (self.ready_bitmap & (1u16 << next_idx)) != 0 {
            return 0;
        }

        // Pet the hardware watchdog only after current-task integrity and the selected
        // next task/context have both passed validation. A canary or scheduler-context
        // failure must never refresh the watchdog immediately before reporting fault.
        if self.critical_task_mask != 0
            && (self.watchdog_matrix & self.critical_task_mask) == self.critical_task_mask
        {
            host_pet_watchdog();
            self.watchdog_matrix = 0;
        }

        self.current_task = next_idx;
        compiler_fence(Ordering::SeqCst);
        self.tasks[next_idx].rsp
    }
}

#[cfg(test)]
mod tests {
    use super::PerCoreScheduler;
    use crate::ffi_callbacks::shawncore_rtos_register_pet_watchdog;
    use crate::tcb::Tcb;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static WATCHDOG_PETS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count_watchdog_pet() {
        WATCHDOG_PETS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn watchdog_pets_only_after_all_critical_tasks_check_in() {
        unsafe { shawncore_rtos_register_pet_watchdog(Some(count_watchdog_pet)) };
        WATCHDOG_PETS.store(0, Ordering::Relaxed);
        let mut scheduler = PerCoreScheduler::new();
        // Mark priorities 2 and 5 as registered without constructing real stacks;
        // registration is represented by a non-zero stack_base in scheduler state.
        scheduler.tasks[2].stack_base = 1;
        scheduler.tasks[5].stack_base = 1;
        scheduler.set_critical_task_mask((1 << 2) | (1 << 5));

        scheduler.task_check_in(2);
        let _ = unsafe { scheduler.schedule_tick(0) };
        assert_eq!(WATCHDOG_PETS.load(Ordering::Relaxed), 0);

        scheduler.task_check_in(5);
        let _ = unsafe { scheduler.schedule_tick(0) };
        assert_eq!(WATCHDOG_PETS.load(Ordering::Relaxed), 1);
        assert_eq!(scheduler.watchdog_matrix, 0);
    }

    #[test]
    fn watchdog_ignores_unregistered_critical_slots_and_checkins() {
        let mut scheduler = PerCoreScheduler::new();

        scheduler.set_critical_task_mask(1 << 3);
        assert_eq!(scheduler.critical_task_mask, 0);

        scheduler.task_check_in(3);
        assert_eq!(scheduler.watchdog_matrix, 0);
    }

    #[test]
    fn watchdog_does_not_pet_after_current_task_canary_failure() {
        unsafe { shawncore_rtos_register_pet_watchdog(Some(count_watchdog_pet)) };
        WATCHDOG_PETS.store(0, Ordering::Relaxed);

        let mut scheduler = PerCoreScheduler::new();
        let mut stack = [0u64; 2];
        let stack_base = stack.as_mut_ptr() as u64;
        let stack_size = core::mem::size_of_val(&stack);
        let rsp = stack_base + core::mem::size_of::<u64>() as u64;

        unsafe {
            scheduler
                .create_task(Tcb::new_task(1, stack_base, stack_size, rsp, 1), 0xA5A5)
                .unwrap();
        }
        scheduler.current_task = 1;
        scheduler.set_critical_task_mask(1 << 1);
        scheduler.task_check_in(1);

        // Corrupt the canary while preserving a structurally valid task stack.
        stack[0] = 0xDEAD_BEEF;

        let result = unsafe { scheduler.schedule_tick(rsp) };
        assert_eq!(result, 0);
        assert_eq!(WATCHDOG_PETS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn idle_fallback_does_not_run_unregistered_priority_15() {
        let mut scheduler = PerCoreScheduler::new();

        // No ready tasks: priority 15 is a valid idle fallback and has no stack.
        let rsp = unsafe { scheduler.schedule_tick(0) };
        assert_eq!(rsp, 0);
        assert_eq!(scheduler.current_task, 15);

        // A ready bit for an unregistered priority-15 task is a scheduler fault,
        // not permission to fabricate or run a nonexistent stack.
        scheduler.ready_bitmap = 1u16 << 15;
        let rsp = unsafe { scheduler.schedule_tick(0) };
        assert_eq!(rsp, 0);
        assert_eq!(scheduler.current_task, 15);
    }

    #[test]
    fn zero_entry_point_is_rejected() {
        let mut scheduler = PerCoreScheduler::new();
        let mut stack = [0u64; 2];
        let stack_base = stack.as_mut_ptr() as u64;
        let stack_size = core::mem::size_of_val(&stack);

        let result = unsafe {
            scheduler.create_task(
                Tcb::new_task(0, stack_base, stack_size, stack_base, 1),
                0xA5A5,
            )
        };

        assert!(result.is_err());
    }

    #[test]
    fn rsp_cannot_overlap_stack_canary() {
        let mut scheduler = PerCoreScheduler::new();
        let mut stack = [0u64; 2];
        let stack_base = stack.as_mut_ptr() as u64;
        let stack_size = core::mem::size_of_val(&stack);
        let canary = 0xAA55u64;

        // The first u64 at stack_base is reserved for the canary.
        let overlaps_canary = Tcb::new_task(
            1,
            stack_base,
            stack_size,
            stack_base,
            1,
        );
        assert!(unsafe { scheduler.create_task(overlaps_canary, canary) }.is_err());

        // The first stack address after the canary is valid.
        let after_canary = Tcb::new_task(
            2,
            stack_base,
            stack_size,
            stack_base + core::mem::size_of::<u64>() as u64,
            2,
        );
        assert!(unsafe { scheduler.create_task(after_canary, canary) }.is_ok());
    }

    #[test]
    fn duplicate_priority_and_zero_stack_base_are_rejected() {
        let mut scheduler = PerCoreScheduler::new();
        let mut stack = [0u64; 2];
        let stack_base = stack.as_mut_ptr() as u64;
        let stack_size = core::mem::size_of_val(&stack);

        assert!(unsafe {
            scheduler.create_task(Tcb::new_task(1, 0, stack_size, stack_base, 1), 0xAA55)
        }
        .is_err());
        unsafe {
            scheduler
                .create_task(
                    Tcb::new_task(1, stack_base, stack_size, stack_base + core::mem::size_of::<u64>() as u64, 1),
                    0xAA55,
                )
                .unwrap();
        }
        assert!(unsafe {
            scheduler.create_task(
                Tcb::new_task(2, stack_base, stack_size, stack_base + core::mem::size_of::<u64>() as u64, 1),
                0x55AA,
            )
        }
        .is_err());
    }
}
