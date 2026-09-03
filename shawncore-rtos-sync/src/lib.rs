#![no_std]
#![deny(clippy::all)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! ShawnCore RTOS Sync Library
//! Hardware-agnostic deterministic execution and synchronization primitives for MarTac USVs.
//! Designed for seamless C/C++ host OS integration via FFI.

pub mod bitmap_scheduler;
pub mod error;
pub mod ffi;
pub mod ffi_callbacks;
pub mod ffi_error;
pub mod fft_queue;
pub mod interrupt_spinlock;
pub mod latency_tracker;
pub mod ring_buffer;
pub mod spsc_queue;
pub mod state_machine;
pub mod static_dma_pool;
pub mod tcb;
pub mod telemetry_queue;

#[cfg(test)]
mod tests {
    use super::bitmap_scheduler::PerCoreScheduler;
    use super::ffi::FftResult;
    use super::state_machine::{EnclaveState, StateMachine};
    use super::tcb::Tcb;

    #[test]
    fn state_machine_accepts_only_valid_transitions() {
        let machine = StateMachine::new();
        assert_eq!(machine.get_state(), EnclaveState::Init as u8);
        assert!(machine.try_advance(EnclaveState::Operational).is_err());
        machine.try_advance(EnclaveState::Bootstrapping).unwrap();
        machine.try_advance(EnclaveState::Operational).unwrap();
        machine.try_advance(EnclaveState::Degraded).unwrap();
        machine.try_advance(EnclaveState::Operational).unwrap();
        assert!(machine.try_advance(EnclaveState::Init).is_err());
        assert_eq!(machine.get_state(), EnclaveState::Operational as u8);
    }

    #[test]
    fn fft_result_has_one_cache_line_layout() {
        assert_eq!(core::mem::size_of::<FftResult>(), 64);
        assert_eq!(core::mem::align_of::<FftResult>(), 64);
    }

    #[test]
    fn scheduler_selects_highest_priority_ready_task() {
        let mut scheduler = PerCoreScheduler::new();
        let mut stacks = [[0u64; 2]; 2];
        let first_stack_base = stacks[0].as_mut_ptr() as u64;
        let second_stack_base = stacks[1].as_mut_ptr() as u64;
        let stack_size = core::mem::size_of_val(&stacks[0]);
        unsafe {
            scheduler
                .create_task(
                    Tcb::new_task(1, first_stack_base, stack_size, first_stack_base, 5),
                    0xAA55,
                )
                .unwrap();
            scheduler
                .create_task(
                    Tcb::new_task(2, second_stack_base, stack_size, second_stack_base, 2),
                    0x55AA,
                )
                .unwrap();
        }

        assert_eq!(unsafe { scheduler.schedule_tick(0) }, second_stack_base);
        scheduler.clear_ready(2);
        assert_eq!(
            unsafe { scheduler.schedule_tick(second_stack_base) },
            first_stack_base
        );
        scheduler.clear_ready(5);
        assert_eq!(unsafe { scheduler.schedule_tick(first_stack_base) }, 0);
    }

    #[test]
    fn scheduler_rejects_invalid_priority() {
        let mut scheduler = PerCoreScheduler::new();
        assert!(unsafe { scheduler.create_task(Tcb::new_task(0, 0, 0, 0, 16), 0) }.is_err());
    }

    #[test]
    fn scheduler_rejects_invalid_stack_descriptor() {
        let mut scheduler = PerCoreScheduler::new();
        assert!(unsafe { scheduler.create_task(Tcb::new_task(0, 3, 8, 0, 1), 0) }.is_err());
        assert!(unsafe { scheduler.create_task(Tcb::new_task(0, 8, 7, 0, 1), 0) }.is_err());
        assert!(
            unsafe { scheduler.create_task(Tcb::new_task(0, 0x1000, 0x100, 0x2000, 1), 0) }
                .is_err()
        );
        assert!(unsafe {
            scheduler.create_task(Tcb::new_task(0, u64::MAX - 3, 8, u64::MAX - 3, 1), 0)
        }
        .is_err());
    }
}
