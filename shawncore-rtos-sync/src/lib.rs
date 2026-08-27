#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
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
    fn scheduler_selects_highest_priority_ready_task() {
        let mut scheduler = PerCoreScheduler::new();
        scheduler
            .create_task(Tcb::new_task(1, 0, 0, 0x1000, 5), 0xAA55)
            .unwrap();
        scheduler
            .create_task(Tcb::new_task(2, 0, 0, 0x2000, 2), 0x55AA)
            .unwrap();

        assert_eq!(scheduler.schedule_tick(0), 0x2000);
        scheduler.clear_ready(2);
        assert_eq!(scheduler.schedule_tick(0), 0x1000);
        scheduler.clear_ready(5);
        assert_eq!(scheduler.schedule_tick(0), 0);
    }

    #[test]
    fn scheduler_rejects_invalid_priority() {
        let mut scheduler = PerCoreScheduler::new();
        assert!(scheduler
            .create_task(Tcb::new_task(0, 0, 0, 0, 16), 0)
            .is_err());
    }

    #[test]
    fn scheduler_rejects_invalid_stack_descriptor() {
        let mut scheduler = PerCoreScheduler::new();
        assert!(scheduler
            .create_task(Tcb::new_task(0, 3, 8, 0, 1), 0)
            .is_err());
        assert!(scheduler
            .create_task(Tcb::new_task(0, 8, 7, 0, 1), 0)
            .is_err());
        assert!(scheduler
            .create_task(Tcb::new_task(0, 0x1000, 0x100, 0x2000, 1), 0)
            .is_err());
        assert!(scheduler
            .create_task(Tcb::new_task(0, u64::MAX - 3, 8, u64::MAX - 3, 1), 0)
            .is_err());
    }
}
