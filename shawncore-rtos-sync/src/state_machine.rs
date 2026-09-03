#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Atomic State Machine for USV Execution States.
//!
//! Hardware-agnostic state machine tracking the lifecycle of the RTOS enclave.
//! Validates state transitions securely across threads without locking.

use core::sync::atomic::{AtomicU8, Ordering};

/// Valid operational states for the RTOS enclave.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveState {
    /// Initialized but not yet running.
    Init = 0,
    /// Bootstrapping and running self-tests.
    Bootstrapping = 1,
    /// Normal operational mode.
    Operational = 2,
    /// Degraded mode (e.g., sensor failure, fallback execution).
    Degraded = 3,
    /// Terminal fault mode requiring a micro-reboot.
    Terminal = 4,
}

/// An atomic state machine for tracking global enclave execution states.
#[repr(C, align(64))]
pub struct StateMachine {
    current_state: AtomicU8,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine {
    /// Creates a new `StateMachine` initialized to `EnclaveState::Init`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            current_state: AtomicU8::new(EnclaveState::Init as u8),
        }
    }

    /// Attempts to advance the state machine to the target state.
    ///
    /// # Returns
    /// `Ok(())` if the transition is valid, or `Err(())` if the transition is forbidden.
    #[allow(clippy::result_unit_err)]
    pub fn try_advance(&self, target: EnclaveState) -> Result<(), ()> {
        let target = target as u8;
        let mut current = self.current_state.load(Ordering::Acquire);

        loop {
            let valid = matches!(
                (current, target),
                (0, 1) | (1, 2) | (1, 4) | (2, 3) | (2, 4) | (3, 4) | (3, 2)
            );

            if !valid {
                return Err(());
            }

            match self.current_state.compare_exchange_weak(
                current,
                target,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(updated) => current = updated,
            }
        }
    }

    /// Returns the current state of the enclave.
    #[must_use]
    pub fn get_state(&self) -> u8 {
        self.current_state.load(Ordering::Acquire)
    }
}
