#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Hardware-Agnostic Execution Latency Tracker.
//!
//! Provides lock-free tracking of maximum and cumulative execution times
//! for deterministic RTOS task profiling.

use core::sync::atomic::{AtomicU64, Ordering};

/// A lock-free telemetry tracker for execution latency.
#[repr(C, align(64))]
pub struct LatencyTracker {
    start_time: AtomicU64,
    max_latency: AtomicU64,
    total_latency: AtomicU64,
    samples: AtomicU64,
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyTracker {
    /// Creates a new `LatencyTracker`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            start_time: AtomicU64::new(0),
            max_latency: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            samples: AtomicU64::new(0),
        }
    }

    /// Marks the beginning of a timed execution block.
    pub fn mark_start(&self, current_timestamp: u64) {
        self.start_time.store(current_timestamp, Ordering::Release);
    }

    /// Marks the end of a timed execution block, updating maximums and averages.
    pub fn mark_end(&self, current_timestamp: u64) {
        let start = self.start_time.load(Ordering::Acquire);
        if start == 0 || current_timestamp < start {
            return;
        }

        let delta = current_timestamp - start;

        // Update maximum latency using CAS loop
        let mut current_max = self.max_latency.load(Ordering::Relaxed);
        while delta > current_max {
            match self.max_latency.compare_exchange_weak(
                current_max,
                delta,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(updated_max) => current_max = updated_max,
            }
        }

        self.total_latency.fetch_add(delta, Ordering::Relaxed);
        self.samples.fetch_add(1, Ordering::Release);
    }
}
