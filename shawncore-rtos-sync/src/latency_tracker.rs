#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Hardware-Agnostic Execution Latency Tracker.
//!
//! Provides lock-free tracking of maximum and cumulative execution times
//! for deterministic RTOS task profiling.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A lock-free telemetry tracker for execution latency.
#[repr(C, align(64))]
pub struct LatencyTracker {
    started: AtomicBool,
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
            started: AtomicBool::new(false),
            start_time: AtomicU64::new(0),
            max_latency: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            samples: AtomicU64::new(0),
        }
    }

    /// Marks the beginning of a timed execution block.
    pub fn mark_start(&self, current_timestamp: u64) {
        self.start_time.store(current_timestamp, Ordering::Release);
        self.started.store(true, Ordering::Release);
    }

    /// Marks the end of a timed execution block, updating maximums and averages.
    pub fn mark_end(&self, current_timestamp: u64) {
        if !self.started.swap(false, Ordering::AcqRel) {
            return;
        }
        let start = self.start_time.load(Ordering::Acquire);
        if current_timestamp < start {
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

        let mut current_total = self.total_latency.load(Ordering::Relaxed);
        loop {
            let updated_total = current_total.saturating_add(delta);
            match self.total_latency.compare_exchange_weak(
                current_total,
                updated_total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(updated_total) => current_total = updated_total,
            }
        }
        self.samples.fetch_add(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::LatencyTracker;

    #[test]
    fn timestamp_zero_is_a_valid_start_and_end_is_single_use() {
        let tracker = LatencyTracker::new();

        tracker.mark_start(0);
        tracker.mark_end(5);
        assert_eq!(
            tracker
                .total_latency
                .load(core::sync::atomic::Ordering::Relaxed),
            5
        );
        assert_eq!(
            tracker.samples.load(core::sync::atomic::Ordering::Relaxed),
            1
        );

        tracker.mark_end(10);
        assert_eq!(
            tracker.samples.load(core::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn total_latency_saturates() {
        let tracker = LatencyTracker::new();
        tracker
            .total_latency
            .store(u64::MAX - 1, core::sync::atomic::Ordering::Relaxed);
        tracker.mark_start(1);
        tracker.mark_end(5);

        assert_eq!(
            tracker
                .total_latency
                .load(core::sync::atomic::Ordering::Relaxed),
            u64::MAX
        );
    }
}
