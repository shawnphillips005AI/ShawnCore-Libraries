#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Telemetry Event Definitions.
//!
//! Provides standard event payloads for cross-core diagnostic tracking.

/// A generalized telemetry event for diagnostic tracking and health monitoring.
///
/// Padded explicitly to 64 bytes to perfectly align with CPU cache lines,
/// preventing false sharing during lock-free queue ingress/egress.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct TelemetryEvent {
    /// Unique identifier for the telemetry event type.
    pub event_id: u32,
    /// Explicit padding to satisfy alignment rules.
    pub _padding_1: [u8; 4],
    /// Monotonic timestamp of the event.
    pub timestamp: u64,
    /// Primary event payload data.
    pub payload: [u8; 48],
}

impl Default for TelemetryEvent {
    fn default() -> Self {
        Self {
            event_id: 0,
            _padding_1: [0; 4],
            timestamp: 0,
            payload: [0; 48],
        }
    }
}
