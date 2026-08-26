#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Trigger the host OS panic callback to prevent cross-boundary unwinding UB.
    crate::ffi_error::invoke_panic_hook();
    
    // If the host OS callback returns (it shouldn't), halt the thread safely.
    loop {
        core::hint::spin_loop();
    }
}
