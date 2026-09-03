#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Foreign Function Interface (FFI) for the RTOS Sync Stack.
//!
//! Provides safe, opaque C-callable boundaries for the MarTac host OS.
//! Prevents cross-boundary Undefined Behavior (UB) by encapsulating all
//! complex Rust types and returning C-compatible error codes.

use crate::bitmap_scheduler::PerCoreScheduler;
use crate::ffi_error::ShawncoreRtosErr;
use crate::latency_tracker::LatencyTracker;
use crate::ring_buffer::RingBuffer;
use crate::spsc_queue::{CacheAlignedSlot, SpscQueue};
use crate::state_machine::{EnclaveState, StateMachine};
use crate::static_dma_pool::StaticDmaPool;
use crate::tcb::Tcb;
use crate::telemetry_queue::TelemetryEvent;
use core::sync::atomic::{compiler_fence, Ordering};

// ============================================================================
// Concrete Type Aliases for Generics (Monomorphization for C)
// ============================================================================

/// Concrete DMA Pool: 256 buffers of 2048 bytes (4 bitmap words).
pub type DmaPool2K = StaticDmaPool<[u8; 2048], 256, 4>;

/// Concrete SPSC Queue for Telemetry Events: 64 elements.
pub type SpscQueueTelemetry = SpscQueue<TelemetryEvent, 64>;

/// Concrete Cache Aligned Slot for Telemetry Events.
pub type SpscQueueTelemetrySlot = CacheAlignedSlot<TelemetryEvent>;

/// Electronic Warfare Command.
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
pub struct EwCommand {
    /// Attack mode.
    pub mode: u8,
    /// Explicit padding to prevent uninitialized stack memory
    /// from leaking into the lock-free IPC queue, causing Undefined Behavior.
    pub _padding: [u8; 7],
    /// Target frequency.
    pub target_freq: u64,
    /// Target bandwidth.
    pub target_bw: u64,
}

/// Represents a processed FFT result from the SDR.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct FftResult {
    /// Signal-to-Noise Ratio in dB.
    pub snr_db: u32,
    /// Center frequency of the detected signal.
    pub center_freq: u64,
    /// Bandwidth of the detected signal.
    pub bandwidth: u64,
    /// Timestamp of the detection.
    pub timestamp: u64,
    /// Padding to ensure 64-byte alignment.
    pub _padding: [u8; 36],
}

impl Default for FftResult {
    fn default() -> Self {
        Self {
            snr_db: 0,
            center_freq: 0,
            bandwidth: 0,
            timestamp: 0,
            _padding: [0; 36],
        }
    }
}

/// Concrete Ring Buffer for EW Commands: 1024 elements.
pub type RingBufferEwCommand = RingBuffer<EwCommand, 1024>;

/// Concrete FFT Queue: 256 elements.
pub type SpscQueueFft = SpscQueue<FftResult, 256>;

/// Concrete Cache Aligned Slot for FFT Results.
pub type SpscQueueFftSlot = CacheAlignedSlot<FftResult>;

fn valid_dma_region<T>(memory_base: *mut T, size_in_bytes: usize, element_count: usize) -> bool {
    let required_alignment = core::mem::align_of::<T>();
    if memory_base.is_null()
        || (memory_base as usize) % 4096 != 0
        || (memory_base as usize) % required_alignment != 0
    {
        return false;
    }

    element_count
        .checked_mul(core::mem::size_of::<T>())
        .and_then(|required_size| (size_in_bytes >= required_size).then_some(required_size))
        .and_then(|required_size| (memory_base as usize).checked_add(required_size))
        .is_some()
}

// ============================================================================
// Scheduler & TCB FFI
// ============================================================================

/// Returns the memory size required to allocate a `PerCoreScheduler`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_scheduler_sizeof() -> usize {
    core::mem::size_of::<PerCoreScheduler>()
}

/// Returns the memory alignment required to allocate a `PerCoreScheduler`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_scheduler_alignof() -> usize {
    core::mem::align_of::<PerCoreScheduler>()
}

/// Initializes a host-allocated `PerCoreScheduler`.
///
/// # Safety
/// `scheduler` must point to a valid, properly aligned, UNINITIALIZED memory region.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_scheduler_init(
    scheduler: *mut PerCoreScheduler,
) -> ShawncoreRtosErr {
    if scheduler.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(scheduler, PerCoreScheduler::new());
    }

    ShawncoreRtosErr::Success
}

/// Destroys a `PerCoreScheduler`.
///
/// # Safety
/// `scheduler` must point to a valid, initialized `PerCoreScheduler`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_scheduler_destroy(
    scheduler: *mut PerCoreScheduler,
) -> ShawncoreRtosErr {
    if scheduler.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(scheduler);
    }

    ShawncoreRtosErr::Success
}

/// Populates a `Tcb` structure.
///
/// # Safety
/// `out_tcb` must point to a valid `Tcb` struct.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_tcb_new(
    entry_point: u64,
    stack_base: u64,
    stack_size: usize,
    initial_rsp: u64,
    priority: u8,
    out_tcb: *mut Tcb,
) -> ShawncoreRtosErr {
    if out_tcb.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let tcb = Tcb::new_task(entry_point, stack_base, stack_size, initial_rsp, priority);

    unsafe {
        core::ptr::write(out_tcb, tcb);
    }

    ShawncoreRtosErr::Success
}

/// Retrieves the current stack pointer from a `Tcb`.
///
/// # Safety
/// `tcb` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_tcb_get_rsp(tcb: *const Tcb) -> u64 {
    if tcb.is_null() {
        return 0;
    }

    let tcb_ref = unsafe { &*tcb };
    compiler_fence(Ordering::SeqCst);
    tcb_ref.rsp
}

/// Updates the stack pointer in a `Tcb` after a context switch.
///
/// # Safety
/// `tcb` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_tcb_set_rsp(tcb: *mut Tcb, rsp: u64) -> ShawncoreRtosErr {
    if tcb.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let tcb_ref = unsafe { &mut *tcb };
    tcb_ref.rsp = rsp;

    compiler_fence(Ordering::SeqCst);
    ShawncoreRtosErr::Success
}

/// Registers a task with the scheduler.
///
/// # Safety
/// `scheduler` and `tcb` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_scheduler_create_task(
    scheduler: *mut PerCoreScheduler,
    tcb: *const Tcb,
    canary_value: u64,
) -> ShawncoreRtosErr {
    if scheduler.is_null() || tcb.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let scheduler_ref = unsafe { &mut *scheduler };
    let tcb_val = unsafe { *tcb };

    match scheduler_ref.create_task(tcb_val, canary_value) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(_) => ShawncoreRtosErr::TaskFault,
    }
}

/// Executes a scheduling tick, returning the stack pointer of the next task to run.
///
/// # Safety
/// `scheduler` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_scheduler_tick(
    scheduler: *mut PerCoreScheduler,
    current_rsp: u64,
) -> u64 {
    if scheduler.is_null() {
        return current_rsp; // Fallback to current if invalid
    }

    let scheduler_ref = unsafe { &mut *scheduler };
    scheduler_ref.schedule_tick(current_rsp)
}

/// Records a critical task check-in for the current watchdog window.
///
/// # Safety
/// `scheduler` must be a valid, non-null pointer to an initialized scheduler.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_scheduler_task_check_in(
    scheduler: *mut PerCoreScheduler,
    priority: u8,
) -> ShawncoreRtosErr {
    if scheduler.is_null() || priority >= 16 {
        return ShawncoreRtosErr::InvalidMemory;
    }
    unsafe { (*scheduler).task_check_in(priority) };
    ShawncoreRtosErr::Success
}

// ============================================================================
// DMA Pool FFI
// ============================================================================

/// Returns the memory size required to allocate a `DmaPool2K`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_dmapool2k_sizeof() -> usize {
    core::mem::size_of::<DmaPool2K>()
}

/// Returns the memory alignment required to allocate a `DmaPool2K`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_dmapool2k_alignof() -> usize {
    core::mem::align_of::<DmaPool2K>()
}

/// Initializes a host-allocated `DmaPool2K` and binds it to a host-provided DMA memory region.
///
/// # Safety
/// `pool` must point to a valid, uninitialized `DmaPool2K`. `memory_base` must point to a page-aligned
/// region of at least `256 * 2048` bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_dmapool2k_init(
    pool: *mut DmaPool2K,
    memory_base: *mut u8,
    size_in_bytes: usize,
) -> ShawncoreRtosErr {
    if pool.is_null() || !valid_dma_region(memory_base, size_in_bytes, 256) {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(pool, DmaPool2K::new());
    }

    let pool_ref = unsafe { &mut *pool };
    let typed_base = memory_base as *mut [u8; 2048];

    match pool_ref.init(typed_base, size_in_bytes) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(e) => e.into(),
    }
}

/// Destroys a `DmaPool2K`.
///
/// # Safety
/// `pool` must point to a valid, initialized `DmaPool2K`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_dmapool2k_destroy(
    pool: *mut DmaPool2K,
) -> ShawncoreRtosErr {
    if pool.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(pool);
    }

    ShawncoreRtosErr::Success
}

/// Allocates a buffer from the DMA pool.
///
/// # Safety
/// `pool`, `out_idx`, `out_generation`, and `out_ptr` must be valid, non-null pointers.
/// The returned generation must be supplied unchanged when freeing the returned index.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_dmapool2k_allocate(
    pool: *const DmaPool2K,
    out_idx: *mut usize,
    out_generation: *mut u64,
    out_ptr: *mut *mut u8,
) -> ShawncoreRtosErr {
    if pool.is_null() || out_idx.is_null() || out_generation.is_null() || out_ptr.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let pool_ref = unsafe { &*pool };

    match pool_ref.allocate() {
        Ok((idx, generation, buf_ptr)) => {
            unsafe {
                core::ptr::write(out_idx, idx);
                core::ptr::write(out_generation, generation);
                core::ptr::write(out_ptr, buf_ptr.as_ptr().cast::<u8>());
            }
            ShawncoreRtosErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Frees a buffer back to the DMA pool.
///
/// # Safety
/// `pool` must be a valid, non-null pointer. `generation` must be the token returned
/// by the matching allocation and must not be reused after a successful free.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_dmapool2k_free(
    pool: *const DmaPool2K,
    buffer_idx: usize,
    generation: u64,
) -> ShawncoreRtosErr {
    if pool.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let pool_ref = unsafe { &*pool };

    match pool_ref.free(buffer_idx, generation) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(e) => e.into(),
    }
}

// ============================================================================
// SPSC Telemetry Queue FFI
// ============================================================================

/// Returns the memory size required to allocate a `SpscQueueTelemetry`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_spsc_telemetry_sizeof() -> usize {
    core::mem::size_of::<SpscQueueTelemetry>()
}

/// Returns the memory alignment required to allocate a `SpscQueueTelemetry`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_spsc_telemetry_alignof() -> usize {
    core::mem::align_of::<SpscQueueTelemetry>()
}

/// Initializes a host-allocated `SpscQueueTelemetry` and binds it to a host-provided memory region.
///
/// # Safety
/// `queue` must point to valid, properly aligned storage that has not previously
/// been initialized. `memory_base` must point to a page-aligned region of at
/// least `64 * sizeof(SpscQueueTelemetrySlot)` bytes. Initialization is one-shot;
/// stop all producers and consumers before destroying the queue and reusing its storage.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_telemetry_init(
    queue: *mut SpscQueueTelemetry,
    memory_base: *mut SpscQueueTelemetrySlot,
    size_in_bytes: usize,
) -> ShawncoreRtosErr {
    if queue.is_null() || !valid_dma_region(memory_base, size_in_bytes, 64) {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(queue, SpscQueueTelemetry::new());
    }

    let queue_ref = unsafe { &mut *queue };

    match unsafe { queue_ref.init(memory_base, size_in_bytes) } {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(e) => e.into(),
    }
}

/// Destroys a `SpscQueueTelemetry`.
///
/// # Safety
/// `queue` must point to a valid, initialized `SpscQueueTelemetry`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_telemetry_destroy(
    queue: *mut SpscQueueTelemetry,
) -> ShawncoreRtosErr {
    if queue.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(queue);
    }

    ShawncoreRtosErr::Success
}

/// Enqueues a telemetry event.
///
/// # Safety
/// `queue` and `event` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_telemetry_push(
    queue: *const SpscQueueTelemetry,
    event: *const TelemetryEvent,
) -> ShawncoreRtosErr {
    if queue.is_null() || event.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let queue_ref = unsafe { &*queue };
    let event_val = unsafe { *event };

    match queue_ref.push(event_val) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(error) => error.into(),
    }
}

/// Dequeues a telemetry event.
///
/// # Safety
/// `queue` and `out_event` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_telemetry_pop(
    queue: *const SpscQueueTelemetry,
    out_event: *mut TelemetryEvent,
) -> ShawncoreRtosErr {
    if queue.is_null() || out_event.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let queue_ref = unsafe { &*queue };

    if !queue_ref.is_initialized() {
        return ShawncoreRtosErr::NotInitialized;
    }

    match queue_ref.pop() {
        Some(event) => {
            unsafe {
                core::ptr::write(out_event, event);
            }
            ShawncoreRtosErr::Success
        }
        None => ShawncoreRtosErr::QueueEmpty,
    }
}

// ============================================================================
// RingBufferEwCommand FFI
// ============================================================================

/// Returns the memory size required to allocate a `RingBufferEwCommand`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_ringbuffer_ew_sizeof() -> usize {
    core::mem::size_of::<RingBufferEwCommand>()
}

/// Returns the memory alignment required to allocate a `RingBufferEwCommand`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_ringbuffer_ew_alignof() -> usize {
    core::mem::align_of::<RingBufferEwCommand>()
}

/// Initializes a host-allocated `RingBufferEwCommand`.
///
/// # Safety
/// `rb` must point to valid, properly aligned storage that has not previously
/// been initialized. Initialization is one-shot; stop all producers and
/// consumers before destroying the ring buffer and reusing its storage.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_ringbuffer_ew_init(
    rb: *mut RingBufferEwCommand,
    memory_base: *mut CacheAlignedSlot<EwCommand>,
    size_in_bytes: usize,
) -> ShawncoreRtosErr {
    if rb.is_null() || !valid_dma_region(memory_base, size_in_bytes, 1024) {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(rb, RingBufferEwCommand::new());
    }

    let rb_ref = unsafe { &mut *rb };

    match unsafe { rb_ref.init(memory_base, size_in_bytes) } {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(e) => e.into(),
    }
}

/// Destroys a `RingBufferEwCommand`.
///
/// # Safety
/// `rb` must point to a valid, initialized `RingBufferEwCommand`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_ringbuffer_ew_destroy(
    rb: *mut RingBufferEwCommand,
) -> ShawncoreRtosErr {
    if rb.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(rb);
    }

    ShawncoreRtosErr::Success
}

/// Pushes an item into the `RingBufferEwCommand`.
///
/// # Safety
/// `rb` and `item` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_ringbuffer_ew_push(
    rb: *const RingBufferEwCommand,
    item: *const EwCommand,
) -> ShawncoreRtosErr {
    if rb.is_null() || item.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let rb_ref = unsafe { &*rb };
    let item_val = unsafe { *item };

    match rb_ref.push(item_val) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(error) => error.into(),
    }
}

/// Pops an item from the `RingBufferEwCommand`.
///
/// # Safety
/// `rb` and `out_item` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_ringbuffer_ew_pop(
    rb: *const RingBufferEwCommand,
    out_item: *mut EwCommand,
) -> ShawncoreRtosErr {
    if rb.is_null() || out_item.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let rb_ref = unsafe { &*rb };

    if !rb_ref.is_initialized() {
        return ShawncoreRtosErr::NotInitialized;
    }

    match rb_ref.pop() {
        Some(item) => {
            unsafe {
                core::ptr::write(out_item, item);
            }
            ShawncoreRtosErr::Success
        }
        None => ShawncoreRtosErr::QueueEmpty,
    }
}

/// Peeks an item from the `RingBufferEwCommand`.
///
/// # Safety
/// `rb` and `out_item` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_ringbuffer_ew_peek(
    rb: *const RingBufferEwCommand,
    out_item: *mut EwCommand,
) -> ShawncoreRtosErr {
    if rb.is_null() || out_item.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let rb_ref = unsafe { &*rb };

    if !rb_ref.is_initialized() {
        return ShawncoreRtosErr::NotInitialized;
    }

    match rb_ref.peek() {
        Some(item) => {
            unsafe {
                core::ptr::write(out_item, item);
            }
            ShawncoreRtosErr::Success
        }
        None => ShawncoreRtosErr::QueueEmpty,
    }
}

// ============================================================================
// SpscQueueFft FFI
// ============================================================================

/// Returns the memory size required to allocate a `SpscQueueFft`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_spsc_fft_sizeof() -> usize {
    core::mem::size_of::<SpscQueueFft>()
}

/// Returns the memory alignment required to allocate a `SpscQueueFft`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_spsc_fft_alignof() -> usize {
    core::mem::align_of::<SpscQueueFft>()
}

/// Initializes a host-allocated `SpscQueueFft` and binds it to a host-provided memory region.
///
/// # Safety
/// `queue` must point to valid, properly aligned storage that has not previously
/// been initialized. `memory_base` must point to a page-aligned region of at
/// least `256 * sizeof(SpscQueueFftSlot)` bytes. Initialization is one-shot;
/// stop all producers and consumers before destroying the queue and reusing its storage.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_fft_init(
    queue: *mut SpscQueueFft,
    memory_base: *mut SpscQueueFftSlot,
    size_in_bytes: usize,
) -> ShawncoreRtosErr {
    if queue.is_null() || !valid_dma_region(memory_base, size_in_bytes, 256) {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(queue, SpscQueueFft::new());
    }

    let queue_ref = unsafe { &mut *queue };

    match unsafe { queue_ref.init(memory_base, size_in_bytes) } {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(e) => e.into(),
    }
}

/// Destroys a `SpscQueueFft`.
///
/// # Safety
/// `queue` must point to a valid, initialized `SpscQueueFft`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_fft_destroy(
    queue: *mut SpscQueueFft,
) -> ShawncoreRtosErr {
    if queue.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(queue);
    }

    ShawncoreRtosErr::Success
}

/// Pushes an item into the `SpscQueueFft`.
///
/// # Safety
/// `queue` and `item` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_fft_push(
    queue: *const SpscQueueFft,
    item: *const FftResult,
) -> ShawncoreRtosErr {
    if queue.is_null() || item.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let queue_ref = unsafe { &*queue };
    let item_val = unsafe { *item };

    match queue_ref.push(item_val) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(error) => error.into(),
    }
}

/// Pops an item from the `SpscQueueFft`.
///
/// # Safety
/// `queue` and `out_item` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_spsc_fft_pop(
    queue: *const SpscQueueFft,
    out_item: *mut FftResult,
) -> ShawncoreRtosErr {
    if queue.is_null() || out_item.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let queue_ref = unsafe { &*queue };

    if !queue_ref.is_initialized() {
        return ShawncoreRtosErr::NotInitialized;
    }

    match queue_ref.pop() {
        Some(item) => {
            unsafe {
                core::ptr::write(out_item, item);
            }
            ShawncoreRtosErr::Success
        }
        None => ShawncoreRtosErr::QueueEmpty,
    }
}

// ============================================================================
// State Machine FFI
// ============================================================================

/// Returns the memory size required to allocate a `StateMachine`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_state_machine_sizeof() -> usize {
    core::mem::size_of::<StateMachine>()
}

/// Returns the memory alignment required to allocate a `StateMachine`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_state_machine_alignof() -> usize {
    core::mem::align_of::<StateMachine>()
}

/// Initializes a host-allocated `StateMachine`.
///
/// # Safety
/// `machine` must point to a valid, uninitialized `StateMachine`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_state_machine_init(
    machine: *mut StateMachine,
) -> ShawncoreRtosErr {
    if machine.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(machine, StateMachine::new());
    }

    ShawncoreRtosErr::Success
}

/// Destroys a `StateMachine`.
///
/// # Safety
/// `machine` must point to a valid, initialized `StateMachine`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_state_machine_destroy(
    machine: *mut StateMachine,
) -> ShawncoreRtosErr {
    if machine.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(machine);
    }

    ShawncoreRtosErr::Success
}

/// Attempts to advance the state machine.
///
/// # Safety
/// `machine` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_state_machine_try_advance(
    machine: *const StateMachine,
    target_state: u8,
) -> ShawncoreRtosErr {
    if machine.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let target = match target_state {
        0 => EnclaveState::Init,
        1 => EnclaveState::Bootstrapping,
        2 => EnclaveState::Operational,
        3 => EnclaveState::Degraded,
        4 => EnclaveState::Terminal,
        _ => return ShawncoreRtosErr::InvalidState,
    };

    let machine_ref = unsafe { &*machine };

    match machine_ref.try_advance(target) {
        Ok(_) => ShawncoreRtosErr::Success,
        Err(_) => ShawncoreRtosErr::InvalidState,
    }
}

// ============================================================================
// Latency Tracker FFI
// ============================================================================

/// Returns the memory size required to allocate a `LatencyTracker`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_latency_tracker_sizeof() -> usize {
    core::mem::size_of::<LatencyTracker>()
}

/// Returns the memory alignment required to allocate a `LatencyTracker`.
#[no_mangle]
pub extern "C" fn shawncore_rtos_latency_tracker_alignof() -> usize {
    core::mem::align_of::<LatencyTracker>()
}

/// Initializes a host-allocated `LatencyTracker`.
///
/// # Safety
/// `tracker` must point to a valid, uninitialized `LatencyTracker`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_latency_tracker_init(
    tracker: *mut LatencyTracker,
) -> ShawncoreRtosErr {
    if tracker.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::write(tracker, LatencyTracker::new());
    }

    ShawncoreRtosErr::Success
}

/// Destroys a `LatencyTracker`.
///
/// # Safety
/// `tracker` must point to a valid, initialized `LatencyTracker`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_latency_tracker_destroy(
    tracker: *mut LatencyTracker,
) -> ShawncoreRtosErr {
    if tracker.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    unsafe {
        core::ptr::drop_in_place(tracker);
    }

    ShawncoreRtosErr::Success
}

/// Marks the start of a latency measurement.
///
/// # Safety
/// `tracker` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_latency_tracker_mark_start(
    tracker: *const LatencyTracker,
    current_timestamp: u64,
) -> ShawncoreRtosErr {
    if tracker.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let tracker_ref = unsafe { &*tracker };
    tracker_ref.mark_start(current_timestamp);

    ShawncoreRtosErr::Success
}

/// Marks the end of a latency measurement.
///
/// # Safety
/// `tracker` must be a valid, non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn shawncore_rtos_latency_tracker_mark_end(
    tracker: *const LatencyTracker,
    current_timestamp: u64,
) -> ShawncoreRtosErr {
    if tracker.is_null() {
        return ShawncoreRtosErr::InvalidMemory;
    }

    let tracker_ref = unsafe { &*tracker };
    tracker_ref.mark_end(current_timestamp);

    ShawncoreRtosErr::Success
}
