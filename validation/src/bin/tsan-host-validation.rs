// shawncore-tsan-standalone-v1
// Standalone host executable for ThreadSanitizer validation.
// There is intentionally no #[test] harness: this process directly exercises the
// concurrent ShawnCore queue implementations so sanitizer reports are attributable
// to the validation code/library rather than libtest's internal event channel.
//
// This is a host-only workload. The workspace-wide
// `cargo check --target aarch64-unknown-none --workspace` gate type-checks this
// package for the bare-metal target as well, where host `std` is unavailable; on
// bare-metal targets the binary compiles to an inert stub.

#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
mod bare_metal {
    use core::panic::PanicInfo;

    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        loop {}
    }
}

#[cfg(not(target_os = "none"))]
use shawncore_rtos_sync::ffi_callbacks::{
    shawncore_rtos_register_cache_flush, shawncore_rtos_register_cache_invalidate,
};
#[cfg(not(target_os = "none"))]
use shawncore_rtos_sync::ring_buffer::RingBuffer;
#[cfg(not(target_os = "none"))]
use shawncore_rtos_sync::spsc_queue::{CacheAlignedSlot as SpscSlot, SpscQueue};
#[cfg(not(target_os = "none"))]
use std::mem::MaybeUninit;
#[cfg(not(target_os = "none"))]
use std::sync::Arc;
#[cfg(not(target_os = "none"))]
use std::thread;

#[cfg(not(target_os = "none"))]
const QUEUE_CAPACITY: usize = 64;
#[cfg(not(target_os = "none"))]
const TRANSFERS_PER_ROUND: u32 = 100_000;
#[cfg(not(target_os = "none"))]
const ROUNDS: usize = 3;

#[cfg(not(target_os = "none"))]
extern "C" fn cache_callback(_: *const u8, _: usize) {}

#[cfg(not(target_os = "none"))]
fn install_cache_callbacks() {
    unsafe {
        shawncore_rtos_register_cache_flush(Some(cache_callback));
        shawncore_rtos_register_cache_invalidate(Some(cache_callback));
    }
}

#[cfg(not(target_os = "none"))]
#[repr(C, align(4096))]
struct SlotStorage<const N: usize>(MaybeUninit<[SpscSlot<u32>; N]>);

#[cfg(not(target_os = "none"))]
fn run_spsc_round(round: usize) {
    let queue = Arc::new(SpscQueue::<u32, QUEUE_CAPACITY>::new());
    let mut storage = Box::new(SlotStorage::<QUEUE_CAPACITY>(MaybeUninit::uninit()));
    let ptr = storage.0.as_mut_ptr().cast::<SpscSlot<u32>>();
    let bytes = core::mem::size_of::<[SpscSlot<u32>; QUEUE_CAPACITY]>();
    unsafe { queue.init(ptr, bytes) }.expect("SPSC init failed");

    let producer_queue = Arc::clone(&queue);
    let producer = thread::spawn(move || {
        for value in 0..TRANSFERS_PER_ROUND {
            loop {
                if unsafe { producer_queue.push(value) }.is_ok() {
                    break;
                }
                thread::yield_now();
            }
        }
    });

    let consumer_queue = Arc::clone(&queue);
    let consumer = thread::spawn(move || {
        let mut expected = 0u32;
        while expected < TRANSFERS_PER_ROUND {
            match unsafe { consumer_queue.pop() } {
                Some(actual) => {
                    assert_eq!(actual, expected, "SPSC round={round}");
                    expected += 1;
                }
                None => thread::yield_now(),
            }
        }
        expected
    });

    producer.join().expect("SPSC producer panicked");
    let consumed = consumer.join().expect("SPSC consumer panicked");
    assert_eq!(consumed, TRANSFERS_PER_ROUND, "SPSC round={round}");
}

#[cfg(not(target_os = "none"))]
fn run_ring_round(round: usize) {
    let ring = Arc::new(RingBuffer::<u32, QUEUE_CAPACITY>::new());
    let mut storage = Box::new(SlotStorage::<QUEUE_CAPACITY>(MaybeUninit::uninit()));
    let ptr = storage.0.as_mut_ptr().cast::<SpscSlot<u32>>();
    let bytes = core::mem::size_of::<[SpscSlot<u32>; QUEUE_CAPACITY]>();
    unsafe { ring.init(ptr, bytes) }.expect("ring init failed");

    let producer_ring = Arc::clone(&ring);
    let producer = thread::spawn(move || {
        for value in 0..TRANSFERS_PER_ROUND {
            loop {
                if unsafe { producer_ring.push(value) }.is_ok() {
                    break;
                }
                thread::yield_now();
            }
        }
    });

    let consumer_ring = Arc::clone(&ring);
    let consumer = thread::spawn(move || {
        let mut expected = 0u32;
        while expected < TRANSFERS_PER_ROUND {
            match unsafe { consumer_ring.pop() } {
                Some(actual) => {
                    assert_eq!(actual, expected, "ring round={round}");
                    expected += 1;
                }
                None => thread::yield_now(),
            }
        }
        expected
    });

    producer.join().expect("ring producer panicked");
    let consumed = consumer.join().expect("ring consumer panicked");
    assert_eq!(consumed, TRANSFERS_PER_ROUND, "ring round={round}");
}

#[cfg(not(target_os = "none"))]
fn main() {
    install_cache_callbacks();

    println!("[+] standalone TSan workload: {ROUNDS} rounds x {TRANSFERS_PER_ROUND} transfers");

    for round in 0..ROUNDS {
        run_spsc_round(round);
        run_ring_round(round);
    }

    println!("[+] SPSC and ring-buffer stress workload completed");
}

#[cfg(target_os = "none")]
fn main() {}
