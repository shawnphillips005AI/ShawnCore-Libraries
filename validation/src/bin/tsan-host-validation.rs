// shawncore-tsan-standalone-v1
// Standalone host executable for ThreadSanitizer validation.
// There is intentionally no #[test] harness: this process directly exercises the
// concurrent ShawnCore queue implementations so sanitizer reports are attributable
// to the validation code/library rather than libtest's internal event channel.

use shawncore_rtos_sync::ffi_callbacks::{
    shawncore_rtos_register_cache_flush, shawncore_rtos_register_cache_invalidate,
};
use shawncore_rtos_sync::ring_buffer::RingBuffer;
use shawncore_rtos_sync::spsc_queue::{CacheAlignedSlot as SpscSlot, SpscQueue};
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::thread;

const QUEUE_CAPACITY: usize = 64;
const TRANSFERS_PER_ROUND: u32 = 100_000;
const ROUNDS: usize = 3;

extern "C" fn cache_callback(_: *const u8, _: usize) {}

fn install_cache_callbacks() {
    unsafe {
        shawncore_rtos_register_cache_flush(Some(cache_callback));
        shawncore_rtos_register_cache_invalidate(Some(cache_callback));
    }
}

#[repr(C, align(4096))]
struct SlotStorage<const N: usize>(MaybeUninit<[SpscSlot<u32>; N]>);

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

fn main() {
    install_cache_callbacks();

    println!("[+] standalone TSan workload: {ROUNDS} rounds x {TRANSFERS_PER_ROUND} transfers");

    for round in 0..ROUNDS {
        run_spsc_round(round);
        run_ring_round(round);
    }

    println!("[+] SPSC and ring-buffer stress workload completed");
}
