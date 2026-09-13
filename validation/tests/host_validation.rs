// # shawncore-host-validation-tests-v2
// Host-side value-add validation for ShawnCore RTOS synchronization primitives.
// Deterministic pseudo-random traces are used so failures are reproducible without a
// host-only property-testing dependency in the production RTOS crate.

use shawncore_rtos_sync::error::{AllocatorError, IpcError};
use shawncore_rtos_sync::ffi_callbacks::{
    shawncore_rtos_register_cache_flush, shawncore_rtos_register_cache_invalidate,
};
use shawncore_rtos_sync::ring_buffer::RingBuffer;
use shawncore_rtos_sync::spsc_queue::{CacheAlignedSlot as SpscSlot, SpscQueue};
use shawncore_rtos_sync::static_dma_pool::StaticDmaPool;
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::thread;

const TRACE_SEEDS: [u64; 8] = [
    0x0000_0000_0000_0001,
    0x9E37_79B9_7F4A_7C15,
    0xD1B5_4A32_D192_ED03,
    0xA409_3822_299F_31D0,
    0x082E_FA98_EC4E_6C89,
    0x4528_21E6_38D0_1377,
    0xBE54_66CF_34E9_0C6C,
    0xC0AC_29B7_C97C_50DD,
];

const TRACE_LENGTH: usize = 2_000;
const DMA_TRACE_LENGTH: usize = 4_000;

extern "C" fn test_cache_callback(_: *const u8, _: usize) {}

fn install_cache_callbacks() {
    unsafe {
        shawncore_rtos_register_cache_flush(Some(test_cache_callback));
        shawncore_rtos_register_cache_invalidate(Some(test_cache_callback));
    }
}

#[repr(C, align(4096))]
struct SpscStorage<const N: usize>(MaybeUninit<[SpscSlot<u32>; N]>);

#[repr(C, align(4096))]
struct RingStorage<const N: usize>(MaybeUninit<[SpscSlot<u32>; N]>);

#[repr(C, align(4096))]
struct DmaStorage<const N: usize>(MaybeUninit<[u32; N]>);

#[derive(Clone, Copy, Debug)]
enum QueueOp {
    Push(u32),
    Pop,
}

#[derive(Clone, Copy, Debug)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        assert_ne!(seed, 0);
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        assert!(upper_exclusive > 0);
        (self.next_u64() as usize) % upper_exclusive
    }

    fn next_queue_op(&mut self) -> QueueOp {
        if self.next_u64() & 1 == 0 {
            QueueOp::Push(self.next_u32())
        } else {
            QueueOp::Pop
        }
    }
}

fn generated_trace(seed: u64, len: usize) -> Vec<QueueOp> {
    let mut rng = DeterministicRng::new(seed);
    (0..len).map(|_| rng.next_queue_op()).collect()
}

fn spsc_trace(seed: u64) {
    install_cache_callbacks();
    const N: usize = 8;
    let queue = SpscQueue::<u32, N>::new();
    let mut storage = SpscStorage::<N>(MaybeUninit::uninit());
    let ptr = storage.0.as_mut_ptr().cast::<SpscSlot<u32>>();
    let bytes = core::mem::size_of::<[SpscSlot<u32>; N]>();
    unsafe { queue.init(ptr, bytes) }.unwrap();

    let mut model = VecDeque::<u32>::new();
    for (step, op) in generated_trace(seed, TRACE_LENGTH).into_iter().enumerate() {
        match op {
            QueueOp::Push(value) => {
                let actual = unsafe { queue.push(value) };
                let expected = if model.len() == N {
                    Err(IpcError::QueueFull)
                } else {
                    model.push_back(value);
                    Ok(())
                };
                assert_eq!(actual, expected, "SPSC seed={seed:#018x}, step={step}");
            }
            QueueOp::Pop => {
                let actual = unsafe { queue.pop() };
                let expected = model.pop_front();
                assert_eq!(actual, expected, "SPSC seed={seed:#018x}, step={step}");
            }
        }
    }
    assert_eq!(
        unsafe { queue.pop() },
        model.pop_front(),
        "SPSC seed={seed:#018x}, final drain"
    );
}

fn ring_trace(seed: u64) {
    install_cache_callbacks();
    const N: usize = 8;
    let ring = RingBuffer::<u32, N>::new();
    let mut storage = RingStorage::<N>(MaybeUninit::uninit());
    let ptr = storage.0.as_mut_ptr().cast::<SpscSlot<u32>>();
    let bytes = core::mem::size_of::<[SpscSlot<u32>; N]>();
    unsafe { ring.init(ptr, bytes) }.unwrap();

    let mut model = VecDeque::<u32>::new();
    for (step, op) in generated_trace(seed, TRACE_LENGTH).into_iter().enumerate() {
        match op {
            QueueOp::Push(value) => {
                let actual = unsafe { ring.push(value) };
                let expected = if model.len() == N {
                    Err(IpcError::QueueFull)
                } else {
                    model.push_back(value);
                    Ok(())
                };
                assert_eq!(actual, expected, "Ring seed={seed:#018x}, step={step}");
            }
            QueueOp::Pop => {
                let actual = unsafe { ring.pop() };
                let expected = model.pop_front();
                assert_eq!(actual, expected, "Ring seed={seed:#018x}, step={step}");
            }
        }
    }
    assert_eq!(
        unsafe { ring.pop() },
        model.pop_front(),
        "Ring seed={seed:#018x}, final drain"
    );
}

fn dma_trace(seed: u64) {
    install_cache_callbacks();
    const N: usize = 4;
    let pool = StaticDmaPool::<u32, N, 1>::new();
    let mut storage = DmaStorage::<N>(MaybeUninit::uninit());
    let ptr = storage.0.as_mut_ptr().cast::<u32>();
    let bytes = core::mem::size_of::<[u32; N]>();
    unsafe { pool.init(ptr, bytes) }.unwrap();

    let mut live: [Option<(usize, u64)>; N] = [None; N];
    let mut rng = DeterministicRng::new(seed);
    for step in 0..DMA_TRACE_LENGTH {
        let slot_hint = rng.next_usize(N);
        match live[slot_hint] {
            Some((index, generation)) => {
                assert_eq!(
                    pool.free(index, generation),
                    Ok(()),
                    "DMA seed={seed:#018x}, step={step}"
                );
                live[slot_hint] = None;
            }
            None => match pool.allocate() {
                Ok((index, generation, _pointer)) => {
                    assert!(index < N);
                    assert!(live
                        .iter()
                        .all(|entry| entry.map_or(true, |(i, _)| i != index)));
                    live[slot_hint] = Some((index, generation));
                }
                Err(AllocatorError::OutOfMemory) => {
                    assert!(live.iter().all(Option::is_some));
                }
                Err(other) => panic!(
                    "unexpected DMA allocation error {other:?}: seed={seed:#018x}, step={step}"
                ),
            },
        }
    }

    for entry in live.into_iter().flatten() {
        assert_eq!(pool.free(entry.0, entry.1), Ok(()));
    }
    let (index, generation, _) = pool.allocate().unwrap();
    assert_eq!(pool.free(index, generation), Ok(()));
}

#[test]
fn deterministic_spsc_traces_match_reference() {
    for seed in TRACE_SEEDS {
        spsc_trace(seed);
    }
}

#[test]
fn deterministic_ring_traces_match_reference() {
    for seed in TRACE_SEEDS {
        ring_trace(seed);
    }
}

#[test]
fn deterministic_dma_traces_preserve_ownership() {
    for seed in TRACE_SEEDS {
        dma_trace(seed ^ 0xA5A5_A5A5_A5A5_A5A5);
    }
}

#[test]
fn host_spsc_threads_move_all_values_without_loss() {
    install_cache_callbacks();
    const N: usize = 64;
    const COUNT: u32 = 50_000;

    let queue = Arc::new(SpscQueue::<u32, N>::new());
    let mut storage = Box::new(SpscStorage::<N>(MaybeUninit::uninit()));
    let ptr = storage.0.as_mut_ptr().cast::<SpscSlot<u32>>();
    let bytes = core::mem::size_of::<[SpscSlot<u32>; N]>();
    unsafe { queue.init(ptr, bytes) }.unwrap();

    let producer_q = Arc::clone(&queue);
    let producer = thread::spawn(move || {
        for value in 0..COUNT {
            loop {
                if unsafe { producer_q.push(value) }.is_ok() {
                    break;
                }
                thread::yield_now();
            }
        }
    });

    let consumer_q = Arc::clone(&queue);
    let consumer = thread::spawn(move || {
        let mut next = 0u32;
        while next < COUNT {
            match unsafe { consumer_q.pop() } {
                Some(value) => {
                    assert_eq!(value, next);
                    next += 1;
                }
                None => thread::yield_now(),
            }
        }
        next
    });

    producer.join().unwrap();
    assert_eq!(consumer.join().unwrap(), COUNT);
}

#[test]
fn host_ring_threads_move_all_values_without_loss() {
    install_cache_callbacks();
    const N: usize = 64;
    const COUNT: u32 = 50_000;

    let ring = Arc::new(RingBuffer::<u32, N>::new());
    let mut storage = Box::new(RingStorage::<N>(MaybeUninit::uninit()));
    let ptr = storage.0.as_mut_ptr().cast::<SpscSlot<u32>>();
    let bytes = core::mem::size_of::<[SpscSlot<u32>; N]>();
    unsafe { ring.init(ptr, bytes) }.unwrap();

    let producer_ring = Arc::clone(&ring);
    let producer = thread::spawn(move || {
        for value in 0..COUNT {
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
        let mut next = 0u32;
        while next < COUNT {
            match unsafe { consumer_ring.pop() } {
                Some(value) => {
                    assert_eq!(value, next);
                    next += 1;
                }
                None => thread::yield_now(),
            }
        }
        next
    });

    producer.join().unwrap();
    assert_eq!(consumer.join().unwrap(), COUNT);
}
