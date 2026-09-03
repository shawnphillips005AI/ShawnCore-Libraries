#![no_main]

use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{AtomicUsize, Ordering};
use libfuzzer_sys::fuzz_target;
use shawncore_rtos_sync::error::{AllocatorError, IpcError};
use shawncore_rtos_sync::ffi_callbacks::{
    shawncore_rtos_register_cache_flush, shawncore_rtos_register_cache_invalidate,
};
use shawncore_rtos_sync::ring_buffer::RingBuffer;
use shawncore_rtos_sync::spsc_queue::{CacheAlignedSlot, SpscQueue};
use shawncore_rtos_sync::state_machine::{EnclaveState, StateMachine};
use shawncore_rtos_sync::static_dma_pool::StaticDmaPool;
use std::collections::VecDeque;

const CAPACITY: usize = 8;
type TestPool = StaticDmaPool<[u8; 16], CAPACITY, 1>;
type TestQueue = SpscQueue<u32, CAPACITY>;
type TestRing = RingBuffer<u32, CAPACITY>;

static FLUSH_A_COUNT: AtomicUsize = AtomicUsize::new(0);
static FLUSH_B_COUNT: AtomicUsize = AtomicUsize::new(0);
static INVALIDATE_A_COUNT: AtomicUsize = AtomicUsize::new(0);
static INVALIDATE_B_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn flush_a(_: *const u8, _: usize) {
    FLUSH_A_COUNT.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn flush_b(_: *const u8, _: usize) {
    FLUSH_B_COUNT.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn invalidate_a(_: *const u8, _: usize) {
    INVALIDATE_A_COUNT.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn invalidate_b(_: *const u8, _: usize) {
    INVALIDATE_B_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[repr(align(4096))]
struct DmaBacking([MaybeUninit<[u8; 16]>; CAPACITY]);

#[repr(align(4096))]
struct QueueBacking([MaybeUninit<CacheAlignedSlot<u32>>; CAPACITY]);

fn byte_at(input: &[u8], index: usize) -> u8 {
    input
        .get(index % input.len().max(1))
        .copied()
        .unwrap_or((index as u8).wrapping_mul(29).wrapping_add(0xA7))
}

fn install_callbacks(use_b: bool) {
    unsafe {
        shawncore_rtos_register_cache_flush(Some(if use_b { flush_b } else { flush_a }));
        shawncore_rtos_register_cache_invalidate(Some(if use_b {
            invalidate_b
        } else {
            invalidate_a
        }));
    }
}

fn queue_push(queue: &TestQueue, model: &mut VecDeque<u32>, value: u32) {
    let result = unsafe { queue.push(value) };
    if model.len() == CAPACITY {
        assert_eq!(result, Err(IpcError::QueueFull));
    } else {
        assert_eq!(result, Ok(()));
        model.push_back(value);
    }
}

fn queue_pop(queue: &TestQueue, model: &mut VecDeque<u32>) {
    assert_eq!(unsafe { queue.pop() }, model.pop_front());
}

fn ring_push(ring: &TestRing, model: &mut VecDeque<u32>, value: u32) {
    let result = unsafe { ring.push(value) };
    if model.len() == CAPACITY {
        assert_eq!(result, Err(IpcError::QueueFull));
    } else {
        assert_eq!(result, Ok(()));
        model.push_back(value);
    }
}

fn ring_pop(ring: &TestRing, model: &mut VecDeque<u32>) {
    assert_eq!(unsafe { ring.pop() }, model.pop_front());
}

fn enclave_state(value: u8) -> EnclaveState {
    match value % 5 {
        0 => EnclaveState::Init,
        1 => EnclaveState::Bootstrapping,
        2 => EnclaveState::Operational,
        3 => EnclaveState::Degraded,
        _ => EnclaveState::Terminal,
    }
}

fn valid_transition(current: u8, target: u8) -> bool {
    matches!(
        (current, target),
        (0, 1) | (1, 2) | (1, 4) | (2, 3) | (2, 4) | (3, 2) | (3, 4)
    )
}

fuzz_target!(|input: &[u8]| {
    FLUSH_A_COUNT.store(0, Ordering::Relaxed);
    FLUSH_B_COUNT.store(0, Ordering::Relaxed);
    INVALIDATE_A_COUNT.store(0, Ordering::Relaxed);
    INVALIDATE_B_COUNT.store(0, Ordering::Relaxed);
    install_callbacks(false);

    let pool = TestPool::new();
    let mut pool_backing = Box::new(DmaBacking([const { MaybeUninit::uninit() }; CAPACITY]));
    assert_eq!(
        unsafe {
            pool.init(
                pool_backing.0.as_mut_ptr().cast(),
                size_of::<[[u8; 16]; CAPACITY]>(),
            )
        },
        Ok(())
    );
    assert_eq!(
        unsafe {
            pool.init(
                pool_backing.0.as_mut_ptr().cast(),
                size_of::<[[u8; 16]; CAPACITY]>(),
            )
        },
        Err(AllocatorError::AlreadyInitialized)
    );

    let queue = TestQueue::new();
    let mut queue_backing = Box::new(QueueBacking([const { MaybeUninit::uninit() }; CAPACITY]));
    assert_eq!(
        unsafe {
            queue.init(
                queue_backing.0.as_mut_ptr().cast(),
                size_of::<[CacheAlignedSlot<u32>; CAPACITY]>(),
            )
        },
        Ok(())
    );
    assert_eq!(
        unsafe {
            queue.init(
                queue_backing.0.as_mut_ptr().cast(),
                size_of::<[CacheAlignedSlot<u32>; CAPACITY]>(),
            )
        },
        Err(IpcError::AlreadyInitialized)
    );

    let ring = TestRing::new();
    let mut ring_backing = Box::new(QueueBacking([const { MaybeUninit::uninit() }; CAPACITY]));
    assert_eq!(
        unsafe {
            ring.init(
                ring_backing.0.as_mut_ptr().cast(),
                size_of::<[CacheAlignedSlot<u32>; CAPACITY]>(),
            )
        },
        Ok(())
    );
    assert_eq!(
        unsafe {
            ring.init(
                ring_backing.0.as_mut_ptr().cast(),
                size_of::<[CacheAlignedSlot<u32>; CAPACITY]>(),
            )
        },
        Err(IpcError::AlreadyInitialized)
    );

    let mut live = [None; CAPACITY];
    let mut last_generation = [0u64; CAPACITY];
    let mut queue_model = VecDeque::new();
    let mut ring_model = VecDeque::new();
    let machine = StateMachine::new();
    let mut expected_state = EnclaveState::Init as u8;

    for (step, operation) in input.iter().take(256).enumerate() {
        let selector = operation & 0x0F;
        let index = byte_at(input, step.wrapping_mul(7)) as usize % CAPACITY;
        let value = u32::from_le_bytes([
            *operation,
            byte_at(input, step.wrapping_add(1)),
            byte_at(input, step.wrapping_add(2)),
            byte_at(input, step.wrapping_add(3)),
        ]);

        match selector {
            0 | 1 => match pool.allocate() {
                Ok((slot, generation, pointer)) => {
                    assert!(live[slot].is_none());
                    unsafe { pointer.as_ptr().write([*operation; 16]) };
                    live[slot] = Some((generation, pointer.as_ptr()));
                    last_generation[slot] = generation;
                }
                Err(error) => {
                    assert_eq!(error, AllocatorError::OutOfMemory);
                    assert!(live.iter().all(Option::is_some));
                }
            },
            2 | 3 => {
                if let Some((generation, pointer)) = live[index].take() {
                    assert_eq!(pool.free(index, generation), Ok(()));
                    assert_eq!(unsafe { pointer.read() }, [0; 16]);
                } else {
                    assert_eq!(
                        pool.free(index, last_generation[index]),
                        Err(AllocatorError::DoubleFree)
                    );
                }
            }
            4 => {
                assert_eq!(
                    pool.free(CAPACITY + index, last_generation[index]),
                    Err(AllocatorError::AddressOutOfBounds)
                );
            }
            5 => queue_push(&queue, &mut queue_model, value),
            6 => queue_pop(&queue, &mut queue_model),
            7 => {
                while queue_model.len() < CAPACITY {
                    queue_push(&queue, &mut queue_model, value.wrapping_add(queue_model.len() as u32));
                }
                queue_push(&queue, &mut queue_model, value);
            }
            8 => ring_push(&ring, &mut ring_model, value),
            9 => ring_pop(&ring, &mut ring_model),
            10 => assert_eq!(unsafe { ring.peek() }, ring_model.front().copied()),
            11 => {
                while ring_model.len() < CAPACITY {
                    ring_push(&ring, &mut ring_model, value.wrapping_add(ring_model.len() as u32));
                }
                ring_push(&ring, &mut ring_model, value);
            }
            12 => {
                let target = enclave_state(byte_at(input, step.wrapping_add(11)));
                let expected_success = valid_transition(expected_state, target as u8);
                assert_eq!(machine.try_advance(target).is_ok(), expected_success);
                if expected_success {
                    expected_state = target as u8;
                }
                assert_eq!(machine.get_state(), expected_state);
            }
            13 => install_callbacks(operation & 0x10 != 0),
            _ => {
                let before_flush_a = FLUSH_A_COUNT.load(Ordering::Relaxed);
                let before_flush_b = FLUSH_B_COUNT.load(Ordering::Relaxed);
                let was_full = queue_model.len() == CAPACITY;
                queue_push(&queue, &mut queue_model, value);
                if !was_full {
                    assert!(
                        FLUSH_A_COUNT.load(Ordering::Relaxed) > before_flush_a
                            || FLUSH_B_COUNT.load(Ordering::Relaxed) > before_flush_b
                    );
                }
            }
        }
    }

    for (index, entry) in live.iter_mut().enumerate() {
        if let Some((generation, pointer)) = entry.take() {
            assert_eq!(pool.free(index, generation), Ok(()));
            assert_eq!(unsafe { pointer.read() }, [0; 16]);
        }
    }
});