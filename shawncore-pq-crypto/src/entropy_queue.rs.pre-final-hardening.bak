#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Lock-free Single-Producer Single-Consumer (SPSC) queue for entropy ingestion.
//!
//! This CPU-shared-memory queue lets one serialized C/C++ host producer feed
//! hardware RNG bytes to one cryptographic consumer. It is not an MPSC queue and
//! does not itself establish device cache coherency.

use crate::error::CryptoError;
use crate::zeroize::secure_zeroize;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Size of a single entropy chunk in bytes (256 bits).
/// This matches the expected input size for the SHA-384 based Fortuna accumulator.
pub const ENTROPY_CHUNK_SIZE: usize = 32;

/// The maximum number of entropy chunks the queue can hold.
/// Must be a power of two for efficient modulo arithmetic.
pub const ENTROPY_QUEUE_SIZE: usize = 64;

/// A cache-line aligned atomic index to prevent false sharing between producer and consumer cores.
#[repr(C, align(64))]
pub struct CacheAlignedIndex(pub AtomicUsize);

/// A cache-line aligned slot to prevent false sharing between queue elements.
#[repr(C, align(64))]
pub struct CacheAlignedSlot {
    /// The underlying data cell containing the entropy chunk.
    pub data: UnsafeCell<[u8; ENTROPY_CHUNK_SIZE]>,
}

/// A lock-free, single-producer, single-consumer queue optimized for entropy ingestion.
///
/// The host OS acts as the single producer, pushing hardware RNG data into the queue.
/// The internal cryptographic state machine acts as the single consumer, popping data
/// to mix into the global entropy pool.
#[repr(C, align(64))]
pub struct EntropyQueue {
    /// The underlying buffer storing the entropy chunks.
    buffer: [CacheAlignedSlot; ENTROPY_QUEUE_SIZE],
    /// The atomic index representing the head (write position).
    head: CacheAlignedIndex,
    /// The atomic index representing the tail (read position).
    tail: CacheAlignedIndex,
}

// # Safety
// SPSC queue is safe to share across threads as long as there is strictly one producer and one consumer.
unsafe impl Sync for EntropyQueue {}
unsafe impl Send for EntropyQueue {}

impl Default for EntropyQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyQueue {
    /// Creates a new, empty `EntropyQueue`.
    #[must_use]
    pub const fn new() -> Self {
        const {
            assert!(
                ENTROPY_QUEUE_SIZE.is_power_of_two(),
                "Queue size must be a power of 2"
            )
        };

        Self {
            buffer: [const {
                CacheAlignedSlot {
                    data: UnsafeCell::new([0u8; ENTROPY_CHUNK_SIZE]),
                }
            }; ENTROPY_QUEUE_SIZE],
            head: CacheAlignedIndex(AtomicUsize::new(0)),
            tail: CacheAlignedIndex(AtomicUsize::new(0)),
        }
    }

    /// Pushes a single entropy chunk into the queue.
    ///
    /// Designed to be called asynchronously by the host OS via FFI.
    ///
    /// # Arguments
    /// * `item` - A 32-byte array containing hardware-generated entropy.
    ///
    /// # Returns
    /// `Ok(())` if the push was successful, or `CryptoError::InvalidState` if the queue is full.
    ///
    /// # Safety
    /// The caller must be the queue's sole producer for its full lifetime.
    pub unsafe fn push(&self, item: &[u8; ENTROPY_CHUNK_SIZE]) -> Result<(), CryptoError> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);

        if head.wrapping_sub(tail) >= ENTROPY_QUEUE_SIZE {
            return Err(CryptoError::InvalidState); // Queue full
        }

        let index = head % ENTROPY_QUEUE_SIZE;

        // # Safety
        // Spatial: `index` is masked by `ENTROPY_QUEUE_SIZE`, ensuring it is strictly within bounds.
        // Temporal: The producer has exclusive write access to the `head` index.
        // Alignment: `UnsafeCell` guarantees proper alignment.
        unsafe {
            let slot_ptr = self.buffer[index].data.get();
            core::ptr::copy_nonoverlapping(item.as_ptr(), slot_ptr as *mut u8, ENTROPY_CHUNK_SIZE);
        }

        // Release ordering publishes preceding writes under the Rust memory model.
        self.head.0.store(head.wrapping_add(1), Ordering::Release);

        Ok(())
    }

    /// Pops a single entropy chunk from the queue.
    ///
    /// Designed to be called internally by the cryptographic state machine.
    /// Automatically zeroizes the slot memory after reading to prevent lingering secrets.
    ///
    /// # Arguments
    /// * `out` - A mutable 32-byte array to store the popped entropy.
    ///
    /// # Returns
    /// `true` if an item was successfully popped, `false` if the queue was empty.
    ///
    /// # Safety
    /// The caller must be the queue's sole consumer for its full lifetime.
    pub unsafe fn pop(&self, out: &mut [u8; ENTROPY_CHUNK_SIZE]) -> bool {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);

        if head == tail {
            return false;
        }

        let index = tail % ENTROPY_QUEUE_SIZE;

        // # Safety
        // Spatial: `index` is masked by `ENTROPY_QUEUE_SIZE`, ensuring it is strictly within bounds.
        // Temporal: The consumer has exclusive read access to the `tail` index.
        // Alignment: `UnsafeCell` guarantees proper alignment.
        unsafe {
            let slot_ptr = self.buffer[index].data.get();
            core::ptr::copy_nonoverlapping(
                slot_ptr as *const u8,
                out.as_mut_ptr(),
                ENTROPY_CHUNK_SIZE,
            );

            // Dynamic memory zeroization of the popped slot
            secure_zeroize(core::slice::from_raw_parts_mut(
                slot_ptr.cast::<u8>(),
                ENTROPY_CHUNK_SIZE,
            ));
        }

        // Release ordering publishes preceding writes under the Rust memory model.
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);

        true
    }
}

#[cfg(test)]
mod tests {
    use super::{EntropyQueue, ENTROPY_QUEUE_SIZE};
    use crate::error::CryptoError;

    #[test]
    fn queue_preserves_fifo_order_reuses_slots_and_zeroizes_consumed_data() {
        let queue = EntropyQueue::new();
        for value in 0..ENTROPY_QUEUE_SIZE {
            unsafe { queue.push(&[value as u8; 32]) }.unwrap();
        }
        assert_eq!(
            unsafe { queue.push(&[0xFF; 32]) },
            Err(CryptoError::InvalidState)
        );

        let mut output = [0u8; 32];
        for value in 0..ENTROPY_QUEUE_SIZE {
            assert!(unsafe { queue.pop(&mut output) });
            assert_eq!(output, [value as u8; 32]);
        }
        assert!(!unsafe { queue.pop(&mut output) });
        assert_eq!(unsafe { *queue.buffer[0].data.get() }, [0u8; 32]);

        unsafe { queue.push(&[0xA5; 32]) }.unwrap();
        assert!(unsafe { queue.pop(&mut output) });
        assert_eq!(output, [0xA5; 32]);
    }
}
