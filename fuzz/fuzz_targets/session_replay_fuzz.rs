#![no_main]

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use libfuzzer_sys::fuzz_target;
use shawncore_pq_crypto::ffi::{
    shawncore_crypto_hmac_sha384, shawncore_crypto_session_manager_decrypt_packet,
    shawncore_crypto_session_manager_destroy, shawncore_crypto_session_manager_encapsulate_for_peer,
    shawncore_crypto_session_manager_encrypt_packet, shawncore_crypto_session_manager_finalize_handshake,
    shawncore_crypto_session_manager_init, shawncore_crypto_session_manager_initiate_handshake,
    shawncore_crypto_session_manager_zeroize,
};
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ffi_error::ShawncoreCryptoErr;
use shawncore_pq_crypto::ml_kem_wrapper::{Ciphertext1024, PublicKey1024};
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::X25519Public;

const MAX_AAD: usize = 32;
const MAX_DATA: usize = 96;
const MAX_PACKETS: usize = 16;
const MAX_OPERATIONS: usize = 48;

static CALLBACK_A_COUNT: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_B_COUNT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn cache_callback_a(_: *const u8, _: usize) {
    CALLBACK_A_COUNT.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn cache_callback_b(_: *const u8, _: usize) {
    CALLBACK_B_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Recipient {
    Initiator,
    Responder,
}

#[derive(Clone)]
struct Packet {
    epoch: u32,
    recipient: Recipient,
    aad: [u8; MAX_AAD],
    aad_len: usize,
    plaintext: [u8; MAX_DATA],
    data_len: usize,
    ciphertext: [u8; MAX_DATA],
    nonce: [u8; 12],
    tag: [u8; 48],
    delivered: bool,
}

struct SessionPair {
    initiator: Box<MaybeUninit<SessionManager>>,
    responder: Box<MaybeUninit<SessionManager>>,
}

impl SessionPair {
    fn new() -> Self {
        let mut initiator = Box::new_uninit();
        let mut responder = Box::new_uninit();

        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(initiator.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(responder.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );

        Self {
            initiator,
            responder,
        }
    }

    fn manager(&mut self, recipient: Recipient) -> *mut SessionManager {
        match recipient {
            Recipient::Initiator => self.initiator.as_mut_ptr(),
            Recipient::Responder => self.responder.as_mut_ptr(),
        }
    }

    fn zeroize(&mut self) {
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_zeroize(self.initiator.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_zeroize(self.responder.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
    }
}

impl Drop for SessionPair {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_destroy(self.initiator.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_destroy(self.responder.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
    }
}

fn byte_at(input: &[u8], index: usize) -> u8 {
    input
        .get(index % input.len().max(1))
        .copied()
        .unwrap_or((index as u8).wrapping_mul(37).wrapping_add(0x5A))
}

fn material<const N: usize>(input: &[u8], offset: usize, domain: u8) -> [u8; N] {
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = byte_at(input, offset.wrapping_add(index)).rotate_left((index % 8) as u32)
            ^ domain.wrapping_add(index as u8);
    }
    output[0] = domain;
    output[N - 1] = domain ^ 0xA5;
    output
}

fn exercise_callback_replacement() {
    let key = [0xA5; 32];
    let message = [0x5A; 7];
    let mut output = [0u8; 48];

    unsafe { shawncore_crypto_register_cache_flush(Some(cache_callback_a)) };
    let before_a = CALLBACK_A_COUNT.load(Ordering::Relaxed);
    assert_eq!(
        unsafe { shawncore_crypto_hmac_sha384(key.as_ptr(), message.as_ptr(), message.len(), output.as_mut_ptr()) },
        ShawncoreCryptoErr::Success
    );
    assert!(CALLBACK_A_COUNT.load(Ordering::Relaxed) > before_a);

    unsafe { shawncore_crypto_register_cache_flush(Some(cache_callback_b)) };
    let after_a = CALLBACK_A_COUNT.load(Ordering::Relaxed);
    let before_b = CALLBACK_B_COUNT.load(Ordering::Relaxed);
    assert_eq!(
        unsafe { shawncore_crypto_hmac_sha384(key.as_ptr(), message.as_ptr(), message.len(), output.as_mut_ptr()) },
        ShawncoreCryptoErr::Success
    );
    assert_eq!(CALLBACK_A_COUNT.load(Ordering::Relaxed), after_a);
    assert!(CALLBACK_B_COUNT.load(Ordering::Relaxed) > before_b);

    unsafe { shawncore_crypto_register_cache_flush(None) };
    unsafe { shawncore_crypto_register_cache_flush(Some(cache_callback_a)) };
}

fn establish(pair: &mut SessionPair, input: &[u8], offset: usize, test_failed_recovery: bool) {
    let responder_entropy = material::<96>(input, offset, 0x31);
    let initiator_entropy = material::<64>(input, offset.wrapping_add(96), 0x52);
    let salt = material::<16>(input, offset.wrapping_add(160), 0x73);
    let info = material::<16>(input, offset.wrapping_add(176), 0x94);
    let mut responder_kem = MaybeUninit::<PublicKey1024>::uninit();
    let mut responder_x25519 = MaybeUninit::<X25519Public>::uninit();
    let mut ciphertext = MaybeUninit::<Ciphertext1024>::uninit();
    let mut initiator_x25519 = MaybeUninit::<X25519Public>::uninit();

    assert_eq!(
        unsafe {
            shawncore_crypto_session_manager_initiate_handshake(
                pair.responder.as_mut_ptr(),
                responder_entropy.as_ptr(),
                responder_kem.as_mut_ptr(),
                responder_x25519.as_mut_ptr(),
            )
        },
        ShawncoreCryptoErr::Success
    );
    assert_eq!(
        unsafe {
            shawncore_crypto_session_manager_encapsulate_for_peer(
                pair.initiator.as_mut_ptr(),
                responder_kem.as_ptr(),
                responder_x25519.as_ptr(),
                initiator_entropy.as_ptr(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                ciphertext.as_mut_ptr(),
                initiator_x25519.as_mut_ptr(),
            )
        },
        ShawncoreCryptoErr::Success
    );

    if test_failed_recovery {
        let invalid_peer = X25519Public([0; 32]);
        assert_ne!(
            unsafe {
                shawncore_crypto_session_manager_finalize_handshake(
                    pair.responder.as_mut_ptr(),
                    &invalid_peer,
                    ciphertext.as_ptr(),
                    salt.as_ptr(),
                    salt.len(),
                    info.as_ptr(),
                    info.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );
    }

    assert_eq!(
        unsafe {
            shawncore_crypto_session_manager_finalize_handshake(
                pair.responder.as_mut_ptr(),
                initiator_x25519.as_ptr(),
                ciphertext.as_ptr(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
            )
        },
        ShawncoreCryptoErr::Success
    );
}

fn transmit(
    pair: &mut SessionPair,
    recipient: Recipient,
    epoch: u32,
    input: &[u8],
    offset: usize,
) -> Packet {
    let mut packet = Packet {
        epoch,
        recipient,
        aad: material::<MAX_AAD>(input, offset, 0xB5),
        aad_len: byte_at(input, offset.wrapping_add(1)) as usize % (MAX_AAD + 1),
        plaintext: material::<MAX_DATA>(input, offset.wrapping_add(2), 0xD6),
        data_len: byte_at(input, offset.wrapping_add(3)) as usize % (MAX_DATA + 1),
        ciphertext: [0; MAX_DATA],
        nonce: [0; 12],
        tag: [0; 48],
        delivered: false,
    };
    let sender = match recipient {
        Recipient::Initiator => Recipient::Responder,
        Recipient::Responder => Recipient::Initiator,
    };

    assert_eq!(
        unsafe {
            shawncore_crypto_session_manager_encrypt_packet(
                pair.manager(sender),
                packet.aad.as_ptr(),
                packet.aad_len,
                packet.plaintext.as_ptr(),
                packet.ciphertext.as_mut_ptr(),
                packet.data_len,
                packet.nonce.as_mut_ptr(),
                packet.tag.as_mut_ptr(),
            )
        },
        ShawncoreCryptoErr::Success
    );
    packet
}

fn decrypt(pair: &mut SessionPair, packet: &Packet) -> ShawncoreCryptoErr {
    let mut plaintext = [0u8; MAX_DATA];
    let result = unsafe {
        shawncore_crypto_session_manager_decrypt_packet(
            pair.manager(packet.recipient),
            packet.aad.as_ptr(),
            packet.aad_len,
            packet.ciphertext.as_ptr(),
            packet.data_len,
            packet.nonce.as_ptr(),
            packet.tag.as_ptr(),
            plaintext.as_mut_ptr(),
        )
    };
    if result == ShawncoreCryptoErr::Success {
        assert_eq!(
            &plaintext[..packet.data_len],
            &packet.plaintext[..packet.data_len]
        );
    }
    result
}

fn verify_teardown(pair: &mut SessionPair) {
    let mut ciphertext = [0u8; 1];
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; 48];
    assert_ne!(
        unsafe {
            shawncore_crypto_session_manager_encrypt_packet(
                pair.initiator.as_mut_ptr(),
                core::ptr::null(),
                0,
                ciphertext.as_ptr(),
                ciphertext.as_mut_ptr(),
                1,
                nonce.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        },
        ShawncoreCryptoErr::Success
    );
}

fuzz_target!(|input: &[u8]| {
    CALLBACK_A_COUNT.store(0, Ordering::Relaxed);
    CALLBACK_B_COUNT.store(0, Ordering::Relaxed);
    exercise_callback_replacement();

    let mut pair = SessionPair::new();
    let mut established = false;
    let mut epoch = 0u32;
    let mut packets = Vec::new();

    verify_teardown(&mut pair);

    for (step, operation) in input.iter().take(MAX_OPERATIONS).enumerate() {
        let offset = step.wrapping_mul(23);
        match operation & 0x0F {
            0 | 1 => {
                establish(&mut pair, input, offset, operation & 1 != 0);
                epoch = epoch.wrapping_add(1);
                established = true;
            }
            2 | 3 if established => {
                let recipient = if operation & 1 == 0 {
                    Recipient::Responder
                } else {
                    Recipient::Initiator
                };
                packets.push(transmit(&mut pair, recipient, epoch, input, offset));
                if packets.len() > MAX_PACKETS {
                    packets.remove(0);
                }
            }
            4 if !packets.is_empty() => {
                let index = byte_at(input, offset) as usize % packets.len();
                let packet = packets[index].clone();
                let should_succeed = established && packet.epoch == epoch && !packet.delivered;
                let result = decrypt(&mut pair, &packet);
                if should_succeed {
                    assert_eq!(result, ShawncoreCryptoErr::Success);
                    packets[index].delivered = true;
                } else {
                    assert_ne!(result, ShawncoreCryptoErr::Success);
                }
            }
            5 if !packets.is_empty() => {
                let index = byte_at(input, offset) as usize % packets.len();
                let packet = packets[index].clone();
                if established && packet.epoch == epoch && !packet.delivered {
                    assert_eq!(decrypt(&mut pair, &packet), ShawncoreCryptoErr::Success);
                    packets[index].delivered = true;
                }
                assert_ne!(decrypt(&mut pair, &packet), ShawncoreCryptoErr::Success);
            }
            6 | 7 if !packets.is_empty() => {
                let index = byte_at(input, offset) as usize % packets.len();
                let packet = packets[index].clone();
                if established && packet.epoch == epoch && !packet.delivered {
                    let mut invalid = packet.clone();
                    if operation & 1 == 0 {
                        invalid.tag[0] ^= 1;
                    } else {
                        invalid.nonce[8] = 1;
                    }
                    assert_ne!(decrypt(&mut pair, &invalid), ShawncoreCryptoErr::Success);
                    assert_eq!(decrypt(&mut pair, &packet), ShawncoreCryptoErr::Success);
                    packets[index].delivered = true;
                }
            }
            8 if !packets.is_empty() => {
                let index = byte_at(input, offset) as usize % packets.len();
                let packet = packets[index].clone();
                if established && packet.epoch == epoch && !packet.delivered {
                    let mut wrong_direction = packet.clone();
                    wrong_direction.recipient = match packet.recipient {
                        Recipient::Initiator => Recipient::Responder,
                        Recipient::Responder => Recipient::Initiator,
                    };
                    assert_ne!(decrypt(&mut pair, &wrong_direction), ShawncoreCryptoErr::Success);
                    assert_eq!(decrypt(&mut pair, &packet), ShawncoreCryptoErr::Success);
                    packets[index].delivered = true;
                }
            }
            9 | 10 => {
                pair.zeroize();
                pair.zeroize();
                established = false;
                verify_teardown(&mut pair);
            }
            11 => exercise_callback_replacement(),
            _ => verify_teardown(&mut pair),
        }
    }
});