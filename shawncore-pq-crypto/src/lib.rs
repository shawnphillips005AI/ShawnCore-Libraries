#![no_std]
#![deny(clippy::all)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! ShawnCore Post-Quantum Cryptography Library
//! Hardware-agnostic hybrid cryptographic building blocks for MarTac USVs.
//! Designed for seamless C/C++ host OS integration via FFI.

pub mod aead_wrapper;
pub mod entropy_pool;
pub mod entropy_queue;
pub mod error;
pub mod ffi;
pub mod ffi_callbacks;
pub mod ffi_error;
pub mod hybrid_kdf;
pub mod ml_dsa_wrapper;
pub mod ml_kem_wrapper;
pub mod session_manager;
pub mod x25519_wrapper;
pub mod zeroize;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::aead_wrapper::{
        aead_decrypt, aead_decrypt_in_place, aead_encrypt, aead_encrypt_in_place,
        hkdf_expand_sha384, AEAD_TAG_SIZE,
    };
    use super::ffi::{
        shawncore_crypto_aead_decrypt, shawncore_crypto_aead_encrypt,
        shawncore_crypto_entropy_push, shawncore_crypto_hkdf_expand_sha384,
        shawncore_crypto_hmac_sha384, shawncore_crypto_ml_dsa_sign, shawncore_crypto_ml_dsa_verify,
        shawncore_crypto_session_manager_encapsulate_for_peer,
        shawncore_crypto_session_manager_encrypt_packet,
        shawncore_crypto_session_manager_finalize_handshake,
        shawncore_crypto_session_manager_initiate_handshake, shawncore_crypto_x25519_keygen,
    };
    use super::ffi_callbacks::shawncore_crypto_register_cache_flush;
    use super::ffi_error::ShawncoreCryptoErr;
    use super::hybrid_kdf::derive_hybrid_key;
    use super::ml_dsa_wrapper::{ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};
    use super::ml_kem_wrapper::{ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen};
    use super::session_manager::SessionManager;
    use super::x25519_wrapper::{x25519_diffie_hellman, x25519_keygen, X25519Public};

    extern "C" fn test_cache_flush(_: *const u8, _: usize) {}

    fn install_test_callbacks() {
        unsafe {
            shawncore_crypto_register_cache_flush(Some(test_cache_flush));
        }
    }

    #[test]
    fn aead_round_trip_rejects_tampering() {
        install_test_callbacks();
        let enc_key = [0x11; 32];
        let mac_key = [0x22; 32];
        let nonce = [0x33; 12];
        let aad = b"shawncore-aad";
        let plaintext = b"authenticated payload";
        let mut ciphertext = [0u8; 21];
        let mut tag = [0u8; AEAD_TAG_SIZE];

        aead_encrypt(
            &enc_key,
            &mac_key,
            &nonce,
            aad,
            plaintext,
            &mut ciphertext,
            &mut tag,
        )
        .unwrap();

        let mut recovered = [0u8; 21];
        aead_decrypt(
            &enc_key,
            &mac_key,
            &nonce,
            aad,
            &ciphertext,
            &tag,
            &mut recovered,
        )
        .unwrap();
        assert_eq!(&recovered, plaintext);

        ciphertext[0] ^= 1;
        assert!(aead_decrypt(
            &enc_key,
            &mac_key,
            &nonce,
            aad,
            &ciphertext,
            &tag,
            &mut recovered,
        )
        .is_err());
        assert_eq!(recovered, [0u8; 21]);
    }

    #[test]
    fn aead_in_place_round_trip_rejects_tampering() {
        install_test_callbacks();
        let enc_key = [0x11; 32];
        let mac_key = [0x22; 32];
        let nonce = [0x33; 12];
        let aad = b"shawncore-aad";
        let original = *b"in-place payload";
        let mut buffer = original;
        let mut tag = [0u8; AEAD_TAG_SIZE];

        aead_encrypt_in_place(&enc_key, &mac_key, &nonce, aad, &mut buffer, &mut tag).unwrap();
        aead_decrypt_in_place(&enc_key, &mac_key, &nonce, aad, &mut buffer, &tag).unwrap();
        assert_eq!(buffer, original);

        tag[0] ^= 1;
        assert!(aead_decrypt_in_place(&enc_key, &mac_key, &nonce, aad, &mut buffer, &tag).is_err());
        assert_eq!(buffer, [0u8; 16]);
    }

    #[test]
    fn aead_ffi_rejects_overlapping_buffers_and_round_trips() {
        install_test_callbacks();
        let enc_key = [0x11; 32];
        let mac_key = [0x22; 32];
        let nonce = [0x33; 12];
        let aad = *b"ffi-aad";
        let plaintext = *b"ffi payload";
        let mut ciphertext = [0u8; 11];
        let mut tag = [0u8; AEAD_TAG_SIZE];

        let encrypt_result = unsafe {
            shawncore_crypto_aead_encrypt(
                enc_key.as_ptr(),
                mac_key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                ciphertext.as_mut_ptr(),
                plaintext.len(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(encrypt_result, ShawncoreCryptoErr::Success);

        let mut recovered = [0u8; 11];
        let decrypt_result = unsafe {
            shawncore_crypto_aead_decrypt(
                enc_key.as_ptr(),
                mac_key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                ciphertext.as_ptr(),
                tag.as_ptr(),
                recovered.as_mut_ptr(),
                ciphertext.len(),
            )
        };
        assert_eq!(decrypt_result, ShawncoreCryptoErr::Success);
        assert_eq!(recovered, plaintext);

        let overlap_result = unsafe {
            shawncore_crypto_aead_encrypt(
                enc_key.as_ptr(),
                mac_key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.as_ptr() as *mut u8,
                plaintext.len(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(overlap_result, ShawncoreCryptoErr::InvalidLength);
    }

    #[test]
    fn session_ffi_rejects_overlapping_output_buffers() {
        let mut manager = SessionManager::new();
        let aad = [0u8; 1];
        let plaintext = [0u8; 48];
        let mut ciphertext_and_tag = [0u8; 48];
        let mut nonce = [0u8; 12];

        let result = unsafe {
            shawncore_crypto_session_manager_encrypt_packet(
                &mut manager,
                aad.as_ptr(),
                0,
                plaintext.as_ptr(),
                ciphertext_and_tag.as_mut_ptr(),
                plaintext.len(),
                nonce.as_mut_ptr(),
                ciphertext_and_tag.as_mut_ptr(),
            )
        };

        assert_eq!(result, ShawncoreCryptoErr::InvalidLength);
    }

    #[test]
    fn session_handshake_ffi_rejects_manager_input_overlap() {
        let mut manager = SessionManager::new();
        let manager_ptr = core::ptr::addr_of_mut!(manager);
        let manager_bytes = manager_ptr.cast::<u8>();
        let mut ml_kem_pk = core::mem::MaybeUninit::uninit();
        let mut x25519_pk = core::mem::MaybeUninit::uninit();
        let mut ciphertext = core::mem::MaybeUninit::uninit();

        let initiate_result = unsafe {
            shawncore_crypto_session_manager_initiate_handshake(
                manager_ptr,
                manager_bytes,
                ml_kem_pk.as_mut_ptr(),
                x25519_pk.as_mut_ptr(),
            )
        };
        assert_eq!(initiate_result, ShawncoreCryptoErr::InvalidLength);

        let finalize_result = unsafe {
            shawncore_crypto_session_manager_finalize_handshake(
                manager_ptr,
                x25519_pk.as_ptr(),
                ciphertext.as_ptr(),
                manager_bytes,
                1,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(finalize_result, ShawncoreCryptoErr::InvalidLength);

        let encapsulate_result = unsafe {
            shawncore_crypto_session_manager_encapsulate_for_peer(
                manager_ptr,
                ml_kem_pk.as_ptr(),
                x25519_pk.as_ptr(),
                manager_bytes,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                ciphertext.as_mut_ptr(),
                x25519_pk.as_mut_ptr(),
            )
        };
        assert_eq!(encapsulate_result, ShawncoreCryptoErr::InvalidLength);
    }

    #[test]
    fn keygen_ffi_rejects_overlapping_outputs() {
        let entropy = [0x42; 32];
        let mut public_key = [0u8; core::mem::size_of::<super::x25519_wrapper::X25519Public>()];
        let result = unsafe {
            shawncore_crypto_x25519_keygen(
                entropy.as_ptr(),
                public_key.as_mut_ptr().cast(),
                public_key.as_mut_ptr().cast(),
            )
        };
        assert_eq!(result, ShawncoreCryptoErr::InvalidLength);
    }

    #[test]
    fn entropy_ffi_rejects_uniform_chunks() {
        let zero = [0u8; 32];
        let ones = [0xFF; 32];
        assert_eq!(
            unsafe { shawncore_crypto_entropy_push(zero.as_ptr()) },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(
            unsafe { shawncore_crypto_entropy_push(ones.as_ptr()) },
            ShawncoreCryptoErr::InvalidState
        );
    }

    #[test]
    fn hmac_ffi_accepts_null_for_zero_length_data() {
        install_test_callbacks();
        let key = [0x11; 32];
        let mut mac = [0u8; AEAD_TAG_SIZE];
        assert_eq!(
            unsafe {
                shawncore_crypto_hmac_sha384(key.as_ptr(), core::ptr::null(), 0, mac.as_mut_ptr())
            },
            ShawncoreCryptoErr::Success
        );
    }

    #[test]
    fn kdf_and_aead_ffi_accept_null_for_zero_length_buffers() {
        install_test_callbacks();
        let enc_key = [0x11; 32];
        let mac_key = [0x22; 32];
        let nonce = [0x33; 12];
        let mut tag = [0u8; AEAD_TAG_SIZE];
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_encrypt(
                    enc_key.as_ptr(),
                    mac_key.as_ptr(),
                    nonce.as_ptr(),
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    0,
                    tag.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_decrypt(
                    enc_key.as_ptr(),
                    mac_key.as_ptr(),
                    nonce.as_ptr(),
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    tag.as_ptr(),
                    core::ptr::null_mut(),
                    0,
                )
            },
            ShawncoreCryptoErr::Success
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    [0x44; 48].as_ptr(),
                    core::ptr::null(),
                    0,
                    core::ptr::null_mut(),
                    0,
                )
            },
            ShawncoreCryptoErr::Success
        );
    }

    #[test]
    fn ml_dsa_ffi_accepts_null_for_zero_length_message() {
        std::thread::Builder::new()
            .name("ml-dsa-empty-message-test".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                install_test_callbacks();
                let (public_key, signing_key) = ml_dsa_keygen(&[0x81; 32]).unwrap();
                let mut signature = core::mem::MaybeUninit::uninit();
                assert_eq!(
                    unsafe {
                        shawncore_crypto_ml_dsa_sign(
                            &signing_key,
                            core::ptr::null(),
                            0,
                            signature.as_mut_ptr(),
                        )
                    },
                    ShawncoreCryptoErr::Success
                );
                let signature = unsafe { signature.assume_init() };
                assert_eq!(
                    unsafe {
                        shawncore_crypto_ml_dsa_verify(
                            &public_key,
                            core::ptr::null(),
                            0,
                            &signature,
                        )
                    },
                    ShawncoreCryptoErr::Success
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn key_derivation_is_deterministic_and_wipes_inputs() {
        install_test_callbacks();
        let mut pq = [0x44; 32];
        let mut classical = [0x55; 32];
        let expected = derive_hybrid_key(&mut pq, &mut classical, b"salt", b"context").unwrap();
        assert_eq!(pq, [0u8; 32]);
        assert_eq!(classical, [0u8; 32]);

        let mut pq_again = [0x44; 32];
        let mut classical_again = [0x55; 32];
        assert_eq!(
            expected,
            derive_hybrid_key(&mut pq_again, &mut classical_again, b"salt", b"context",).unwrap()
        );

        let mut expanded = [0u8; 64];
        hkdf_expand_sha384(&[0x66; 48], b"context", &mut expanded).unwrap();
        assert_ne!(expanded, [0u8; 64]);
    }

    #[test]
    fn x25519_peers_derive_the_same_secret() {
        install_test_callbacks();
        let (alice_public, alice_secret) = x25519_keygen(&[0x61; 32]);
        let (bob_public, bob_secret) = x25519_keygen(&[0x62; 32]);
        let alice_shared = x25519_diffie_hellman(&alice_secret, &bob_public).unwrap();
        let bob_shared = x25519_diffie_hellman(&bob_secret, &alice_public).unwrap();
        assert_eq!(alice_shared.0, bob_shared.0);
    }

    #[test]
    fn x25519_rejects_all_zero_peer_key() {
        install_test_callbacks();
        let (_, secret) = x25519_keygen(&[0x61; 32]);
        assert!(x25519_diffie_hellman(&secret, &X25519Public([0u8; 32])).is_err());
    }

    #[test]
    fn ml_kem_peers_derive_the_same_secret() {
        install_test_callbacks();
        let (public_key, secret_key) = ml_kem_keygen(&[0x71; 64]).unwrap();
        let (encapsulated, ciphertext) = ml_kem_encapsulate(&public_key, &[0x72; 32]).unwrap();
        let decapsulated = ml_kem_decapsulate(&secret_key, &ciphertext).unwrap();
        assert_eq!(encapsulated.0, decapsulated.0);
    }

    #[test]
    fn ml_dsa_verifies_and_rejects_modified_messages() {
        std::thread::Builder::new()
            .name("ml-dsa-test".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                install_test_callbacks();
                let (public_key, signing_key) = ml_dsa_keygen(&[0x81; 32]).unwrap();
                let signature = ml_dsa_sign(&signing_key, b"signed message").unwrap();
                ml_dsa_verify(&public_key, b"signed message", &signature).unwrap();
                assert!(ml_dsa_verify(&public_key, b"modified message", &signature).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn hybrid_session_handshake_derives_matching_keys() {
        install_test_callbacks();
        let mut receiver = SessionManager::new();
        let mut sender = SessionManager::new();
        let (receiver_kem_pk, receiver_x25519_pk) =
            receiver.initiate_handshake(&[0x91; 96]).unwrap();
        let mut ciphertext = super::ml_kem_wrapper::Ciphertext1024([0u8; 1568]);
        let mut sender_x25519_pk = super::x25519_wrapper::X25519Public([0u8; 32]);
        sender
            .encapsulate_for_peer(
                &receiver_kem_pk,
                &receiver_x25519_pk,
                &[0x92; 64],
                b"salt",
                b"MarTac session",
                &mut ciphertext,
                &mut sender_x25519_pk,
            )
            .unwrap();

        receiver
            .finalize_handshake(&sender_x25519_pk, &ciphertext, b"salt", b"MarTac session")
            .unwrap();

        let mut nonce = [0u8; 12];
        let mut tag = [0u8; AEAD_TAG_SIZE];
        let mut ciphertext_payload = [0u8; 14];
        let mut plaintext = [0u8; 14];
        sender
            .encrypt_packet(
                b"MarTac session",
                b"telemetry data",
                &mut ciphertext_payload,
                &mut nonce,
                &mut tag,
            )
            .unwrap();
        receiver
            .decrypt_packet(
                b"MarTac session",
                &ciphertext_payload,
                &nonce,
                &tag,
                &mut plaintext,
            )
            .unwrap();
        assert_eq!(&plaintext, b"telemetry data");

        assert!(receiver
            .decrypt_packet(
                b"MarTac session",
                &ciphertext_payload,
                &nonce,
                &tag,
                &mut plaintext,
            )
            .is_err());

        sender
            .encrypt_packet(
                b"MarTac session",
                b"next packet 00",
                &mut ciphertext_payload,
                &mut nonce,
                &mut tag,
            )
            .unwrap();
        receiver
            .decrypt_packet(
                b"MarTac session",
                &ciphertext_payload,
                &nonce,
                &tag,
                &mut plaintext,
            )
            .unwrap();
        assert_eq!(&plaintext, b"next packet 00");
        receiver.verify_key_integrity().unwrap();
        sender.verify_key_integrity().unwrap();
    }

    #[test]
    fn reestablishment_resets_directional_sequence_and_replay_state() {
        install_test_callbacks();
        let mut receiver = SessionManager::new();
        let mut sender = SessionManager::new();
        let (initial_kem_pk, initial_x25519_pk) = receiver.initiate_handshake(&[0x91; 96]).unwrap();
        let mut initial_ciphertext = super::ml_kem_wrapper::Ciphertext1024([0u8; 1568]);
        let mut initial_sender_pk = super::x25519_wrapper::X25519Public([0u8; 32]);
        sender
            .encapsulate_for_peer(
                &initial_kem_pk,
                &initial_x25519_pk,
                &[0x92; 64],
                b"salt",
                b"rekey",
                &mut initial_ciphertext,
                &mut initial_sender_pk,
            )
            .unwrap();
        receiver
            .finalize_handshake(&initial_sender_pk, &initial_ciphertext, b"salt", b"rekey")
            .unwrap();

        let mut nonce = [0u8; 12];
        let mut tag = [0u8; AEAD_TAG_SIZE];
        let mut ciphertext_payload = [0u8; 9];
        let mut plaintext = [0u8; 9];
        sender
            .encrypt_packet(
                b"rekey",
                b"first key",
                &mut ciphertext_payload,
                &mut nonce,
                &mut tag,
            )
            .unwrap();
        receiver
            .decrypt_packet(b"rekey", &ciphertext_payload, &nonce, &tag, &mut plaintext)
            .unwrap();

        let (replacement_kem_pk, replacement_x25519_pk) =
            receiver.initiate_handshake(&[0x93; 96]).unwrap();
        let mut replacement_ciphertext = super::ml_kem_wrapper::Ciphertext1024([0u8; 1568]);
        let mut replacement_sender_pk = super::x25519_wrapper::X25519Public([0u8; 32]);
        sender
            .encapsulate_for_peer(
                &replacement_kem_pk,
                &replacement_x25519_pk,
                &[0x94; 64],
                b"salt",
                b"rekey",
                &mut replacement_ciphertext,
                &mut replacement_sender_pk,
            )
            .unwrap();
        receiver
            .finalize_handshake(
                &replacement_sender_pk,
                &replacement_ciphertext,
                b"salt",
                b"rekey",
            )
            .unwrap();

        sender
            .encrypt_packet(
                b"rekey",
                b"fresh key",
                &mut ciphertext_payload,
                &mut nonce,
                &mut tag,
            )
            .unwrap();
        assert_eq!(nonce, [0u8; 12]);
        receiver
            .decrypt_packet(b"rekey", &ciphertext_payload, &nonce, &tag, &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext, b"fresh key");
    }

    #[test]
    fn session_rejects_tampering_without_committing_replay_state() {
        install_test_callbacks();
        let mut receiver = SessionManager::new();
        let mut sender = SessionManager::new();
        let (receiver_kem_pk, receiver_x25519_pk) =
            receiver.initiate_handshake(&[0x91; 96]).unwrap();
        let mut handshake_ciphertext = super::ml_kem_wrapper::Ciphertext1024([0u8; 1568]);
        let mut sender_x25519_pk = super::x25519_wrapper::X25519Public([0u8; 32]);
        sender
            .encapsulate_for_peer(
                &receiver_kem_pk,
                &receiver_x25519_pk,
                &[0x92; 64],
                b"salt",
                b"replay",
                &mut handshake_ciphertext,
                &mut sender_x25519_pk,
            )
            .unwrap();
        receiver
            .finalize_handshake(&sender_x25519_pk, &handshake_ciphertext, b"salt", b"replay")
            .unwrap();

        let message = *b"first packet";
        let mut ciphertext = [0u8; 12];
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; AEAD_TAG_SIZE];
        let mut plaintext = [0u8; 12];
        sender
            .encrypt_packet(b"replay", &message, &mut ciphertext, &mut nonce, &mut tag)
            .unwrap();

        let mut modified_ciphertext = ciphertext;
        modified_ciphertext[0] ^= 1;
        assert!(receiver
            .decrypt_packet(
                b"replay",
                &modified_ciphertext,
                &nonce,
                &tag,
                &mut plaintext,
            )
            .is_err());
        receiver
            .decrypt_packet(b"replay", &ciphertext, &nonce, &tag, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, message);
        assert!(receiver
            .decrypt_packet(b"replay", &ciphertext, &nonce, &tag, &mut plaintext)
            .is_err());

        let second_message = *b"secondpacket";
        sender
            .encrypt_packet(
                b"replay",
                &second_message,
                &mut ciphertext,
                &mut nonce,
                &mut tag,
            )
            .unwrap();
        assert!(receiver
            .decrypt_packet(b"wrong", &ciphertext, &nonce, &tag, &mut plaintext)
            .is_err());
        receiver
            .decrypt_packet(b"replay", &ciphertext, &nonce, &tag, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, second_message);

        let third_message = *b"third packet";
        sender
            .encrypt_packet(
                b"replay",
                &third_message,
                &mut ciphertext,
                &mut nonce,
                &mut tag,
            )
            .unwrap();
        let mut modified_tag = tag;
        modified_tag[0] ^= 1;
        assert!(receiver
            .decrypt_packet(
                b"replay",
                &ciphertext,
                &nonce,
                &modified_tag,
                &mut plaintext,
            )
            .is_err());
        receiver
            .decrypt_packet(b"replay", &ciphertext, &nonce, &tag, &mut plaintext)
            .unwrap();
        assert_eq!(plaintext, third_message);
        assert!(SessionManager::new()
            .decrypt_packet(b"replay", &ciphertext, &nonce, &tag, &mut plaintext)
            .is_err());

        let mut reordered_receiver = SessionManager::new();
        let mut reordered_sender = SessionManager::new();
        let (reordered_kem_pk, reordered_x25519_pk) =
            reordered_receiver.initiate_handshake(&[0x93; 96]).unwrap();
        let mut reordered_handshake_ct = super::ml_kem_wrapper::Ciphertext1024([0u8; 1568]);
        let mut reordered_sender_pk = super::x25519_wrapper::X25519Public([0u8; 32]);
        reordered_sender
            .encapsulate_for_peer(
                &reordered_kem_pk,
                &reordered_x25519_pk,
                &[0x94; 64],
                b"salt",
                b"replay",
                &mut reordered_handshake_ct,
                &mut reordered_sender_pk,
            )
            .unwrap();
        reordered_receiver
            .finalize_handshake(
                &reordered_sender_pk,
                &reordered_handshake_ct,
                b"salt",
                b"replay",
            )
            .unwrap();

        let mut first_ciphertext = [0u8; 12];
        let mut first_nonce = [0u8; 12];
        let mut first_tag = [0u8; AEAD_TAG_SIZE];
        let mut second_ciphertext = [0u8; 12];
        let mut second_nonce = [0u8; 12];
        let mut second_tag = [0u8; AEAD_TAG_SIZE];
        reordered_sender
            .encrypt_packet(
                b"replay",
                &message,
                &mut first_ciphertext,
                &mut first_nonce,
                &mut first_tag,
            )
            .unwrap();
        reordered_sender
            .encrypt_packet(
                b"replay",
                &second_message,
                &mut second_ciphertext,
                &mut second_nonce,
                &mut second_tag,
            )
            .unwrap();
        reordered_receiver
            .decrypt_packet(
                b"replay",
                &second_ciphertext,
                &second_nonce,
                &second_tag,
                &mut plaintext,
            )
            .unwrap();
        reordered_receiver
            .decrypt_packet(
                b"replay",
                &first_ciphertext,
                &first_nonce,
                &first_tag,
                &mut plaintext,
            )
            .unwrap();
        assert!(reordered_receiver
            .decrypt_packet(
                b"replay",
                &first_ciphertext,
                &first_nonce,
                &first_tag,
                &mut plaintext,
            )
            .is_err());
    }
}
