#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! ShawnCore Post-Quantum Cryptography Library
//! Hardware-agnostic CNSA 2.0 compliant cryptographic stack for MarTac USVs.
//! Designed for seamless C/C++ host OS integration via FFI.

pub mod aead_wrapper;
pub mod entropy_pool;
pub mod entropy_queue;
#[path = "Error.rs"]
pub mod error;
pub mod ffi;
pub mod ffi_callbacks;
pub mod ffi_error;
pub mod hybrid_kdf;
pub mod ml_dsa_wrapper;
pub mod ml_kem_wrapper;
pub mod session_manager;
pub mod x25519_wrapper;
#[path = "Zeroize.rs"]
pub mod zeroize;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::aead_wrapper::{aead_decrypt, aead_encrypt, hkdf_expand_sha384, AEAD_TAG_SIZE};
    use super::ffi::{
        shawncore_crypto_aead_decrypt, shawncore_crypto_aead_encrypt,
        shawncore_crypto_x25519_keygen,
    };
    use super::ffi_callbacks::shawncore_crypto_register_cache_flush;
    use super::ffi_error::ShawncoreCryptoErr;
    use super::hybrid_kdf::derive_hybrid_key;
    use super::ml_dsa_wrapper::{ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};
    use super::ml_kem_wrapper::{ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen};
    use super::session_manager::SessionManager;
    use super::x25519_wrapper::{x25519_diffie_hellman, x25519_keygen};

    extern "C" fn test_cache_flush(_: *const u8, _: usize) {}

    fn install_test_callbacks() {
        unsafe {
            shawncore_crypto_register_cache_flush(test_cache_flush);
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
        let (receiver_kem_pk, receiver_x25519_pk) = receiver.initiate_handshake(&[0x91; 96]).unwrap();
        let (ciphertext, sender_x25519_pk) = sender
            .encapsulate_for_peer(
                &receiver_kem_pk,
                &receiver_x25519_pk,
                &[0x92; 64],
                b"salt",
                b"MarTac session",
            )
            .unwrap();

        receiver
            .finalize_handshake(&sender_x25519_pk, &ciphertext, b"salt", b"MarTac session")
            .unwrap();

        let mut receiver_rx_key = [0u8; 32];
        let mut sender_rx_key = [0u8; 32];
        let mut receiver_tx_key = [0u8; 32];
        receiver.get_rx_key(&mut receiver_rx_key).unwrap();
        receiver.get_tx_key(&mut receiver_tx_key).unwrap();
        sender.get_rx_key(&mut sender_rx_key).unwrap();
        assert_eq!(receiver_rx_key, sender_rx_key);
        assert_ne!(receiver_tx_key, receiver_rx_key);
        receiver.verify_key_integrity().unwrap();
        sender.verify_key_integrity().unwrap();
    }
}
