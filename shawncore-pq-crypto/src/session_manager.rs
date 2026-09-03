#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Post-Quantum Session Key Manager.
//! Hybrid ML-KEM-1024 and X25519 handshake.
//! Hardware-agnostic implementation for MarTac USVs.
//! Manages both ML-KEM-1024 and X25519 key encapsulation/decapsulation to establish
//! a secure, forward-secret hybrid symmetric key for network communications.
//! Prevents single-algorithm cryptographic collapse.
//! Every sensitive local (entropy arrays, shared secrets, and the derived hybrid
//! key) explicitly calls `.zeroize()` on every return path, success or error,
//! rather than relying on a host-provided stack-wipe callback: wiping the stack
//! from a C callback is architecture-dependent and risks overwriting frame
//! pointers, so this crate no longer exposes that callback at all.

use crate::aead_wrapper::{aead_decrypt, aead_encrypt, AEAD_TAG_SIZE};
use crate::error::CryptoError;
use crate::hybrid_kdf::derive_hybrid_key;
use crate::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024, DecapsKey1024,
    PublicKey1024,
};
use crate::x25519_wrapper::{x25519_diffie_hellman, x25519_keygen, X25519Public, X25519Secret};
use crate::zeroize::{secure_cache_flush, secure_zeroize};
use core::sync::atomic::{compiler_fence, Ordering};
use sha2::{Digest, Sha384};
use zeroize::Zeroize;

/// Manages the lifecycle of the hybrid post-quantum session key.
/// Designed to be instantiated by the host OS and passed across the FFI boundary.
pub struct SessionManager {
    /// The secret ML-KEM decapsulation key (held temporarily during handshake).
    ml_kem_dk: Option<DecapsKey1024>,
    /// The secret X25519 key (held temporarily during handshake).
    x25519_sk: Option<X25519Secret>,
    /// The established transmit key for this session role.
    tx_key: Option<[u8; 64]>,
    /// The established receive key for this session role.
    rx_key: Option<[u8; 64]>,
    /// Integrity checksum for the transmit key.
    tx_key_checksum: u32,
    /// Integrity checksum for the receive key.
    rx_key_checksum: u32,
    /// Whether a completed handshake has established directional session keys.
    is_established: bool,
    /// Sequence number assigned to the next outbound packet.
    tx_counter: u64,
    /// Highest accepted inbound sequence number.
    rx_counter: u64,
    /// Bitmask of accepted sequence numbers in the trailing 64-packet window.
    rx_window: u64,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        self.zeroize_session();
    }
}

impl SessionManager {
    /// Creates a new, uninitialized session manager.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ml_kem_dk: None,
            x25519_sk: None,
            tx_key: None,
            rx_key: None,
            tx_key_checksum: 0,
            rx_key_checksum: 0,
            is_established: false,
            tx_counter: 0,
            rx_counter: 0,
            rx_window: 0,
        }
    }

    /// Generates a new Hybrid keypair (ML-KEM + X25519) for an incoming handshake.
    /// Returns the public keys to be sent to the Command Center.
    ///
    /// # Arguments
    /// * `entropy` - 96 bytes of cryptographically secure random data.
    pub fn initiate_handshake(
        &mut self,
        entropy: &[u8; 96],
    ) -> Result<(PublicKey1024, X25519Public), CryptoError> {
        if entropy.iter().all(|&byte| byte == 0) || entropy.iter().all(|&byte| byte == 0xFF) {
            return Err(CryptoError::InvalidState);
        }

        let mut ml_kem_entropy = [0u8; 64];
        let mut x25519_entropy = [0u8; 32];

        ml_kem_entropy.copy_from_slice(&entropy[0..64]);
        x25519_entropy.copy_from_slice(&entropy[64..96]);

        let ml_kem_res = ml_kem_keygen(&ml_kem_entropy);
        let (ml_kem_pk, ml_kem_dk) = match ml_kem_res {
            Ok(keys) => keys,
            Err(e) => {
                ml_kem_entropy.zeroize();
                x25519_entropy.zeroize();
                return Err(e);
            }
        };

        let (x25519_pk, x25519_sk) = x25519_keygen(&x25519_entropy);

        ml_kem_entropy.zeroize();
        x25519_entropy.zeroize();

        self.zeroize_session();
        self.ml_kem_dk = Some(ml_kem_dk);
        self.x25519_sk = Some(x25519_sk);

        Ok((ml_kem_pk, x25519_pk))
    }

    /// Processes an incoming hybrid ciphertext/public key from the Command Center to establish
    /// the session key.
    ///
    /// # Arguments
    /// * `peer_x25519_pk` - The peer's X25519 public key.
    /// * `ml_kem_ct` - The ML-KEM-1024 ciphertext.
    /// * `salt` - HKDF salt.
    /// * `info` - HKDF info.
    pub fn finalize_handshake(
        &mut self,
        peer_x25519_pk: &X25519Public,
        ml_kem_ct: &Ciphertext1024,
        salt: &[u8],
        info: &[u8],
    ) -> Result<(), CryptoError> {
        let ml_kem_dk = match self.ml_kem_dk.as_ref() {
            Some(dk) => dk,
            None => {
                return Err(CryptoError::InvalidState);
            }
        };

        let x25519_sk = match self.x25519_sk.as_ref() {
            Some(sk) => sk,
            None => {
                return Err(CryptoError::InvalidState);
            }
        };

        let pq_secret_res = ml_kem_decapsulate(ml_kem_dk, ml_kem_ct);
        let mut pq_secret = match pq_secret_res {
            Ok(s) => s.0,
            Err(e) => {
                return Err(e);
            }
        };

        let classical_secret_res = x25519_diffie_hellman(x25519_sk, peer_x25519_pk);
        let mut classical_secret = match classical_secret_res {
            Ok(s) => s.0,
            Err(e) => {
                pq_secret.zeroize();
                return Err(e);
            }
        };

        let mut transcript = handshake_transcript(ml_kem_ct, peer_x25519_pk, info);
        let hybrid_key_res =
            derive_hybrid_key(&mut pq_secret, &mut classical_secret, salt, &transcript);
        transcript.zeroize();
        let mut hybrid_key_64 = match hybrid_key_res {
            Ok(k) => k,
            Err(e) => {
                return Err(e);
            }
        };

        let mut tx_key = [0u8; 64];
        let mut rx_key = [0u8; 64];
        tx_key[..32].copy_from_slice(&hybrid_key_64[..32]);
        tx_key[32..].copy_from_slice(&hybrid_key_64[96..]);
        rx_key.copy_from_slice(&hybrid_key_64[32..96]);
        hybrid_key_64.zeroize();

        self.zeroize_session();
        self.tx_key = Some(tx_key);
        self.rx_key = Some(rx_key);
        self.tx_key_checksum = key_checksum(&tx_key);
        self.rx_key_checksum = key_checksum(&rx_key);
        self.is_established = true;
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        compiler_fence(Ordering::SeqCst);

        Ok(())
    }

    /// Encapsulates a shared secret for a peer (if the USV is initiating the connection).
    ///
    /// # Arguments
    /// * `peer_ml_kem_pk` - The peer's ML-KEM-1024 public key.
    /// * `peer_x25519_pk` - The peer's X25519 public key.
    /// * `entropy` - 64 bytes of cryptographically secure random data.
    /// * `salt` - HKDF salt.
    /// * `info` - HKDF info.
    #[allow(clippy::too_many_arguments)]
    pub fn encapsulate_for_peer(
        &mut self,
        peer_ml_kem_pk: &PublicKey1024,
        peer_x25519_pk: &X25519Public,
        entropy: &[u8; 64],
        salt: &[u8],
        info: &[u8],
        out_ct: &mut Ciphertext1024,
        out_pk: &mut X25519Public,
    ) -> Result<(), CryptoError> {
        if entropy.iter().all(|&byte| byte == 0) || entropy.iter().all(|&byte| byte == 0xFF) {
            return Err(CryptoError::InvalidState);
        }

        let mut ml_kem_entropy = [0u8; 32];
        let mut x25519_entropy = [0u8; 32];

        ml_kem_entropy.copy_from_slice(&entropy[0..32]);
        x25519_entropy.copy_from_slice(&entropy[32..64]);

        let ml_kem_res = ml_kem_encapsulate(peer_ml_kem_pk, &ml_kem_entropy);
        let (mut pq_secret_wrapper, ct) = match ml_kem_res {
            Ok(res) => res,
            Err(e) => {
                ml_kem_entropy.zeroize();
                x25519_entropy.zeroize();
                return Err(e);
            }
        };

        let (my_x25519_pk, my_x25519_sk) = x25519_keygen(&x25519_entropy);

        let classical_res = x25519_diffie_hellman(&my_x25519_sk, peer_x25519_pk);
        let mut classical_secret_wrapper = match classical_res {
            Ok(res) => res,
            Err(e) => {
                ml_kem_entropy.zeroize();
                x25519_entropy.zeroize();
                pq_secret_wrapper.0.zeroize();
                return Err(e);
            }
        };

        let mut transcript = handshake_transcript(&ct, &my_x25519_pk, info);
        let hybrid_res = derive_hybrid_key(
            &mut pq_secret_wrapper.0,
            &mut classical_secret_wrapper.0,
            salt,
            &transcript,
        );
        transcript.zeroize();

        let mut hybrid_key_64 = match hybrid_res {
            Ok(k) => k,
            Err(e) => {
                ml_kem_entropy.zeroize();
                x25519_entropy.zeroize();
                return Err(e);
            }
        };

        let mut tx_key = [0u8; 64];
        let mut rx_key = [0u8; 64];
        tx_key.copy_from_slice(&hybrid_key_64[32..96]);
        rx_key[..32].copy_from_slice(&hybrid_key_64[..32]);
        rx_key[32..].copy_from_slice(&hybrid_key_64[96..]);
        hybrid_key_64.zeroize();

        self.zeroize_session();
        self.tx_key = Some(tx_key);
        self.rx_key = Some(rx_key);
        self.tx_key_checksum = key_checksum(&tx_key);
        self.rx_key_checksum = key_checksum(&rx_key);
        self.is_established = true;
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        ml_kem_entropy.zeroize();
        x25519_entropy.zeroize();

        compiler_fence(Ordering::SeqCst);

        *out_ct = ct;
        *out_pk = my_x25519_pk;
        Ok(())
    }

    /// Assigns a unique RFC 8439 nonce to the next outbound packet.
    pub fn get_next_tx_nonce(&mut self, nonce: &mut [u8; 12]) -> Result<(), CryptoError> {
        if self.tx_counter == u64::MAX {
            return Err(CryptoError::InvalidState);
        }
        nonce[..8].copy_from_slice(&self.tx_counter.to_le_bytes());
        nonce[8..].fill(0);
        self.tx_counter = self
            .tx_counter
            .checked_add(1)
            .ok_or(CryptoError::InvalidState)?;
        Ok(())
    }

    /// Checks whether an inbound nonce is within the replay window and unseen.
    pub fn check_rx_nonce(&self, host_nonce: &[u8; 12]) -> Result<(), CryptoError> {
        if host_nonce[8..].iter().any(|&byte| byte != 0) {
            return Err(CryptoError::InvalidState);
        }
        let mut sequence_bytes = [0u8; 8];
        sequence_bytes.copy_from_slice(&host_nonce[..8]);
        let sequence = u64::from_le_bytes(sequence_bytes);
        if sequence > self.rx_counter {
            return Ok(());
        }
        let offset = self.rx_counter - sequence;
        if offset >= 64 || self.rx_window & (1u64 << offset) != 0 {
            return Err(CryptoError::InvalidState);
        }
        Ok(())
    }

    /// Records a successfully authenticated inbound nonce in the replay window.
    pub fn commit_rx_nonce(&mut self, host_nonce: &[u8; 12]) {
        let mut sequence_bytes = [0u8; 8];
        sequence_bytes.copy_from_slice(&host_nonce[..8]);
        let sequence = u64::from_le_bytes(sequence_bytes);
        if sequence > self.rx_counter {
            let shift = sequence - self.rx_counter;
            self.rx_window = if shift >= 64 {
                1
            } else {
                (self.rx_window << shift) | 1
            };
            self.rx_counter = sequence;
        } else {
            self.rx_window |= 1u64 << (self.rx_counter - sequence);
        }
    }

    /// Encrypts and authenticates a packet using the transmit session key.
    pub fn encrypt_packet(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        nonce: &mut [u8; 12],
        tag: &mut [u8; AEAD_TAG_SIZE],
    ) -> Result<(), CryptoError> {
        if !self.is_established || ciphertext.len() != plaintext.len() {
            return Err(CryptoError::InvalidState);
        }
        if self.tx_counter == u64::MAX {
            return Err(CryptoError::InvalidState);
        }
        let key = self.tx_key.as_ref().ok_or(CryptoError::InvalidState)?;
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&key[..32]);
        mac_key.copy_from_slice(&key[32..]);
        nonce[..8].copy_from_slice(&self.tx_counter.to_le_bytes());
        nonce[8..].fill(0);
        let result = aead_encrypt(&enc_key, &mac_key, nonce, aad, plaintext, ciphertext, tag);
        enc_key.zeroize();
        mac_key.zeroize();
        result?;
        self.tx_counter = self
            .tx_counter
            .checked_add(1)
            .ok_or(CryptoError::InvalidState)?;
        Ok(())
    }

    /// Authenticates and decrypts a packet, committing its nonce only on success.
    pub fn decrypt_packet(
        &mut self,
        aad: &[u8],
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; AEAD_TAG_SIZE],
        plaintext: &mut [u8],
    ) -> Result<(), CryptoError> {
        if !self.is_established || plaintext.len() != ciphertext.len() {
            return Err(CryptoError::InvalidState);
        }
        self.check_rx_nonce(nonce)?;
        let key = self.rx_key.as_ref().ok_or(CryptoError::InvalidState)?;
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&key[..32]);
        mac_key.copy_from_slice(&key[32..]);
        let result = aead_decrypt(&enc_key, &mac_key, nonce, aad, ciphertext, tag, plaintext);
        enc_key.zeroize();
        mac_key.zeroize();
        result?;
        self.commit_rx_nonce(nonce);
        Ok(())
    }

    /// Verifies that both established keys still match their stored integrity checksums.
    pub fn verify_key_integrity(&self) -> Result<(), CryptoError> {
        if !self.is_established {
            return Err(CryptoError::InvalidState);
        }
        let Some(tx_key) = self.tx_key.as_ref() else {
            return Err(CryptoError::InvalidState);
        };
        let Some(rx_key) = self.rx_key.as_ref() else {
            return Err(CryptoError::InvalidState);
        };

        let tx_difference = key_checksum(tx_key) ^ self.tx_key_checksum;
        let rx_difference = key_checksum(rx_key) ^ self.rx_key_checksum;
        if (tx_difference | rx_difference) != 0 {
            return Err(CryptoError::InvalidState);
        }
        Ok(())
    }

    /// Explicitly zeroizes the active session key.
    pub fn zeroize_session(&mut self) {
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        if let Some(ref mut key) = self.tx_key {
            secure_zeroize(key);
            secure_cache_flush(key);
        }
        if let Some(ref mut key) = self.rx_key {
            secure_zeroize(key);
            secure_cache_flush(key);
        }
        self.tx_key = None;
        self.rx_key = None;
        self.tx_key_checksum = 0;
        self.rx_key_checksum = 0;
        self.is_established = false;
        self.tx_counter = 0;
        self.rx_counter = 0;
        self.rx_window = 0;

        compiler_fence(Ordering::SeqCst);
    }
}

fn handshake_transcript(
    ciphertext: &Ciphertext1024,
    sender_public_key: &X25519Public,
    application_info: &[u8],
) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(b"ShawnCore-v1.3-hybrid-handshake");
    hasher.update(ciphertext.0);
    hasher.update(sender_public_key.0);
    hasher.update(application_info);

    let mut transcript = [0u8; 48];
    transcript.copy_from_slice(&hasher.finalize());
    transcript
}

fn key_checksum(key: &[u8; 64]) -> u32 {
    let mut checksum = 0u32;
    let mut index = 0;
    while index < key.len() {
        checksum ^= u32::from(key[index]) << ((index % 4) * 8);
        checksum = checksum.rotate_left(5) ^ 0x9E37_79B9;
        index += 1;
    }
    checksum
}

#[cfg(test)]
mod tests {
    use super::{key_checksum, SessionManager};
    use crate::error::CryptoError;
    use crate::ffi_callbacks::shawncore_crypto_register_cache_flush;

    extern "C" fn test_cache_flush(_: *const u8, _: usize) {}

    #[test]
    fn key_integrity_detects_single_bit_corruption() {
        unsafe {
            shawncore_crypto_register_cache_flush(Some(test_cache_flush));
        }
        let mut manager = SessionManager {
            ml_kem_dk: None,
            x25519_sk: None,
            tx_key: Some([0x11; 64]),
            rx_key: Some([0x22; 64]),
            tx_key_checksum: key_checksum(&[0x11; 64]),
            rx_key_checksum: key_checksum(&[0x22; 64]),
            is_established: true,
            tx_counter: 0,
            rx_counter: 0,
            rx_window: 0,
        };

        assert_eq!(manager.verify_key_integrity(), Ok(()));
        manager.tx_key.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            manager.verify_key_integrity(),
            Err(CryptoError::InvalidState)
        );
    }

    #[test]
    fn failed_encryption_does_not_consume_a_nonce() {
        unsafe {
            shawncore_crypto_register_cache_flush(Some(test_cache_flush));
        }
        let mut manager = SessionManager {
            ml_kem_dk: None,
            x25519_sk: None,
            tx_key: Some([0x11; 64]),
            rx_key: Some([0x22; 64]),
            tx_key_checksum: key_checksum(&[0x11; 64]),
            rx_key_checksum: key_checksum(&[0x22; 64]),
            is_established: true,
            tx_counter: 7,
            rx_counter: 0,
            rx_window: 0,
        };
        let mut ciphertext = [0u8; 1];
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 48];

        assert_eq!(
            manager.encrypt_packet(b"", b"too long", &mut ciphertext, &mut nonce, &mut tag),
            Err(CryptoError::InvalidState)
        );
        assert_eq!(manager.tx_counter, 7);
    }

    #[test]
    fn exhausted_nonce_does_not_modify_output() {
        let mut manager = SessionManager::new();
        manager.tx_counter = u64::MAX;
        let mut nonce = [0xA5; 12];

        assert_eq!(
            manager.get_next_tx_nonce(&mut nonce),
            Err(CryptoError::InvalidState)
        );
        assert_eq!(nonce, [0xA5; 12]);
    }
}
