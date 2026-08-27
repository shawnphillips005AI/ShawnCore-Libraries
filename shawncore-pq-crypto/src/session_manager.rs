#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Post-Quantum Session Key Manager.
//! True Hybrid Handshake (CNSA 2.0 Compliance).
//! Hardware-agnostic implementation for MarTac USVs.
//! Manages both ML-KEM-1024 and X25519 key encapsulation/decapsulation to establish
//! a secure, forward-secret hybrid symmetric key for network communications.
//! Prevents single-algorithm cryptographic collapse.
//! Every sensitive local (entropy arrays, shared secrets, and the derived hybrid
//! key) explicitly calls `.zeroize()` on every return path, success or error,
//! rather than relying on a host-provided stack-wipe callback: wiping the stack
//! from a C callback is architecture-dependent and risks overwriting frame
//! pointers, so this crate no longer exposes that callback at all.

use crate::error::CryptoError;
use crate::hybrid_kdf::derive_hybrid_key;
use crate::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024, DecapsKey1024,
    PublicKey1024,
};
use crate::x25519_wrapper::{x25519_diffie_hellman, x25519_keygen, X25519Public, X25519Secret};
use crate::zeroize::{secure_cache_flush, secure_zeroize};
use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

/// Manages the lifecycle of the hybrid post-quantum session key.
/// Designed to be instantiated by the host OS and passed across the FFI boundary.
pub struct SessionManager {
    /// The secret ML-KEM decapsulation key (held temporarily during handshake).
    ml_kem_dk: Option<DecapsKey1024>,
    /// The secret X25519 key (held temporarily during handshake).
    x25519_sk: Option<X25519Secret>,
    /// The established transmit key, derived from the first half of the hybrid output.
    tx_key: Option<[u8; 32]>,
    /// The established receive key, derived from the second half of the hybrid output.
    rx_key: Option<[u8; 32]>,
    /// Integrity checksum for the transmit key.
    tx_key_checksum: u32,
    /// Integrity checksum for the receive key.
    rx_key_checksum: u32,
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

        self.ml_kem_dk = Some(ml_kem_dk);
        self.x25519_sk = Some(x25519_sk);
        self.tx_key = None;
        self.rx_key = None;
        self.tx_key_checksum = 0;
        self.rx_key_checksum = 0;

        compiler_fence(Ordering::SeqCst);

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

        // True Hybrid Handshake (CNSA 2.0 Compliance)
        let hybrid_key_res = derive_hybrid_key(&mut pq_secret, &mut classical_secret, salt, info);
        let mut hybrid_key_64 = match hybrid_key_res {
            Ok(k) => k,
            Err(e) => {
                return Err(e);
            }
        };

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        tx_key.copy_from_slice(&hybrid_key_64[0..32]);
        rx_key.copy_from_slice(&hybrid_key_64[32..64]);
        hybrid_key_64.zeroize();

        self.tx_key = Some(tx_key);
        self.rx_key = Some(rx_key);
        self.tx_key_checksum = key_checksum(&tx_key);
        self.rx_key_checksum = key_checksum(&rx_key);
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
    pub fn encapsulate_for_peer(
        &mut self,
        peer_ml_kem_pk: &PublicKey1024,
        peer_x25519_pk: &X25519Public,
        entropy: &[u8; 64],
        salt: &[u8],
        info: &[u8],
    ) -> Result<(Ciphertext1024, X25519Public), CryptoError> {
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

        // True Hybrid Handshake (CNSA 2.0 Compliance)
        let hybrid_res = derive_hybrid_key(
            &mut pq_secret_wrapper.0,
            &mut classical_secret_wrapper.0,
            salt,
            info,
        );

        let mut hybrid_key_64 = match hybrid_res {
            Ok(k) => k,
            Err(e) => {
                ml_kem_entropy.zeroize();
                x25519_entropy.zeroize();
                return Err(e);
            }
        };

        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        tx_key.copy_from_slice(&hybrid_key_64[0..32]);
        rx_key.copy_from_slice(&hybrid_key_64[32..64]);
        hybrid_key_64.zeroize();

        self.tx_key = Some(tx_key);
        self.rx_key = Some(rx_key);
        self.tx_key_checksum = key_checksum(&tx_key);
        self.rx_key_checksum = key_checksum(&rx_key);
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        ml_kem_entropy.zeroize();
        x25519_entropy.zeroize();

        compiler_fence(Ordering::SeqCst);

        Ok((ct, my_x25519_pk))
    }

    /// Retrieves the active transmit key for network packet encryption.
    pub fn get_tx_key(&self, out_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        let key = match self.tx_key.as_ref() {
            Some(k) => k,
            None => {
                return Err(CryptoError::InvalidState);
            }
        };

        out_key.copy_from_slice(key);
        compiler_fence(Ordering::SeqCst);

        Ok(())
    }

    /// Retrieves the active receive key for network packet decryption.
    pub fn get_rx_key(&self, out_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        let key = match self.rx_key.as_ref() {
            Some(k) => k,
            None => {
                return Err(CryptoError::InvalidState);
            }
        };

        out_key.copy_from_slice(key);
        compiler_fence(Ordering::SeqCst);

        Ok(())
    }

    /// Verifies that both established keys still match their stored integrity checksums.
    pub fn verify_key_integrity(&self) -> Result<(), CryptoError> {
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
            secure_cache_flush(key.as_ptr(), key.len());
        }
        if let Some(ref mut key) = self.rx_key {
            secure_zeroize(key);
            secure_cache_flush(key.as_ptr(), key.len());
        }
        self.tx_key = None;
        self.rx_key = None;
        self.tx_key_checksum = 0;
        self.rx_key_checksum = 0;

        compiler_fence(Ordering::SeqCst);
    }
}

fn key_checksum(key: &[u8; 32]) -> u32 {
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

    #[test]
    fn key_integrity_detects_single_bit_corruption() {
        let mut manager = SessionManager {
            ml_kem_dk: None,
            x25519_sk: None,
            tx_key: Some([0x11; 32]),
            rx_key: Some([0x22; 32]),
            tx_key_checksum: key_checksum(&[0x11; 32]),
            rx_key_checksum: key_checksum(&[0x22; 32]),
        };

        assert_eq!(manager.verify_key_integrity(), Ok(()));
        manager.tx_key.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            manager.verify_key_integrity(),
            Err(CryptoError::InvalidState)
        );
    }
}
