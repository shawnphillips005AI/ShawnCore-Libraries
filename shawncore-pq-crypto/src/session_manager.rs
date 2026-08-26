#![no_std]
#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Post-Quantum Session Key Manager.
//! True Hybrid Handshake (CNSA 2.0 Compliance).
//! Hardware-agnostic implementation for MarTac USVs.
//! Manages both ML-KEM-1024 and X25519 key encapsulation/decapsulation to establish
//! a secure, forward-secret hybrid symmetric key for network communications.
//! Prevents single-algorithm cryptographic collapse.
//! Deep Stack Annihilation (`secure_stack_wipe`) implemented to clear
//! cryptographic remnants (scalars, polynomial vectors) immediately after every handshake.
//! Cryptographic Stack Wipe Bypass via Early Return fixed. Removed `?` operators
//! to ensure `secure_stack_wipe` is ALWAYS called before returning an error, preventing data leaks.

use crate::error::CryptoError;
use crate::hybrid_kdf::derive_hybrid_key;
use crate::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024,
    DecapsKey1024, PublicKey1024,
};
use crate::x25519_wrapper::{
    x25519_diffie_hellman, x25519_keygen, X25519Public, X25519Secret,
};
use crate::zeroize::{secure_cache_flush, secure_stack_wipe, secure_zeroize};
use core::sync::atomic::{compiler_fence, Ordering};

/// Manages the lifecycle of the hybrid post-quantum session key.
/// Designed to be instantiated by the host OS and passed across the FFI boundary.
pub struct SessionManager {
    /// The secret ML-KEM decapsulation key (held temporarily during handshake).
    ml_kem_dk: Option<DecapsKey1024>,
    /// The secret X25519 key (held temporarily during handshake).
    x25519_sk: Option<X25519Secret>,
    /// The established symmetric session key (truncated to 32 bytes for AEAD).
    session_key: Option<[u8; 32]>,
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
            session_key: None,
        }
    }

    /// Generates a new Hybrid keypair (ML-KEM + X25519) for an incoming handshake.
    /// Returns the public keys to be sent to the Command Center.
    ///
    /// # Arguments
    /// * `entropy` - 96 bytes of cryptographically secure random data.
    /// * `stack_base` - The base address of the current thread's stack, used for deep stack annihilation.
    pub fn initiate_handshake(
        &mut self,
        entropy: &[u8; 96],
        stack_base: u64,
    ) -> Result<(PublicKey1024, X25519Public), CryptoError> {
        let mut ml_kem_entropy = [0u8; 64];
        let mut x25519_entropy = [0u8; 32];

        ml_kem_entropy.copy_from_slice(&entropy[0..64]);
        x25519_entropy.copy_from_slice(&entropy[64..96]);

        let ml_kem_res = ml_kem_keygen(&ml_kem_entropy);
        let (ml_kem_pk, ml_kem_dk) = match ml_kem_res {
            Ok(keys) => keys,
            Err(e) => {
                secure_zeroize(&mut ml_kem_entropy);
                secure_zeroize(&mut x25519_entropy);
                secure_stack_wipe(stack_base);
                return Err(e);
            }
        };

        let (x25519_pk, x25519_sk) = x25519_keygen(&x25519_entropy);

        secure_zeroize(&mut ml_kem_entropy);
        secure_zeroize(&mut x25519_entropy);

        self.ml_kem_dk = Some(ml_kem_dk);
        self.x25519_sk = Some(x25519_sk);
        self.session_key = None; // Invalidate any old session

        // Deep Stack Annihilation
        // Wipes the stack frame of the complex polynomial and scalar multiplication
        // structures allocated inside the third-party Dalek/ML-KEM dependencies.
        secure_stack_wipe(stack_base);

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
    /// * `stack_base` - The base address of the current thread's stack, used for deep stack annihilation.
    pub fn finalize_handshake(
        &mut self,
        peer_x25519_pk: &X25519Public,
        ml_kem_ct: &Ciphertext1024,
        salt: &[u8],
        info: &[u8],
        stack_base: u64,
    ) -> Result<(), CryptoError> {
        let ml_kem_dk = match self.ml_kem_dk.as_ref() {
            Some(dk) => dk,
            None => {
                secure_stack_wipe(stack_base);
                return Err(CryptoError::InvalidState);
            }
        };

        let x25519_sk = match self.x25519_sk.as_ref() {
            Some(sk) => sk,
            None => {
                secure_stack_wipe(stack_base);
                return Err(CryptoError::InvalidState);
            }
        };

        let pq_secret_res = ml_kem_decapsulate(ml_kem_dk, ml_kem_ct);
        let mut pq_secret = match pq_secret_res {
            Ok(s) => s.0,
            Err(e) => {
                secure_stack_wipe(stack_base);
                return Err(e);
            }
        };

        let classical_secret_res = x25519_diffie_hellman(x25519_sk, peer_x25519_pk);
        let mut classical_secret = match classical_secret_res {
            Ok(s) => s.0,
            Err(e) => {
                secure_zeroize(&mut pq_secret);
                secure_stack_wipe(stack_base);
                return Err(e);
            }
        };

        // True Hybrid Handshake (CNSA 2.0 Compliance)
        let hybrid_key_res = derive_hybrid_key(&mut pq_secret, &mut classical_secret, salt, info);
        let hybrid_key_64 = match hybrid_key_res {
            Ok(k) => k,
            Err(e) => {
                secure_stack_wipe(stack_base);
                return Err(e);
            }
        };

        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&hybrid_key_64[0..32]);

        self.session_key = Some(session_key);
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        // Deep Stack Annihilation
        secure_stack_wipe(stack_base);

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
    /// * `stack_base` - The base address of the current thread's stack, used for deep stack annihilation.
    pub fn encapsulate_for_peer(
        &mut self,
        peer_ml_kem_pk: &PublicKey1024,
        peer_x25519_pk: &X25519Public,
        entropy: &[u8; 64],
        salt: &[u8],
        info: &[u8],
        stack_base: u64,
    ) -> Result<(Ciphertext1024, X25519Public), CryptoError> {
        let mut ml_kem_entropy = [0u8; 32];
        let mut x25519_entropy = [0u8; 32];

        ml_kem_entropy.copy_from_slice(&entropy[0..32]);
        x25519_entropy.copy_from_slice(&entropy[32..64]);

        let ml_kem_res = ml_kem_encapsulate(peer_ml_kem_pk, &ml_kem_entropy);
        let (mut pq_secret_wrapper, ct) = match ml_kem_res {
            Ok(res) => res,
            Err(e) => {
                secure_zeroize(&mut ml_kem_entropy);
                secure_zeroize(&mut x25519_entropy);
                secure_stack_wipe(stack_base);
                return Err(e);
            }
        };

        let (my_x25519_pk, my_x25519_sk) = x25519_keygen(&x25519_entropy);

        let classical_res = x25519_diffie_hellman(&my_x25519_sk, peer_x25519_pk);
        let mut classical_secret_wrapper = match classical_res {
            Ok(res) => res,
            Err(e) => {
                secure_zeroize(&mut ml_kem_entropy);
                secure_zeroize(&mut x25519_entropy);
                secure_zeroize(&mut pq_secret_wrapper.0);
                secure_stack_wipe(stack_base);
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

        let hybrid_key_64 = match hybrid_res {
            Ok(k) => k,
            Err(e) => {
                secure_zeroize(&mut ml_kem_entropy);
                secure_zeroize(&mut x25519_entropy);
                secure_stack_wipe(stack_base);
                return Err(e);
            }
        };

        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&hybrid_key_64[0..32]);

        self.session_key = Some(session_key);
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        secure_zeroize(&mut ml_kem_entropy);
        secure_zeroize(&mut x25519_entropy);

        // Deep Stack Annihilation
        secure_stack_wipe(stack_base);

        compiler_fence(Ordering::SeqCst);

        Ok((ct, my_x25519_pk))
    }

    /// Retrieves the active session key for network packet decryption.
    pub fn get_session_key(&self, out_key: &mut [u8; 32]) -> Result<(), CryptoError> {
        let sk = match self.session_key.as_ref() {
            Some(k) => k,
            None => {
                return Err(CryptoError::InvalidState);
            }
        };

        out_key.copy_from_slice(sk);
        compiler_fence(Ordering::SeqCst);

        Ok(())
    }

    /// Explicitly zeroizes the active session key.
    pub fn zeroize_session(&mut self) {
        self.ml_kem_dk = None;
        self.x25519_sk = None;

        if let Some(ref mut key) = self.session_key {
            secure_zeroize(key);
            secure_cache_flush(key.as_ptr(), key.len());
        }
        self.session_key = None;

        compiler_fence(Ordering::SeqCst);
    }
}
