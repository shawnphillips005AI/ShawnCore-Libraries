// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Post-Quantum Session Key Manager.
//! Hybrid ML-KEM-1024 and X25519 handshake.
//! Hardware-agnostic implementation for autonomous surface vehicles.
//!
//! Security boundary: `initiate_handshake` / `finalize_handshake` / `encapsulate_for_peer` do not
//! authenticate a peer identity. Use `encapsulate_authenticated` / `finalize_authenticated` /
//! `confirm_peer` (feature `ml-dsa`) for MITM resistance; they are unreviewed (see SECURITY.md).
//! Manages both ML-KEM-1024 and X25519 key encapsulation/decapsulation to establish
//! a hybrid symmetric key for network communications. Trust provisioning and any
//! application-level forward-secrecy guarantees are defined by
//! the integrating protocol rather than this module alone.
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

#[cfg(feature = "ml-dsa")]
use crate::auth_handshake::{
    handshake_binding, identity_fingerprint, transcript_hash, CONTEXT_ENCAPSULATING_SIDE,
    CONTEXT_KEYGEN_SIDE,
};
#[cfg(feature = "ml-dsa")]
use crate::ml_dsa_wrapper::{
    ml_dsa_sign_with_context, ml_dsa_verify_with_context, PublicKey87, Signature87, SigningKey87,
};
#[cfg(feature = "ml-dsa")]
use subtle::ConstantTimeEq;

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
    /// Set while an authenticated encapsulation awaits the peer's signature; traffic is refused.
    pending_auth: Option<PendingAuthentication>,
}

/// What `confirm_peer` must check: the signed transcript and the identity it was bound to.
#[cfg_attr(not(feature = "ml-dsa"), allow(dead_code))]
struct PendingAuthentication {
    transcript: [u8; 48],
    peer_identity: [u8; 48],
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
            pending_auth: None,
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
    /// Any cryptographic failure after a pending handshake has started consumes the pending
    /// ephemeral ML-KEM/X25519 state and requires a fresh `initiate_handshake` call.
    /// This fail-closed behavior prevents failed handshake inputs from reusing ephemeral state.
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
                self.zeroize_session();
                return Err(e);
            }
        };

        let classical_secret_res = x25519_diffie_hellman(x25519_sk, peer_x25519_pk);
        let mut classical_secret = match classical_secret_res {
            Ok(s) => s.0,
            Err(e) => {
                pq_secret.zeroize();
                self.zeroize_session();
                return Err(e);
            }
        };

        let mut transcript = handshake_transcript(ml_kem_ct, peer_x25519_pk, info);
        let hybrid_key_res =
            derive_hybrid_key(&mut pq_secret, &mut classical_secret, salt, &transcript);
        transcript.zeroize();
        let mut hybrid_key_128 = match hybrid_key_res {
            Ok(k) => k,
            Err(e) => {
                pq_secret.zeroize();
                classical_secret.zeroize();
                self.zeroize_session();
                return Err(e);
            }
        };

        let mut tx_key = [0u8; 64];
        let mut rx_key = [0u8; 64];
        tx_key[..32].copy_from_slice(&hybrid_key_128[..32]);
        tx_key[32..].copy_from_slice(&hybrid_key_128[96..]);
        rx_key.copy_from_slice(&hybrid_key_128[32..96]);
        hybrid_key_128.zeroize();

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

        let mut hybrid_key_128 = match hybrid_res {
            Ok(k) => k,
            Err(e) => {
                ml_kem_entropy.zeroize();
                x25519_entropy.zeroize();
                return Err(e);
            }
        };

        let mut tx_key = [0u8; 64];
        let mut rx_key = [0u8; 64];
        tx_key.copy_from_slice(&hybrid_key_128[32..96]);
        rx_key[..32].copy_from_slice(&hybrid_key_128[..32]);
        rx_key[32..].copy_from_slice(&hybrid_key_128[96..]);
        hybrid_key_128.zeroize();

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

    /// Assigns the next RFC 8439 transmit nonce and advances `tx_counter`.
    ///
    /// `encrypt_packet` allocates and advances its own nonce internally. Do not
    /// call this method for a packet that will also be passed to `encrypt_packet`,
    /// or the transmit counter will advance twice.
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
    ///
    /// Sequences older than the trailing 64-packet window are ignored; `check_rx_nonce`
    /// already rejects them, so there is no window bit left to record.
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
            let offset = self.rx_counter - sequence;
            if offset >= 64 {
                return;
            }
            self.rx_window |= 1u64 << offset;
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
        if !self.is_established
            || self.pending_auth.is_some()
            || ciphertext.len() != plaintext.len()
        {
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
        let mut pending_nonce = [0u8; 12];
        pending_nonce[..8].copy_from_slice(&self.tx_counter.to_le_bytes());
        pending_nonce[8..].fill(0);

        let result = aead_encrypt(
            &enc_key,
            &mac_key,
            &pending_nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
        );

        enc_key.zeroize();
        mac_key.zeroize();

        if let Err(e) = result {
            pending_nonce.zeroize();
            return Err(e);
        }

        nonce.copy_from_slice(&pending_nonce);
        pending_nonce.zeroize();
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
        if !self.is_established
            || self.pending_auth.is_some()
            || plaintext.len() != ciphertext.len()
        {
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
        self.pending_auth = None;

        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(feature = "ml-dsa")]
impl SessionManager {
    /// Encapsulating side of the authenticated handshake.
    ///
    /// Runs [`Self::encapsulate_for_peer`] with `info` set to the handshake binding, then signs the
    /// transcript with `own_signing_key`. The session keys are derived but **unconfirmed**: the
    /// session refuses all traffic until [`Self::confirm_peer`] verifies the peer's signature.
    ///
    /// `peer_verifying_key` is the trust anchor for the key-generating side. Any failure after
    /// the keys were derived wipes the session.
    #[allow(clippy::too_many_arguments)]
    pub fn encapsulate_authenticated(
        &mut self,
        own_signing_key: &SigningKey87,
        peer_verifying_key: &PublicKey87,
        peer_ml_kem_pk: &PublicKey1024,
        peer_x25519_pk: &X25519Public,
        entropy: &[u8; 64],
        salt: &[u8],
        app_info: &[u8],
        out_ct: &mut Ciphertext1024,
        out_pk: &mut X25519Public,
        out_signature: &mut Signature87,
    ) -> Result<(), CryptoError> {
        let own_identity = identity_fingerprint(&own_signing_key.verifying_key());
        let peer_identity = identity_fingerprint(peer_verifying_key);
        let binding = handshake_binding(
            peer_ml_kem_pk,
            peer_x25519_pk,
            &peer_identity,
            &own_identity,
            app_info,
        )?;

        self.encapsulate_for_peer(
            peer_ml_kem_pk,
            peer_x25519_pk,
            entropy,
            salt,
            &binding,
            out_ct,
            out_pk,
        )?;

        let transcript = transcript_hash(&binding, out_ct, out_pk);
        match ml_dsa_sign_with_context(own_signing_key, &transcript, CONTEXT_ENCAPSULATING_SIDE) {
            Ok(signature) => {
                *out_signature = signature;
                self.pending_auth = Some(PendingAuthentication {
                    transcript,
                    peer_identity,
                });
                Ok(())
            }
            Err(error) => {
                self.zeroize_session();
                Err(error)
            }
        }
    }

    /// Key-generating side of the authenticated handshake.
    ///
    /// Verifies the encapsulating side's signature over the transcript against
    /// `peer_verifying_key` **before** finalizing, so a forged response costs one signature
    /// verification and consumes nothing: the pending handshake survives and the genuine
    /// response can still be processed. On success the keys are live and `out_signature`
    /// (this side's proof) must be sent to the peer for [`Self::confirm_peer`].
    ///
    /// `salt` and `app_info` must equal the peer's. A valid signature with a failing key
    /// derivation (for example a low-order X25519 point) consumes the pending handshake.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_authenticated(
        &mut self,
        own_signing_key: &SigningKey87,
        peer_verifying_key: &PublicKey87,
        peer_x25519_pk: &X25519Public,
        ml_kem_ct: &Ciphertext1024,
        peer_signature: &Signature87,
        salt: &[u8],
        app_info: &[u8],
        out_signature: &mut Signature87,
    ) -> Result<(), CryptoError> {
        let (own_ml_kem_pk, own_x25519_pk) = {
            let dk = self.ml_kem_dk.as_ref().ok_or(CryptoError::InvalidState)?;
            let sk = self.x25519_sk.as_ref().ok_or(CryptoError::InvalidState)?;
            (
                PublicKey1024(dk.0.encapsulation_key().clone()),
                x25519_keygen(&sk.0).0,
            )
        };
        let own_identity = identity_fingerprint(&own_signing_key.verifying_key());
        let peer_identity = identity_fingerprint(peer_verifying_key);
        let binding = handshake_binding(
            &own_ml_kem_pk,
            &own_x25519_pk,
            &own_identity,
            &peer_identity,
            app_info,
        )?;
        let transcript = transcript_hash(&binding, ml_kem_ct, peer_x25519_pk);

        ml_dsa_verify_with_context(
            peer_verifying_key,
            &transcript,
            CONTEXT_ENCAPSULATING_SIDE,
            peer_signature,
        )?;

        self.finalize_handshake(peer_x25519_pk, ml_kem_ct, salt, &binding)?;

        match ml_dsa_sign_with_context(own_signing_key, &transcript, CONTEXT_KEYGEN_SIDE) {
            Ok(signature) => {
                *out_signature = signature;
                Ok(())
            }
            Err(error) => {
                self.zeroize_session();
                Err(error)
            }
        }
    }

    /// Completes the encapsulating side by verifying the key-generating side's signature.
    ///
    /// `peer_verifying_key` must be the identity this session was bound to; a signature from any
    /// other key is rejected even if it verifies. A failed check leaves the session unconfirmed
    /// (still refusing traffic) so the genuine signature can still arrive; call
    /// [`Self::zeroize_session`] to abandon it.
    pub fn confirm_peer(
        &mut self,
        peer_verifying_key: &PublicKey87,
        peer_signature: &Signature87,
    ) -> Result<(), CryptoError> {
        let pending = self
            .pending_auth
            .as_ref()
            .ok_or(CryptoError::InvalidState)?;
        let presented = identity_fingerprint(peer_verifying_key);
        if !bool::from(presented.as_slice().ct_eq(pending.peer_identity.as_slice())) {
            return Err(CryptoError::VerificationFailed);
        }
        ml_dsa_verify_with_context(
            peer_verifying_key,
            &pending.transcript,
            CONTEXT_KEYGEN_SIDE,
            peer_signature,
        )?;
        self.pending_auth = None;
        Ok(())
    }

    /// Whether this side is waiting for [`Self::confirm_peer`].
    #[must_use]
    pub fn is_awaiting_peer_confirmation(&self) -> bool {
        self.pending_auth.is_some()
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

    #[test]
    fn key_integrity_detects_single_bit_corruption() {
        crate::test_support::install_callbacks();
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
            pending_auth: None,
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
        crate::test_support::install_callbacks();
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
            pending_auth: None,
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

    /// The handshake has no peer authentication or key confirmation: tampering is only
    /// detected when the first packet fails authentication.
    #[test]
    fn tampered_or_mismatched_handshake_inputs_fail_the_first_packet() {
        use crate::ml_kem_wrapper::Ciphertext1024;
        use crate::x25519_wrapper::X25519Public;

        crate::test_support::install_callbacks();

        let run = |tamper_ct: bool, responder_info: &[u8]| -> bool {
            let mut responder = SessionManager::new();
            let mut initiator = SessionManager::new();
            let (pk, x_pk) = responder.initiate_handshake(&[0x31; 96]).unwrap();
            let mut ct = Ciphertext1024([0; 1568]);
            let mut my_pk = X25519Public([0; 32]);
            initiator
                .encapsulate_for_peer(
                    &pk,
                    &x_pk,
                    &[0x42; 64],
                    b"salt",
                    b"info",
                    &mut ct,
                    &mut my_pk,
                )
                .unwrap();
            if tamper_ct {
                ct.0[0] ^= 1;
            }
            responder
                .finalize_handshake(&my_pk, &ct, b"salt", responder_info)
                .unwrap();

            let mut wire = [0u8; 5];
            let mut nonce = [0u8; 12];
            let mut tag = [0u8; 48];
            initiator
                .encrypt_packet(b"aad", b"hello", &mut wire, &mut nonce, &mut tag)
                .unwrap();
            let mut plain = [0u8; 5];
            let accepted = responder
                .decrypt_packet(b"aad", &wire, &nonce, &tag, &mut plain)
                .is_ok();
            assert!(!accepted || &plain == b"hello");
            accepted
        };

        assert!(
            run(false, b"info"),
            "untampered handshake must interoperate"
        );
        assert!(!run(true, b"info"), "tampered ciphertext must be detected");
        assert!(!run(false, b"other"), "mismatched info must be detected");
    }

    #[test]
    fn last_usable_counter_encrypts_once_then_refuses_without_wrapping() {
        crate::test_support::install_callbacks();
        let mut manager = SessionManager {
            ml_kem_dk: None,
            x25519_sk: None,
            tx_key: Some([0x11; 64]),
            rx_key: Some([0x22; 64]),
            tx_key_checksum: key_checksum(&[0x11; 64]),
            rx_key_checksum: key_checksum(&[0x22; 64]),
            is_established: true,
            tx_counter: u64::MAX - 1,
            rx_counter: 0,
            rx_window: 0,
            pending_auth: None,
        };
        let mut ciphertext = [0u8; 2];
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 48];

        manager
            .encrypt_packet(b"", b"ok", &mut ciphertext, &mut nonce, &mut tag)
            .unwrap();
        assert_eq!(&nonce[..8], &(u64::MAX - 1).to_le_bytes());
        assert_eq!(manager.tx_counter, u64::MAX);

        let before = (ciphertext, nonce, tag);
        assert_eq!(
            manager.encrypt_packet(b"", b"no", &mut ciphertext, &mut nonce, &mut tag),
            Err(CryptoError::InvalidState)
        );
        assert_eq!((ciphertext, nonce, tag), before);
        assert_eq!(manager.tx_counter, u64::MAX);
    }

    #[test]
    fn replay_window_handles_extreme_sequence_numbers() {
        let nonce = |sequence: u64| {
            let mut n = [0u8; 12];
            n[..8].copy_from_slice(&sequence.to_le_bytes());
            n
        };
        let mut manager = SessionManager::new();

        manager.commit_rx_nonce(&nonce(u64::MAX));
        assert_eq!(manager.rx_counter, u64::MAX);
        assert_eq!(manager.rx_window, 1);
        assert_eq!(
            manager.check_rx_nonce(&nonce(u64::MAX)),
            Err(CryptoError::InvalidState)
        );
        assert_eq!(manager.check_rx_nonce(&nonce(u64::MAX - 1)), Ok(()));
        assert_eq!(manager.check_rx_nonce(&nonce(u64::MAX - 63)), Ok(()));
        assert_eq!(
            manager.check_rx_nonce(&nonce(u64::MAX - 64)),
            Err(CryptoError::InvalidState)
        );
        assert_eq!(
            manager.check_rx_nonce(&nonce(0)),
            Err(CryptoError::InvalidState)
        );

        manager.commit_rx_nonce(&nonce(u64::MAX - 63));
        assert_eq!(manager.rx_window, 1 | (1 << 63));
        assert_eq!(
            manager.check_rx_nonce(&nonce(u64::MAX - 63)),
            Err(CryptoError::InvalidState)
        );
    }

    #[test]
    fn zeroize_session_wipes_each_key_before_it_is_flushed() {
        use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering as O};
        static TX: AtomicUsize = AtomicUsize::new(0);
        static RX: AtomicUsize = AtomicUsize::new(0);
        static WIPED: AtomicUsize = AtomicUsize::new(0);
        static DIRTY: AtomicBool = AtomicBool::new(false);

        // Identified by address, so flushes from concurrent tests are ignored.
        fn hook(ptr: *const u8, len: usize) {
            let bit = if ptr as usize == TX.load(O::SeqCst) {
                1
            } else if ptr as usize == RX.load(O::SeqCst) {
                2
            } else {
                return;
            };
            let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
            if len == 64 && bytes.iter().all(|&b| b == 0) {
                WIPED.fetch_or(bit, O::SeqCst);
            } else {
                DIRTY.store(true, O::SeqCst);
            }
        }

        let _hook_guard = crate::test_support::hook_guard();
        crate::test_support::install_callbacks();
        let mut manager = SessionManager {
            ml_kem_dk: None,
            x25519_sk: None,
            tx_key: Some([0xC3; 64]),
            rx_key: Some([0x3C; 64]),
            tx_key_checksum: key_checksum(&[0xC3; 64]),
            rx_key_checksum: key_checksum(&[0x3C; 64]),
            is_established: true,
            tx_counter: 5,
            rx_counter: 9,
            rx_window: 3,
            pending_auth: None,
        };
        TX.store(
            manager.tx_key.as_ref().unwrap().as_ptr() as usize,
            O::SeqCst,
        );
        RX.store(
            manager.rx_key.as_ref().unwrap().as_ptr() as usize,
            O::SeqCst,
        );
        WIPED.store(0, O::SeqCst);
        DIRTY.store(false, O::SeqCst);

        crate::test_support::set_cache_flush_hook(Some(hook));
        manager.zeroize_session();
        crate::test_support::set_cache_flush_hook(None);

        assert_eq!(
            WIPED.load(O::SeqCst),
            3,
            "both keys must be flushed as zeros"
        );
        assert!(
            !DIRTY.load(O::SeqCst),
            "key bytes reached the flush callback unwiped"
        );
        assert!(!manager.is_established);
        assert_eq!(
            (manager.tx_counter, manager.rx_counter, manager.rx_window),
            (0, 0, 0)
        );
    }

    #[test]
    fn commit_leaves_replay_state_intact_for_sequences_below_the_window() {
        let mut manager = SessionManager::new();
        manager.rx_counter = 100;
        manager.rx_window = 1;

        let mut stale_nonce = [0u8; 12];
        stale_nonce[..8].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            manager.check_rx_nonce(&stale_nonce),
            Err(CryptoError::InvalidState)
        );

        manager.commit_rx_nonce(&stale_nonce);
        assert_eq!(manager.rx_counter, 100);
        assert_eq!(manager.rx_window, 1);

        let mut in_window_nonce = [0u8; 12];
        in_window_nonce[..8].copy_from_slice(&99u64.to_le_bytes());
        assert_eq!(manager.check_rx_nonce(&in_window_nonce), Ok(()));
        manager.commit_rx_nonce(&in_window_nonce);
        assert_eq!(manager.rx_window, 0b11);
        assert_eq!(
            manager.check_rx_nonce(&in_window_nonce),
            Err(CryptoError::InvalidState)
        );
    }
}
