// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Active-attacker tests for the authenticated handshake, protocol version 2 (ML-DSA-87 signed
//! transcript plus explicit key confirmation).
//!
//! Each test distinguishes an authentication failure (`VerificationFailed`: a bad signature or
//! identity, which changes no state) from a key-confirmation failure (`KeyConfirmationFailed`: an
//! authentic peer whose derived key differs). These are behavioral tests, not a security proof.
//! See SECURITY.md section 10.

#![cfg(feature = "ml-dsa")]

use shawncore_pq_crypto::aead_wrapper::AEAD_TAG_SIZE;
use shawncore_pq_crypto::auth_handshake::{
    confirmation_tag, encapsulator_digest, handshake_binding, identity_fingerprint, keygen_digest,
    transcript_hash, CONFIRMATION_TAG_LEN, CONFIRM_LABEL_ENCAPSULATING_SIDE,
    CONFIRM_LABEL_KEYGEN_SIDE, CONTEXT_ENCAPSULATING_SIDE, CONTEXT_KEYGEN_SIDE,
};
use shawncore_pq_crypto::error::CryptoError;
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_dsa_wrapper::{
    ml_dsa_keygen, ml_dsa_sign_with_context, PublicKey87, Signature87, SigningKey87,
};
use shawncore_pq_crypto::ml_kem_wrapper::{Ciphertext1024, PublicKey1024};
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::X25519Public;

type Tag = [u8; CONFIRMATION_TAG_LEN];

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

// Unoptimized builds put the expanded ML-DSA keys and temporaries on the stack.
fn big_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
            test();
        })
        .unwrap()
        .join()
        .unwrap();
}

struct Identity {
    vk: PublicKey87,
    sk: SigningKey87,
}

fn identity(seed: u8) -> Identity {
    let (vk, sk) = ml_dsa_keygen(&[seed; 32]).unwrap();
    Identity { vk, sk }
}

fn blank_signature() -> Signature87 {
    Signature87([0; 4627])
}

/// The first message, and the encapsulating side's reply (message two).
#[derive(Clone)]
struct Reply {
    ct: Ciphertext1024,
    xe: X25519Public,
    sig_e: Signature87,
    tag_e: Tag,
}

/// The key-generating side's proof (message three).
struct Proof {
    sig_k: Signature87,
    tag_k: Tag,
}

const SALT: &[u8] = b"shared salt";
const APP: &[u8] = b"app";

fn start_keygen(keygen: &mut SessionManager, seed: u8) -> (PublicKey1024, X25519Public) {
    keygen.initiate_handshake(&[seed; 96]).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn reply_with(
    encap: &mut SessionManager,
    own: &Identity,
    keygen_vk: &PublicKey87,
    ek: PublicKey1024,
    xk: X25519Public,
    entropy: u8,
    salt: &[u8],
    app_info: &[u8],
) -> Reply {
    let mut ct = Ciphertext1024([0; 1568]);
    let mut xe = X25519Public([0; 32]);
    let mut sig_e = blank_signature();
    let mut tag_e = [0u8; CONFIRMATION_TAG_LEN];
    encap
        .encapsulate_authenticated(
            &own.sk,
            keygen_vk,
            &ek,
            &xk,
            &[entropy; 64],
            salt,
            app_info,
            &mut ct,
            &mut xe,
            &mut sig_e,
            &mut tag_e,
        )
        .expect("encapsulate_authenticated");
    Reply {
        ct,
        xe,
        sig_e,
        tag_e,
    }
}

fn reply(
    encap: &mut SessionManager,
    own: &Identity,
    keygen_vk: &PublicKey87,
    ek: PublicKey1024,
    xk: X25519Public,
) -> Reply {
    reply_with(encap, own, keygen_vk, ek, xk, 0x22, SALT, APP)
}

fn finalize_with(
    keygen: &mut SessionManager,
    own: &Identity,
    trusted_peer: &PublicKey87,
    reply: &Reply,
    salt: &[u8],
    app_info: &[u8],
) -> Result<Proof, CryptoError> {
    let mut sig_k = blank_signature();
    let mut tag_k = [0u8; CONFIRMATION_TAG_LEN];
    keygen
        .finalize_authenticated(
            &own.sk,
            trusted_peer,
            &reply.xe,
            &reply.ct,
            &reply.sig_e,
            &reply.tag_e,
            salt,
            app_info,
            &mut sig_k,
            &mut tag_k,
        )
        .map(|()| Proof { sig_k, tag_k })
}

fn finalize(
    keygen: &mut SessionManager,
    own: &Identity,
    trusted_peer: &PublicKey87,
    reply: &Reply,
) -> Result<Proof, CryptoError> {
    finalize_with(keygen, own, trusted_peer, reply, SALT, APP)
}

fn send(
    from: &mut SessionManager,
    to: &mut SessionManager,
    text: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut ct = vec![0u8; text.len()];
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    from.encrypt_packet(b"", text, &mut ct, &mut nonce, &mut tag)?;
    let mut plain = vec![0u8; text.len()];
    to.decrypt_packet(b"", &ct, &nonce, &tag, &mut plain)?;
    Ok(plain)
}

fn can_send(session: &mut SessionManager) -> bool {
    let (mut ct, mut nonce, mut tag) = ([0u8; 4], [0u8; 12], [0u8; AEAD_TAG_SIZE]);
    session
        .encrypt_packet(b"", b"data", &mut ct, &mut nonce, &mut tag)
        .is_ok()
}

fn confirm(
    encap: &mut SessionManager,
    keygen_vk: &PublicKey87,
    proof: &Proof,
) -> Result<(), CryptoError> {
    encap.confirm_peer(keygen_vk, &proof.sig_k, &proof.tag_k)
}

/// A complete, successful handshake; returns both sessions, confirmed.
fn established(
    k_id: &Identity,
    e_id: &Identity,
    seed: u8,
) -> (SessionManager, SessionManager, Reply, Proof) {
    let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
    let (ek, xk) = start_keygen(&mut keygen, seed);
    let reply = reply_with(&mut encap, e_id, &k_id.vk, ek, xk, seed ^ 0x33, SALT, APP);
    let proof = finalize(&mut keygen, k_id, &e_id.vk, &reply).unwrap();
    confirm(&mut encap, &k_id.vk, &proof).unwrap();
    (keygen, encap, reply, proof)
}

#[test]
fn matching_salt_and_context_complete_with_mutual_confirmation() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply(&mut encap, &e_id, &k_id.vk, ek, xk);

        // Stage 1: the encapsulating side has derived keys but is unconfirmed: it neither sends
        // nor receives. The key-generating side has nothing installed yet.
        assert!(encap.is_awaiting_peer_confirmation());
        assert!(!can_send(&mut encap));
        assert!(!can_send(&mut keygen));

        // Stage 2: the key-generating side verified signature and tag, so it may send; the
        // encapsulating side still refuses what arrives until it confirms.
        let proof = finalize(&mut keygen, &k_id, &e_id.vk, &reply).unwrap();
        assert_eq!(
            send(&mut keygen, &mut encap, b"early"),
            Err(CryptoError::InvalidState)
        );

        // Stage 3: after confirm_peer both directions work.
        let mut encap2 = encap;
        confirm(&mut encap2, &k_id.vk, &proof).unwrap();
        assert!(!encap2.is_awaiting_peer_confirmation());
        assert_eq!(send(&mut keygen, &mut encap2, b"hello").unwrap(), b"hello");
        assert_eq!(send(&mut encap2, &mut keygen, b"world").unwrap(), b"world");
        assert_ne!(reply.tag_e, proof.tag_k, "directions use different tags");
    });
}

#[test]
fn an_active_intermediary_with_its_own_identity_is_rejected_and_consumes_nothing() {
    big_stack(|| {
        let (k_id, e_id, m_id) = (identity(0x41), identity(0x42), identity(0x4D));
        let (mut keygen, mut mitm, mut encap) = (
            SessionManager::new(),
            SessionManager::new(),
            SessionManager::new(),
        );
        let (ek, xk) = start_keygen(&mut keygen, 0x11);

        let forged = reply(&mut mitm, &m_id, &k_id.vk, ek.clone(), xk.clone());
        assert_eq!(
            finalize(&mut keygen, &k_id, &e_id.vk, &forged).map(|_| ()),
            Err(CryptoError::VerificationFailed)
        );

        // The pending handshake survives, so the genuine reply still completes.
        let genuine = reply(&mut encap, &e_id, &k_id.vk, ek, xk);
        let proof = finalize(&mut keygen, &k_id, &e_id.vk, &genuine).unwrap();
        confirm(&mut encap, &k_id.vk, &proof).unwrap();
        assert_eq!(send(&mut keygen, &mut encap, b"ok").unwrap(), b"ok");
    });
}

#[test]
fn every_tampered_reply_field_fails_authentication_and_consumes_nothing() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let genuine = reply(&mut encap, &e_id, &k_id.vk, ek, xk);

        let mut bad_ct = genuine.clone();
        bad_ct.ct.0[0] ^= 1;
        let mut bad_xe = genuine.clone();
        bad_xe.xe.0[0] ^= 1;
        let mut bad_sig = genuine.clone();
        bad_sig.sig_e.0[100] ^= 1;
        let mut bad_tag = genuine.clone();
        bad_tag.tag_e[0] ^= 1;

        for (name, tampered, app) in [
            ("ciphertext", &bad_ct, APP),
            ("encapsulator x25519 key", &bad_xe, APP),
            ("signature", &bad_sig, APP),
            ("confirmation tag", &bad_tag, APP),
            ("application context", &genuine, &b"other app"[..]),
        ] {
            assert_eq!(
                finalize_with(&mut keygen, &k_id, &e_id.vk, tampered, SALT, app).map(|_| ()),
                Err(CryptoError::VerificationFailed),
                "{name}: an unauthenticated alteration must be a signature failure"
            );
        }
        // None of it consumed the pending handshake.
        let proof = finalize(&mut keygen, &k_id, &e_id.vk, &genuine).unwrap();
        confirm(&mut encap, &k_id.vk, &proof).unwrap();
    });
}

#[test]
fn the_wrong_trust_anchor_rejects_a_genuine_reply() {
    big_stack(|| {
        let (k_id, e_id, other) = (identity(0x41), identity(0x42), identity(0x4D));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let genuine = reply(&mut encap, &e_id, &k_id.vk, ek, xk);
        assert_eq!(
            finalize(&mut keygen, &k_id, &other.vk, &genuine).map(|_| ()),
            Err(CryptoError::VerificationFailed)
        );
    });
}

/// The signed transcript does not contain the salt (it may be a secret); key confirmation is what
/// detects a mismatch, during the handshake and as a different error from a bad signature.
#[test]
fn different_salts_are_rejected_during_the_handshake_by_key_confirmation() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply_with(&mut encap, &e_id, &k_id.vk, ek, xk, 0x22, b"salt A", APP);

        // Signature and identity are fine; the keys are not the same.
        assert_eq!(
            finalize_with(&mut keygen, &k_id, &e_id.vk, &reply, b"salt B", APP).map(|_| ()),
            Err(CryptoError::KeyConfirmationFailed)
        );
        // Nothing was installed: the key-generating side does not believe it has a session, and
        // the failure consumed the pending handshake (fail closed).
        assert!(!can_send(&mut keygen));
        assert_eq!(
            finalize(&mut keygen, &k_id, &e_id.vk, &reply).map(|_| ()),
            Err(CryptoError::InvalidState)
        );
        // The encapsulating side never became usable.
        assert!(encap.is_awaiting_peer_confirmation());
        assert!(!can_send(&mut encap));

        // Recovery: a fresh handshake with matching salts succeeds.
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x12);
        let reply = reply_with(&mut encap, &e_id, &k_id.vk, ek, xk, 0x23, b"salt A", APP);
        let proof = finalize_with(&mut keygen, &k_id, &e_id.vk, &reply, b"salt A", APP).unwrap();
        confirm(&mut encap, &k_id.vk, &proof).unwrap();
        assert_eq!(send(&mut encap, &mut keygen, b"fine").unwrap(), b"fine");
    });
}

#[test]
fn an_empty_salt_on_one_side_only_is_also_a_key_confirmation_failure() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply_with(&mut encap, &e_id, &k_id.vk, ek, xk, 0x22, b"", APP);
        assert_eq!(
            finalize_with(&mut keygen, &k_id, &e_id.vk, &reply, SALT, APP).map(|_| ()),
            Err(CryptoError::KeyConfirmationFailed)
        );
    });
}

/// A validly signed reply whose ciphertext is not the one the signer derived its key from. The
/// signature is genuine, but the channel would be unusable; v1 accepted this.
#[test]
fn a_validly_signed_but_unusable_exchange_fails_key_confirmation() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let honest = reply(&mut encap, &e_id, &k_id.vk, ek.clone(), xk.clone());

        // An authenticated (or faulty) encapsulating side re-signs a different ciphertext.
        let mut unusable = honest.clone();
        unusable.ct.0[7] ^= 0x55;
        let binding = handshake_binding(
            &ek,
            &xk,
            &identity_fingerprint(&k_id.vk),
            &identity_fingerprint(&e_id.vk),
            APP,
        )
        .unwrap();
        let digest = encapsulator_digest(
            &transcript_hash(&binding, &unusable.ct, &unusable.xe),
            &unusable.tag_e,
        );
        unusable.sig_e =
            ml_dsa_sign_with_context(&e_id.sk, &digest, CONTEXT_ENCAPSULATING_SIDE).unwrap();

        assert_eq!(
            finalize(&mut keygen, &k_id, &e_id.vk, &unusable).map(|_| ()),
            Err(CryptoError::KeyConfirmationFailed),
            "authentic signature, wrong key: not an authentication failure"
        );
        assert!(
            !can_send(&mut keygen),
            "no operational session was installed"
        );
    });
}

#[test]
fn a_replayed_reply_from_a_previous_handshake_is_rejected_by_a_new_one() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let recorded = reply(&mut encap, &e_id, &k_id.vk, ek, xk);

        let mut fresh = SessionManager::new();
        start_keygen(&mut fresh, 0x99); // a new ephemeral key pair
        assert_eq!(
            finalize(&mut fresh, &k_id, &e_id.vk, &recorded).map(|_| ()),
            Err(CryptoError::VerificationFailed)
        );
    });
}

#[test]
fn an_impersonator_of_the_keygen_side_cannot_confirm_the_session() {
    big_stack(|| {
        let (k_id, e_id, m_id) = (identity(0x41), identity(0x42), identity(0x4D));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply(&mut encap, &e_id, &k_id.vk, ek.clone(), xk.clone());
        let genuine = finalize(&mut keygen, &k_id, &e_id.vk, &reply).unwrap();

        // Everything the intermediary needs is public except the keys, so it signs a proof of
        // its own and invents a tag.
        let binding = handshake_binding(
            &ek,
            &xk,
            &identity_fingerprint(&k_id.vk),
            &identity_fingerprint(&e_id.vk),
            APP,
        )
        .unwrap();
        let digest = encapsulator_digest(
            &transcript_hash(&binding, &reply.ct, &reply.xe),
            &reply.tag_e,
        );
        let invented: Tag = [0x5A; CONFIRMATION_TAG_LEN];
        let forged = Proof {
            sig_k: ml_dsa_sign_with_context(
                &m_id.sk,
                &keygen_digest(&digest, &invented),
                CONTEXT_KEYGEN_SIDE,
            )
            .unwrap(),
            tag_k: invented,
        };

        assert_eq!(
            confirm(&mut encap, &k_id.vk, &forged),
            Err(CryptoError::VerificationFailed),
            "a forged signature under the pinned identity"
        );
        assert_eq!(
            confirm(&mut encap, &m_id.vk, &forged),
            Err(CryptoError::VerificationFailed),
            "a valid signature from a different identity"
        );
        assert!(encap.is_awaiting_peer_confirmation());
        assert!(!can_send(&mut encap));

        confirm(&mut encap, &k_id.vk, &genuine).unwrap();
        assert_eq!(send(&mut keygen, &mut encap, b"yes").unwrap(), b"yes");
    });
}

#[test]
fn tampering_with_the_proof_in_flight_is_a_signature_failure_that_keeps_the_session_pending() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply(&mut encap, &e_id, &k_id.vk, ek, xk);
        let genuine = finalize(&mut keygen, &k_id, &e_id.vk, &reply).unwrap();

        let mut bad_sig = Proof {
            sig_k: genuine.sig_k.clone(),
            tag_k: genuine.tag_k,
        };
        bad_sig.sig_k.0[10] ^= 1;
        let mut bad_tag = Proof {
            sig_k: genuine.sig_k.clone(),
            tag_k: genuine.tag_k,
        };
        bad_tag.tag_k[0] ^= 1;

        for proof in [&bad_sig, &bad_tag] {
            assert_eq!(
                confirm(&mut encap, &k_id.vk, proof),
                Err(CryptoError::VerificationFailed)
            );
            assert!(encap.is_awaiting_peer_confirmation());
        }
        confirm(&mut encap, &k_id.vk, &genuine).unwrap();
    });
}

/// The key-generating side's signature is valid but its tag does not match the key the
/// encapsulating side derived: authentic peer, no shared key. The session must be wiped.
#[test]
fn a_valid_signature_over_a_wrong_confirmation_tag_wipes_the_unconfirmed_session() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply(&mut encap, &e_id, &k_id.vk, ek.clone(), xk.clone());

        // A faulty or malicious key-generating side signs a digest that embeds a wrong tag.
        let binding = handshake_binding(
            &ek,
            &xk,
            &identity_fingerprint(&k_id.vk),
            &identity_fingerprint(&e_id.vk),
            APP,
        )
        .unwrap();
        let digest = encapsulator_digest(
            &transcript_hash(&binding, &reply.ct, &reply.xe),
            &reply.tag_e,
        );
        let wrong: Tag = [0xC3; CONFIRMATION_TAG_LEN];
        let proof = Proof {
            sig_k: ml_dsa_sign_with_context(
                &k_id.sk,
                &keygen_digest(&digest, &wrong),
                CONTEXT_KEYGEN_SIDE,
            )
            .unwrap(),
            tag_k: wrong,
        };

        assert_eq!(
            confirm(&mut encap, &k_id.vk, &proof),
            Err(CryptoError::KeyConfirmationFailed)
        );
        assert!(!encap.is_awaiting_peer_confirmation(), "failed closed");
        assert!(!can_send(&mut encap));
        assert_eq!(
            confirm(&mut encap, &k_id.vk, &proof),
            Err(CryptoError::InvalidState)
        );
    });
}

/// Confirmation keys are separated by role: the encapsulating side's tag, presented by an
/// authenticated key-generating side as its own, does not verify.
#[test]
fn confirmation_keys_and_labels_are_separated_by_role() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let reply = reply(&mut encap, &e_id, &k_id.vk, ek.clone(), xk.clone());

        let binding = handshake_binding(
            &ek,
            &xk,
            &identity_fingerprint(&k_id.vk),
            &identity_fingerprint(&e_id.vk),
            APP,
        )
        .unwrap();
        let transcript = transcript_hash(&binding, &reply.ct, &reply.xe);
        let digest = encapsulator_digest(&transcript, &reply.tag_e);
        let reflected = Proof {
            sig_k: ml_dsa_sign_with_context(
                &k_id.sk,
                &keygen_digest(&digest, &reply.tag_e),
                CONTEXT_KEYGEN_SIDE,
            )
            .unwrap(),
            tag_k: reply.tag_e,
        };
        assert_eq!(
            confirm(&mut encap, &k_id.vk, &reflected),
            Err(CryptoError::KeyConfirmationFailed)
        );

        // The labels alone already separate the roles for any fixed key and digest.
        let key = [0x11u8; 48];
        assert_ne!(
            confirmation_tag(&key, CONFIRM_LABEL_ENCAPSULATING_SIDE, &digest).unwrap(),
            confirmation_tag(&key, CONFIRM_LABEL_KEYGEN_SIDE, &digest).unwrap()
        );
    });
}

#[test]
fn repeated_and_out_of_order_messages_are_refused_without_side_effects() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let mut idle = SessionManager::new();
        let blank = Proof {
            sig_k: blank_signature(),
            tag_k: [0; CONFIRMATION_TAG_LEN],
        };
        assert_eq!(
            confirm(&mut idle, &k_id.vk, &blank),
            Err(CryptoError::InvalidState),
            "confirm before any encapsulation"
        );
        let early = Reply {
            ct: Ciphertext1024([0; 1568]),
            xe: X25519Public([2; 32]),
            sig_e: blank_signature(),
            tag_e: [0; CONFIRMATION_TAG_LEN],
        };
        assert_eq!(
            finalize(&mut idle, &k_id, &e_id.vk, &early).map(|_| ()),
            Err(CryptoError::InvalidState),
            "finalize before any initiate_handshake"
        );

        let (mut keygen, mut encap, reply, proof) = established(&k_id, &e_id, 0x11);
        for text in [&b"one"[..], b"two", b"three"] {
            assert_eq!(send(&mut keygen, &mut encap, text).unwrap(), text);
        }
        // A second confirmation, a second finalize and a replayed reply change nothing, and in
        // particular cannot reset the counters or the keys of a live session.
        assert_eq!(
            confirm(&mut encap, &k_id.vk, &proof),
            Err(CryptoError::InvalidState)
        );
        assert_eq!(
            finalize(&mut keygen, &k_id, &e_id.vk, &reply).map(|_| ()),
            Err(CryptoError::InvalidState)
        );
        assert_eq!(send(&mut keygen, &mut encap, b"four").unwrap(), b"four");
        let (mut nonce, mut tag, mut ct) = ([0u8; 12], [0u8; AEAD_TAG_SIZE], [0u8; 1]);
        keygen
            .encrypt_packet(b"", b"x", &mut ct, &mut nonce, &mut tag)
            .unwrap();
        assert_eq!(&nonce[..8], &4u64.to_le_bytes(), "the counter kept running");
    });
}

#[test]
fn an_abandoned_handshake_clears_state_and_a_new_one_recovers() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let _lost = reply(&mut encap, &e_id, &k_id.vk, ek, xk);

        // The final flight never arrives; the host times out and abandons the session.
        encap.zeroize_session();
        keygen.zeroize_session();
        assert!(!encap.is_awaiting_peer_confirmation());
        assert!(!can_send(&mut encap) && !can_send(&mut keygen));

        let (mut keygen, mut encap, _, _) = established(&k_id, &e_id, 0x21);
        assert_eq!(
            send(&mut keygen, &mut encap, b"recovered").unwrap(),
            b"recovered"
        );
    });
}

#[test]
fn matching_inputs_give_a_working_channel_while_a_confirmation_failure_never_does() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        // Positive: a confirmed session authenticates traffic in both directions.
        let (mut keygen, mut encap, _, _) = established(&k_id, &e_id, 0x11);
        assert_eq!(send(&mut keygen, &mut encap, b"a").unwrap(), b"a");
        assert_eq!(send(&mut encap, &mut keygen, b"b").unwrap(), b"b");

        // Negative: whatever mismatched, no confirmed session exists afterwards.
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x12);
        let reply = reply_with(&mut encap, &e_id, &k_id.vk, ek, xk, 0x23, b"x", APP);
        assert!(finalize_with(&mut keygen, &k_id, &e_id.vk, &reply, b"y", APP).is_err());
        assert!(send(&mut encap, &mut keygen, b"c").is_err());
        assert!(send(&mut keygen, &mut encap, b"d").is_err());
    });
}

#[test]
fn the_binding_and_digests_depend_on_every_input() {
    big_stack(|| {
        let ek = shawncore_pq_crypto::ml_kem_wrapper::ml_kem_keygen(&[0x33; 64])
            .unwrap()
            .0;
        let other_ek = shawncore_pq_crypto::ml_kem_wrapper::ml_kem_keygen(&[0x34; 64])
            .unwrap()
            .0;
        let (xk, fp_k, fp_e) = (X25519Public([1; 32]), [2u8; 48], [3u8; 48]);
        let base = handshake_binding(&ek, &xk, &fp_k, &fp_e, b"info").unwrap();

        let variants = [
            handshake_binding(&other_ek, &xk, &fp_k, &fp_e, b"info").unwrap(),
            handshake_binding(&ek, &X25519Public([9; 32]), &fp_k, &fp_e, b"info").unwrap(),
            handshake_binding(&ek, &xk, &[9u8; 48], &fp_e, b"info").unwrap(),
            handshake_binding(&ek, &xk, &fp_k, &[9u8; 48], b"info").unwrap(),
            handshake_binding(&ek, &xk, &fp_k, &fp_e, b"infp").unwrap(),
            handshake_binding(&ek, &xk, &fp_e, &fp_k, b"info").unwrap(),
        ];
        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(*variant, base, "variant {index}");
        }

        let ct = Ciphertext1024([5; 1568]);
        let xe = X25519Public([6; 32]);
        let t = transcript_hash(&base, &ct, &xe);
        assert_ne!(t, transcript_hash(&variants[0], &ct, &xe));
        assert_ne!(t, transcript_hash(&base, &Ciphertext1024([7; 1568]), &xe));
        assert_ne!(t, transcript_hash(&base, &ct, &X25519Public([8; 32])));

        let tag: Tag = [4; CONFIRMATION_TAG_LEN];
        let digest = encapsulator_digest(&t, &tag);
        assert_ne!(digest, encapsulator_digest(&t, &[5; CONFIRMATION_TAG_LEN]));
        assert_ne!(digest, encapsulator_digest(&base, &tag));
        assert_ne!(
            keygen_digest(&digest, &tag),
            keygen_digest(&digest, &[6; CONFIRMATION_TAG_LEN])
        );
    });
}
