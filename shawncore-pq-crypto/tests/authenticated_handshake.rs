// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Active-attacker tests for the authenticated handshake (signed ML-DSA-87 transcript).
//!
//! These are behavioral negative tests, not a security proof. See SECURITY.md section 10.

#![cfg(feature = "ml-dsa")]

use shawncore_pq_crypto::aead_wrapper::AEAD_TAG_SIZE;
use shawncore_pq_crypto::auth_handshake::{
    handshake_binding, identity_fingerprint, transcript_hash, CONTEXT_KEYGEN_SIDE,
};
use shawncore_pq_crypto::error::CryptoError;
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_dsa_wrapper::{
    ml_dsa_keygen, ml_dsa_sign_with_context, PublicKey87, Signature87, SigningKey87,
};
use shawncore_pq_crypto::ml_kem_wrapper::{Ciphertext1024, PublicKey1024};
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::X25519Public;

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

/// The first message and the encapsulating side's reply.
struct Flow {
    ek: PublicKey1024,
    xk: X25519Public,
    ct: Ciphertext1024,
    xe: X25519Public,
    sig_e: Signature87,
}

fn start_keygen(keygen: &mut SessionManager, seed: u8) -> (PublicKey1024, X25519Public) {
    keygen.initiate_handshake(&[seed; 96]).unwrap()
}

fn reply(
    encap: &mut SessionManager,
    own: &Identity,
    keygen_vk: &PublicKey87,
    ek: PublicKey1024,
    xk: X25519Public,
    app_info: &[u8],
) -> Flow {
    let mut ct = Ciphertext1024([0; 1568]);
    let mut xe = X25519Public([0; 32]);
    let mut sig_e = blank_signature();
    encap
        .encapsulate_authenticated(
            &own.sk,
            keygen_vk,
            &ek,
            &xk,
            &[0x22; 64],
            b"salt",
            app_info,
            &mut ct,
            &mut xe,
            &mut sig_e,
        )
        .expect("encapsulate_authenticated");
    Flow {
        ek,
        xk,
        ct,
        xe,
        sig_e,
    }
}

fn finalize(
    keygen: &mut SessionManager,
    own: &Identity,
    trusted_peer: &PublicKey87,
    flow: &Flow,
    app_info: &[u8],
) -> Result<Signature87, CryptoError> {
    let mut sig_k = blank_signature();
    keygen
        .finalize_authenticated(
            &own.sk,
            trusted_peer,
            &flow.xe,
            &flow.ct,
            &flow.sig_e,
            b"salt",
            app_info,
            &mut sig_k,
        )
        .map(|()| sig_k)
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

#[test]
fn mutual_authentication_completes_and_traffic_flows_both_ways() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let flow = reply(&mut encap, &e_id, &k_id.vk, ek, xk, b"app");
        assert!(encap.is_awaiting_peer_confirmation());

        let sig_k = finalize(&mut keygen, &k_id, &e_id.vk, &flow, b"app").unwrap();
        // Until the key-generating side proves itself, the encapsulating side stays shut.
        assert!(send(&mut keygen, &mut encap, b"too early").is_err());
        assert_eq!(
            send(&mut encap, &mut keygen, b"too early"),
            Err(CryptoError::InvalidState)
        );

        encap.confirm_peer(&k_id.vk, &sig_k).unwrap();
        assert!(!encap.is_awaiting_peer_confirmation());
        assert_eq!(send(&mut keygen, &mut encap, b"hello").unwrap(), b"hello");
        assert_eq!(send(&mut encap, &mut keygen, b"world").unwrap(), b"world");
    });
}

#[test]
fn an_active_intermediary_with_its_own_identity_is_rejected() {
    big_stack(|| {
        let (k_id, e_id, m_id) = (identity(0x41), identity(0x42), identity(0x4D));
        let (mut keygen, mut mitm, mut encap) = (
            SessionManager::new(),
            SessionManager::new(),
            SessionManager::new(),
        );
        let (ek, xk) = start_keygen(&mut keygen, 0x11);

        // The intermediary answers the key-generating side as if it were the genuine peer.
        let forged = reply(&mut mitm, &m_id, &k_id.vk, ek.clone(), xk.clone(), b"app");
        assert_eq!(
            finalize(&mut keygen, &k_id, &e_id.vk, &forged, b"app").map(|_| ()),
            Err(CryptoError::VerificationFailed)
        );

        // The pending handshake survives, so the genuine reply still works.
        let genuine = reply(&mut encap, &e_id, &k_id.vk, ek, xk, b"app");
        assert!(finalize(&mut keygen, &k_id, &e_id.vk, &genuine, b"app").is_ok());
    });
}

#[test]
fn every_tampered_reply_field_is_rejected_without_consuming_the_handshake() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let genuine = reply(&mut encap, &e_id, &k_id.vk, ek, xk, b"app");

        let copy = |f: &Flow| Flow {
            ek: f.ek.clone(),
            xk: f.xk.clone(),
            ct: f.ct.clone(),
            xe: f.xe.clone(),
            sig_e: f.sig_e.clone(),
        };

        let mut bad_ct = copy(&genuine);
        bad_ct.ct.0[0] ^= 1;
        let mut bad_xe = copy(&genuine);
        bad_xe.xe.0[0] ^= 1;
        let mut bad_sig = copy(&genuine);
        bad_sig.sig_e.0[100] ^= 1;

        for (name, flow, app) in [
            ("ciphertext", &bad_ct, &b"app"[..]),
            ("encapsulator x25519 key", &bad_xe, b"app"),
            ("signature", &bad_sig, b"app"),
            ("application info", &genuine, b"other"),
        ] {
            assert_eq!(
                finalize(&mut keygen, &k_id, &e_id.vk, flow, app).map(|_| ()),
                Err(CryptoError::VerificationFailed),
                "{name}"
            );
        }
        assert!(finalize(&mut keygen, &k_id, &e_id.vk, &genuine, b"app").is_ok());
    });
}

#[test]
fn the_wrong_trust_anchor_rejects_a_genuine_reply() {
    big_stack(|| {
        let (k_id, e_id, other) = (identity(0x41), identity(0x42), identity(0x4D));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let flow = reply(&mut encap, &e_id, &k_id.vk, ek, xk, b"app");
        assert_eq!(
            finalize(&mut keygen, &k_id, &other.vk, &flow, b"app").map(|_| ()),
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
        let flow = reply(&mut encap, &e_id, &k_id.vk, ek.clone(), xk.clone(), b"app");
        let genuine_sig_k = finalize(&mut keygen, &k_id, &e_id.vk, &flow, b"app").unwrap();

        // The transcript is public, so the intermediary can sign it with its own key.
        let binding = handshake_binding(
            &ek,
            &xk,
            &identity_fingerprint(&k_id.vk),
            &identity_fingerprint(&e_id.vk),
            b"app",
        )
        .unwrap();
        let transcript = transcript_hash(&binding, &flow.ct, &flow.xe);
        let forged = ml_dsa_sign_with_context(&m_id.sk, &transcript, CONTEXT_KEYGEN_SIDE).unwrap();

        assert_eq!(
            encap.confirm_peer(&k_id.vk, &forged),
            Err(CryptoError::VerificationFailed),
            "a forged signature under the pinned identity"
        );
        assert_eq!(
            encap.confirm_peer(&m_id.vk, &forged),
            Err(CryptoError::VerificationFailed),
            "a valid signature from a different identity"
        );
        assert!(encap.is_awaiting_peer_confirmation());
        assert!(send(&mut keygen, &mut encap, b"nope").is_err());

        encap.confirm_peer(&k_id.vk, &genuine_sig_k).unwrap();
        assert_eq!(send(&mut keygen, &mut encap, b"yes").unwrap(), b"yes");
    });
}

#[test]
fn role_contexts_stop_one_sides_signature_standing_in_for_the_other() {
    big_stack(|| {
        // One key on both sides, so only the FIPS 204 context string can tell the roles apart.
        let shared = identity(0x43);
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let flow = reply(
            &mut encap,
            &shared,
            &shared.vk,
            ek.clone(),
            xk.clone(),
            b"app",
        );

        // The encapsulating side's signature reflected back as the keygen proof.
        assert_eq!(
            encap.confirm_peer(&shared.vk, &flow.sig_e),
            Err(CryptoError::VerificationFailed)
        );

        // The keygen-role signature over the same transcript offered as the encapsulating one.
        let binding = handshake_binding(
            &ek,
            &xk,
            &identity_fingerprint(&shared.vk),
            &identity_fingerprint(&shared.vk),
            b"app",
        )
        .unwrap();
        let transcript = transcript_hash(&binding, &flow.ct, &flow.xe);
        let wrong_role = Flow {
            sig_e: ml_dsa_sign_with_context(&shared.sk, &transcript, CONTEXT_KEYGEN_SIDE).unwrap(),
            ..flow
        };
        assert_eq!(
            finalize(&mut keygen, &shared, &shared.vk, &wrong_role, b"app").map(|_| ()),
            Err(CryptoError::VerificationFailed)
        );
    });
}

#[test]
fn a_reply_recorded_from_an_earlier_handshake_does_not_verify_in_a_new_one() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let (mut keygen, mut encap) = (SessionManager::new(), SessionManager::new());
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        let recorded = reply(&mut encap, &e_id, &k_id.vk, ek, xk, b"app");

        let mut fresh = SessionManager::new();
        start_keygen(&mut fresh, 0x99); // a new ephemeral key pair
        assert_eq!(
            finalize(&mut fresh, &k_id, &e_id.vk, &recorded, b"app").map(|_| ()),
            Err(CryptoError::VerificationFailed)
        );
    });
}

#[test]
fn calls_out_of_order_fail_without_side_effects() {
    big_stack(|| {
        let (k_id, e_id) = (identity(0x41), identity(0x42));
        let mut idle = SessionManager::new();
        let sig = blank_signature();
        assert_eq!(
            idle.confirm_peer(&k_id.vk, &sig),
            Err(CryptoError::InvalidState)
        );
        let flow = Flow {
            ek: ml_kem_pk(),
            xk: X25519Public([1; 32]),
            ct: Ciphertext1024([0; 1568]),
            xe: X25519Public([2; 32]),
            sig_e: blank_signature(),
        };
        assert_eq!(
            finalize(&mut idle, &k_id, &e_id.vk, &flow, b"app").map(|_| ()),
            Err(CryptoError::InvalidState)
        );

        // An unconfirmed session can be abandoned, after which nothing is pending.
        let mut encap = SessionManager::new();
        let mut keygen = SessionManager::new();
        let (ek, xk) = start_keygen(&mut keygen, 0x11);
        reply(&mut encap, &e_id, &k_id.vk, ek, xk, b"app");
        encap.zeroize_session();
        assert!(!encap.is_awaiting_peer_confirmation());
        assert_eq!(
            encap.confirm_peer(&k_id.vk, &sig),
            Err(CryptoError::InvalidState)
        );
    });
}

fn ml_kem_pk() -> PublicKey1024 {
    shawncore_pq_crypto::ml_kem_wrapper::ml_kem_keygen(&[0x33; 64])
        .unwrap()
        .0
}

#[test]
fn the_binding_and_transcript_depend_on_every_input() {
    big_stack(|| {
        let ek = ml_kem_pk();
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
    });
}
