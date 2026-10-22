// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Exhaustive attacker-choice conformance test for the authenticated handshake, version 2.
//!
//! For every combination of attacker-controlled fields in the key-generating side's input (and in
//! the encapsulating side's confirmation), the implementation must give the outcome that a small
//! executable specification predicts: acceptance only when everything is genuine, a signature
//! failure for any altered or forged field, a key-confirmation failure only for an authentic
//! exchange whose salt differs, and, after any rejected forgery, a pending handshake that the
//! genuine message still completes. The specification mirrors the symbolic model in
//! `validation/formal/handshake_model.py`. This is bounded testing of the real code over a finite
//! set of attacker choices; it is not a proof and not a formal verification.

#![cfg(feature = "ml-dsa")]

use shawncore_pq_crypto::auth_handshake::{
    encapsulator_digest, handshake_binding, identity_fingerprint, transcript_hash,
    CONFIRMATION_TAG_LEN, CONTEXT_ENCAPSULATING_SIDE, CONTEXT_KEYGEN_SIDE,
};
use shawncore_pq_crypto::error::CryptoError;
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_dsa_wrapper::{
    ml_dsa_keygen, ml_dsa_sign_with_context, PublicKey87, Signature87, SigningKey87,
};
use shawncore_pq_crypto::ml_kem_wrapper::{ml_kem_encapsulate, Ciphertext1024, PublicKey1024};
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::{x25519_keygen, X25519Public};

type Tag = [u8; CONFIRMATION_TAG_LEN];

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

struct Identity {
    vk: PublicKey87,
    sk: SigningKey87,
}

fn identity(seed: u8) -> Identity {
    let (vk, sk) = ml_dsa_keygen(&[seed; 32]).unwrap();
    Identity { vk, sk }
}

#[derive(Clone)]
struct Reply {
    ct: Ciphertext1024,
    xe: X25519Public,
    sig: Signature87,
    tag: Tag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Accept,
    KeyConfirmation,
    Signature,
}

const SALT: &[u8] = b"salt";
const APP: &[u8] = b"app";

fn start(seed: u8) -> (SessionManager, PublicKey1024, X25519Public) {
    let mut keygen = SessionManager::new();
    let (ek, xk) = keygen.initiate_handshake(&[seed; 96]).unwrap();
    (keygen, ek, xk)
}

fn reply(
    e_id: &Identity,
    k_vk: &PublicKey87,
    ek: &PublicKey1024,
    xk: &X25519Public,
    entropy: u8,
) -> Reply {
    let mut encap = SessionManager::new();
    let mut ct = Ciphertext1024([0; 1568]);
    let mut xe = X25519Public([0; 32]);
    let mut sig = Signature87([0; 4627]);
    let mut tag = [0u8; CONFIRMATION_TAG_LEN];
    encap
        .encapsulate_authenticated(
            &e_id.sk,
            k_vk,
            ek,
            xk,
            &[entropy; 64],
            SALT,
            APP,
            &mut ct,
            &mut xe,
            &mut sig,
            &mut tag,
        )
        .unwrap();
    Reply { ct, xe, sig, tag }
}

fn finalize(
    keygen: &mut SessionManager,
    k_id: &Identity,
    e_vk: &PublicKey87,
    r: &Reply,
    salt: &[u8],
    app: &[u8],
) -> Result<(Signature87, Tag), CryptoError> {
    let mut sig_k = Signature87([0; 4627]);
    let mut tag_k = [0u8; CONFIRMATION_TAG_LEN];
    keygen
        .finalize_authenticated(
            &k_id.sk, e_vk, &r.xe, &r.ct, &r.sig, &r.tag, salt, app, &mut sig_k, &mut tag_k,
        )
        .map(|()| (sig_k, tag_k))
}

fn can_send(session: &mut SessionManager) -> bool {
    let (mut ct, mut nonce, mut tag) = ([0u8; 4], [0u8; 12], [0u8; 48]);
    session
        .encrypt_packet(b"", b"data", &mut ct, &mut nonce, &mut tag)
        .is_ok()
}

fn classify(result: &Result<(Signature87, Tag), CryptoError>) -> Expected {
    match result {
        Ok(_) => Expected::Accept,
        Err(CryptoError::KeyConfirmationFailed) => Expected::KeyConfirmation,
        Err(CryptoError::VerificationFailed) => Expected::Signature,
        Err(other) => panic!("unexpected error class {other:?}"),
    }
}

#[test]
fn every_attacker_choice_on_the_key_generating_side_matches_the_specification() {
    std::thread::Builder::new()
        .stack_size(128 << 20)
        .spawn(|| {
            unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
            let (k_id, e_id, m_id) = (identity(0x41), identity(0x42), identity(0x4D));
            let (_, ek, xk) = start(0x11);
            let genuine = reply(&e_id, &k_id.vk, &ek, &xk, 0x22);
            let other = reply(&e_id, &k_id.vk, &ek, &xk, 0x23); // a second, different E session

            // Attacker-made values: an encapsulation under the public key with known entropy, an
            // X25519 key it holds the secret for, and bit-flipped copies.
            let (_, ct_attacker) = ml_kem_encapsulate(&ek, &[0x66; 32]).unwrap();
            let (xe_attacker, _) = x25519_keygen(&[0x77; 32]);
            let mut ct_flipped = genuine.ct.clone();
            ct_flipped.0[5] ^= 1;
            let mut xe_flipped = genuine.xe.clone();
            xe_flipped.0[3] ^= 1;

            let cts = [
                ("genuine", genuine.ct.clone()),
                ("other session", other.ct.clone()),
                ("attacker made", ct_attacker),
                ("bit flipped", ct_flipped),
            ];
            let xes = [
                ("genuine", genuine.xe.clone()),
                ("attacker key", xe_attacker),
                ("bit flipped", xe_flipped),
            ];
            let tags: [(&str, Tag); 3] = [
                ("genuine", genuine.tag),
                ("other session", other.tag),
                ("zero", [0; CONFIRMATION_TAG_LEN]),
            ];
            let k_fp = identity_fingerprint(&k_id.vk);
            let e_fp = identity_fingerprint(&e_id.vk);

            let mut combinations = 0usize;
            let mut seen = std::collections::BTreeMap::<&'static str, usize>::new();
            for (ct_name, ct) in &cts {
                for (xe_name, xe) in &xes {
                    for (tag_name, tag) in &tags {
                        // The signature an attacker could present: the genuine one, one from the
                        // other session, one it makes itself over the correct digest for these
                        // fields (wrong key), and zeros.
                        let binding = handshake_binding(&ek, &xk, &k_fp, &e_fp, APP).unwrap();
                        let digest = encapsulator_digest(&transcript_hash(&binding, ct, xe), tag);
                        let forged = ml_dsa_sign_with_context(
                            &m_id.sk, &digest, CONTEXT_ENCAPSULATING_SIDE,
                        )
                        .unwrap();
                        let sigs = [
                            ("genuine", genuine.sig.clone()),
                            ("other session", other.sig.clone()),
                            ("attacker signed", forged),
                            ("zero", Signature87([0; 4627])),
                        ];
                        for (sig_name, sig) in &sigs {
                            for (salt_name, salt) in [("same", SALT), ("different", &b"salt2"[..])] {
                                for (app_name, app) in [("same", APP), ("different", &b"app2"[..])] {
                                    let everything_genuine = *ct_name == "genuine"
                                        && *xe_name == "genuine"
                                        && *tag_name == "genuine"
                                        && *sig_name == "genuine"
                                        && app_name == "same";
                                    let expected = match (everything_genuine, salt_name) {
                                        (true, "same") => Expected::Accept,
                                        (true, _) => Expected::KeyConfirmation,
                                        _ => Expected::Signature,
                                    };
                                    let case = format!(
                                        "ct={ct_name} xe={xe_name} tag={tag_name} sig={sig_name} salt={salt_name} app={app_name}"
                                    );

                                    let (mut keygen, ..) = start(0x11);
                                    let candidate = Reply {
                                        ct: ct.clone(),
                                        xe: xe.clone(),
                                        sig: sig.clone(),
                                        tag: *tag,
                                    };
                                    let result =
                                        finalize(&mut keygen, &k_id, &e_id.vk, &candidate, salt, app);
                                    let outcome = classify(&result);
                                    assert_eq!(outcome, expected, "{case}");
                                    *seen.entry(match outcome {
                                        Expected::Accept => "accepted",
                                        Expected::KeyConfirmation => "key confirmation failed",
                                        Expected::Signature => "signature rejected",
                                    })
                                    .or_default() += 1;

                                    match outcome {
                                        Expected::Accept => assert!(can_send(&mut keygen), "{case}"),
                                        Expected::KeyConfirmation => {
                                            assert!(!can_send(&mut keygen), "{case}: nothing installed");
                                            // Fail closed: the pending handshake is gone.
                                            assert_eq!(
                                                finalize(&mut keygen, &k_id, &e_id.vk, &genuine, SALT, APP)
                                                    .map(|_| ()),
                                                Err(CryptoError::InvalidState),
                                                "{case}"
                                            );
                                        }
                                        Expected::Signature => {
                                            assert!(!can_send(&mut keygen), "{case}");
                                            // A forgery consumed nothing: the genuine reply works.
                                            assert!(
                                                finalize(&mut keygen, &k_id, &e_id.vk, &genuine, SALT, APP)
                                                    .is_ok(),
                                                "{case}: the pending handshake was consumed"
                                            );
                                        }
                                    }
                                    combinations += 1;
                                }
                            }
                        }
                    }
                }
            }
            assert_eq!(combinations, 4 * 3 * 3 * 4 * 2 * 2);
            assert_eq!(seen.len(), 3, "every outcome class must be exercised: {seen:?}");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn every_attacker_choice_on_the_confirming_side_matches_the_specification() {
    std::thread::Builder::new()
        .stack_size(128 << 20)
        .spawn(|| {
            unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
            let (k_id, e_id, m_id) = (identity(0x41), identity(0x42), identity(0x4D));

            // One complete exchange gives the genuine proof and an unrelated second session gives
            // a proof that is valid elsewhere.
            let run = |seed: u8| {
                let (mut keygen, ek, xk) = start(seed);
                let mut encap = SessionManager::new();
                let mut ct = Ciphertext1024([0; 1568]);
                let mut xe = X25519Public([0; 32]);
                let mut sig = Signature87([0; 4627]);
                let mut tag = [0u8; CONFIRMATION_TAG_LEN];
                encap
                    .encapsulate_authenticated(
                        &e_id.sk,
                        &k_id.vk,
                        &ek,
                        &xk,
                        &[seed ^ 0x33; 64],
                        SALT,
                        APP,
                        &mut ct,
                        &mut xe,
                        &mut sig,
                        &mut tag,
                    )
                    .unwrap();
                let r = Reply { ct, xe, sig, tag };
                let proof = finalize(&mut keygen, &k_id, &e_id.vk, &r, SALT, APP).unwrap();
                (encap, ek, xk, r, proof)
            };
            let (_, _, _, _, other_proof) = run(0x31);
            let genuine_proof = run(0x11).4;
            let tags: [(&str, Tag); 3] = [
                ("genuine", genuine_proof.1),
                ("other session", other_proof.1),
                ("zero", [0; CONFIRMATION_TAG_LEN]),
            ];

            let mut combinations = 0usize;
            for (tag_name, tag) in &tags {
                for sig_name in ["genuine", "other session", "attacker signed", "zero"] {
                    for (anchor_name, anchor_is_k) in [("K", true), ("M", false)] {
                        let (mut encap, ek, xk, r, _) = run(0x11);
                        let anchor = if anchor_is_k { &k_id.vk } else { &m_id.vk };
                        let sig = match sig_name {
                            "genuine" => genuine_proof.0.clone(),
                            "other session" => other_proof.0.clone(),
                            "zero" => Signature87([0; 4627]),
                            _ => {
                                let binding = handshake_binding(
                                    &ek,
                                    &xk,
                                    &identity_fingerprint(&k_id.vk),
                                    &identity_fingerprint(&e_id.vk),
                                    APP,
                                )
                                .unwrap();
                                let the = encapsulator_digest(
                                    &transcript_hash(&binding, &r.ct, &r.xe),
                                    &r.tag,
                                );
                                let digest =
                                    shawncore_pq_crypto::auth_handshake::keygen_digest(&the, tag);
                                ml_dsa_sign_with_context(&m_id.sk, &digest, CONTEXT_KEYGEN_SIDE)
                                    .unwrap()
                            }
                        };
                        let accepts =
                            *tag_name == "genuine" && sig_name == "genuine" && anchor_is_k;
                        let case = format!("tag={tag_name} sig={sig_name} anchor={anchor_name}");
                        let result = encap.confirm_peer(anchor, &sig, tag);
                        assert_eq!(result.is_ok(), accepts, "{case}: {result:?}");
                        if accepts {
                            assert!(can_send(&mut encap), "{case}");
                        } else {
                            assert_eq!(result, Err(CryptoError::VerificationFailed), "{case}");
                            assert!(encap.is_awaiting_peer_confirmation(), "{case}");
                            assert!(
                                !can_send(&mut encap),
                                "{case}: unconfirmed sessions stay silent"
                            );
                            // The forgery consumed nothing: the genuine proof still confirms.
                            assert!(
                                encap
                                    .confirm_peer(&k_id.vk, &genuine_proof.0, &genuine_proof.1)
                                    .is_ok(),
                                "{case}"
                            );
                        }
                        combinations += 1;
                    }
                }
            }
            assert_eq!(combinations, 3 * 4 * 2);
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Documented limitation, pinned so it cannot change silently: the first message is not
/// authenticated, so an encapsulating manager that is handed a second first message replaces its
/// pending handshake. The host must use one manager per attempt (see SECURITY.md section 10).
#[test]
fn a_second_unauthenticated_first_message_evicts_the_pending_handshake() {
    std::thread::Builder::new()
        .stack_size(128 << 20)
        .spawn(|| {
            unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
            let (k_id, e_id) = (identity(0x41), identity(0x42));
            let (mut keygen, ek, xk) = start(0x11);
            let mut encap = SessionManager::new();
            let (mut ct, mut xe) = (Ciphertext1024([0; 1568]), X25519Public([0; 32]));
            let (mut sig, mut tag) = (Signature87([0; 4627]), [0u8; CONFIRMATION_TAG_LEN]);
            encap
                .encapsulate_authenticated(
                    &e_id.sk,
                    &k_id.vk,
                    &ek,
                    &xk,
                    &[0x22; 64],
                    SALT,
                    APP,
                    &mut ct,
                    &mut xe,
                    &mut sig,
                    &mut tag,
                )
                .unwrap();
            let genuine = Reply { ct, xe, sig, tag };
            let proof = finalize(&mut keygen, &k_id, &e_id.vk, &genuine, SALT, APP).unwrap();

            // The attacker injects its own first message before the genuine proof arrives.
            let (_, attacker_ek, attacker_xk) = start(0x66);
            let (mut ct2, mut xe2) = (Ciphertext1024([0; 1568]), X25519Public([0; 32]));
            let (mut sig2, mut tag2) = (Signature87([0; 4627]), [0u8; CONFIRMATION_TAG_LEN]);
            encap
                .encapsulate_authenticated(
                    &e_id.sk,
                    &k_id.vk,
                    &attacker_ek,
                    &attacker_xk,
                    &[0x23; 64],
                    SALT,
                    APP,
                    &mut ct2,
                    &mut xe2,
                    &mut sig2,
                    &mut tag2,
                )
                .unwrap();

            // The genuine proof no longer confirms, and nothing unauthenticated was accepted.
            assert_eq!(
                encap.confirm_peer(&k_id.vk, &proof.0, &proof.1),
                Err(CryptoError::VerificationFailed)
            );
            assert!(!can_send(&mut encap));
        })
        .unwrap()
        .join()
        .unwrap();
}
