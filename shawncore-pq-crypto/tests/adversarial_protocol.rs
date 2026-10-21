// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Active-attacker tests against the session handshake and packet protection.
//!
//! These are negative, behavioral tests through the public Rust API. They are not
//! known-answer tests and prove nothing about constant-time behavior.

use shawncore_pq_crypto::aead_wrapper::AEAD_TAG_SIZE;
use shawncore_pq_crypto::error::CryptoError;
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_kem_wrapper::Ciphertext1024;
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::X25519Public;

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

// An unregistered cache-flush callback halts by design, so every test registers one.
fn setup() {
    unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
}

struct Packet {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; AEAD_TAG_SIZE],
}

/// Returns `(keygen_side, encap_side)` with an established session.
fn established_pair(keygen_seed: u8, encap_seed: u8) -> (SessionManager, SessionManager) {
    let mut keygen_side = SessionManager::new();
    let mut encap_side = SessionManager::new();
    let (pk, x_pk) = keygen_side
        .initiate_handshake(&[keygen_seed; 96])
        .expect("initiate");
    let mut ct = Ciphertext1024([0; 1568]);
    let mut my_pk = X25519Public([0; 32]);
    encap_side
        .encapsulate_for_peer(
            &pk,
            &x_pk,
            &[encap_seed; 64],
            b"salt",
            b"info",
            &mut ct,
            &mut my_pk,
        )
        .expect("encapsulate");
    keygen_side
        .finalize_handshake(&my_pk, &ct, b"salt", b"info")
        .expect("finalize");
    (keygen_side, encap_side)
}

fn seal(sender: &mut SessionManager, aad: &[u8], plaintext: &[u8]) -> Packet {
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    sender
        .encrypt_packet(aad, plaintext, &mut ciphertext, &mut nonce, &mut tag)
        .expect("encrypt");
    Packet {
        ciphertext,
        nonce,
        tag,
    }
}

fn open(
    receiver: &mut SessionManager,
    aad: &[u8],
    packet: &Packet,
) -> Result<Vec<u8>, CryptoError> {
    let mut plaintext = vec![0xAAu8; packet.ciphertext.len()];
    receiver
        .decrypt_packet(
            aad,
            &packet.ciphertext,
            &packet.nonce,
            &packet.tag,
            &mut plaintext,
        )
        .map(|()| plaintext)
}

fn nonce_for(sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&sequence.to_le_bytes());
    nonce
}

#[test]
fn established_session_round_trips_in_both_directions() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);

    let to_a = seal(&mut b, b"hdr", b"from b");
    assert_eq!(open(&mut a, b"hdr", &to_a).unwrap(), b"from b");
    let to_b = seal(&mut a, b"hdr", b"from a");
    assert_eq!(open(&mut b, b"hdr", &to_b).unwrap(), b"from a");
}

#[test]
fn reflected_packet_is_rejected_by_its_own_sender() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);

    let from_a = seal(&mut a, b"", b"reflect me");
    assert_eq!(
        open(&mut a, b"", &from_a),
        Err(CryptoError::VerificationFailed)
    );
    let from_b = seal(&mut b, b"", b"reflect me");
    assert_eq!(
        open(&mut b, b"", &from_b),
        Err(CryptoError::VerificationFailed)
    );
}

#[test]
fn duplicate_packet_is_accepted_once() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let packet = seal(&mut a, b"", b"once");

    assert!(open(&mut b, b"", &packet).is_ok());
    assert_eq!(open(&mut b, b"", &packet), Err(CryptoError::InvalidState));
}

#[test]
fn reordered_packets_inside_the_window_are_accepted_once_each() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let packets: Vec<Packet> = (0..8u8).map(|i| seal(&mut a, b"", &[i; 4])).collect();

    for index in [7usize, 3, 5, 0, 6, 1, 4, 2] {
        assert_eq!(
            open(&mut b, b"", &packets[index]).unwrap(),
            vec![index as u8; 4]
        );
    }
    for packet in &packets {
        assert_eq!(open(&mut b, b"", packet), Err(CryptoError::InvalidState));
    }
}

#[test]
fn packets_older_than_the_window_are_rejected_even_when_authentic() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let packets: Vec<Packet> = (0..70u8).map(|i| seal(&mut a, b"", &[i])).collect();

    assert!(open(&mut b, b"", &packets[69]).is_ok());
    // Offset 63 is the oldest sequence still inside the 64-packet window; 64 is outside.
    assert!(open(&mut b, b"", &packets[6]).is_ok());
    assert_eq!(
        open(&mut b, b"", &packets[5]),
        Err(CryptoError::InvalidState)
    );
}

#[test]
fn forged_tag_does_not_poison_the_replay_window() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let genuine = seal(&mut a, b"aad", b"payload");

    let mut forged = Packet {
        ciphertext: genuine.ciphertext.clone(),
        nonce: genuine.nonce,
        tag: genuine.tag,
    };
    forged.tag[0] ^= 0x01;
    assert_eq!(
        open(&mut b, b"aad", &forged),
        Err(CryptoError::VerificationFailed)
    );
    // The forgery used the genuine sequence number; the real packet must still be accepted.
    assert_eq!(open(&mut b, b"aad", &genuine).unwrap(), b"payload");
}

#[test]
fn forged_far_future_sequence_does_not_slide_the_window() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let first = seal(&mut a, b"", b"first");

    let forged = Packet {
        ciphertext: vec![0u8; 5],
        nonce: nonce_for(1 << 40),
        tag: [0x5A; AEAD_TAG_SIZE],
    };
    assert_eq!(
        open(&mut b, b"", &forged),
        Err(CryptoError::VerificationFailed)
    );
    assert_eq!(open(&mut b, b"", &first).unwrap(), b"first");
}

#[test]
fn every_single_bit_flip_in_ciphertext_aad_nonce_and_tag_is_rejected() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let genuine = seal(&mut a, b"header", b"sixteen byte msg");

    for bit in 0..genuine.ciphertext.len() * 8 {
        let mut p = Packet {
            ciphertext: genuine.ciphertext.clone(),
            nonce: genuine.nonce,
            tag: genuine.tag,
        };
        p.ciphertext[bit / 8] ^= 1 << (bit % 8);
        assert!(open(&mut b, b"header", &p).is_err(), "ciphertext bit {bit}");
    }
    for bit in 0..AEAD_TAG_SIZE * 8 {
        let mut p = Packet {
            ciphertext: genuine.ciphertext.clone(),
            nonce: genuine.nonce,
            tag: genuine.tag,
        };
        p.tag[bit / 8] ^= 1 << (bit % 8);
        assert!(open(&mut b, b"header", &p).is_err(), "tag bit {bit}");
    }
    for bit in 0..12 * 8 {
        let mut p = Packet {
            ciphertext: genuine.ciphertext.clone(),
            nonce: genuine.nonce,
            tag: genuine.tag,
        };
        p.nonce[bit / 8] ^= 1 << (bit % 8);
        assert!(open(&mut b, b"header", &p).is_err(), "nonce bit {bit}");
    }
    for bit in 0..b"header".len() * 8 {
        let mut aad = *b"header";
        aad[bit / 8] ^= 1 << (bit % 8);
        assert!(open(&mut b, &aad, &genuine).is_err(), "aad bit {bit}");
    }
    // None of the failures above may have consumed the genuine sequence number.
    assert_eq!(
        open(&mut b, b"header", &genuine).unwrap(),
        b"sixteen byte msg"
    );
}

#[test]
fn nonce_with_nonzero_reserved_bytes_is_rejected() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let mut packet = seal(&mut a, b"", b"x");
    packet.nonce[11] = 1;
    assert_eq!(open(&mut b, b"", &packet), Err(CryptoError::InvalidState));
}

#[test]
fn truncated_extended_and_mismatched_ciphertexts_are_rejected() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let genuine = seal(&mut a, b"", b"0123456789");

    let truncated = Packet {
        ciphertext: genuine.ciphertext[..9].to_vec(),
        nonce: genuine.nonce,
        tag: genuine.tag,
    };
    assert_eq!(
        open(&mut b, b"", &truncated),
        Err(CryptoError::VerificationFailed)
    );

    let mut extended = genuine.ciphertext.clone();
    extended.push(0);
    let extended = Packet {
        ciphertext: extended,
        nonce: genuine.nonce,
        tag: genuine.tag,
    };
    assert_eq!(
        open(&mut b, b"", &extended),
        Err(CryptoError::VerificationFailed)
    );

    let mut short_out = [0u8; 9];
    assert_eq!(
        b.decrypt_packet(
            b"",
            &genuine.ciphertext,
            &genuine.nonce,
            &genuine.tag,
            &mut short_out
        ),
        Err(CryptoError::InvalidState)
    );
    assert_eq!(open(&mut b, b"", &genuine).unwrap(), b"0123456789");
}

#[test]
fn failed_authentication_never_releases_plaintext() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let genuine = seal(&mut a, b"", b"top secret data");

    let mut forged_tag = genuine.tag;
    forged_tag[47] ^= 0x80;
    let mut out = vec![0xAAu8; genuine.ciphertext.len()];
    assert!(b
        .decrypt_packet(
            b"",
            &genuine.ciphertext,
            &genuine.nonce,
            &forged_tag,
            &mut out
        )
        .is_err());
    assert!(out.iter().all(|&byte| byte == 0), "output must be wiped");

    assert!(open(&mut b, b"", &genuine).is_ok());
    let mut out = vec![0xAAu8; genuine.ciphertext.len()];
    assert!(b
        .decrypt_packet(
            b"",
            &genuine.ciphertext,
            &genuine.nonce,
            &genuine.tag,
            &mut out
        )
        .is_err());
    assert!(
        !out.windows(6).any(|w| w == b"top se"),
        "replay must not expose plaintext"
    );
}

#[test]
fn zero_length_payload_is_authenticated() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let packet = seal(&mut a, b"only aad", b"");
    assert_eq!(open(&mut b, b"only aad", &packet).unwrap(), b"");
    let packet = seal(&mut a, b"only aad", b"");
    assert!(open(&mut b, b"different", &packet).is_err());
}

#[test]
fn packets_from_a_previous_session_are_rejected_after_rekeying() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let old = seal(&mut a, b"", b"old session");
    assert!(open(&mut b, b"", &old).is_ok());

    let (_a2, mut b2) = established_pair(0x33, 0x44);
    assert_eq!(
        open(&mut b2, b"", &old),
        Err(CryptoError::VerificationFailed)
    );
}

/// Documents a host obligation: the library cannot detect that the host replayed entropy.
#[test]
fn reusing_entropy_on_both_sides_repeats_keys_and_accepts_cross_session_replay() {
    setup();
    let (mut a, _b) = established_pair(0x11, 0x22);
    let old = seal(&mut a, b"", b"recorded");

    let (_a2, mut b2) = established_pair(0x11, 0x22);
    assert_eq!(open(&mut b2, b"", &old).unwrap(), b"recorded");
}

#[test]
fn unestablished_and_zeroized_sessions_refuse_traffic() {
    setup();
    let mut idle = SessionManager::new();
    let mut ct = [0u8; 4];
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    assert_eq!(
        idle.encrypt_packet(b"", b"data", &mut ct, &mut nonce, &mut tag),
        Err(CryptoError::InvalidState)
    );
    let mut out = [0u8; 4];
    assert_eq!(
        idle.decrypt_packet(b"", &ct, &nonce, &tag, &mut out),
        Err(CryptoError::InvalidState)
    );

    let (mut a, mut b) = established_pair(0x11, 0x22);
    let packet = seal(&mut a, b"", b"data");
    b.zeroize_session();
    assert_eq!(open(&mut b, b"", &packet), Err(CryptoError::InvalidState));
    a.zeroize_session();
    let mut ct = [0u8; 4];
    assert_eq!(
        a.encrypt_packet(b"", b"data", &mut ct, &mut nonce, &mut tag),
        Err(CryptoError::InvalidState)
    );
}

#[test]
fn finalize_without_a_pending_handshake_fails_and_does_not_disturb_a_live_session() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    let ct = Ciphertext1024([7; 1568]);
    let pk = X25519Public([9; 32]);

    assert_eq!(
        b.finalize_handshake(&pk, &ct, b"salt", b"info"),
        Err(CryptoError::InvalidState)
    );
    let packet = seal(&mut a, b"", b"still alive");
    assert_eq!(open(&mut b, b"", &packet).unwrap(), b"still alive");
}

#[test]
fn failed_finalize_consumes_the_pending_handshake_and_cannot_be_retried() {
    setup();
    let mut keygen_side = SessionManager::new();
    keygen_side.initiate_handshake(&[0x11; 96]).unwrap();

    // The all-zero X25519 point has small order and must be rejected.
    let zero_point = X25519Public([0; 32]);
    let ct = Ciphertext1024([7; 1568]);
    assert!(keygen_side
        .finalize_handshake(&zero_point, &ct, b"", b"")
        .is_err());
    assert_eq!(
        keygen_side.finalize_handshake(&X25519Public([9; 32]), &ct, b"", b""),
        Err(CryptoError::InvalidState),
        "retry must require a fresh initiate_handshake"
    );
    let mut out = [0u8; 1];
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    assert_eq!(
        keygen_side.encrypt_packet(b"", b"x", &mut out, &mut nonce, &mut tag),
        Err(CryptoError::InvalidState)
    );
}

#[test]
fn a_second_finalize_cannot_replace_an_established_session() {
    setup();
    let mut keygen_side = SessionManager::new();
    let mut encap_side = SessionManager::new();
    let (pk, x_pk) = keygen_side.initiate_handshake(&[0x11; 96]).unwrap();
    let mut ct = Ciphertext1024([0; 1568]);
    let mut my_pk = X25519Public([0; 32]);
    encap_side
        .encapsulate_for_peer(&pk, &x_pk, &[0x22; 64], b"", b"", &mut ct, &mut my_pk)
        .unwrap();
    keygen_side
        .finalize_handshake(&my_pk, &ct, b"", b"")
        .unwrap();

    let packet = seal(&mut encap_side, b"", b"genuine");
    // An attacker replaying the handshake response a second time gains nothing.
    assert_eq!(
        keygen_side.finalize_handshake(&my_pk, &ct, b"", b""),
        Err(CryptoError::InvalidState)
    );
    assert_eq!(open(&mut keygen_side, b"", &packet).unwrap(), b"genuine");
}

#[test]
fn all_zero_and_all_one_entropy_are_rejected_without_side_effects() {
    setup();
    let (mut a, mut b) = established_pair(0x11, 0x22);
    assert_eq!(
        a.initiate_handshake(&[0u8; 96]).map(|_| ()),
        Err(CryptoError::InvalidState)
    );
    assert_eq!(
        a.initiate_handshake(&[0xFFu8; 96]).map(|_| ()),
        Err(CryptoError::InvalidState)
    );
    let packet = seal(&mut b, b"", b"unaffected");
    assert_eq!(open(&mut a, b"", &packet).unwrap(), b"unaffected");
}

/// Demonstrates the exact attacker capability recorded in SECURITY.md section 10: with no
/// peer identity bound into the handshake, an active intermediary becomes a transparent relay
/// that can read and rewrite traffic while both endpoints see a valid session.
#[test]
fn unauthenticated_handshake_lets_an_active_intermediary_relay_and_rewrite_traffic() {
    setup();
    let mut victim_a = SessionManager::new(); // keygen side
    let mut victim_b = SessionManager::new(); // encapsulating side
    let mut mitm_toward_a = SessionManager::new(); // plays the encapsulating role to A
    let mut mitm_toward_b = SessionManager::new(); // plays the keygen role to B

    let (pk_a, x_a) = victim_a.initiate_handshake(&[0x11; 96]).unwrap();
    // The intermediary swallows A's public keys and answers as if it were B.
    let mut ct_m = Ciphertext1024([0; 1568]);
    let mut x_m = X25519Public([0; 32]);
    mitm_toward_a
        .encapsulate_for_peer(&pk_a, &x_a, &[0x55; 64], b"", b"", &mut ct_m, &mut x_m)
        .unwrap();
    victim_a
        .finalize_handshake(&x_m, &ct_m, b"", b"")
        .expect("A accepts the intermediary as B");

    // Toward B the intermediary presents fresh keys of its own.
    let (pk_m, x_pk_m) = mitm_toward_b.initiate_handshake(&[0x66; 96]).unwrap();
    let mut ct_b = Ciphertext1024([0; 1568]);
    let mut x_b = X25519Public([0; 32]);
    victim_b
        .encapsulate_for_peer(&pk_m, &x_pk_m, &[0x22; 64], b"", b"", &mut ct_b, &mut x_b)
        .unwrap();
    mitm_toward_b
        .finalize_handshake(&x_b, &ct_b, b"", b"")
        .unwrap();

    // B -> A traffic is read, rewritten and forwarded; both victims see valid packets.
    let from_b = seal(&mut victim_b, b"", b"transfer 10");
    let seen_by_mitm = open(&mut mitm_toward_b, b"", &from_b).unwrap();
    assert_eq!(seen_by_mitm, b"transfer 10");
    let rewritten = seal(&mut mitm_toward_a, b"", b"transfer 99");
    assert_eq!(
        open(&mut victim_a, b"", &rewritten).unwrap(),
        b"transfer 99"
    );
}

/// Establishes a session with an explicit salt on each side.
fn pair_with_salts(keygen_salt: &[u8], encap_salt: &[u8]) -> (SessionManager, SessionManager) {
    let mut keygen_side = SessionManager::new();
    let mut encap_side = SessionManager::new();
    let (pk, x_pk) = keygen_side.initiate_handshake(&[0x11; 96]).unwrap();
    let mut ct = Ciphertext1024([0; 1568]);
    let mut my_pk = X25519Public([0; 32]);
    encap_side
        .encapsulate_for_peer(
            &pk,
            &x_pk,
            &[0x22; 64],
            encap_salt,
            b"",
            &mut ct,
            &mut my_pk,
        )
        .unwrap();
    keygen_side
        .finalize_handshake(&my_pk, &ct, keygen_salt, b"")
        .unwrap();
    (keygen_side, encap_side)
}

#[test]
fn mismatched_salts_produce_unrelated_keys_and_fail_the_first_packet() {
    setup();
    let (mut a, mut b) = pair_with_salts(b"shared secret", b"shared secret");
    let packet = seal(&mut b, b"", b"ok");
    assert_eq!(open(&mut a, b"", &packet).unwrap(), b"ok");

    let (mut a, mut b) = pair_with_salts(b"shared secret", b"wrong secret");
    let packet = seal(&mut b, b"", b"nope");
    assert_eq!(
        open(&mut a, b"", &packet),
        Err(CryptoError::VerificationFailed)
    );
}

/// A pre-provisioned secret passed as `salt` is the one authentication mitigation available through
/// the existing ABI: an intermediary that does not hold it derives keys unrelated to its victim's.
/// This is a mitigation, not a reviewed authenticated-handshake protocol.
#[test]
fn an_intermediary_without_the_preshared_salt_cannot_read_the_session() {
    setup();
    let psk = b"provisioned out of band";
    let mut victim_a = SessionManager::new(); // keygen side, knows the secret
    let mut mitm = SessionManager::new(); // answers A without the secret

    let (pk_a, x_a) = victim_a.initiate_handshake(&[0x11; 96]).unwrap();
    let mut ct = Ciphertext1024([0; 1568]);
    let mut x_m = X25519Public([0; 32]);
    mitm.encapsulate_for_peer(&pk_a, &x_a, &[0x55; 64], b"", b"", &mut ct, &mut x_m)
        .unwrap();
    victim_a
        .finalize_handshake(&x_m, &ct, psk, b"")
        .expect("finalize still completes; failure is only visible at the first packet");

    let from_a = seal(&mut victim_a, b"", b"confidential");
    assert_eq!(
        open(&mut mitm, b"", &from_a),
        Err(CryptoError::VerificationFailed)
    );
}
