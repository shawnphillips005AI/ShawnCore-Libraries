// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Cross-implementation vectors: ML-KEM-1024 and ML-DSA-87 against OpenSSL 3.5.
//!
//! `tests/vectors/openssl_interop.txt` is produced by `validation/gen_openssl_vectors.sh`
//! entirely by OpenSSL, an implementation independent of the `ml-kem`/`ml-dsa` crates.
//! Agreement is evidence of interoperability for these inputs. These are **not** NIST ACVP
//! vectors and do not establish FIPS 203/204 conformance or constant-time behavior.

use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024, PublicKey1024,
};
use std::collections::HashMap;

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

fn setup() {
    unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
}

fn vectors() -> HashMap<String, Vec<u8>> {
    include_str!("vectors/openssl_interop.txt")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line.split_once(" = ").expect("name = hex");
            let bytes = (0..value.len() / 2)
                .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            (name.to_string(), bytes)
        })
        .collect()
}

fn array<const N: usize>(map: &HashMap<String, Vec<u8>>, key: &str) -> [u8; N] {
    map[key]
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("{key} length"))
}

#[test]
fn ml_kem_1024_agrees_with_openssl() {
    setup();
    let v = vectors();
    for case in ["kem1", "kem2"] {
        let seed: [u8; 64] = array(&v, &format!("{case}.seed"));
        let (pk, dk) = ml_kem_keygen(&seed).unwrap();
        assert_eq!(
            pk.to_bytes().as_slice(),
            v[&format!("{case}.pk")].as_slice(),
            "{case}: public key from seed"
        );

        // Deterministic encapsulation must reproduce OpenSSL's ciphertext and secret bytes.
        let openssl_pk = PublicKey1024::from_bytes(&array(&v, &format!("{case}.pk"))).unwrap();
        let m: [u8; 32] = array(&v, &format!("{case}.m"));
        let (shared, ct) = ml_kem_encapsulate(&openssl_pk, &m).unwrap();
        assert_eq!(
            ct.0.as_slice(),
            v[&format!("{case}.ct")].as_slice(),
            "{case}: ct"
        );
        assert_eq!(
            shared.0.as_slice(),
            v[&format!("{case}.ss")].as_slice(),
            "{case}: ss"
        );

        // Decapsulating OpenSSL's ciphertext recovers OpenSSL's secret.
        let openssl_ct = Ciphertext1024(array(&v, &format!("{case}.ct")));
        let recovered = ml_kem_decapsulate(&dk, &openssl_ct).unwrap();
        assert_eq!(recovered.0.as_slice(), v[&format!("{case}.ss")].as_slice());

        // A tampered ciphertext must yield OpenSSL's implicit-rejection secret, not an error.
        let tampered = Ciphertext1024(array(&v, &format!("{case}.tampered_ct")));
        let rejected = ml_kem_decapsulate(&dk, &tampered).unwrap();
        assert_eq!(
            rejected.0.as_slice(),
            v[&format!("{case}.tampered_ss")].as_slice(),
            "{case}: implicit rejection"
        );
        assert_ne!(rejected.0.as_slice(), v[&format!("{case}.ss")].as_slice());
    }
}

/// The whole session (transcript, key split, directions, nonce and MAC framing) re-derived by
/// `validation/gen_session_vector.py` with OpenSSL, Python and an RFC 7748 ladder.
#[test]
fn session_derivation_matches_an_independent_implementation() {
    use shawncore_pq_crypto::session_manager::SessionManager;
    use shawncore_pq_crypto::x25519_wrapper::X25519Public;

    setup();
    let v = vectors();
    let keygen_entropy: [u8; 96] = array(&v, "session.keygen_entropy");
    let encap_entropy: [u8; 64] = array(&v, "session.encap_entropy");
    let (salt, info, aad) = (&v["session.salt"], &v["session.info"], &v["session.aad"]);

    let mut keygen_side = SessionManager::new();
    let mut encap_side = SessionManager::new();
    let (pk, x_pk) = keygen_side.initiate_handshake(&keygen_entropy).unwrap();
    assert_eq!(x_pk.0.as_slice(), v["session.keygen_x25519_pk"].as_slice());

    let mut ct = Ciphertext1024([0; 1568]);
    let mut encap_pk = X25519Public([0; 32]);
    encap_side
        .encapsulate_for_peer(
            &pk,
            &x_pk,
            &encap_entropy,
            salt,
            info,
            &mut ct,
            &mut encap_pk,
        )
        .unwrap();
    assert_eq!(ct.0.as_slice(), v["session.kem_ct"].as_slice());
    assert_eq!(
        encap_pk.0.as_slice(),
        v["session.encap_x25519_pk"].as_slice()
    );
    keygen_side
        .finalize_handshake(&encap_pk, &ct, salt, info)
        .unwrap();

    // Packets sealed independently decrypt, and our packets equal the independent bytes.
    fn exchange(
        sender: &mut SessionManager,
        receiver: &mut SessionManager,
        v: &HashMap<String, Vec<u8>>,
        aad: &[u8],
        direction: &str,
    ) {
        let plaintext = &v[&format!("session.{direction}_plaintext")];
        let mut out = [0u8; 22];
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 48];
        sender
            .encrypt_packet(aad, plaintext, &mut out, &mut nonce, &mut tag)
            .unwrap();
        assert_eq!(
            out.as_slice(),
            v[&format!("session.{direction}_ct")].as_slice()
        );
        assert_eq!(
            tag.as_slice(),
            v[&format!("session.{direction}_tag")].as_slice()
        );
        assert_eq!(nonce, [0u8; 12]);

        let mut recovered = [0u8; 22];
        receiver
            .decrypt_packet(aad, &out, &nonce, &tag, &mut recovered)
            .unwrap();
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }
    exchange(&mut encap_side, &mut keygen_side, &v, aad, "e2k");
    exchange(&mut keygen_side, &mut encap_side, &v, aad, "k2e");
}

#[cfg(feature = "ml-dsa")]
#[test]
fn ml_dsa_87_agrees_with_openssl() {
    use shawncore_pq_crypto::ml_dsa_wrapper::{
        ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, PublicKey87, Signature87,
    };

    // Unoptimized builds put the expanded ML-DSA keys and temporaries on the stack.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            setup();
            let v = vectors();
            let seed: [u8; 32] = array(&v, "dsa.seed");
            let (pk, sk) = ml_dsa_keygen(&seed).unwrap();
            assert_eq!(
                pk.to_bytes().as_slice(),
                v["dsa.pk"].as_slice(),
                "public key from seed"
            );

            let msg = &v["dsa.msg"];
            let openssl_sig = Signature87(array(&v, "dsa.sig"));
            let openssl_pk = PublicKey87::from_bytes(&array(&v, "dsa.pk")).unwrap();
            assert!(ml_dsa_verify(&openssl_pk, msg, &openssl_sig).is_ok());

            // Equality with OpenSSL's deterministic signature also proves OpenSSL would
            // verify ours (it verified its own in the generator).
            let ours = ml_dsa_sign(&sk, msg).unwrap();
            assert_eq!(
                ours.0.as_slice(),
                openssl_sig.0.as_slice(),
                "deterministic signature"
            );

            let mut altered = msg.clone();
            altered[0] ^= 1;
            assert!(ml_dsa_verify(&openssl_pk, &altered, &openssl_sig).is_err());
            let mut flipped = openssl_sig.clone();
            flipped.0[100] ^= 1;
            assert!(ml_dsa_verify(&openssl_pk, msg, &flipped).is_err());
        })
        .unwrap()
        .join()
        .unwrap();
}

/// The authenticated handshake (identities, binding, transcript, both signatures and the
/// resulting session) re-derived by `validation/gen_session_vector.py` with OpenSSL and Python.
#[cfg(feature = "ml-dsa")]
#[test]
fn authenticated_handshake_matches_an_independent_implementation() {
    use shawncore_pq_crypto::auth_handshake::{
        handshake_binding, identity_fingerprint, transcript_hash,
    };
    use shawncore_pq_crypto::ml_dsa_wrapper::{ml_dsa_keygen, Signature87};
    use shawncore_pq_crypto::session_manager::SessionManager;
    use shawncore_pq_crypto::x25519_wrapper::X25519Public;

    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            setup();
            let v = vectors();
            let (k_vk, k_sk) = ml_dsa_keygen(&[0x41; 32]).unwrap();
            let (e_vk, e_sk) = ml_dsa_keygen(&[0x42; 32]).unwrap();
            assert_eq!(
                k_vk.to_bytes().as_slice(),
                v["auth.keygen_identity_pk"].as_slice()
            );
            assert_eq!(
                e_vk.to_bytes().as_slice(),
                v["auth.encap_identity_pk"].as_slice()
            );

            let keygen_entropy: [u8; 96] = array(&v, "session.keygen_entropy");
            let encap_entropy: [u8; 64] = array(&v, "session.encap_entropy");
            let (salt, aad) = (&v["session.salt"], &v["session.aad"]);
            let app_info = &v["auth.app_info"];

            let mut keygen = SessionManager::new();
            let mut encap = SessionManager::new();
            let (ek, xk) = keygen.initiate_handshake(&keygen_entropy).unwrap();

            let binding = handshake_binding(
                &ek,
                &xk,
                &identity_fingerprint(&k_vk),
                &identity_fingerprint(&e_vk),
                app_info,
            )
            .unwrap();
            assert_eq!(binding.as_slice(), v["auth.binding"].as_slice());

            let mut ct = Ciphertext1024([0; 1568]);
            let mut xe = X25519Public([0; 32]);
            let mut sig_e = Signature87([0; 4627]);
            encap
                .encapsulate_authenticated(
                    &e_sk,
                    &k_vk,
                    &ek,
                    &xk,
                    &encap_entropy,
                    salt,
                    app_info,
                    &mut ct,
                    &mut xe,
                    &mut sig_e,
                )
                .unwrap();
            assert_eq!(
                transcript_hash(&binding, &ct, &xe).as_slice(),
                v["auth.transcript"].as_slice()
            );
            assert_eq!(
                sig_e.0.as_slice(),
                v["auth.sig_e"].as_slice(),
                "encapsulating signature"
            );

            let mut sig_k = Signature87([0; 4627]);
            keygen
                .finalize_authenticated(&k_sk, &e_vk, &xe, &ct, &sig_e, salt, app_info, &mut sig_k)
                .unwrap();
            assert_eq!(
                sig_k.0.as_slice(),
                v["auth.sig_k"].as_slice(),
                "key-generating signature"
            );
            encap.confirm_peer(&k_vk, &sig_k).unwrap();

            let plaintext = &v["session.e2k_plaintext"];
            let mut out = vec![0u8; plaintext.len()];
            let (mut nonce, mut tag) = ([0u8; 12], [0u8; 48]);
            encap
                .encrypt_packet(aad, plaintext, &mut out, &mut nonce, &mut tag)
                .unwrap();
            assert_eq!(out.as_slice(), v["auth.e2k_ct"].as_slice());
            assert_eq!(tag.as_slice(), v["auth.e2k_tag"].as_slice());
            let mut back = vec![0u8; out.len()];
            keygen
                .decrypt_packet(aad, &out, &nonce, &tag, &mut back)
                .unwrap();
            assert_eq!(&back, plaintext);
            let plaintext = &v["session.k2e_plaintext"];
            let mut out = vec![0u8; plaintext.len()];
            let (mut nonce, mut tag) = ([0u8; 12], [0u8; 48]);
            keygen
                .encrypt_packet(aad, plaintext, &mut out, &mut nonce, &mut tag)
                .unwrap();
            assert_eq!(out.as_slice(), v["auth.k2e_ct"].as_slice());
            assert_eq!(tag.as_slice(), v["auth.k2e_tag"].as_slice());
        })
        .unwrap()
        .join()
        .unwrap();
}
