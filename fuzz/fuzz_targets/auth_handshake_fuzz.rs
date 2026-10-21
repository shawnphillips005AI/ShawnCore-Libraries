#![no_main]

use libfuzzer_sys::fuzz_target;
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_dsa_wrapper::{ml_dsa_keygen, PublicKey87, Signature87, SigningKey87};
use shawncore_pq_crypto::ml_kem_wrapper::Ciphertext1024;
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::X25519Public;
use std::sync::OnceLock;

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

struct Identity {
    vk: PublicKey87,
    sk: SigningKey87,
}

fn identities() -> &'static (Identity, Identity) {
    static IDENTITIES: OnceLock<(Identity, Identity)> = OnceLock::new();
    IDENTITIES.get_or_init(|| {
        unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
        let make = |seed: u8| {
            let (vk, sk) = ml_dsa_keygen(&[seed; 32]).unwrap();
            Identity { vk, sk }
        };
        (make(0x41), make(0x42))
    })
}

/// Fills `out` from `data`, repeating it, so every input length exercises every field.
fn fill(out: &mut [u8], data: &[u8], offset: usize) {
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = if data.is_empty() {
            0
        } else {
            data[(offset + index) % data.len()]
        };
    }
}

// Arbitrary replies must never authenticate, must never disturb the pending handshake, a salt
// mismatch must fail key confirmation without installing a session, and an unconfirmed session
// must never carry traffic.
fuzz_target!(|data: &[u8]| {
    let (keygen_id, encap_id) = identities();
    let mut keygen = SessionManager::new();
    let mut encap = SessionManager::new();
    let (ek, xk) = keygen.initiate_handshake(&[0x11; 96]).unwrap();

    let mut forged_ct = Ciphertext1024([0; 1568]);
    let mut forged_xe = X25519Public([0; 32]);
    let mut forged_sig = Signature87([0; 4627]);
    let mut forged_tag = [0u8; 48];
    fill(&mut forged_ct.0, data, 0);
    fill(&mut forged_xe.0, data, 1568);
    fill(&mut forged_sig.0, data, 1600);
    fill(&mut forged_tag, data, 6227);

    let app_info = data.get(..data.len().min(32)).unwrap_or(&[]);
    let mut unused = Signature87([0; 4627]);
    let mut unused_tag = [0u8; 48];
    assert!(keygen
        .finalize_authenticated(
            &keygen_id.sk,
            &encap_id.vk,
            &forged_xe,
            &forged_ct,
            &forged_sig,
            &forged_tag,
            b"salt",
            app_info,
            &mut unused,
            &mut unused_tag,
        )
        .is_err());

    // The genuine reply must still work: the forgery consumed nothing.
    let mut ct = Ciphertext1024([0; 1568]);
    let mut xe = X25519Public([0; 32]);
    let mut sig_e = Signature87([0; 4627]);
    let mut tag_e = [0u8; 48];
    encap
        .encapsulate_authenticated(
            &encap_id.sk,
            &keygen_id.vk,
            &ek,
            &xk,
            &[0x22; 64],
            b"salt",
            app_info,
            &mut ct,
            &mut xe,
            &mut sig_e,
            &mut tag_e,
        )
        .unwrap();

    // A mismatched salt (chosen by the input) is an authentic peer with a different key.
    let mut mismatched = SessionManager::new();
    let (ek2, xk2) = mismatched.initiate_handshake(&[0x11; 96]).unwrap();
    assert_eq!((ek2.to_bytes(), xk2.0), (ek.to_bytes(), xk.0));
    let wrong_salt = [data.first().copied().unwrap_or(0) | 0x80; 5];
    let outcome = mismatched.finalize_authenticated(
        &keygen_id.sk,
        &encap_id.vk,
        &xe,
        &ct,
        &sig_e,
        &tag_e,
        &wrong_salt,
        app_info,
        &mut unused,
        &mut unused_tag,
    );
    assert_eq!(
        outcome,
        Err(shawncore_pq_crypto::error::CryptoError::KeyConfirmationFailed)
    );
    let mut out = [0u8; 4];
    let (mut nonce, mut tag) = ([0u8; 12], [0u8; 48]);
    assert!(mismatched
        .encrypt_packet(b"", b"data", &mut out, &mut nonce, &mut tag)
        .is_err());

    let mut sig_k = Signature87([0; 4627]);
    let mut tag_k = [0u8; 48];
    keygen
        .finalize_authenticated(
            &keygen_id.sk,
            &encap_id.vk,
            &xe,
            &ct,
            &sig_e,
            &tag_e,
            b"salt",
            app_info,
            &mut sig_k,
            &mut tag_k,
        )
        .unwrap();

    // An arbitrary proof must not confirm the encapsulating side, which must stay shut.
    assert!(encap
        .confirm_peer(&keygen_id.vk, &forged_sig, &forged_tag)
        .is_err());
    assert!(encap
        .encrypt_packet(b"", b"data", &mut out, &mut nonce, &mut tag)
        .is_err());
    encap.confirm_peer(&keygen_id.vk, &sig_k, &tag_k).unwrap();
});
