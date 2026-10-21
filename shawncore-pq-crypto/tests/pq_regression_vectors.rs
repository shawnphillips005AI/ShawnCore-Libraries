// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Regression vectors for the ML-KEM-1024 and ML-DSA-87 dependencies.
//!
//! These values were captured from the pinned `ml-kem` 0.2.3 and `ml-dsa` 0.1.1
//! releases, not from NIST ACVP. They detect behavior drift across dependency
//! upgrades; they are not evidence of FIPS 203/204 conformance.

use sha2::{Digest, Sha256};
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_kem_wrapper::{ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen};

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

fn setup() {
    unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// Unoptimized builds put the expanded ML-DSA keys and temporaries on the stack.
fn with_large_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[test]
fn ml_kem_1024_regression_vector() {
    with_large_stack(ml_kem_1024_body);
}

fn ml_kem_1024_body() {
    setup();
    let seed: [u8; 64] = core::array::from_fn(|i| i as u8);
    let entropy: [u8; 32] = core::array::from_fn(|i| 0xc0 ^ i as u8);

    let (pk, dk) = ml_kem_keygen(&seed).unwrap();
    assert_eq!(
        sha256_hex(&pk.to_bytes()),
        "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530"
    );

    let (ss, ct) = ml_kem_encapsulate(&pk, &entropy).unwrap();
    assert_eq!(
        sha256_hex(&ct.0),
        "25eb344e175955c23d68d48675233b9ae297f026e8b1c350a6f029494076a924"
    );
    assert_eq!(
        hex(&ss.0),
        "cb06b34d7e5af6e011eb9aae422f9e7a431af2a3c8a47078b27d3121f798239c"
    );

    assert_eq!(ml_kem_decapsulate(&dk, &ct).unwrap().0, ss.0);
}

#[cfg(feature = "ml-dsa")]
#[test]
fn ml_dsa_87_regression_vector() {
    with_large_stack(ml_dsa_87_body);
}

#[cfg(feature = "ml-dsa")]
fn ml_dsa_87_body() {
    use shawncore_pq_crypto::ml_dsa_wrapper::{ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};

    setup();
    let seed: [u8; 32] = core::array::from_fn(|i| 0x30 + i as u8);
    let msg = b"shawncore golden message";

    let (pk, sk) = ml_dsa_keygen(&seed).unwrap();
    assert_eq!(
        sha256_hex(&pk.to_bytes()),
        "ff6d98d0d9dbc2e41f28a4f0364980fd9faf733dc3751b4a9ee19fe4ca993d84"
    );

    let sig = ml_dsa_sign(&sk, msg).unwrap();
    assert_eq!(
        sha256_hex(&sig.0),
        "80b3e87f8a17d37ee383e1d099c72c742882af844b686364eb0820c1570eb3ef"
    );
    ml_dsa_verify(&pk, msg, &sig).unwrap();
    assert!(ml_dsa_verify(&pk, b"different message", &sig).is_err());
}

#[test]
fn ml_kem_public_key_decode_enforces_fips_203_modulus_check() {
    use shawncore_pq_crypto::ml_kem_wrapper::{PublicKey1024, ML_KEM_PUBLICKEY_BYTES};

    setup();
    // 0xff packs 12-bit coefficients of 4095, which exceed q = 3329.
    assert!(PublicKey1024::from_bytes(&[0xff; ML_KEM_PUBLICKEY_BYTES]).is_err());

    let seed: [u8; 64] = core::array::from_fn(|i| i as u8);
    let (pk, _dk) = ml_kem_keygen(&seed).unwrap();
    let decoded = PublicKey1024::from_bytes(&pk.to_bytes()).unwrap();
    assert_eq!(decoded.to_bytes(), pk.to_bytes());
}
