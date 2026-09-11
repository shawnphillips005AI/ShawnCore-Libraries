// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

use std::hint::black_box;
use std::time::{Duration, Instant};

use shawncore_pq_crypto::aead_wrapper::{
    aead_decrypt, aead_encrypt, hkdf_expand_sha384, hmac_sha384, AEAD_TAG_SIZE,
};
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::hybrid_kdf::derive_hybrid_key;
use shawncore_pq_crypto::ml_dsa_wrapper::{ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};
use shawncore_pq_crypto::ml_kem_wrapper::{ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen};
use shawncore_pq_crypto::x25519_wrapper::{x25519_diffie_hellman, x25519_keygen};

extern "C" fn bench_cache_flush(_: *const u8, _: usize) {}

fn install_callbacks() {
    unsafe {
        shawncore_crypto_register_cache_flush(Some(bench_cache_flush));
    }
}

fn iterations(default: u64) -> u64 {
    std::env::var("SHAWNCORE_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn measure<F>(mut f: F, iters: u64) -> Duration
where
    F: FnMut(),
{
    f();
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed()
}

fn report(name: &str, iters: u64, total: Duration) {
    let nanos = total.as_nanos() as f64 / iters as f64;
    let ops = 1_000_000_000.0 / nanos;
    println!("| {name} | {iters} | {:.3} | {:.2} |", nanos, ops);
}

fn main() {
    install_callbacks();

    const KEM_SEED: [u8; 64] = [0x11; 64];
    const KEM_ENTROPY: [u8; 32] = [0x22; 32];
    const DSA_SEED: [u8; 32] = [0x33; 32];
    const X_SEED_A: [u8; 32] = [0x44; 32];
    const X_SEED_B: [u8; 32] = [0x55; 32];
    const MESSAGE: [u8; 1024] = [0x5a; 1024];
    const AAD: [u8; 32] = [0xa5; 32];
    const SALT: [u8; 32] = [0x66; 32];
    const INFO: [u8; 32] = [0x77; 32];
    const ENC_KEY: [u8; 32] = [0x88; 32];
    const MAC_KEY: [u8; 32] = [0x99; 32];
    const NONCE: [u8; 12] = [0xaa; 12];
    const PRK: [u8; 48] = [0xbb; 48];

    let (kem_pk, kem_dk) =
        ml_kem_keygen(&KEM_SEED).expect("deterministic ML-KEM setup must succeed");
    let (_, kem_ct) =
        ml_kem_encapsulate(&kem_pk, &KEM_ENTROPY).expect("deterministic ML-KEM setup must succeed");
    let (dsa_pk, dsa_sk) =
        ml_dsa_keygen(&DSA_SEED).expect("deterministic ML-DSA setup must succeed");
    let dsa_sig = ml_dsa_sign(&dsa_sk, &MESSAGE).expect("deterministic ML-DSA setup must succeed");
    let (x_pk_a, x_sk_a) = x25519_keygen(&X_SEED_A);
    let (_x_pk_b, x_sk_b) = x25519_keygen(&X_SEED_B);

    println!("ShawnCore Benchmarks v12.3.2");
    println!(
        "Rust target: {}",
        std::env::var("TARGET").unwrap_or_else(|_| "host target".into())
    );
    println!("Benchmark payload: 1024 bytes");
    println!(
        "Timing source: std::time::Instant; one warm-up iteration; fixed deterministic inputs"
    );
    println!("Numbers are machine/toolchain dependent and are not certification evidence.");
    println!();
    println!("| Operation | Iterations | Mean ns/op | Ops/sec |");
    println!("|---|---:|---:|---:|");

    let n = iterations(100);
    let dsa_n = iterations(10);

    report(
        "ML-KEM-1024 keygen",
        n,
        measure(
            || {
                black_box(ml_kem_keygen(&KEM_SEED).expect("benchmark input valid"));
            },
            n,
        ),
    );
    report(
        "ML-KEM-1024 encapsulate",
        n,
        measure(
            || {
                black_box(
                    ml_kem_encapsulate(&kem_pk, &KEM_ENTROPY).expect("benchmark input valid"),
                );
            },
            n,
        ),
    );
    report(
        "ML-KEM-1024 decapsulate",
        n,
        measure(
            || {
                black_box(ml_kem_decapsulate(&kem_dk, &kem_ct).expect("benchmark input valid"));
            },
            n,
        ),
    );

    report(
        "ML-DSA-87 keygen",
        dsa_n,
        measure(
            || {
                black_box(ml_dsa_keygen(&DSA_SEED).expect("benchmark input valid"));
            },
            dsa_n,
        ),
    );
    report(
        "ML-DSA-87 sign (1 KiB)",
        dsa_n,
        measure(
            || {
                black_box(ml_dsa_sign(&dsa_sk, &MESSAGE).expect("benchmark input valid"));
            },
            dsa_n,
        ),
    );
    report(
        "ML-DSA-87 verify (1 KiB)",
        dsa_n,
        measure(
            || {
                black_box((ml_dsa_verify(&dsa_pk, &MESSAGE, &dsa_sig)).is_ok());
            },
            dsa_n,
        ),
    );

    report(
        "X25519 keygen",
        n,
        measure(
            || {
                black_box(x25519_keygen(&X_SEED_A));
            },
            n,
        ),
    );
    report(
        "X25519 Diffie-Hellman",
        n,
        measure(
            || {
                black_box((x25519_diffie_hellman(&x_sk_a, &x_pk_a)).is_ok());
            },
            n,
        ),
    );

    report(
        "HKDF-SHA384 (128 B)",
        n,
        measure(
            || {
                let mut out = [0u8; 128];
                black_box((hkdf_expand_sha384(&PRK, &INFO, &mut out)).is_ok());
            },
            n,
        ),
    );
    report(
        "HMAC-SHA384 (1 KiB)",
        n,
        measure(
            || {
                black_box((hmac_sha384(&MAC_KEY, &MESSAGE)).is_ok());
            },
            n,
        ),
    );
    report(
        "Hybrid KDF (128 B)",
        n,
        measure(
            || {
                let mut pq = [0x12u8; 32];
                let mut classical = [0x34u8; 32];
                black_box((derive_hybrid_key(&mut pq, &mut classical, &SALT, &INFO)).is_ok());
            },
            n,
        ),
    );

    report(
        "AEAD encrypt (1 KiB)",
        n,
        measure(
            || {
                let mut ciphertext = [0u8; 1024];
                let mut tag = [0u8; AEAD_TAG_SIZE];
                black_box(
                    (aead_encrypt(
                        &ENC_KEY,
                        &MAC_KEY,
                        &NONCE,
                        &AAD,
                        &MESSAGE,
                        &mut ciphertext,
                        &mut tag,
                    ))
                    .is_ok(),
                );
            },
            n,
        ),
    );
    let mut ciphertext = [0u8; 1024];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    aead_encrypt(
        &ENC_KEY,
        &MAC_KEY,
        &NONCE,
        &AAD,
        &MESSAGE,
        &mut ciphertext,
        &mut tag,
    )
    .expect("benchmark setup must succeed");
    report(
        "AEAD decrypt (1 KiB)",
        n,
        measure(
            || {
                let mut plaintext = [0u8; 1024];
                black_box(
                    (aead_decrypt(
                        &ENC_KEY,
                        &MAC_KEY,
                        &NONCE,
                        &AAD,
                        &ciphertext,
                        &tag,
                        &mut plaintext,
                    ))
                    .is_ok(),
                );
            },
            n,
        ),
    );

    let _ = x_sk_b;
    println!();
    println!("Tip: set SHAWNCORE_BENCH_ITERS=1000 for longer runs.");
}
