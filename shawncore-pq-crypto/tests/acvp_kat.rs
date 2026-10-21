// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Official NIST ACVP-Server known-answer tests for ML-KEM-1024 (FIPS 203) and
//! ML-DSA-87 (FIPS 204).
//!
//! `tests/vectors/acvp_fips203_204.txt` is copied verbatim from usnistgov/ACVP-Server at the
//! pinned commit named in its header (see `validation/fetch_acvp_vectors.py`). These are the
//! published ACVP sample vector sets: passing them is evidence for the exact cases listed, not a
//! CAVP/CMVP validation, FIPS 140-3 certificate, or timing claim.
//!
//! Not covered because the library exposes no entry point for them: ML-DSA signature
//! generation from an expanded signing key, non-empty-context signing, and pre-hash modes.

// ACVP supplies ML-KEM decapsulation keys in the legacy expanded form.
#![allow(deprecated)]

use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024, DecapsKey1024,
    PublicKey1024,
};
use std::collections::{BTreeSet, HashMap};

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

fn setup() {
    unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
}

struct Vectors(HashMap<String, Vec<u8>>);

impl Vectors {
    fn load() -> Self {
        let map = include_str!("vectors/acvp_fips203_204.txt")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .map(|line| {
                let (name, value) = line.split_once(" = ").expect("name = hex");
                let bytes = (0..value.len() / 2)
                    .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
                    .collect();
                (name.to_string(), bytes)
            })
            .collect();
        Self(map)
    }

    /// Test-case ids present for a family such as `mlkem.keygen`.
    fn cases(&self, family: &str) -> Vec<String> {
        let prefix = format!("{family}.");
        let ids: BTreeSet<u32> = self
            .0
            .keys()
            .filter_map(|key| key.strip_prefix(&prefix))
            .map(|rest| rest.split('.').next().unwrap().parse().unwrap())
            .collect();
        assert!(!ids.is_empty(), "no vectors for {family}");
        ids.into_iter().map(|id| format!("{family}.{id}")).collect()
    }

    fn get(&self, case: &str, field: &str) -> &[u8] {
        &self.0[&format!("{case}.{field}")]
    }

    fn array<const N: usize>(&self, case: &str, field: &str) -> [u8; N] {
        self.get(case, field)
            .try_into()
            .unwrap_or_else(|_| panic!("{case}.{field} length"))
    }

    fn passed(&self, case: &str) -> bool {
        self.get(case, "passed") == [1]
    }
}

fn expanded_dk(bytes: &[u8]) -> Option<DecapsKey1024> {
    let encoded = ml_kem::ml_kem_1024::ExpandedDecapsulationKey::try_from(bytes).ok()?;
    ml_kem::DecapsulationKey1024::from_expanded(&encoded)
        .ok()
        .map(DecapsKey1024)
}

#[test]
fn acvp_ml_kem_1024_key_generation() {
    use ml_kem::ExpandedKeyEncoding;
    setup();
    let v = Vectors::load();
    let cases = v.cases("mlkem.keygen");
    assert_eq!(cases.len(), 25);
    for case in cases {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(v.get(&case, "d"));
        seed[32..].copy_from_slice(v.get(&case, "z"));
        let (ek, dk) = ml_kem_keygen(&seed).unwrap();
        assert_eq!(ek.to_bytes().as_slice(), v.get(&case, "ek"), "{case}: ek");
        let expanded = dk.0.to_expanded_bytes();
        assert_eq!(expanded.as_slice(), v.get(&case, "dk"), "{case}: dk");
    }
}

#[test]
fn acvp_ml_kem_1024_encapsulation() {
    setup();
    let v = Vectors::load();
    let cases = v.cases("mlkem.encap");
    assert_eq!(cases.len(), 25);
    for case in cases {
        let ek = PublicKey1024::from_bytes(&v.array(&case, "ek")).expect("valid ek");
        let (shared, ct) = ml_kem_encapsulate(&ek, &v.array(&case, "m")).unwrap();
        assert_eq!(ct.0.as_slice(), v.get(&case, "c"), "{case}: c");
        assert_eq!(shared.0.as_slice(), v.get(&case, "k"), "{case}: k");
    }
}

#[test]
fn acvp_ml_kem_1024_decapsulation() {
    setup();
    let v = Vectors::load();
    let cases = v.cases("mlkem.decap");
    assert_eq!(cases.len(), 10);
    for case in cases {
        let dk = expanded_dk(v.get(&case, "dk")).expect("ACVP decapsulation key loads");
        let ct = Ciphertext1024(v.array(&case, "c"));
        let shared = ml_kem_decapsulate(&dk, &ct).unwrap();
        assert_eq!(shared.0.as_slice(), v.get(&case, "k"), "{case}: k");
    }
}

#[test]
fn acvp_ml_kem_1024_key_checks_agree_on_every_verdict() {
    setup();
    let v = Vectors::load();
    let ek_cases = v.cases("mlkem.ekcheck");
    assert_eq!(ek_cases.len(), 10);
    for case in ek_cases {
        let accepted = PublicKey1024::from_bytes(&v.array(&case, "ek")).is_ok();
        assert_eq!(accepted, v.passed(&case), "{case}: encapsulation key check");
    }
    let dk_cases = v.cases("mlkem.dkcheck");
    assert_eq!(dk_cases.len(), 10);
    for case in dk_cases {
        let accepted = expanded_dk(v.get(&case, "dk")).is_some();
        assert_eq!(accepted, v.passed(&case), "{case}: decapsulation key check");
    }
}

#[cfg(feature = "ml-dsa")]
#[test]
fn acvp_ml_dsa_87_key_generation_and_signature_verification() {
    use ml_dsa::{MlDsa87, Signature};
    use shawncore_pq_crypto::ml_dsa_wrapper::{ml_dsa_keygen, PublicKey87};

    // Unoptimized builds put the expanded ML-DSA keys and temporaries on the stack.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(|| {
            setup();
            let v = Vectors::load();

            let cases = v.cases("mldsa.keygen");
            assert_eq!(cases.len(), 25);
            for case in cases {
                let (pk, _sk) = ml_dsa_keygen(&v.array(&case, "seed")).unwrap();
                assert_eq!(pk.to_bytes().as_slice(), v.get(&case, "pk"), "{case}: pk");
            }

            let cases = v.cases("mldsa.sigver");
            assert_eq!(cases.len(), 15);
            let (mut accepted, mut rejected) = (0, 0);
            for case in cases {
                let pk = PublicKey87::from_bytes(&v.array(&case, "pk")).unwrap();
                let verdict = match Signature::<MlDsa87>::try_from(v.get(&case, "signature")) {
                    Ok(sig) => pk.0.verify_with_context(
                        v.get(&case, "message"),
                        v.get(&case, "context"),
                        &sig,
                    ),
                    Err(_) => false,
                };
                assert_eq!(verdict, v.passed(&case), "{case}: verification verdict");
                if verdict {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            }
            assert!(
                accepted > 0 && rejected > 0,
                "vector set must exercise both verdicts"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
