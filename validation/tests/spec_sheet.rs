// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Spec-sheet conformance. Every quantitative claim in the README "Specifications"
//! section is checked against the code, the C header and the benchmark record, and
//! the documents that repeat those numbers are checked for drift.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use shawncore_pq_crypto::aead_wrapper::{AEAD_KEY_SIZE, AEAD_NONCE_SIZE, AEAD_TAG_SIZE};
use shawncore_pq_crypto::entropy_pool::MAX_MIX_CHUNKS_PER_CALL;
use shawncore_pq_crypto::entropy_queue::{EntropyQueue, ENTROPY_CHUNK_SIZE, ENTROPY_QUEUE_SIZE};
use shawncore_pq_crypto::hybrid_kdf::HYBRID_OUTPUT_SIZE;
use shawncore_pq_crypto::ml_dsa_wrapper::{
    PublicKey87, Signature87, SigningKey87, ML_DSA_PUBLICKEY_BYTES, ML_DSA_SIGNATURE_BYTES,
};
use shawncore_pq_crypto::ml_kem_wrapper::{
    Ciphertext1024, DecapsKey1024, PublicKey1024, ML_KEM_CIPHERTEXT_BYTES, ML_KEM_PUBLICKEY_BYTES,
};
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::{X25519Public, X25519_PUBLICKEY_BYTES};
use shawncore_rtos_sync::bitmap_scheduler::{PerCoreScheduler, MAX_TASKS};
use shawncore_rtos_sync::error::AllocatorError;
use shawncore_rtos_sync::ffi::shawncore_rtos_dmapool2k_sizeof;
use shawncore_rtos_sync::ffi_callbacks::shawncore_rtos_register_cache_flush;
use shawncore_rtos_sync::spsc_queue::CacheAlignedSlot;
use shawncore_rtos_sync::state_machine::{EnclaveState, StateMachine};
use shawncore_rtos_sync::static_dma_pool::StaticDmaPool;
use shawncore_rtos_sync::tcb::Tcb;

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

fn read(relative: &str) -> String {
    let path = repo_path(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn with_commas(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn assert_doc_contains(document: &str, name: &str, needle: &str) {
    assert!(
        document.contains(needle),
        "{name} must contain `{needle}`; the spec and the code have drifted apart"
    );
}

/// Function names declared in `shawncore.h`, including multi-line declarations.
fn header_functions() -> BTreeSet<String> {
    let header = read("shawncore-ffi/include/shawncore.h");
    let mut names = BTreeSet::new();
    for line in header.lines() {
        let text = line.trim_start();
        if text.is_empty()
            || text.starts_with('#')
            || text.starts_with("/*")
            || text.starts_with('*')
            || text.starts_with("//")
            || text.starts_with("typedef")
        {
            continue;
        }
        for prefix in ["shawncore_crypto_", "shawncore_rtos_"] {
            for (start, _) in text.match_indices(prefix) {
                let rest = &text[start..];
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                let before = text[..start].trim_end();
                let after = rest[end..].trim_start();
                if after.starts_with('(')
                    && !before.is_empty()
                    && !before.ends_with('(')
                    && !before.ends_with(',')
                {
                    names.insert(rest[..end].to_owned());
                }
            }
        }
    }
    names
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn count_test_functions() -> usize {
    let mut files = Vec::new();
    for krate in [
        "shawncore-pq-crypto",
        "shawncore-rtos-sync",
        "shawncore-ffi",
        "validation",
        "benchmarks",
    ] {
        for sub in ["src", "tests"] {
            collect_rust_files(&repo_path(krate).join(sub), &mut files);
        }
    }
    files
        .iter()
        .map(|file| {
            fs::read_to_string(file)
                .unwrap_or_default()
                .lines()
                .filter(|line| line.trim() == "#[test]")
                .count()
        })
        .sum()
}

#[test]
fn cryptographic_suite_sizes_match_the_spec() {
    assert_eq!(ML_KEM_PUBLICKEY_BYTES, 1568);
    assert_eq!(ML_KEM_CIPHERTEXT_BYTES, 1568);
    assert_eq!(X25519_PUBLICKEY_BYTES, 32);
    assert_eq!(ML_DSA_PUBLICKEY_BYTES, 2592);
    assert_eq!(ML_DSA_SIGNATURE_BYTES, 4627);
    assert_eq!(AEAD_KEY_SIZE, 32);
    assert_eq!(AEAD_NONCE_SIZE, 12);
    assert_eq!(AEAD_TAG_SIZE, 48);
    assert_eq!(HYBRID_OUTPUT_SIZE, 128);
    // ChaCha20's 32-bit block counter bounds one message per (key, nonce).
    assert_eq!(u64::from(u32::MAX) * 64, (1u64 << 38) - 64);
}

#[test]
fn replay_window_and_nonce_format_match_the_spec() {
    fn nonce(sequence: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&sequence.to_le_bytes());
        n
    }

    let mut session = SessionManager::new();
    assert!(session.check_rx_nonce(&nonce(0)).is_ok());
    session.commit_rx_nonce(&nonce(0));
    assert!(session.check_rx_nonce(&nonce(0)).is_err(), "duplicate");

    session.commit_rx_nonce(&nonce(100));
    assert!(session.check_rx_nonce(&nonce(100)).is_err(), "duplicate");
    assert!(session.check_rx_nonce(&nonce(101)).is_ok(), "new high");
    assert!(
        session.check_rx_nonce(&nonce(99)).is_ok(),
        "in window, unseen"
    );
    assert!(
        session.check_rx_nonce(&nonce(37)).is_ok(),
        "offset 63 is inside"
    );
    assert!(
        session.check_rx_nonce(&nonce(36)).is_err(),
        "offset 64 is outside"
    );

    let mut padded = nonce(200);
    padded[11] = 1;
    assert!(
        session.check_rx_nonce(&padded).is_err(),
        "tail must be zero"
    );

    let mut first = [0xffu8; 12];
    let mut second = [0xffu8; 12];
    session.get_next_tx_nonce(&mut first).unwrap();
    session.get_next_tx_nonce(&mut second).unwrap();
    assert_eq!(first, nonce(0));
    assert_eq!(second, nonce(1));
}

#[test]
fn handshake_rejects_uniform_entropy() {
    let mut session = SessionManager::new();
    assert!(session.initiate_handshake(&[0x00; 96]).is_err());
    assert!(session.initiate_handshake(&[0xff; 96]).is_err());
}

#[test]
fn entropy_queue_capacity_and_mix_bound_match_the_spec() {
    assert_eq!(ENTROPY_CHUNK_SIZE, 32);
    assert_eq!(ENTROPY_QUEUE_SIZE, 64);
    assert_eq!(MAX_MIX_CHUNKS_PER_CALL, 8);

    let queue = EntropyQueue::new();
    for i in 0..ENTROPY_QUEUE_SIZE {
        let chunk = [i as u8 + 1; ENTROPY_CHUNK_SIZE];
        assert!(unsafe { queue.push(&chunk) }.is_ok());
    }
    assert!(
        unsafe { queue.push(&[0x55; ENTROPY_CHUNK_SIZE]) }.is_err(),
        "full"
    );

    let mut out = [0u8; ENTROPY_CHUNK_SIZE];
    assert!(unsafe { queue.pop(&mut out) });
    assert_eq!(out, [1u8; ENTROPY_CHUNK_SIZE], "FIFO order");
    assert!(unsafe { queue.push(&[0x55; ENTROPY_CHUNK_SIZE]) }.is_ok());
}

#[test]
fn scheduler_state_machine_and_task_block_match_the_spec() {
    assert_eq!(MAX_TASKS, 16);
    let scheduler = PerCoreScheduler::new();
    assert_eq!(scheduler.tasks.len(), 16);
    let _bitmap_width: u16 = scheduler.ready_bitmap;
    assert_eq!(core::mem::size_of::<Tcb>(), 64);
    assert_eq!(core::mem::align_of::<Tcb>(), 64);

    let states = [
        EnclaveState::Init,
        EnclaveState::Bootstrapping,
        EnclaveState::Operational,
        EnclaveState::Degraded,
        EnclaveState::Terminal,
    ];
    let machine = StateMachine::new();
    assert_eq!(machine.get_state(), EnclaveState::Init as u8);
    machine.try_advance(EnclaveState::Bootstrapping).unwrap();
    machine.try_advance(EnclaveState::Operational).unwrap();
    machine.try_advance(EnclaveState::Degraded).unwrap();
    machine.try_advance(EnclaveState::Operational).unwrap();
    machine.try_advance(EnclaveState::Degraded).unwrap();
    machine.try_advance(EnclaveState::Terminal).unwrap();
    for state in states {
        assert!(machine.try_advance(state).is_err(), "Terminal is absorbing");
    }
}

#[test]
fn dma_pool_alignment_tokens_and_zeroization_match_the_spec() {
    #[repr(C, align(4096))]
    struct Page([u32; 1024]);

    extern "C" fn no_flush(_: *const u8, _: usize) {}
    unsafe { shawncore_rtos_register_cache_flush(Some(no_flush)) };

    let mut page = Page([0xAAAA_AAAA; 1024]);
    let base = page.0.as_mut_ptr();

    let misaligned_pool = StaticDmaPool::<u32, 1, 1>::new();
    let misaligned = unsafe { base.cast::<u8>().add(4).cast::<u32>() };
    assert_eq!(
        unsafe { misaligned_pool.init(misaligned, 4092) },
        Err(AllocatorError::InvalidAlignment),
        "backing storage must be 4096-byte aligned"
    );

    let pool = StaticDmaPool::<u32, 1, 1>::new();
    unsafe { pool.init(base, 4096) }.unwrap();
    let (index, token, pointer) = pool.allocate().unwrap();
    unsafe { pointer.as_ptr().write(0xDEAD_BEEF) };
    pool.free(index, token).unwrap();
    assert_eq!(
        unsafe { core::ptr::read_volatile(base) },
        0,
        "slot is zeroized on free"
    );
    assert_eq!(pool.free(index, token), Err(AllocatorError::DoubleFree));

    let (_, next_token, _) = pool.allocate().unwrap();
    assert_ne!(next_token, token, "reuse advances the generation token");
    assert_eq!(
        pool.free(index, token),
        Err(AllocatorError::DoubleFree),
        "a stale token cannot free a newer allocation"
    );
}

#[test]
fn object_sizes_match_the_spec_sheet() {
    fn aligned_64<T>() -> usize {
        assert_eq!(core::mem::align_of::<T>(), 64);
        core::mem::size_of::<T>()
    }

    assert_eq!(aligned_64::<SessionManager>(), 4608);
    assert_eq!(aligned_64::<PublicKey1024>(), 2112);
    assert_eq!(aligned_64::<DecapsKey1024>(), 4288);
    assert_eq!(aligned_64::<Ciphertext1024>(), 1600);
    assert_eq!(aligned_64::<X25519Public>(), 64);
    assert_eq!(aligned_64::<PublicKey87>(), 73856);
    assert_eq!(aligned_64::<SigningKey87>(), 104640);
    assert_eq!(aligned_64::<Signature87>(), 4672);
    assert_eq!(aligned_64::<PerCoreScheduler>(), 1088);
    assert_eq!(shawncore_rtos_dmapool2k_sizeof(), 4160);
    assert_eq!(aligned_64::<CacheAlignedSlot<u32>>() % 64, 0);
}

#[test]
fn c_interface_surface_matches_the_spec() {
    let functions = header_functions();
    assert!(functions.len() > 100, "header parser found too little");

    let sizeofs = functions.iter().filter(|n| n.ends_with("_sizeof")).count();
    let alignofs = functions.iter().filter(|n| n.ends_with("_alignof")).count();
    assert_eq!(sizeofs, 24);
    assert_eq!(alignofs, sizeofs, "every sized type has an alignment query");

    let callbacks: BTreeSet<&str> = functions
        .iter()
        .filter_map(|name| name.split("_register_").nth(1))
        .map(|suffix| suffix.strip_prefix("read_").unwrap_or(suffix))
        .collect();
    let expected: BTreeSet<&str> = [
        "panic_hook",
        "disable_interrupts",
        "restore_interrupts",
        "cache_flush",
        "cache_invalidate",
        "monotonic_clock",
        "pet_watchdog",
    ]
    .into_iter()
    .collect();
    assert_eq!(callbacks, expected, "exactly seven host callbacks");

    let codecs: BTreeSet<&str> = functions
        .iter()
        .filter(|n| n.ends_with("_to_bytes") || n.ends_with("_from_bytes"))
        .map(|n| {
            n.trim_start_matches("shawncore_crypto_")
                .trim_end_matches("_to_bytes")
                .trim_end_matches("_from_bytes")
        })
        .collect();
    let public_only: BTreeSet<&str> = [
        "ml_kem_publickey",
        "ml_kem_ciphertext",
        "x25519_publickey",
        "ml_dsa_publickey",
        "ml_dsa_signature",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        codecs, public_only,
        "secret keys have no serialization entry point"
    );
}

#[test]
fn documents_repeat_the_numbers_the_code_enforces() {
    let readme = read("README.md");
    let architecture = read("ARCHITECTURE.md");
    let functions = header_functions().len();

    assert_doc_contains(
        &readme,
        "README.md",
        &format!("{functions} exported functions"),
    );
    assert_doc_contains(&readme, "README.md", &format!("({functions} functions"));
    assert_doc_contains(
        &architecture,
        "ARCHITECTURE.md",
        &format!("{functions} exported symbols"),
    );

    for (label, bytes) in [
        ("ML-KEM public key and ciphertext", ML_KEM_PUBLICKEY_BYTES),
        ("ML-DSA public key", ML_DSA_PUBLICKEY_BYTES),
        ("ML-DSA signature", ML_DSA_SIGNATURE_BYTES),
    ] {
        assert_doc_contains(&readme, label, &with_commas(bytes as u64));
    }
    for needle in [
        format!("{AEAD_KEY_SIZE} B cipher key"),
        format!("{AEAD_KEY_SIZE} B MAC key"),
        format!("{AEAD_TAG_SIZE} B tag"),
        format!("{AEAD_NONCE_SIZE} B: 64-bit little-endian counter"),
        format!("{HYBRID_OUTPUT_SIZE} B output"),
        format!("{ENTROPY_QUEUE_SIZE}-slot"),
        format!("{ENTROPY_CHUNK_SIZE} B chunks"),
        format!("at most {MAX_MIX_CHUNKS_PER_CALL} queued chunks"),
        format!("{MAX_TASKS} priority levels"),
        "$2^{64}-1$".to_owned(),
        "$2^{38}-64$".to_owned(),
    ] {
        assert_doc_contains(&readme, "README.md", &needle);
    }

    let sizes: [(&str, &str, usize); 9] = [
        (
            "Session manager",
            "session_manager",
            core::mem::size_of::<SessionManager>(),
        ),
        (
            "ML-KEM public key",
            "ml_kem_publickey",
            core::mem::size_of::<PublicKey1024>(),
        ),
        (
            "ML-KEM decapsulation key",
            "ml_kem_decapskey",
            core::mem::size_of::<DecapsKey1024>(),
        ),
        (
            "ML-KEM ciphertext",
            "ml_kem_ciphertext",
            core::mem::size_of::<Ciphertext1024>(),
        ),
        (
            "ML-DSA verifying key",
            "ml_dsa_publickey",
            core::mem::size_of::<PublicKey87>(),
        ),
        (
            "ML-DSA signing key",
            "ml_dsa_signingkey",
            core::mem::size_of::<SigningKey87>(),
        ),
        (
            "ML-DSA signature",
            "ml_dsa_signature",
            core::mem::size_of::<Signature87>(),
        ),
        (
            "Scheduler",
            "scheduler",
            core::mem::size_of::<PerCoreScheduler>(),
        ),
        (
            "DMA pool control object",
            "dmapool2k",
            shawncore_rtos_dmapool2k_sizeof(),
        ),
    ];
    for (readme_label, architecture_label, size) in sizes {
        let formatted = with_commas(size as u64);
        assert_doc_contains(
            &readme,
            "README.md",
            &format!("{readme_label} | {formatted}"),
        );
        assert_doc_contains(
            &architecture,
            "ARCHITECTURE.md",
            &format!("| `{architecture_label}` | {formatted} | 64 |"),
        );
    }

    let manifest = read("Cargo.toml");
    let msrv = manifest
        .lines()
        .find_map(|l| l.strip_prefix("rust-version = "))
        .map(|v| v.trim_matches('"').to_owned())
        .expect("workspace rust-version");
    let toolchain = read("rust-toolchain.toml");
    let channel = toolchain
        .lines()
        .find_map(|l| l.strip_prefix("channel = "))
        .map(|v| v.trim_matches('"').to_owned())
        .expect("toolchain channel");
    assert_doc_contains(&readme, "README.md", &format!("inimum Rust {msrv}"));
    assert_doc_contains(&readme, "README.md", &channel);
    let workflow = read(".github/workflows/ci.yml");
    assert_doc_contains(&workflow, "ci.yml", &format!("rust-toolchain@{channel}"));
    assert_doc_contains(&workflow, "ci.yml", &format!("rust-toolchain@{msrv}.0"));
}

#[test]
fn documents_state_the_real_test_count() {
    let count = count_test_functions();
    assert!(count > 100, "test discovery found too little: {count}");

    assert_doc_contains(
        &read("README.md"),
        "README.md",
        &format!("**{count} Rust #[test] functions**"),
    );
    assert_doc_contains(
        &read("VALIDATION.md"),
        "VALIDATION.md",
        &format!("**{count} Rust functions annotated"),
    );
    assert_doc_contains(
        &read("RELEASE_MANIFEST.txt"),
        "RELEASE_MANIFEST.txt",
        &format!("source inventory): {count}"),
    );
}

#[test]
fn platform_requirement_and_independent_evidence_are_enforced_and_documented() {
    for krate in ["shawncore-pq-crypto", "shawncore-rtos-sync"] {
        let lib = read(&format!("{krate}/src/lib.rs"));
        assert!(
            lib.contains("compile_error!") && lib.contains("target_has_atomic = \"64\""),
            "{krate} must reject targets without 64-bit atomics"
        );
    }
    assert_doc_contains(
        &read("README.md"),
        "README.md",
        "64-bit target with native 64-bit atomics",
    );

    let vectors = read("shawncore-pq-crypto/tests/vectors/openssl_interop.txt");
    for key in [
        "kem1.pk",
        "kem2.tampered_ss",
        "dsa.sig",
        "session.e2k_tag",
        "session.k2e_tag",
    ] {
        assert!(
            vectors.contains(&format!("{key} = ")),
            "vector {key} missing"
        );
    }
    let acvp = read("shawncore-pq-crypto/tests/vectors/acvp_fips203_204.txt");
    for family in [
        "mlkem.keygen.",
        "mlkem.encap.",
        "mlkem.decap.",
        "mlkem.ekcheck.",
        "mlkem.dkcheck.",
        "mldsa.keygen.",
        "mldsa.sigver.",
    ] {
        assert!(acvp.contains(family), "ACVP family {family} missing");
    }
    assert_doc_contains(
        &read("VALIDATION.md"),
        "VALIDATION.md",
        "usnistgov/ACVP-Server",
    );
    assert_doc_contains(&read("VALIDATION.md"), "VALIDATION.md", "OpenSSL 3.5.8");
    assert_doc_contains(&read("SECURITY.md"), "SECURITY.md", "unauthenticated");
}

#[test]
fn readme_performance_table_matches_the_benchmark_record() {
    let benchmarks = read("BENCHMARKS.md");
    let section = benchmarks
        .split("## Reference Results")
        .nth(1)
        .expect("BENCHMARKS.md has a Reference Results section")
        .split("### Effect of")
        .next()
        .expect("section body");

    let rows: Vec<(String, u64)> = section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect();
            (cells.len() == 5).then_some(())?;
            Some((cells[0].to_owned(), cells[3].parse::<u64>().ok()?))
        })
        .collect();
    assert_eq!(rows.len(), 13, "one row per benchmarked operation");

    let readme = read("README.md");
    for (operation, best_ns) in rows {
        let ops = (1e9 / best_ns as f64).round() as u64;
        assert_doc_contains(
            &readme,
            &format!("README.md ({operation})"),
            &with_commas(ops),
        );
    }
}
