# ShawnCore Libraries

No-std Rust libraries for embedded systems that need hybrid cryptography and deterministic RTOS synchronization primitives.

## Crates

- `shawncore-pq-crypto`: ML-KEM-1024, ML-DSA-87, X25519, hybrid HKDF derivation with separate Tx/Rx keys, ChaCha20/HMAC-SHA384 AEAD, entropy management, and C FFI.
- `shawncore-rtos-sync`: static DMA pools, SPSC queues, ring buffers, scheduling, state machines, and telemetry support.

## Verification

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo check --workspace --all-targets
cargo check --target aarch64-unknown-none --workspace
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo check --manifest-path fuzz/Cargo.toml --bin ffi_aead_fuzz
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only integration/martac_hal_stubs.c
```

The crypto crate includes round-trip tests for AEAD, HKDF, X25519, ML-KEM, ML-DSA, and the hybrid session manager.

The repository toolchain file pins Rust `1.85.0` and the `aarch64-unknown-none` target for the bare-metal build. This is required because the selected `ml-dsa` dependency resolves through `signature 3.x`, which requires Rust `1.85` and Edition 2024 support.

Release profiles use `panic = "abort"` so Rust panics cannot unwind across the C ABI. The MarTac firmware must still register the panic callback and implement the platform fail-safe response.

The `fuzz/` directory contains a cargo-fuzz harness for bounded malformed-input testing of the AEAD FFI. It intentionally uses valid in-process storage and fuzzed lengths; arbitrary invalid pointers cannot be safely dereferenced by a harness and require sanitizer-backed native FFI testing.

## FFI Requirements

The host must allocate each opaque object with the `sizeof` and `alignof` functions exported by its crate, initialize it exactly once, and destroy it exactly once. Object storage may be reused only after destruction, with all producers and consumers stopped. Host callbacks for cache flushing, stack wiping, panic handling, and RTOS interrupt save/restore must be registered before invoking paths that require them.

The FFI contracts require valid pointers, correct buffer lengths, and single-producer/single-consumer ownership where documented. The host must provide hardware-in-the-loop validation for DMA coherency, interrupt behavior, stack wiping, and target ABI integration.

RTOS SPSC queues require registered cache invalidate and flush callbacks before use. The DMA pool uses an ABA-tagged lock-free Treiber free list and returns an ownership generation with each allocation; both the index and generation are required to release a buffer. Lock-free does not mean wait-free under arbitrary contention, so callers must handle allocation failure deterministically.

Version 1.2 adds per-session Tx/Rx key integrity checks, per-slot seqlock validation against torn DMA reads, and a scheduler watchdog matrix. Critical tasks must call the scheduler check-in API before the configured watchdog window closes. A zero critical-task mask disables watchdog petting until configured by the host.

## Toolchain Note

`rust-toolchain.toml` pins the compiler and bare-metal target used by local and CI verification. MarTac should approve this toolchain for the target firmware build before integration.

## Compliance Notice

The libraries implement the ML-KEM and ML-DSA algorithms and a hybrid key-establishment design. This repository is not a claim of FIPS certification, CNSA approval, or operational USV readiness. Those claims require independent review, known-answer and interoperability testing, target-specific validation, and MarTac acceptance testing.
