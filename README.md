# ShawnCore Libraries

ShawnCore is a no-std Rust prototype for embedded systems that need hybrid cryptographic session establishment alongside deterministic RTOS synchronization primitives. It provides Rust APIs and C-callable FFI boundaries; platform integration remains the responsibility of the host firmware.

## Architecture

- `shawncore-pq-crypto`: ML-KEM-1024, ML-DSA-87, X25519, hybrid HKDF-SHA384 derivation, ChaCha20/HMAC-SHA384 authenticated encryption, entropy handling, session lifecycle management, and C FFI.
- `shawncore-rtos-sync`: DMA-pool ownership tracking, SPSC and ring buffers, priority scheduling, state machines, interrupt spinlocks, latency tracking, and telemetry support.
- `shawncore-ffi`: the C-linkable `staticlib` facade. It owns the required `no_std` panic handler and includes both component crates' exported FFI symbols.

The hybrid KDF returns exactly 128 bytes. For a responder, transmit material is bytes `0..32 || 96..128` and receive material is bytes `32..96`. The initiator applies the complementary assignment. Each directional key is therefore 64 bytes: 32 bytes for ChaCha20 encryption and 32 bytes for HMAC-SHA384 authentication. The handshake transcript includes a fixed protocol label, the ML-KEM ciphertext, the sender X25519 public key, and application info.

## Security Boundaries

Session decryption authenticates the packet before committing replay-window state. Duplicate and out-of-window nonces are rejected. Failed packet encryption does not advance the transmit sequence; exhaustion is rejected before a nonce is reused. Session and temporary derivation material are explicitly zeroized by the implementation where supported by the underlying types.

Rust atomic ordering establishes ordering and visibility under the Rust memory model. It does not itself flush processor caches, make data visible to a DMA device, or prove board-level coherency. The host must register platform-specific cache flush/invalidate callbacks where required and validate the resulting cache, barrier, interrupt, and DMA behavior on the target hardware.

The SPSC queues rely on one producer and one consumer, with exclusive slot ownership transferred through Acquire/Release publication. They are CPU-shared-memory structures. They are not a complete DMA protocol without host-provided cache-maintenance operations and a board-specific ownership contract.

## C FFI Contract

Build the C artifact with `cargo build -p shawncore-ffi --release`. Link the resulting `target/release/libshawncore_ffi.a` and include [`shawncore-ffi/include/shawncore.h`](shawncore-ffi/include/shawncore.h). The header exposes every ABI function, stable C payload layouts, and size/alignment queries for opaque Rust objects and queue slots.

Opaque objects must use the crate-exported `sizeof` and `alignof` values, be initialized exactly once, and be destroyed exactly once after all concurrent users stop. Pointer arguments must be valid, aligned for their declared object types, and live for the entire call. Buffers must satisfy their documented lengths and non-overlap requirements. A non-null pointer is not sufficient evidence that it is mapped, writable, owned by the caller, or valid for the required lifetime; those are host obligations.

Register panic, interrupt, monotonic-clock, watchdog, and cache callbacks before calling paths that require them. Callback registrations use C ABI function pointers and must remain valid for the duration of any possible call. The provided C HAL file is compile-only scaffolding, not an implementation of cache, interrupt, watchdog, panic, or clock behavior.

## Validation Status

**IMPLEMENTED:** AEAD, X25519, ML-KEM-1024, ML-DSA-87, hybrid KDF/session keys, FFI surfaces, RTOS primitives, and C HAL stubs.

**TESTED:** local Rust unit tests cover crypto round trips and tampering, selected FFI null/overlap handling, session establishment, replay-related paths, queue reuse/corruption paths, DMA-pool exhaustion and stale-generation rejection, scheduler boundaries, state transitions, and the FFT one-cache-line ABI. A C11 smoke program compiles, links, and executes against the release static library.

**FUZZED:** the `ffi_aead_fuzz` cargo-fuzz target supplies valid storage while varying bounded lengths and data, including malformed ciphertext, overlap, and null-with-length cases. Its compile check is part of CI; a fuzz campaign is a separate nightly CI job.

**STATICALLY REVIEWED:** strict Clippy, formatting, workspace checks, documentation build, C syntax compilation, and a bare-metal AArch64 type check are configured in CI.

**MODEL TESTED:** software tests exercise Rust-level ordering and API behavior only; they do not model cache-coherent DMA hardware.

**HARDWARE VALIDATED:** not yet validated by this repository.

**NOT YET VALIDATED:** target ABI interoperability, cache coherency, DMA visibility, ISR/NMI/FIQ behavior, watchdog behavior, entropy-source quality, sanitizer-backed native FFI misuse tests, ML-KEM/ML-DSA known-answer and external interoperability tests, and independent security review.

## Reproducible Checks

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo check --target aarch64-unknown-none --workspace
cargo check --manifest-path fuzz/Cargo.toml --bin ffi_aead_fuzz
cc -std=c11 -Wall -Wextra -Werror -I shawncore-ffi/include -fsyntax-only integration/martac_hal_stubs.c
cc -std=c11 -Wall -Wextra -Werror -I shawncore-ffi/include integration/c_api_smoke.c target/release/libshawncore_ffi.a -o /tmp/shawncore-c-api-smoke
/tmp/shawncore-c-api-smoke
```

`rust-toolchain.toml` pins Rust `1.85.0`, including the `aarch64-unknown-none` target used by the configured target check. Release profiles use `panic = "abort"` so a Rust panic cannot unwind through the C ABI; the host panic callback still needs a platform fail-safe response.

## Status and Claims

This is a prototype intended for technical evaluation. It implements ML-KEM-1024 and ML-DSA-87 using their selected dependency implementations and a hybrid key-establishment design. It is not a claim of FIPS certification, CNSA approval, operational USV readiness, or comprehensive security assurance. Those conclusions require independent review, known-answer and interoperability testing, target-specific validation, and host-organization acceptance testing.

## Distribution

This repository is proprietary and all rights are reserved. The crates are intentionally excluded from registry publication; distribution, evaluation, and integration require a separate written agreement with the copyright holder.
