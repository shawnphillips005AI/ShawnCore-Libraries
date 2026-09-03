# ShawnCore Libraries

ShawnCore is a no-std Rust prototype for embedded systems that need hybrid cryptographic session establishment alongside deterministic RTOS synchronization primitives. It provides Rust APIs and C-callable FFI boundaries; platform integration remains the responsibility of the host firmware.

It is a release-candidate prototype for external technical evaluation, not certified or hardware-qualified production software.

## Why It Exists

The project is an evaluable prototype for firmware teams considering hybrid post-quantum session establishment and bounded RTOS coordination. It keeps platform-specific hardware control, cache maintenance, interrupt behavior, stack provisioning, and entropy collection outside the Rust libraries so those assumptions are visible for review.

## Architecture

- `shawncore-pq-crypto`: ML-KEM-1024, ML-DSA-87, X25519, hybrid HKDF-SHA384 derivation, ChaCha20/HMAC-SHA384 authenticated encryption, entropy handling, session lifecycle management, and C FFI.
- `shawncore-rtos-sync`: DMA-pool ownership tracking, SPSC and ring buffers, priority scheduling, state machines, interrupt spinlocks, latency tracking, and telemetry support.
- `shawncore-ffi`: the C-linkable `staticlib` facade. It owns the required `no_std` panic handler and includes both component crates' exported FFI symbols.

The hybrid KDF returns exactly 128 bytes. For a responder, transmit material is bytes `0..32 || 96..128` and receive material is bytes `32..96`. The initiator applies the complementary assignment. Each directional key is therefore 64 bytes: 32 bytes for ChaCha20 encryption and 32 bytes for HMAC-SHA384 authentication. The handshake transcript includes a fixed protocol label, the ML-KEM ciphertext, the sender X25519 public key, and application info.

## Security Boundaries

[SECURITY.md](SECURITY.md) is the authoritative statement of the trust boundaries, the threats this repository does and does not mitigate, known limitations, and the host integration contract. Read it before integrating.

Session decryption authenticates the packet before committing replay-window state. Duplicate and out-of-window nonces are rejected. Failed packet encryption does not advance the transmit sequence; exhaustion is rejected before a nonce is reused. Re-establishment zeroizes prior directional keys and resets transmit and replay state before installing replacement keys. Session and temporary derivation material are explicitly zeroized by the implementation where supported by the underlying types.

The raw AEAD API requires a unique 96-bit nonce for every encryption under a given key pair. Session packet encryption assigns and tracks nonces internally; raw AEAD callers own nonce generation and uniqueness.

## RTOS and Concurrency Model

SPSC queues and the entropy queue require one stable producer and one stable consumer for their full initialized lifetimes. The Rust APIs mark producer/consumer operations `unsafe` because their roles cannot be proven by a shared reference; C callers carry the same contract. Slots transfer ownership through publication and consumption using Acquire/Release ordering, and tested software behavior covers FIFO, full/empty, repeated reuse, and unstable slot sequence rejection.

The scheduler validates priority bounds, stack range arithmetic, stack alignment, and stack size. The host is responsible for mapped writable task-stack memory, stack lifetime and ownership, and platform context-switch behavior. The scheduler writes and verifies a canary at the stack base; it is not a substitute for target stack analysis or an MPU configuration.

## DMA and Cache Model

Rust atomic ordering establishes ordering and visibility under the Rust memory model. It does not itself flush processor caches, make data visible to a DMA device, or prove board-level coherency. The host must register platform-specific cache flush/invalidate callbacks where required and validate the resulting cache, barrier, interrupt, and DMA behavior on the target hardware.

The SPSC queues and ring buffer invoke registered cache callbacks around CPU producer/consumer slot transitions. The DMA pool flushes a CPU-side zeroization before it republishes a freed slot. These calls do not establish DMA pinning, physical ownership, or a complete device protocol. Page alignment is an alignment/storage requirement, not proof of DMA pinning. The host must quiesce any device before freeing its allocation and define cache ownership transitions before target validation.

## C FFI Model

Build the C artifact with `cargo build -p shawncore-ffi --release`. Link the resulting `target/release/libshawncore_ffi.a` and include [`shawncore-ffi/include/shawncore.h`](shawncore-ffi/include/shawncore.h). [`integration/Makefile`](integration/Makefile) drives the C syntax check, smoke build, execution, and the optional sanitizer and Valgrind variants. The header exposes every ABI function, stable C payload layouts, and size/alignment queries for opaque Rust objects and queue slots.

Opaque objects must use the crate-exported `sizeof` and `alignof` values, be initialized exactly once, and be destroyed exactly once after all concurrent users stop. Pointer arguments must be valid, aligned for their declared object types, and live for the entire call. Buffers must satisfy their documented lengths and non-overlap requirements. A non-null pointer is not sufficient evidence that it is mapped, writable, owned by the caller, or valid for the required lifetime; those are host obligations.

Register panic, interrupt, monotonic-clock, watchdog, and cache callbacks before calling paths that require them. Callback registrations may be cleared with `NULL`, but registration/replacement must not race invocation; callbacks must remain valid for the duration of any possible call and must not unwind, throw, or `longjmp` through Rust. The provided C HAL file is compile-only scaffolding, not an implementation of cache, interrupt, watchdog, panic, or clock behavior.

## Cryptographic Components

The project integrates ML-KEM-1024, ML-DSA-87, X25519, HKDF-SHA384, and a ChaCha20/HMAC-SHA384 Encrypt-then-MAC construction through selected no-std dependencies and local wrappers. It does not claim certification, interoperability, or platform approval for those components.

## Testing

Rust unit tests cover cryptographic round trips and tampering, FFI null/zero-length/overlap handling, re-establishment, replay rejection and reordering, queue corruption/reuse, DMA-pool exhaustion and stale generations, and scheduler boundary behavior. The C smoke program compiles, links, and executes basic public ABI, null, and zero-length checks against the release static library.

## Fuzzing

The `ffi_aead_fuzz` cargo-fuzz target supplies valid backing storage while varying bounded lengths and data, including malformed ciphertext, overlap, and null-with-length cases. Its regression corpus and lockfile are retained in the source tree. A successful compile check is not a fuzz campaign; the configured CI fuzz job runs 10,000 executions on the Rust nightly toolchain.

## Validation Status

**IMPLEMENTED:** AEAD, X25519, ML-KEM-1024, ML-DSA-87, hybrid KDF/session keys, FFI surfaces, RTOS primitives, and C HAL stubs.

**TESTED:** local Rust unit tests cover crypto round trips and tampering, FFI null/zero-length/overlap handling, session re-establishment and replay paths, queue reuse/corruption paths, DMA-pool exhaustion and stale-generation rejection, scheduler boundaries, state transitions, and the FFT one-cache-line ABI. A C11 smoke program compiles, links, and executes against the release static library.

**FUZZED:** a fuzz target, regression corpus, and a 10,000-execution CI fuzz job are configured. Compile checks are not reported as fuzz executions.

**STATICALLY REVIEWED:** strict Clippy, formatting, workspace checks, documentation build, C syntax compilation, and a bare-metal AArch64 type check are configured in CI.

**MODEL TESTED:** no formal model checking or exhaustive concurrency-state model has been performed. Rust unit tests exercise implementation behavior only; they do not model cache-coherent DMA hardware.

**HARDWARE VALIDATED:** not yet validated by this repository.

**NOT YET VALIDATED:** target ABI interoperability, cache coherency, DMA visibility, ISR/NMI/FIQ behavior, watchdog behavior, entropy-source quality, sanitizer-backed native FFI misuse tests, ML-KEM/ML-DSA known-answer and external interoperability tests, free-list ABA-tag wraparound, and independent security review.

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

`rust-toolchain.toml` pins Rust `1.85.0`, the `rustfmt` and `clippy` components, and the `aarch64-unknown-none` target used by the configured target check. Release profiles use `panic = "abort"` so a Rust panic cannot unwind through the C ABI; the host panic callback still needs a platform fail-safe response.

## Limitations

This is a prototype intended for technical evaluation. It is not a claim of FIPS certification, CNSA approval, operational USV readiness, or comprehensive security assurance. The 32-bit DMA-pool free-list ABA tag can wrap after $2^{32}$ free-list mutations; deployments must bound that operational lifetime or reinitialize the pool. The retained regression tests do not establish target timing, cache, or physical-memory behavior.

## External Review Status

Independent security review, ML-KEM/ML-DSA known-answer and interoperability testing, target ABI validation, and board-level cache/DMA, interrupt, watchdog, entropy, and stack validation remain required before deployment or any certification/approval conclusion.

## Distribution

This repository is proprietary and all rights are reserved. The crates are intentionally excluded from registry publication; distribution, evaluation, and integration require a separate written agreement with the copyright holder.

## Repository Map

| Document | Contents |
| --- | --- |
| [SECURITY.md](SECURITY.md) | Trust boundaries, threat model, known limitations, host integration contract |
| [REVIEW.md](REVIEW.md) | External reviewer quickstart and requested review scope |
| [VALIDATION.md](VALIDATION.md) | Host-side validation record and open external gates |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
