# External Reviewer Quickstart

## Purpose and Status

ShawnCore-Libraries is a `no_std` Rust prototype for hybrid post-quantum
session establishment and deterministic RTOS synchronization primitives with a
C-callable boundary. It is intended for technical evaluation of library design
and integration contracts, not as certified production firmware or
hardware-qualified software.

The host validation record is in [VALIDATION.md](VALIDATION.md). It identifies
what executed locally and the target-hardware, interoperability, and independent
review gates that remain open. The trust boundaries, threat model, and host
integration contract are in [SECURITY.md](SECURITY.md). The design rationale,
diagrams, and measured footprint are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Architecture

- `shawncore-pq-crypto`: ML-KEM-1024, ML-DSA-87, X25519, HKDF-SHA384 hybrid
  derivation, ChaCha20/HMAC-SHA384 AEAD, entropy ingestion, session management,
  replay handling, and crypto FFI.
- `shawncore-rtos-sync`: scheduler, state machine, SPSC/ring queues, DMA-pool
  ownership tracking, interrupt synchronization, latency, and telemetry.
- `shawncore-ffi`: C-linkable `staticlib` facade and the single `no_std` panic
  handler.

The hybrid KDF produces 128 bytes. Responder transmit material is bytes
`0..32 || 96..128`; responder receive material is bytes `32..96`. The initiator
uses the complementary assignment.

## Important Boundaries

- Session decryption verifies authentication before committing replay-window
  state. Session re-establishment clears existing directional keys and replay
  state before replacing them.
- Raw AEAD callers must provide a unique 96-bit nonce for every encryption under
  one key pair. Session packet encryption manages nonces internally.
- SPSC, ring, and entropy queues require exactly one stable producer and one
  stable consumer. The Rust role operations are `unsafe`; C callers carry the
  same requirement.
- Page alignment is a storage/alignment requirement, not DMA pinning. Rust
  atomics publish writes under the language memory model but do not perform cache
  writeback. Registered host callbacks perform platform-specific cache work.
- The scheduler checks arithmetic, range, size, and alignment. The host owns
  task-stack mapping, writability, lifetime, ownership, and context switching.
- Opaque C objects require the exported size/alignment functions, one
  initialization, no concurrent destruction/use, and caller-owned valid storage.
- Values that cross a link use fixed-length wire codecs. In-memory forms are
  expanded and larger than their encodings. Decoding validates length and
  structure only and does not authenticate a peer. Secret key material has no
  serialization entry point.
- Callback registration can be cleared with `NULL`; replacement must not race
  invocation, and a registered callback must remain valid until all calls stop.

## Requirements

- Rust 1.85.0, the `rustfmt` and `clippy` components, and the
  `aarch64-unknown-none` target, all selected by `rust-toolchain.toml`.
- A C11 compiler for C integration checks.
- Optional: Rust nightly plus `cargo-fuzz`, Clang/ASan, and Valgrind.

From the repository root, run the basic Rust validation:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --release
cargo doc --workspace --no-deps
cargo check --target aarch64-unknown-none --workspace
```

## C FFI Checks

[`integration/Makefile`](integration/Makefile) wraps the checks below:
`make syntax`, `make run`, `make asan`, and `make valgrind`. The equivalent
explicit commands are:

```text
cc -std=c11 -Wall -Wextra -Werror -I shawncore-ffi/include -fsyntax-only integration/martac_hal_stubs.c
cc -std=c11 -Wall -Wextra -Werror -I shawncore-ffi/include integration/c_api_smoke.c target/release/libshawncore_ffi.a -o /tmp/shawncore-c-api-smoke
/tmp/shawncore-c-api-smoke
```

The sanitizer and memory-check variants exercise the C caller plus the linked
release archive. They do not instrument Rust dependencies unless the archive is
rebuilt with a working Rust sanitizer configuration.

```text
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address -fno-omit-frame-pointer -I shawncore-ffi/include integration/c_api_smoke.c target/release/libshawncore_ffi.a -o /tmp/shawncore-c-api-smoke-asan
ASAN_OPTIONS=detect_leaks=1 /tmp/shawncore-c-api-smoke-asan
valgrind --error-exitcode=1 --leak-check=full /tmp/shawncore-c-api-smoke
```

## Fuzz Smoke Test

```text
cargo check --manifest-path fuzz/Cargo.toml --bin ffi_aead_fuzz
cd fuzz
cargo +nightly fuzz run ffi_aead_fuzz -- -runs=1000 -max_len=512
```

The retained corpus is intentional regression input. A bounded smoke run is not
a security proof; CI configures a separate 10,000-execution fuzz job.

## Requested Technical Review

- Confirm the C ABI, object lifecycle, callback lifetime, and overlap contracts
  match the intended MARTAC integration environment.
- Evaluate the platform HAL contract for interrupt masking, fault handling,
  watchdog policy, monotonic clock behavior, and cache maintenance.
- Validate target stack layout/context-switch behavior and scheduler canary use.
- Define the DMA device ownership, pinning, cache, barrier, and reuse protocol
  for the selected board.
- Run target ABI and C interoperability tests with the real toolchain and HAL.
- Perform ML-KEM/ML-DSA KAT and external interoperability testing.
- Review the hybrid handshake transcript, directional keys, nonce policy, replay
  window, and cryptographic dependency choices.
- Assess entropy-source quality and ISR/NMI/FIQ integration constraints.

## Open Validation Gates

No certification, CNSA approval, FIPS certification, production readiness, or
independent security review is claimed. Target hardware behavior, real DMA/cache
coherency, interrupts, watchdog behavior, hardware entropy, KATs, external
interoperability, and independent security review remain required before
deployment. See [VALIDATION.md](VALIDATION.md) for each gate's exact status.
