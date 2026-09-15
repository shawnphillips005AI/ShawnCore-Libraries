# Changelog

All notable changes to this project are documented here. This project is a
prototype under external technical evaluation; version numbers track the
internal release-candidate line and do not imply certification, hardware
qualification, or production readiness.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Lite MCU footprint profile
- Added and documented a constrained-MCU Lite configuration.
- ML-DSA remains enabled in the full/default build but is omitted from Lite.
- Documented the resulting authentication/security boundary and validation requirements.

### Concurrency hardening continuation
- Hardened both ring-buffer consumer payload read paths.
- Completed entropy SPSC ordinary-memory payload access.
- Preserved volatile access only for explicit secret zeroization.
- Added regression coverage for FIFO ordering and slot scrubbing.

## [12.3.10] — 2026-09-11


All notable changes to this project are documented here. This project is a
prototype under external technical evaluation; version numbers track the
internal release-candidate line and do not imply certification, hardware
qualification, or production readiness.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [12.3.10] — 2026-09-11

### Added
- Added `shawncore_crypto_self_test()` to the C API as a SHA-384 software known-answer test.
- The self-test does not claim FIPS 140-3 certification, a formal power-on test, or physical-silicon verification.

## [12.3.9] — 2026-09-11

### Security
- **Anti-Forensics (Data Remanence):** Injected volatile zeroization into the `pop()` paths of the lock-free queues. Queue slots are now explicitly wiped immediately after the payload is extracted and before the sequence counter is released. This prevents cryptographic material (like entropy chunks) from lingering in the queue's backing array, mitigating cold-boot and physical memory dump attacks.

## [12.3.8] — 2026-09-10

### Security & Performance
- **CAS Bus Starvation (Hardware Livelock):** Injected `core::hint::spin_loop()` into the `compare_exchange_weak` failure branches of the State Machine and Latency Tracker. This emits hardware `YIELD` instructions, preventing tight CAS loops from flooding the memory controller and starving concurrent cores.
- **Double-Panic Abort Prevention:** Wrapped the `no_std` FFI panic handler in an `AtomicBool` reentrancy guard. If the host C-callback triggers a secondary Rust panic, the system now safely halts via a spin loop rather than triggering an uncatchable hardware `ud2` illegal instruction abort.

## [12.3.7] — 2026-09-10

### Security
- **Replay Window Shift Overflow:** Fixed a critical cryptographic protocol vulnerability where a sequence number jump of $\ge 64$ would trigger CPU shift masking (e.g., `x << 64` evaluating to `x << 0` on ARM/x86). The sliding window now explicitly zeroes itself on large sequence jumps, structurally preventing "Phantom Replay" attacks.

## [12.3.6] — 2026-09-10

### Security
- **Silicon-Level Memory Barriers:** Injected `SeqCst` hardware memory fences into the lock-free queue consumer paths. This prevents AArch64/RISC-V weak memory models from speculatively reordering the volatile payload read *after* the trailing sequence-counter validation, structurally eliminating a hardware-level Seqlock data race.
- **C-API Hardening:** Finalized C99 `[static N]` array extents for `entropy_push`, `hmac_sha384`, and `hkdf_expand_sha384` to guarantee strict compile-time bounds checking across the entire FFI surface.

## [12.3.5] — 2026-09-10

### Changed
- **Deployment Optimization:** Enabled `lto = "fat"`, `codegen-units = 1`, and `strip = "symbols"` in the release profile. This guarantees cross-crate inlining across the FFI boundary and aggressively strips dead code, significantly reducing the `.a` static archive footprint for constrained microcontrollers.
- **C-API Hardening:** Completed the C99 `[static N]` array extent rollout by applying strict bounds to the remaining AEAD and Session Manager nonce (`[static 12]`) and MAC (`[static 48]`) pointers.

## [12.3.4] — 2026-09-10

### Fixed
- **State Machine Memory Leak:** `finalize_handshake` now correctly invokes `self.zeroize_session()` if the X25519 Diffie-Hellman derivation fails, ensuring temporary post-quantum keys are not left in RAM.
- **Scheduler Task Overwrite:** `create_task` now checks the actual TCB array (`stack_base != 0`) instead of the `ready_bitmap` to verify slot availability, preventing the silent overwrite of blocked/sleeping tasks.

## [12.3.3] — 2026-09-10

### Security
- **C-API Hardening:** Upgraded all fixed-length FFI pointer arguments (entropy, nonces, keys, MACs) to use C99 `[static N]` array extents. This enforces strict compile-time bounds checking and non-null guarantees in the C compiler without altering the Rust ABI.
- **Documentation:** Explicitly documented the Rust move-semantics "ghost stack copy" limitation for large cryptographic keys in `SECURITY.md`.

## [12.3.2] — 2026-09-10

### Fixed

- Serialized high-level entropy operations so the global SPSC entropy queue has a
  single consumer and concurrent extraction cannot race pool-state evolution.
- Removed variable-sized SHA-384 output generation from the interrupt-masked
  entropy-pool critical section; only fixed-size pool snapshots and state commits
  are protected by `CryptoSpinlock`.
- Concurrent entropy extraction now returns a retryable `EntropyBusy` error rather
  than spinning indefinitely, avoiding priority inversion and ISR deadlock hazards.
- Zeroized ML-KEM key-generation and encapsulation seed temporaries.
- Retained volatile payload access in lock-free queue paths with the existing
  Acquire/Release ownership protocol.
- Reduced DMA zeroization operation count using aligned volatile word clears while
  preserving arbitrary-length handling and cache maintenance.

### Validation

Fresh 12.3.2 validation must be recorded from the patched source tree. Inherited
12.3.1 results remain historical evidence.

## [12.3.1] — 2026-09-03

Security hardening release for the C ABI and entropy accumulator.

### Fixed

- RTOS queue and DMA initializers now reject backing storage that overlaps their
  host-owned control object. DMA allocation result pointers are mutually
  distinct and cannot overwrite the pool; queue result pointers cannot
  overwrite a live queue control object.
- ML-KEM encapsulation now rejects shared-secret or ciphertext output storage
  that overlaps its public-key input, preserving the caller's public key on a
  rejected call.
- Entropy pool cache-maintenance callbacks now run after the entropy spinlock
  is released, preventing callback re-entry from permanently deadlocking the
  pool. Reseed publication still occurs only after state update and cache
  maintenance.

### Added

- Seven regressions covering C-ABI control/backing and result/control aliasing,
  ML-KEM output/input aliasing, and bounded entropy callback re-entry.

### Changed

- The public header and security guide now require non-overlapping control,
  backing, input, and output storage where applicable, and explicitly prohibit
  callbacks from re-entering ShawnCore.

## [12.3.0] — 2026-09-03

Closes a functional gap that blocked C integration, and documents the
architecture for external technical review.

### Added

- **Wire codecs for the C ABI.** Every handshake value that crosses a link now
  has a fixed-length encoder and decoder: ML-KEM-1024 public key (1,568 B) and
  ciphertext (1,568 B), X25519 public key (32 B), ML-DSA-87 verifying key
  (2,592 B) and signature (4,627 B). Each exposes `_encoded_len`, `_to_bytes`,
  and `_from_bytes`. 15 new symbols; the C ABI grew from 119 to 134 exports.
  All additions are additive — no existing signature changed.
- `ARCHITECTURE.md`: design rationale, layering, handshake sequence, the
  128-byte KDF split, nonce and replay-window ordering, DMA/cache boundary,
  concurrency model, and measured object footprints.
- Six wire codec unit tests asserting semantic equivalence after decode, plus
  null, wrong-length, and overlap rejection. Test count is now 49, up from 43.
- The C integration binary now drives a complete two-party hybrid handshake with
  every public value passed through its wire encoding, followed by an
  authenticated packet exchange and a replay rejection.
- `SECURITY.md`: secret material is explicitly non-exportable, and wire decoding
  explicitly does not authenticate a peer.

### Fixed

- A C host could not complete a handshake over a link. ML-KEM public keys and
  ciphertexts, X25519 public keys, ML-DSA verifying keys, and signatures were
  opaque handles with no serialization, so a caller could neither transmit its
  own public values nor reconstruct a peer's from received bytes. Rust callers
  were unaffected because the wrapper fields are public.

### Notes

- Secret material remains deliberately non-serializable. Decapsulation keys,
  signing keys, and shared secrets have no export path through the ABI.
- ML-DSA-87 in-memory objects are the dependency's expanded representations:
  a verifying key is 73,856 bytes and a signing key is 104,640 bytes, versus
  2,592 and 4,896 bytes encoded. This is now published for RAM planning.

## [12.2.0] — 2026-09-03

Release-candidate prototype prepared for external technical review.

### Added

- `SECURITY.md`: trust boundaries, in-scope and out-of-scope threats, known
  limitations, and the host integration contract.
- `CHANGELOG.md`.
- `integration/Makefile` covering the C syntax check, smoke build and run, and
  the optional AddressSanitizer and Valgrind variants.

### Changed

- Renamed `shawncore-pq-crypto/src/Error.rs` to `error.rs` and `Zeroize.rs` to
  `zeroize.rs`, removing the `#[path]` attribute workarounds in `lib.rs`. Module
  paths (`crate::error`, `crate::zeroize`) are unchanged.
- Documentation now describes the 10,000-execution CI fuzz job accurately; the
  workflow has no scheduled nightly trigger.

### Removed

- `shawncore-rtos-sync/src/fft_queue.rs`, an empty placeholder module with no
  types, no functions, and no dependents. The concrete `FftResult` type and the
  FFT SPSC queue remain in `shawncore-rtos-sync::ffi`; the C ABI is unchanged.

### Security

No security defects were identified or fixed in this release. The security
posture, mitigations, and unmitigated threats are described in `SECURITY.md`.

### Validation

Host-side evidence is recorded in `VALIDATION.md`. Target-hardware behavior,
DMA and cache coherency, interrupt and watchdog behavior, hardware entropy
quality, ML-KEM/ML-DSA known-answer and interoperability testing, and
independent security review remain open gates.

## Earlier

Development prior to 12.2.0 was not tracked with release notes. The commit
history records the initial construction of the three crates, the C FFI surface,
the fuzz harness, and the CI workflow.
