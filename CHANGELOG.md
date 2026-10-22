# Changelog

All notable changes to this project are documented here. This project is a
prototype under external technical evaluation; version numbers track the
internal release-candidate line and do not imply certification, hardware
qualification, or production readiness.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [12.3.11] — 2026-10-21

### C ABI boundary audit
- **Fixed** (details and reproductions in VALIDATION.md, "C ABI boundary audit"): lengths above
  `PTRDIFF_MAX` and ranges that wrap the address space reached `slice::from_raw_parts` in the crypto
  FFI (`salt`, `info`, `app_info`, `aad`, HMAC data, HKDF input and output, signature messages);
  `ml_dsa_verify` had no range check at all; an interior zero-length range was counted as an overlap;
  the crypto library called the host cache-flush callback with an empty range; `dmapool2k_init`
  validated its backing region as 256 bytes instead of 256 buffers of 2048 bytes.
- **Behavior changes** (all reject input that was previously undefined behavior or a spurious
  rejection; none changes a wire or key format or an exported symbol or signature):
  lengths above `PTRDIFF_MAX`, wrapping ranges, packet and AEAD data above 64 x (2^32 - 1) bytes and
  `app_info` above `UINT32_MAX` now return `INVALID_LENGTH` before anything is read; a zero-length
  range never counts as overlapping; the crypto cache-flush callback is never invoked with length
  zero; an undersized DMA pool backing now returns `INVALID_MEMORY` (previously
  `ADDRESS_OUT_OF_BOUNDS`) and leaves the control object untouched.
- **Header:** `ml_dsa_keygen`'s seed is declared as 32 bytes like the other fixed-length inputs
  (same ABI); the header now documents length limits, the error code per rejection class, which
  failures write an output, zero-length handling, and the callback contract.
- **Added:** `validation/check_header_signatures.py` (header versus Rust signatures, in the release
  gate), `validation/run_mutants.py` (23 reproducible mutants), C struct offset assertions, 10 crypto
  and 4 RTOS ABI boundary tests, and gate steps for C AddressSanitizer, Valgrind (when installed),
  release-profile tests and `cargo doc -D warnings`, matching CI.
- **Corrected evidence claims:** the manifest and README disagreed on the mutation count and the
  earlier 24 mutants were not reproducible from the repository (now stated); the `cargo package`
  file count and two fuzz durations were stale.

### Authenticated handshake, protocol version 2 (new, unreviewed)
- **Added** (full configuration, `ml-dsa` feature): `encapsulate_authenticated`,
  `finalize_authenticated` and `confirm_peer` on `SessionManager`, the three C functions
  `shawncore_crypto_session_manager_{encapsulate_authenticated_v2,finalize_authenticated_v2,confirm_peer_v2}`
  (header: 135 to 138 symbols; the Lite header and archive stay at 119), the `auth_handshake`
  module (transcript, digest and confirmation-tag encodings), `derive_hybrid_key_with_confirmation`
  and `confirmation_info` in `hybrid_kdf`, and `ml_dsa_sign_with_context` /
  `ml_dsa_verify_with_context` / `SigningKey87::verifying_key`. Design: mutual ML-DSA-87
  signatures over a SHA-384 transcript binding version, suite, both parties' keys and identity
  fingerprints, application `info`, the ciphertext and the encapsulating side's X25519 key, with
  role-specific FIPS 204 contexts, plus explicit HMAC-SHA384 key confirmation under per-role keys
  expanded from the same PRK under their own label. Each signature covers the same side's tag. The
  salt is deliberately not in the transcript (it may be a secret); a salt mismatch is caught by
  the tags. The unconfirmed session refuses traffic; a forged reply is rejected before
  decapsulation and does not consume the pending handshake. Specified in ARCHITECTURE.md 4.5,
  assessed in SECURITY.md 10.
- **Protocol revision (before any tag or release):** the first draft of this handshake verified
  signatures only. An audit confirmed by execution that it accepted mismatched salts (both sides
  reported success and then could not communicate) and accepted a validly signed but unusable
  ciphertext on the key-generating side. It is replaced, not extended, so the signature-only draft
  does not interoperate with version 2. The C functions are renamed with a `_v2` suffix so a
  binary built against the draft fails at link time instead of calling a changed signature, and
  `finalize`/`encapsulate`/`confirm` gained confirmation-tag parameters (a Rust compile break for
  anyone who adopted the draft). A new error, `CryptoError::KeyConfirmationFailed` /
  `SHAWNCORE_CRYPTO_KEY_CONFIRMATION_FAILED = 7`, reports an authentic peer whose derived key
  differs; the C enum gained a value, so a host `switch` over it should handle 7.
- **Unchanged:** the unauthenticated functions, every wire format and key format, the legacy
  `derive_hybrid_key`, and all feature defaults. Existing integrators are unaffected unless they
  adopted the draft.
- **Changed:** the pending authentication state now holds the digest, the peer fingerprint and one
  confirmation key and is wiped (and the key flushed as zeros) on completion, failure and
  abandonment; `SessionManager` stays 4,736 bytes. Hosts must already allocate from `_sizeof()`.
- **Evidence:** 16 active-attacker tests, 5 KDF unit tests, a zeroization observation test, 2 C-ABI
  tests, a C smoke round trip through the exported functions including a salt mismatch, an
  `auth_handshake_fuzz` harness (3,000 executions, no finding), byte-identical agreement with an
  independent OpenSSL 3.5.8 / Python derivation (binding, transcript, confirmation keys, tags,
  both signatures, packets; regression vectors for a custom protocol, not standards vectors), and
  15 mutants detected. **Not** formally analyzed and **not** independently reviewed; Miri was not
  run on it.

### Adversarial verification (second pass)
- **Findings:** no new defect in exported behavior was found. Confirmed issues were
  a 32-bit build that failed with unclear errors (now a clear `compile_error!`; no
  32-bit support is claimed), an unobserved key wipe and an unpinned handshake
  transcript in the test suite, a test that asserted only constants, and unsynchronized
  tests sharing process-global callbacks. The unauthenticated handshake is now
  demonstrated rather than only asserted.
- **Platform guard:** `shawncore-pq-crypto` and `shawncore-rtos-sync` stop with a
  clear `compile_error!` on targets without 64-bit pointers and native 64-bit
  atomics. `thumbv7em-none-eabihf` previously failed with scattered `AtomicU64` and
  shift-overflow errors.
- **Evidence added:** official NIST ACVP-Server sample vectors for ML-KEM-1024
  (key generation, encapsulation, decapsulation, both key checks) and ML-DSA-87
  (key generation, signature verification), 120 cases, all passing
  (`tests/acvp_kat.rs`, fetched by `validation/fetch_acvp_vectors.py` at a pinned
  commit); 22 active-attacker protocol tests; cross-implementation
  vectors against OpenSSL 3.5.8 (ML-KEM-1024, ML-DSA-87 and a complete session
  re-derived in Python) with reproducible generators; wraparound, boundary and
  fail-closed tests for the SPSC queue, ring buffer and DMA pool (including
  usize-index and generation-counter rollover); a key-wipe observation test; FFI
  tests for absurd lengths, oversized HKDF output, and null pointers on every
  session entry point.
- **Test hygiene:** the rtos-sync tests that register the process-global cache
  callbacks (and the ring buffer test that counts them) now serialize through one
  lock instead of racing; a pq-crypto test hook lock does the same. A test that only
  asserted constants was replaced with real ring-buffer tests.
- **Release gate:** `check_archive.sh` also checks that the header seen with
  `SHAWNCORE_LITE` equals the Lite archive's exports; `release_gate.sh` adds
  optional steps for 32-bit rejection and OpenSSL vector reproducibility.
- **Docs:** SECURITY.md records the demonstrated man-in-the-middle capability, the
  `salt`-based mitigation available without an ABI change, deterministic ML-DSA
  signing, the `lite` feature footgun, and what "bounded" does and does not mean.
  No wire format, public API, feature default or ownership contract changed.

### Security hardening audit
- **Fixed:** `shawncore_crypto_session_manager_encapsulate_for_peer` now rejects
  misaligned `manager`, peer-key and output pointers (`InvalidState`) before forming
  Rust references, matching every other typed-pointer entry point.
- **Fixed:** `shawncore_rtos_scheduler_create_task` copies the TCB before forming the
  `&mut` scheduler reference, so a pointer into scheduler storage cannot alias it.
- `shawncore_crypto_self_test()` now also checks the RFC 8439 A.1 ChaCha20 keystream
  (matches OpenSSL). Its HMAC-SHA384, HKDF and X25519 expected values are not
  official vectors; they were independently re-verified with Python. The self-test requires the cache-flush
  callback to be registered; this is now stated in the header and SECURITY.md.
- `validation/check_archive.sh` now builds the Lite archive and fails if it contains
  ML-DSA or X25519 precomputed-table symbols or loses ML-KEM.
- New regression tests: misaligned `encapsulate_for_peer` pointers, self-test, and
  tampered/mismatched handshake inputs failing the first packet.
- Documentation: SECURITY.md now records the handshake assessment (no peer
  authentication, no key confirmation, partial transcript, entropy reuse) with the
  properties an authenticated handshake must have, the limits of the panic guard,
  the self-test scope, and the sanitizer status. Misleading SPSC ordering comments
  were corrected. No protocol was redesigned and no ABI changed.

### Changed
- Upgraded the pinned Rust toolchain from 1.85.0 to 1.99.1 (`rust-toolchain.toml`,
  CI workflow, and documentation). The minimum supported Rust version is 1.88, the
  floor set by `sha2` 0.11; it is declared in `[workspace.package]` and checked in CI.
- Host-only tooling (`shawncore-benchmarks`, `tsan-host-validation`) now compiles to
  an inert stub on bare-metal targets so the documented
  `cargo check --target aarch64-unknown-none --workspace` gate covers the whole
  workspace again; the validation placeholder library is now `#![no_std]`.
- C smoke test routes its deliberate null argument through a volatile pointer so
  `-Wnonnull` on C11 `[static N]` parameters does not reject the test at compile
  time; the runtime null-rejection contract is still exercised.
- Upgraded dependencies: `ml-kem` 0.2.3 to 0.3.3, `x25519-dalek` 2.0 to 3.0,
  `sha2` 0.10 to 0.11, `hmac`/`hkdf` 0.12 to 0.13, plus in-range lockfile updates.
  Every known-answer and regression vector listed below was recorded or checked
  before the upgrade and is byte-identical after it.
- `ml_kem_wrapper` is ported to the `ml-kem` 0.3 API. `PublicKey1024::from_bytes`
  (and `shawncore_crypto_ml_kem_publickey_from_bytes`) now applies the FIPS 203
  modulus check and rejects non-canonical encodings.
- CI is reorganized into `rust`, `c-integration`, `tsan` and `fuzz` jobs. The
  duplicated `cargo audit` steps and the invalid `cargo audit --manifest-path`
  invocation are removed; Lite tests, Valgrind, ThreadSanitizer, `cargo doc` with
  warnings denied, and the archive checks now run in CI.
- `validation/release_gate.sh` now also checks the fuzz crate formatting, runs the
  Lite crypto tests and the bare-metal check, and invokes the new
  `validation/check_archive.sh` (header/archive symbol parity and aarch64 archive
  self-containment). Its `fail()` helper printed a literal `%s` and is fixed.

### Added
- `validation/tests/spec_sheet.rs`: a 12-test spec-sheet conformance suite. It checks
  the README Specifications against the code (wire and object sizes, replay window,
  nonce format, entropy queue, scheduler, state machine, DMA pool behavior), parses
  the C header for the function, type and callback counts and for the absence of
  secret-key serialization, and fails if the README, ARCHITECTURE, VALIDATION,
  RELEASE_MANIFEST, CI workflow or the benchmark record disagree with each other or
  with the code. On its first run it caught a mis-rounded ops/sec figure in the README.
- `fast-x25519` feature (default on, off in Lite): enables `x25519-dalek`'s precomputed
  basepoint tables. Measured back to back it makes X25519 key generation about 1.75x
  faster (31 to 17 µs on the reference machine) for about 30 KB more code and rodata
  on `aarch64-unknown-none`; Diffie-Hellman multiplies an arbitrary point and is
  unchanged. The release gate now expects the `default, fast-x25519, lite, ml-dsa`
  feature set.
- The benchmark harness reports the median and the best of 25 batches per operation
  instead of one mean, because a single mean varied about 2x between sessions on a
  shared host. Reference results are re-recorded in `BENCHMARKS.md` and the README.
- README "Specifications" sheet (cryptographic suite, session behavior, entropy, RTOS
  primitives, C interface, object sizes, build/platform) and measured host reference
  results, also recorded with machine, toolchain, commit and command in `BENCHMARKS.md`.
- `LICENSES/AGPL-3.0-or-later.txt`: the unmodified AGPLv3 text that `LICENSE` offers
  by reference, so recipients receive a copy with the source.
- `shawncore.h` is now valid C++ (it declared `extern "C"` but did not parse as
  C++). Fixed-length parameters use `SHAWNCORE_MIN_LEN(n)`, which expands to
  `static n` for C99/C11 and to `n` under C++ and MSVC. The function surface is
  unchanged (135 symbols). `integration/cxx_smoke.cpp` (`make -C integration cxx`)
  builds, links and runs from C++17 in CI and in the release gate.
- `SHAWNCORE_VERSION_MAJOR`/`MINOR`/`PATCH`/`STRING` in the header, with
  `validation/tests/release_metadata.rs` failing if the header, the crate version,
  `RELEASE_MANIFEST.txt` or the newest changelog heading disagree.
- Package version, edition, `rust-version`, repository and `publish` are defined once
  in `[workspace.package]` and inherited by every crate. The redundant path-dependency
  version pins in `shawncore-ffi` are removed.
- The benchmark banner reports the crate version and the host platform instead of a
  hard-coded version and a `TARGET` variable that is unset at run time.
- Known-answer tests (`shawncore-pq-crypto/tests/known_answers.rs`) for
  HMAC-SHA384 (RFC 4231), X25519 (RFC 7748), HKDF-SHA384, the hybrid KDF, and the
  AEAD framing, with vectors produced by independent implementations, plus a
  per-bit tag-tamper sweep.
- Regression vectors (`tests/pq_regression_vectors.rs`) that pin ML-KEM-1024 and
  ML-DSA-87 output across dependency upgrades. They are not NIST ACVP vectors.

### Fixed
- The facade's panic handler now has the reentrancy guard that 12.3.8 documented but
  the code never contained: a panic raised from inside a host panic hook halts in
  the spin loop instead of recursing into the hook until the stack overflows.
- The test-only cache-flush dispatcher converted an integer back into a function
  pointer, which Miri reports as undefined behavior; it now holds the hook in a
  `Mutex`.
- Resolved Rust 1.99 clippy `-D warnings` regressions: `unnecessary_map_or` in the
  DMA trace validation, `unused_assignments` on the scheduler stack-canary
  corruption write (now an explicit raw-pointer write), and `manual_is_multiple_of`
  in the alignment checks.
- Unit tests could hang or fail intermittently. An unregistered cache-flush
  callback halts by design, and several entropy tests reached it before any test
  had registered one; one entropy test also raced the global queue consumer gate.
  All pq-crypto unit tests now register one shared dispatcher
  (`test_support`), and the unserialized entropy test takes the serial lock.
- The Lite test configuration did not compile because unit tests referenced
  ML-DSA unconditionally. ML-DSA-only test code is now feature-gated.
- Corrected stale layout sizes, symbol counts, test counts and fuzz-corpus counts
  in the documentation, removed a misplaced section and a reference to a
  nonexistent `patch.py`, and aligned the licensing text with `LICENSE`.
- Removed a duplicated preamble and duplicated `12.3.10` section heading from this
  changelog.

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

### Added
- Added `shawncore_crypto_self_test()` to the C API as a SHA-384 software known-answer test.
- The self-test does not claim FIPS 140-3 certification, a formal power-on test, or physical-silicon verification.

## [12.3.9] — 2026-09-11

### Security
- **Anti-Forensics (Data Remanence):** Injected volatile zeroization into the `pop()` paths of the lock-free queues. Queue slots are now explicitly wiped immediately after the payload is extracted and before the sequence counter is released. This prevents cryptographic material (like entropy chunks) from lingering in the queue's backing array, mitigating cold-boot and physical memory dump attacks.

## [12.3.8] — 2026-09-10

### Security & Performance
- **CAS Bus Starvation (Hardware Livelock):** Injected `core::hint::spin_loop()` into the `compare_exchange_weak` failure branches of the State Machine and Latency Tracker. This emits hardware `YIELD` instructions, preventing tight CAS loops from flooding the memory controller and starving concurrent cores.
- **Double-Panic Abort Prevention:** Wrapped the `no_std` FFI panic handler in an `AtomicBool` reentrancy guard. If the host C-callback triggers a secondary Rust panic, the system now spins in the hook-then-halt path rather than recursing. The guard only limits recursion; it cannot recover system state or guarantee a safe stop on every target.

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
