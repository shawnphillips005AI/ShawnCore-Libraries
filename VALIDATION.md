> **VALIDATION DISCLAIMER:** The evidence recorded in this document reflects **host-environment simulation and testing only**. Target-specific hardware validation, including DMA coherency, ISR safety, cache maintenance, and silicon-specific timing, has not been executed. Host-level passes must not be substituted for on-device validation.

# Validation Record

This record documents the host-side validation evidence for the 12.3.11
release-candidate. Every row below was executed for 12.3.11 on 2026-10-21 unless
it is explicitly marked historical. Environment: Ubuntu 24.04.5 development
container, x86-64 host, Rust 1.99.1 (pinned in `rust-toolchain.toml` with
`rustfmt`, `clippy` and the `aarch64-unknown-none` target) plus the nightly
toolchain for ThreadSanitizer, AddressSanitizer, Miri and fuzzing.

This is host-side evidence for a prototype. It does not establish target
hardware behavior, certification, production approval, or independent review.

## BUILD VALIDATION

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | Executed and passed. |
| `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` | PASS | Executed and passed. |
| `cargo check --workspace --all-targets --locked` | PASS | Executed and passed. |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS | Executed and passed. |
| `cargo build --workspace --release --locked` | PASS | Executed and passed. |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | PASS | Executed and passed. |
| `cargo check --target aarch64-unknown-none --workspace --locked` | PASS | Executed and passed; compile check only, not target execution. |
| `cargo audit` and `cargo audit --file fuzz/Cargo.lock` | PASS | cargo-audit 0.22.2 against 1,348 advisories: no advisories for either lockfile (54 and 52 crates). |
| MSRV: tests, `aarch64-unknown-none` check and Lite check on Rust 1.88.0 | PASS | All 100 tests pass. 1.88 is the floor set by the `sha2` 0.11 dependency; the crates' own code builds there unchanged. |

## TEST VALIDATION

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --all-targets --locked` (debug and `--release`) | PASS | All 100 #[test] functions passed in both profiles: 53 in `shawncore-pq-crypto` (42 unit, 8 known-answer, 3 regression-vector), 37 in `shawncore-rtos-sync`, 1 in `shawncore-ffi` (panic-handler guard), 9 in the validation harness (including the version-drift guards). |
| `cargo test -p shawncore-pq-crypto --no-default-features --features lite --locked` | PASS | Lite suite: 49 tests (39 unit, 8 known-answer, 2 regression-vector); the ML-DSA tests are feature-gated out. |
| `cargo test -p shawncore-pq-crypto --no-default-features --features ml-dsa --locked` | PASS | Full crypto suite without `fast-x25519` (53 tests); the RFC 7748 X25519 vectors pass with and without the precomputed tables. |
| Repeated lib-test runs | PASS | The `shawncore-pq-crypto` unit-test binary ran 300 consecutive times with a 20 s hang timeout: 0 failures, 0 hangs. Before the test-callback fix the same loop hung in roughly 1 run in 17. |
| `validation/run_tsan.sh` (nightly ThreadSanitizer) | PASS | Standalone workload of 3 rounds x 100,000 SPSC and ring-buffer transfers completed with no reported data race. |
| `validation/run_asan.sh` (nightly, Rust-instrumented AddressSanitizer) | PASS | `shawncore-pq-crypto` (53) and `shawncore-rtos-sync` (37) test targets ran under `-Zsanitizer=address` with no report; leak detection was disabled for these runs. |
| `cargo +nightly miri test -p shawncore-rtos-sync` with `-Zmiri-symbolic-alignment-check` | PASS | 37 tests passed. With `-Zmiri-strict-provenance` the run stops at the first scheduler test: the scheduler API takes stack addresses as integers (`u64`) and casts them to pointers, which strict provenance rejects by design. Miri was not run on the lattice-heavy `shawncore-pq-crypto` tests; it ran on `shawncore-rtos-sync` (37 tests) and on the crypto crate's entropy-pool, entropy-queue and session-state unit tests (12), all with `-Zmiri-symbolic-alignment-check`. That run caught undefined behavior in the test-only cache-flush dispatcher (an integer-to-function-pointer transmute), which is fixed. |

Known-answer tests (`shawncore-pq-crypto/tests/known_answers.rs`) check HMAC-SHA384
against RFC 4231 cases 1 and 2, X25519 against the RFC 7748 section 6.1 vectors,
and HKDF-SHA384, the 128-byte hybrid KDF and the Encrypt-then-MAC framing against
vectors computed with Python `hmac`/`hashlib` and OpenSSL ChaCha20; a bit-flip
sweep rejects every single-bit change to a valid tag. These passed against the old
and the upgraded dependency set alike.

Regression vectors (`tests/pq_regression_vectors.rs`) pin ML-KEM-1024 and ML-DSA-87
output captured from `ml-kem` 0.2.3 and `ml-dsa` 0.1.1; `ml-kem` 0.3.3 reproduces
them byte for byte. They detect dependency drift and are **not** NIST ACVP vectors.

The executed tests cover AEAD and in-place round trips, authentication failure,
FFI null/zero-length/overlap handling, session re-establishment, replay,
reordering, replay-window commit for sequences below the window, entropy queue
reuse, DMA-pool stale-generation rejection, queue behavior, scheduler boundaries,
and state transitions.

The wire codec tests assert semantic equivalence rather than byte equality: a
decoded ML-KEM key is used to encapsulate and the original decapsulation key
recovers the same secret; a decoded X25519 key produces the same Diffie-Hellman
output as the peer; a decoded ML-DSA key verifies a signature decoded from its
own wire form and rejects a single-bit mutation of it.

The 12.3.10 regressions reject RTOS control-object/backing-storage aliasing,
RTOS result/control-object aliasing without consuming the queued item, DMA
allocation result aliasing, and ML-KEM output/public-key aliasing. A bounded
reentrant cache-callback test confirms the entropy pool releases its spinlock
before dispatching cache maintenance.

## FFI VALIDATION

| Command or check | Result | Evidence |
| --- | --- | --- |
| C11 HAL syntax check | PASS | `make -C integration syntax` executed and passed. |
| C++ header and smoke executable | PASS | `make -C integration cxx` built `integration/cxx_smoke.cpp` with `-std=c++17 -Wall -Wextra -Werror -pedantic`, linked the release archive, and ran a self-test and an HMAC-SHA384 vector. The header also passes `-fsyntax-only` as C++11/17/20, C99, C11 `-pedantic` and with `SHAWNCORE_LITE`. |
| C smoke executable | PASS | `make -C integration run` automatically built the release archive, then built and executed `integration/c_api_smoke.c`; exit status 0. |
| C wire handshake | PASS | The smoke binary drives two session managers through a complete hybrid handshake with every public value passed through its wire codec, then an authenticated packet exchange and a replay rejection. |
| Public-symbol check | PASS | Header declarations and archive exports were compared and matched exactly: 135 symbols, empty diff. |
| Self-contained archive check | PASS | `validation/check_archive.sh`: for `aarch64-unknown-none`, the set of undefined symbols minus the set of archive-defined symbols is empty, and `nm` shows no `malloc`, `free`, `__rust_alloc`, libc I/O, or pthread references. |
| AddressSanitizer C smoke | PASS | `make -C integration asan` built with `-fsanitize=address` and executed with `ASAN_OPTIONS=detect_leaks=1`; no findings. |
| Valgrind C smoke | PASS | `make -C integration valgrind` reported `ERROR SUMMARY: 0 errors from 0 contexts` and `in use at exit: 0 bytes in 0 blocks`. |
| Rust-instrumented AddressSanitizer | PASS | See `validation/run_asan.sh` above. The earlier `zeroize_derive` (`E0463`) failure came from sanitizing proc-macros; an explicit `--target` avoids it. |

The C smoke test checks ABI size/alignment, selected null errors, zero-length
AEAD/HKDF calls, wire codec rejection of null and wrong-length arguments, a full
two-party hybrid handshake conducted entirely through wire encodings, an
authenticated packet exchange, replay rejection, and static-library linkage. It
is not target C ABI or hardware integration validation.

## FUZZING

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo check --manifest-path fuzz/Cargo.toml --bin <target> --locked` (3 targets) | PASS | Executed and passed for `ffi_aead_fuzz`, `session_replay_fuzz` and `rtos_stateful_fuzz`. |
| `cd fuzz && cargo +nightly fuzz run ffi_aead_fuzz -- -runs=10000 -max_len=512` | PASS | 10,000 executions from the 91 retained corpus files; no crash, timeout or artifact. |
| `cd fuzz && cargo +nightly fuzz run session_replay_fuzz -- -runs=10000 -max_len=512` | PASS | 10,000 executions from the 256 retained corpus files (544 s); no crash, timeout or artifact. |
| `cd fuzz && cargo +nightly fuzz run rtos_stateful_fuzz -- -runs=10000 -max_len=512` | PASS | 10,000 executions from the 225 retained corpus files; no crash, timeout or artifact. |
| `cd fuzz && cargo +nightly fuzz run <ffi_aead_fuzz\|rtos_stateful_fuzz> -- -runs=500000 -max_len=512 -seed=7` | PASS | Extended campaigns: 500,000 executions each (93 s and 48 s); no crash, timeout or artifact. |

Corpus inputs discovered during these runs were not added to the repository. The
same three 10,000-execution campaigns are configured in CI. A bounded campaign is
evidence only for its harness and duration; it is not proof of security.

## STATIC REVIEW

| Area | Result | Scope |
| --- | --- | --- |
| Unsafe code | REVIEWED | Raw pointers, FFI storage, callback conversion, stack canaries, queue payload access, and DMA byte zeroization were inspected. |
| FFI | REVIEWED | Null and zero-length conventions, input/output/control/backing overlap checks, opaque lifecycle, alignment, callback ABI, and session-manager aliasing were inspected. |
| Concurrency | MODEL PASS | SPSC ownership and Acquire/Release publication were reasoned about under the Rust memory model. No formal model checker was run. |
| DMA/cache | REVIEWED | Cache callback transitions and the limits of page alignment/atomics were inspected; hardware coherency was not tested. |
| Crypto | REVIEWED | AEAD lengths/authentication, X25519 checks, 128-byte hybrid KDF, directional key assignment, and cleanup paths were inspected. |
| Session/replay | REVIEWED | Authentication precedes replay-state commitment; re-establishment resets state before replacement keys are installed. |
| Package hygiene | PASS | `cargo package --list` for all three crates listed 45 source/metadata files with no generated artifact paths. |

## TARGET/HARDWARE VALIDATION

The following items are explicitly out-of-scope for this host-level validation suite. They remain required before deployment or
any certification or approval conclusion.

| Gate | Result | Reason |
| --- | --- | --- |
| AArch64 target behavior and ABI | NOT EXECUTED | The target compiled, but no target board or target C execution was available. |
| DMA/cache coherency and ownership | NOT EXECUTED | Requires target memory map, device, cache-maintenance implementation, and board tests. |
| Interrupt, ISR/NMI/FIQ, watchdog, and stack behavior | NOT EXECUTED | Requires approved HAL, RTOS integration, and hardware fault-path tests. |
| Hardware entropy quality | NOT EXECUTED | Requires qualified source and target health testing. |
| ML-KEM/ML-DSA ACVP known-answer tests and interoperability | NOT EXECUTED | No external KAT or interoperability suite was run. Regression vectors exist but are not conformance evidence. |
| Independent security review | NOT EXECUTED | No independent review has been performed or claimed. |

## NOT YET VALIDATED

The target and external gates in the preceding table remain open. They are
explicitly outside the evidence collected in this host-side validation record.

## RELEASE HYGIENE

`.gitignore` excludes `target/`, `fuzz/target/`, fuzz crash artifacts, generated
documentation/packaging output, compiled object/library files, and editor/OS
metadata. Intentional fuzz corpus files and the fuzz lockfile are retained.
`git diff --check` completed without reported errors.

The tracked source tree contains no generated build output. `target/` and
`fuzz/target/` are ignored local build directories and are not part of the
distribution set, so reproducing this evidence requires rebuilding from source.
Before external distribution, commit the intended source set so the recipient can
reproduce this evidence from the delivered revision.

## MIRI

See the TEST VALIDATION table. The earlier maintainer-reported claim of a
workspace-wide pass with `-Zmiri-strict-provenance` was not reproduced and is no
longer carried forward: strict provenance rejects the scheduler's integer stack
addresses, and `shawncore-pq-crypto` has only been run under Miri on its entropy and session-state tests.

## Current Source Inventory

The repository contains **100 Rust functions annotated with `#[test]`**. All 100 were
executed and passed in the `cargo test --workspace --all-targets` runs recorded
above.

## Lite Validation Matrix

Lite and full configurations must be validated independently.

| Area | Full | Lite |
| --- | --- | --- |
| ML-KEM | enabled | enabled |
| X25519 | enabled | enabled |
| AEAD/session machinery | enabled | enabled |
| ML-DSA | enabled | omitted |
| RTOS synchronization | enabled | enabled |
| Entropy infrastructure | enabled | enabled |
| C FFI | enabled | reduced DSA surface |

For a Lite deployment, measure the final target artifact rather than assuming
that a Rust library archive size equals deployed firmware size. Record flash,
static RAM, stack high-water marks, transient cryptographic memory, interrupt
latency, watchdog margin, and DMA/cache behavior on the actual target.
