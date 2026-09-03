# Validation Record

This record applies to the ShawnCore-Libraries working tree evaluated on
2026-09-03 in an Ubuntu 24.04.4 development container. The repository pins
Rust 1.85.0, the `rustfmt`/`clippy` components, and the `aarch64-unknown-none`
target in `rust-toolchain.toml`.

This is host-side evidence for a prototype. It does not establish target
hardware behavior, certification, production approval, or independent review.

## BUILD VALIDATION

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | Actually executed and passed. |
| `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` | PASS | Actually executed and passed. |
| `cargo check --workspace --all-targets` | PASS | Actually executed and passed. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS | Actually executed and passed. |
| `cargo build --workspace --release` | PASS | Actually executed and passed. |
| `cargo doc --workspace --no-deps` | PASS | Actually executed and passed. |
| `cargo check --target aarch64-unknown-none --workspace` | PASS | Actually executed and passed; compile check only, not target execution. |

## TEST VALIDATION

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --all-targets` | PASS | Actually executed and passed: 43 unit tests (23 crypto, 20 RTOS); the FFI facade has no unit tests. |

The executed tests cover AEAD and in-place round trips, authentication failure,
FFI null/zero-length/overlap handling, session re-establishment, replay,
reordering, replay-window commit for sequences below the window, entropy queue
reuse, DMA-pool stale-generation rejection, queue behavior, scheduler boundaries,
and state transitions.

## FFI VALIDATION

| Command or check | Result | Evidence |
| --- | --- | --- |
| C11 HAL syntax check | PASS | `make -C integration syntax` executed and passed. |
| C smoke executable | PASS | `make -C integration run` built and executed `integration/c_api_smoke.c` against `target/release/libshawncore_ffi.a`; exit status 0. |
| Public-symbol check | PASS | Header declarations and archive exports were compared and matched exactly: 119 symbols, empty diff. |
| AddressSanitizer C smoke | PASS | `make -C integration asan` built with `-fsanitize=address` and executed with `ASAN_OPTIONS=detect_leaks=1`; no findings. |
| Valgrind C smoke | PASS | `make -C integration valgrind` reported `ERROR SUMMARY: 0 errors from 0 contexts` and no leaks (0 allocs, 0 frees). |
| Rust-instrumented AddressSanitizer | BLOCKED | Attempted, but nightly failed to resolve `zeroize_derive` in sanitizer build mode (`E0463`). No Rust ASan result is claimed. |

The C smoke test checks ABI size/alignment, selected null errors, zero-length
AEAD/HKDF calls, and static-library linkage. It is not target C ABI or hardware
integration validation.

## FUZZING

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo check --manifest-path fuzz/Cargo.toml --bin ffi_aead_fuzz` | PASS | Actually executed and passed. |
| `cd fuzz && cargo +nightly fuzz run ffi_aead_fuzz -- -runs=1000 -max_len=512` | PASS | Actually executed: 1,000 executions seeded from 87 retained corpus files completed with no crash, no timeout, and no new artifact written. |

CI configures a separate fuzz job with 10,000 executions. It was not run
for this local record. The smoke campaign is evidence only for this harness and
duration; it is not proof of security.

## STATIC REVIEW

| Area | Result | Scope |
| --- | --- | --- |
| Unsafe code | REVIEWED | Raw pointers, FFI storage, callback conversion, stack canaries, queue payload access, and DMA byte zeroization were inspected. |
| FFI | REVIEWED | Null and zero-length conventions, overlap checks, opaque lifecycle, alignment, callback ABI, and session-manager aliasing were inspected. |
| Concurrency | MODEL PASS | SPSC ownership and Acquire/Release publication were reasoned about under the Rust memory model. No formal model checker was run. |
| DMA/cache | REVIEWED | Cache callback transitions and the limits of page alignment/atomics were inspected; hardware coherency was not tested. |
| Crypto | REVIEWED | AEAD lengths/authentication, X25519 checks, 128-byte hybrid KDF, directional key assignment, and cleanup paths were inspected. |
| Session/replay | REVIEWED | Authentication precedes replay-state commitment; re-establishment resets state before replacement keys are installed. |
| Package hygiene | PASS | `cargo package --list` for all three crates listed 45 source/metadata files with no generated artifact paths. |

## TARGET/HARDWARE VALIDATION

These are not host-prototype failures. They remain required before deployment or
any certification or approval conclusion.

| Gate | Result | Reason |
| --- | --- | --- |
| AArch64 target behavior and ABI | BLOCKED | The target compiled, but no target board or target C execution was available. |
| DMA/cache coherency and ownership | BLOCKED | Requires target memory map, device, cache-maintenance implementation, and board tests. |
| Interrupt, ISR/NMI/FIQ, watchdog, and stack behavior | BLOCKED | Requires approved HAL, RTOS integration, and hardware fault-path tests. |
| Hardware entropy quality | BLOCKED | Requires qualified source and target health testing. |
| ML-KEM/ML-DSA KATs and interoperability | BLOCKED | No external KAT/interoperability suite was executed. |
| Independent security review | BLOCKED | No independent review has been performed or claimed. |

## NOT YET VALIDATED

The target and external gates in the preceding table remain open. They are
explicitly outside the evidence collected in this host-side validation record.

## RELEASE HYGIENE

`.gitignore` excludes `target/`, `fuzz/target/`, fuzz crash artifacts, generated
documentation/packaging output, compiled object/library files, and editor/OS
metadata. Intentional fuzz corpus files and the fuzz lockfile are retained.
`git diff --check` and the editor diagnostic check completed without reported
errors.

The tracked source tree contains no generated build output. `target/` and
`fuzz/target/` are ignored local build directories and are not part of the
distribution set; they were removed from the working tree during release
cleanup, so reproducing this evidence requires rebuilding from source. Before
external distribution, commit the intended source set so the recipient can
reproduce this evidence from the delivered revision.
