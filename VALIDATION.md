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
| MSRV: tests, `aarch64-unknown-none` check and Lite check on Rust 1.88.0 | PASS | All 171 tests pass. 1.88 is the floor set by the `sha2` 0.11 dependency; the crates' own code builds there unchanged. |

## TEST VALIDATION

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --all-targets --locked` (debug and `--release`) | PASS | All 171 #[test] functions passed in both profiles: 105 in `shawncore-pq-crypto` (54 unit, 8 known-answer, 3 regression-vector, 22 adversarial protocol, 4 OpenSSL cross-implementation, 5 ACVP, 9 authenticated handshake), 44 in `shawncore-rtos-sync`, 1 in `shawncore-ffi` (panic-handler guard), 21 in the validation harness (host traces, layout contracts, version-drift guards and the 12-test spec-sheet suite). |
| `cargo test -p shawncore-pq-crypto --test adversarial_protocol --test openssl_interop --locked` | PASS | 22 active-attacker tests and 3 cross-implementation tests (see the sections below the table). |
| `cargo test -p shawncore-pq-crypto --no-default-features --features lite --locked` | PASS | Lite suite: 87 tests (49 unit, 8 known-answer, 22 adversarial protocol, 2 regression-vector, 2 OpenSSL cross-implementation, 4 ACVP); the ML-DSA tests are feature-gated out. |
| `cargo test -p shawncore-validation --test spec_sheet --locked` | PASS | 12 tests: crypto and wire sizes, replay window (offset 63 accepted, 64 rejected), nonce format, uniform-entropy rejection, entropy queue capacity and mix bound, scheduler/state machine/TCB, DMA pool alignment, token and zeroization behavior, object sizes, the C header surface (function, type and callback counts, no secret-key serialization), and drift checks that the README, ARCHITECTURE, VALIDATION, RELEASE_MANIFEST, CI workflow and BENCHMARKS record state the same numbers. It found a mis-rounded ops/sec figure in the README on its first run. |
| `cargo test -p shawncore-pq-crypto --no-default-features --features ml-dsa --locked` | PASS | Full crypto suite without `fast-x25519` (105 tests); the RFC 7748 X25519 vectors pass with and without the precomputed tables. |
| Repeated lib-test runs | PASS | The `shawncore-pq-crypto` unit-test binary ran 300 consecutive times with a 20 s hang timeout: 0 failures, 0 hangs. Before the test-callback fix the same loop hung in roughly 1 run in 17. |
| `validation/run_tsan.sh` (nightly ThreadSanitizer) | PASS | Standalone workload of 3 rounds x 100,000 SPSC and ring-buffer transfers completed with no reported data race. |
| `validation/run_asan.sh` (nightly, Rust-instrumented AddressSanitizer) | PASS | `shawncore-pq-crypto` (105) and `shawncore-rtos-sync` (44) test targets ran under `-Zsanitizer=address` with no report; leak detection was disabled for these runs. |
| `cargo +nightly miri test -p shawncore-rtos-sync` with `-Zmiri-symbolic-alignment-check` | PASS | 44 tests passed. With `-Zmiri-strict-provenance` the run stops at the first scheduler test: the scheduler API takes stack addresses as integers (`u64`) and casts them to pointers, which strict provenance rejects by design. Miri was not run on the lattice-heavy ML-KEM/ML-DSA tests or on the OpenSSL interop tests. It ran on all 44 `shawncore-rtos-sync` tests and on 24 `shawncore-pq-crypto` tests (entropy pool and queue, session counters, replay window, key-wipe observation, wire-codec pointer validation, and the null/oversized-length/misalignment FFI tests), all with `-Zmiri-symbolic-alignment-check`; the only diagnostic was the expected integer-to-pointer cast warning from the deliberately bogus never-dereferenced address in `absurd_lengths_are_rejected_before_any_dereference`. The earlier run caught undefined behavior in the test-only cache-flush dispatcher (an integer-to-function-pointer transmute), which is fixed. |

Known-answer tests (`shawncore-pq-crypto/tests/known_answers.rs`) check HMAC-SHA384
against RFC 4231 cases 1 and 2, X25519 against the RFC 7748 section 6.1 vectors,
and HKDF-SHA384, the 128-byte hybrid KDF and the Encrypt-then-MAC framing against
vectors computed with Python `hmac`/`hashlib` and OpenSSL ChaCha20; a bit-flip
sweep rejects every single-bit change to a valid tag. These passed against the old
and the upgraded dependency set alike.

Regression vectors (`tests/pq_regression_vectors.rs`) pin ML-KEM-1024 and ML-DSA-87
output captured from `ml-kem` 0.2.3 and `ml-dsa` 0.1.1; `ml-kem` 0.3.3 reproduces
them byte for byte. They detect dependency drift and are not conformance vectors; the official ACVP vectors are in the next section.

## Official ACVP known-answer tests

`shawncore-pq-crypto/tests/acvp_kat.rs` runs the **official NIST ACVP-Server sample
vectors** (usnistgov/ACVP-Server, commit `975de31eb83d87039ec88934fdc47d8c312b892d`, vector
set id 42), copied verbatim into `tests/vectors/acvp_fips203_204.txt` by
`validation/fetch_acvp_vectors.py` with the source file hashes recorded in its header. All pass:

| Set | Cases | Checked |
| --- | ---: | --- |
| ML-KEM-1024 key generation | 25 | Encapsulation key and the 3,168-byte expanded decapsulation key from `d`, `z` |
| ML-KEM-1024 encapsulation | 25 | Ciphertext and shared secret from `ek`, `m` |
| ML-KEM-1024 decapsulation | 10 | Shared secret from the supplied expanded key and ciphertext |
| ML-KEM-1024 encapsulation-key check | 10 | Accept/reject verdict of `PublicKey1024::from_bytes` (FIPS 203 modulus check) |
| ML-KEM-1024 decapsulation-key check | 10 | Accept/reject verdict when loading the expanded key |
| ML-DSA-87 key generation | 25 | Public key from the 32-byte seed |
| ML-DSA-87 signature verification (external, pure) | 15 | Every accept/reject verdict, with the vector's context string |

These are the published sample vectors, not a CAVP/CMVP validation or FIPS certificate, and
they say nothing about timing. Not exercised because the library has no entry point for
them: ML-DSA signature generation from an expanded key, non-empty-context signing and
pre-hash modes. Expanded-form decapsulation keys are deprecated in the `ml-kem` crate and are
used here only because ACVP supplies them.

## Cross-implementation vectors

`shawncore-pq-crypto/tests/openssl_interop.rs` compares ShawnCore against
**OpenSSL 3.5.8**, an implementation independent of the `ml-kem` and `ml-dsa`
crates, using `tests/vectors/openssl_interop.txt`. The file is produced entirely
by `validation/gen_openssl_vectors.sh` and `validation/gen_session_vector.py`
(re-running it reproduces the file byte for byte). Results, all passing:

| Check | Outcome |
| --- | --- |
| ML-KEM-1024 public key derived from a 64-byte seed (2 seeds) | Identical to OpenSSL's |
| ML-KEM-1024 encapsulation with fixed 32-byte entropy (2 cases) | Ciphertext and shared secret identical to OpenSSL's |
| ML-KEM-1024 decapsulation of OpenSSL's ciphertext | Recovers OpenSSL's secret |
| ML-KEM-1024 decapsulation of a one-bit-flipped ciphertext | Returns OpenSSL's implicit-rejection secret (not an error) |
| ML-DSA-87 public key derived from a 32-byte seed | Identical to OpenSSL's |
| ML-DSA-87 deterministic signature | Identical to OpenSSL's 4,627-byte signature, which OpenSSL also verified; altered message or signature bit rejected |
| One complete hybrid session | Handshake ciphertext, both X25519 public keys, and both directions' packet ciphertext and tag identical to a Python/OpenSSL re-implementation of the documented transcript, key split, nonce and MAC framing |

These are cross-implementation vectors, **not** NIST ACVP vectors; they cover the
listed inputs only and say nothing about timing. The session vector re-implements
the protocol from its documentation, so it detects divergence from the documented
design, not a flaw in the design itself.

## Adversarial protocol tests

`shawncore-pq-crypto/tests/adversarial_protocol.rs` (22 tests, public API only)
models an active network attacker. Observed outcomes:

| Attack | Result |
| --- | --- |
| Reflecting a packet back to its sender | Rejected (`VerificationFailed`): directional keys differ |
| Duplicate packet | First accepted, second rejected |
| Reordering inside the 64-packet window | Every packet accepted exactly once |
| Authentic packet older than the window | Rejected (offset 63 accepted, 64 rejected) |
| Forged tag or forged far-future sequence number | Rejected, and the replay window is not moved; the genuine packet is still accepted afterwards |
| Every single-bit flip in ciphertext, AAD, nonce and tag | Every one rejected |
| Nonzero reserved nonce bytes; truncated, extended or length-mismatched ciphertext | Rejected |
| Failed authentication | Output buffer wiped; a replayed packet leaves no plaintext in the output |
| Packet from a previous session after re-keying | Rejected; **but** reusing identical entropy on both sides reproduces the keys and the old packet is accepted (documented host obligation) |
| Traffic before a handshake or after `zeroize_session` | Rejected |
| `finalize_handshake` with no pending handshake, or replayed a second time | Rejected; a live session is not disturbed |
| Failed finalize (low-order X25519 point) | Consumes the pending handshake; retry requires a new `initiate_handshake` |
| Uniform all-zero / all-`0xFF` entropy | Rejected without side effects |
| Active intermediary between two endpoints | **Succeeds**: relays and rewrites traffic undetected. The handshake is unauthenticated; see SECURITY.md section 10 |
| Intermediary without a pre-shared `salt` | Cannot decrypt the victim's first packet (a mitigation, not a reviewed protocol) |

## Authenticated handshake

`shawncore-pq-crypto/tests/authenticated_handshake.rs` (9 tests, full configuration only), two
C-ABI tests in `src/ffi.rs`, and `openssl_interop.rs::authenticated_handshake_matches_an_independent_implementation`
exercise the design in ARCHITECTURE.md section 4.5. All pass.

| Attack or property | Outcome |
| --- | --- |
| Intermediary with its own identity answers the key-generating side | `VerificationFailed`; the pending handshake survives and the genuine reply then succeeds |
| Tampered ciphertext, encapsulator X25519 key, signature, or application info | Each rejected with `VerificationFailed`; none consumes the pending handshake |
| Genuine reply checked against the wrong trust anchor | Rejected |
| Forged keygen-side signature under the pinned identity, and a valid signature from a different identity | Both rejected by `confirm_peer`; the session stays unconfirmed and refuses traffic until the genuine signature arrives |
| One key used on both sides: encapsulator signature reflected as the keygen proof, and keygen-role signature offered as the encapsulator signature | Both rejected: only the FIPS 204 context differs |
| Reply recorded from an earlier handshake replayed against a new ephemeral key | Rejected |
| `confirm_peer` / `finalize_authenticated` with nothing pending; abandoned session | `InvalidState`, no side effects |
| Unconfirmed encapsulating side sends or receives | `InvalidState` until `confirm_peer` succeeds |
| Binding and transcript hashes | Differ for every changed input (ek, X25519 keys, either identity, role order, application info, ciphertext) |
| C ABI | Round trip through the exported functions, forged reply rejected without writing outputs, null/misaligned/overlapping/short-salt arguments rejected, outputs written only on success |
| Independent derivation (OpenSSL 3.5.8 ML-DSA with FIPS 204 contexts, ML-KEM, Python for hashes, X25519, HKDF and packet framing) | Identity keys, `binding`, `transcript`, both signatures and both packet directions byte-identical |

Also run: `cargo test -p shawncore-pq-crypto --lib authenticated` (C-ABI tests). Miri was not run
on these tests (ML-DSA is lattice-heavy). The design has had **no formal analysis and no
independent review**; passing these tests shows the implementation matches its specification
and resists the listed attacks, not that the protocol is secure.

## Test sensitivity (mutation testing)

Twenty-four deliberate faults were applied one at a time to a disposable copy of the
source tree (`/tmp`, never the repository) and the relevant tests run. Every
mutant was killed, and the copy's mutations were reverted after each run.

| Mutant | Killed by |
| --- | --- |
| AEAD decrypt accepts any tag | Many tests, including `aead_round_trip_rejects_tampering` |
| Replay window ignores already-seen bits | Several tests, including `replay_window_handles_extreme_sequence_numbers` |
| Nonce committed before authentication | `session_rejects_tampering_without_committing_replay_state` and others |
| `encrypt_packet` without the counter-exhaustion guard | `last_usable_counter_encrypts_once_then_refuses_without_wrapping` |
| SPSC queue and ring buffer full-boundary off-by-one | `full_queue_rejects_push_without_overwriting_the_oldest_item` and `full_and_empty_boundaries_are_exact` |
| DMA ownership token never advances | `ownership_token_wraps_and_stale_tokens_remain_rejected`, `rapid_reuse_rejects_every_stale_generation` and others |
| `encapsulate_for_peer` alignment check removed | `encapsulate_for_peer_rejects_misaligned_typed_pointers` (the unchecked call aborts with a misaligned-pointer dereference) |
| AAD not covered by the MAC | Many tests, including `tampered_or_mismatched_handshake_inputs_fail_the_first_packet` |
| Ciphertext, or the protocol label, dropped from the handshake transcript | `session_derivation_matches_an_independent_implementation` (only the independent vector detects these) |
| Reserved nonce bytes not checked | `nonce_with_nonzero_reserved_bytes_is_rejected` |
| `secure_zeroize` made a no-op | Several tests, including `oversized_hkdf_request_fails_and_releases_no_key_material` |
| `zeroize_session` skips wiping a key | `zeroize_session_wipes_each_key_before_it_is_flushed` |
| Failed finalize keeps the pending handshake | `failed_finalize_consumes_the_pending_handshake_and_cannot_be_retried` |
| `lite` feature secretly enabling ML-DSA | `validation/check_archive.sh` (`[archive][FAIL] Lite archive exports ML-DSA symbols`) |
| Authenticated handshake: peer signature ignored in `finalize_authenticated` or in `confirm_peer` | `c_abi_authenticated_handshake_round_trips_and_rejects_a_forged_reply`, `an_impersonator_of_the_keygen_side_cannot_confirm_the_session` and others |
| Authenticated handshake: identity pin dropped from `confirm_peer` | `an_impersonator_of_the_keygen_side_cannot_confirm_the_session` |
| Authenticated handshake: both roles share one signature context | `role_contexts_stop_one_sides_signature_standing_in_for_the_other` |
| Authenticated handshake: unconfirmed session allowed to send | `c_abi_authenticated_handshake_round_trips_and_rejects_a_forged_reply` and others |
| Authenticated handshake: application info, or the encapsulator identity, omitted from the binding | `the_binding_and_transcript_depend_on_every_input` |
| Authenticated handshake: a forged reply consumes the pending handshake | `c_abi_authenticated_handshake_round_trips_and_rejects_a_forged_reply` and others |

Gaps found and closed: the key-wipe mutant **survived** the pre-existing suite
(confirmed by running the mutant with the new test skipped), and no test pinned
the handshake transcript. The unobserved-wipe gap is now covered by a cache-flush
observation test; the transcript by the independent session vector. A trivially
true test (`ring_payload_paths_are_expected_to_use_atomic_ownership`, which only
asserted constants) was removed and replaced by real ring-buffer boundary,
wraparound and fail-closed tests. Mutants that were not run: the timing
properties of `verify_tag_constant_time`, and any fault confined to the C
harness.

## Target scope

`cargo check -p shawncore-pq-crypto --target thumbv7em-none-eabihf` and the same
for `shawncore-rtos-sync` fail: the entropy pool, latency tracker and DMA pool
need `AtomicU64`, and the DMA free-list head packs 32+32 bits into a `usize`.
Both crates now stop with an explicit `compile_error!` on any target that is not
64-bit with native 64-bit atomics. Supported and checked: x86-64 host and
`aarch64-unknown-none`.

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
| Public-symbol check | PASS | Header declarations and archive exports were compared and matched exactly: 138 symbols, empty diff. |
| Self-contained archive check | PASS | `validation/check_archive.sh`: for `aarch64-unknown-none`, the set of undefined symbols minus the set of archive-defined symbols is empty, and `nm` shows no `malloc`, `free`, `__rust_alloc`, libc I/O, or pthread references. |
| Lite archive exclusions | PASS | `validation/check_archive.sh` builds the Lite archive in a scratch target directory and fails if it exports or contains any ML-DSA symbol or the `ED25519_BASEPOINT_TABLE` precomputed table, or if it loses ML-KEM. The same patterns are confirmed present in the full archive, so the check is not vacuous. |
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
| FFI | REVIEWED | Null and zero-length conventions, input/output/control/backing overlap checks, opaque lifecycle, alignment, callback ABI, and session-manager aliasing were inspected. The 12.3.11 audit of every `extern "C"` entry point found one missing alignment check (`encapsulate_for_peer`) and one reference-ordering hazard (`scheduler_create_task`); both are fixed with regression coverage for the former. No allocator use exists in library code (only test modules use `Box`). |
| Concurrency | MODEL PASS | SPSC ownership and Acquire/Release publication were reasoned about under the Rust memory model. No formal model checker was run. |
| DMA/cache | REVIEWED | Cache callback transitions and the limits of page alignment/atomics were inspected; hardware coherency was not tested. |
| Crypto | REVIEWED | AEAD lengths/authentication, X25519 checks, 128-byte hybrid KDF, directional key assignment, and cleanup paths were inspected. |
| Session/replay | REVIEWED | Authentication precedes replay-state commitment; re-establishment resets state before replacement keys are installed. |
| Handshake | REVIEWED | Unauthenticated by design: no peer identity, key confirmation, or full transcript binding. A test shows tampered ciphertext or mismatched `info` is detected only at the first packet. See SECURITY.md section 10. |
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
| ML-KEM/ML-DSA full ACVP coverage, CAVP/CMVP validation, and interoperability with a second peer over a real link | NOT EXECUTED | Official ACVP sample vectors for ML-KEM-1024 and ML-DSA-87 key generation and verification were run (see "Official ACVP known-answer tests"); ML-DSA signature generation, non-empty-context signing and pre-hash modes are not exercised, and no algorithm validation was performed. |
| Independent security review | NOT EXECUTED | No independent review has been performed or claimed. |
| Formal analysis and independent review of the authenticated handshake | NOT EXECUTED | The design is new and unreviewed; tests and an independent re-derivation show implementation fidelity, not protocol security. |

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

The repository contains **171 Rust functions annotated with `#[test]`**. All 171 were
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
