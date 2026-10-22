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
| MSRV: tests, `aarch64-unknown-none` check and Lite check on Rust 1.88.0 | PASS | All 199 tests pass. 1.88 is the floor set by the `sha2` 0.11 dependency; the crates' own code builds there unchanged. |

## TEST VALIDATION

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo test --workspace --all-targets --locked` (debug and `--release`) | PASS | All 199 #[test] functions passed in both profiles: 128 in `shawncore-pq-crypto` (70 unit, 8 known-answer, 3 regression-vector, 22 adversarial protocol, 4 OpenSSL cross-implementation, 5 ACVP, 16 authenticated handshake), 48 in `shawncore-rtos-sync`, 1 in `shawncore-ffi` (panic-handler guard), 22 in the validation harness (host traces, layout contracts, version-drift guards and the 12-test spec-sheet suite). |
| `cargo test -p shawncore-pq-crypto --test adversarial_protocol --test openssl_interop --locked` | PASS | 22 active-attacker tests and 3 cross-implementation tests (see the sections below the table). |
| `cargo test -p shawncore-pq-crypto --no-default-features --features lite --locked` | PASS | Lite suite: 100 tests (62 unit, 8 known-answer, 22 adversarial protocol, 2 regression-vector, 2 OpenSSL cross-implementation, 4 ACVP); the ML-DSA tests are feature-gated out. |
| `cargo test -p shawncore-validation --test spec_sheet --locked` | PASS | 12 tests: crypto and wire sizes, replay window (offset 63 accepted, 64 rejected), nonce format, uniform-entropy rejection, entropy queue capacity and mix bound, scheduler/state machine/TCB, DMA pool alignment, token and zeroization behavior, object sizes, the C header surface (function, type and callback counts, no secret-key serialization), and drift checks that the README, ARCHITECTURE, VALIDATION, RELEASE_MANIFEST, CI workflow and BENCHMARKS record state the same numbers. It found a mis-rounded ops/sec figure in the README on its first run. |
| `cargo test -p shawncore-pq-crypto --no-default-features --features ml-dsa --locked` | PASS | Full crypto suite without `fast-x25519` (128 tests); the RFC 7748 X25519 vectors pass with and without the precomputed tables. |
| Repeated lib-test runs | PASS | The `shawncore-pq-crypto` unit-test binary ran 300 consecutive times with a 20 s hang timeout: 0 failures, 0 hangs. Before the test-callback fix the same loop hung in roughly 1 run in 17. |
| `validation/run_tsan.sh` (nightly ThreadSanitizer) | PASS | Standalone workload of 3 rounds x 100,000 SPSC and ring-buffer transfers completed with no reported data race. |
| `validation/run_asan.sh` (nightly, Rust-instrumented AddressSanitizer) | PASS | `shawncore-pq-crypto` (128) and `shawncore-rtos-sync` (48) test targets ran under `-Zsanitizer=address` with no report; leak detection was disabled for these runs. |
| `cargo +nightly miri test -p shawncore-rtos-sync` with `-Zmiri-symbolic-alignment-check` | PASS | 48 tests passed (re-run on this revision, including the new RTOS ABI contract tests). With `-Zmiri-strict-provenance` the run stops at the first scheduler test: the scheduler API takes stack addresses as integers (`u64`) and casts them to pointers, which strict provenance rejects by design. Miri was not run on the lattice-heavy ML-KEM/ML-DSA tests or on the OpenSSL interop tests. It ran on all 44 `shawncore-rtos-sync` tests and on 24 `shawncore-pq-crypto` tests (entropy pool and queue, session counters, replay window, key-wipe observation, wire-codec pointer validation, and the null/oversized-length/misalignment FFI tests), all with `-Zmiri-symbolic-alignment-check`; the only diagnostic was the expected integer-to-pointer cast warning from the deliberately bogus never-dereferenced address in `absurd_lengths_are_rejected_before_any_dereference`. The earlier run caught undefined behavior in the test-only cache-flush dispatcher (an integer-to-function-pointer transmute), which is fixed. |

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

Protocol version 2 (signed transcript plus explicit key confirmation).
`shawncore-pq-crypto/tests/authenticated_handshake.rs` (16 tests, full configuration only), five
KDF unit tests in `src/hybrid_kdf.rs`, one zeroization unit test in `src/session_manager.rs`, two
C-ABI tests in `src/ffi.rs`, the C smoke binary, an `auth_handshake_fuzz` harness, and
`openssl_interop.rs::authenticated_handshake_matches_an_independent_implementation` exercise the
design in ARCHITECTURE.md section 4.5. All pass.

An audit of the first, signature-only draft confirmed two protocol gaps by running them (a salt
mismatch ended with both sides reporting success and then unable to communicate; a validly signed
but unusable ciphertext was accepted by the key-generating side) before any fix was written. The
version 2 tests below fail against that behavior: a salt mismatch must be a `KeyConfirmationFailed`
during the handshake, and the mutant "finalize skips the tag check" is killed by five of them.

| Attack or property | Outcome |
| --- | --- |
| Intermediary with its own identity answers the key-generating side | `VerificationFailed`; the pending handshake survives and the genuine reply then succeeds |
| Tampered ciphertext, encapsulator X25519 key, signature, tag, or application info | Each rejected with `VerificationFailed`; none consumes the pending handshake |
| Genuine reply checked against the wrong trust anchor | Rejected |
| Different salts (or an empty salt on one side) | `KeyConfirmationFailed` during `finalize_authenticated`; nothing installed, pending handshake consumed, encapsulating side stays unconfirmed and silent, a fresh handshake with matching salts succeeds |
| Validly signed reply whose ciphertext is not the one the signer derived from | `KeyConfirmationFailed`; no session on the key-generating side |
| Forged keygen-side proof under the pinned identity, valid signature from a different identity, tampered proof tag | Rejected by `confirm_peer` with `VerificationFailed`; the session stays unconfirmed and refuses traffic until the genuine proof arrives |
| Valid keygen-side signature over a wrong tag | `KeyConfirmationFailed`; the unconfirmed session is wiped, a repeat is `InvalidState` |
| Encapsulator's tag reflected as the keygen proof (authentic signature) | `KeyConfirmationFailed`: confirmation keys and labels are separated by role |
| Reply recorded from an earlier handshake replayed against a new ephemeral key | Rejected |
| Second `confirm_peer`, second `finalize_authenticated`, replayed reply on a live session | `InvalidState`; keys and counters unchanged (next nonce continues) |
| `confirm_peer` / `finalize_authenticated` with nothing pending; abandoned session | `InvalidState`, no side effects; a fresh handshake then succeeds |
| Unconfirmed encapsulating side sends or receives; key-generating side before `finalize` | `InvalidState` |
| Binding and digests | Differ for every changed input (ek, X25519 keys, either identity, role order, application info, ciphertext, either tag) |
| Pending confirmation key | Observed flushed as 48 zero bytes, never unwiped, on abandon and on failed confirmation |
| Confirmation expansion | First 128 bytes identical to the legacy derivation; neither confirmation key equals any window of the session keys; a different salt changes both keys; inputs zeroized |
| C ABI | Round trip, forged reply rejected without writing outputs, `KEY_CONFIRMATION_FAILED` for a salt mismatch, null/misaligned/overlapping/short-salt arguments rejected, outputs written only on success; the C smoke binary does the same through the exported functions |
| Independent derivation (OpenSSL 3.5.8 ML-DSA with FIPS 204 contexts, ML-KEM, Python for hashes, X25519, HKDF, HMAC and packet framing, written from the ARCHITECTURE.md encodings) | Identity keys, `binding`, `transcript`, both confirmation keys, both tags, both digests, both signatures and both packet directions byte-identical |

These authenticated-handshake vectors in `tests/vectors/openssl_interop.txt` are regression vectors
for a custom protocol, **not** standards vectors: the design is this project's, and agreement shows
two implementations of one specification agree. Also run: `cargo test -p shawncore-pq-crypto --lib
authenticated` (C-ABI tests) and `cd fuzz && cargo +nightly fuzz run auth_handshake_fuzz --
-runs=3000 -max_len=512` (3,000 executions, no finding). Miri was not run on these tests (ML-DSA is
lattice-heavy). The design has had **no formal analysis and no independent review**; passing these
tests shows the implementation matches its specification and resists the listed attacks, not that
the protocol is secure.

## Test sensitivity (mutation testing)

Two records exist and they differ in how reproducible they are.

- **Reproducible from this repository:** `python3 validation/run_mutants.py` applies 23
  deliberate faults, one at a time, to a disposable copy (the working tree is never modified),
  requires the named tests to fail, and exits non-zero on any survivor or any mutant that does
  not compile. Fifteen target authenticated handshake version 2, seven the crypto C ABI boundary
  (length and wrap bounds, zero-length overlap, empty cache-flush ranges), and one the RTOS DMA pool
  initializer. All 23 are killed on this revision. One more fault, removing the redundant
  `MAX_APP_INFO_LEN` check in the FFI, is an equivalent mutant (the Rust API returns the same
  error before reading the range) and is not listed.
- **Not reproducible from this repository:** the first 24 faults recorded below (including
  eight against the superseded first handshake draft) were run with an ad-hoc script that was not
  kept. They are reported as history, not as a result a reader can regenerate.

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
| Authenticated handshake v1 (superseded draft): the eight faults of the first draft | The draft's tests; the draft was replaced because it lacked key confirmation |
| v2: `finalize_authenticated` skips the tag check | Five tests, including `a_validly_signed_but_unusable_exchange_fails_key_confirmation` |
| v2: `confirm_peer` accepts any tag | `a_valid_signature_over_a_wrong_confirmation_tag_wipes_the_unconfirmed_session` and two others |
| v2: encapsulator tag computed with the keygen label; keygen tag with the encapsulator key; both roles share one label | `confirmation_keys_and_labels_are_separated_by_role` and many round-trip tests |
| v2: confirmation expansion reuses the session `info` | `confirmation_keys_are_distinct_and_independent_of_the_session_keys` |
| v2: either digest drops its tag; binding drops `app_info`, the encapsulator identity or `ek`; transcript drops the ciphertext | `every_tampered_reply_field_fails_authentication_and_consumes_nothing`, `the_binding_and_digests_depend_on_every_input` |
| v2: traffic allowed while unconfirmed | Four tests, including `an_impersonator_of_the_keygen_side_cannot_confirm_the_session` |
| v2: failed `finalize_authenticated` keeps pending state | `different_salts_are_rejected_during_the_handshake_by_key_confirmation` |
| v2: `confirm_peer` skips the identity pin | `an_impersonator_of_the_keygen_side_cannot_confirm_the_session` |
| v2: pending confirmation key not zeroized | `pending_confirmation_key_is_wiped_and_flushed_on_abandon_and_on_failed_confirmation` |
| ABI: hmac, hkdf or `finalize_handshake` accept a length above `PTRDIFF_MAX` | `lengths_beyond_the_slice_limit_are_rejected_before_any_slice_is_formed` (without the check the process aborts in `slice::from_raw_parts`) |
| ABI: `ml_dsa_verify` accepts a range that wraps the address space | `a_range_that_wraps_the_address_space_is_rejected_where_no_overlap_check_exists` |
| ABI: packet length cap removed | `length_bounds_are_exact` |
| ABI: zero-length range counted as an overlap | `a_zero_length_range_never_overlaps_anything`, `a_zero_length_input_may_point_inside_an_output_buffer` |
| ABI: cache-flush callback receives an empty range | `the_cache_flush_callback_is_never_called_for_an_empty_range` |
| ABI: DMA pool backing validated as bytes instead of 2048-byte buffers | `an_absurd_backing_size_is_rejected_and_the_control_object_is_untouched` |

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
| C authenticated handshake | PASS | The same binary (full configuration) runs the signed handshake through the exported C functions: an intermediary with its own identity is rejected with `VERIFICATION_FAILED`, an unconfirmed initiator refuses to send, a signature from the wrong identity or a tampered tag does not confirm, mismatched salts give `KEY_CONFIRMATION_FAILED` with no usable session, and packets flow only after `confirm_peer_v2`. Clean under AddressSanitizer and Valgrind (0 errors, 0 bytes in use at exit); the file also passes `-fsyntax-only` with `SHAWNCORE_LITE`. |
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

## C ABI boundary audit

Scope: all 138 exported symbols (72 `shawncore_crypto_*`, 66 `shawncore_rtos_*`, each count including callback registration and the `sizeof`/`alignof` queries), the public
header, callback registration, and the release evidence. Method: source reading of every entry
point, regression tests written first and observed failing on the unfixed code, then the fix.

| # | Defect (violated invariant) | Evidence before the fix | Fix |
| --- | --- | --- | --- |
| 1 | A pointer-plus-length pair with a length above `isize::MAX` reached `slice::from_raw_parts` for `salt`, `info`, `app_info`, `aad`, HMAC data, HKDF `info` and output, and signature messages. A slice may not exceed `isize::MAX`; the existing overlap check only caught ranges that wrap the address space, so lengths between `isize::MAX` and the wrap point passed. | The new test aborted the process in a debug build: `unsafe precondition(s) violated: slice::from_raw_parts requires ... the total size of the slice not to exceed isize::MAX` at the HMAC entry point. | Every pointer-plus-length pair is checked (`range_ok`) before a slice is formed: length at most `PTRDIFF_MAX`, no address wrap, plus per-function protocol limits. |
| 2 | `ml_dsa_verify` has no overlap check, so a range wrapping the address space reached slice creation. | Test returned `VerificationFailed` instead of `InvalidLength` (the slice had been formed). | Covered by the same `range_ok` check. |
| 3 | `ranges_overlap` reported a zero-length range whose address lay inside another range as an overlap, rejecting a valid call. | Test failed: `ranges_overlap(p+16, 0, p, 32)` was true. | A zero-length range never overlaps. |
| 4 | The crypto library called the host cache-flush callback with the dangling pointer of an empty slice and length 0 (AEAD with empty data). A host that rounds to a cache line could fault. | Test failed: the callback saw `len == 0`. | The callback is not called for an empty range. |
| 5 | `dmapool2k_init` validated the backing region with the element type `u8` (256 bytes) instead of 256 buffers of 2048 bytes, so the real check ran only inside `pool.init`, after the control object had been overwritten, and returned `AddressOutOfBounds`. | Test failed: size 524287 gave `AddressOutOfBounds`. | Validated with the real element type before any write; undersized backing is now `InvalidMemory`. |
| 6 | Hardening, no failing test possible: the unauthenticated `encapsulate_for_peer` C wrapper took `&mut` references to possibly uninitialized caller storage. | Source review. | Writes go through local values and `ptr::write` on success, as the authenticated functions already did. |

Bounds enforced, with `INVALID_LENGTH` and no side effect on violation: every length at most
`PTRDIFF_MAX`; packet and AEAD data at most 64 x (2^32 - 1) bytes (ChaCha20 limit for one key and
nonce, the limit the Rust API already enforced); `app_info` at most `UINT32_MAX` (its transcript
length prefix). HKDF output above 12,240 bytes keeps its previous behavior (`HKDF_ERROR`, output
zeroed). No other cap is imposed on `salt`, `info`, `aad` or message length; a latency-bounded host
should apply its own. Header, `SECURITY.md` and the crate documentation state the rules, the error
code per rejection class (pinned by `rejected_arguments_return_the_codes_the_header_documents`), and
the two deliberate cases where a failed call writes its output (a failed MAC check zeroes the
plaintext buffer; an oversized HKDF request zeroes its output). Those and the other results below
were produced on this revision:

| Command or check | Result | Evidence |
| --- | --- | --- |
| `python3 validation/check_header_signatures.py` | PASS | All 138 header declarations match their Rust `extern "C"` definitions in parameter count, scalar width, pointer constness, pointee type, callback typedef and return type. Negative controls (a dropped `const`, a narrowed length type, a changed return type) are detected. It parses source text and does not compile either side. |
| C struct offsets | PASS | `integration/c_api_smoke.c` `_Static_assert`s every field offset of the four header structs and compares their size and alignment with the exported `*_sizeof`/`*_alignof`; `ffi_layout_contracts.rs::c_header_struct_offsets_match_rust_types` asserts the same literals against the Rust types. |
| C smoke, ASan, Valgrind | PASS | The smoke binary now also checks that `INTPTR_MAX + 1` lengths are refused without touching memory and that a zero-length NULL is accepted. ASan with leak detection: no report. Valgrind: 0 errors, 0 bytes in use at exit. |
| New tests | PASS | 10 crypto ABI boundary tests, 4 RTOS ABI contract tests (null and misaligned codes, value fallbacks, absurd sizes, success-only outputs) and the layout test. |
| Miri | PASS (partial) | `-Zmiri-symbolic-alignment-check`: the 8 non-lattice boundary tests, plus 17 entropy, session-state and FFI pointer tests, and all 48 RTOS tests; the only diagnostic is the expected integer-to-pointer warning for the deliberately unmapped address. Not run on ML-KEM/ML-DSA-heavy tests. |
| `python3 validation/run_mutants.py` | PASS | 23 of 23 mutants killed. |
| `cargo audit` and `cargo audit --file fuzz/Cargo.lock` | PASS | No advisory reported (database of 1,349 advisories fetched at run time, `cargo-audit` 0.22.2). |

Findings that are not defects and remain caller duties: a non-null pointer cannot be proven
mapped, live, initialized or large enough; a pointer that stays valid for the whole call is the
host's guarantee. Callback registration publishes one bare function pointer (no context, no
lifetime management); replacing a callback that another core can still enter is unsafe and needs
host quiescence, a missing required callback halts the caller after invoking the library's panic
hook, and each library has its own registry. Both are documented in `SECURITY.md`. Repeating
`destroy` on a session manager is harmless and tested but not part of the contract; calling `init`
on a live manager overwrites it without wiping its keys.

## FUZZING

| Command | Result | Evidence |
| --- | --- | --- |
| `cargo check --manifest-path fuzz/Cargo.toml --bin <target> --locked` (4 targets) | PASS | Executed and passed for `ffi_aead_fuzz`, `session_replay_fuzz`, `rtos_stateful_fuzz` and `auth_handshake_fuzz`. |
| `cd fuzz && cargo +nightly fuzz run auth_handshake_fuzz -- -runs=3000 -max_len=512` | PASS | 3,000 executions (171 s, about 20 exec/s because every input signs and verifies ML-DSA); no crash, timeout or artifact. The harness asserts that arbitrary replies never authenticate, never consume the pending handshake, and never let an unconfirmed session carry traffic. The corpus was not retained. |
| `cd fuzz && cargo +nightly fuzz run ffi_aead_fuzz -- -runs=10000 -max_len=512` | PASS | 10,000 executions from the 91 retained corpus files; no crash, timeout or artifact. |
| `cd fuzz && cargo +nightly fuzz run session_replay_fuzz -- -runs=10000 -max_len=512` | PASS | 10,000 executions from the 256 retained corpus files (258 s on the Phase 4 revision); no crash, timeout or artifact. |
| `cd fuzz && cargo +nightly fuzz run rtos_stateful_fuzz -- -runs=10000 -max_len=512` | PASS | 10,000 executions from the 225 retained corpus files; no crash, timeout or artifact. |
| `cd fuzz && cargo +nightly fuzz run <ffi_aead_fuzz\|rtos_stateful_fuzz> -- -runs=500000 -max_len=512 -seed=7` | PASS | Extended campaigns: 500,000 executions each (93 s and 48 s); no crash, timeout or artifact. |

Corpus inputs discovered during these runs were not added to the repository. The
same three 10,000-execution campaigns are configured in CI. A bounded campaign is
evidence only for its harness and duration; it is not proof of security.

## STATIC REVIEW

| Area | Result | Scope |
| --- | --- | --- |
| Unsafe code | REVIEWED | Raw pointers, FFI storage, callback conversion, stack canaries, queue payload access, and DMA byte zeroization were inspected. |
| FFI | REVIEWED | Null and zero-length conventions, input/output/control/backing overlap checks, opaque lifecycle, alignment, callback ABI, and session-manager aliasing were inspected. The 12.3.11 audit of every `extern "C"` entry point found one missing alignment check (`encapsulate_for_peer`) and one reference-ordering hazard (`scheduler_create_task`); both are fixed with regression coverage for the former. The Phase 4 audit (section "C ABI boundary audit") found five further defects, all fixed with regression tests. No allocator use exists in library code (only test modules use `Box`). |
| Concurrency | MODEL PASS | SPSC ownership and Acquire/Release publication were reasoned about under the Rust memory model. No formal model checker was run. |
| DMA/cache | REVIEWED | Cache callback transitions and the limits of page alignment/atomics were inspected; hardware coherency was not tested. |
| Crypto | REVIEWED | AEAD lengths/authentication, X25519 checks, 128-byte hybrid KDF, directional key assignment, and cleanup paths were inspected. |
| Session/replay | REVIEWED | Authentication precedes replay-state commitment; re-establishment resets state before replacement keys are installed. |
| Handshake | REVIEWED | Unauthenticated by design (the plain handshake): no peer identity, key confirmation, or full transcript binding; the authenticated variant adds them. A test shows tampered ciphertext or mismatched `info` is detected only at the first packet. See SECURITY.md section 10. |
| Package hygiene | PASS | `cargo package --list` for all three crates listed 54 source/metadata files (28, 19 and 7) with no generated artifact paths. |

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

The repository contains **199 Rust functions annotated with `#[test]`**. All 199 were
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
