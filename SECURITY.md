# Security Model and Integration Guide

This document describes the security assumptions, trust boundaries, threat
model, and host integration obligations for ShawnCore-Libraries.

ShawnCore-Libraries is a prototype for technical evaluation. Nothing in this
document asserts FIPS certification, CNSA approval, production readiness,
target-hardware validation, or independent security review. The current
evidence set is recorded in [VALIDATION.md](VALIDATION.md); the open gates
listed there are unresolved.

## Reporting a Vulnerability

This repository has no public issue tracker for security matters. Report
suspected vulnerabilities directly to the copyright holder, Shawn Phillips, by a
private channel (for example the contact established in your licensing
agreement or a private GitHub security advisory on the repository). Do not file
security reports as public issues.

## Trust Boundaries

There are three parties in the deployed picture:

1. **The ShawnCore Rust libraries.** Enforce argument validation, length and
   overlap checks, state-machine ordering, replay logic, key zeroization, and
   `no_std` memory-safety invariants.
2. **The host firmware / RTOS (C or C++).** Owns memory mapping, entropy
   sourcing, cache maintenance, interrupt masking, watchdog policy, task stack
   provisioning, context switching, DMA device control, and callback lifetime.
3. **The peer and the transport.** Untrusted. All inbound bytes are attacker
   controlled.

The libraries treat parties 2 and 3 differently. Party 3 is untrusted input to
be validated. Party 2 is **trusted**: a host that violates its documented
contract can cause undefined behavior that the libraries cannot detect. The
contracts below are therefore security requirements, not style guidance.

## In Scope

The libraries are intended to resist the following, subject to the correctness
of their dependencies and of the host contract:

| Threat | Mitigation in this repository |
| --- | --- |
| Ciphertext tampering | Encrypt-then-MAC with HMAC-SHA384; a 48-byte tag is verified in constant time via `subtle` before any plaintext is released. |
| Packet replay | 64-entry sliding replay window. Authentication succeeds before any replay-window state is committed, so a forged packet cannot poison the window. |
| Packet reordering | Sequence numbers below the window edge are rejected; in-window duplicates are rejected by bitmask. |
| Nonce reuse on transmit | Session packet encryption owns nonce assignment. A failed encryption does not advance the transmit sequence, and counter exhaustion is rejected before a nonce could repeat. |
| Key material left in memory | Shared secrets, combined KDF entropy, and directional keys are explicitly zeroized on every return path, success or error, using volatile clears plus a compiler fence. |
| Secret key exfiltration through the ABI | Decapsulation keys, signing keys, and shared secrets have no serialization entry point. Only public keys, ciphertexts, and signatures can be encoded to bytes. |
| Stale keys after rekey | Re-establishment zeroizes prior directional keys and resets transmit and replay state before installing replacements. |
| Single-algorithm cryptanalytic break | Hybrid construction: ML-KEM-1024 and X25519 secrets are both fed into HKDF-SHA384 extract, so recovering the session key requires breaking both. |
| Handshake transcript confusion | The KDF `info` binds a fixed protocol label, the ML-KEM ciphertext, the sender X25519 public key, and application info. |
| Degenerate X25519 keys | Contributory-behavior / all-zero shared-secret checks reject low-order and invalid peer points. |
| Malformed FFI arguments | Null, zero-length, misaligned, oversized, and overlapping-buffer arguments return typed error codes rather than dereferencing. Fixed-length buffers use C99 `[static N]` bounds (a plain `[N]` under C++ or MSVC) so C compilers can diagnose null or short arguments at compile time. |
| Panic unwinding into C | Release and dev profiles set `panic = "abort"`; the facade crate owns the single `no_std` panic handler, which invokes the host hook and then spins. |
| RNG exhaustion / starvation DoS | Fortuna-style accumulator pool with domain-separated output and post-supply state evolution; starvation is a typed error, not a silent weak key. |
| ISR deadlock on shared state | Interrupt-aware spinlocks disable and restore interrupts through host callbacks around the critical section. |
| Unbounded scheduler latency | Bitmap priority selection is constant-time with respect to task count. |
| Task stack overflow (detection only) | A canary is written and verified at the stack base. This is detection, not prevention, and is not a substitute for MPU configuration or target stack analysis. |

## Explicitly Out of Scope

These are **not** mitigated by this repository, and several cannot be mitigated
in portable `no_std` Rust at all.

- **Physical and side-channel attacks.** Power analysis, EM, fault injection,
  glitching, cold-boot, and probing are out of scope. `subtle` provides
  constant-time comparison, but the end-to-end timing and power behavior of the
  compiled artifact depends on the compiler, the optimizer, and the target core.
  No side-channel evaluation has been performed on target hardware.
- **Entropy quality.** The pool accumulates and conditions what the host feeds
  it. It cannot create entropy. A predictable host source yields predictable
  keys. Qualified source selection and health testing are host obligations.
- **Cache and DMA coherency.** Rust atomics establish ordering under the Rust
  memory model only. They do not flush caches, do not make data visible to a DMA
  engine, and do not prove board-level coherency. Page alignment is an
  alignment and storage property, **not** DMA pinning or physical ownership.
- **PKI and identity provisioning.** The authenticated handshake (section 10)
  authenticates a peer against a verifying key you provisioned. Certificate
  formats, chains, revocation, key rotation and provisioning are platform policy
  and are not defined here, and the Lite configuration has no ML-DSA and so no
  authenticated handshake.
- **Traffic analysis.** No padding, cover traffic, or length hiding.
- **Denial of service at the link layer.** Jamming, flooding, and resource
  exhaustion driven from outside the library are not addressed.
- **Rollback and secure boot.** Image authenticity, anti-rollback, and key
  provisioning are platform functions.
- **Multi-producer or multi-consumer queue use.** The SPSC and entropy queues
  are unsound if the single-producer / single-consumer contract is broken.
- **Malicious host firmware.** A host that violates the FFI contract is inside
  the trust boundary and can defeat every mitigation above.

## Known Limitations

- **Rust Move Semantics (Ghost Stack Copies):** Due to Rust's move semantics, initializing large opaque objects (like ML-KEM decapsulation keys) via value returns creates a bitwise copy on the stack. While `ZeroizeOnDrop` wipes the final memory location, the intermediate stack frame copy is not automatically zeroized. Integrators must ensure stack memory is cleared by subsequent frame usage or RTOS context switches.
- The 32-bit DMA-pool free-list ABA tag wraps after $2^{32}$ free-list
  mutations. Deployments must bound the operational lifetime between
  reinitializations or re-initialize the pool.
- The `fast-x25519` feature replaces fixed-base X25519 multiplication with the
  dependency's precomputed-table path. Table selection timing is a property of
  `curve25519-dalek` and the target compiler output and has not been measured
  here, the same as every other constant-time property in this repository.
- Official NIST ACVP sample vectors for ML-KEM-1024 (key generation,
  encapsulation, decapsulation, key checks) and ML-DSA-87 (key generation,
  signature verification) pass, but ML-DSA signature generation, non-empty-context
  signing and pre-hash modes are not exercised and no CAVP/CMVP algorithm
  validation has been performed. What exists beyond that: byte-for-byte agreement
  with OpenSSL 3.5.8 (an independent
  implementation) for ML-KEM-1024 key generation, deterministic encapsulation,
  decapsulation and implicit rejection, ML-DSA-87 key generation, deterministic
  signing and verification, and one complete session derivation re-implemented in
  Python (`validation/gen_openssl_vectors.sh`); RFC known-answer tests for the
  classical primitives; and regression vectors that pin the current
  `ml-kem`/`ml-dsa` output. Cross-implementation agreement on these inputs is not
  conformance evidence, and regression vectors only detect dependency drift.
  Algorithm identifiers refer to the FIPS 203 and FIPS 204 standards by name only;
  they are not certification claims.
- ML-DSA signing is deterministic (it matches OpenSSL's deterministic mode byte
  for byte) and signs the raw message with an empty context. Exposure of
  deterministic signing to fault injection has not been evaluated, and an
  integrator must add its own domain separation to signed messages.
- A 64-bit target with native 64-bit atomics is required. Both crates fail with a
  `compile_error!` otherwise; `thumbv7em-none-eabihf` (Cortex-M4) was confirmed
  not to build because the entropy pool, latency tracker and DMA pool use
  `AtomicU64` and a 64-bit packed free-list head.
- The `lite` feature does not by itself remove anything. Build Lite with
  `--no-default-features --features lite`; `validation/check_archive.sh` asserts
  the resulting archive has no ML-DSA or X25519 table symbols.
- `SessionManager` has no internal synchronization. Concurrent calls on one
  manager are a data race; the host must serialize them.
- "Bounded" means algorithmically bounded (for example at most 8 entropy chunks
  mixed per call, one 16-slot scan for the watchdog mask, no unbounded loop in
  scheduler selection). No worst-case execution time has been measured on target
  hardware, and the interrupt-disabled spinlock can wait indefinitely if its
  owner stalls.
- Rust-instrumented AddressSanitizer and ThreadSanitizer runs are part of the
  release gate (see [VALIDATION.md](VALIDATION.md)); they detect only what the
  executed tests exercise and are not a proof of absence of memory errors.
- Miri has not been run on the lattice-heavy ML-KEM/ML-DSA tests; it has been run
  on the RTOS crate and on the pointer-validation and session-state tests.
- The panic handler's reentrancy guard only limits recursion: a panic raised
  while the hook is already running spins instead of recursing. It cannot
  recover system state, and a panic with a lock held or interrupts disabled
  leaves them that way once the hook returns and the handler spins.
- The `shawncore-ffi` staticlib exports the single `#[panic_handler]` and
  `rust_eh_personality`. A Rust program that links this staticlib alongside its
  own `no_std` runtime will see duplicate-symbol errors.
- `shawncore_crypto_self_test()` covers SHA-384, HMAC-SHA384, HKDF-Expand-SHA384,
  X25519 and the ChaCha20 keystream only. It requires the cache-flush callback
  to be registered first, includes no ML-KEM/ML-DSA vector, and is not a FIPS
  power-on self-test.
- No formal model checking of the concurrency design has been performed.

## Host Integration Requirements

Each item below is a security requirement. Violating it can produce undefined
behavior, key compromise, or silent data corruption.

### 1. Register callbacks before first use

Register every callback your code paths require **before** invoking those
paths. Both component libraries carry independent registries, so a callback
needed by both must be registered twice.

Crypto:

```c
shawncore_crypto_register_panic_hook(host_panic);
shawncore_crypto_register_disable_interrupts(host_disable_irq);
shawncore_crypto_register_restore_interrupts(host_restore_irq);
shawncore_crypto_register_cache_flush(host_cache_flush);
```

An unregistered cache-flush callback halts the caller by design, so register it
before the first call to any HMAC, HKDF, AEAD, session, or self-test function.

RTOS:

```c
shawncore_rtos_register_panic_hook(host_panic);
shawncore_rtos_register_disable_interrupts(host_disable_irq);
shawncore_rtos_register_restore_interrupts(host_restore_irq);
shawncore_rtos_register_read_monotonic_clock(host_monotonic_ns);
shawncore_rtos_register_cache_flush(host_cache_flush);
shawncore_rtos_register_cache_invalidate(host_cache_invalidate);
shawncore_rtos_register_pet_watchdog(host_pet_watchdog);
```

Callback rules:

- A registered callback must remain valid for the duration of every possible
  call. Registration may be cleared with `NULL`, but replacement or clearing
  **must not race** an in-flight invocation.
- A callback must not unwind, throw a C++ exception, or `longjmp` through Rust.
- A callback must not re-enter any ShawnCore function. Callback dispatch is not
  a recursive API and re-entry can violate serialized queue roles, object
  lifecycle, and callback-registration assumptions. Entropy cache maintenance
  runs after its internal lock is released as a defensive deadlock prevention;
  this does not relax the non-reentrancy contract.
- The panic hook must implement a platform fail-safe response. Panic aborts; it
  does not return.
- `shawncore-ffi/../integration/hal_stubs.c` is compile-only scaffolding.
  It does **not** implement cache, interrupt, watchdog, or clock behavior.

What registration does and does not guarantee:

- A registration stores one bare function pointer with a sequentially consistent
  atomic store, and every call site loads it with acquire ordering. That makes
  the new pointer visible; it says nothing about the old one. A core or ISR that
  loaded the previous pointer before the store can still be executing it or enter
  it afterwards, and the library keeps neither a reference count nor a context
  argument. Keeping the code of a replaced callback mapped, and stopping every
  caller first, is the host's responsibility. The only replacement that is safe
  without quiescence is storing the same function again.
- The interrupt callbacks work as a pair. Replacing either between a spinlock's
  disable and its restore hands the saved flags to a different function.
- A missing required callback is not an error return. The library invokes its
  own panic hook (if one is registered) and then spins forever, with interrupts
  masked if it is the restore callback that is missing. Each library has its own
  hook and registry. In the crypto library the cache-flush callback runs inside
  `zeroize` and `destroy`, so with it unregistered those calls halt after wiping
  the transmit key and before wiping the receive key; register it first.
- The crypto cache-flush callback is never called with a zero-length range, so a
  host implementation need not guard against the dangling pointer an empty slice
  carries. The entropy pool releases its interrupt-masking lock before it calls
  the callback; host callbacks are otherwise called at arbitrary points and must
  be short, non-blocking and safe in the context (thread or ISR) of the caller.

### 2. Allocate opaque objects correctly

Rust object layouts are not exposed to C. Query size and alignment at runtime:

```c
size_t size  = shawncore_crypto_session_manager_sizeof();
size_t align = shawncore_crypto_session_manager_alignof();
```

- Storage must satisfy both the reported size and the reported alignment.
- Opaque objects, input buffers, output buffers, and queue/DMA backing storage
  must occupy separate non-overlapping ranges unless a function explicitly
  documents an in-place operation. In particular, a queue or DMA pool's control
  object must not be placed within its backing region, and result pointers must
  not point into a live control object.
- Initialize exactly once. Destroy exactly once, only after every concurrent
  user has stopped.
- Do not copy, move, or memcpy an initialized object.
- A non-null pointer is not evidence that memory is mapped, writable, owned by
  the caller, or valid for the required lifetime. Those remain host obligations.
- Variable-length inputs (`salt`, `info`, `app_info`, `aad`, packet and message
  data, HKDF output) are described by a pointer and a length. Before it reads
  any of them the library rejects, with `INVALID_LENGTH`, a length above
  `PTRDIFF_MAX`, a range that wraps the address space, packet data longer than
  one ChaCha20 key and nonce can process (64 * (2^32 - 1) bytes), and `app_info`
  longer than `UINT32_MAX`. A nonzero length with a NULL pointer is rejected
  too. Nothing else about the range can be checked: the host guarantees that a
  nonzero-length range is entirely valid, initialized (for inputs) and writable
  (for outputs) memory of that size. The library imposes no other cap on `salt`,
  `info`, `aad` or message length; time is linear in them, so a host that must
  bound latency should bound lengths itself.
- Repeating `shawncore_crypto_session_manager_zeroize` or `_destroy` on an
  initialized session manager is harmless today and is tested, but the contract
  is still "destroy once". Calling `_init` on a live manager overwrites it without
  wiping its keys; destroy it first.

### 3. Honor the queue role contract

SPSC queues, the ring buffer, and the entropy queue require **exactly one
stable producer and exactly one stable consumer** for their entire initialized
lifetime. The Rust role operations are `unsafe` because the roles cannot be
proven from a shared reference. C callers carry the identical requirement; there
is no runtime enforcement.

### 4. Own the cache and DMA protocol

The libraries invoke registered cache callbacks around CPU-side producer and
consumer transitions, and flush a CPU-side zeroization before republishing a
freed DMA slot. That is the extent of it. You must:

- Define cache ownership transitions for every buffer shared with a device.
- Quiesce a device before freeing its allocation.
- Validate the resulting cache, barrier, interrupt, and DMA behavior on the
  target board. Host tests cannot establish it.

### 5. Own task stacks

The scheduler validates priority bounds, stack range arithmetic, alignment, and
size, and maintains a base canary. You must supply mapped, writable, correctly
sized stack memory with a lifetime that outlives the task, and implement the
platform context switch.

### 6. Manage nonces for the raw AEAD API

`shawncore_crypto_aead_encrypt` requires a **unique 96-bit nonce for every
encryption under a given key pair**. Reuse breaks confidentiality and
authenticity. Session packet encryption assigns and tracks nonces internally;
raw AEAD callers do not get that protection.

### 7. Handle the 128-byte hybrid KDF split correctly

The hybrid KDF returns exactly 128 bytes. For a responder, transmit material is
bytes `0..32 || 96..128` and receive material is bytes `32..96`. The initiator
applies the complementary assignment. Each directional key is 64 bytes: 32 for
ChaCha20 encryption and 32 for HMAC-SHA384 authentication. Both peers must agree
on role assignment or the session will not interoperate.

### 8. Treat error codes as security-relevant

Every FFI entry point returns a typed status. Do not discard it. In particular,
decryption failure means the packet was not authenticated and its plaintext
buffer contents must not be used.

### 9. Wire codecs do not authenticate

`*_from_bytes` validates length and structure only. For ML-KEM public keys the
structure check includes the FIPS 203 modulus check, so a non-canonical encoding
is rejected. Any other well-formed encoding of the correct length decodes, and
none of the decoders authenticates a peer. Binding a public key to a peer identity — through
ML-DSA signatures over a transcript, a pre-provisioned trust anchor, or an
out-of-band channel — is your protocol layer's responsibility unless you use the
authenticated handshake (section 10), which binds identities through a signed transcript.
Without one of them the handshake is unauthenticated and open to an active man-in-the-middle.

### 10. Peer authentication

ShawnCore offers two handshakes. Choose deliberately.

**Unauthenticated (`initiate_handshake`, `finalize_handshake`, `encapsulate_for_peer`).**
Hybrid key agreement only: no peer identity, no key confirmation, and a transcript that omits
the key-generating peer's public keys, roles, version and suite. These functions are unchanged and
remain open to an active man-in-the-middle, which the test
`unauthenticated_handshake_lets_an_active_intermediary_relay_and_rewrite_traffic` demonstrates: an
intermediary who intercepts the exchange sits between the endpoints, reads and rewrites every
packet, and both endpoints see valid sessions. A forged ML-KEM ciphertext is not an error (implicit
rejection yields an unrelated secret), so tampering surfaces only at the first packet, and a
response that fails outright (for example a low-order X25519 point) consumes the pending handshake.
Starting or completing a handshake resets the packet counters, so reusing the same entropy on both
sides repeats keys and nonces; never supply entropy twice. Use this API only where an active
attacker is out of scope, or authenticate the link another way (a pre-provisioned secret passed as
`salt` stops an intermediary that lacks it from deriving the keys; this gives symmetric
authentication only and mismatch shows at the first packet).

**Authenticated (`encapsulate_authenticated`, `finalize_authenticated`, `confirm_peer`; C: `…_v2`).**
Full configuration only (it needs ML-DSA-87; the Lite configuration has no equivalent). The C
functions are `encapsulate_authenticated_v2`, `finalize_authenticated_v2` and `confirm_peer_v2`
(prefix `shawncore_crypto_session_manager_`). This is protocol version 2; the earlier signature-only draft was found to lack key confirmation and was
replaced before any release (see CHANGELOG).

*Why version 2.* An audit of the first draft confirmed two gaps by running them: the signed
transcript did not bind the HKDF `salt`, and `confirm_peer` verified only the peer's signature, not
that the peer derived the same key. Two sides given different salts both reported success and then
could not talk. A signed unusable ciphertext was likewise accepted. Version 2 adds explicit key
confirmation.

*Design decision.* The hybrid exchange is kept as is and wrapped in the signed-transcript pattern
used by TLS 1.3 and SIGMA, using only primitives already in the library. Each side holds an ML-DSA-87
signing key and a **trust anchor**: the peer's verifying key, provisioned out of band. This was
chosen over a pre-shared key because it gives per-device identity and survives compromise of a
single device's secrets, and over a certificate chain because chains, revocation and clocks are
platform policy this library cannot own. Key confirmation is an HMAC-SHA384 tag under a key expanded
from the same PRK with its own label, one key and label per role.

*Salt.* The salt is **not** placed in the transcript: it may be a secret pre-shared value and a
signed or hashed copy would expose it to offline guessing. It enters the PRK, so a mismatch changes
the confirmation keys and fails the tag check as `KeyConfirmationFailed` during the handshake. A
secret salt therefore also acts as a symmetric second factor: an authenticated peer without it
cannot complete the handshake, and an attacker without it cannot confirm.

*Flow* (names as in [ARCHITECTURE.md](ARCHITECTURE.md#45-the-authenticated-handshake)):

1. Key-generating side: `initiate_handshake` sends its ML-KEM and X25519 public keys.
2. Encapsulating side: `encapsulate_authenticated` derives the session and confirmation keys,
   computes its tag, signs the digest that covers the transcript and the tag, and sends ciphertext,
   X25519 key, signature and tag. Its session is **unconfirmed** and refuses all traffic.
3. Key-generating side: `finalize_authenticated` verifies that signature against its trust anchor
   *first* (failure changes nothing), then derives the keys, verifies the tag
   (`KeyConfirmationFailed` otherwise), only then installs the keys, and sends its own signature
   and tag.
4. Encapsulating side: `confirm_peer` verifies the pinned identity, the signature and the tag; only
   then may the session carry traffic.

*What each error means.* `VerificationFailed`: an unauthenticated or mis-attributed message; no
state is consumed, so forgeries are cheap to reject and cannot cause denial of the genuine peer's
reply. `KeyConfirmationFailed`: the peer is authentic but derived a different key (salt mismatch,
inconsistent ciphertext, faulty peer); the pending handshake or unconfirmed session is wiped and
nothing is installed. `InvalidState`: wrong call order, repeat or replay; no side effects, and a
live session's keys and counters are untouched.

*What the transcript binds.* Protocol version, suite identifier (including the key-confirmation
suite), the key-generating side's ML-KEM and X25519 public keys, both identities (SHA-384
fingerprints of the verifying keys), the length-prefixed application `info`, the ML-KEM ciphertext
and the encapsulating side's X25519 key; each signature also covers the same side's confirmation
tag. The salt is deliberately absent (above). The binding is also the HKDF `info`, so the session
keys depend on all of it.

*Properties the design aims at, and what evidence exists* (host tests only; the second column is not
a proof):

| Property | Evidence |
| --- | --- |
| An intermediary with its own key cannot impersonate either side | `an_active_intermediary_with_its_own_identity_is_rejected_and_consumes_nothing`, `an_impersonator_of_the_keygen_side_cannot_confirm_the_session` |
| Every transcript field, both tags and both signatures are authenticated | `every_tampered_reply_field_fails_authentication_and_consumes_nothing`, `tampering_with_the_proof_in_flight_is_a_signature_failure_that_keeps_the_session_pending` |
| No unknown-key-share: identities are bound and `confirm_peer` pins the identity | `the_wrong_trust_anchor_rejects_a_genuine_reply`, `an_impersonator_of_the_keygen_side_cannot_confirm_the_session` |
| Different salts are detected during the handshake, as a distinct error, installing nothing | `different_salts_are_rejected_during_the_handshake_by_key_confirmation`, `an_empty_salt_on_one_side_only_is_also_a_key_confirmation_failure` |
| A validly signed but unusable exchange is rejected | `a_validly_signed_but_unusable_exchange_fails_key_confirmation` |
| A valid signature over a wrong tag wipes the unconfirmed session | `a_valid_signature_over_a_wrong_confirmation_tag_wipes_the_unconfirmed_session` |
| Roles and directions are separated (keys and labels; no reflection) | `confirmation_keys_and_labels_are_separated_by_role`, `confirmation_keys_are_distinct_and_independent_of_the_session_keys` |
| Freshness: a recorded reply fails against a new ephemeral key | `a_replayed_reply_from_a_previous_handshake_is_rejected_by_a_new_one` |
| State machine: no traffic before confirmation; repeats and out-of-order calls refused; live counters not reset | `matching_salt_and_context_complete_with_mutual_confirmation`, `repeated_and_out_of_order_messages_are_refused_without_side_effects`, `an_abandoned_handshake_clears_state_and_a_new_one_recovers` |
| Pending confirmation key is wiped and flushed as zeros | `pending_confirmation_key_is_wiped_and_flushed_on_abandon_and_on_failed_confirmation` |
| The encodings match an independent implementation | `authenticated_handshake_matches_an_independent_implementation`: binding, transcript, both confirmation keys, both tags, both ML-DSA signatures (OpenSSL 3.5.8) and the packets are byte-identical |
| The tests detect regressions | Fifteen targeted faults in version 2 (skipping either tag check, role-swapped tag key or label, a shared label, confirmation expansion reusing the session info, tag or app info or identity or key or ciphertext dropped from a digest or the binding, traffic allowed while unconfirmed, failed finalize keeping state, identity pin dropped, pending key not wiped) were each caught |

*Not claimed.* No formal analysis (for example Tamarin or ProVerif) and no independent review: this
is a composition of standard components, but the composition itself is new and **unreviewed**.
Authentication is post-quantum only through ML-DSA (the key exchange is hybrid). Forward secrecy
against later compromise of a long-term signing key is the design intent (session keys come from
ephemeral keys) and has not been proven. Identity privacy is not provided: both verifying keys'
fingerprints are bound, and the signatures travel in the clear. There is no revocation, key
rotation or provisioning mechanism; those are platform policy. Freshness depends on the key-
generating side's entropy being fresh. Signing is deterministic (see Known Limitations).

*Integrator obligations.* Provision each side's trust anchor through a channel you trust. Supply
unpredictable entropy and never reuse it. Give both sides identical `salt` and `app_info`; a
mismatch is reported as `KeyConfirmationFailed` (salt) or `VerificationFailed` (`app_info`). Treat a
salt you intend to be secret as a secret: it is not signed or transmitted. Abandon a handshake that
does not complete (`zeroize`); a forged or delayed message cannot be told from loss. After
`KeyConfirmationFailed` start over with a fresh `initiate_handshake`.

*Review this needs.* Before relying on version 2 for anything that matters, have a cryptographer
review: the composition of signed transcript and MAC confirmation (including whether the
confirmation tags need to cover more of the transcript than they do), the use of two HKDF
expansions of one PRK and the label separation, deterministic signing, the one-decapsulation
failure policy, and a mechanised model (for example Tamarin or ProVerif) of the message flow. None
of that has been done.
Budget the memory: an ML-DSA signing key occupies about 105 KB and a verifying key about 74 KB in
memory, and signing uses a large stack (see the README).

## Build and Link

```text
cargo build -p shawncore-ffi --release
```

Link `target/release/libshawncore_ffi.a` and include
[`shawncore-ffi/include/shawncore.h`](shawncore-ffi/include/shawncore.h). The
`integration/` directory contains a `Makefile` that performs the C syntax check,
smoke build, execution, and the optional sanitizer and Valgrind variants.

Release and dev profiles both set `panic = "abort"` so a Rust panic cannot
unwind through the C ABI.

## Before Deployment

The following remain required and are not satisfied by this repository:

- Independent security review.
- ML-KEM / ML-DSA known-answer and external interoperability testing.
- Target ABI validation with the real toolchain and HAL.
- Board-level cache, DMA, interrupt, watchdog, entropy, and stack validation.
- A reviewed key-provisioning and revocation process for the authenticated
  handshake's trust anchors, and independent review of the handshake itself.

## Lite Security Boundary

The Lite configuration intentionally removes ML-DSA. This reduces the embedded
footprint but also removes the ML-DSA signing and verification capability from
the Lite ABI.

This means Lite must not be advertised as having identical security properties
to the full configuration. In particular, post-quantum digital-signature
operations are unavailable unless supplied by another component in the
integrating system.

The following remain part of Lite when enabled by the crate configuration:

- ML-KEM key encapsulation
- X25519 key agreement
- HKDF-SHA384 derivation
- ChaCha20/HMAC-SHA384 authenticated encryption
- replay-aware session management
- entropy infrastructure
- RTOS synchronization/resource-ownership primitives

Production deployment still requires target-specific hardware validation,
cryptographic interoperability/KAT testing, timing/stack analysis, and
independent security review appropriate to the system's threat model.
