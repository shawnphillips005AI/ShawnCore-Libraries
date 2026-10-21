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
- **Peer authentication and PKI.** ML-DSA-87 primitives are provided, but this
  repository does not define an identity model, certificate format, trust
  anchor, revocation mechanism, or binding of a signature to the handshake
  transcript. That protocol layer is the integrator's responsibility.
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
- NIST ACVP known-answer tests for ML-KEM and ML-DSA have not been run. What
  exists instead: byte-for-byte agreement with OpenSSL 3.5.8 (an independent
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
out-of-band channel — is your protocol layer's responsibility. Without it the
handshake is unauthenticated and open to an active man-in-the-middle.

### 10. The handshake is unauthenticated; required properties of an authenticated one

The session handshake performs hybrid key agreement only. Assessment of the
current implementation:

- **No peer identity.** Nothing binds either public key to an identity. ML-DSA-87
  primitives exist but are not connected to the handshake. An active attacker can
  substitute keys and terminate a session with each side separately.
- **No key confirmation.** Neither side proves possession of the derived keys, so
  a mismatched or tampered handshake is detected only when the first packet fails
  authentication.
- **Partial transcript.** The KDF input covers the ML-KEM ciphertext, the
  encapsulating peer's X25519 public key and caller `info`. It does not cover the
  key-generating peer's ML-KEM or X25519 public keys, roles, a protocol version or
  algorithm identifiers. Put these into `info` until a defined protocol exists.
- **Entropy reuse reuses nonces.** Starting or completing a handshake resets the
  packet counters. If both peers reuse the entropy they supplied earlier, the
  derived keys and the nonce sequence repeat, which breaks confidentiality and
  authenticity. The host must never supply the same entropy twice.
- **No negotiation.** The library has a single fixed suite, so it exposes no
  in-library downgrade surface; an integrator-added negotiation must be covered
  by the signed transcript.
- **Failed handshakes fail closed.** A response that fails (for example a
  low-order X25519 point) consumes the pending handshake, so an on-path attacker
  can force the key-generating side to restart. A forged ML-KEM ciphertext does
  not fail: ML-KEM implicit rejection yields an unrelated secret and the failure
  surfaces only at the first packet.

**Demonstrated attacker capability** (test
`unauthenticated_handshake_lets_an_active_intermediary_relay_and_rewrite_traffic`):
an active intermediary who can intercept the key exchange establishes one session
with each endpoint, reads and rewrites every packet, and both endpoints see valid
sessions.

**Smallest mitigation available without an ABI change.** Pass a secret that was
provisioned out of band as `salt` on both sides. HKDF-Extract is HMAC keyed by the
salt, so an intermediary without it derives keys unrelated to its victim's (test
`an_intermediary_without_the_preshared_salt_cannot_read_the_session`). This is a
mitigation, not a reviewed protocol: it gives symmetric, not per-device,
authentication, requires secure provisioning and rotation, and reveals mismatch
only at the first packet.

This repository does not define the replacement protocol. A design for expert
review should include: pre-provisioned ML-DSA trust anchors; a signature over the
full transcript (both parties' public keys and ciphertext, roles, version, suite
identifier, a fresh nonce from each side); key-confirmation MACs under keys
derived from the transcript; and a rekey policy that bounds the packet counter.
The `info` and `salt` parameters are bound into the KDF, so a protocol layer can
add its transcript without changing the ABI. Do not describe the library as
resistant to active man-in-the-middle attacks until that layer exists and is
reviewed.

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
- A defined peer authentication and key-provisioning protocol.

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
