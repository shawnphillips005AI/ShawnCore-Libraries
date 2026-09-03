# Security Model and Integration Guide

This document describes the security assumptions, trust boundaries, threat
model, and host integration obligations for ShawnCore-Libraries.

ShawnCore-Libraries is a prototype for technical evaluation. Nothing in this
document asserts FIPS certification, CNSA approval, production readiness,
target-hardware validation, or independent security review. The current
evidence set is recorded in [VALIDATION.md](VALIDATION.md); the open gates
listed there are unresolved.

## Reporting a Vulnerability

This repository is proprietary and has no public issue tracker for security
matters. Report suspected vulnerabilities directly to the copyright holder
through the channel established in your written agreement. Do not file
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
| Malformed FFI arguments | Null, zero-length, misaligned, oversized, and overlapping-buffer arguments return typed error codes rather than dereferencing. |
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

- The 32-bit DMA-pool free-list ABA tag wraps after $2^{32}$ free-list
  mutations. Deployments must bound the operational lifetime between
  reinitializations or re-initialize the pool.
- ML-KEM and ML-DSA known-answer tests and external interoperability testing
  have not been run. Algorithm identifiers refer to the FIPS 203 and FIPS 204
  standards by name only; they are not certification claims.
- No Rust-instrumented AddressSanitizer result exists; the sanitizer build was
  blocked by a dependency resolution failure. See [VALIDATION.md](VALIDATION.md).
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
- The panic hook must implement a platform fail-safe response. Panic aborts; it
  does not return.
- `shawncore-ffi/../integration/martac_hal_stubs.c` is compile-only scaffolding.
  It does **not** implement cache, interrupt, watchdog, or clock behavior.

### 2. Allocate opaque objects correctly

Rust object layouts are not exposed to C. Query size and alignment at runtime:

```c
size_t size  = shawncore_crypto_session_manager_sizeof();
size_t align = shawncore_crypto_session_manager_alignof();
```

- Storage must satisfy both the reported size and the reported alignment.
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

`*_from_bytes` validates length and structure only. A well-formed encoding of the
correct length always decodes. Binding a public key to a peer identity — through
ML-DSA signatures over a transcript, a pre-provisioned trust anchor, or an
out-of-band channel — is your protocol layer's responsibility. Without it the
handshake is unauthenticated and open to an active man-in-the-middle.

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
