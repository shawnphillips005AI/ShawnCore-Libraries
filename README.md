# ShawnCore Libraries

**Hybrid post-quantum session establishment and deterministic RTOS
synchronization for embedded systems, in `no_std` Rust with a C ABI.**

ShawnCore gives firmware two things that are hard to get right and dangerous to
get wrong: a hybrid ML-KEM-1024 + X25519 secure channel, and a set of lock-free
RTOS primitives with analyzable worst-case behavior. It ships as a single
self-contained static library with a C header that compiles as C99, C11 and C++11 or later.

> **Status:** release-candidate prototype for external technical evaluation.
> Not certified, not hardware-qualified, not independently reviewed.
> [VALIDATION.md](VALIDATION.md) records exactly what has been executed and what
> has not.

---

## At a glance

| | |
|---|---|
| **Key establishment** | ML-KEM-1024 + X25519, combined through HKDF-SHA384 into two independent directional keys |
| **Packet protection** | ChaCha20 + HMAC-SHA384 Encrypt-then-MAC, per-direction nonce counters, 64-entry replay window |
| **Signatures** | ML-DSA-87, optional (omitted by the `lite` configuration) |
| **RTOS primitives** | O(1) bitmap scheduler, SPSC/ring queues, ABA-tagged DMA pool, interrupt-aware spinlocks, state machine |
| **Integration** | One `staticlib`, one header for C99/C11 and C++ (135 functions, `SHAWNCORE_VERSION_*` macros), no libc, no heap, caller-allocated objects |
| **Targets built** | Host (x86-64) and `aarch64-unknown-none` |
| **Toolchain** | `no_std`, `panic = "abort"`; minimum Rust 1.88 (CI-checked), developed and validated on 1.99.1 |

---

## Why this is different

Most embedded crypto libraries quietly reach into the platform — flushing caches
with inline assembly, wiping stacks, reading RNGs, assuming coherency. Each reach
is a correctness claim the library cannot verify on a board it has never seen.

**ShawnCore makes every hardware assumption explicit and finite.** There are
exactly seven, and they are all registered host callbacks:

`panic` · `disable_interrupts` · `restore_interrupts` · `cache_flush` ·
`cache_invalidate` · `monotonic_clock` · `pet_watchdog`

That is the complete list of things a target integrator must validate. Nothing
is hidden inside the library, which is why the open validation gates in this
repository are enumerated rather than implied.

---

## Verified properties

Every claim below is reproducible from a clean checkout with
`bash validation/release_gate.sh` and the commands in [REVIEW.md](REVIEW.md).

| | |
|---|---|
| **Zero external symbols** | The `aarch64-unknown-none` archive resolves entirely within itself. `memcpy`/`memset`/`memcmp` and soft-float builtins are bundled. No libc required. Checked by [`validation/check_archive.sh`](validation/check_archive.sh). |
| **Zero heap** | No `malloc`, no `__rust_alloc`, no allocator linked. Every object is caller-allocated via published `_sizeof()`/`_alignof()`. |
| **Zero unwinding into C** | `panic = "abort"` in both profiles; the facade owns the single `no_std` panic handler. |
| **135 exported symbols** | Header declarations and archive exports are diffed in CI and must match exactly. |
| **99 Rust #[test] functions** | Crypto round trips, tampering, replay, reordering, wire round trips, FFI ownership rejection, entropy callback reentrancy, queue reuse, DMA stale generations, scheduler bounds. The Lite configuration runs its own 49-test suite. |
| **Known-answer tests for the classical primitives** | HMAC-SHA384 (RFC 4231), X25519 (RFC 7748 section 6.1), HKDF-SHA384, the hybrid KDF, and the AEAD framing, with vectors produced by independent implementations. ML-KEM/ML-DSA have regression vectors only; see the open gates below. |
| **Clean under ASan + Valgrind** | 0 errors, 0 leaks on the C integration binary. |
| **Fuzzed** | Three harnesses (`ffi_aead_fuzz`, `session_replay_fuzz`, `rtos_stateful_fuzz`) with retained regression corpora; CI runs 10,000 executions of each. |
| **ThreadSanitizer** | Standalone SPSC and ring-buffer stress workload, no reported race. |
| **Bare-metal clean** | `cargo check --target aarch64-unknown-none` and `clippy -D warnings` for the whole workspace. |
| **Dependency advisories** | `cargo audit` reports no advisories for the root and fuzz lockfiles. |

---

## Architecture at a glance

```mermaid
graph LR
    subgraph HOST["Host firmware (C/C++)"]
        APP["Application"]
        HAL["Platform HAL"]
    end
    subgraph SC["ShawnCore — no_std Rust"]
        FFI["shawncore-ffi<br/>staticlib facade"]
        PQ["pq-crypto<br/>ML-KEM · ML-DSA · X25519<br/>HKDF · AEAD · sessions"]
        RT["rtos-sync<br/>scheduler · SPSC · DMA pool<br/>spinlocks · telemetry"]
    end
    APP -->|shawncore.h| FFI
    FFI --> PQ
    FFI --> RT
    PQ -.->|7 callbacks| HAL
    RT -.->|7 callbacks| HAL

    classDef host fill:#e8f0fe,stroke:#4285f4,color:#000
    classDef rust fill:#e6f4ea,stroke:#34a853,color:#000
    class APP,HAL host
    class FFI,PQ,RT rust
```

**[Read ARCHITECTURE.md](ARCHITECTURE.md)** for the design rationale, handshake
sequence, replay-window ordering, DMA/cache boundary, and measured footprint.

---

## Quickstart

```bash
make -C integration run  # builds the release archive and runs the C integration binary
```

Link the archive and include [`shawncore-ffi/include/shawncore.h`](shawncore-ffi/include/shawncore.h).

```c
#include "shawncore.h"

/* 1. Register the platform callbacks this code path needs. */
shawncore_crypto_register_cache_flush(host_cache_flush);
shawncore_crypto_register_panic_hook(host_panic);

/* 2. Allocate the session object yourself; the library never allocates. */
static _Alignas(64) uint8_t storage[8192];
shawncore_crypto_session_manager *s = (void *)storage;
assert(shawncore_crypto_session_manager_sizeof() <= sizeof storage);
shawncore_crypto_session_manager_init(s);

/* 3. Responder: publish hybrid public keys in wire format. */
shawncore_crypto_session_manager_initiate_handshake(s, entropy96, pk, xpk);
uint8_t ek_wire[1568], x_wire[32];
shawncore_crypto_ml_kem_publickey_to_bytes(pk,  ek_wire, sizeof ek_wire);
shawncore_crypto_x25519_publickey_to_bytes(xpk, x_wire,  sizeof x_wire);
link_send(ek_wire, sizeof ek_wire);
link_send(x_wire,  sizeof x_wire);

/* 4. Initiator: rebuild the peer keys from bytes, then encapsulate against them. */
shawncore_crypto_ml_kem_publickey_from_bytes(ek_wire, sizeof ek_wire, peer_pk);
shawncore_crypto_x25519_publickey_from_bytes(x_wire,  sizeof x_wire,  peer_xpk);
shawncore_crypto_session_manager_encapsulate_for_peer(
    s2, peer_pk, peer_xpk, entropy64, NULL, 0, NULL, 0, ct, my_xpk);

/* 5. Responder: rebuild the reply from bytes and finalize. */
shawncore_crypto_ml_kem_ciphertext_from_bytes(ct_wire, 1568, ct);
shawncore_crypto_x25519_publickey_from_bytes(peer_wire, 32, peer);
shawncore_crypto_session_manager_finalize_handshake(s, peer, ct, NULL, 0, NULL, 0);

/* 6. Send. Nonces are assigned and tracked internally. */
shawncore_crypto_session_manager_encrypt_packet(
    s, aad, aad_len, pt, ct_out, len, out_nonce, out_tag);
```

Every call returns a typed status; check it. Entropy buffers must come from a
qualified host source. The fragment above elides declarations and error handling.

[`integration/c_api_smoke.c`](integration/c_api_smoke.c) runs this end to end —
two session managers completing a full hybrid handshake with every public value
passed through its wire encoding, then an authenticated packet exchange and a
replay rejection.

---

## Components

| Crate | Contents |
|---|---|
| [`shawncore-pq-crypto`](shawncore-pq-crypto) | ML-KEM-1024, ML-DSA-87, X25519, HKDF-SHA384 hybrid derivation, ChaCha20/HMAC-SHA384 Encrypt-then-MAC, entropy pool and queue, session lifecycle, replay handling, wire codecs |
| [`shawncore-rtos-sync`](shawncore-rtos-sync) | O(1) bitmap scheduler, ABA-tagged DMA pool, SPSC and ring queues, interrupt-aware spinlocks, atomic state machine, latency tracking, telemetry |
| [`shawncore-ffi`](shawncore-ffi) | C-linkable `staticlib` facade; owns the single `no_std` panic handler |

---

## Security model in one paragraph

Session decryption authenticates a packet **before** committing any replay-window
state, so forged traffic cannot poison the window or lock out a legitimate peer.
Failed encryption never advances the transmit sequence, so no failure path can
reuse a nonce. Re-establishment zeroizes prior directional keys and resets
transmit and replay state before installing replacements. Sensitive material is
explicitly zeroized on every return path, success or error. Secret keys have no
serialization entry point and cannot be exported through the ABI.

Full trust boundaries, in-scope and out-of-scope threats, known limitations, and
the host integration contract: **[SECURITY.md](SECURITY.md)**.

---

## Key facts an integrator needs early

**The 128-byte hybrid KDF split.** For a responder, transmit material is bytes
`0..32 ‖ 96..128` and receive material is bytes `32..96`; the initiator uses the
complementary assignment. Each 64-byte directional key is 32 bytes of ChaCha20
key plus 32 bytes of HMAC-SHA384 key.

**ML-DSA-87 is RAM-expensive in this representation.** A verifying key is 73,856
bytes in memory versus 2,592 on the wire; a signing key is 104,640 bytes versus
4,896. The dependency caches expanded matrices for speed. Budget roughly 178 KB
for a signing identity, or use ML-DSA selectively.

**Page alignment is not DMA pinning, and atomics are not cache maintenance.**
The library requires 4096-byte alignment as a storage property and calls your
cache callbacks at ownership transitions. Physical residency, pinning, device
quiesce, and board-level coherency remain yours.

**The SPSC contract is a safety requirement.** One stable producer, one stable
consumer, for the entire initialized lifetime. Not enforced at runtime.

---

## Dependencies

The wrappers delegate the primitives to RustCrypto crates and add zeroization,
length/overlap validation, and the FFI boundary.

| Primitive | Crate | Version |
|---|---|---|
| ML-KEM-1024 (FIPS 203) | `ml-kem` (`hazmat` for seed-based keygen and deterministic encapsulation) | 0.3.3 |
| ML-DSA-87 (FIPS 204) | `ml-dsa` (optional) | 0.1.1 |
| X25519 | `x25519-dalek` | 3.0 |
| ChaCha20 | `chacha20` | 0.10 |
| SHA-384, HMAC, HKDF | `sha2`, `hmac`, `hkdf` | 0.11, 0.13, 0.13 |
| Constant-time compare, zeroize | `subtle`, `zeroize` | 2.6, 1.9 |

The lockfiles are committed and `cargo audit` is part of CI. Constant-time
behavior is a property of these dependencies and the target compiler output; it
has not been measured here.

## Footprint

Measured on the `aarch64-unknown-none` FFI static archive with Rust 1.99.1.
"Code + rodata" is the sum over all archive members before linker garbage
collection, so it is an upper bound, not a firmware size. Measure the linked
artifact on your target.

| Profile | Archive bytes | Code + rodata bytes |
|---|---:|---:|
| `release` (full, ML-DSA enabled) | 6,839,576 | 623,429 |
| `usv` (full, `opt-level = "z"`) | 6,670,822 | 282,485 |
| `lite` (no ML-DSA, `opt-level = "z"`) | 6,521,938 | 251,130 |

Static RAM in the archive is 4,489 bytes of `.bss`. Opaque object sizes are
listed in [ARCHITECTURE.md](ARCHITECTURE.md#92-caller-allocated-opaque-objects).

---

## Reproducible checks

The full gate, including ThreadSanitizer (needs a nightly toolchain), the Lite
configuration, and the archive checks:

```text
bash validation/release_gate.sh
```

The individual commands:

```text
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --release --locked
cargo doc --workspace --no-deps --locked
cargo check --target aarch64-unknown-none --workspace --locked
cargo test -p shawncore-pq-crypto --no-default-features --features lite --locked
cargo audit && cargo audit --file fuzz/Cargo.lock
bash validation/check_archive.sh
make -C integration syntax run cxx asan valgrind
```

`rust-toolchain.toml` pins Rust `1.99.1`, the `rustfmt` and `clippy` components,
and the `aarch64-unknown-none` target.

---

## Validation status

The evidence behind each line is in [VALIDATION.md](VALIDATION.md).

**IMPLEMENTED** — AEAD, X25519, ML-KEM-1024, ML-DSA-87, hybrid KDF and
directional session keys, wire codecs, FFI surfaces, RTOS primitives, C HAL stubs.

**TESTED** — 99 Rust #[test] functions covering crypto round trips and tampering,
known-answer vectors for the classical primitives, wire round trips proving
semantic equivalence after decode, FFI null/zero-length and overlap handling,
session re-establishment and replay paths, queue reuse and corruption paths,
DMA-pool exhaustion and stale-generation rejection, scheduler boundaries, state
transitions, and the FFT one-cache-line ABI. A C11 integration binary and a C++17
smoke binary compile,
links, and executes a full wire handshake against the release archive, clean
under AddressSanitizer and Valgrind.

**FUZZED** — three harnesses with retained regression corpora and a
10,000-execution CI job per harness. Compile checks are not reported as fuzz
executions, and a bounded campaign is not a security proof.

**STATICALLY REVIEWED** — strict Clippy, formatting, workspace checks,
documentation build with warnings denied, C syntax compilation, header/archive
symbol parity, archive self-containment, dependency advisory scan, and a
bare-metal AArch64 type check, all in CI.

**MODEL TESTED** — no formal model checking or exhaustive concurrency-state model
has been performed. Unit tests exercise implementation behavior only; they do not
model cache-coherent DMA hardware.

**HARDWARE VALIDATED** — not yet validated by this repository.

**NOT YET VALIDATED** — target ABI interoperability, cache coherency, DMA
visibility, ISR/NMI/FIQ behavior, watchdog behavior, entropy-source quality,
Rust-instrumented sanitizer tests, ML-KEM/ML-DSA known-answer and external
interoperability tests, free-list ABA-tag wraparound, and independent security
review.

---

## Limitations

This is a prototype for technical evaluation. It is not a claim of FIPS
certification, CNSA approval, operational USV readiness, or comprehensive
security assurance. The 32-bit DMA-pool free-list ABA tag can wrap after $2^{32}$
free-list mutations; deployments must bound that operational lifetime or
reinitialize the pool. No peer identity, PKI, trust-anchor, or revocation model
is defined here; that protocol layer belongs to the integrator. Retained
regression tests do not establish target timing, cache, or physical-memory
behavior.

## External review status

Independent security review, ML-KEM/ML-DSA known-answer and interoperability
testing, target ABI validation, and board-level cache/DMA, interrupt, watchdog,
entropy, and stack validation remain required before deployment or any
certification or approval conclusion.

---

## Repository map

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design rationale, diagrams, measured layouts, concurrency model |
| [SECURITY.md](SECURITY.md) | Trust boundaries, threat model, host integration contract |
| [REVIEW.md](REVIEW.md) | Reviewer quickstart and requested review scope |
| [VALIDATION.md](VALIDATION.md) | Host-side validation record and open external gates |
| [BENCHMARKS.md](BENCHMARKS.md) | Host benchmark methodology |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## License

ShawnCore is dual-licensed; see [LICENSE](LICENSE) for the governing terms. The
unmodified GNU AGPLv3 text is in
[LICENSES/AGPL-3.0-or-later.txt](LICENSES/AGPL-3.0-or-later.txt).

1. **GNU Affero General Public License v3 (or later)** for open-source evaluation
   and research.
2. **Commercial license** for use in closed-source or proprietary products
   without the AGPL's copyleft obligations.

The crates are `publish = false` and are not distributed through a package
registry. For commercial licensing or integration support, contact the
copyright holder, Shawn Phillips, directly. Licensing does not alter the
validation status above: no hardware qualification, certification, or
independent review is implied by either license.

## Lite MCU Build

ShawnCore provides a constrained-MCU build configuration in addition to the
full/default configuration.

The full/default configuration keeps ML-DSA enabled. The Lite configuration
omits ML-DSA at compile/link time while retaining ML-KEM, X25519, authenticated
encryption, session management, entropy handling, and RTOS synchronization.
The C header hides the ML-DSA declarations when `SHAWNCORE_LITE` is defined.

Build the Lite crypto crate:

```text
cargo build -p shawncore-pq-crypto --no-default-features --features lite --profile lite
```

Build the Lite C facade:

```text
cargo build -p shawncore-ffi --no-default-features --features lite --profile lite
```

Lite is a constrained deployment profile, not a security-certification or
hardware-readiness claim. The integrating system remains responsible for
providing an appropriate device identity/authentication mechanism when ML-DSA
signatures are not available on the target.
