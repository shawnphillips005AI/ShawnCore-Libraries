# ShawnCore Benchmark Methodology

This repository includes a reproducible host-side benchmark harness for the cryptographic building blocks in `shawncore-pq-crypto`. It is intended to provide **engineering measurements**, not certification or hardware-performance claims.

## Run

From the repository root:

```bash
cargo run -p shawncore-benchmarks --release
```

For a longer run, set the iteration count explicitly:

```bash
SHAWNCORE_BENCH_ITERS=1000 cargo run -p shawncore-benchmarks --release
```

The harness makes one warm-up call, then splits the requested iterations into 25 batches and reports, per operation, the **median** and **best** batch mean in nanoseconds per operation plus operations per second at the median, using `std::time::Instant`. On a shared host a single mean varied about 2x between sessions; the best batch agrees across runs to about 1%, so quote that and keep the median alongside it. Inputs are deterministic so repeated runs are comparable on the same machine/toolchain.

## Measurements

The harness reports ML-KEM-1024 key generation/encapsulation/decapsulation, ML-DSA-87 key generation/sign/verify, X25519 key generation/Diffie-Hellman, HKDF-SHA384, HMAC-SHA384, the hybrid KDF, and 1 KiB AEAD encryption/decryption.

## Reference Results

Recorded for release 12.3.11, source commit `5de2c29`, default features
(`ml-dsa` and `fast-x25519` enabled).

- **Machine:** AMD EPYC 7763, 2 vCPU shared development container, x86-64 Linux
- **Toolchain:** Rust 1.99.1, `release` profile (`lto = "fat"`, `codegen-units = 1`)
- **Command:** `SHAWNCORE_BENCH_ITERS=2500 cargo run -p shawncore-benchmarks --release --locked`

| Operation | Iterations | Median ns/op | Best ns/op | Ops/sec (median) |
|---|---:|---:|---:|---:|
| ML-KEM-1024 keygen | 2500 | 53737 | 51730 | 18609 |
| ML-KEM-1024 encapsulate | 2500 | 53244 | 51213 | 18781 |
| ML-KEM-1024 decapsulate | 2500 | 63946 | 62883 | 15638 |
| ML-DSA-87 keygen | 2500 | 455126 | 409792 | 2197 |
| ML-DSA-87 sign (1 KiB) | 2500 | 241575 | 228948 | 4140 |
| ML-DSA-87 verify (1 KiB) | 2500 | 102888 | 101821 | 9719 |
| X25519 keygen | 2500 | 17571 | 17427 | 56911 |
| X25519 Diffie-Hellman | 2500 | 57793 | 57373 | 17303 |
| HKDF-SHA384 (128 B) | 2500 | 2171 | 2158 | 460713 |
| HMAC-SHA384 (1 KiB) | 2500 | 2981 | 2979 | 335405 |
| Hybrid KDF (128 B) | 2500 | 3251 | 3241 | 307563 |
| AEAD encrypt (1 KiB) | 2500 | 3536 | 3523 | 282797 |
| AEAD decrypt (1 KiB) | 2500 | 3917 | 3636 | 255297 |

Three consecutive runs gave best-batch times within about 1% of each other for
every operation. The README quotes the best batch; the median is within about
11% of it here.

### Effect of `fast-x25519`

Measured back to back on the same machine, 2,700 iterations, best of 9 batches
(an earlier build of this harness):

| Operation | Without `fast-x25519` | With `fast-x25519` |
|---|---:|---:|
| X25519 keygen | 30,975 ns | 17,640 ns |
| X25519 Diffie-Hellman | 58,464 ns | 57,618 ns |

The precomputed tables only accelerate multiplication of the fixed basepoint, so
key generation speeds up about 1.75x and Diffie-Hellman does not change. The
feature adds about 30 KB of code and rodata on `aarch64-unknown-none` (see the
README footprint table).

## Interpreting Results

Results depend on CPU, OS, compiler, optimization level, cache state, and the selected dependency implementations. They should not be represented as certification evidence, constant-time proof, or target-hardware performance. For acquisition diligence, record the exact machine, Rust toolchain, commit, and command alongside any quoted numbers.

## Embedded Footprint

The benchmark harness intentionally does not invent flash/RAM/stack numbers for a target that has not been measured. Target-specific footprint should be collected from the buyer's actual architecture/toolchain using its normal linker/map-file tooling.

## Lite Footprint Measurements

The Lite configuration exists primarily for constrained flash/RAM targets.
Benchmark reports should compare like-for-like artifacts:

```text
cargo build -p shawncore-ffi --release
cargo build -p shawncore-ffi --no-default-features --features lite --profile lite
```

Record final static-library/firmware size together with execution timing and
stack/RAM measurements. Size reduction alone is not sufficient evidence that
a target MCU is suitable.
