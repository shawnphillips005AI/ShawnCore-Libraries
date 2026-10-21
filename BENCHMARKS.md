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

The harness performs one warm-up operation and then reports mean nanoseconds per operation and operations per second using `std::time::Instant`. Inputs are deterministic so repeated runs are comparable on the same machine/toolchain.

## Measurements

The harness reports ML-KEM-1024 key generation/encapsulation/decapsulation, ML-DSA-87 key generation/sign/verify, X25519 key generation/Diffie-Hellman, HKDF-SHA384, HMAC-SHA384, the hybrid KDF, and 1 KiB AEAD encryption/decryption.

## Reference Results

Recorded for release 12.3.11, source commit `f32bcf6`.

- **Machine:** AMD EPYC 7763, 2 vCPU development container, x86-64 Linux
- **Toolchain:** Rust 1.99.1, `release` profile (`lto = "fat"`, `codegen-units = 1`)
- **Command:** `SHAWNCORE_BENCH_ITERS=500 cargo run -p shawncore-benchmarks --release --locked`

| Operation | Iterations | Mean ns/op | Ops/sec |
|---|---:|---:|---:|
| ML-KEM-1024 keygen | 500 | 162,888 | 6,139 |
| ML-KEM-1024 encapsulate | 500 | 104,483 | 9,571 |
| ML-KEM-1024 decapsulate | 500 | 125,856 | 7,946 |
| ML-DSA-87 keygen | 500 | 1,206,640 | 829 |
| ML-DSA-87 sign (1 KiB) | 500 | 883,870 | 1,131 |
| ML-DSA-87 verify (1 KiB) | 500 | 387,234 | 2,582 |
| X25519 keygen | 500 | 120,950 | 8,268 |
| X25519 Diffie-Hellman | 500 | 286,805 | 3,487 |
| HKDF-SHA384 (128 B) | 500 | 3,332 | 300,136 |
| HMAC-SHA384 (1 KiB) | 500 | 5,319 | 188,004 |
| Hybrid KDF (128 B) | 500 | 7,012 | 142,606 |
| AEAD encrypt (1 KiB) | 500 | 5,607 | 178,353 |
| AEAD decrypt (1 KiB) | 500 | 5,962 | 167,716 |

The container is shared and the harness is single-threaded with one warm-up
iteration, so expect run-to-run variation of several percent. Treat these as a
relative comparison between operations on one machine.

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
