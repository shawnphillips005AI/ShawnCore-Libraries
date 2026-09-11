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

## Interpreting Results

Results depend on CPU, OS, compiler, optimization level, cache state, and the selected dependency implementations. They should not be represented as certification evidence, constant-time proof, or target-hardware performance. For acquisition diligence, record the exact machine, Rust toolchain, commit, and command alongside any quoted numbers.

## Embedded Footprint

The benchmark harness intentionally does not invent flash/RAM/stack numbers for a target that has not been measured. Target-specific footprint should be collected from the buyer's actual architecture/toolchain using its normal linker/map-file tooling.
