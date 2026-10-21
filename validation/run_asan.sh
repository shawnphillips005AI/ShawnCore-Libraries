#!/usr/bin/env bash
# shawncore-asan-runner-v1
# Rust-instrumented AddressSanitizer run of the crypto and RTOS test suites.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOST_TRIPLE="${HOST_TRIPLE:-x86_64-unknown-linux-gnu}"

rustup run nightly rustc --version >/dev/null 2>&1 || {
    echo "error: Rust nightly toolchain is required" >&2
    exit 2
}

# An explicit --target keeps RUSTFLAGS off proc-macros and build scripts; without it
# `zeroize_derive` fails to resolve (E0463) under -Zsanitizer.
export CARGO_TARGET_DIR="${ASAN_TARGET_DIR:-$ROOT/target/asan}"
export RUSTFLAGS="-Zsanitizer=address"
# The no_std crates never allocate on the host side; leak checking adds only libtest noise.
export ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

cargo +nightly test \
    --target "$HOST_TRIPLE" \
    --locked \
    -p shawncore-rtos-sync -p shawncore-pq-crypto \
    --lib --tests

printf '%s\n' "[+] AddressSanitizer completed with no reported error."
