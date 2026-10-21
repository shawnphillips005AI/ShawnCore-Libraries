#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() {
    printf '%s\n' "[release-gate] $1"
}

pass() {
    printf '%s\n' "[release-gate][+] $1"
}

fail() {
    printf '%s\n' "[release-gate][FAIL] $1" >&2
    exit 1
}

# 1. Formatting.
step "format check"
cargo fmt --all -- --check
cargo fmt --manifest-path "$ROOT/fuzz/Cargo.toml" -- --check
pass "format"

# 2. Lint. Keep the gate deterministic and fail on warnings.
step "clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
pass "clippy"

# 3. Full workspace tests, including all default-feature cryptographic paths.
step "workspace tests"
cargo test --workspace --all-targets --locked
pass "workspace tests"

# 4. Standalone ThreadSanitizer workload.
step "ThreadSanitizer"
"$ROOT/validation/run_tsan.sh"
pass "ThreadSanitizer"

# 4b. Rust-instrumented AddressSanitizer over the crypto and RTOS test suites.
step "AddressSanitizer"
"$ROOT/validation/run_asan.sh"
pass "AddressSanitizer"

# 5. Build the complete FFI release artifact with the full feature set.
step "full FFI release build"
cargo build -p shawncore-ffi --release --locked
pass "full FFI release build"

ARTIFACT=""
if [[ -f "$ROOT/target/release/libshawncore_ffi.a" ]]; then
    ARTIFACT="$ROOT/target/release/libshawncore_ffi.a"
elif [[ -f "$ROOT/target/release/libshawncore_ffi.so" ]]; then
    ARTIFACT="$ROOT/target/release/libshawncore_ffi.so"
elif [[ -f "$ROOT/target/release/shawncore_ffi.dll" ]]; then
    ARTIFACT="$ROOT/target/release/shawncore_ffi.dll"
fi

if [[ -z "$ARTIFACT" ]]; then
    fail "FFI release artifact was not found"
fi

ARTIFACT_BYTES="$(wc -c < "$ARTIFACT")"
printf '%s\n' "[release-gate] full artifact bytes: $ARTIFACT_BYTES"

# 6. Verify the public PQ feature surface is exactly the expected trio.
PQ_FEATURES="$(cargo metadata --format-version 1 --no-deps --locked \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); p=next(x for x in d["packages"] if x["name"]=="shawncore-pq-crypto"); print(", ".join(sorted(p["features"])))')"
printf '%s\n' "[release-gate] PQ features: $PQ_FEATURES"

EXPECTED_FEATURES="default, lite, ml-dsa"
[[ "$PQ_FEATURES" == "$EXPECTED_FEATURES" ]] || \
    fail "unexpected shawncore-pq-crypto feature set: $PQ_FEATURES"

# 7. Compile the FFI Lite profile explicitly. This catches stale ML-DSA symbols
#    or feature-forwarding mistakes even when the default build is healthy.
step "Lite FFI check"
cargo check -p shawncore-ffi --no-default-features --features lite --locked
pass "Lite FFI check"

step "Lite crypto tests"
cargo test -p shawncore-pq-crypto --no-default-features --features lite --locked
pass "Lite crypto tests"

# 8. Bare-metal type check, header/archive symbol parity, and archive self-containment.
step "bare-metal check"
cargo check --target aarch64-unknown-none --workspace --locked
pass "bare-metal check"

step "archive checks"
bash "$ROOT/validation/check_archive.sh"
pass "archive checks"

step "C and C++ integration"
make -C "$ROOT/integration" syntax run cxx
pass "C and C++ integration"

# 9. Check the gate itself before declaring success.
bash -n "$ROOT/validation/release_gate.sh"
bash -n "$ROOT/validation/check_archive.sh"
pass "release gate syntax"

pass "release gate complete"
