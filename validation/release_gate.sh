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

# 6. Verify the public PQ feature surface is exactly the expected set.
PQ_FEATURES="$(cargo metadata --format-version 1 --no-deps --locked \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); p=next(x for x in d["packages"] if x["name"]=="shawncore-pq-crypto"); print(", ".join(sorted(p["features"])))')"
printf '%s\n' "[release-gate] PQ features: $PQ_FEATURES"

EXPECTED_FEATURES="default, fast-x25519, lite, ml-dsa"
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

# 7b. Targets without 64-bit atomics must be rejected with the documented message.
# Skipped, loudly, when the Cortex-M target is not installed.
if rustup target list --installed 2>/dev/null | grep -qx thumbv7em-none-eabihf; then
    step "32-bit target rejection"
    if cargo check -p shawncore-pq-crypto -p shawncore-rtos-sync \
        --target thumbv7em-none-eabihf --locked > "$ROOT/target/thumb.log" 2>&1; then
        fail "a 32-bit target unexpectedly built"
    fi
    [[ "$(grep -c 'requires a 64-bit target with native 64-bit atomics' "$ROOT/target/thumb.log")" -ge 2 ]] || \
        fail "32-bit rejection message missing for one of the crates"
    pass "32-bit target rejection"
else
    step "32-bit target rejection SKIPPED (rustup target add thumbv7em-none-eabihf to enable)"
fi

# 7c. The OpenSSL cross-implementation vectors must be reproducible. Skipped when OpenSSL < 3.5.
case "$(openssl version 2>/dev/null | awk '{print $2}')" in
    3.[5-9]*|[4-9].*)
        step "OpenSSL vector reproducibility"
        REGENERATED="$(mktemp)"
        SHAWNCORE_VECTOR_OUT="$REGENERATED" bash "$ROOT/validation/gen_openssl_vectors.sh" > /dev/null
        diff -u <(grep -v '^#' "$ROOT/shawncore-pq-crypto/tests/vectors/openssl_interop.txt") \
                <(grep -v '^#' "$REGENERATED") || fail "OpenSSL vectors are not reproducible"
        rm -f "$REGENERATED"
        pass "OpenSSL vector reproducibility"
        ;;
    *) step "OpenSSL vector reproducibility SKIPPED (OpenSSL >= 3.5 required)" ;;
esac

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
