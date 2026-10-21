#!/usr/bin/env bash
# Verifies the FFI static archives against the public C header.
#   1. Header function declarations and exported archive symbols match exactly.
#   2. The aarch64-unknown-none archive resolves every undefined symbol internally
#      and references no allocator, libc I/O, or threading symbols.
#   3. The Lite archive excludes ML-DSA and the X25519 precomputed tables.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HEADER="$ROOT/shawncore-ffi/include/shawncore.h"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cargo build -p shawncore-ffi --release --locked
HOST_ARCHIVE="$ROOT/target/release/libshawncore_ffi.a"

grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_[:space:]*]*[[:space:]]+shawncore_(crypto|rtos)_[A-Za-z0-9_]+[[:space:]]*\(' "$HEADER" \
    | sed -E 's/.*[[:space:]](shawncore_(crypto|rtos)_[A-Za-z0-9_]+)[[:space:]]*\(.*/\1/' \
    | sort -u > "$TMP/header"
nm -g --defined-only "$HOST_ARCHIVE" | awk '{print $3}' \
    | grep -E '^shawncore_(crypto|rtos)_' | sort -u > "$TMP/archive"

diff -u "$TMP/header" "$TMP/archive"
printf '%s\n' "[archive] header/archive symbols match: $(wc -l < "$TMP/header") symbols"

cargo build -p shawncore-ffi --release --target aarch64-unknown-none --locked
BARE_ARCHIVE="$ROOT/target/aarch64-unknown-none/release/libshawncore_ffi.a"

nm -g --defined-only "$BARE_ARCHIVE" | awk 'NF==3 {print $3}' | sort -u > "$TMP/defined"
nm -u "$BARE_ARCHIVE" | awk 'NF==2 {print $2}' | sort -u > "$TMP/undefined"

UNRESOLVED="$(comm -23 "$TMP/undefined" "$TMP/defined")"
if [[ -n "$UNRESOLVED" ]]; then
    printf '%s\n' "[archive][FAIL] undefined symbols not defined by the archive:" "$UNRESOLVED" >&2
    exit 1
fi

FORBIDDEN="$(grep -E '^(malloc|calloc|realloc|free|__rust_alloc|__rust_dealloc|__rust_realloc|printf|puts|write|mmap|pthread_.*)$' "$TMP/undefined" || true)"
if [[ -n "$FORBIDDEN" ]]; then
    printf '%s\n' "[archive][FAIL] forbidden external references:" "$FORBIDDEN" >&2
    exit 1
fi
printf '%s\n' "[archive] aarch64-unknown-none archive is self-contained"

# The Lite archive must not carry ML-DSA, its signature ABI, or the X25519 precomputed tables.
cargo build -p shawncore-ffi --release --no-default-features --features lite --locked \
    --target-dir "$TMP/lite-target"
LITE_ARCHIVE="$TMP/lite-target/release/libshawncore_ffi.a"
nm -g --defined-only "$LITE_ARCHIVE" | awk 'NF==3 {print $3}' | sort -u > "$TMP/lite-defined"
if grep -Ei 'ml_dsa|mldsa' "$TMP/lite-defined"; then
    printf '%s\n' "[archive][FAIL] Lite archive exports ML-DSA symbols" >&2
    exit 1
fi
if nm "$LITE_ARCHIVE" 2>/dev/null | grep -Ei 'ml_dsa|mldsa|ED25519_BASEPOINT_TABLE|basepoint_table' >/dev/null; then
    printf '%s\n' "[archive][FAIL] Lite archive contains ML-DSA or precomputed-table symbols" >&2
    exit 1
fi
grep -q '^shawncore_crypto_ml_kem_keygen$' "$TMP/lite-defined" \
    || { printf '%s\n' "[archive][FAIL] Lite archive lost ML-KEM" >&2; exit 1; }

# The header seen with SHAWNCORE_LITE must declare exactly what the Lite archive exports.
SYMBOL_PATTERN='^[[:space:]]*[A-Za-z_][A-Za-z0-9_[:space:]*]*[[:space:]]+shawncore_(crypto|rtos)_[A-Za-z0-9_]+[[:space:]]*\('
cc -E -P -DSHAWNCORE_LITE "$HEADER" | grep -E "$SYMBOL_PATTERN" \
    | sed -E 's/.*[[:space:]](shawncore_(crypto|rtos)_[A-Za-z0-9_]+)[[:space:]]*\(.*/\1/' \
    | sort -u > "$TMP/lite-header"
grep -E '^shawncore_(crypto|rtos)_' "$TMP/lite-defined" | sort -u > "$TMP/lite-archive"
diff -u "$TMP/lite-header" "$TMP/lite-archive"
printf '%s\n' "[archive] Lite header/archive symbols match: $(wc -l < "$TMP/lite-header") symbols"
printf '%s\n' "[archive] Lite archive excludes ML-DSA and X25519 tables, retains ML-KEM"
