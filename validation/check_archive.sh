#!/usr/bin/env bash
# Verifies the FFI static archives against the public C header.
#   1. Header function declarations and exported archive symbols match exactly.
#   2. The aarch64-unknown-none archive resolves every undefined symbol internally
#      and references no allocator, libc I/O, or threading symbols.
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
