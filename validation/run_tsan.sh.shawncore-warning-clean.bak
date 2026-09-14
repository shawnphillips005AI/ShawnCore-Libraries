#!/usr/bin/env bash
# shawncore-tsan-runner-v5
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HOST_TRIPLE="${HOST_TRIPLE:-x86_64-unknown-linux-gnu}"
TSAN_TARGET_DIR="${TSAN_TARGET_DIR:-$ROOT/target/tsan-standalone}"

command -v rustup >/dev/null 2>&1 || {
    echo "error: rustup is required for ThreadSanitizer validation" >&2
    exit 2
}
command -v cargo >/dev/null 2>&1 || {
    echo "error: cargo is required for ThreadSanitizer validation" >&2
    exit 2
}

rustup run nightly rustc --version >/dev/null 2>&1 || {
    echo "error: Rust nightly toolchain is required" >&2
    echo "install with: rustup toolchain install nightly" >&2
    exit 2
}

rustup target list --installed --toolchain nightly | grep -Fxq "$HOST_TRIPLE" || {
    echo "error: nightly target $HOST_TRIPLE is not installed" >&2
    echo "install with: rustup target add --toolchain nightly $HOST_TRIPLE" >&2
    exit 2
}

rm -rf -- "$TSAN_TARGET_DIR"
mkdir -p -- "$TSAN_TARGET_DIR"

export CARGO_TARGET_DIR="$TSAN_TARGET_DIR"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zsanitizer=thread -Cunsafe-allow-abi-mismatch=sanitizer"
export TSAN_OPTIONS="halt_on_error=1:exitcode=66:report_signal_unsafe=0${TSAN_OPTIONS:+:$TSAN_OPTIONS}"

printf '%s\n' "[+] ThreadSanitizer validation"
printf '%s\n' "[+] target: $HOST_TRIPLE"
printf '%s\n' "[+] clean cargo target: $CARGO_TARGET_DIR"
printf '%s\n' "[+] standalone binary: shawncore-validation/bin/tsan_host_validation"
printf '%s\n' "[+] libtest harness is NOT used"

# Standalone executable on purpose. Do not replace this with `cargo test`:
# libtest contains its own concurrent event-reporting machinery, which can produce
# sanitizer reports unrelated to the code under validation when std is uninstrumented.
cargo +nightly run \
    --target "$HOST_TRIPLE" \
    --manifest-path "$ROOT/Cargo.toml" \
    --locked \
    -p shawncore-validation \
    --bin tsan_host_validation

printf '%s\n' "[+] ThreadSanitizer completed with no reported data race."
