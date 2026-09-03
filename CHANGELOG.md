# Changelog

All notable changes to this project are documented here. This project is a
prototype under external technical evaluation; version numbers track the
internal release-candidate line and do not imply certification, hardware
qualification, or production readiness.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [12.2.0] — 2026-09-03

Release-candidate prototype prepared for external technical review.

### Added

- `SECURITY.md`: trust boundaries, in-scope and out-of-scope threats, known
  limitations, and the host integration contract.
- `CHANGELOG.md`.
- `integration/Makefile` covering the C syntax check, smoke build and run, and
  the optional AddressSanitizer and Valgrind variants.

### Changed

- Renamed `shawncore-pq-crypto/src/Error.rs` to `error.rs` and `Zeroize.rs` to
  `zeroize.rs`, removing the `#[path]` attribute workarounds in `lib.rs`. Module
  paths (`crate::error`, `crate::zeroize`) are unchanged.
- Documentation now describes the 10,000-execution CI fuzz job accurately; the
  workflow has no scheduled nightly trigger.

### Removed

- `shawncore-rtos-sync/src/fft_queue.rs`, an empty placeholder module with no
  types, no functions, and no dependents. The concrete `FftResult` type and the
  FFT SPSC queue remain in `shawncore-rtos-sync::ffi`; the C ABI is unchanged.

### Security

No security defects were identified or fixed in this release. The security
posture, mitigations, and unmitigated threats are described in `SECURITY.md`.

### Validation

Host-side evidence is recorded in `VALIDATION.md`. Target-hardware behavior,
DMA and cache coherency, interrupt and watchdog behavior, hardware entropy
quality, ML-KEM/ML-DSA known-answer and interoperability testing, and
independent security review remain open gates.

## Earlier

Development prior to 12.2.0 was not tracked with release notes. The commit
history records the initial construction of the three crates, the C FFI surface,
the fuzz harness, and the CI workflow.
