#!/usr/bin/env python3
"""Mutation check: applies one deliberate fault at a time to a disposable copy and requires the
named tests to fail. The repository is never modified.

    python3 validation/run_mutants.py            # all mutants
    python3 validation/run_mutants.py NAME ...   # only mutants whose name contains NAME

Each mutant replaces the first occurrence of `old` with `new`. A mutant is KILLED when the
selected `cargo test` command exits non-zero (including a process abort or signal), SURVIVED when
it passes, and INVALID when the pattern is missing or the mutant does not compile; the run fails
on SURVIVED or INVALID. This covers only the faults listed here: the mutants recorded in
VALIDATION.md before version 2 of the authenticated handshake were run with an ad-hoc script that
is not part of this repository and cannot be reproduced from it.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PQ = "shawncore-pq-crypto/src"
AUTH = ["-p", "shawncore-pq-crypto", "--test", "authenticated_handshake"]
LIB = ["-p", "shawncore-pq-crypto", "--lib"]

# (name, file, old, new, cargo test arguments)
MUTANTS = [
    # Authenticated handshake, protocol version 2.
    ("v2 finalize skips tag check", f"{PQ}/session_manager.rs",
     "if !confirmation_tags_equal(&expected, peer_confirmation) {", "if false {", AUTH),
    ("v2 confirm_peer accepts any tag", f"{PQ}/session_manager.rs",
     "Ok(tag) if confirmation_tags_equal(&tag, peer_confirmation) => {", "Ok(_tag) => {", AUTH),
    ("v2 encapsulator tag uses the keygen label", f"{PQ}/session_manager.rs",
     "            &encapsulator_key,\n            CONFIRM_LABEL_ENCAPSULATING_SIDE,\n            &transcript,",
     "            &encapsulator_key,\n            CONFIRM_LABEL_KEYGEN_SIDE,\n            &transcript,", AUTH),
    ("v2 both roles share one label", f"{PQ}/auth_handshake.rs",
     'pub const CONFIRM_LABEL_KEYGEN_SIDE: &[u8] = b"ShawnCore-auth-v2 confirm key-generating side";',
     'pub const CONFIRM_LABEL_KEYGEN_SIDE: &[u8] = b"ShawnCore-auth-v2 confirm encapsulating side";', AUTH),
    ("v2 keygen tag uses the encapsulator key", f"{PQ}/session_manager.rs",
     "confirmation_tag(&keygen_key, CONFIRM_LABEL_KEYGEN_SIDE, peer_digest)",
     "confirmation_tag(&encapsulator_key, CONFIRM_LABEL_KEYGEN_SIDE, peer_digest)", AUTH),
    ("v2 confirmation expansion reuses the session info", f"{PQ}/hybrid_kdf.rs",
     "hkdf.expand(confirmation_info, &mut confirmation)", "hkdf.expand(info, &mut confirmation)",
     LIB + ["confirmation_tests"]),
    ("v2 encapsulator digest drops its tag", f"{PQ}/auth_handshake.rs",
     "sha384(&[ENCAPSULATOR_DIGEST_LABEL, transcript, encapsulator_tag])",
     "sha384(&[ENCAPSULATOR_DIGEST_LABEL, transcript])", AUTH),
    ("v2 keygen digest drops its tag", f"{PQ}/auth_handshake.rs",
     "sha384(&[KEYGEN_DIGEST_LABEL, encapsulator_digest, keygen_tag])",
     "sha384(&[KEYGEN_DIGEST_LABEL, encapsulator_digest])", AUTH),
    ("v2 binding drops app_info", f"{PQ}/auth_handshake.rs",
     "        &app_info_len.to_be_bytes(),\n        app_info,\n    ]))",
     "        &app_info_len.to_be_bytes(),\n    ]))", AUTH),
    ("v2 binding drops the encapsulator identity", f"{PQ}/auth_handshake.rs",
     "        keygen_identity,\n        encapsulator_identity,", "        keygen_identity,", AUTH),
    ("v2 binding drops the ML-KEM key", f"{PQ}/auth_handshake.rs",
     "        &keygen_ml_kem_pk.to_bytes(),\n", "", AUTH),
    ("v2 transcript drops the ciphertext", f"{PQ}/auth_handshake.rs",
     "        binding,\n        &ciphertext.0,\n        &encapsulator_x25519_pk.0,",
     "        binding,\n        &encapsulator_x25519_pk.0,", AUTH),
    ("v2 traffic allowed while unconfirmed", f"{PQ}/session_manager.rs",
     "            || self.pending_auth.is_some()", "            || false", AUTH),
    ("v2 confirm_peer skips the identity pin", f"{PQ}/session_manager.rs",
     "if !confirmation_tags_equal(&presented, &pinned_identity) {", "if false {", AUTH),
    ("v2 pending confirmation key is not zeroized", f"{PQ}/session_manager.rs",
     "            secure_zeroize(&mut pending.confirmation_key);\n            secure_cache_flush(&pending.confirmation_key);",
     "            secure_cache_flush(&pending.confirmation_key);", LIB + ["pending_confirmation"]),
    # C ABI boundary, input bounds and host-callback contract.
    ("abi hmac accepts a length beyond the slice limit", f"{PQ}/ffi.rs",
     "    if !range_ok(data, data_len) {", "    if false {", LIB + ["boundary_tests"]),
    ("abi hkdf accepts an oversized output length", f"{PQ}/ffi.rs",
     "    if !range_ok(info, info_len) || !range_ok(out, out_len) {", "    if false {",
     LIB + ["boundary_tests"]),
    ("abi ml_dsa_verify accepts a wrapping range", f"{PQ}/ffi.rs",
     "    if !range_ok(msg, msg_len) {\n        return ShawncoreCryptoErr::InvalidLength;\n    }\n    if !ptr_is_aligned(pk) || !ptr_is_aligned(sig) {",
     "    if !ptr_is_aligned(pk) || !ptr_is_aligned(sig) {", LIB + ["boundary_tests"]),
    ("abi finalize_handshake accepts an oversized salt", f"{PQ}/ffi.rs",
     "        || !range_ok(salt, salt_len)", "        || false", LIB + ["boundary_tests"]),
    # Removing the `MAX_APP_INFO_LEN` check in ffi.rs is an equivalent mutant: the Rust API rejects
    # an `app_info` above u32::MAX with the same InvalidLength before reading it, so only slice
    # formation over an unread range differs and no test can observe that. The check stays as
    # defense in depth and is deliberately not listed here.
    ("abi packet length cap removed", f"{PQ}/ffi.rs",
     "slice_len_valid(len) && len as u64 <= crate::aead_wrapper::CHACHA20_MAX_BYTES",
     "slice_len_valid(len)", LIB + ["boundary_tests"]),
    ("abi zero-length range counted as overlap", f"{PQ}/ffi.rs",
     "    if first_len == 0 || second_len == 0 {", "    if false {", LIB + ["boundary_tests"]),
    ("host callback receives an empty range", f"{PQ}/zeroize.rs",
     "    if len == 0 {\n        return;\n    }", "    if false {\n        return;\n    }",
     LIB + ["boundary_tests"]),
    ("abi dmapool init validates the backing as bytes, not buffers", "shawncore-rtos-sync/src/ffi.rs",
     "valid_dma_region(memory_base.cast::<[u8; 2048]>(), size_in_bytes, 256)",
     "valid_dma_region(memory_base, size_in_bytes, 256)",
     ["-p", "shawncore-rtos-sync", "--lib", "boundary_contract_tests"]),
]


def main():
    wanted = sys.argv[1:]
    selected = [m for m in MUTANTS if not wanted or any(w in m[0] for w in wanted)]
    work = Path(tempfile.mkdtemp(prefix="shawncore-mutants-"))
    copy = work / "tree"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns("target", ".git", "corpus", "artifacts"))
    env = dict(os.environ, CARGO_TARGET_DIR=str(work / "target"))
    env.pop("RUSTUP_TOOLCHAIN", None)

    def cargo_test(args):
        return subprocess.run(["cargo", "test", "--locked", *args], cwd=copy, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    baseline = {tuple(m[4]): None for m in selected}
    for args in baseline:
        result = cargo_test(list(args))
        if result.returncode != 0:
            print(f"baseline FAILED for `cargo test {' '.join(args)}`; refusing to mutate\n{result.stdout[-2000:]}")
            return 2

    bad = 0
    for name, relative, old, new, args in selected:
        path = copy / relative
        original = path.read_text()
        if old not in original:
            print(f"INVALID   {name}: pattern not found in {relative}")
            bad += 1
            continue
        path.write_text(original.replace(old, new, 1))
        try:
            result = cargo_test(args)
        finally:
            path.write_text(original)
        if "error[E" in result.stdout or "could not compile" in result.stdout:
            print(f"INVALID   {name}: mutant does not compile")
            bad += 1
        elif result.returncode == 0:
            print(f"SURVIVED  {name}")
            bad += 1
        else:
            failing = [l for l in result.stdout.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
            how = f"{len(failing)} failing test(s)" if failing else "process aborted or signalled"
            print(f"KILLED    {name} ({how})")
    shutil.rmtree(work, ignore_errors=True)
    print(f"{len(selected) - bad}/{len(selected)} mutants killed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
