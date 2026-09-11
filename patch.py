#!/usr/bin/env python3
from pathlib import Path
import shutil, subprocess, sys

ROOT = Path(__file__).resolve().parent

def die(msg):
    print(f"[ERROR] {msg}")
    raise SystemExit(1)

def backup(p):
    b = p.with_suffix(p.suffix + ".pre-final-review.bak")
    if not b.exists():
        shutil.copy2(p,b)
        print(f"[+] Backup created: {b.name}")

def replace_once(p, old, new, label):
    s = p.read_text(encoding='utf-8')
    if new in s and old not in s:
        print(f"[=] {label}: already applied")
        return
    n=s.count(old)
    if n != 1: die(f"{label}: expected exactly 1 match, found {n}")
    backup(p); p.write_text(s.replace(old,new,1),encoding='utf-8'); print(f"[+] {label}: applied")

def run(cmd):
    print("\n$ "+" ".join(cmd)); r=subprocess.run(cmd,cwd=ROOT)
    if r.returncode: die(f"Command failed: {' '.join(cmd)}")

def main():
    if not (ROOT/'Cargo.toml').exists(): die('Put patch.py beside root Cargo.toml.')
    aead = ROOT/'shawncore-pq-crypto/src/ffi.rs'
    changelog = ROOT/'CHANGELOG.md'
    ci = ROOT/'.github/workflows/ci.yml'
    lib = ROOT/'shawncore-pq-crypto/src/lib.rs'
    for p in [aead,changelog,ci,lib]:
        if not p.exists(): die(f'Missing {p}')

    # Full SHA-384 KAT and truthful documentation.
    old_doc='''/// FIPS 140-3 Power-On Self-Test (POST)\n/// Verifies silicon ALU integrity by executing a SHA-384 Known-Answer Test (KAT).'''
    new_doc='''/// Cryptographic self-test using the NIST SHA-384 "abc" known-answer vector.\n///\n/// This verifies the linked SHA-384 implementation and does not establish FIPS\n/// certification, hardware integrity, or production suitability.'''
    replace_once(aead, old_doc, new_doc, 'self-test documentation')

    old_body='''    // NIST FIPS 180-4 SHA-384 Test Vector for "abc"\n    let expected_prefix = [0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b];\n\n    // Constant-time comparison to prevent timing side-channels during boot\n    use subtle::ConstantTimeEq;\n    if result[..8].ct_eq(&expected_prefix).unwrap_u8() == 1 {'''
    new_body='''    // NIST FIPS 180-4 SHA-384 test vector for "abc". Compare all 48 bytes.\n    let expected = [\n        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,\n        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,\n        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,\n        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,\n        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,\n        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,\n    ];\n\n    use subtle::ConstantTimeEq;\n    if result.ct_eq(&expected).unwrap_u8() == 1 {'''
    replace_once(aead, old_body, new_body, 'full SHA-384 KAT')

    # Add a direct self-test unit test to the existing root test module.
    marker='''    #[test]\n    fn aead_round_trip_rejects_tampering() {'''
    test='''    #[test]\n    fn crypto_self_test_accepts_known_sha384_vector() {\n        assert_eq!(\n            super::ffi::shawncore_crypto_self_test(),\n            ShawncoreCryptoErr::Success\n        );\n    }\n\n'''
    s=lib.read_text(encoding='utf-8')
    if 'fn crypto_self_test_accepts_known_sha384_vector()' not in s:
        if marker not in s: die('self-test regression insertion point not found')
        backup(lib); lib.write_text(s.replace(marker,test+marker,1),encoding='utf-8'); print('[+] self-test regression added')
    else: print('[=] self-test regression already present')

    # CI: existing session replay fuzz target should actually execute in CI.
    c=ci.read_text(encoding='utf-8')
    check_line='      - run: cargo check --manifest-path fuzz/Cargo.toml --bin session_replay_fuzz\n'
    fuzz_line='      - run: cargo +nightly fuzz run session_replay_fuzz -- -runs=10000 -max_len=512\n'
    if 'cargo check --manifest-path fuzz/Cargo.toml --bin session_replay_fuzz' not in c:
        anchor='      - run: cargo check --manifest-path fuzz/Cargo.toml --bin rtos_stateful_fuzz\n'
        if anchor not in c: die('CI fuzz check insertion point not found')
        backup(ci); c=c.replace(anchor,anchor+check_line,1); ci.write_text(c,encoding='utf-8'); print('[+] CI session_replay_fuzz build check added')
    else: print('[=] CI session replay build check already present')
    c=ci.read_text(encoding='utf-8')
    if 'cargo +nightly fuzz run session_replay_fuzz ' not in c:
        anchor='      - run: cargo +nightly fuzz run rtos_stateful_fuzz -- -runs=10000 -max_len=512\n'
        if anchor not in c: die('CI fuzz-run insertion point not found')
        backup(ci); c=c.replace(anchor,anchor+fuzz_line,1); ci.write_text(c,encoding='utf-8'); print('[+] CI session_replay_fuzz run added')
    else: print('[=] CI session replay run already present')

    # Correct the old changelog overclaim without rewriting history excessively.
    old='''- **FIPS 140-3 Compliance:** Added `shawncore_crypto_self_test()` to the C-API. This implements a Power-On Self-Test (POST) Known-Answer Test (KAT) for the underlying cryptographic primitives. Integrators must call this function during the boot sequence to verify silicon ALU integrity before processing sensitive data.'''
    new='''- **Cryptographic self-test:** Added `shawncore_crypto_self_test()` to the C API. This runs a full SHA-384 known-answer test for the `abc` vector. It verifies the linked SHA-384 implementation; it is not a FIPS 140-3 certification claim or a hardware-integrity test.'''
    replace_once(changelog,old,new,'self-test changelog wording')

    if shutil.which('cargo'):
        run(['cargo','fmt','--all'])
        run(['cargo','fmt','--all','--','--check'])
        run(['cargo','check','--workspace'])
        run(['cargo','test','--workspace'])
        run(['cargo','clippy','--workspace','--all-targets','--','-D','warnings'])
        run(['cargo','build','--workspace','--release'])
    else:
        print('[WARN] cargo unavailable; run validation in Codespaces.')
    if shutil.which('git') and (ROOT/'.git').exists():
        run(['git','diff','--check'])
    print('\nSUCCESS: final evidence/hardening patch applied. Review diff before commit.')

if __name__=='__main__': main()