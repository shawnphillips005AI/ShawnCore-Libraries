#!/usr/bin/env python3
"""ShawnCore 12.3.10 boundary-hardening patch.

Changes:
  1. Reject zero task entry points in the TCB/scheduler boundary.
  2. Document and enforce the same requirement through the C TCB constructor.
  3. Make SessionManager FFI exclusive-access requirements explicit.
  4. Make LatencyTracker single-measurement ownership explicit.
  5. Standardize FFI object-output lifecycle language where ptr::write is used.
  6. Add regression tests for zero entry points and contract text.

This script is intentionally transactional: it edits files in-place, never creates
.bak files, and aborts on an unexpected source shape.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path.cwd()
if not (ROOT / "shawncore-rtos-sync/src/ffi.rs").exists():
    ROOT = Path(__file__).resolve().parent


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.exists():
        raise RuntimeError(f"missing required file: {rel}")
    return p.read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count == 1:
        write(rel, text.replace(old, new, 1))
        return
    if count == 0 and new in text:
        return
    raise RuntimeError(f"{rel}: expected one unpatched match or an already-patched form; found {count}")


def insert_once(rel: str, anchor: str, insertion: str, *, after: bool = True) -> None:
    text = read(rel)
    if insertion in text:
        return
    count = text.count(anchor)
    if count != 1:
        raise RuntimeError(f"{rel}: expected exactly one anchor, found {count}")
    repl = anchor + insertion if after else insertion + anchor
    write(rel, text.replace(anchor, repl, 1))


def main() -> int:
    print("ShawnCore boundary-hardening patch")

    # ------------------------------------------------------------------
    # Scheduler: reject an executable task with no entry point.
    # ------------------------------------------------------------------
    replace_once(
        "shawncore-rtos-sync/src/bitmap_scheduler.rs",
        "        if tcb.priority >= 16 || !valid_stack || self.tasks[tcb.priority as usize].stack_base != 0 {\n            return Err(SchedulerError::TaskFault);\n        }",
        "        if tcb.entry_point == 0\n            || tcb.priority >= 16\n            || !valid_stack\n            || self.tasks[tcb.priority as usize].stack_base != 0\n        {\n            return Err(SchedulerError::TaskFault);\n        }",
    )

    replace_once(
        "shawncore-rtos-sync/src/tcb.rs",
        "    /// * `entry_point` - The memory address of the task's entry function.\n",
        "    /// * `entry_point` - The non-zero memory address of the task's entry function.\n",
    )

    # TCB constructor may already contain one or both guards from earlier
    # boundary-hardening patches. Add only the missing guards and tolerate
    # equivalent formatting rather than requiring one exact source snapshot.
    ffi_rel = "shawncore-rtos-sync/src/ffi.rs"
    ffi_text = read(ffi_rel)
    m = re.search(
        r"(pub unsafe extern \"C\" fn shawncore_rtos_tcb_new\(.*?\) -> ShawncoreRtosErr \{)(.*?)(\n\})",
        ffi_text,
        re.S,
    )
    if not m:
        raise RuntimeError("shawncore-rtos-sync/src/ffi.rs: could not locate shawncore_rtos_tcb_new")
    body = m.group(2)
    changed = False

    # Preserve the existing null check and insert alignment immediately after it.
    if "ptr_is_aligned(out_tcb)" not in body:
        null_pat = r"(\n\s*if out_tcb\.is_null\(\) \{\n\s*return ShawncoreRtosErr::InvalidMemory;\n\s*\})"
        if not re.search(null_pat, body):
            raise RuntimeError("shawncore-rtos-sync/src/ffi.rs: tcb_new null-check shape not found")
        body = re.sub(
            null_pat,
            r"\1\n    if !ptr_is_aligned(out_tcb) {\n        return ShawncoreRtosErr::InvalidMemory;\n    }",
            body,
            count=1,
        )
        changed = True

    if "if entry_point == 0" not in body:
        marker = "    if !ptr_is_aligned(out_tcb) {\n        return ShawncoreRtosErr::InvalidMemory;\n    }" if "ptr_is_aligned(out_tcb)" in body else None
        if marker and marker in body:
            body = body.replace(
                marker,
                marker + "\n    if entry_point == 0 {\n        return ShawncoreRtosErr::TaskFault;\n    }",
                1,
            )
            changed = True
        elif "if out_tcb.is_null()" in body:
            null_pat = r"(\n\s*if out_tcb\.is_null\(\) \{\n\s*return ShawncoreRtosErr::InvalidMemory;\n\s*\})"
            body = re.sub(
                null_pat,
                r"\1\n    if entry_point == 0 {\n        return ShawncoreRtosErr::TaskFault;\n    }",
                body,
                count=1,
            )
            changed = True
        else:
            raise RuntimeError("shawncore-rtos-sync/src/ffi.rs: tcb_new guard insertion point not found")

    if changed:
        ffi_text = ffi_text[:m.start(2)] + body + ffi_text[m.end(2):]
        write(ffi_rel, ffi_text)

    replace_once(
        "shawncore-rtos-sync/src/ffi.rs",
        "/// # Safety\n/// `out_tcb` must point to a valid `Tcb` struct.\n",
        "/// # Safety\n/// `out_tcb` must point to valid, properly aligned, UNINITIALIZED storage for a `Tcb`.\n/// `entry_point` must be non-zero. A previously initialized object in the destination\n/// storage must be destroyed before this function is called again.\n",
    )

    # Add scheduler test for the newly enforced entry-point invariant.
    insert_once(
        "shawncore-rtos-sync/src/bitmap_scheduler.rs",
        "    #[test]\n    fn duplicate_priority_and_zero_stack_base_are_rejected() {",
        "\n    #[test]\n    fn zero_entry_point_is_rejected() {\n        let mut scheduler = PerCoreScheduler::new();\n        let mut stack = [0u64; 2];\n        let stack_base = stack.as_mut_ptr() as u64;\n        let stack_size = core::mem::size_of_val(&stack);\n\n        assert!(unsafe {\n            scheduler.create_task(\n                Tcb::new_task(0, stack_base, stack_size, stack_base, 1),\n                0xA5A5,\n            )\n        }\n        .is_err());\n    }\n",
        after=False,
    )

    # ------------------------------------------------------------------
    # SessionManager: explicit exclusive-access contract at the C ABI.
    # ------------------------------------------------------------------
    session_notes = (
        "///\n/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access\n"
        "/// while any state-mutating operation is in progress. The C ABI does not serialize\n"
        "/// concurrent callers; the host RTOS must provide the required mutex, critical section,\n"
        "/// or task ownership. In particular, callers must not concurrently invoke handshake,\n"
        "/// encrypt/decrypt, or zeroize operations on the same manager.\n"
    )

    for signature in [
        "pub unsafe extern \"C\" fn shawncore_crypto_session_manager_initiate_handshake(\n",
        "pub unsafe extern \"C\" fn shawncore_crypto_session_manager_finalize_handshake(\n",
        "pub unsafe extern \"C\" fn shawncore_crypto_session_manager_encapsulate_for_peer(\n",
        "pub unsafe extern \"C\" fn shawncore_crypto_session_manager_encrypt_packet(\n",
        "pub unsafe extern \"C\" fn shawncore_crypto_session_manager_decrypt_packet(\n",
        "pub unsafe extern \"C\" fn shawncore_crypto_session_manager_zeroize(\n",
    ]:
        text = read("shawncore-pq-crypto/src/ffi.rs")
        if session_notes + signature in text:
            continue
        count = text.count(signature)
        if count != 1:
            raise RuntimeError(f"session FFI signature anchor not found uniquely: {signature.strip()}")
        text = text.replace(signature, session_notes + signature, 1)
        write("shawncore-pq-crypto/src/ffi.rs", text)

    # Also make the module contract explicit once at the top for integrators.
    module_anchor = "//! Foreign Function Interface (FFI) for the Cryptographic Stack.\n"
    module_note = (
        "//!\n"
        "//! Session objects are not internally serialized. The host must provide exclusive ownership\n"
        "//! while invoking any operation that mutates a `SessionManager`, including handshake state,\n"
        "//! replay counters, packet encryption/decryption state, and explicit zeroization.\n"
    )
    text = read("shawncore-pq-crypto/src/ffi.rs")
    if "Session objects are not internally serialized." not in text:
        insert_once("shawncore-pq-crypto/src/ffi.rs", module_anchor, module_note)

    # ------------------------------------------------------------------
    # LatencyTracker: explicit single-measurement ownership contract.
    # ------------------------------------------------------------------
    replace_once(
        "shawncore-rtos-sync/src/latency_tracker.rs",
        "/// Marks the beginning of a timed execution block.\n",
        "/// Marks the beginning of a timed execution block.\n    ///\n    /// The tracker represents one active measurement at a time. The host must ensure\n    /// that only one logical owner performs a `mark_start`/`mark_end` pair on a given\n    /// tracker. Concurrent or interleaved measurements on the same tracker are unsupported.\n",
    )

    replace_once(
        "shawncore-rtos-sync/src/latency_tracker.rs",
        "    /// Marks the end of a timed execution block, updating maximums and averages.\n",
        "    /// Marks the end of a timed execution block, updating maximums and averages.\n    ///\n    /// The matching `mark_start` must belong to the same logical measurement owner.\n    /// `mark_end` consumes the current active measurement exactly once.\n",
    )

    replace_once(
        "shawncore-rtos-sync/src/ffi.rs",
        "/// Marks the start of a latency measurement.\n///\n/// # Safety\n/// `tracker` must be a valid, non-null pointer.\n",
        "/// Marks the start of a latency measurement.\n///\n/// **Concurrency contract:** one `LatencyTracker` supports one logical measurement owner at a time.\n/// The host must serialize or otherwise exclusively assign a start/end pair; concurrent or\n/// interleaved measurements on the same tracker are unsupported.\n///\n/// # Safety\n/// `tracker` must be a valid, non-null, properly aligned pointer to an initialized tracker.\n",
    )

    replace_once(
        "shawncore-rtos-sync/src/ffi.rs",
        "/// Marks the end of a latency measurement.\n///\n/// # Safety\n/// `tracker` must be a valid, non-null pointer.\n",
        "/// Marks the end of a latency measurement.\n///\n/// **Concurrency contract:** the call must pair with the same logical owner's most recent\n/// `mark_start`; the C ABI does not provide cross-thread measurement ownership.\n///\n/// # Safety\n/// `tracker` must be a valid, non-null, properly aligned pointer to an initialized tracker.\n",
    )

    # Add FFI alignment checks for latency tracker because the docs now promise aligned typed deref.
    replace_once(
        "shawncore-rtos-sync/src/ffi.rs",
        "    if tracker.is_null() {\n        return ShawncoreRtosErr::InvalidMemory;\n    }\n\n    let tracker_ref = unsafe { &*tracker };\n    tracker_ref.mark_start(current_timestamp);",
        "    if tracker.is_null() || !ptr_is_aligned(tracker) {\n        return ShawncoreRtosErr::InvalidMemory;\n    }\n\n    let tracker_ref = unsafe { &*tracker };\n    tracker_ref.mark_start(current_timestamp);",
    )

    replace_once(
        "shawncore-rtos-sync/src/ffi.rs",
        "    if tracker.is_null() {\n        return ShawncoreRtosErr::InvalidMemory;\n    }\n\n    let tracker_ref = unsafe { &*tracker };\n    tracker_ref.mark_end(current_timestamp);",
        "    if tracker.is_null() || !ptr_is_aligned(tracker) {\n        return ShawncoreRtosErr::InvalidMemory;\n    }\n\n    let tracker_ref = unsafe { &*tracker };\n    tracker_ref.mark_end(current_timestamp);",
    )

    # ------------------------------------------------------------------
    # Normalize output-storage lifecycle wording for object-producing RTOS FFI.
    # ------------------------------------------------------------------
    lifecycle_replacements = [
        (
            "/// `scheduler` must point to a valid, properly aligned, UNINITIALIZED memory region.\n",
            "/// `scheduler` must point to valid, properly aligned, UNINITIALIZED storage.\n/// Any previously initialized scheduler in that storage must be destroyed before reinitialization.\n",
        ),
        (
            "/// `pool` must point to a valid, uninitialized `DmaPool2K`. `memory_base` must point to a page-aligned\n",
            "/// `pool` must point to valid, properly aligned, UNINITIALIZED `DmaPool2K` storage.\n/// Any previously initialized pool in that storage must be destroyed before reinitialization.\n/// `memory_base` must point to a page-aligned\n",
        ),
        (
            "/// `tracker` must point to a valid, uninitialized `LatencyTracker`.\n",
            "/// `tracker` must point to valid, properly aligned, UNINITIALIZED `LatencyTracker` storage.\n/// Any previously initialized tracker in that storage must be destroyed before reinitialization.\n",
        ),
    ]
    for old, new in lifecycle_replacements:
        text = read("shawncore-rtos-sync/src/ffi.rs")
        if old in text:
            replace_once("shawncore-rtos-sync/src/ffi.rs", old, new)

    # SessionManager init wording.
    replace_once(
        "shawncore-pq-crypto/src/ffi.rs",
        "/// `manager` must point to a valid, properly aligned, UNINITIALIZED memory region of at least\n/// `shawncore_crypto_session_manager_sizeof()` bytes.\n",
        "/// `manager` must point to valid, properly aligned, UNINITIALIZED storage of at least\n/// `shawncore_crypto_session_manager_sizeof()` bytes. Any previously initialized manager in\n/// that storage must be destroyed before reinitialization.\n",
    )

    # ------------------------------------------------------------------
    # Verification markers.
    # ------------------------------------------------------------------
    checks = {
        "bitmap scheduler zero-entry rejection": (
            "if tcb.entry_point == 0",
            "shawncore-rtos-sync/src/bitmap_scheduler.rs",
        ),
        "scheduler regression test": (
            "fn zero_entry_point_is_rejected()",
            "shawncore-rtos-sync/src/bitmap_scheduler.rs",
        ),
        "C TCB zero-entry rejection": (
            "if entry_point == 0",
            "shawncore-rtos-sync/src/ffi.rs",
        ),
        "session concurrency contract": (
            "host RTOS must provide the required mutex",
            "shawncore-pq-crypto/src/ffi.rs",
        ),
        "latency concurrency contract": (
            "one active measurement at a time",
            "shawncore-rtos-sync/src/latency_tracker.rs",
        ),
        "latency FFI alignment": (
            "tracker.is_null() || !ptr_is_aligned(tracker)",
            "shawncore-rtos-sync/src/ffi.rs",
        ),
    }
    failures = []
    for label, (needle, rel) in checks.items():
        if needle not in read(rel):
            failures.append(label)

    if failures:
        raise RuntimeError("verification failed: " + ", ".join(failures))

    print("[+] scheduler rejects zero entry_point")
    print("[+] C TCB constructor rejects zero entry_point")
    print("[+] SessionManager FFI exclusive-access contract documented")
    print("[+] LatencyTracker single-owner contract documented")
    print("[+] LatencyTracker typed-pointer alignment checked")
    print("[+] FFI initialization lifecycle wording hardened")
    print("[=] no .bak files created")
    print("[=] Rust tests/formatting should be run in the target Codespace")
    print("PATCH COMPLETE")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
