#!/usr/bin/env python3
"""ShawnCore scheduler stack/canary boundary hardening patch.

Portable: locates the repository from the current working directory or the
script's directory and never assumes a nested `repo/` or fixed archive name.
Idempotent and creates no .bak files.
"""
from __future__ import annotations
from pathlib import Path
import sys

TARGET_REL = Path("shawncore-rtos-sync/src/bitmap_scheduler.rs")


def find_repo_root() -> Path:
    candidates: list[Path] = []
    for base in (Path.cwd(), Path(__file__).resolve().parent):
        base = base.resolve()
        for p in (base, *base.parents):
            candidates.extend((p, p / "ShawnCore-Libraries-main", p / "repo"))
    seen = set()
    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        if (candidate / "Cargo.toml").is_file() and (candidate / TARGET_REL).is_file():
            return candidate
        # Also allow a directory identified by the target alone; useful when
        # Cargo metadata is temporarily unavailable in a minimal checkout.
        if (candidate / TARGET_REL).is_file():
            return candidate
    raise SystemExit(
        "ERROR: could not locate ShawnCore repository. Run from the repository "
        "root (the directory containing Cargo.toml) or place patch.py there."
    )


def replace_once(text: str, old: str, new: str, label: str) -> tuple[str, bool]:
    count = text.count(old)
    if count == 0:
        if new in text:
            return text, False
        raise RuntimeError(f"{label}: no known unpatched or already-patched form found")
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1), True


def patch_scheduler(text: str) -> tuple[str, int]:
    changes = 0

    old = "        && rsp >= tcb.stack_base\n        && rsp <= stack_end\n"
    new = (
        "        && rsp >= tcb.stack_base + core::mem::size_of::<u64>() as u64\n"
        "        && rsp <= stack_end\n"
    )
    text, changed = replace_once(text, old, new, "valid_stack_pointer RSP lower bound")
    changes += changed

    # Tests that previously placed RSP directly on stack_base must move past
    # the reserved canary word.
    for task_id in (1, 2):
        old_test = f"Tcb::new_task({task_id}, stack_base, stack_size, stack_base, 1)"
        new_test = (
            f"Tcb::new_task({task_id}, stack_base, stack_size, "
            "stack_base + core::mem::size_of::<u64>() as u64, 1)"
        )
        text, changed = replace_once(text, old_test, new_test, f"scheduler test {task_id} RSP")
        changes += changed

    marker = """    #[test]\n    fn duplicate_priority_and_zero_stack_base_are_rejected() {\n"""
    regression = """    #[test]\n    fn rsp_cannot_overlap_stack_canary() {\n        let mut scheduler = PerCoreScheduler::new();\n        let mut stack = [0u64; 2];\n        let stack_base = stack.as_mut_ptr() as u64;\n        let stack_size = core::mem::size_of_val(&stack);\n        let canary = 0xAA55u64;\n\n        // The first u64 at stack_base is reserved for the canary.\n        let overlaps_canary = Tcb::new_task(\n            1,\n            stack_base,\n            stack_size,\n            stack_base,\n            1,\n        );\n        assert!(unsafe { scheduler.create_task(overlaps_canary, canary) }.is_err());\n\n        // The first stack address after the canary is valid.\n        let after_canary = Tcb::new_task(\n            2,\n            stack_base,\n            stack_size,\n            stack_base + core::mem::size_of::<u64>() as u64,\n            2,\n        );\n        assert!(unsafe { scheduler.create_task(after_canary, canary) }.is_ok());\n    }\n\n"""
    if "fn rsp_cannot_overlap_stack_canary()" not in text:
        if marker not in text:
            raise RuntimeError("RSP canary regression insertion point not found")
        text, changed = replace_once(
            text,
            marker,
            regression + marker,
            "RSP canary regression insertion",
        )
        changes += changed

    return text, changes


def main() -> int:
    print("ShawnCore scheduler stack/canary hardening patch")
    repo = find_repo_root()
    target = repo / TARGET_REL
    print(f"Repository: {repo}")

    original = target.read_text(encoding="utf-8")
    patched, changes = patch_scheduler(original)
    if patched != original:
        target.write_text(patched, encoding="utf-8", newline="")

    assert "rsp >= tcb.stack_base + core::mem::size_of::<u64>() as u64" in patched
    assert patched.count("fn rsp_cannot_overlap_stack_canary()") == 1

    print(f"Applied changes: {changes}")
    print("Verified: canary-reserved RSP bound and regression coverage present")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
