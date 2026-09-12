#!/usr/bin/env python3
"""
ShawnCore-Libraries release-hygiene patcher.

Run from the repository root:
    python3 patch.py

This patch intentionally does NOT create .bak files. Git provides the
appropriate rollback/review mechanism for a source repository.

Changes:
  1. Synchronize package versions with the newest CHANGELOG version.
  2. Update stale version references in VALIDATION.md.
  3. Reconcile README test-count claims with the current source tree.
  4. Add a clear validation-status note without claiming hardware validation.
  5. Qualify queue comments so they describe memory ordering accurately.
  6. Run cargo fmt --all when Cargo is installed.

The script is conservative:
  - It only changes the first package-level `version` field in each
    Cargo.toml.
  - It does not modify dependency versions.
  - It does not invent test results.
  - It does not claim that source-level tests constitute hardware validation.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def latest_changelog_version(changelog: str) -> str | None:
    """
    Extract the newest release heading from CHANGELOG.md.

    Expected examples:
        ## [12.3.10] - 2026-09-11
        ## 12.3.10 - 2026-09-11
    """
    match = re.search(
        r"(?im)^\s*##\s*\[?(\d+\.\d+\.\d+)\]?(?=\s|[-–—]|$)",
        changelog,
    )
    if match:
        return match.group(1)

    return None


def count_rust_tests() -> int:
    """Count explicit Rust #[test] attributes in source files."""
    count = 0

    for path in ROOT.rglob("*.rs"):
        excluded = {".git", "target", ".cargo"}

        # Fuzz targets are intentionally excluded from the normal Rust test
        # count because they are separate fuzzing artifacts.
        if any(part in excluded for part in path.parts):
            continue

        if "fuzz" in path.parts:
            continue

        try:
            source = read_text(path)
        except (OSError, UnicodeDecodeError):
            continue

        count += len(
            re.findall(r"(?m)^\s*#\[test\]\s*$", source)
        )

    return count


def patch_cargo_versions(version: str) -> int:
    """
    Update only the first `version = "..."` field in each Cargo.toml.

    This is intended to hit [package].version while leaving dependency
    version requirements untouched.
    """
    changed = 0

    for path in ROOT.rglob("Cargo.toml"):
        if any(part in {".git", "target"} for part in path.parts):
            continue

        original = read_text(path)

        updated, replacements = re.subn(
            r'(?m)^(\s*version\s*=\s*")\d+\.\d+\.\d+(")',
            rf"\g<1>{version}\2",
            original,
            count=1,
        )

        if replacements and updated != original:
            write_text(path, updated)
            changed += 1
            print(f"[+] {path.relative_to(ROOT)}: package version -> {version}")

    return changed


def patch_validation(version: str, test_count: int) -> bool:
    path = ROOT / "VALIDATION.md"

    if not path.exists():
        print("[=] VALIDATION.md not found; skipping")
        return False

    original = read_text(path)
    updated = original

    # Replace the specifically known stale release reference.
    updated = re.sub(
        r"(?i)\b12\.3\.2\b",
        version,
        updated,
    )

    marker = "### Current release-hygiene status"

    if marker not in updated:
        updated += (
            "\n\n"
            f"{marker}\n\n"
            f"- Current repository release target: `{version}`.\n"
            f"- Current source-tree count: `{test_count}` Rust functions "
            f"annotated with `#[test]`.\n"
            "- The source tree contains crypto self-test/KAT coverage.\n"
            "- Hardware validation, independent interoperability/KAT "
            "cross-validation, and independent security review remain "
            "separate validation gates.\n"
        )

    if updated == original:
        return False

    write_text(path, updated)
    print("[+] VALIDATION.md updated")
    return True


def patch_readme(test_count: int) -> bool:
    path = ROOT / "README.md"

    if not path.exists():
        print("[=] README.md not found; skipping")
        return False

    original = read_text(path)
    updated = original

    # Correct the known stale counts without globally replacing unrelated
    # numbers elsewhere in the document.
    updated = re.sub(
        r"(?i)\b56\s+tests\b",
        f"{test_count} Rust #[test] functions",
        updated,
    )

    updated = re.sub(
        r"(?i)\b49\s+Rust\s+unit\s+tests\b",
        f"{test_count} Rust #[test] functions",
        updated,
    )

    updated = re.sub(
        r"(?i)\b49\s+unit\s+tests\b",
        f"{test_count} Rust #[test] functions",
        updated,
    )

    marker = "### Validation-count note"

    if marker not in updated:
        updated += (
            "\n\n"
            f"{marker}\n\n"
            f"`patch.py` detects `{test_count}` Rust functions annotated "
            f"with `#[test]`. This is a source-tree count, not a claim that "
            f"all tests have been executed on hardware. Runtime, hardware, "
            f"interoperability, and independent security validation remain "
            f"distinct gates.\n"
        )

    if updated == original:
        return False

    write_text(path, updated)
    print("[+] README.md updated")
    return True


def patch_queue_comments() -> int:
    replacements = {
        (
            "Prevent the CPU from reordering the payload read AFTER the "
            "second sequence check."
        ): (
            "Provides a SeqCst ordering barrier between the payload access "
            "and sequence validation under the Rust atomic memory model."
        ),
        (
            "Prevent the CPU from reordering the payload write BEFORE "
            "publishing the sequence."
        ): (
            "Provides a SeqCst ordering barrier between the payload write "
            "and sequence publication under the Rust atomic memory model."
        ),
    }

    changed = 0

    for filename in ("spsc_queue.rs", "ring_buffer.rs"):
        candidates = (
            ROOT / filename,
            ROOT / "src" / filename,
        )

        for path in candidates:
            if not path.exists():
                continue

            original = read_text(path)
            updated = original

            for old, new in replacements.items():
                updated = updated.replace(old, new)

            if updated != original:
                write_text(path, updated)
                changed += 1
                print(
                    f"[+] {path.relative_to(ROOT)}: "
                    "memory-ordering comments qualified"
                )

    return changed


def run_cargo_fmt() -> bool:
    cargo = shutil.which("cargo")

    if cargo is None:
        print("[!] cargo not found; skipping cargo fmt --all")
        return False

    print("[>] cargo fmt --all")
    result = subprocess.run(
        [cargo, "fmt", "--all"],
        cwd=ROOT,
        check=False,
    )

    if result.returncode != 0:
        print(
            f"[!] cargo fmt --all returned exit code "
            f"{result.returncode}"
        )
        return False

    print("[+] cargo fmt --all completed")
    return True


def main() -> int:
    print("ShawnCore patch.py — release hygiene + validation consistency")
    print(f"[=] Repository: {ROOT}")

    changelog = ROOT / "CHANGELOG.md"

    if not changelog.exists():
        print("[!] CHANGELOG.md not found")
        return 1

    version = latest_changelog_version(read_text(changelog))

    if version is None:
        print("[!] Could not determine the latest CHANGELOG version")
        return 1

    test_count = count_rust_tests()

    print(f"[=] CHANGELOG release: {version}")
    print(f"[=] Rust #[test] functions detected: {test_count}")

    cargo_changed = patch_cargo_versions(version)
    validation_changed = patch_validation(version, test_count)
    readme_changed = patch_readme(test_count)
    queue_changed = patch_queue_comments()

    total_changes = (
        cargo_changed
        + int(validation_changed)
        + int(readme_changed)
        + queue_changed
    )

    if total_changes:
        run_cargo_fmt()
    else:
        print("[=] No repository changes were necessary")

    print()
    print("Patch complete.")
    print(f"  Release version:       {version}")
    print(f"  Rust #[test] count:   {test_count}")
    print(f"  Cargo files changed:  {cargo_changed}")
    print(f"  Validation changed:   {validation_changed}")
    print(f"  README changed:       {readme_changed}")
    print(f"  Queue files changed:  {queue_changed}")
    print()
    print("No .bak files were created.")
    print("Review with: git diff")

    return 0


if __name__ == "__main__":
    sys.exit(main())
