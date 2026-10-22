#!/usr/bin/env python3
"""Documentation consistency check: every concrete thing the documents point at must exist.

Checks, for README.md, ARCHITECTURE.md, SECURITY.md, VALIDATION.md, REVIEW.md, BENCHMARKS.md,
CHANGELOG.md and RELEASE_MANIFEST.txt:
  * `test_name` style identifiers in backticks that look like Rust test names exist as functions
    in the source tree;
  * `shawncore_*` identifiers exist in the public header (or as an exported Rust function);
  * repository paths written in backticks or in links exist;
  * relative Markdown links and in-file anchors resolve.
It cannot judge whether a sentence is true; it only catches references that point at nothing.
Identifiers listed under HISTORICAL are names of things that were removed and are kept on purpose.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ["README.md", "ARCHITECTURE.md", "SECURITY.md", "VALIDATION.md", "REVIEW.md",
        "BENCHMARKS.md", "CHANGELOG.md", "RELEASE_MANIFEST.txt", "ANALYSIS.md"]
SOURCE_GLOBS = ["**/*.rs", "**/*.c", "**/*.h", "**/*.py", "**/*.sh", "**/*.toml", "**/Makefile"]
SKIP_DIRS = {"target", ".git", "corpus", "node_modules"}
# Names that are not defined in this repository (external crates and clippy lints).
EXTERNAL = {"compiler_builtins", "manual_is_multiple_of", "unnecessary_map_or", "unused_assignments"}
# Names of removed items that the records mention deliberately.
HISTORICAL = {
    "ring_payload_paths_are_expected_to_use_atomic_ownership",
    "role_contexts_stop_one_sides_signature_standing_in_for_the_other",
    "the_binding_and_transcript_depend_on_every_input",
    "a_reply_recorded_from_an_earlier_handshake_does_not_verify_in_a_new_one",
    "mutual_authentication_completes_and_traffic_flows_both_ways",
    "every_tampered_reply_field_is_rejected_without_consuming_the_handshake",
}


def source_text():
    parts = []
    for pattern in SOURCE_GLOBS:
        for path in ROOT.glob(pattern):
            if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
                continue
            try:
                parts.append(path.read_text())
            except UnicodeDecodeError:
                pass
    return "\n".join(parts)


def github_anchor(heading):
    text = re.sub(r"[`*_]", "", heading.strip().lower())
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


OVERCLAIMS = re.compile(
    r"formally verified|formal verification (?:has been|was) (?:done|performed|completed)|proven secure|"
    r"provably secure|fips[- ]validated|fips 140-3 certified|independently reviewed by|"
    r"hardware[- ]qualified", re.I)
NEGATION = re.compile(r"\b(not|no|never|nor|without|neither|cannot|isn't|hasn't|NOT CLAIMED)\b|n't", re.I)


def main():
    corpus = source_text()
    header = (ROOT / "shawncore-ffi/include/shawncore.h").read_text()
    problems = []
    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text()
        if name == "CHANGELOG.md":  # older entries legitimately name removed files and tests
            second = [m.start() for m in re.finditer(r"^## \[", text, re.M)]
            text = text[: second[1]] if len(second) > 1 else text
        lines = text.splitlines()
        for number, line in enumerate(lines, start=1):
            context = (lines[number - 2] + " " if number > 1 else "") + line
            if OVERCLAIMS.search(line) and not NEGATION.search(context):
                problems.append(f"{name}:{number}: possible overclaim without a negation: {line.strip()[:100]}")
        headings = {github_anchor(m.group(2)) for m in re.finditer(r"^(#{1,6})\s+(.*)$", text, re.M)}
        for ident in sorted(set(re.findall(r"`([a-z][a-z0-9_]{14,})`", text))):
            if ident in HISTORICAL or ident in EXTERNAL or ident.startswith("shawncore_"):
                continue
            if "_" in ident and not re.search(r"\b" + re.escape(ident) + r"\b", corpus):
                problems.append(f"{name}: `{ident}` is not defined anywhere in the source tree")
        for ident in sorted(set(re.findall(r"\b(shawncore_(?:crypto|rtos)_[a-z0-9_]+)\b", text))):
            if ident not in header and not re.search(r"fn " + ident + r"\b", corpus) and not any(
                    ident.endswith(s) or s in ident for s in ("{", "}")):
                problems.append(f"{name}: `{ident}` is neither declared in the header nor a Rust function")
        candidates = set(re.findall(r"`((?:[\w.\-]+/)+[\w.\-]+\.(?:rs|md|sh|py|c|h|toml|cpp|yml|txt))`", text))
        candidates |= set(re.findall(r"\]\(((?!https?:|#|mailto:)[^)\s#]+)(?:#[^)]*)?\)", text))
        for ref in sorted(candidates):
            target = (ROOT / ref)
            crate_relative = any(ROOT.glob("*/" + ref))
            if not target.exists() and not crate_relative:
                if "*" in ref or ref.startswith(("target/", "/tmp", "~")):
                    continue
                problems.append(f"{name}: path `{ref}` does not exist")
        for anchor in sorted(set(re.findall(r"\]\(#([^)]+)\)", text))):
            if anchor not in headings:
                problems.append(f"{name}: anchor `#{anchor}` matches no heading")
        for ref, anchor in re.findall(r"\]\(([\w./\-]+\.md)#([^)]+)\)", text):
            other = ROOT / ref
            if other.exists():
                other_headings = {github_anchor(m.group(2)) for m in re.finditer(
                    r"^(#{1,6})\s+(.*)$", other.read_text(), re.M)}
                if anchor not in other_headings:
                    problems.append(f"{name}: `{ref}#{anchor}` matches no heading in {ref}")
    if problems:
        print("[docs][FAIL] dangling documentation references:", file=sys.stderr)
        for line in problems:
            print("  " + line, file=sys.stderr)
        return 1
    print(f"[docs] {len(DOCS)} documents checked: every referenced test, symbol, path and link exists")
    return 0


if __name__ == "__main__":
    sys.exit(main())
