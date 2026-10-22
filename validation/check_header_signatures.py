#!/usr/bin/env python3
"""Checks every C declaration in shawncore.h against the Rust `extern "C"` definition it names.

validation/check_archive.sh proves that header and archive agree on symbol *names*. This script
compares parameter count, order, scalar width, pointer constness, pointee type and return type, so
a swapped argument, a dropped `const` or a stale length type fails the release gate even for
functions the C smoke test never calls. It parses source text; it is not a compiler and it does not
check structure layout (see integration/c_api_smoke.c and validation/tests/ffi_layout_contracts.rs).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "shawncore-ffi/include/shawncore.h"
RUST_SOURCES = [
    "shawncore-pq-crypto/src/ffi.rs",
    "shawncore-pq-crypto/src/ffi_callbacks.rs",
    "shawncore-pq-crypto/src/ffi_error.rs",
    "shawncore-rtos-sync/src/ffi.rs",
    "shawncore-rtos-sync/src/ffi_callbacks.rs",
    "shawncore-rtos-sync/src/ffi_error.rs",
]

SCALARS = {
    "uint8_t": "u8", "uint16_t": "u16", "uint32_t": "u32", "uint64_t": "u64",
    "size_t": "usize", "uintptr_t": "usize",
}
RETURNS = {
    "shawncore_crypto_err": "ShawncoreCryptoErr", "shawncore_rtos_err": "ShawncoreRtosErr",
    "size_t": "usize", "uint64_t": "u64", "void": "()",
}
# C types with no sizeof function of their own.
EXTRA_OPAQUE = {"shawncore_rtos_ew_command": "EwCommand"}


def strip_c(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def c_declarations(text):
    text = strip_c(text)
    text = re.sub(r"typedef\s+struct[^{;]*\{[^}]*\}\s*\w+\s*;", "", text)
    text = re.sub(r"typedef[^;{]*;", "", text)
    text = re.sub(r'extern\s+"C"\s*\{', "", text)
    pattern = re.compile(r"([A-Za-z_][\w\s\*]*?)\s*\b(shawncore_(?:crypto|rtos)_\w+)\s*\(([^;{}]*?)\)\s*;")
    return [(m.group(2), m.group(1).strip(), m.group(3).strip()) for m in pattern.finditer(text)]


def c_callback_types(text):
    """`typedef R (*name)(args);` -> {name: canonical signature}."""
    out = {}
    for m in re.finditer(r"typedef\s+([\w\s\*]+?)\s*\(\s*\*\s*(\w+)\s*\)\s*\(([^)]*)\)\s*;", strip_c(text)):
        ret = SCALARS.get(m.group(1).strip(), m.group(1).strip())
        args = [canonical_c_scalar_or_ptr(p) for p in split_params(m.group(3))]
        out[m.group(2)] = (ret if ret != "void" else "()", tuple(args))
    return out


def canonical_c_scalar_or_ptr(text):
    kind = c_param(text)
    if kind[0] == "scalar":
        return SCALARS.get(kind[1], kind[1])
    return ("*const" if kind[2] else "*mut") + SCALARS.get(kind[3], kind[3])


def rust_callback_types(text):
    """`type X = extern "C" fn(args) -> R;` -> {X: canonical signature}."""
    out = {}
    for m in re.finditer(r'pub\s+type\s+(\w+)\s*=\s*extern\s+"C"\s+fn\s*\(([^)]*)\)\s*(?:->\s*([^;]+))?;', text):
        args = tuple(p.replace(" ", "") for p in split_params(m.group(2)))
        out[m.group(1)] = ((m.group(3) or "()").strip(), args)
    return out


def c_param(text):
    text = re.sub(r"SHAWNCORE_MIN_LEN\(\d+\)", "", text).strip()
    if text.startswith("shawncore_") and text.count("(") == 0 and "*" not in text and " " not in text:
        return ("scalar", text)
    is_array = "[" in text
    text = re.sub(r"\[[^\]]*\]", "", text)
    const = bool(re.search(r"\bconst\b", text))
    stars = text.count("*") + (1 if is_array else 0)
    words = [w for w in re.split(r"[\s\*]+", text.replace("const", " ")) if w]
    base = words[0]
    if stars == 0:
        return ("scalar", SCALARS.get(base, base))
    return ("ptr", stars, const, base)


def split_params(text):
    text = text.strip()
    if text in ("", "void"):
        return []
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def rust_functions(text):
    out = {}
    pattern = re.compile(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([^{]+?))?\s*\{', re.S)
    for m in pattern.finditer(text):
        params = []
        for part in split_params(m.group(2)):
            name, _, ty = part.partition(":")
            params.append(ty.strip())
        out[m.group(1)] = (params, (m.group(3) or "()").strip())
    return out


def rust_macro_functions(text, opaque):
    out = {}
    for m in re.finditer(r"(?:opaque_type_layout|ffi_type_layout)!\(\s*([^,]+?)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)", text):
        out[m.group(2)] = ([], "usize")
        out[m.group(3)] = ([], "usize")
        opaque[m.group(2).removesuffix("_sizeof")] = m.group(1).strip()
    for m in re.finditer(
        r"wire_codec!\(\s*(\w+)\s*,\s*[\w:]+\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,", text
    ):
        ty, len_fn, to_fn, from_fn = m.groups()
        out[len_fn] = ([], "usize")
        out[to_fn] = ([f"*const {ty}", "*mut u8", "usize"], "ShawncoreCryptoErr")
        out[from_fn] = (["*const u8", "usize", f"*mut {ty}"], "ShawncoreCryptoErr")
    for m in re.finditer(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)_sizeof\(\)[^{]*\{\s*core::mem::size_of::<([^>]+(?:<[^>]*>)?)>\(\)', text):
        opaque[m.group(1)] = m.group(2).strip()
    return out


def rust_param(ty):
    ty = ty.replace(" ", "")
    if ty.startswith("Option<"):
        return ("callback",)
    m = re.match(r"(\*const|\*mut)(.+)", ty)
    if m:
        inner = m.group(2)
        stars = 1
        while inner.startswith(("*const", "*mut")):
            inner = inner.removeprefix("*const").removeprefix("*mut")
            stars += 1
        return ("ptr", stars, m.group(1) == "*const", inner)
    return ("scalar", ty)


def main():
    functions, opaque, rust_callbacks = {}, {}, {}
    for relative in RUST_SOURCES:
        text = (ROOT / relative).read_text()
        functions.update(rust_functions(text))
        functions.update(rust_macro_functions(text, opaque))
        rust_callbacks.update({(relative, k): v for k, v in rust_callback_types(text).items()})
    header_text = HEADER.read_text()
    c_callbacks = c_callback_types(header_text)
    opaque.update(EXTRA_OPAQUE)

    declarations = c_declarations(header_text)
    failures, checked = [], 0
    for name, ret, params in declarations:
        if name not in functions:
            failures.append(f"{name}: declared in the header, no Rust extern \"C\" definition found")
            continue
        rust_params, rust_ret = functions[name]
        c_params = split_params(params)
        if len(c_params) != len(rust_params):
            failures.append(f"{name}: {len(c_params)} C parameters, {len(rust_params)} Rust parameters")
            continue
        if RETURNS.get(ret.split()[-1], ret) != rust_ret.replace(" ", ""):
            failures.append(f"{name}: C returns `{ret}`, Rust returns `{rust_ret}`")
        for index, (c_text, r_text) in enumerate(zip(c_params, rust_params)):
            c_type = c_text.split()[0] if c_text.split() else ""
            if c_type in c_callbacks:
                inner = re.match(r"Option<(\w+)>", r_text.replace(" ", ""))
                candidates = [v for (_, k), v in rust_callbacks.items() if inner and k == inner.group(1)]
                if not inner or not candidates:
                    failures.append(f"{name}: parameter {index} is a callback in C but `{r_text}` in Rust")
                elif c_callbacks[c_type] not in candidates:
                    failures.append(
                        f"{name}: callback `{c_type}` is {c_callbacks[c_type]} in C but {candidates} in Rust")
                continue
            c, r = c_param(c_text), rust_param(r_text)
            if c[0] == "scalar" and r[0] == "scalar":
                if SCALARS.get(c[1], c[1]) != r[1]:
                    failures.append(f"{name}: parameter {index} C `{c_text}` vs Rust `{r_text}`")
            elif c[0] == "ptr" and r[0] == "ptr":
                _, c_stars, c_const, c_base = c
                _, r_stars, r_const, r_base = r
                if c_stars != r_stars or c_const != r_const:
                    failures.append(f"{name}: parameter {index} pointer shape/constness: C `{c_text}` vs Rust `{r_text}`")
                    continue
                if c_base == "void":
                    continue
                expected = SCALARS.get(c_base) or opaque.get(c_base)
                if expected is None:
                    failures.append(f"{name}: parameter {index} C type `{c_base}` has no known Rust counterpart")
                elif expected.replace(" ", "") != r_base:
                    failures.append(f"{name}: parameter {index} pointee C `{c_base}` ({expected}) vs Rust `{r_base}`")
            else:
                failures.append(f"{name}: parameter {index} kind differs: C `{c_text}` vs Rust `{r_text}`")
        checked += 1

    declared = {name for name, _, _ in declarations}
    for name in sorted(set(functions) - declared):
        if name.startswith("shawncore_"):
            failures.append(f"{name}: exported by Rust but not declared in the header")

    if failures:
        print("[header-signatures][FAIL]", file=sys.stderr)
        for line in failures:
            print("  " + line, file=sys.stderr)
        sys.exit(1)
    print(f"[header-signatures] {checked} header declarations match their Rust signatures")


if __name__ == "__main__":
    main()
