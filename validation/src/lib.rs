#![no_std]
#![allow(dead_code)]
//! Host-side validation harness for ShawnCore.
//!
//! Executable validation lives under `tests/`. This library target exists so Cargo
//! treats `validation` as a normal workspace package. It is deliberately `no_std`
//! so the workspace-wide `aarch64-unknown-none` compile check covers it.
