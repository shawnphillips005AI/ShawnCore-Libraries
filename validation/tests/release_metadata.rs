// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Guards against version drift between the crates, the C header, and the release records.

use std::fs;
use std::path::PathBuf;

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn header_define(header: &str, name: &str) -> String {
    header
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next() == Some("#define") && parts.next() == Some(name)).then(|| {
                parts
                    .next()
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_owned()
            })
        })
        .unwrap_or_else(|| panic!("{name} is not defined in shawncore.h"))
}

#[test]
fn c_header_version_matches_the_crate_version() {
    let header = repo_file("shawncore-ffi/include/shawncore.h");
    let version = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "crate version must be MAJOR.MINOR.PATCH");

    assert_eq!(header_define(&header, "SHAWNCORE_VERSION_MAJOR"), parts[0]);
    assert_eq!(header_define(&header, "SHAWNCORE_VERSION_MINOR"), parts[1]);
    assert_eq!(header_define(&header, "SHAWNCORE_VERSION_PATCH"), parts[2]);
    assert_eq!(header_define(&header, "SHAWNCORE_VERSION_STRING"), version);
}

#[test]
fn release_records_name_the_current_version() {
    let version = env!("CARGO_PKG_VERSION");

    let manifest = repo_file("RELEASE_MANIFEST.txt");
    assert!(
        manifest
            .lines()
            .any(|l| l.trim() == format!("Release: {version}")),
        "RELEASE_MANIFEST.txt must say `Release: {version}`"
    );

    let changelog = repo_file("CHANGELOG.md");
    let newest = changelog
        .lines()
        .find(|l| l.starts_with("## ["))
        .expect("CHANGELOG.md has no release heading");
    assert!(
        newest.starts_with(&format!("## [{version}]")),
        "newest CHANGELOG heading `{newest}` must be for {version}"
    );
}
