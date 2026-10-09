//! SPDX-License-Identifier: GPL-3.0-or-later
// These charges depend on the pinned alloc implementation. A stable compiler
// bump requires semantic-budget remeasurement and source-proof revalidation.

pub const RELEASE: &str = "1.98.1";
pub const COMMIT: &str = "48a229ceaefd4985c50990b14116b6d856af0985";

pub fn validate_metadata(metadata: &str) -> Result<(), String> {
    let mut release = None;
    let mut commit = None;
    let mut host = None;
    for line in metadata.lines() {
        for (prefix, field) in [
            ("release: ", &mut release),
            ("commit-hash: ", &mut commit),
            ("host: ", &mut host),
        ] {
            if let Some(value) = line.strip_prefix(prefix)
                && (field.replace(value).is_some() || value.is_empty())
            {
                return Err("malformed or duplicate rustc metadata".into());
            }
        }
    }
    if release != Some(RELEASE) || commit != Some(COMMIT) || host.is_none() {
        return Err(format!(
            "semantic allocation charges require rustc {RELEASE} ({COMMIT}); remeasure and revalidate the semantic budget before updating its compiler guard"
        ));
    }
    Ok(())
}

#[cfg(not(test))]
pub fn emit_proof() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-changed=build_support/semantic_rustc.rs");
    let rustc = std::env::var_os("RUSTC").expect("Cargo supplies the compiling host RUSTC");
    println!(
        "cargo:rerun-if-changed={}",
        std::path::Path::new(&rustc).display()
    );
    let output = std::process::Command::new(rustc)
        .args(["--version", "--verbose"])
        .output()
        .expect("read Cargo RUSTC metadata for semantic-budget revalidation guard");
    assert!(
        output.status.success(),
        "Cargo RUSTC metadata command failed; semantic budget cannot be validated"
    );
    let metadata = std::str::from_utf8(&output.stdout).expect("Cargo RUSTC metadata must be UTF-8");
    validate_metadata(metadata).unwrap_or_else(|reason| panic!("{reason}"));
    println!("cargo:rustc-env=P11SCOPE_SEMANTIC_RUSTC_PROOF={RELEASE}/{COMMIT}");
}
