//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! The identify budget charges each distinct object once: a provider
//! larger than a twenty-fifth of the cap still discovers, because its
//! re-reads stream without a second debit.

use p11scope_discover::discover::discover;
use std::path::PathBuf;
use std::process::Command;

/// A selection-capable provider padded past MAX/25 with a sparse
/// section: under per-read charging its ~25 full re-hashes would
/// exhaust the 512 MiB allowance and refuse the discovery.
fn padded_provider(dir: &std::path::Path) -> PathBuf {
    let source = dir.join("padded-provider.c");
    let plain = dir.join("padded-provider.so");
    let padded = dir.join("padded-provider-padded.so");
    let sparse = dir.join("pad.bin");
    std::fs::write(
        &source,
        "typedef unsigned long CK_RV;\n\
         typedef unsigned long CK_FLAGS;\n\
         CK_RV C_GetInterface(void *name, void *version, void **output, CK_FLAGS flags) {\n\
             (void)name; (void)version; (void)flags;\n\
             *output = (void *)0x12345;\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    assert!(
        Command::new("gcc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&plain)
            .arg(&source)
            .status()
            .unwrap()
            .success(),
        "the padded fixture must compile"
    );
    let pad_len = 22 * 1024 * 1024;
    let pad = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&sparse)
        .unwrap();
    pad.set_len(pad_len).unwrap();
    drop(pad);
    assert!(
        Command::new("objcopy")
            .arg("--add-section")
            .arg(format!(".p11scope_pad={}", sparse.display()))
            .arg(&plain)
            .arg(&padded)
            .status()
            .unwrap()
            .success(),
        "objcopy must pad the fixture"
    );
    padded
}

#[test]
fn provider_past_a_twenty_fifth_of_the_cap_still_discovers() {
    let dir = std::env::temp_dir().join(format!("identify-budget-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let provider = padded_provider(&dir);
    let len = std::fs::metadata(&provider).unwrap().len();
    // Non-vacuous precondition: past the point where per-read charging
    // over ~25 re-hashes would exhaust the allowance.
    assert!(
        len * 25 > 512 * 1024 * 1024,
        "the fixture must exceed MAX/25: {len} bytes"
    );
    let manifest = discover(&provider).expect("a large provider must discover");
    assert!(
        p11scope_manifest::validate::validate_structure(&manifest).is_empty(),
        "the large discovery stays structurally valid"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
