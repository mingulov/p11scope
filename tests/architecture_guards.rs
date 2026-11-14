//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Architecture guards (v0.8.0 P0): the allowlist-v1 byte-identity pin.
//!
//! Golden renderer snapshots land in this file after the port, mem-b2,
//! handle-table and keyrow-yield lanes land; Wave 0 carries only the sha pin.

use sha2::{Digest as _, Sha256};

/// Pinned sha256 of `docs/privacy/allowlist-v1.md` (Global Constraints).
const ALLOWLIST_V1_SHA256: &str =
    "26940546a4962008778650f66550d93e62f6228decc166fe8fba845a70b0df6e";

#[test]
fn allowlist_v1_sha256_pin() {
    let bytes =
        std::fs::read("docs/privacy/allowlist-v1.md").expect("read docs/privacy/allowlist-v1.md");
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex, ALLOWLIST_V1_SHA256,
        "docs/privacy/allowlist-v1.md changed: got {hex}, want {ALLOWLIST_V1_SHA256}"
    );
}
