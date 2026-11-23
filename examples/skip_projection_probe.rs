//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Test fixture: project internal discovery skips through the REAL
//! `capture_skipped_out` and print the public rows as JSON.
//!
//! The Python qualification twins (`test_public_cli_oracle.py`,
//! `test_public_cli_breadth.py`) drive this binary so they judge the
//! producer's output, never source text: a re-pointed, removed, or
//! unreachable projection arm changes the bytes here and fails there.
//!
//! Stdin is a JSON array of `{"subject": ..., "reason": ...}` internal
//! pairs; stdout is a JSON array of `{"name": ..., "reason": ...}`
//! public rows in the same order. Usage/parse errors exit 2.

use p11scope::discovery::scan::Skipped;
use p11scope::render::capture_skipped_out;

#[derive(serde::Deserialize)]
struct InternalPair {
    subject: String,
    reason: String,
}

fn main() {
    let outcome = run();
    if let Err(detail) = outcome {
        eprintln!("skip_projection_probe: {detail}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    use std::io::Read as _;
    let mut stdin = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|error| format!("cannot read stdin: {error}"))?;
    let pairs: Vec<InternalPair> = serde_json::from_str(&stdin)
        .map_err(|error| format!("stdin is not a JSON pair array: {error}"))?;
    let rows: Vec<_> = pairs
        .iter()
        .map(|pair| {
            capture_skipped_out(&Skipped {
                subject: pair.subject.clone(),
                reason: pair.reason.clone(),
            })
        })
        .collect();
    let text =
        serde_json::to_string(&rows).map_err(|error| format!("cannot render rows: {error}"))?;
    println!("{text}");
    Ok(())
}
