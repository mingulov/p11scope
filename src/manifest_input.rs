//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Manifest input hygiene: bounded read of `p11scope-manifest/5`
//! documents. Trusted operator input, validated before use.
//! Structural validation lives in `p11scope_manifest::validate` and is
//! re-exported here, so writer and reader check identical predicates.

use p11scope_manifest::identity::open_regular;
use p11scope_manifest::manifest::*;
use std::io::Read as _;
use std::path::Path;

pub use p11scope_manifest::validate::{GETTER_NAMES, MAX_MANIFEST_BYTES, validate_structure};
pub(crate) use p11scope_manifest::validate::{
    MAX_OBJECTS, effective_surface_walk, selection_surface_usable,
    selection_table_inventory_incomplete, selection_table_name_authorized,
    surface_function_inventory_complete,
};

pub const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

/// Reads one regular, bounded UTF-8 manifest. The descriptor is opened before
/// metadata and content are inspected, so replacing its pathname cannot mix
/// two files in one parse.
pub fn read_manifest(path: &Path) -> Result<String, String> {
    let file = open_regular(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    let bytes = read_bounded(file, metadata.len())?;
    String::from_utf8(bytes).map_err(|error| format!("manifest is not UTF-8: {error}"))
}

/// Reads a manifest whose `fstat` size was `expected_len`, bounded by
/// [`MAX_MANIFEST_BYTES`]. A read that returns any other length means the
/// file was truncated or extended between the `fstat` and the read: it is
/// refused, so a truncation that happens to be valid JSON is never parsed
/// as a shorter manifest (J-manifest_input#1). A same-length rewrite is not
/// detected: the manifest is trusted operator input, and the provider
/// identities it names are still checked against the pinned objects.
pub(crate) fn read_bounded(
    reader: impl std::io::Read,
    expected_len: u64,
) -> Result<Vec<u8>, String> {
    if expected_len > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest is {expected_len} bytes; limit is {MAX_MANIFEST_BYTES}"
        ));
    }
    let mut bytes = Vec::with_capacity(expected_len as usize);
    reader
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read failed: {error}"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest grew beyond the {MAX_MANIFEST_BYTES}-byte limit"
        ));
    }
    if bytes.len() as u64 != expected_len {
        return Err(format!(
            "manifest changed while reading: read {} bytes, its size was {expected_len}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// A manifest that locates getters and claims no walked function: every
/// table it can lead to is read live, from the getter's return.
pub fn is_getter_only(m: &Manifest) -> bool {
    !m.getters.is_empty()
        && m.surfaces
            .iter()
            .all(|surface| surface.functions.is_empty())
        && m.selection_evidence.tables.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// J-manifest_input#1: a manifest truncated (or extended) between the
    /// `fstat` and the read is refused, never parsed as a shorter document.
    #[test]
    fn a_manifest_that_changed_size_while_reading_is_refused() {
        let document = br#"{"schema":"p11scope-manifest/5"}"#;
        assert_eq!(
            read_bounded(&document[..], document.len() as u64).unwrap(),
            document
        );
        for (name, reader, expected) in [
            ("shrunk", &document[..10], document.len() as u64),
            ("grown", &document[..], 10),
        ] {
            let error = read_bounded(reader, expected)
                .expect_err(&format!("a {name} manifest must be refused"));
            assert!(error.contains("changed while reading"), "{name}: {error}");
        }
    }

    #[test]
    fn a_manifest_over_the_limit_is_refused_before_reading() {
        let error = read_bounded(std::io::empty(), MAX_MANIFEST_BYTES + 1).unwrap_err();
        assert!(error.contains("limit is"), "{error}");
    }
}
