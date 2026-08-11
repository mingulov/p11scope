//! Per-object identity for manifest-reuse decisions. A manifest may only be
//! reused against a file whose identity matches (Gate G1: reuse refused on
//! build-ID mismatch). GNU build-ID is authoritative; whole-file SHA-256 is
//! the fallback; a file we cannot read gets an explicit not-reusable state.

use object::Object as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    GnuBuildId,
    Sha256,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub kind: IdentityKind,
    /// Hex digest; `None` only when `kind == Unavailable`.
    pub value: Option<String>,
    /// Whether a manifest may be reused against a file with this identity.
    pub reusable: bool,
    pub note: Option<String>,
}

pub fn identify(path: &Path) -> ObjectIdentity {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            return ObjectIdentity {
                kind: IdentityKind::Unavailable,
                value: None,
                reusable: false,
                note: Some(format!("read failed: {e}")),
            };
        }
    };
    let mut note = None;
    // object reads the build-id from PT_NOTE program headers too, so a
    // stripped section table does not lose it (review finding, 2026-08-11).
    match object::File::parse(&*data) {
        Ok(f) => match f.build_id() {
            Ok(Some(id)) => {
                return ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some(hex(id)),
                    reusable: true,
                    note: None,
                };
            }
            Ok(None) => {}
            Err(e) => note = Some(format!("build-id read failed: {e}")),
        },
        Err(e) => note = Some(format!("not parseable as an object file: {e}")),
    }
    let digest = Sha256::digest(&data);
    ObjectIdentity {
        kind: IdentityKind::Sha256,
        value: Some(hex(&digest)),
        reusable: true,
        note,
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
