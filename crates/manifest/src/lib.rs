//! Probe-manifest schema v4 — the contract between `p11scope-discover`
//! (writer) and `p11scope` (reader). Offsets are ELF object-file byte
//! offsets; see docs/notes/aya-offset-semantics.md.

pub mod identity;
pub mod manifest;

pub use identity::{IdentityKind, ObjectIdentity};
pub use manifest::*;
