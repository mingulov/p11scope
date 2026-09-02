//! Probe-manifest schema v5 — the contract between `p11scope-discover`
//! (writer) and `p11scope` (reader). Offsets are ELF object-file byte
//! offsets; see docs/notes/aya-offset-semantics.md.

#[cfg(feature = "identify")]
pub mod elf;
pub mod identity;
pub mod manifest;
#[cfg(feature = "identify")]
pub mod maps;

pub use identity::{IdentityKind, ObjectIdentity};
pub use manifest::*;
