//! p11scope-discover library — split from the bin so tests call discovery
//! directly. Runs vendor code via dlopen; that is why the helper is a
//! separate unprivileged short-lived process.

pub mod discover;
pub mod maps;

pub use p11scope_manifest::{identity, manifest};
