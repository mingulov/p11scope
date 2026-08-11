//! p11scope-discover library — split from the bin so tests call discovery
//! directly. Runs vendor code via dlopen; that is why the helper is a
//! separate unprivileged short-lived process (design spec, Architecture).

pub mod identity;
pub mod maps;
