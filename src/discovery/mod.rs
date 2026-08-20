//! Discovery: how the observer learns which objects/offsets to probe and pins their
//! identity. Slice 1a: manifest input only (`identity`). Slice 1b adds scan/live/pause.
pub mod hooks;
pub mod identity;
#[allow(
    dead_code,
    reason = "Task 6 checkpoint C consumes this reviewed registry"
)]
pub(crate) mod loader;
pub mod scan;
