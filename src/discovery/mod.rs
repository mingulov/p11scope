//! SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery: how the observer learns which objects/offsets to probe and pins their
//! identity. Slice 1a: manifest input only (`identity`). Slice 1b adds scan/live/pause.
pub mod attribution;
pub mod engine;
pub mod hooks;
pub mod identity;
pub(crate) mod loader;
pub(crate) mod pause;
pub mod scan;
pub(crate) mod scheduler;
