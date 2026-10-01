//! SPDX-License-Identifier: GPL-3.0-or-later
//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes).

/// Crate-wide, non-panicking `eprintln!`/`eprint!` (HIGH-4). The Rust
/// runtime ignores SIGPIPE, so std's macros panic on EPIPE, and stderr is
/// commonly a pipe whose reader can die first (`2>&1 | tee cap.log`, then
/// Ctrl-C kills `tee`). A panic there would unwind past an unpublished
/// report (lost) and SIGKILL a `run` child instead of settling it, all for
/// a diagnostic nobody can read. These definitions come before every
/// `mod`, so their textual scope shadows std's macros throughout the
/// library; a failed diagnostic write is dropped. Test builds keep std's
/// macros so libtest still captures test output.
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr(), $($arg)*);
    }};
}

#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::write!(::std::io::stderr(), $($arg)*);
    }};
}

pub mod attach;
pub mod capacity;
pub mod cli;
pub mod discovery;
pub mod doctor;
pub mod events;
#[cfg(test)]
mod first_use_probe;
pub mod inspect;
pub mod inspect_system;
pub mod kinds;
pub mod longrun;
pub mod manifest_input;
pub mod metrics;
pub mod output;
pub mod plan;
pub mod process;
pub mod render;
pub(crate) mod run;
pub mod scope;
pub mod semantics;
pub mod shapes;
pub(crate) mod sink;
pub mod trace;
pub(crate) mod uretprobe_hazard;

/// The whole public production surface of the capture loops. `run` stays a
/// crate-private module: the owned child, the pause coordinator, its clocks,
/// maps, drains, guards and injected actions are unreachable from outside.
pub use run::{OwnedRunOutcome, capture, capture_startup_signal_dispositions, run_owned};

/// The BPF object, built by build.rs. Alignment matters: aya parses it
/// as ELF in place.
pub static EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf"));

/// Dedicated endpoint-use inventory object. It has no ordinary call event or
/// return/latency state; loader preparation is a separate capability contract.
pub static EBPF_INVENTORY_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-inventory"));

/// Caller/object Inventory producer for private caller preparation and static
/// activation. Public caller selection and query remain separate contracts.
pub static EBPF_INVENTORY_CALLERS_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-inventory-callers"));

pub(crate) mod history;
