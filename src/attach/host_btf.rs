//! SPDX-License-Identifier: GPL-3.0-or-later
//! Process-wide cache of the parsed host vmlinux BTF plus the pidfd-iterator
//! selector probe derived from it.
//!
//! `aya::Btf::from_sys_fs` re-reads and re-parses the ~7MB
//! `/sys/kernel/btf/vmlinux` blob on every call (tens of milliseconds),
//! which alone can exhaust a 25ms native-query job budget when paid per
//! query; the `bpf_iter_attach_task` name lookup is a second linear scan.
//! The running kernel's vmlinux BTF is immutable, so one process-wide
//! parse serves every native query. The existing Inventory and Session
//! preparations already require BTF and now populate this cache, so the
//! parse and lookup complete before any budgeted job tick; per-tick
//! queries borrow the cached facts without cloning or re-scanning.
//! Absence/parse failure is cached as an error and every consumer fails
//! closed exactly as before; a load failure is never coerced into a
//! `false` selector (a successful parse with an absent selector keeps the
//! current bounded fallback). Forked children never touch this cache
//! before exec: the pre-exec path stays syscall-only, and the cache is
//! initialized only in observer preparation.
//!
//! Hermeticity: no test substitutes host BTF (aya hardcodes the sysfs
//! path), so the cache cannot shadow a fixture. Cache tests drive local
//! cells with injected loaders and never touch the production cell.

use std::sync::OnceLock;

/// Selector probe shared by the baseline and bootstrap iterators.
const PIDFD_SELECTOR_TYPE: &str = "bpf_iter_attach_task";

/// The cached host BTF facts: the shared parse plus the derived selector probe.
#[derive(Debug)]
pub(crate) struct HostBtf {
    btf: aya::Btf,
    pidfd_selector: bool,
}

impl HostBtf {
    pub(crate) fn btf(&self) -> &aya::Btf {
        &self.btf
    }

    pub(crate) fn supports_pidfd_iter_selector(&self) -> bool {
        self.pidfd_selector
    }
}

/// Owned snapshot of the `aya::BtfError` captured at load time. It preserves
/// the original Display/Debug renderings exactly, so the cached refusal reads
/// identically to the uncached one.
#[derive(Clone)]
pub(crate) struct CachedError {
    display: String,
    debug: String,
}

impl CachedError {
    fn capture(error: aya::BtfError) -> Self {
        Self {
            display: error.to_string(),
            debug: format!("{error:?}"),
        }
    }
}

impl std::fmt::Display for CachedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display)
    }
}

impl std::fmt::Debug for CachedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.debug)
    }
}

impl std::error::Error for CachedError {}

static HOST_BTF: OnceLock<Result<HostBtf, CachedError>> = OnceLock::new();

fn load(
    load_btf: impl FnOnce() -> Result<aya::Btf, aya::BtfError>,
) -> Result<HostBtf, CachedError> {
    let btf = load_btf().map_err(CachedError::capture)?;
    let pidfd_selector = btf
        .id_by_type_name_kind(PIDFD_SELECTOR_TYPE, aya_obj::btf::BtfKind::Func)
        .is_ok();
    Ok(HostBtf {
        btf,
        pidfd_selector,
    })
}

fn cached(
    cell: &OnceLock<Result<HostBtf, CachedError>>,
    load_btf: impl FnOnce() -> Result<aya::Btf, aya::BtfError>,
) -> Result<&HostBtf, CachedError> {
    cell.get_or_init(|| load(load_btf))
        .as_ref()
        .map_err(|error| error.clone())
}

/// The process-wide host BTF facts, parsed and probed once. Jobs borrow the
/// result: no per-query clone of the parse and no repeated name lookup.
pub(crate) fn shared() -> Result<&'static HostBtf, CachedError> {
    cached(&HOST_BTF, aya::Btf::from_sys_fs)
}
