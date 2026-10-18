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
//! path), so the cache cannot shadow a fixture. The tests below drive
//! local cells with injected loaders and never touch the production cell.

use std::error::Error as _;
use std::sync::{Arc, OnceLock};

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

/// Owned snapshot of the `aya::BtfError` captured at load time. It shares the
/// original error, so Display/Debug renderings and the `source()` chain below
/// the BTF level (e.g. the `io::Error` under `FileError`) read exactly as the
/// uncached refusal: `{error:#}` chains and errno traversal are unchanged.
/// The snapshot is its own type: `downcast_ref::<aya::BtfError>()` does not
/// resolve through it.
#[derive(Clone)]
pub(crate) struct CachedError {
    inner: Arc<aya::BtfError>,
}

impl CachedError {
    fn capture(error: aya::BtfError) -> Self {
        Self {
            inner: Arc::new(error),
        }
    }
}

impl std::fmt::Display for CachedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl std::fmt::Debug for CachedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.inner, f)
    }
}

impl std::error::Error for CachedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Minimal byte-built BTF blob: INT id 1 plus, when asked, the FUNC id 2
    /// the selector probe looks for. Pure synthetic bytes; no sysfs read.
    fn fixture_blob(with_selector: bool) -> Vec<u8> {
        fn intern(strings: &mut Vec<u8>, text: &str) -> u32 {
            let offset = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            offset
        }
        fn header(types: &mut Vec<u8>, name_off: u32, kind: u32, vlen: u32, size_or_type: u32) {
            types.extend_from_slice(&name_off.to_le_bytes());
            types.extend_from_slice(&((kind << 24) | vlen).to_le_bytes());
            types.extend_from_slice(&size_or_type.to_le_bytes());
        }
        let mut types = Vec::new();
        let mut strings = vec![0u8];
        header(&mut types, intern(&mut strings, "unsigned int"), 1, 0, 4);
        types.extend_from_slice(&0x0100_0020u32.to_le_bytes());
        if with_selector {
            header(
                &mut types,
                intern(&mut strings, PIDFD_SELECTOR_TYPE),
                12,
                0,
                1,
            );
        }
        let mut out = Vec::new();
        out.extend_from_slice(&0xE_B9Fu16.to_le_bytes());
        out.extend_from_slice(&[0x01, 0x00]);
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    fn parse_fixture(with_selector: bool) -> Result<aya::Btf, aya::BtfError> {
        aya::Btf::parse(&fixture_blob(with_selector), aya::Endianness::default())
    }

    #[test]
    fn local_cell_parses_success_once_and_shares_one_allocation() {
        let cell = OnceLock::new();
        let calls = AtomicUsize::new(0);
        let loader = || {
            calls.fetch_add(1, Ordering::SeqCst);
            parse_fixture(true)
        };
        let first = cached(&cell, loader).expect("byte fixture parses");
        assert!(first.supports_pidfd_iter_selector());
        assert!(
            first
                .btf()
                .id_by_type_name_kind(PIDFD_SELECTOR_TYPE, aya_obj::btf::BtfKind::Func)
                .is_ok()
        );
        let loader = || {
            calls.fetch_add(1, Ordering::SeqCst);
            parse_fixture(true)
        };
        let second = cached(&cell, loader).expect("cached facts repeat");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one parse per cell");
        assert!(std::ptr::eq(first, second), "one shared allocation");
    }

    #[test]
    fn local_cell_reports_absent_selector_without_failing() {
        let fresh = parse_fixture(false).expect("byte fixture parses");
        assert!(
            fresh
                .id_by_type_name_kind(PIDFD_SELECTOR_TYPE, aya_obj::btf::BtfKind::Func)
                .is_err()
        );
        let cell = OnceLock::new();
        let host = cached(&cell, || parse_fixture(false)).expect("parse succeeds");
        assert!(!host.supports_pidfd_iter_selector());
    }

    #[test]
    fn local_cell_caches_absence_and_never_reloads() {
        fn missing() -> Result<aya::Btf, aya::BtfError> {
            aya::Btf::parse_file("/nonexistent-p11scope-host-btf", aya::Endianness::default())
        }
        missing().expect_err("the absence loader must fail");
        let cell = OnceLock::new();
        let calls = AtomicUsize::new(0);
        let loader = || {
            calls.fetch_add(1, Ordering::SeqCst);
            missing()
        };
        let first = match cached(&cell, loader) {
            Err(error) => error,
            Ok(_) => panic!("absence must fail closed"),
        };
        let loader = || {
            calls.fetch_add(1, Ordering::SeqCst);
            missing()
        };
        let second = match cached(&cell, loader) {
            Err(error) => error,
            Ok(_) => panic!("absence must fail closed"),
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one load per cell");
        assert_eq!(first.to_string(), second.to_string());
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        let raw = missing().expect_err("the absence loader must fail");
        assert_eq!(first.to_string(), raw.to_string());
        assert_eq!(format!("{first:?}"), format!("{raw:?}"));
    }

    #[test]
    fn local_cell_caches_malformed_and_never_reloads() {
        fn malformed() -> Result<aya::Btf, aya::BtfError> {
            aya::Btf::parse(&[0x7Fu8; 64], aya::Endianness::default())
        }
        malformed().expect_err("the malformed loader must fail");
        let cell = OnceLock::new();
        let calls = AtomicUsize::new(0);
        let loader = || {
            calls.fetch_add(1, Ordering::SeqCst);
            malformed()
        };
        let first = match cached(&cell, loader) {
            Err(error) => error,
            Ok(_) => panic!("malformed input must fail closed"),
        };
        let loader = || {
            calls.fetch_add(1, Ordering::SeqCst);
            malformed()
        };
        let second = match cached(&cell, loader) {
            Err(error) => error,
            Ok(_) => panic!("malformed input must fail closed"),
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one load per cell");
        assert_eq!(first.to_string(), second.to_string());
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        let raw = malformed().expect_err("the malformed loader must fail");
        assert_eq!(first.to_string(), raw.to_string());
        assert_eq!(format!("{first:?}"), format!("{raw:?}"));
    }

    #[test]
    fn cached_error_preserves_chain_rendering_and_errno() {
        fn missing() -> Result<aya::Btf, aya::BtfError> {
            aya::Btf::parse_file("/nonexistent-p11scope-host-btf", aya::Endianness::default())
        }
        let raw = missing().expect_err("the absence loader must fail");
        assert!(raw.source().is_some(), "the fixture must carry a source");
        let cell = OnceLock::new();
        let snapshot = match cached(&cell, missing) {
            Err(error) => error,
            Ok(_) => panic!("absence must fail closed"),
        };
        // The contextual alternate rendering matches the uncached chain exactly.
        let uncached = anyhow::Error::new(raw).context("loading required vmlinux BTF");
        let cached = anyhow::Error::new(snapshot).context("loading required vmlinux BTF");
        assert_eq!(format!("{cached:#}"), format!("{uncached:#}"));
        let uncached_chain: Vec<String> = uncached.chain().map(ToString::to_string).collect();
        let cached_chain: Vec<String> = cached.chain().map(ToString::to_string).collect();
        assert_eq!(cached_chain, uncached_chain);
        assert!(
            cached_chain.len() > 2,
            "the chain must keep its source level"
        );
        // Errno traversal (the doctor `raw_errno` shape) reaches the same
        // `io::Error` on both paths.
        fn raw_errno(mut error: &(dyn std::error::Error + 'static)) -> Option<i32> {
            loop {
                if let Some(error) = error.downcast_ref::<std::io::Error>()
                    && error.raw_os_error().is_some()
                {
                    return error.raw_os_error();
                }
                error = error.source()?;
            }
        }
        fn io_kind(mut error: &(dyn std::error::Error + 'static)) -> Option<std::io::ErrorKind> {
            loop {
                if let Some(error) = error.downcast_ref::<std::io::Error>() {
                    return Some(error.kind());
                }
                error = error.source()?;
            }
        }
        let uncached_head = uncached.chain().next().expect("chain is nonempty");
        let cached_head = cached.chain().next().expect("chain is nonempty");
        assert_eq!(raw_errno(cached_head), raw_errno(uncached_head));
        assert_eq!(io_kind(cached_head), Some(std::io::ErrorKind::NotFound));
        assert_eq!(io_kind(uncached_head), Some(std::io::ErrorKind::NotFound));
    }

    #[test]
    fn concurrent_first_access_parses_once_and_shares_one_allocation() {
        use std::sync::Barrier;
        const WORKERS: usize = 8;
        let cell = OnceLock::new();
        let calls = AtomicUsize::new(0);
        let barrier = Barrier::new(WORKERS);
        std::thread::scope(|scope| {
            let mut workers = Vec::with_capacity(WORKERS);
            for _ in 0..WORKERS {
                workers.push(scope.spawn(|| {
                    barrier.wait();
                    let host = cached(&cell, || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        parse_fixture(true)
                    })
                    .expect("byte fixture parses");
                    assert!(host.supports_pidfd_iter_selector());
                    std::ptr::from_ref(host) as usize
                }));
            }
            let mut addresses = Vec::with_capacity(WORKERS);
            for worker in workers {
                addresses.push(worker.join().expect("worker panicked"));
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1, "one parse per cell");
            assert!(
                addresses.iter().all(|address| *address == addresses[0]),
                "one shared allocation"
            );
        });
    }
}
