//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Glibc malloc arena cap, applied once at observer startup.
//!
//! The v0.8.0 quiet-host legs showed process RSS growing through glibc
//! allocator arena proliferation plus heap extension (+2.6 MiB/h) while
//! every counted lane structure stayed flat: 3 to 7 thread arenas over
//! 6 h, all growth in `[heap]` and new arenas. A control leg with
//! `MALLOC_ARENA_MAX=2` held the reservation flat (1 arena all run,
//! heap size fixed after hour 1, bring-up halved, residual fill
//! decelerating to ~0). The product therefore caps arenas itself at
//! startup, so long `--system` captures do not depend on the operator
//! exporting the variable.
//!
//! Why 2: the observer runs about 5 threads steady (quiet-leg
//! `/proc/status`), and allocation is per-pass bursty work done mainly
//! on one thread, not highly concurrent malloc from many threads. Two
//! arenas bound proliferation while leaving headroom against
//! single-arena lock contention; the measured control leg used exactly
//! 1 arena all run under this cap. A larger cap would only re-admit
//! proliferation; 1 would serialize every thread on one arena.
//!
//! An explicit `MALLOC_ARENA_MAX` in the environment always wins: glibc
//! reads it before `main`, so calling `mallopt` afterwards would
//! override the operator. When the variable is present (any value),
//! this module applies nothing.
//!
//! `M_TRIM_THRESHOLD` / `malloc_trim` were considered and deliberately
//! not applied: capped legs plateau without them (the residual fill
//! curve decelerates to ~0 and the remaining +-2 MB sawtooth reverses
//! in 1-2 min), so a trim would add latency at the trim point for no
//! slope gain. Revisit only if a capped leg ever shows a steady
//! post-plateau slope.
//!
//! Off glibc (musl/static builds) there are no arenas to cap; applying
//! is a no-op reported as [`AllocatorTuning::Unsupported`]. A refused
//! `mallopt` reports [`AllocatorTuning::Failed`] and the capture
//! continues: allocator tuning must never refuse an observation.
//!
//! Call [`apply_allocator_tuning`] first in `main`, before any thread
//! spawns: `mallopt` still caps future arenas when called later, but
//! only a pre-thread call guarantees the measured flat shape.

use std::ffi::OsStr;

/// Arena cap applied when the operator did not set one. See the module
/// docs for why 2.
pub const MALLOC_ARENA_CAP: i32 = 2;
/// Environment override: when present (any value), the product applies
/// no cap and glibc's own parsing of this variable stands.
pub const MALLOC_ARENA_ENV: &str = "MALLOC_ARENA_MAX";

/// Outcome of [`apply_allocator_tuning`] / [`apply_allocator_tuning_for_env`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorTuning {
    /// `mallopt(M_ARENA_MAX, arenas)` succeeded.
    Applied {
        /// The cap value passed to `mallopt`.
        arenas: i32,
    },
    /// `MALLOC_ARENA_MAX` was present in the environment; nothing applied.
    SkippedEnvVar,
    /// Not a glibc target: no arenas to cap; nothing applied.
    Unsupported,
    /// On glibc, `mallopt` refused the cap; the capture continues.
    Failed,
}

/// Pure decision: `Some(cap)` when no explicit environment value is set
/// (apply the product cap), `None` when any explicit value is present
/// (respect it, apply nothing). Separated from the `mallopt` call so
/// unit tests cover both branches without touching the global allocator.
pub fn decide_arena_cap(env: Option<&OsStr>) -> Option<i32> {
    if env.is_some() {
        None
    } else {
        Some(MALLOC_ARENA_CAP)
    }
}

/// Calls `mallopt(M_ARENA_MAX, arenas)` on glibc; reports whether the
/// call succeeded. Off glibc there are no arenas, so this always reports
/// false and the caller maps it to [`AllocatorTuning::Unsupported`].
fn set_arena_max(arenas: i32) -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: `mallopt` with `M_ARENA_MAX` only stores the cap for
        // future arena creation; it dereferences no pointer. The call is
        // process-global and thread-safe, and production calls it once at
        // startup before worker threads exist.
        unsafe { libc::mallopt(libc::M_ARENA_MAX, arenas as libc::c_int) != 0 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = arenas;
        false
    }
}

/// Whether this target can cap glibc arenas at all.
fn arenas_supported() -> bool {
    cfg!(all(target_os = "linux", target_env = "gnu"))
}

/// Maps the `mallopt` outcome to its tuning verdict: a refused call
/// reports [`AllocatorTuning::Failed`] and the capture continues.
/// Separated from the `mallopt` call so unit tests pin the fail-open
/// mapping without forcing a real allocator failure.
fn map_set_result(ok: bool, arenas: i32) -> AllocatorTuning {
    if ok {
        AllocatorTuning::Applied { arenas }
    } else {
        AllocatorTuning::Failed
    }
}

/// Applies the arena cap for an injected environment value. Production
/// calls [`apply_allocator_tuning`], which reads the real environment.
pub fn apply_allocator_tuning_for_env(env: Option<&OsStr>) -> AllocatorTuning {
    let Some(arenas) = decide_arena_cap(env) else {
        return AllocatorTuning::SkippedEnvVar;
    };
    if !arenas_supported() {
        return AllocatorTuning::Unsupported;
    }
    map_set_result(set_arena_max(arenas), arenas)
}

/// Reads `MALLOC_ARENA_MAX` and applies the product arena cap unless the
/// operator set one. Call once, first in `main`, before any thread spawns.
/// The return value is diagnostic only: every outcome lets the capture
/// continue, including [`AllocatorTuning::Failed`].
pub fn apply_allocator_tuning() -> AllocatorTuning {
    apply_allocator_tuning_for_env(std::env::var_os(MALLOC_ARENA_ENV).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_applies_cap_when_env_unset() {
        assert_eq!(decide_arena_cap(None), Some(MALLOC_ARENA_CAP));
        assert_eq!(MALLOC_ARENA_CAP, 2);
    }

    #[test]
    fn decide_skips_when_env_set_to_any_value() {
        for value in ["2", "4", "8", "1", "0", "", "auto", " 4 ", "0x10"] {
            assert_eq!(
                decide_arena_cap(Some(OsStr::new(value))),
                None,
                "explicit MALLOC_ARENA_MAX={value:?} must win"
            );
        }
    }

    #[test]
    fn apply_for_env_skips_without_touching_allocator() {
        assert_eq!(
            apply_allocator_tuning_for_env(Some(OsStr::new("8"))),
            AllocatorTuning::SkippedEnvVar
        );
    }

    #[test]
    fn map_set_result_reports_failed_fail_open() {
        assert_eq!(
            map_set_result(true, 2),
            AllocatorTuning::Applied { arenas: 2 }
        );
        assert_eq!(map_set_result(false, 2), AllocatorTuning::Failed);
    }

    /// Serializes the tests that call `mallopt` or mutate the process
    /// environment: both are process-global, and lib tests run threaded.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// On glibc, the unset branch really calls `mallopt` and reports the
    /// applied cap; the real-environment entry point honors a set variable
    /// and applies when it is absent. One test, one mutex hold, so the
    /// process-global `mallopt`/environment mutations never race.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn apply_applies_cap_and_honors_real_env_on_glibc() {
        let _guard = ENV_MUTEX.lock().unwrap();
        assert_eq!(
            apply_allocator_tuning_for_env(None),
            AllocatorTuning::Applied { arenas: 2 }
        );
        // SAFETY: the mutex above serializes every environment mutation
        // in this module's tests; no other thread in the test process
        // touches MALLOC_ARENA_MAX.
        unsafe {
            std::env::set_var(MALLOC_ARENA_ENV, "8");
        }
        assert_eq!(apply_allocator_tuning(), AllocatorTuning::SkippedEnvVar);
        unsafe {
            std::env::remove_var(MALLOC_ARENA_ENV);
        }
        assert_eq!(
            apply_allocator_tuning(),
            AllocatorTuning::Applied { arenas: 2 }
        );
    }

    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    #[test]
    fn apply_reports_unsupported_off_glibc() {
        assert_eq!(
            apply_allocator_tuning_for_env(None),
            AllocatorTuning::Unsupported
        );
    }
}
