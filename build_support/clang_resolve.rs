//! SPDX-License-Identifier: GPL-3.0-or-later
//! Executable resolution for the identity-object clang invocation, shared
//! by `build.rs` and the qualification harness (both include this file by
//! path; it takes no crate dependencies so it compiles in either).
//!
//! Process spawning (`execvp`) selects the first EXECUTABLE hit on `PATH`
//! and skips the rest. Resolving with `is_file()` alone can therefore
//! record a non-executable decoy that never compiled anything. This module
//! resolves like spawning does — first executable hit, absolutized — so
//! the caller executes the returned absolute path directly and the build
//! receipt binds to the compiler that actually ran.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Whether `path` is a regular file the CURRENT user can execute:
/// the `execvp` selection rule (what process spawning would run).
/// Mode bits alone mislead — a file can carry exec bits yet refuse
/// the builder with `EACCES` (e.g. owner-only `x` for a foreign owner,
/// or `0641` for a builder without owner-x) — so this probes effective
/// executability with `faccessat(X_OK)` instead of reading the mode.
pub fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let bytes = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str());
    let Ok(path_c) = std::ffi::CString::new(bytes) else {
        return false;
    };
    // SAFETY: `faccessat` with `AT_FDCWD` reads no memory beyond the
    // NUL-terminated path; `AT_EACCESS` tests the effective ids, as
    // execution would.
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

/// Resolve `file` against `path_env` like process spawning: the first
/// EFFECTIVELY-EXECUTABLE hit, returned as an absolute path (the `PATH`
/// hit itself — the caller canonicalizes separately for the realpath
/// field). Relative `PATH` entries are interpreted against `cwd` once,
/// here — the caller must execute the returned path directly (never
/// re-search `PATH`, never relative), so no later working directory can
/// divert execution elsewhere. `None` when no `PATH` entry holds an
/// executable `file`.
pub fn resolve_executable_in(file: &str, path_env: &OsStr, cwd: &Path) -> Option<PathBuf> {
    if file.is_empty() || file.contains('/') {
        return None;
    }
    for dir in std::env::split_paths(path_env) {
        let joined = if dir.as_os_str().is_empty() {
            cwd.join(file)
        } else if dir.is_absolute() {
            dir.join(file)
        } else {
            cwd.join(dir).join(file)
        };
        if is_executable_file(&joined) {
            return Some(joined);
        }
    }
    None
}

/// Every `PATH` directory as an absolute path, in order, deduped:
/// empty entries mean `cwd`, relative entries join it. The build
/// watches the existing ones, so a brand-new shadowing file bumps its
/// directory and re-runs the build instead of silently shadowing the
/// recorded compiler. Nonexistent entries are still listed (the test
/// recomputes this exact set from the recorded `PATH`) but unwatched.
pub fn path_dirs_in(path_env: &OsStr, cwd: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in std::env::split_paths(path_env) {
        let absolute = if dir.as_os_str().is_empty() {
            cwd.to_path_buf()
        } else if dir.is_absolute() {
            dir
        } else {
            cwd.join(dir)
        };
        if !out.contains(&absolute) {
            out.push(absolute);
        }
    }
    out
}

/// Every `PATH` entry's `file` that exists (executable or not): the build
/// watches all of them, so a resolution-affecting change re-runs the
/// build instead of silently keeping a stale compiler binding.
pub fn candidate_files_in(file: &str, path_env: &OsStr, cwd: &Path) -> Vec<PathBuf> {
    if file.is_empty() || file.contains('/') {
        return Vec::new();
    }
    let mut out = Vec::new();
    for dir in std::env::split_paths(path_env) {
        let joined = if dir.as_os_str().is_empty() {
            cwd.join(file)
        } else if dir.is_absolute() {
            dir.join(file)
        } else {
            cwd.join(dir).join(file)
        };
        if joined.is_file() {
            out.push(joined);
        }
    }
    out
}
