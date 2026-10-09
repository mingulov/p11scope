//! SPDX-License-Identifier: GPL-3.0-or-later
use std::{
    ffi::{CString, OsStr, OsString},
    fs,
    os::{
        raw::c_int,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

pub const PREPARED_CARGO_ENV: &str = "P11SCOPE_PREPARED_BPF_CARGO";
pub const PREPARED_RUSTC_ENV: &str = "P11SCOPE_PREPARED_BPF_RUSTC";

const AT_FDCWD: c_int = -100;
const X_OK: c_int = 1;
const AT_EACCESS: c_int = 0x200;

unsafe extern "C" {
    fn faccessat(
        dirfd: c_int,
        pathname: *const std::os::raw::c_char,
        mode: c_int,
        flags: c_int,
    ) -> c_int;
}

pub fn bpf_cargo_command(
    prepared_cargo: Option<OsString>,
    prepared_rustc: Option<OsString>,
    inherited_library_path: Option<OsString>,
) -> Result<Command, String> {
    let mut command = match (prepared_cargo, prepared_rustc) {
        (None, None) => {
            let mut command = Command::new("cargo");
            command.arg("+nightly-2026-05-20").env_remove("RUSTC");
            command
        }
        (Some(cargo), Some(rustc)) => {
            let cargo = executable(PREPARED_CARGO_ENV, &cargo)?;
            let rustc = executable(PREPARED_RUSTC_ENV, &rustc)?;
            let mut library_paths = vec![selected_rustc_library_path(&rustc)?];
            if let Some(inherited) = inherited_library_path {
                library_paths.extend(std::env::split_paths(&inherited));
            }
            let library_path = std::env::join_paths(library_paths).map_err(|error| {
                format!("constructing selected rustc LD_LIBRARY_PATH failed: {error}")
            })?;
            let mut command = Command::new(cargo);
            command
                .env("RUSTC", rustc)
                .env("LD_LIBRARY_PATH", library_path);
            command
        }
        _ => {
            return Err(format!(
                "{PREPARED_CARGO_ENV} and {PREPARED_RUSTC_ENV} must be provided together"
            ));
        }
    };
    command.env_remove("RUSTC_WORKSPACE_WRAPPER");
    Ok(command)
}

pub fn isolate_bpf_output(command: &mut Command, target_dir: &Path) {
    // Modern Cargo separates intermediate output; sharing a release build lock
    // with the parent can deadlock its build-script child.
    command
        .arg("--target-dir")
        .arg(target_dir)
        .env("CARGO_BUILD_BUILD_DIR", target_dir);
}

fn selected_rustc_library_path(rustc: &Path) -> Result<PathBuf, String> {
    let output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|error| format!("querying selected rustc sysroot failed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "querying selected rustc sysroot failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut path = output.stdout;
    if path.last() == Some(&b'\n') {
        path.pop();
        if path.last() == Some(&b'\r') {
            path.pop();
        }
    }
    if path.is_empty() || path.contains(&b'\n') || path.contains(&b'\r') {
        return Err("selected rustc returned an invalid sysroot path".to_string());
    }
    let sysroot = PathBuf::from(OsString::from_vec(path));
    if !sysroot.is_absolute() {
        return Err(format!(
            "selected rustc returned a non-absolute sysroot path: {}",
            sysroot.display()
        ));
    }
    let library_path = sysroot.join("lib");
    if !library_path.is_dir() {
        return Err(format!(
            "selected rustc sysroot lib directory does not exist: {}",
            library_path.display()
        ));
    }
    Ok(library_path)
}

pub fn bpf_cargo_command_from_env() -> Result<Command, String> {
    bpf_cargo_command(
        std::env::var_os(PREPARED_CARGO_ENV),
        std::env::var_os(PREPARED_RUSTC_ENV),
        std::env::var_os("LD_LIBRARY_PATH"),
    )
}

fn executable(name: &str, value: &OsStr) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if !path.is_absolute() {
        return Err(format!(
            "{name} must be an absolute path: {}",
            path.display()
        ));
    }
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{name} path contains a NUL byte"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("{name} is not an executable regular file: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "{name} is not an executable regular file: {}",
            path.display()
        ));
    }
    // SAFETY: `c_path` is a live, NUL-terminated pathname. `faccessat` only
    // reads it, and these Linux constants request execute access using the
    // effective credentials of this build process.
    if unsafe { faccessat(AT_FDCWD, c_path.as_ptr(), X_OK, AT_EACCESS) } != 0 {
        return Err(format!(
            "{name} is not executable by the effective user: {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(path)
}
