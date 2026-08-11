//! `p11scope discover` — locate and exec the unprivileged helper.
//! p11scope never dlopens a provider itself: it is privileged, static,
//! and must not run vendor constructors in its own address space.

use anyhow::{Result, anyhow};
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::Command;

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut helper: Option<PathBuf> = None;
    let mut forwarded: Vec<String> = Vec::new();
    let mut it = args;
    while let Some(a) = it.next() {
        if a == "--helper" {
            let v = it.next().ok_or_else(|| anyhow!("--helper requires a value"))?;
            helper = Some(PathBuf::from(v));
        } else {
            forwarded.push(a);
        }
    }
    if !forwarded.iter().any(|a| a == "--module") {
        eprintln!("discover requires --module <provider.so>");
        std::process::exit(2);
    }

    let mut searched = Vec::new();
    let path = if let Some(p) = helper {
        // Explicit --helper is authoritative; fail if it doesn't exist.
        searched.push(p.display().to_string());
        if !p.exists() {
            eprintln!(
                "cannot execute discovery helper; searched: {}",
                searched.join(", ")
            );
            std::process::exit(1);
        }
        p
    } else {
        // Without --helper, search: (1) sibling of current_exe(), (2) PATH
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("p11scope-discover")));

        match sibling {
            Some(p) if p.exists() => {
                searched.push(p.display().to_string());
                p
            }
            Some(p) => {
                searched.push(p.display().to_string());
                searched.push("p11scope-discover on PATH".into());
                eprintln!(
                    "cannot execute discovery helper; searched: {}",
                    searched.join(", ")
                );
                std::process::exit(1);
            }
            None => {
                searched.push("p11scope-discover on PATH".into());
                eprintln!(
                    "cannot execute discovery helper; searched: {}",
                    searched.join(", ")
                );
                std::process::exit(1);
            }
        }
    };

    let status = Command::new(&path).args(&forwarded).status().map_err(|e| {
        anyhow!("cannot execute discovery helper ({e}); searched: {}", searched.join(", "))
    })?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    std::process::exit(code);
}
