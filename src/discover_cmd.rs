//! `p11scope discover` — locate and exec the unprivileged helper.
//! p11scope never dlopens a provider itself: it is privileged, static,
//! and must not run vendor constructors in its own address space.

use anyhow::{Result, anyhow};
use std::path::PathBuf;
use std::process::Command;

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut helper: Option<PathBuf> = None;
    let mut forwarded: Vec<String> = Vec::new();
    let mut it = args.peekable();
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
    let path = match helper {
        Some(p) => {
            searched.push(p.display().to_string());
            p.exists().then_some(p)
        }
        None => {
            let sibling = std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|d| d.join("p11scope-discover")));
            match sibling {
                Some(p) => {
                    searched.push(p.display().to_string());
                    if p.exists() { Some(p) } else { None }
                }
                None => None,
            }
        }
    };
    let path = match path {
        Some(p) => p,
        None => {
            searched.push("p11scope-discover on PATH".into());
            PathBuf::from("p11scope-discover")
        }
    };

    let status = Command::new(&path).args(&forwarded).status().map_err(|e| {
        anyhow!("cannot execute discovery helper ({e}); searched: {}", searched.join(", "))
    })?;
    std::process::exit(status.code().unwrap_or(1));
}
