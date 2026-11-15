//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Live cells for getter-only manifests: a statically linked program
//! (`tests/fixtures/manifest-getter/static_getter_app.c`) embeds a
//! provider and exports no PKCS#11 symbol. `scripts/getter-manifest.py`
//! writes a manifest naming only the getters, by file offset from the
//! program's own symbol table. `p11scope profile --pid --manifest` then
//! hooks the getters, reads the tables they return at run time, and must
//! count every table call exactly, named, with each call reached through
//! either table counted once. A third cell lets the calls follow the
//! getter's return at once: they race the table attach, and the report
//! must name that window (`unprotected_live_windows`) rather than read
//! exact.
//!
//! Sync without sleeps: the program prints the addresses its tables
//! hand out, and the cell waits until each of them reads back as a
//! breakpoint byte through `/proc/<pid>/mem` (the kernel's uprobe) before
//! it releases the calls. Root BPF lane, run serially through
//! `scripts/run-privileged-lib-tests.sh`; spawns the real observer
//! (`P11SCOPE_E2E_OBSERVER`, else the `p11scope` sibling of the test
//! binary). Prints GETTER_CELL lines.

use crate::fixture_guard::DieWithParent as _;
use anyhow::{Context as _, Result, bail, ensure};
use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_secs(60);

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn observer_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("P11SCOPE_E2E_OBSERVER") {
        let path = PathBuf::from(path);
        ensure!(
            path.exists(),
            "P11SCOPE_E2E_OBSERVER={} is missing",
            path.display()
        );
        return Ok(path);
    }
    std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join("p11scope"))
        .filter(|path| path.exists())
        .context("no observer binary: set P11SCOPE_E2E_OBSERVER or build p11scope beside this test binary")
}

/// The fixture program, linked fully static (no `-rdynamic`).
fn build_app(dir: &Path) -> Result<PathBuf> {
    let app = dir.join("static_getter_app");
    let status = Command::new("cc")
        .args([
            "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-o",
        ])
        .arg(&app)
        .arg(repo("tests/fixtures/manifest-getter/static_getter_app.c"))
        .status()
        .context("running cc")?;
    ensure!(
        status.success(),
        "static fixture build failed (needs static libc)"
    );
    // The shape under test: no dynamic symbol table at all.
    let output = Command::new("readelf")
        .arg("--dyn-syms")
        .arg(&app)
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    ensure!(
        !text.contains("C_Get"),
        "the static fixture exports a PKCS#11 getter: {text}"
    );
    Ok(app)
}

fn getter_manifest(app: &Path, out: &Path, getters: &[&str]) -> Result<()> {
    let mut command = Command::new("python3");
    command
        .arg("-I")
        .arg(repo("scripts/getter-manifest.py"))
        .arg(app)
        .arg("-o")
        .arg(out);
    for getter in getters {
        command.args(["--getter", getter]);
    }
    let output = command.output().context("running getter-manifest.py")?;
    ensure!(
        output.status.success(),
        "getter-manifest.py failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

struct App {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl App {
    fn spawn(app: &Path, rounds: u32, mode: &str) -> Result<Self> {
        let mut child = Command::new(app)
            .args([rounds.to_string().as_str(), mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .die_with_parent()
            .spawn()
            .context("spawning the static app")?;
        let stdin = child.stdin.take().context("app stdin")?;
        let stdout = child.stdout.take().context("app stdout")?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
        })
    }

    fn expect(&mut self, prefix: &str) -> Result<String> {
        let line = self
            .lines
            .recv_timeout(STEP)
            .with_context(|| format!("the app never printed {prefix:?}"))?;
        ensure!(
            line.starts_with(prefix),
            "expected {prefix:?}, got {line:?}"
        );
        Ok(line)
    }

    fn gate(&mut self, byte: u8) -> Result<()> {
        self.stdin.write_all(&[byte])?;
        self.stdin.flush()?;
        Ok(())
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn wait_for_text(path: &Path, needle: &str, observer: &mut Child) -> Result<()> {
    let deadline = Instant::now() + STEP;
    loop {
        if std::fs::read_to_string(path).is_ok_and(|text| text.contains(needle)) {
            return Ok(());
        }
        if let Some(status) = observer.try_wait()? {
            bail!(
                "the observer exited {status} before {needle:?}: {}",
                tail(path)
            );
        }
        ensure!(
            Instant::now() < deadline,
            "no {needle:?} from the observer: {}",
            tail(path)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<_> = text.lines().rev().take(40).collect();
    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
}

/// Waits until every address reads back as an int3 through the target's
/// own memory: the kernel installed the uprobe there.
fn wait_for_breakpoints(
    pid: u32,
    addresses: &[u64],
    observer: &mut Child,
    log: &Path,
) -> Result<()> {
    let deadline = Instant::now() + STEP;
    let mut mem = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    loop {
        let mut armed = 0;
        for address in addresses {
            let mut byte = [0u8];
            mem.seek(SeekFrom::Start(*address))?;
            mem.read_exact(&mut byte)?;
            armed += usize::from(byte[0] == 0xcc);
        }
        if armed == addresses.len() {
            return Ok(());
        }
        if let Some(status) = observer.try_wait()? {
            bail!(
                "the observer exited {status} before the table probes armed: {}",
                tail(log)
            );
        }
        ensure!(
            Instant::now() < deadline,
            "only {armed}/{} table functions were probed: {}",
            addresses.len(),
            tail(log)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn parse_fields(line: &str) -> BTreeMap<String, String> {
    line.split_whitespace()
        .filter_map(|field| field.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// One getter-only cell: `getters` in the manifest, `mode` in the app.
/// `gated` waits until every published table function is probed before
/// releasing the calls, so the counts must be exact; otherwise the calls
/// race the table attach and the cell checks that the window is named.
fn run_cell(tag: &str, getters: &[&str], mode: &str, gated: bool) -> Result<()> {
    let observer = observer_binary()?;
    let dir = tempfile::tempdir()?;
    let app_path = build_app(dir.path())?;
    let manifest = dir.path().join("getters.json");
    getter_manifest(&app_path, &manifest, getters)?;
    let rounds = 25;
    let mut app = App::spawn(&app_path, rounds, mode)?;
    let ready = parse_fields(&app.expect("READY ")?);
    let pid: u32 = ready.get("pid").context("ready pid")?.parse()?;
    let report = dir.path().join("profile.json");
    let log = dir.path().join("observer.log");
    let log_file = std::fs::File::create(&log)?;
    let mut child = Command::new(&observer)
        .args(["profile", "--pid", &pid.to_string(), "--manifest"])
        .arg(&manifest)
        .args(["--duration", "120s", "-o"])
        .arg(&report)
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .die_with_parent()
        .spawn()
        .context("spawning the observer")?;
    let result = (|| -> Result<serde_json::Value> {
        wait_for_text(&log, "p11scope: capturing:", &mut child)?;
        app.gate(b'G')?;
        if !gated {
            // Both gates at once: the table calls follow the getter's
            // return immediately, inside the attach window.
            app.gate(b'C')?;
        }
        let published = parse_fields(&app.expect("PUBLISHED ")?);
        let addresses: Vec<u64> = published
            .iter()
            .filter(|(key, _)| key.starts_with("C_"))
            .map(|(_, value)| u64::from_str_radix(value.trim_start_matches("0x"), 16))
            .collect::<Result<_, _>>()?;
        ensure!(!addresses.is_empty(), "no published table addresses");
        if gated {
            wait_for_breakpoints(pid, &addresses, &mut child, &log)?;
            app.gate(b'C')?;
        }
        let done = app.expect("DONE ")?;
        println!("GETTER_CELL {tag} ledger {done}");
        if !gated {
            // Keep the program alive until the late table attach landed,
            // so the report covers the window rather than an exit race.
            wait_for_breakpoints(pid, &addresses, &mut child, &log)?;
        }
        app.gate(b'X')?;
        let deadline = Instant::now() + STEP * 3;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "the observer never stopped: {}",
                tail(&log)
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        println!("GETTER_CELL {tag} observer {status}");
        ensure!(status.success(), "profile exited {status}: {}", tail(&log));
        let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&report)?)?;
        let ledger = parse_fields(&done);
        let mut observed: BTreeMap<String, u64> = BTreeMap::new();
        for row in report["functions"].as_array().context("functions")? {
            let calls = row["calls"].as_u64().context("calls")?;
            let names: Vec<&str> = row["names"]
                .as_array()
                .context("names")?
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            if calls != 0 {
                println!("GETTER_CELL {tag} row names={names:?} calls={calls}");
            }
            for name in names {
                *observed.entry(name.to_string()).or_default() += calls;
            }
        }
        for (name, want) in &ledger {
            let want: u64 = want.parse()?;
            let got = observed.get(name).copied().unwrap_or(0);
            // The getters are probed from the start; only table calls can
            // fall inside the attach window.
            let exact = gated || getters.contains(&name.as_str());
            ensure!(
                if exact { got == want } else { got <= want },
                "{name}: profile counted {got}, the program made {want}; rows {observed:?}; {}",
                tail(&log)
            );
        }
        Ok(report)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        println!("GETTER_CELL {tag} observer log:\n{}", tail(&log));
    }
    let report = result?;
    let evidence = &report["evidence"];
    println!(
        "GETTER_CELL {tag} completeness={} verdict_detail={} gap_classes={} skipped={}",
        evidence["completeness"],
        evidence["verdict_detail"],
        evidence["gap_classes"],
        evidence["skipped"]
    );
    // The only observation cause is the attach window: the table
    // attaches after its getter returned it, and calls made before that
    // may be missing. It is named in every getter-only capture (the
    // observer cannot know the program waited); no other loss, real or
    // phantom, is reported. Attribution stays withheld (tables reached
    // through a getter-only manifest carry no layout proof).
    ensure!(
        evidence["gap_classes"]["observation"]["causes"]
            == serde_json::json!(["unprotected_live_windows"])
            && evidence["unprotected_live_windows"] == 1,
        "observation causes are not exactly the attach window: {}",
        evidence["gap_classes"]
    );
    ensure!(
        evidence["skipped"].as_array().is_some_and(Vec::is_empty),
        "named skips: {}",
        evidence["skipped"]
    );
    Ok(())
}

#[test]
#[ignore = "privileged: profile --pid with a getter-only manifest (both getters) counts a static program's table calls exactly"]
fn privileged_getter_only_manifest_both_getters_counts_static_program_exactly() -> Result<()> {
    run_cell(
        "both",
        &["C_GetFunctionList", "C_GetInterface"],
        "both",
        true,
    )
}

#[test]
#[ignore = "privileged: profile --pid with a C_GetFunctionList-only manifest counts a static program's table calls exactly"]
fn privileged_getter_only_manifest_function_list_counts_static_program_exactly() -> Result<()> {
    run_cell("list", &["C_GetFunctionList"], "list", true)
}

#[test]
#[ignore = "privileged: getter-only manifest table calls made right after the getter returns are never hidden: the attach window is named"]
fn privileged_getter_only_manifest_calls_inside_the_attach_window_are_disclosed() -> Result<()> {
    run_cell(
        "window",
        &["C_GetFunctionList", "C_GetInterface"],
        "both",
        false,
    )
}
