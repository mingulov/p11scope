//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Live cells for getter-only manifests: a statically linked program
//! (`tests/fixtures/manifest-getter/static_getter_app.c`) embeds a
//! provider and exports no PKCS#11 symbol. `scripts/getter-manifest.py`
//! writes a manifest naming only the getters, by file offset from the
//! program's own symbol table. `p11scope profile --pid --manifest` then
//! hooks the getters, reads the tables they return at run time, and must
//! count every table call exactly, under standard-layout names (marked
//! not proven), with each call reached through
//! either table counted once. A third cell lets the calls follow the
//! getter's return at once: they race the table attach, and the report
//! must name that window (`unprotected_live_windows`) rather than read
//! exact. A dynamically linked build of the same program (it embeds the
//! provider and still exports nothing) runs under `--cgroup`: the scope
//! leaves a provider-free process unarmed, so the getter waits for its
//! loader to arm on the next scan and attaches under it. One cell takes
//! the helper's default output (all three getters). One cell lets the
//! program fetch its tables before the capture: the memory scan of the
//! manifest's program object must find them and count every call. One
//! cell builds the provider as a shared object exporting no PKCS#11
//! symbol, which a `p11scope run` child dlopens after the capture began.
//!
//! Sync: the program prints the addresses its tables hand out, and the
//! cell waits until each of them reads back as a breakpoint byte through
//! `/proc/<pid>/mem` (the kernel's uprobe) before it releases the calls.
//! The one sleep keeps the program alive after its calls so the
//! observer drains the getter's return before the exit (see `settle`). Root BPF lane, run serially through
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

/// The fixture program, linked fully static (no `-rdynamic`). A host
/// without a C toolchain's static libc (a test-only host) takes a prebuilt
/// copy through `P11SCOPE_GETTER_STATIC_APP`, copied here so the manifest
/// describes the exact file the cell runs. A missing `libc.a` fails the
/// cell by name, never skips it.
fn build_app(dir: &Path) -> Result<PathBuf> {
    let app = dir.join("static_getter_app");
    if let Some(prebuilt) = std::env::var_os("P11SCOPE_GETTER_STATIC_APP") {
        std::fs::copy(&prebuilt, &app).with_context(|| {
            format!(
                "copying P11SCOPE_GETTER_STATIC_APP={}",
                Path::new(&prebuilt).display()
            )
        })?;
    } else {
        let libc = Command::new("cc")
            .arg("-print-file-name=libc.a")
            .output()
            .context("running cc (a C compiler is required to build the static fixture)")?;
        let libc = PathBuf::from(String::from_utf8_lossy(&libc.stdout).trim());
        ensure!(
            libc.is_absolute() && libc.exists(),
            "the static fixture needs libc.a, which cc cannot find (install libc6-dev on \
             Debian/Ubuntu or glibc-static on Fedora, or set P11SCOPE_GETTER_STATIC_APP to a \
             prebuilt `cc -static` build of tests/fixtures/manifest-getter/static_getter_app.c)"
        );
        let status = Command::new("cc")
            .args([
                "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-o",
            ])
            .arg(&app)
            .arg(repo("tests/fixtures/manifest-getter/static_getter_app.c"))
            .status()
            .context("running cc")?;
        ensure!(status.success(), "static fixture build failed");
    }
    exports_no_getter(&app)?;
    Ok(app)
}

/// The fixture linked dynamically (`PT_INTERP`), still exporting no
/// PKCS#11 symbol: a program that embeds its provider.
fn build_dynamic_app(dir: &Path) -> Result<PathBuf> {
    let app = dir.join("dynamic_getter_app");
    let status = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&app)
        .arg(repo("tests/fixtures/manifest-getter/static_getter_app.c"))
        .status()
        .context("running cc (a C compiler is required to build the fixture)")?;
    ensure!(status.success(), "dynamic fixture build failed");
    let headers = Command::new("readelf").arg("-l").arg(&app).output()?;
    ensure!(
        String::from_utf8_lossy(&headers.stdout).contains("INTERP"),
        "the dynamic fixture has no PT_INTERP"
    );
    exports_no_getter(&app)?;
    Ok(app)
}

/// The shape under test: no PKCS#11 getter in the dynamic symbol table.
fn exports_no_getter(app: &Path) -> Result<()> {
    let output = Command::new("readelf")
        .arg("--dyn-syms")
        .arg(app)
        .output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    ensure!(
        !text.contains("C_Get"),
        "the fixture exports a PKCS#11 getter: {text}"
    );
    Ok(())
}

/// A real cgroup v2 leaf holding only the app, removed when dropped
/// (after the app has exited).
struct ScratchCgroup(PathBuf);

impl ScratchCgroup {
    fn holding(pid: u32) -> Result<Self> {
        let path = PathBuf::from(format!(
            "/sys/fs/cgroup/p11scope-getter-cell-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path)
            .with_context(|| format!("creating the cell cgroup {}", path.display()))?;
        let cgroup = Self(path);
        std::fs::write(cgroup.0.join("cgroup.procs"), format!("{pid}\n"))
            .context("moving the app into the cell cgroup")?;
        Ok(cgroup)
    }
}

impl Drop for ScratchCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CellScope {
    /// `profile --pid` of a static program.
    StaticPid,
    /// `profile --cgroup` of a dynamically linked program.
    DynamicCgroup,
}

/// `getters` empty: the helper's default, every standard getter defined.
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
        Self::spawn_with(app, &[rounds.to_string().as_str(), mode])
    }

    fn spawn_with(app: &Path, args: &[&str]) -> Result<Self> {
        let mut child = Command::new(app)
            .args(args)
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

/// Needle for one hook-attach receipt line: the engine prints
/// `file_offset={offset:#x} abi={abi:?}`, so the needle carries the
/// product's trailing delimiter — without it a hex-prefix offset
/// (e.g. `0x2ce`) also matches another offset's line (`0x2ce0`).
fn attach_receipt_needle(offset: u64) -> String {
    format!("dynamic export attached file_offset={offset:#x} ")
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

/// Keeps the program alive briefly after its calls: the observer drains
/// a getter's return record on its next tick, and one drained after the
/// process exited cannot be attributed to it (a named interface-selection
/// loss for a program that exits right after its getter). The cells
/// test the getter path, not that exit race.
fn settle() {
    std::thread::sleep(Duration::from_secs(2));
}

/// The manifest's getter file offsets.
fn manifest_getter_offsets(manifest: &Path) -> Result<Vec<u64>> {
    let written: serde_json::Value = serde_json::from_slice(&std::fs::read(manifest)?)?;
    written["getters"]
        .as_array()
        .context("manifest getters")?
        .iter()
        .map(|getter| {
            getter["resolution"]["file_offset"]
                .as_u64()
                .context("getter file offset")
        })
        .collect()
}

/// The observer's small-cookie probes at each getter offset in `object`,
/// counted per side (`true` = return), from its link fdinfo (which names
/// each link's path and its probes' cookies and offsets); `None` when the
/// kernel's fdinfo lists no probe offsets. A cookie is
/// `slot | descriptor << 32`, so a getter hook (a capture-local cookie)
/// and a count-only static slot at the same offset (descriptor 0) both
/// carry a small cookie; only the count tells them apart.
fn getter_hook_probes(
    observer: &Child,
    object: &Path,
    offsets: &[u64],
) -> Result<Option<BTreeMap<(bool, u64), usize>>> {
    let path_line = format!("path:\t{}", object.display());
    let mut listed = false;
    let mut probes = BTreeMap::new();
    for entry in std::fs::read_dir(format!("/proc/{}/fdinfo", observer.id()))? {
        let Ok(text) = std::fs::read_to_string(entry?.path()) else {
            continue;
        };
        let kind = if text.contains("link_type:\turetprobe_multi") {
            true
        } else if text.contains("link_type:\tuprobe_multi") {
            false
        } else {
            continue;
        };
        listed |= text.contains("uprobe_cnt:");
        if !text.lines().any(|line| line == path_line) {
            continue;
        }
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(cookie), Some(offset)) = (fields.next(), fields.next()) else {
                continue;
            };
            let (Ok(cookie), Some(Ok(offset))) = (
                cookie.parse::<u64>(),
                offset
                    .strip_prefix("0x")
                    .map(|hex| u64::from_str_radix(hex, 16)),
            ) else {
                continue;
            };
            if cookie < 1 << 32 && offsets.contains(&offset) {
                *probes.entry((kind, offset)).or_insert(0) += 1;
            }
        }
    }
    Ok(listed.then_some(probes))
}

/// Waits until the observer holds the getter hooks themselves: one more
/// entry and one more return small-cookie probe at every getter offset
/// than `baseline` held. A count-only static slot at a getter offset (a
/// getter-only manifest's startup slot) also carries a small cookie, so a
/// cell whose static slots exist before its getter hooks passes the
/// count it took before the hooks could attach. A breakpoint byte alone
/// does not prove the return is watched. A kernel whose fdinfo lists no
/// probe offsets leaves the breakpoint wait as the only sync.
fn wait_for_getter_hooks_since(
    observer: &mut Child,
    object: &Path,
    offsets: &[u64],
    baseline: &BTreeMap<(bool, u64), usize>,
    log: &Path,
) -> Result<()> {
    let deadline = Instant::now() + STEP;
    loop {
        let Some(probes) = getter_hook_probes(observer, object, offsets)? else {
            return Ok(());
        };
        let missing: Vec<_> = offsets
            .iter()
            .flat_map(|offset| [(false, *offset), (true, *offset)])
            .filter(|key| {
                probes.get(key).copied().unwrap_or(0) <= baseline.get(key).copied().unwrap_or(0)
            })
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        if let Some(status) = observer.try_wait()? {
            bail!(
                "the observer exited {status} before the getter hooks attached: {}",
                tail(log)
            );
        }
        ensure!(
            Instant::now() < deadline,
            "getter hook probes missing at {missing:x?} (baseline {baseline:x?}): {}",
            tail(log)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_getter_hooks(
    observer: &mut Child,
    object: &Path,
    offsets: &[u64],
    log: &Path,
) -> Result<()> {
    wait_for_getter_hooks_since(observer, object, offsets, &BTreeMap::new(), log)
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
fn run_cell(tag: &str, getters: &[&str], mode: &str, gated: bool, scope: CellScope) -> Result<()> {
    run_cell_with(tag, getters, mode, gated, scope, false, &[], &[])
}

/// `prefetch`: the program calls its getters and fetches its tables
/// before the capture starts, so no getter returns while it runs; the
/// memory scan of the manifest's program object must find the tables
/// and count every table call exactly, with no unreturned-getter cause.
/// `extra_causes`/`extra_skips` name what the cell's shape honestly
/// adds to the attach window.
#[allow(clippy::too_many_arguments)]
fn run_cell_with(
    tag: &str,
    getters: &[&str],
    mode: &str,
    gated: bool,
    scope: CellScope,
    prefetch: bool,
    extra_causes: &[&str],
    extra_skips: &[&str],
) -> Result<()> {
    let observer = observer_binary()?;
    let dir = tempfile::tempdir()?;
    let app_path = match scope {
        CellScope::StaticPid => build_app(dir.path())?,
        CellScope::DynamicCgroup => build_dynamic_app(dir.path())?,
    };
    let manifest = dir.path().join("getters.json");
    getter_manifest(&app_path, &manifest, getters)?;
    let getter_offsets = manifest_getter_offsets(&manifest)?;
    let hooked: Vec<&str> = if getters.is_empty() {
        vec!["C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"]
    } else {
        getters.to_vec()
    };
    let written: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest)?)?;
    let mut named: Vec<&str> = written["getters"]
        .as_array()
        .context("manifest getters")?
        .iter()
        .filter_map(|getter| getter["name"].as_str())
        .collect();
    named.sort_unstable();
    let mut want = hooked.clone();
    want.sort_unstable();
    ensure!(
        named == want,
        "the manifest names {named:?}, expected {want:?}"
    );
    let rounds = 25;
    // Declared before the app so it is removed after the app exited.
    let mut cgroup = None;
    let mut app = App::spawn(&app_path, rounds, mode)?;
    let ready = parse_fields(&app.expect("READY ")?);
    let pid: u32 = ready.get("pid").context("ready pid")?.parse()?;
    let getter_addresses: Vec<u64> = hooked
        .iter()
        .map(|name| {
            let value = ready
                .get(&format!("getter_{name}"))
                .with_context(|| format!("ready getter {name}"))?;
            Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
        })
        .collect::<Result<_>>()?;
    let prefetched = if prefetch {
        app.gate(b'G')?;
        Some(parse_fields(&app.expect("PUBLISHED ")?))
    } else {
        None
    };
    let target: Vec<String> = match scope {
        CellScope::StaticPid => vec!["--pid".into(), pid.to_string()],
        CellScope::DynamicCgroup => {
            let held = ScratchCgroup::holding(pid)?;
            let path = held.0.display().to_string();
            cgroup = Some(held);
            vec!["--cgroup".into(), path]
        }
    };
    let report = dir.path().join("profile.json");
    let log = dir.path().join("observer.log");
    let log_file = std::fs::File::create(&log)?;
    let mut command = Command::new(&observer);
    command
        .arg("profile")
        .args(&target)
        .arg("--manifest")
        .arg(&manifest)
        .args(["--duration", "120s", "-o"])
        .arg(&report)
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .die_with_parent();
    // The hook-attach receipts print only under the explicit opt-in
    // switch (never under `-v`): every getter cell sets it, the cgroup
    // cell gates on the per-offset lines.
    command.env("P11SCOPE_CAPTURE_DIAGNOSTICS", "1");
    let mut child = command.spawn().context("spawning the observer")?;
    let result = (|| -> Result<serde_json::Value> {
        wait_for_text(&log, "p11scope: capturing:", &mut child)?;
        // Every hooked getter is probed before the program calls one: a
        // cgroup capture attaches them only after its loader armed.
        wait_for_breakpoints(pid, &getter_addresses, &mut child, &log)?;
        if scope == CellScope::DynamicCgroup {
            // The fdinfo small-cookie count cannot tell a count-only
            // static slot from the getter hook at the same offset, and
            // the hooks attach past `capturing`: wait for the engine's
            // per-offset attach receipts, so the calls below cannot run
            // ahead of the hooks that must observe them.
            for offset in &getter_offsets {
                wait_for_text(&log, &attach_receipt_needle(*offset), &mut child)?;
            }
        }
        wait_for_getter_hooks(&mut child, &app_path, &getter_offsets, &log)?;
        let published = match &prefetched {
            Some(published) => published.clone(),
            None => {
                app.gate(b'G')?;
                if !gated {
                    // Both gates at once: the table calls follow the
                    // getter's return immediately, inside the attach
                    // window.
                    app.gate(b'C')?;
                }
                parse_fields(&app.expect("PUBLISHED ")?)
            }
        };
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
        settle();
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
        check_counts(tag, &report, &done, &log, |name| {
            // The getters are probed from the start; only table calls can
            // fall inside the attach window. A prefetching program called
            // its getters before the capture: none of those is counted.
            let getter = hooked.contains(&name);
            (gated || getter, prefetch && getter)
        })?;
        Ok(report)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        println!("GETTER_CELL {tag} observer log:\n{}", tail(&log));
    }
    let report = result?;
    drop(app);
    drop(cgroup);
    check_evidence(tag, &report, extra_causes, extra_skips)
}

/// Compares the report's per-function totals with the program's DONE
/// ledger. `rule(name)` gives `(exact, uncounted)`: an exact name must
/// match, any other may only fall short; an uncounted name ran before
/// the capture, so the report must hold none of its calls.
fn check_counts(
    tag: &str,
    report: &serde_json::Value,
    done: &str,
    log: &Path,
    rule: impl Fn(&str) -> (bool, bool),
) -> Result<()> {
    let ledger = parse_fields(done);
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
        let (exact, uncounted) = rule(name);
        let want = if uncounted { 0 } else { want };
        ensure!(
            if exact { got == want } else { got <= want },
            "{name}: the report counted {got}, the program made {want}; rows {observed:?}; {}",
            tail(log)
        );
    }
    Ok(())
}

/// The evidence every getter cell must show: no loss but the always-named
/// attach window, and no named skip (an unreturned-getter cause would be
/// one).
fn check_evidence(
    tag: &str,
    report: &serde_json::Value,
    extra_causes: &[&str],
    extra_skips: &[&str],
) -> Result<()> {
    let evidence = &report["evidence"];
    println!(
        "GETTER_CELL {tag} completeness={} verdict_detail={} gap_classes={} skipped={}",
        evidence["completeness"],
        evidence["verdict_detail"],
        evidence["gap_classes"],
        evidence["skipped"]
    );
    // The only observation cause is the attach window: a table a getter
    // returns attaches after the return, and calls made before that may
    // be missing. It is named in every getter-only capture (the observer
    // cannot know the program waited, nor that the scan already held the
    // table); no other loss, real or phantom, is reported beyond the
    // cell's own named `extra_causes`/`extra_skips`. Attribution stays
    // withheld (tables reached through a getter-only manifest carry no
    // layout proof).
    let mut causes: Vec<&str> = evidence["gap_classes"]["observation"]["causes"]
        .as_array()
        .context("observation causes")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    causes.sort_unstable();
    let mut want: Vec<&str> = ["unprotected_live_windows"]
        .into_iter()
        .chain(extra_causes.iter().copied())
        .collect();
    want.sort_unstable();
    ensure!(
        causes == want && evidence["unprotected_live_windows"] == 1,
        "observation causes are not exactly {want:?}: {}",
        evidence["gap_classes"]
    );
    let mut skips: Vec<&str> = evidence["skipped"]
        .as_array()
        .context("skipped")?
        .iter()
        .filter_map(|skip| skip["reason"].as_str())
        .collect();
    skips.sort_unstable();
    let mut want_skips = extra_skips.to_vec();
    want_skips.sort_unstable();
    ensure!(
        skips == want_skips,
        "named skips are not exactly {want_skips:?}: {}",
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
        CellScope::StaticPid,
    )
}

#[test]
#[ignore = "privileged: profile --pid with a C_GetFunctionList-only manifest counts a static program's table calls exactly"]
fn privileged_getter_only_manifest_function_list_counts_static_program_exactly() -> Result<()> {
    run_cell(
        "list",
        &["C_GetFunctionList"],
        "list",
        true,
        CellScope::StaticPid,
    )
}

#[test]
#[ignore = "privileged: getter-only manifest table calls made right after the getter returns are never hidden: the attach window is named"]
fn privileged_getter_only_manifest_calls_inside_the_attach_window_are_disclosed() -> Result<()> {
    run_cell(
        "window",
        &["C_GetFunctionList", "C_GetInterface"],
        "both",
        false,
        CellScope::StaticPid,
    )
}

#[test]
#[ignore = "privileged: the helper's default manifest (all three getters) counts a static program's table calls exactly"]
fn privileged_default_getter_manifest_counts_static_program_exactly() -> Result<()> {
    run_cell("default", &[], "both", true, CellScope::StaticPid)
}

#[test]
#[ignore = "privileged: profile --cgroup arms a dynamically linked embedding program's loader for its getters and counts its table calls exactly"]
fn privileged_getter_manifest_counts_a_dynamic_program_under_cgroup_exactly() -> Result<()> {
    // At the program's exit its scanned table's probes retire, while the
    // getter probes stay for later processes of the scope; they share one
    // attach group, so they are reattached and the report names that
    // short reattach window (a real interval, though nothing ran in it).
    run_cell_with(
        "cgroup",
        &["C_GetFunctionList", "C_GetInterface"],
        "both",
        true,
        CellScope::DynamicCgroup,
        false,
        &["skipped", "multi_rebuild_gaps"],
        &[
            "discovery unavailable",
            "static probes detached and exact pairs reattached",
        ],
    )
}

#[test]
#[ignore = "privileged: a static program that fetched its tables before the capture is counted exactly through the scanned program object"]
fn privileged_getter_manifest_counts_a_program_that_fetched_before_the_capture() -> Result<()> {
    // The program selected its interface before the capture, so which
    // interface it chose stays unknown: named, never hidden.
    run_cell_with(
        "prefetch",
        &[],
        "both",
        true,
        CellScope::StaticPid,
        true,
        &["interface_selection"],
        &[],
    )
}

/// The embedding provider as a shared object a `run` child loads after
/// the capture started: `static_getter_app.c` built `-shared` with only
/// `getter_app_main` exported, and `dlopen_loader.c` to load and run it.
fn build_dlopen_fixture(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let library = dir.join("libembedded_getter.so");
    let status = Command::new("cc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-shared",
            "-Dmain=getter_app_main",
        ])
        .arg(format!(
            "-Wl,--version-script={}",
            repo("tests/fixtures/manifest-getter/embedded.map").display()
        ))
        .arg("-o")
        .arg(&library)
        .arg(repo("tests/fixtures/manifest-getter/static_getter_app.c"))
        .status()
        .context("running cc (a C compiler is required to build the fixture)")?;
    ensure!(status.success(), "embedded library build failed");
    exports_no_getter(&library)?;
    let loader = dir.join("dlopen_loader");
    let status = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&loader)
        .arg(repo("tests/fixtures/manifest-getter/dlopen_loader.c"))
        .arg("-ldl")
        .status()
        .context("running cc")?;
    ensure!(status.success(), "loader build failed");
    Ok((library, loader))
}

/// The staging dir for the dlopen fixture a `run` child loads: the
/// runner points `CARGO_TARGET_TMPDIR` at an owned-child-writable dir
/// (like the other owned-run cells), never under the root-owned 0700
/// TMPDIR the dropped child cannot traverse. `None` when the runner did
/// not provide it: there is no TMPDIR fallback.
fn run_child_staging_dir_from(
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    lookup("CARGO_TARGET_TMPDIR").map(PathBuf::from)
}

fn run_child_staging_dir() -> Result<PathBuf> {
    run_child_staging_dir_from(|name| std::env::var_os(name)).context(
        "the run-child dlopen cell needs CARGO_TARGET_TMPDIR, the runner-provided \
         owned-child-writable dir: its fixture must live where the sudo-dropped \
         run child can read it, never under the root-owned 0700 TMPDIR",
    )
}

/// Copies the dlopen fixture into the owned-child-writable staging dir
/// and chmods both files 0755, so the sudo-dropped `run` child can exec
/// the loader and dlopen the library whatever the ambient umask. Returns
/// the staged (library, loader) paths; the manifest must be generated
/// from the staged library, since it embeds the object path.
fn stage_run_child_fixture(
    staging: &Path,
    library: &Path,
    loader: &Path,
) -> Result<(PathBuf, PathBuf)> {
    use std::os::unix::fs::PermissionsExt as _;
    let staged_library = staging.join("libembedded_getter.so");
    let staged_loader = staging.join("dlopen_loader");
    for (source, staged) in [(library, &staged_library), (loader, &staged_loader)] {
        std::fs::copy(source, staged)
            .with_context(|| format!("staging {} for the run child", source.display()))?;
        std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok((staged_library, staged_loader))
}

/// The observer's stdout, which carries the `run` child's protocol lines
/// (the child inherits it); other lines are skipped.
struct RunLines(mpsc::Receiver<String>);

impl RunLines {
    fn expect(&self, prefix: &str) -> Result<String> {
        let deadline = Instant::now() + STEP;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .0
                .recv_timeout(left)
                .with_context(|| format!("the run child never printed {prefix:?}"))?;
            if line.starts_with(prefix) {
                return Ok(line);
            }
        }
    }
}

#[test]
#[ignore = "privileged: a named-pid capture with a getter-only manifest counts a provider object the process dlopens after the capture started exactly"]
fn privileged_getter_manifest_counts_a_later_dlopen_under_a_named_pid() -> Result<()> {
    // A named-pid tick with no refresh request does nothing else, so the
    // getter pass the loader hit owes must still run on that tick.
    let tag = "pid-dlopen";
    let observer = observer_binary()?;
    let dir = tempfile::tempdir()?;
    let (library, loader) = build_dlopen_fixture(dir.path())?;
    let manifest = dir.path().join("getters.json");
    getter_manifest(&library, &manifest, &[])?;
    let getter_offsets = manifest_getter_offsets(&manifest)?;
    let library_arg = library.display().to_string();
    let mut app = App::spawn_with(&loader, &[library_arg.as_str(), "25", "both"])?;
    let loader_line = parse_fields(&app.expect("LOADER ")?);
    let pid: u32 = loader_line.get("pid").context("loader pid")?.parse()?;
    let report = dir.path().join("profile.json");
    let log = dir.path().join("observer.log");
    let log_file = std::fs::File::create(&log)?;
    let mut child = Command::new(&observer)
        .arg("profile")
        .args(["--pid", pid.to_string().as_str()])
        .arg("--manifest")
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
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        ensure!(
            !maps.contains(&library_arg),
            "the provider object is mapped before the dlopen"
        );
        // Let the capture settle into quiet ticks before the dlopen.
        settle();
        // The startup getter slots already sit at the getter offsets.
        let baseline = getter_hook_probes(&child, &library, &getter_offsets)?.unwrap_or_default();
        app.gate(b'L')?;
        let ready = parse_fields(&app.expect("READY ")?);
        let getters: Vec<u64> = ["C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"]
            .iter()
            .map(|name| {
                let value = ready
                    .get(&format!("getter_{name}"))
                    .with_context(|| format!("ready getter {name}"))?;
                Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
            })
            .collect::<Result<_>>()?;
        wait_for_breakpoints(pid, &getters, &mut child, &log)?;
        wait_for_getter_hooks_since(&mut child, &library, &getter_offsets, &baseline, &log)?;
        app.gate(b'G')?;
        let published = parse_fields(&app.expect("PUBLISHED ")?);
        let addresses: Vec<u64> = published
            .iter()
            .filter(|(key, _)| key.starts_with("C_"))
            .map(|(_, value)| u64::from_str_radix(value.trim_start_matches("0x"), 16))
            .collect::<Result<_, _>>()?;
        ensure!(!addresses.is_empty(), "no published table addresses");
        wait_for_breakpoints(pid, &addresses, &mut child, &log)?;
        app.gate(b'C')?;
        let done = app.expect("DONE ")?;
        println!("GETTER_CELL {tag} ledger {done}");
        settle();
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
        check_counts(tag, &report, &done, &log, |_| (true, false))?;
        Ok(report)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        println!("GETTER_CELL {tag} observer log:\n{}", tail(&log));
    }
    let report = result?;
    drop(app);
    // Named, not lost: a dlopen in a running process has no pause to prove
    // it ran before the library's constructor (`loader_discovery`). The
    // getter hooks attach before the program calls a getter, so its
    // interface selection is observed; the ended process retires its
    // probes with no physical gap.
    check_evidence(tag, &report, &["loader_discovery"], &[])
}

#[test]
#[ignore = "privileged: run with a getter-only manifest counts a provider object its child dlopens after the capture started exactly"]
fn privileged_getter_manifest_counts_a_later_dlopen_in_a_run_child() -> Result<()> {
    let tag = "dlopen";
    let observer = observer_binary()?;
    let dir = tempfile::tempdir()?;
    let (library, loader) = build_dlopen_fixture(dir.path())?;
    // The run child drops to the sudo invoker, which cannot traverse the
    // root-owned 0700 TMPDIR tree: stage the fixture where it can read
    // and execute it, and generate the manifest from the staged library.
    let staging = run_child_staging_dir()?;
    let (library, loader) = stage_run_child_fixture(&staging, &library, &loader)?;
    let manifest = dir.path().join("getters.json");
    getter_manifest(&library, &manifest, &[])?;
    let getter_offsets = manifest_getter_offsets(&manifest)?;
    let report = dir.path().join("run.json");
    let log = dir.path().join("observer.log");
    let log_file = std::fs::File::create(&log)?;
    let mut child = Command::new(&observer)
        .arg("run")
        .arg("--manifest")
        .arg(&manifest)
        .arg("-o")
        .arg(&report)
        .arg("--")
        .arg(&loader)
        .arg(&library)
        .args(["25", "both"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(log_file)
        .die_with_parent()
        .spawn()
        .context("spawning the observer")?;
    let mut stdin = child.stdin.take().context("observer stdin")?;
    let stdout = child.stdout.take().context("observer stdout")?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let lines = RunLines(receiver);
    let mut gate = |byte: u8| -> Result<()> {
        stdin.write_all(&[byte])?;
        stdin.flush()?;
        Ok(())
    };
    let result = (|| -> Result<serde_json::Value> {
        let loader_line = parse_fields(&lines.expect("LOADER ")?);
        let pid: u32 = loader_line.get("pid").context("loader pid")?.parse()?;
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        ensure!(
            !maps.contains(&library.display().to_string()),
            "the provider object is mapped before the dlopen"
        );
        let baseline = getter_hook_probes(&child, &library, &getter_offsets)?.unwrap_or_default();
        gate(b'L')?;
        let ready = parse_fields(&lines.expect("READY ")?);
        let getters: Vec<u64> = ["C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"]
            .iter()
            .map(|name| {
                let value = ready
                    .get(&format!("getter_{name}"))
                    .with_context(|| format!("ready getter {name}"))?;
                Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
            })
            .collect::<Result<_>>()?;
        // The loader hit's rescan attaches the getters in the newly
        // mapped object before the program calls one.
        wait_for_breakpoints(pid, &getters, &mut child, &log)?;
        wait_for_getter_hooks_since(&mut child, &library, &getter_offsets, &baseline, &log)?;
        gate(b'G')?;
        let published = parse_fields(&lines.expect("PUBLISHED ")?);
        let addresses: Vec<u64> = published
            .iter()
            .filter(|(key, _)| key.starts_with("C_"))
            .map(|(_, value)| u64::from_str_radix(value.trim_start_matches("0x"), 16))
            .collect::<Result<_, _>>()?;
        wait_for_breakpoints(pid, &addresses, &mut child, &log)?;
        gate(b'C')?;
        let done = lines.expect("DONE ")?;
        println!("GETTER_CELL {tag} ledger {done}");
        settle();
        gate(b'X')?;
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
        ensure!(status.success(), "run exited {status}: {}", tail(&log));
        let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&report)?)?;
        check_counts(tag, &report, &done, &log, |_| (true, false))?;
        Ok(report)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        println!("GETTER_CELL {tag} observer log:\n{}", tail(&log));
    }
    check_evidence(tag, &result?, &[], &[])
}

#[test]
fn run_child_staging_uses_the_runner_target_tmpdir_only() {
    let lookup = |name: &str| match name {
        "CARGO_TARGET_TMPDIR" => Some(std::ffi::OsString::from("/owned/target/tmp")),
        "TMPDIR" => Some(std::ffi::OsString::from("/root-only")),
        _ => None,
    };
    assert_eq!(
        run_child_staging_dir_from(lookup),
        Some(PathBuf::from("/owned/target/tmp")),
        "the fixture must stage in the owned-child-writable target tmpdir, not TMPDIR"
    );
    let no_target_tmpdir = |name: &str| match name {
        "TMPDIR" => Some(std::ffi::OsString::from("/root-only")),
        _ => None,
    };
    assert_eq!(
        run_child_staging_dir_from(no_target_tmpdir),
        None,
        "without CARGO_TARGET_TMPDIR there is no TMPDIR fallback"
    );
}

#[test]
fn run_child_staging_copies_and_chmods_the_fixture() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let source = tempfile::tempdir()?;
    let library = source.path().join("libembedded_getter.so");
    let loader = source.path().join("dlopen_loader");
    std::fs::write(&library, b"library-bytes")?;
    std::fs::write(&loader, b"loader-bytes")?;
    // Restrictive sources: a plain copy would keep 0600 and stay
    // unreadable to the dropped child, so the chmod must be explicit.
    for path in [&library, &loader] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let staging = tempfile::tempdir()?;
    let (staged_library, staged_loader) =
        stage_run_child_fixture(staging.path(), &library, &loader)?;
    assert_eq!(staged_library.file_name(), library.file_name());
    assert_eq!(staged_loader.file_name(), loader.file_name());
    assert_eq!(std::fs::read(&staged_library)?, b"library-bytes");
    assert_eq!(std::fs::read(&staged_loader)?, b"loader-bytes");
    for staged in [&staged_library, &staged_loader] {
        let mode = std::fs::metadata(staged)?.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o755,
            "staged {} must be world-readable and executable",
            staged.display()
        );
    }
    Ok(())
}

#[test]
fn attach_receipt_needle_terminates_at_the_offset() {
    // Product lines as `note_dynamic_export_attached` formats them
    // (`src/discovery/engine.rs`): the offset is followed by ` abi=`.
    let own = "p11scope: dynamic export attached file_offset=0x2ce abi=FunctionList";
    let longer = "p11scope: dynamic export attached file_offset=0x2ce0 abi=FunctionList";
    // Control: the unterminated needle cannot tell a hex-prefix offset
    // from the longer offset's line, so the delimiter must do it.
    let short = "dynamic export attached file_offset=0x2ce";
    assert!(
        longer.contains(short),
        "the prefix collision the delimiter guards against is gone: {longer:?}"
    );
    let needle = attach_receipt_needle(0x2ce);
    assert!(
        own.contains(&needle),
        "the terminated needle must accept its own line: {needle:?}"
    );
    assert!(
        !longer.contains(&needle),
        "the terminated needle must reject the hex-prefix collision: {needle:?}"
    );
}
