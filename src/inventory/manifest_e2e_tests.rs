//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Owned, ignored end-to-end gate for the v0.5.0 headline command:
//! `inventory --system --manifest` over a live SoftHSM2 ledger workload
//! through the real CLI surface (`cli::parse` + `inventory::run`).
//! Root BPF lane, run serially through `scripts/run-privileged-lib-tests.sh`.
//! The workload dlopens after a gate the cell opens once the native
//! attach has settled, so its calls are post-attach (R-34b). The cell
//! asserts rc 0 plus populated S1 edges (mechanisms and API results)
//! or named route-loss gaps (R-51); a run with neither fails as a
//! silent drop. It also asserts the `journal_unavailable` S1 marker.
//! Prints MAN1_E2E lines.
//!
//! The scale cell below reuses the same live `inventory --system
//! --manifest` shape over 4,097+ admitted endpoints: distinct SoftHSM2
//! copies (one manifest each, full exported surface) held mapped by a
//! single holder process, plus the gated ledger caller that must grow
//! a populated S1 edge. Prints SCALE2_E2E lines.

use super::*;
use crate::fixture_guard::DieWithParent as _;
use anyhow::ensure;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// SoftHSM2 provider layouts across guest images (Debian multiarch
/// first, then the /usr/lib layout the vng guests carry, then the
/// Fedora /usr/lib64 layout the controller's live cells use).
const SOFTHSM_CANDIDATES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
];

/// PKCS#11 functions the ledger `mech` cell calls (setup, the ten
/// main-phase table calls per iteration, teardown): the cell manifest
/// resolves exactly these.
const MECH_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_GetSlotList",
    "C_OpenSession",
    "C_Login",
    "C_DigestInit",
    "C_Digest",
    "C_GenerateKey",
    "C_EncryptInit",
    "C_Encrypt",
    "C_SignInit",
    "C_Sign",
    "C_DestroyObject",
    "C_Logout",
    "C_CloseSession",
    "C_Finalize",
];

/// PKCS#11 functions the `mt_sign` cell calls (setup keygen after
/// the gate, per-worker sessions with SignInit/Sign, teardown): the
/// cell manifest resolves exactly these.
const MT_SIGN_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_GetSlotList",
    "C_OpenSession",
    "C_Login",
    "C_GenerateKeyPair",
    "C_SignInit",
    "C_Sign",
    "C_CloseSession",
];

fn ledger_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-cli/inventory-ledger.c")
}

fn mt_sign_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-cli/mt_sign.c")
}

fn capacity_matrix_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture/version_matrix.c")
}

fn softhsm_path() -> Result<String> {
    for candidate in SOFTHSM_CANDIDATES {
        if Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }
    anyhow::bail!(
        "SoftHSM2 provider is missing (tried {})",
        SOFTHSM_CANDIDATES.join(", ")
    )
}

/// The observer under test: an explicit `P11SCOPE_E2E_OBSERVER` binary
/// (the guest driver stages one) or the `p11scope` sibling of this
/// test binary's directory (a local `cargo build` layout).
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
    let sibling = std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join("p11scope"));
    if let Some(sibling) = sibling.filter(|path| path.exists()) {
        return Ok(sibling);
    }
    anyhow::bail!(
        "no observer binary: set P11SCOPE_E2E_OBSERVER or build the p11scope binary beside this test binary"
    )
}

struct E2eWorkload {
    dir: tempfile::TempDir,
    ledger: PathBuf,
    conf: PathBuf,
}

#[derive(Clone, Copy)]
enum E2eLifetime {
    ExitAfterWork,
    HoldAfterWork,
}

impl E2eWorkload {
    fn build(module: &str) -> Result<Self> {
        Self::build_with(module, &ledger_source(), "ledger", "man1e2e")
    }

    fn build_with(module: &str, source: &Path, bin: &str, label: &str) -> Result<Self> {
        ensure!(
            Path::new(module).exists(),
            "SoftHSM2 provider {module} is missing"
        );
        ensure!(source.exists(), "fixture {} is missing", source.display());
        let dir = tempfile::tempdir()?;
        let ledger = dir.path().join(bin);
        let status = Command::new("cc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(source)
            .arg("-o")
            .arg(&ledger)
            .args(["-ldl", "-lpthread"])
            .status()
            .context("running cc")?;
        ensure!(status.success(), "{bin} build failed");
        let tokens = dir.path().join("tokens");
        std::fs::create_dir(&tokens)?;
        let conf = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )?;
        let status = Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", label])
            .args(["--so-pin", "5678", "--pin", "1234"])
            .env("SOFTHSM2_CONF", &conf)
            .stdout(Stdio::null())
            .status()
            .context("running softhsm2-util")?;
        ensure!(status.success(), "softhsm2-util --init-token failed");
        Ok(Self { dir, ledger, conf })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn spawn(
        &self,
        out: &Path,
        module: &str,
        gate: &Path,
        iters: u32,
        delay_ms: u64,
        lifetime: E2eLifetime,
    ) -> Result<E2eProcess> {
        use std::os::unix::fs::OpenOptionsExt as _;

        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
        let private_log = |path: &Path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        };
        let stderr = out.with_extension("stderr");
        let mut command = Command::new(&self.ledger);
        command.args([
            "mech",
            "--cell",
            "E",
            "--module",
            module,
            "--iters",
            &iters.to_string(),
            "--gate",
            gate.to_str().context("gate path")?,
            "--late",
            "--delay-ms",
            &delay_ms.to_string(),
        ]);
        if matches!(lifetime, E2eLifetime::HoldAfterWork) {
            command.arg("--hold");
        }
        let child = command
            .env("SOFTHSM2_CONF", &self.conf)
            .stdin(Stdio::null())
            .stdout(private_log(out)?)
            .stderr(private_log(&stderr)?)
            .die_with_parent()
            .spawn()
            .context("spawning ledger")?;
        Ok(E2eProcess {
            child,
            out: out.to_path_buf(),
            stderr,
        })
    }

    /// Spawn the `mt_sign` fixture (8 threads x 50 signs by
    /// default): `mt_sign MODULE THREADS SIGNS GATE PIN LABEL`. The
    /// fixture prints TARGET/READY, waits on the gate file, then
    /// keygens and signs after the cell opens the gate, and holds
    /// after LEDGER under MT_MIXED_HOLD=1 for the capture window.
    fn spawn_mt_sign(
        &self,
        out: &Path,
        module: &str,
        gate: &Path,
        threads: u32,
        signs: u32,
    ) -> Result<E2eProcess> {
        use std::os::unix::fs::OpenOptionsExt as _;

        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
        let private_log = |path: &Path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        };
        let stderr = out.with_extension("stderr");
        let child = Command::new(&self.ledger)
            .args([
                module,
                &threads.to_string(),
                &signs.to_string(),
                gate.to_str().context("gate path")?,
                "1234",
                "mt-sign-key",
            ])
            .env("SOFTHSM2_CONF", &self.conf)
            .env("MT_MIXED_HOLD", "1")
            .stdin(Stdio::null())
            .stdout(private_log(out)?)
            .stderr(private_log(&stderr)?)
            .die_with_parent()
            .spawn()
            .context("spawning mt_sign")?;
        Ok(E2eProcess {
            child,
            out: out.to_path_buf(),
            stderr,
        })
    }
}

struct E2eProcess {
    child: Child,
    out: PathBuf,
    stderr: PathBuf,
}

impl E2eProcess {
    fn has(&self, prefix: &str) -> bool {
        std::fs::read_to_string(&self.out)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(prefix)))
    }

    fn diagnostics(&self) -> String {
        use std::io::{Read as _, Seek as _, SeekFrom};

        fn tail(path: &Path) -> std::io::Result<Vec<String>> {
            let mut file = std::fs::File::open(path)?;
            let start = file.metadata()?.len().saturating_sub(4096);
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.take(4096).read_to_end(&mut bytes)?;
            let text = String::from_utf8_lossy(&bytes);
            let mut lines: Vec<_> = text.lines().rev().take(12).map(String::from).collect();
            lines.reverse();
            Ok(lines)
        }
        format!(
            "ledger tail={:?}; stderr tail={:?}",
            tail(&self.out),
            tail(&self.stderr)
        )
    }

    fn ensure_alive(&mut self, point: &str) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!(
                "ledger exited {point} with {status}: {}",
                self.diagnostics()
            );
        }
        Ok(())
    }

    fn wait_for(&mut self, prefix: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has(prefix) {
            if let Err(error) = self.ensure_alive(&format!("before {prefix:?}")) {
                // A finite control can publish its last line between the
                // first read and exit observation. Re-read after reaping.
                if self.has(prefix) {
                    break;
                }
                return Err(error);
            }
            ensure!(
                Instant::now() < deadline,
                "ledger {} never printed {prefix:?}: {}",
                self.out.display(),
                self.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn kill(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for E2eProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Bounded observer-log tail for failure evidence: the last 60 lines
/// within 16 KiB, so a failure carries the observer's own words.
fn observer_log_tail(log: &Path) -> Vec<String> {
    const MAX_LINES: usize = 60;
    const MAX_BYTES: usize = 16384;
    let text = match std::fs::read_to_string(log) {
        Ok(text) => text,
        Err(error) => return vec![format!("<log unreadable: {error}>")],
    };
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.len() > MAX_LINES {
        lines.drain(..lines.len() - MAX_LINES);
    }
    let mut bytes = 0;
    let mut kept = Vec::new();
    for line in lines.into_iter().rev() {
        if bytes + line.len() + 1 > MAX_BYTES {
            break;
        }
        bytes += line.len() + 1;
        kept.push(line.to_string());
    }
    kept.reverse();
    kept
}

/// One failure line carrying the observer's exit status, the report
/// path and the bounded log tail.
fn observer_evidence(log: &Path, report: &Path, status: &str) -> String {
    format!(
        "observer {status}; report={}; log tail={:?}",
        report.display(),
        observer_log_tail(log)
    )
}

/// Keep the workload directory on failure so the printed report path
/// stays readable; on success the directory drops as before.
fn keep_workload_on_failure(workload: E2eWorkload, outcome: Result<()>, tag: &str) -> Result<()> {
    if outcome.is_err() {
        eprintln!("{tag} evidence kept at {}", workload.dir.path().display());
        let _ = workload.dir.keep();
    }
    outcome
}

/// Copies of the scale cell's report and observer log exported to the
/// runner's per-test evidence dir when the cell fails, so a CI red
/// arrives root-caused. Armed at spawn time, disarmed on success; any
/// early `ensure!` bail drops the guard and copies whatever exists.
/// A missing file or an unset dir is silent: local runs without the
/// runner keep only the workload dir.
struct ScaleFailureEvidence {
    inv: PathBuf,
    observer: PathBuf,
    done: bool,
}

impl ScaleFailureEvidence {
    fn arm(inv: &Path, observer: &Path) -> Self {
        Self {
            inv: inv.to_path_buf(),
            observer: observer.to_path_buf(),
            done: false,
        }
    }

    fn disarm(&mut self) {
        self.done = true;
    }
}

impl Drop for ScaleFailureEvidence {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let Some(dir) = std::env::var_os("P11SCOPE_TASK4_EVIDENCE_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        for (src, name) in [
            (&self.inv, "scale4097-inv.json"),
            (&self.observer, "scale4097-observer.out"),
        ] {
            if std::fs::copy(src, dir.join(name)).is_ok() {
                println!("SCALE2_E2E evidence kept {name}");
            }
        }
    }
}

/// Print the shed and scan-refusal reasons behind a scale run: every
/// `semantic calls unrouted*` and `semantic scan refused` gap reason
/// from the report, bounded to whole ASCII lines. Both arms print, so
/// a pass and a fail can be compared row for row.
fn print_scale_shed_reasons(gaps: &[serde_json::Value]) {
    const MAX_CHARS: usize = 1500;
    for gap in gaps {
        let subject = gap
            .get("subject")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        if subject != "semantic calls unrouted"
            && subject != "semantic calls unrouted from other callers"
            && subject != "semantic scan refused"
        {
            continue;
        }
        let reason = gap
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let bounded: String = reason.chars().take(MAX_CHARS).collect();
        let cut = if bounded.len() < reason.len() {
            " [truncated]"
        } else {
            ""
        };
        println!("SCALE2_E2E shed subject={subject:?} reason={bounded:?}{cut}");
    }
}

#[test]
fn headline_workload_holds_after_done_without_adding_calls() -> Result<()> {
    let module = softhsm_path()?;
    let workload = E2eWorkload::build(&module)?;
    let held_out = workload.path("held.out");
    let held_gate = workload.path("held.gate");
    let mut held = workload.spawn(
        &held_out,
        &module,
        &held_gate,
        2,
        0,
        E2eLifetime::HoldAfterWork,
    )?;
    held.wait_for("READY ", Duration::from_secs(30))?;
    std::fs::write(&held_gate, b"open\n")?;
    held.wait_for("DONE ", Duration::from_secs(30))?;
    let held_ledger = std::fs::read_to_string(&held_out)?;

    // A second finite workload must finish while the headline workload
    // remains mapped, with no additional PKCS#11 calls after DONE.
    let control_out = workload.path("control.out");
    let control_gate = workload.path("control.gate");
    let mut control = workload.spawn(
        &control_out,
        &module,
        &control_gate,
        2,
        0,
        E2eLifetime::ExitAfterWork,
    )?;
    control.wait_for("READY ", Duration::from_secs(30))?;
    std::fs::write(&control_gate, b"open\n")?;
    control.wait_for("DONE ", Duration::from_secs(30))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = control.child.try_wait()? {
            break status;
        }
        ensure!(Instant::now() < deadline, "finite ledger did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    ensure!(status.success(), "finite ledger exited with {status}");
    held.ensure_alive("after DONE before the observer could stop")?;
    ensure!(
        std::fs::read_to_string(format!("/proc/{}/maps", held.child.id()))?.contains(&module),
        "held workload lost its provider mapping"
    );
    ensure!(
        std::fs::read_to_string(&held_out)? == held_ledger,
        "held ledger added calls after DONE"
    );

    let counts = |text: &str| {
        let mut counts = std::collections::BTreeMap::new();
        for line in text.lines().filter(|line| line.starts_with("LEDGER ")) {
            let fields: std::collections::BTreeMap<_, _> = line
                .split_whitespace()
                .filter_map(|field| field.split_once('='))
                .collect();
            assert_eq!(fields["bad"], "0", "ledger API call failed: {line}");
            let key = format!("{} {} {}", fields["fn"], fields["mech"], fields["phase"]);
            *counts.entry(key).or_insert(0u64) += fields["n"].parse::<u64>().unwrap();
        }
        counts
    };
    let held_counts = counts(&held_ledger);
    assert_eq!(
        held_counts
            .iter()
            .filter(|(key, _)| key.ends_with(" main"))
            .map(|(_, count)| count)
            .sum::<u64>(),
        20,
        "two iterations must retain ten calls each"
    );
    assert_eq!(held_counts, counts(&std::fs::read_to_string(&control_out)?));
    let held_pid = held.child.id();
    drop(held);
    // SAFETY: the workload was our child; Drop must have terminated and
    // reaped it, leaving no waitable child at its former PID.
    assert_eq!(
        unsafe { libc::waitpid(held_pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    Ok(())
}

#[test]
fn headline_workload_reports_early_exit_status_and_private_diagnostics() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let module = softhsm_path()?;
    let workload = E2eWorkload::build(&module)?;
    let missing = workload.path("missing-provider.so");
    let gate = workload.path("failure.gate");
    let mut target = workload.spawn(
        &workload.path("failure.out"),
        missing.to_str().context("missing provider path")?,
        &gate,
        2,
        0,
        E2eLifetime::HoldAfterWork,
    )?;
    target.wait_for("READY ", Duration::from_secs(30))?;
    std::fs::write(&gate, b"open\n")?;
    let error = target
        .wait_for("LEDGER ", Duration::from_secs(30))
        .expect_err("a missing provider must exit before any calls")
        .to_string();
    assert!(error.contains("exit status: 1"), "{error}");
    assert!(error.contains("status=fail"), "{error}");
    assert!(error.contains("stderr tail=Ok(["), "{error}");
    assert!(error.contains("realpath of a module failed"), "{error}");
    for path in [&target.out, &target.stderr] {
        assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

/// A manifest resolving exactly the ledger `mech` functions against
/// the live provider file (offsets read from the ELF, identity and
/// provenance from the held object), shaped like the discover output.
fn mech_manifest(workload: &E2eWorkload, module: &str) -> Result<PathBuf> {
    live_manifest(workload, module, MECH_FUNCTIONS, "mech-live.json")
}

/// A manifest resolving exactly `names` against the live provider
/// file (offsets read from the ELF, identity and provenance from
/// the held object), shaped like the discover output.
fn live_manifest(
    workload: &E2eWorkload,
    module: &str,
    names: &[&str],
    filename: &str,
) -> Result<PathBuf> {
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    let path = Path::new(module);
    let file = open_object(path).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(path)?;
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&elf).map_err(anyhow::Error::msg)?;
    let mut offsets = std::collections::BTreeMap::new();
    for name in names {
        let fact = snapshot
            .defined_symbol(name)
            .map_err(anyhow::Error::msg)?
            .with_context(|| format!("SoftHSM2 exports no {name}"))?;
        offsets.insert(name.to_string(), fact.file_offset);
    }
    let functions = match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
        version: cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        },
    }) {
        pkcs11_module::TableSet::Walk(spans) => spans
            .iter()
            .flat_map(|span| span.fields())
            .map(|field| {
                let resolution = match offsets.get(field.name) {
                    Some(offset) => Resolution::Resolved {
                        object: 0,
                        file_offset: *offset,
                    },
                    None => Resolution::NullPointer,
                };
                FunctionRecord {
                    name: field.name.into(),
                    resolution,
                }
            })
            .collect(),
        _ => anyhow::bail!("2.40 is a full standard table"),
    };
    let path = path.to_str().context("SoftHSM2 path")?.to_string();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: path.clone(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.clone(),
            identity: inspected.identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path,
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity: inspected.identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions,
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
        getters: Vec::new(),
    };
    ensure!(
        crate::manifest_input::validate_structure(&manifest).is_empty(),
        "the {filename} manifest is well-formed"
    );
    let manifest_path = workload.path(filename);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    Ok(manifest_path)
}

/// The v0.5.0 headline command end to end: `inventory --system
/// --manifest` over a live SoftHSM2 ledger workload exits 0 with
/// populated S1 edges (mechanisms and API results) or named
/// route-loss gaps (R-51); a run with neither fails as a silent
/// drop. The workload dlopens after the gate opens, strictly
/// post-attach: the cell opens the gate once the observer's pass 0
/// publishes (the native attach settled in its apply step). Needs an
/// observer binary via `P11SCOPE_E2E_OBSERVER` (the guest driver
/// stages one) or a `p11scope` sibling of this test binary. Prints
/// MAN1_E2E lines. Root BPF lane, serial, about a minute.
#[test]
#[ignore = "privileged: inventory --system --manifest end to end with a SoftHSM workload exits 0 with populated S1 edges or named route-loss gaps"]
fn privileged_inventory_system_manifest_e2e_softhsm_edges_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build(&module)?;
    let outcome = man1_e2e_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "MAN1_E2E")
}

fn man1_e2e_inner(workload: &E2eWorkload, module: &str, observer: &Path) -> Result<()> {
    let manifest = mech_manifest(workload, module)?;
    let out = workload.path("inv.json");
    let gate = workload.path("gate");
    let ledger_out = workload.path("ledger.out");
    let observer_out = workload.path("observer.out");
    let mut target = workload.spawn(
        &ledger_out,
        module,
        &gate,
        100_000,
        2_000,
        E2eLifetime::HoldAfterWork,
    )?;
    // READY prints before the gate wait: the workload is up and its
    // dlopen is held until the cell opens the gate post-attach.
    target.wait_for("READY ", Duration::from_secs(30))?;
    println!(
        "MAN1_E2E workload spawned pid={} gate={}",
        target.child.id(),
        gate.display()
    );
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut child = Command::new(observer)
        .args([
            "inventory",
            "--system",
            "--manifest",
            manifest.to_str().context("manifest path")?,
            "--duration",
            "25",
            "--json",
            "-o",
            out.to_str().context("out path")?,
        ])
        .stdin(Stdio::null())
        .stdout(observer_log.try_clone()?)
        .stderr(observer_log)
        .die_with_parent()
        .spawn()
        .context("spawning observer")?;
    println!("MAN1_E2E observer spawned pid={}", child.id());
    // Pass 0 publishes after its apply step extended the native
    // probes: opening the gate here keeps the dlopen strictly
    // post-attach without any sleep.
    let gate_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let published = std::fs::read_to_string(&observer_out)
            .is_ok_and(|text| text.lines().any(|line| line.contains("p11scope: pass 0:")));
        if published {
            break;
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the observer exited before pass 0: {}",
                observer_evidence(&observer_out, &out, &format!("exited {status}"))
            );
        }
        ensure!(
            Instant::now() < gate_deadline,
            "pass 0 never published (observer pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::write(&gate, b"open\n")?;
    println!("MAN1_E2E gate opened");
    let stop_deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < stop_deadline,
            "the observer never stopped (pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    target.ensure_alive("at observer stop")?;
    target.kill();
    let rc = status.code().unwrap_or(-1);
    println!("MAN1_E2E observer rc={rc}");
    ensure!(
        rc == 0,
        "inventory --system --manifest exits 0, got {rc}: {}",
        observer_evidence(&observer_out, &out, &format!("exited {status}"))
    );
    if let Ok(text) = std::fs::read_to_string(&observer_out) {
        for line in text.lines().filter(|line| line.contains("semantic calls:")) {
            println!("MAN1_E2E {line}");
        }
    }
    if let Ok(text) = std::fs::read_to_string(&ledger_out) {
        let mut lines = text.lines();
        println!("MAN1_E2E ledger head={:?}", lines.next().unwrap_or(""));
        let tail: Vec<&str> = text.lines().collect();
        println!("MAN1_E2E ledger tail={:?}", tail.last().unwrap_or(&""));
    }
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&out)?)?;
    let gaps = report
        .get("gaps")
        .and_then(serde_json::Value::as_array)
        .context("gaps array")?;
    {
        use std::collections::BTreeMap;
        let mut subjects: BTreeMap<&str, usize> = BTreeMap::new();
        for gap in gaps {
            if let Some(subject) = gap.get("subject").and_then(serde_json::Value::as_str) {
                *subjects.entry(subject).or_default() += 1;
            }
        }
        println!("MAN1_E2E gaps={subjects:?}");
        for gap in gaps.iter().filter(|gap| {
            gap.get("subject").and_then(serde_json::Value::as_str)
                == Some("semantic admission refused")
        }) {
            println!(
                "MAN1_E2E admission={}",
                gap.get("reason").unwrap_or(&serde_json::Value::Null)
            );
        }
    }
    let edges = report
        .get("semantic_edges")
        .and_then(serde_json::Value::as_array)
        .context("semantic_edges array")?;
    println!("MAN1_E2E semantic_edges={}", edges.len());
    for (index, edge) in edges.iter().enumerate().take(4) {
        println!("MAN1_E2E edge[{index}]={edge}");
    }
    // Stub edges (no calls observed for their instance) are honest
    // disclosure; the R-51 verdict below accepts populated edges or
    // a named route-loss gap, never a silent drop.
    let mut populated = 0usize;
    for edge in edges {
        let Some(mechanisms) = edge.get("mechanisms").and_then(serde_json::Value::as_array) else {
            continue;
        };
        if mechanisms.is_empty() {
            continue;
        }
        let mut calls = 0u64;
        let mut ok = false;
        for mechanism in mechanisms {
            calls += mechanism
                .get("calls")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let returns = mechanism
                .get("evidence")
                .and_then(|evidence| evidence.get("returns"))
                .and_then(serde_json::Value::as_array)
                .context("mechanism returns")?;
            ok |= returns
                .iter()
                .any(|ret| ret.get("rv").and_then(serde_json::Value::as_u64) == Some(0));
        }
        ensure!(calls > 0, "the edge records mechanism calls");
        ensure!(ok, "the edge records a CKR_OK API result");
        let api_returns = edge
            .get("api_returns")
            .and_then(|returns| returns.get("count"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        ensure!(api_returns > 0, "the edge records API returns");
        ensure!(
            edge.get("semantics").and_then(serde_json::Value::as_str) == Some("observed"),
            "the edge semantics are observed"
        );
        populated += 1;
    }
    println!("MAN1_E2E populated_edges={populated}");
    // R-51 acceptance: populated edges, or a named route-loss gap
    // disclosing why the calls stayed unrouted. A run with neither
    // is a silent drop and fails.
    let route_loss = gaps.iter().any(|gap| {
        matches!(
            gap.get("subject").and_then(serde_json::Value::as_str),
            Some("semantic calls unrouted" | "semantic admission refused")
        )
    });
    ensure!(
        populated > 0 || route_loss,
        "edges are populated or route loss is disclosed"
    );
    println!(
        "MAN1_E2E verdict={}",
        if populated > 0 {
            "edges"
        } else {
            "route-loss-gaps"
        }
    );
    let observations = report
        .get("object_observations")
        .context("object_observations")?;
    ensure!(
        observations
            .get("status")
            .and_then(serde_json::Value::as_str)
            == Some("unavailable")
            && observations
                .get("reason")
                .and_then(serde_json::Value::as_str)
                == Some("journal_unavailable"),
        "key operations stay unavailable on the S1 path"
    );
    println!("MAN1_E2E edges={} rc=0", edges.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// Scale cell: --system --manifest over 4,097+ endpoints, finite S1 stop.
// ---------------------------------------------------------------------------

/// Scale target: an explicit-budget 4,097-endpoint scale cell (the run
/// carries `--max-endpoints`, so the admission is real). Under the raised
/// inventory budget this is no longer past the product default;
/// `P11SCOPE_SCALE2_TARGET` overrides the target up to the 8,192 helper
/// cap for the controller's full-scale run. That cap is a fixture-cost
/// cap (`SCALE_MAX_COPIES=140`, about 9.5K endpoints max), not the
/// 131,072 product ceiling; anything outside 4,097..=8,192 is refused.
const SCALE_TARGET_ENDPOINTS: u64 = 4097;
const SCALE_MAX_TARGET: u64 = 8192;

/// The endpoint target for this run: the default 4,097 or the
/// `P11SCOPE_SCALE2_TARGET` override inside 4,097..=8,192.
fn scale_target() -> Result<u64> {
    match std::env::var("P11SCOPE_SCALE2_TARGET") {
        Ok(raw) => parse_scale_target(Some(&raw)),
        Err(std::env::VarError::NotPresent) => parse_scale_target(None),
        Err(error) => anyhow::bail!("P11SCOPE_SCALE2_TARGET is unreadable: {error}"),
    }
}

/// The pure target rule: default without input, the override when it
/// parses inside 4,097..=8,192, refused otherwise.
fn parse_scale_target(raw: Option<&str>) -> Result<u64> {
    let target = match raw {
        Some(text) => text
            .parse::<u64>()
            .with_context(|| format!("P11SCOPE_SCALE2_TARGET={text:?} is not a number"))?,
        None => SCALE_TARGET_ENDPOINTS,
    };
    ensure!(
        (SCALE_TARGET_ENDPOINTS..=SCALE_MAX_TARGET).contains(&target),
        "scale target {target} is outside 4097..=8192"
    );
    Ok(target)
}

#[test]
fn scale_target_defaults_to_4097_without_env() {
    assert_eq!(parse_scale_target(None).unwrap(), 4097);
}

#[test]
fn scale_target_accepts_the_8192_ceiling() {
    assert_eq!(parse_scale_target(Some("8192")).unwrap(), 8192);
}

#[test]
fn scale_target_refuses_below_default() {
    assert!(parse_scale_target(Some("4096")).is_err());
}

#[test]
fn scale_target_refuses_above_ceiling() {
    assert!(parse_scale_target(Some("8193")).is_err());
}

#[test]
fn scale_target_refuses_a_non_number() {
    assert!(parse_scale_target(Some("many")).is_err());
}

/// Exact population for near-cap targets: full SoftHSM copies plus a
/// smaller physical tail so the admitted total equals the target.
/// Returns `(full_copies, tail_endpoints)`. The ledger's original
/// provider adds one more full surface; the tail is scan-only (no
/// manifest) and `0` means no tail file is needed.
fn scale_exact_population(target: u64, per_copy: usize) -> (usize, usize) {
    let per_copy_u64 = per_copy as u64;
    let full_including_original = (target / per_copy_u64) as usize;
    let tail = (target % per_copy_u64) as usize;
    (full_including_original.saturating_sub(1), tail)
}

#[test]
fn scale_exact_8192_is_119_full_plus_32_tail() {
    assert_eq!(scale_exact_population(8192, 68), (119, 32));
}

#[test]
fn scale_exact_8160_needs_no_tail() {
    assert_eq!(scale_exact_population(8160, 68), (119, 0));
}

#[test]
fn scale_exact_8108_is_118_plus_16_tail() {
    assert_eq!(scale_exact_population(8108, 68), (118, 16));
}

#[test]
fn scale_exact_composition_hits_its_target() {
    for target in [8108u64, 8160, 8192] {
        let (full, tail) = scale_exact_population(target, 68);
        assert_eq!((full + 1) * 68 + tail, target as usize);
        assert!(tail < 68, "the tail is smaller than one full surface");
    }
}

/// Upper bound on distinct provider copies. The population stops as
/// soon as the resolved total reaches the target (or the exact
/// composition for near-cap targets); this cap only bounds a
/// degenerate surface (a symbol-read bug resolving a handful of
/// functions must fail, never spawn thousands of copies). It covers
/// the smallest valid surface (60): 135 copies plus a tail at 8192.
const SCALE_MAX_COPIES: usize = 140;

/// A full SoftHSM2 2.40 surface resolves ~68 functions. Fewer than 60
/// resolved on a copy means the manifest shape broke, not that the
/// library shrank: fail instead of compensating with more copies.
const SCALE_MIN_SURFACE: usize = 60;

/// A manifest resolving every exported function of the 2.40 walk
/// spans against one provider file, shaped like the discover output
/// (single object, like `mech_manifest`, which stays untouched for the
/// headline cell). Writes the manifest to `out` and returns the
/// resolved function count.
fn full_surface_manifest(module: &str, out: &Path) -> Result<usize> {
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    let path = Path::new(module);
    let file = open_object(path).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(path)?;
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&elf).map_err(anyhow::Error::msg)?;
    let spans = match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
        version: cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        },
    }) {
        pkcs11_module::TableSet::Walk(spans) => spans,
        _ => anyhow::bail!("2.40 is a full standard table"),
    };
    let mut resolved = 0usize;
    let functions = spans
        .iter()
        .flat_map(|span| span.fields())
        .map(|field| {
            let resolution = snapshot
                .defined_symbol(field.name)
                .map_err(anyhow::Error::msg)?
                .map(|fact| {
                    resolved += 1;
                    Resolution::Resolved {
                        object: 0,
                        file_offset: fact.file_offset,
                    }
                })
                .unwrap_or(Resolution::NullPointer);
            Ok(FunctionRecord {
                name: field.name.into(),
                resolution,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let path = path.to_str().context("provider path")?.to_string();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: path.clone(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.clone(),
            identity: inspected.identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path,
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity: inspected.identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions,
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
        getters: Vec::new(),
    };
    ensure!(
        crate::manifest_input::validate_structure(&manifest).is_empty(),
        "the scale manifest is well-formed"
    );
    std::fs::write(out, serde_json::to_vec(&manifest)?)?;
    Ok(resolved)
}

fn build_capacity_tail(directory: &Path, endpoints: usize) -> Result<(PathBuf, PathBuf)> {
    use p11scope_manifest::manifest::{Manifest, Resolution};
    use std::os::unix::fs::OpenOptionsExt as _;

    ensure!((1..=68).contains(&endpoints), "capacity tail fits legacy68");
    let matrix = capacity_matrix_source();
    ensure!(matrix.exists(), "capacity matrix fixture is missing");
    let provider = directory.join("tail.so");
    let flag = format!("-DCAPACITY_UNIQUE={endpoints}");
    let status = Command::new("cc")
        .args(["-shared", "-fPIC", &flag])
        .arg("-o")
        .arg(&provider)
        .arg(&matrix)
        .status()
        .context("building the capacity tail")?;
    ensure!(status.success(), "capacity tail build failed");
    ensure!(provider.exists(), "the capacity tail was not written");
    let manifest_path = directory.join("tail.json");
    let out = directory.join("tail-helper.out");
    let stderr = directory.join("tail-helper.stderr");
    let private_log = |path: &Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    // Use the same real helper entrypoint as lifecycle regressions, in a
    // fresh process so unrelated fixture dlopens cannot churn its maps.
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "discovery::engine::tests::lifecycle_manifest_helper_entrypoint",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env("P11SCOPE_TEST_DISCOVERY_PROVIDER", &provider)
        .env("P11SCOPE_TEST_DISCOVERY_MANIFEST", &manifest_path)
        .stdin(Stdio::null())
        .stdout(private_log(&out)?)
        .stderr(private_log(&stderr)?)
        .die_with_parent()
        .spawn()
        .context("spawning the capacity-tail helper")?;
    let mut helper = E2eProcess { child, out, stderr };
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = helper.child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < deadline,
            "capacity-tail helper did not stop: {}",
            helper.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    ensure!(
        status.success(),
        "capacity-tail helper exited with {status}: {}",
        helper.diagnostics()
    );
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let problems = crate::manifest_input::validate_structure(&manifest);
    ensure!(problems.is_empty(), "capacity-tail manifest: {problems:?}");
    ensure!(
        manifest.module_path == provider.to_str().context("capacity-tail path")?,
        "capacity-tail helper preserved the provider path"
    );
    let targets: std::collections::BTreeSet<_> = manifest
        .surfaces
        .iter()
        .flat_map(|surface| &surface.functions)
        .filter_map(|function| match function.resolution {
            Resolution::Resolved {
                object,
                file_offset,
            } => Some((object, file_offset)),
            _ => None,
        })
        .collect();
    ensure!(
        targets.len() == endpoints,
        "capacity tail resolves {} unique targets, expected {endpoints}",
        targets.len()
    );
    Ok((provider, manifest_path))
}

#[test]
#[cfg(target_pointer_width = "64")]
fn scale_tail_helper_manifest_admits_thirty_two_unique_lp64_targets() -> Result<()> {
    use crate::discovery::identity::pin_manifest_objects;
    use crate::plan::{AdmissionPolicy, AdmissionScope, build_from_sources_for_policy_scoped};
    use p11scope_manifest::elf::ElfAbi;
    use p11scope_manifest::manifest::Manifest;

    let directory = tempfile::tempdir()?;
    let (provider, manifest_path) = build_capacity_tail(directory.path(), 32)?;
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    assert_eq!(manifest.module_path, provider.to_str().unwrap());
    let problems = crate::manifest_input::validate_structure(&manifest);
    assert!(problems.is_empty(), "{problems:?}");
    let pins = pin_manifest_objects(&manifest).map_err(|errors| anyhow::anyhow!("{errors:?}"))?;
    let policy = AdmissionPolicy::inventory(
        crate::capacity::InventoryBudget::new(32, 32 * 8).map_err(anyhow::Error::msg)?,
    );
    let plan = build_from_sources_for_policy_scoped(
        &[],
        std::slice::from_ref(&manifest),
        &pins,
        policy,
        AdmissionScope::Shared,
    );
    assert_eq!(
        plan.slots.len(),
        32,
        "alias rows must deduplicate to32 targets"
    );
    assert_eq!(plan.refused_modules().count(), 0);
    for slot in &plan.slots {
        assert_eq!(pins.abi_for(slot.object), Some(ElfAbi::Lp64));
        let pinned = pins.summary(slot.object).unwrap();
        assert_eq!(pinned.path, provider.to_str().unwrap());
        assert_eq!(
            Some(pinned.sha256),
            manifest.objects[0].identity.sha256.as_deref()
        );
    }

    // The helper's input proof cannot be reused after the file changes.
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&provider)?
        .write_all(&[0])?;
    assert!(pin_manifest_objects(&manifest).is_err());
    Ok(())
}

/// Holder source: dlopens every argv path, prints READY, then sleeps
/// until killed. One process holds all scale copies mapped so system
/// discovery finds them; it makes no PKCS#11 calls itself.
const HOLDER_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        void *handle = dlopen(argv[i], RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "dlopen %s: %s\n", argv[i], dlerror());
            return 1;
        }
    }
    printf("READY handles=%d\n", argc - 1);
    fflush(stdout);
    for (;;) pause();
    return 0;
}
"#;

struct ScaleHolder {
    child: Child,
    out: PathBuf,
    err: PathBuf,
}

impl ScaleHolder {
    fn spawn(holder: &Path, out: &Path, copies: &[PathBuf]) -> Result<Self> {
        let err = out.with_extension("err");
        let child = Command::new(holder)
            .args(copies)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(out)?)
            .stderr(std::fs::File::create(&err)?)
            .die_with_parent()
            .spawn()
            .context("spawning holder")?;
        Ok(Self {
            child,
            out: out.to_path_buf(),
            err,
        })
    }

    fn wait_ready(&self, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            if std::fs::read_to_string(&self.out)
                .is_ok_and(|text| text.lines().any(|line| line.starts_with("READY ")))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let tail = std::fs::read_to_string(&self.err)
                    .map(|text| text.lines().rev().take(5).collect::<Vec<_>>().join(" | "))
                    .unwrap_or_default();
                anyhow::bail!("holder {} never printed READY: {tail}", self.out.display());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ScaleHolder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `--system --manifest` at inventory scale: 4,097+ admitted endpoints
/// over distinct provider copies stop finitely (rc 0) with the
/// semantic lane active, a populated S1 edge (mechanisms and API
/// results) for the long-running ledger caller, and the
/// `journal_unavailable` S1 marker. Strict on edges: a bound call with
/// no edge and no gap is a silent drop and fails (R-51); the
/// route-loss fallback the headline cell carries does not apply here.
/// `P11SCOPE_SCALE2_TARGET` raises the target up to 8,192 for the
/// full-scale run; near-cap targets add one smaller helper-discovered tail so
/// the admitted total equals the target exactly (119 full copies plus
/// a 32-endpoint tail at 8,192). Prints SCALE2_E2E lines. Root BPF
/// lane, serial, a few minutes.
#[test]
#[ignore = "privileged: inventory --system --manifest over 4097+ endpoints stops finitely with S1 edges for a long-running caller and the journal_unavailable disclosure"]
fn privileged_inventory_system_manifest_scale4097_softsm_edges_lp64() -> Result<()> {
    let endpoint_target = scale_target()?;
    println!("SCALE2_E2E target={endpoint_target}");
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build(&module)?;
    let outcome = scale4097_inner(&workload, &module, &observer, endpoint_target);
    keep_workload_on_failure(workload, outcome, "SCALE2_E2E")
}

fn scale4097_inner(
    workload: &E2eWorkload,
    module: &str,
    observer: &Path,
    endpoint_target: u64,
) -> Result<()> {
    // Distinct copies, one full-surface manifest each, until the
    // resolved total reaches the target past the default budget. Near
    // the 8192 cap a full-copies-only population overshoots into whole-
    // module refusals (68-endpoint granules cannot hit 8192: 120*68 =
    // 8160), so those targets use an exact composition instead: full
    // copies plus one smaller helper-discovered tail so the admitted total
    // equals the target with nothing refused.
    let first_copy = workload.path("copy-0.so");
    std::fs::copy(module, &first_copy)?;
    let first_manifest = workload.path("copy-0.json");
    let per_copy =
        full_surface_manifest(first_copy.to_str().context("copy path")?, &first_manifest)?;
    println!("SCALE2_E2E per_copy_resolved={per_copy}");
    ensure!(
        per_copy >= SCALE_MIN_SURFACE,
        "a scale copy resolves its full surface, got {per_copy}"
    );
    let mech_manifest_path = mech_manifest(workload, module)?;
    let mut manifests = vec![mech_manifest_path];
    let mut copies = vec![first_copy];
    manifests.push(first_manifest);
    // The ledger's original provider admits a full surface via the scan
    // union on top of its 15-function mech manifest (run 1: attested
    // 4163, occupied 4216 = 62*68), so the admitted demand is one full
    // surface per copy plus one for the original. When that loop total
    // would exceed the cap, size exactly with a tail instead.
    let loop_copies =
        (endpoint_target - MECH_FUNCTIONS.len() as u64).div_ceil(per_copy as u64) as usize;
    let loop_admitted = (loop_copies + 1) * per_copy;
    let tail_path: Option<PathBuf>;
    let tail_endpoints: usize;
    let total: u64;
    if loop_admitted as u64 <= SCALE_MAX_TARGET {
        let mut running = per_copy as u64 + MECH_FUNCTIONS.len() as u64;
        let mut index = 1usize;
        while running < endpoint_target {
            ensure!(
                copies.len() < SCALE_MAX_COPIES,
                "scale population hit the copy cap at {running} endpoints"
            );
            let copy = workload.path(&format!("copy-{index}.so"));
            std::fs::copy(module, &copy)?;
            let manifest_path = workload.path(&format!("copy-{index}.json"));
            let resolved =
                full_surface_manifest(copy.to_str().context("copy path")?, &manifest_path)?;
            ensure!(
                resolved == per_copy,
                "every scale copy resolves the same surface, got {resolved}"
            );
            copies.push(copy);
            manifests.push(manifest_path);
            running += per_copy as u64;
            index += 1;
        }
        tail_path = None;
        tail_endpoints = 0;
        total = running;
    } else {
        let (full, tail) = scale_exact_population(endpoint_target, per_copy);
        ensure!(
            full <= SCALE_MAX_COPIES,
            "scale population hit the copy cap at {full} copies"
        );
        ensure!(
            tail < per_copy && tail <= 68,
            "the tail fits one smaller surface, got {tail}"
        );
        for index in 1..full {
            let copy = workload.path(&format!("copy-{index}.so"));
            std::fs::copy(module, &copy)?;
            let manifest_path = workload.path(&format!("copy-{index}.json"));
            let resolved =
                full_surface_manifest(copy.to_str().context("copy path")?, &manifest_path)?;
            ensure!(
                resolved == per_copy,
                "every scale copy resolves the same surface, got {resolved}"
            );
            copies.push(copy);
            manifests.push(manifest_path);
        }
        ensure!(
            copies.len() == full,
            "the exact population holds {full} copies, got {}",
            copies.len()
        );
        if tail > 0 {
            let (tail_so, tail_manifest) = build_capacity_tail(workload.dir.path(), tail)?;
            manifests.push(tail_manifest);
            tail_path = Some(tail_so);
        } else {
            tail_path = None;
        }
        tail_endpoints = tail;
        total = MECH_FUNCTIONS.len() as u64 + full as u64 * per_copy as u64 + tail as u64;
    }
    println!(
        "SCALE2_E2E copies={} tail_endpoints={tail_endpoints} endpoints_attested={total}",
        copies.len(),
    );
    if let Some(tail) = &tail_path {
        println!("SCALE2_E2E tail_built={}", tail.display());
    }
    // The holder maps every copy before the observer starts, so pass 0
    // discovers and attaches the whole population at once.
    let holder_source = workload.path("holder.c");
    std::fs::write(&holder_source, HOLDER_SOURCE)?;
    let holder_bin = workload.path("holder");
    let status = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&holder_source)
        .arg("-o")
        .arg(&holder_bin)
        .arg("-ldl")
        .status()
        .context("running cc")?;
    ensure!(status.success(), "holder build failed");
    let holder_out = workload.path("holder.out");
    let mut holder_modules = copies.clone();
    if let Some(tail) = &tail_path {
        holder_modules.push(tail.clone());
    }
    let holder = ScaleHolder::spawn(&holder_bin, &holder_out, &holder_modules)?;
    holder.wait_ready(Duration::from_secs(60))?;
    println!(
        "SCALE2_E2E holder spawned pid={} copies={} holder_modules={}",
        holder.child.id(),
        copies.len(),
        holder_modules.len()
    );
    let out = workload.path("inv.json");
    let gate = workload.path("gate");
    let ledger_out = workload.path("ledger.out");
    let observer_out = workload.path("observer.out");
    let mut scale_evidence = ScaleFailureEvidence::arm(&out, &observer_out);
    let mut target = workload.spawn(
        &ledger_out,
        module,
        &gate,
        100_000,
        2_000,
        E2eLifetime::ExitAfterWork,
    )?;
    target.wait_for("READY ", Duration::from_secs(30))?;
    let ledger_pid = target.child.id();
    println!(
        "SCALE2_E2E workload spawned pid={ledger_pid} gate={}",
        gate.display()
    );
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut command = Command::new(observer);
    command.arg("inventory").arg("--system");
    for manifest in &manifests {
        command
            .arg("--manifest")
            .arg(manifest.to_str().context("manifest path")?);
    }
    command
        .args([
            "--max-endpoints",
            "8192",
            "--duration",
            "30",
            "--json",
            "-o",
        ])
        .arg(out.to_str().context("out path")?)
        .stdin(Stdio::null())
        .stdout(observer_log.try_clone()?)
        .stderr(observer_log);
    command.die_with_parent();
    let mut child = command.spawn().context("spawning observer")?;
    println!("SCALE2_E2E observer spawned pid={}", child.id());
    let gate_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let published = std::fs::read_to_string(&observer_out)
            .is_ok_and(|text| text.lines().any(|line| line.contains("p11scope: pass 0:")));
        if published {
            break;
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the observer exited before pass 0: {}",
                observer_evidence(&observer_out, &out, &format!("exited {status}"))
            );
        }
        ensure!(
            Instant::now() < gate_deadline,
            "pass 0 never published (observer pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::write(&gate, b"open\n")?;
    println!("SCALE2_E2E gate opened");
    let stop_deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < stop_deadline,
            "the observer never stopped (pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    target.kill();
    drop(holder);
    let rc = status.code().unwrap_or(-1);
    println!("SCALE2_E2E observer rc={rc}");
    ensure!(
        rc == 0,
        "inventory --system --manifest exits 0, got {rc}: {}",
        observer_evidence(&observer_out, &out, &format!("exited {status}"))
    );
    if let Ok(text) = std::fs::read_to_string(&observer_out) {
        for line in text.lines().filter(|line| line.contains("semantic calls:")) {
            println!("SCALE2_E2E {line}");
        }
    }
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&out)?)?;
    let occupied = report
        .get("budgets")
        .and_then(|budgets| budgets.get("endpoints"))
        .and_then(|endpoints| endpoints.get("occupied"))
        .and_then(serde_json::Value::as_u64)
        .context("budgets.endpoints.occupied")?;
    println!("SCALE2_E2E endpoints_occupied={occupied}");
    ensure!(
        occupied >= endpoint_target,
        "{endpoint_target}+ endpoints are admitted, got {occupied}"
    );
    let dir_prefix = workload
        .dir
        .path()
        .to_str()
        .context("work dir")?
        .to_string();
    let modules = report
        .get("modules")
        .and_then(serde_json::Value::as_array)
        .context("modules array")?;
    let copy_modules = modules
        .iter()
        .filter(|module| {
            module
                .get("paths")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|paths| {
                    paths.iter().any(|path| {
                        path.as_str()
                            .is_some_and(|path| path.starts_with(&dir_prefix))
                    })
                })
        })
        .count();
    println!("SCALE2_E2E copy_modules={copy_modules}");
    ensure!(
        copy_modules >= copies.len(),
        "every scale copy is a discovered module"
    );
    let gaps = report
        .get("gaps")
        .and_then(serde_json::Value::as_array)
        .context("gaps array")?;
    {
        use std::collections::BTreeMap;
        let mut subjects: BTreeMap<&str, usize> = BTreeMap::new();
        for gap in gaps {
            if let Some(subject) = gap.get("subject").and_then(serde_json::Value::as_str) {
                *subjects.entry(subject).or_default() += 1;
            }
        }
        println!("SCALE2_E2E gaps={subjects:?}");
    }
    print_scale_shed_reasons(gaps);
    let callers = report
        .get("callers")
        .and_then(serde_json::Value::as_array)
        .context("callers array")?;
    // The ledger may still hold a live caller row, or it may have
    // exited and folded into departed_use (v0.8.0 folding): either way
    // its S1 evidence must be present and populated, never silently
    // dropped. No route-loss fallback: this cell proves edges form at
    // scale.
    let ledger_caller = callers
        .iter()
        .find(|caller| {
            caller.get("pid").and_then(serde_json::Value::as_u64) == Some(u64::from(ledger_pid))
        })
        .and_then(|caller| caller.get("id"))
        .and_then(serde_json::Value::as_str);
    let folded_ledger = report
        .get("modules")
        .and_then(serde_json::Value::as_array)
        .map(|modules| {
            modules
                .iter()
                .filter_map(|module| module.get("departed_use"))
                .flat_map(|departed| {
                    departed
                        .get("identities")
                        .and_then(serde_json::Value::as_array)
                        .map(|identities| {
                            identities.iter().filter(|ident| {
                                ident.get("pid").and_then(serde_json::Value::as_u64)
                                    == Some(u64::from(ledger_pid))
                            })
                        })
                        .into_iter()
                        .flatten()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ensure!(
        ledger_caller.is_some() || !folded_ledger.is_empty(),
        "the ledger caller has a caller row or a folded identity"
    );
    if let Some(ledger_caller) = ledger_caller {
        println!("SCALE2_E2E ledger_caller={ledger_caller} (live)");
    } else {
        println!(
            "SCALE2_E2E ledger folded identities={} (exited)",
            folded_ledger.len()
        );
    }
    let edges = report
        .get("semantic_edges")
        .and_then(serde_json::Value::as_array)
        .context("semantic_edges array")?;
    println!("SCALE2_E2E semantic_edges={}", edges.len());
    // Strict R-51 verdict for the long-running caller: a populated edge
    // (mechanisms, calls, a CKR_OK API result), never a silent drop.
    let mut populated = 0usize;
    if let Some(ledger_caller) = ledger_caller {
        for edge in edges.iter().filter(|edge| {
            edge.get("caller").and_then(serde_json::Value::as_str) == Some(ledger_caller)
        }) {
            let Some(mechanisms) = edge.get("mechanisms").and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            if mechanisms.is_empty() {
                continue;
            }
            let mut calls = 0u64;
            let mut ok = false;
            for mechanism in mechanisms {
                calls += mechanism
                    .get("calls")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let returns = mechanism
                    .get("evidence")
                    .and_then(|evidence| evidence.get("returns"))
                    .and_then(serde_json::Value::as_array)
                    .context("mechanism returns")?;
                ok |= returns
                    .iter()
                    .any(|ret| ret.get("rv").and_then(serde_json::Value::as_u64) == Some(0));
            }
            ensure!(calls > 0, "the edge records mechanism calls");
            ensure!(ok, "the edge records a CKR_OK API result");
            let api_returns = edge
                .get("api_returns")
                .and_then(|returns| returns.get("count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            ensure!(api_returns > 0, "the edge records API returns");
            ensure!(
                edge.get("semantics").and_then(serde_json::Value::as_str) == Some("observed"),
                "the edge semantics are observed"
            );
            populated += 1;
        }
    } else {
        // Folded: the departed aggregate carries the same per-mechanism
        // rows (calls, CKR_OK returns) plus folded entry/API-return
        // totals. The per-edge "observed" string folds into the label
        // distribution, so the populated-mechanisms proof stands in.
        let modules = report
            .get("modules")
            .and_then(serde_json::Value::as_array)
            .context("modules array")?;
        for departed in modules
            .iter()
            .filter_map(|module| module.get("departed_use"))
        {
            let Some(mechanisms) = departed
                .get("mechanisms")
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            if mechanisms.is_empty() {
                continue;
            }
            let mut calls = 0u64;
            let mut ok = false;
            for mechanism in mechanisms {
                calls += mechanism
                    .get("calls")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                if let Some(returns) = mechanism
                    .get("evidence")
                    .and_then(|evidence| evidence.get("returns"))
                    .and_then(serde_json::Value::as_array)
                {
                    ok |= returns
                        .iter()
                        .any(|ret| ret.get("rv").and_then(serde_json::Value::as_u64) == Some(0));
                }
            }
            if calls == 0 || !ok {
                continue;
            }
            let entries = departed
                .get("entries")
                .and_then(|entries| entries.get("count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            ensure!(entries > 0, "the folded aggregate records entries");
            let api_returns = departed
                .get("instances")
                .and_then(|instances| instances.get("api_returns"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            ensure!(api_returns > 0, "the folded aggregate records API returns");
            populated += 1;
        }
    }
    println!("SCALE2_E2E populated_edges={populated}");
    ensure!(
        populated > 0,
        "the long-running caller grows a populated S1 edge"
    );
    let observations = report
        .get("object_observations")
        .context("object_observations")?;
    ensure!(
        observations
            .get("status")
            .and_then(serde_json::Value::as_str)
            == Some("unavailable")
            && observations
                .get("reason")
                .and_then(serde_json::Value::as_str)
                == Some("journal_unavailable"),
        "key operations stay unavailable on the S1 path"
    );
    println!("SCALE2_E2E edges={} rc=0", edges.len());
    scale_evidence.disarm();
    Ok(())
}

/// Judge `object_observations` against the `mt_sign` LEDGER sign
/// total. Populated: attributed rows plus the named unknown sign
/// buckets must equal the ledger exactly, every unknown sign
/// reason must be a known MT race bucket, and at least one sign
/// must land in a row (an all-unknown run would be vacuous). A
/// build without the journal pins the `journal_unavailable`
/// refusal instead of exact rows. Anything else fails as silently
/// wrong. Returns a one-line summary.
fn judge_mt_key_observations(
    observations: &serde_json::Value,
    ledger_signs: u64,
) -> Result<String> {
    let status = observations
        .get("status")
        .and_then(serde_json::Value::as_str)
        .context("object_observations status")?;
    if status == "unavailable" {
        let reason = observations
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .context("object_observations reason")?;
        ensure!(
            reason == "journal_unavailable",
            "key rows refused with {reason}, want the pinned journal_unavailable refusal"
        );
        return Ok(format!("refused={reason}"));
    }
    ensure!(
        status == "populated",
        "object_observations status is {status}, want populated or the pinned refusal"
    );
    let rows = observations
        .get("key_operations")
        .and_then(serde_json::Value::as_array)
        .context("key_operations rows")?;
    let rows_done: u64 = rows
        .iter()
        .filter(|row| row.get("category").and_then(serde_json::Value::as_str) == Some("sign"))
        .map(|row| {
            row.get("completed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    let unknown = observations
        .get("unknown_key_operations")
        .and_then(serde_json::Value::as_array)
        .context("unknown_key_operations")?;
    let mut unknown_done = 0u64;
    for bucket in unknown
        .iter()
        .filter(|bucket| bucket.get("category").and_then(serde_json::Value::as_str) == Some("sign"))
    {
        let reason = bucket
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .context("unknown sign reason")?;
        ensure!(
            reason == "key_join_lost" || reason == "unbound",
            "unknown sign bucket {reason} is not a known MT race bucket"
        );
        unknown_done += bucket
            .get("completed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
    }
    ensure!(
        rows_done + unknown_done == ledger_signs,
        "observer-vs-ledger sign mismatch: rows {rows_done} + unknown {unknown_done} != ledger {ledger_signs}"
    );
    ensure!(
        rows_done > 0,
        "no sign landed in a key row: rows 0 + unknown {unknown_done} is vacuous"
    );
    Ok(format!(
        "rows={rows_done} unknown={unknown_done} total={ledger_signs} nrows={}",
        rows.len()
    ))
}

/// Parse the `mt_sign` LEDGER line: the `key_operations.signs`
/// total, cross-checked against the C_Sign function attempts.
fn mt_sign_ledger_signs(transcript: &str) -> Result<u64> {
    for line in transcript.lines() {
        let Some(payload) = line.strip_prefix("LEDGER ") else {
            continue;
        };
        let ledger: serde_json::Value = serde_json::from_str(payload).context("LEDGER json")?;
        ensure!(
            ledger.get("complete").and_then(serde_json::Value::as_bool) == Some(true),
            "LEDGER is incomplete"
        );
        let signs = ledger
            .pointer("/key_operations/signs")
            .and_then(serde_json::Value::as_u64)
            .context("LEDGER key_operations.signs")?;
        let attempts: u64 = ledger
            .get("functions")
            .and_then(serde_json::Value::as_array)
            .context("LEDGER functions")?
            .iter()
            .filter(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some("C_Sign"))
            .map(|entry| {
                entry
                    .get("attempts")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            })
            .sum();
        ensure!(
            attempts == signs,
            "LEDGER signs {signs} disagree with C_Sign attempts {attempts}"
        );
        return Ok(signs);
    }
    anyhow::bail!("no LEDGER line in the workload transcript")
}

/// Wait until the workload edge is native-matched in the event
/// stream: an `edge_observed` record for the workload pid and the
/// TARGET provider identity whose coverage is `counted` or
/// `watched_no_use`. Inventory counts only post-match calls, so
/// the cell opens the workload gate only after the match.
fn mt_key_wait_matched(event_log: &Path, transcript: &str, pid: u32) -> Result<()> {
    let mut identity = None;
    for line in transcript.lines() {
        if let Some(payload) = line.strip_prefix("TARGET ") {
            let target: serde_json::Value = serde_json::from_str(payload).context("TARGET json")?;
            let dev = target.get("dev").context("TARGET dev")?;
            identity = Some((
                dev.get(0)
                    .and_then(serde_json::Value::as_u64)
                    .context("dev major")?,
                dev.get(1)
                    .and_then(serde_json::Value::as_u64)
                    .context("dev minor")?,
                target
                    .get("ino")
                    .and_then(serde_json::Value::as_u64)
                    .context("TARGET ino")?,
            ));
            break;
        }
    }
    let (major, minor, ino) = identity.context("no TARGET line in the workload transcript")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = std::fs::read_to_string(event_log).unwrap_or_default();
        for line in text.lines() {
            let record: serde_json::Value = match serde_json::from_str(line) {
                Ok(record) => record,
                Err(_) => continue,
            };
            if record.get("kind").and_then(serde_json::Value::as_str) != Some("edge_observed") {
                continue;
            }
            let event = record.get("event").context("edge_observed event")?;
            let context = event.get("identity_context").context("identity_context")?;
            let caller = context.get("caller").context("caller")?;
            if caller.get("pid").and_then(serde_json::Value::as_u64) != Some(u64::from(pid)) {
                continue;
            }
            let module = context.get("module").context("module")?;
            if module
                .get("device_major")
                .and_then(serde_json::Value::as_u64)
                != Some(major)
                || module
                    .get("device_minor")
                    .and_then(serde_json::Value::as_u64)
                    != Some(minor)
                || module.get("inode").and_then(serde_json::Value::as_u64) != Some(ino)
            {
                continue;
            }
            let state = event
                .pointer("/entries/coverage/state")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if state == "counted" || state == "watched_no_use" {
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "workload edge for pid {pid} never native-matched"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Multi-threaded per-key accounting: `inventory --pid --capture
/// native --key-operations --manifest` over 8 threads x 50
/// C_Sign calls in one `mt_sign` process attributes every sign
/// either to a key row or to a named MT race bucket
/// (`key_join_lost`, `unbound`): rows plus unknown equal the
/// LEDGER exactly, never silently wrong. The single-thread
/// control lands all signs in one row with zero unknown; under 8
/// threads the attributed/unknown split varies run to run while
/// the total stays exact. A build without the journal pins the
/// `journal_unavailable` refusal. Needs an observer binary via
/// `P11SCOPE_E2E_OBSERVER` or a `p11scope` sibling of this test
/// binary. Prints MTKEY lines. Root BPF lane, serial, about a
/// minute.
#[test]
#[ignore = "privileged: mt per-key sign rows plus named race buckets equal the ledger exactly"]
fn privileged_inventory_pid_key_operations_mt_sign_rows_exact() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build_with(&module, &mt_sign_source(), "mt_sign", "mtkey")?;
    let outcome = mt_key_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "MTKEY")
}

fn mt_key_inner(workload: &E2eWorkload, module: &str, observer: &Path) -> Result<()> {
    let manifest = live_manifest(workload, module, MT_SIGN_FUNCTIONS, "mtkey-live.json")?;
    let out = workload.path("inv.json");
    let event_log = workload.path("events.jsonl");
    let gate = workload.path("gate");
    let workload_out = workload.path("mt_sign.out");
    let observer_out = workload.path("observer.out");
    let mut target = workload.spawn_mt_sign(&workload_out, module, &gate, 8, 50)?;
    target.wait_for("READY ", Duration::from_secs(30))?;
    let pid = target.child.id();
    println!("MTKEY workload spawned pid={pid} gate={}", gate.display());
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut child = Command::new(observer)
        .args([
            "inventory",
            "--pid",
            &pid.to_string(),
            "--capture",
            "native",
            "--key-operations",
            "--manifest",
            manifest.to_str().context("manifest path")?,
            "--event-log",
            event_log.to_str().context("event log path")?,
            "--duration",
            "30",
            "--json",
            "-o",
            out.to_str().context("out path")?,
        ])
        .stdin(Stdio::null())
        .stdout(observer_log.try_clone()?)
        .stderr(observer_log)
        .die_with_parent()
        .spawn()
        .context("spawning observer")?;
    println!("MTKEY observer spawned pid={}", child.id());
    let needle_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let active = std::fs::read_to_string(&observer_out).is_ok_and(|text| {
            text.lines()
                .any(|line| line.contains("native usage lane active"))
        });
        if active {
            break;
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the observer exited before the usage lane activated: {}",
                observer_evidence(&observer_out, &out, &format!("exited {status}"))
            );
        }
        target.ensure_alive("before the usage lane activated")?;
        ensure!(
            Instant::now() < needle_deadline,
            "usage lane never activated (observer pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let transcript = std::fs::read_to_string(&workload_out)?;
    mt_key_wait_matched(&event_log, &transcript, pid)?;
    std::fs::write(&gate, b"open\n")?;
    println!("MTKEY gate opened");
    target.wait_for("LEDGER ", Duration::from_secs(120))?;
    let transcript = std::fs::read_to_string(&workload_out)?;
    let ledger_signs = mt_sign_ledger_signs(&transcript)?;
    target.ensure_alive("after LEDGER before the observer stopped")?;
    let stop_deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < stop_deadline,
            "the observer did not stop: {}",
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    ensure!(
        status.success(),
        "the observer exited with {status}: {}",
        observer_evidence(&observer_out, &out, &format!("exited {status}"))
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out)?).context("observer report json")?;
    let observations = report
        .get("object_observations")
        .context("object_observations")?;
    let verdict = judge_mt_key_observations(observations, ledger_signs)?;
    println!("MTKEY {verdict} ledger={ledger_signs}");
    Ok(())
}

#[test]
fn mt_key_judge_accepts_exact_populated_rows() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {"category": "sign", "completed": 378, "object": 3},
            {"category": "sign", "completed": 0, "object": 4},
        ],
        "unknown_key_operations": [
            {"category": "sign", "completed": 13, "reason": "key_join_lost"},
            {"category": "sign", "completed": 9, "reason": "unbound"},
            {"category": "generate_key_pair", "completed": 1, "reason": "not_applicable"},
        ],
    });
    assert_eq!(
        judge_mt_key_observations(&observations, 400).unwrap(),
        "rows=378 unknown=22 total=400 nrows=2"
    );
}

#[test]
fn mt_key_judge_rejects_ledger_plus_one() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [{"category": "sign", "completed": 400}],
        "unknown_key_operations": [],
    });
    let error = judge_mt_key_observations(&observations, 401).unwrap_err();
    assert!(
        format!("{error:#}").contains("observer-vs-ledger sign mismatch"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn mt_key_judge_rejects_unknown_reason_outside_the_race_buckets() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [{"category": "sign", "completed": 390}],
        "unknown_key_operations": [
            {"category": "sign", "completed": 10, "reason": "mystery"},
        ],
    });
    let error = judge_mt_key_observations(&observations, 400).unwrap_err();
    assert!(
        format!("{error:#}").contains("not a known MT race bucket"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn mt_key_judge_rejects_all_unknown_rows() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [],
        "unknown_key_operations": [
            {"category": "sign", "completed": 400, "reason": "unbound"},
        ],
    });
    let error = judge_mt_key_observations(&observations, 400).unwrap_err();
    assert!(
        format!("{error:#}").contains("vacuous"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn mt_key_judge_pins_the_journal_refusal() {
    let observations =
        serde_json::json!({"status": "unavailable", "reason": "journal_unavailable"});
    assert_eq!(
        judge_mt_key_observations(&observations, 400).unwrap(),
        "refused=journal_unavailable"
    );
}

#[test]
fn mt_key_judge_rejects_a_different_refusal() {
    let observations =
        serde_json::json!({"status": "unavailable", "reason": "bootstrap_unavailable"});
    let error = judge_mt_key_observations(&observations, 400).unwrap_err();
    assert!(
        format!("{error:#}").contains("pinned journal_unavailable refusal"),
        "unexpected error: {error:#}"
    );
}

// ---------------------------------------------------------------------------
// Key-sizes live verdicts: the judges behind the two privileged cells
// below. Shared sign accounting (rows plus named race buckets equal
// the LEDGER exactly, at least one sign proved) with per-row size
// verdicts: the sizes judge requires RSA-2048 from `sign_output`
// evidence, the off judge requires unknown sizes beside inferred
// families.
// ---------------------------------------------------------------------------

/// Shared sign accounting behind both sizes judges: populated only
/// (sizes prove nothing on a refused run), proved sign rows plus the
/// named single-thread race buckets equal the LEDGER exactly, and at
/// least one sign lands in a proved row. Returns the proved sign rows
/// with their completed counts.
fn key_sizes_sign_totals(
    observations: &serde_json::Value,
    ledger_signs: u64,
    tag: &str,
) -> Result<(Vec<serde_json::Value>, u64, u64)> {
    let status = observations
        .get("status")
        .and_then(serde_json::Value::as_str)
        .context("object_observations status")?;
    ensure!(
        status == "populated",
        "{tag}: object_observations status is {status}, want populated (sizes prove only on a populated run)"
    );
    let rows = observations
        .get("key_operations")
        .and_then(serde_json::Value::as_array)
        .context("key_operations rows")?;
    let sign_rows: Vec<serde_json::Value> = rows
        .iter()
        .filter(|row| row.get("category").and_then(serde_json::Value::as_str) == Some("sign"))
        .cloned()
        .collect();
    let rows_done: u64 = sign_rows
        .iter()
        .map(|row| {
            row.get("completed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    let unknown = observations
        .get("unknown_key_operations")
        .and_then(serde_json::Value::as_array)
        .context("unknown_key_operations")?;
    let mut unknown_done = 0u64;
    for bucket in unknown
        .iter()
        .filter(|bucket| bucket.get("category").and_then(serde_json::Value::as_str) == Some("sign"))
    {
        let reason = bucket
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .context("unknown sign reason")?;
        ensure!(
            reason == "key_join_lost" || reason == "unbound",
            "{tag}: unknown sign bucket {reason} is not a known race bucket"
        );
        unknown_done += bucket
            .get("completed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
    }
    ensure!(
        rows_done + unknown_done == ledger_signs,
        "{tag}: observer-vs-ledger sign mismatch: rows {rows_done} + unknown {unknown_done} != ledger {ledger_signs}"
    );
    ensure!(
        rows_done > 0,
        "{tag}: no sign landed in a key row: rows 0 + unknown {unknown_done} is vacuous"
    );
    Ok((sign_rows, rows_done, unknown_done))
}

/// Judge `object_observations` for the sizes run: exact sign
/// accounting, every completed sign row infers RSA-2048 from
/// `sign_output` evidence with exact completions, and families infer
/// RSA as the control.
fn judge_key_sizes_observations(
    observations: &serde_json::Value,
    ledger_signs: u64,
) -> Result<String> {
    let (sign_rows, rows_done, unknown_done) =
        key_sizes_sign_totals(observations, ledger_signs, "KEYSIZE")?;
    for row in &sign_rows {
        let completed = row
            .get("completed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if completed == 0 {
            continue;
        }
        let object = row.get("object").and_then(serde_json::Value::as_u64);
        let family = row
            .get("inferred_family")
            .context("sign row inferred_family")?;
        ensure!(
            family.get("status").and_then(serde_json::Value::as_str) == Some("inferred"),
            "KEYSIZE: object {object:?} family status is {}, want inferred",
            family.get("status").unwrap_or(&serde_json::Value::Null)
        );
        ensure!(
            family.get("value").and_then(serde_json::Value::as_str) == Some("rsa"),
            "KEYSIZE: object {object:?} family value is not rsa: {family}"
        );
        ensure!(
            family
                .get("completions")
                .and_then(serde_json::Value::as_u64)
                == Some(completed),
            "KEYSIZE: object {object:?} family completions disagree with completed {completed}: {family}"
        );
        let size = row.get("inferred_size").context("sign row inferred_size")?;
        ensure!(
            size.get("status").and_then(serde_json::Value::as_str) == Some("inferred"),
            "KEYSIZE: object {object:?} size status is {}, want inferred",
            size.get("status").unwrap_or(&serde_json::Value::Null)
        );
        let detail = size.get("detail").context("inferred size detail")?;
        ensure!(
            detail.get("kind").and_then(serde_json::Value::as_str) == Some("rsa"),
            "KEYSIZE: object {object:?} size kind is not rsa: {detail}"
        );
        ensure!(
            detail.get("size_class").and_then(serde_json::Value::as_u64) == Some(2048),
            "KEYSIZE: object {object:?} size_class is not 2048: {detail}"
        );
        ensure!(
            detail
                .get("modulus_bytes")
                .and_then(serde_json::Value::as_u64)
                == Some(256),
            "KEYSIZE: object {object:?} modulus_bytes is not 256: {detail}"
        );
        ensure!(
            detail.get("evidence").and_then(serde_json::Value::as_str) == Some("sign_output"),
            "KEYSIZE: object {object:?} size evidence is not sign_output: {detail}"
        );
        ensure!(
            size.get("completions").and_then(serde_json::Value::as_u64) == Some(completed),
            "KEYSIZE: object {object:?} size completions disagree with completed {completed}: {size}"
        );
    }
    Ok(format!(
        "rows={rows_done} unknown={unknown_done} total={ledger_signs} size=rsa2048"
    ))
}

/// Judge `object_observations` for the no-sizes twin: exact sign
/// accounting, every completed sign row carries unknown sizes (null
/// detail, zero completions), and families still infer RSA.
fn judge_key_sizes_off_observations(
    observations: &serde_json::Value,
    ledger_signs: u64,
) -> Result<String> {
    let (sign_rows, rows_done, unknown_done) =
        key_sizes_sign_totals(observations, ledger_signs, "KEYSIZE_OFF")?;
    for row in &sign_rows {
        let completed = row
            .get("completed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if completed == 0 {
            continue;
        }
        let object = row.get("object").and_then(serde_json::Value::as_u64);
        let family = row
            .get("inferred_family")
            .context("sign row inferred_family")?;
        ensure!(
            family.get("status").and_then(serde_json::Value::as_str) == Some("inferred"),
            "KEYSIZE_OFF: object {object:?} family status is {}, want inferred",
            family.get("status").unwrap_or(&serde_json::Value::Null)
        );
        ensure!(
            family.get("value").and_then(serde_json::Value::as_str) == Some("rsa"),
            "KEYSIZE_OFF: object {object:?} family value is not rsa: {family}"
        );
        ensure!(
            family
                .get("completions")
                .and_then(serde_json::Value::as_u64)
                == Some(completed),
            "KEYSIZE_OFF: object {object:?} family completions disagree with completed {completed}: {family}"
        );
        let size = row.get("inferred_size").context("sign row inferred_size")?;
        ensure!(
            size.get("status").and_then(serde_json::Value::as_str) == Some("unknown"),
            "KEYSIZE_OFF: object {object:?} size status is {}, want unknown",
            size.get("status").unwrap_or(&serde_json::Value::Null)
        );
        ensure!(
            size.get("detail").is_some_and(|detail| detail.is_null()),
            "KEYSIZE_OFF: object {object:?} size detail is not null: {size}"
        );
        ensure!(
            size.get("completions").and_then(serde_json::Value::as_u64) == Some(0),
            "KEYSIZE_OFF: object {object:?} size completions are not 0: {size}"
        );
    }
    Ok(format!(
        "rows={rows_done} unknown={unknown_done} total={ledger_signs} size=off"
    ))
}

#[test]
fn key_sizes_judge_accepts_exact_rsa2048_row() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    assert_eq!(
        judge_key_sizes_observations(&observations, 3).unwrap(),
        "rows=3 unknown=0 total=3 size=rsa2048"
    );
}

#[test]
fn key_sizes_judge_rejects_missing_size() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {"status": "unknown", "detail": null, "completions": 0},
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("want inferred"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_wrong_size_class() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 3072, "modulus_bytes": 384, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size_class"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_ledger_mismatch() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 2,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 2},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 2,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("observer-vs-ledger sign mismatch"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_accepts_unsized_row() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {"status": "unknown", "detail": null, "completions": 0},
            },
        ],
        "unknown_key_operations": [],
    });
    assert_eq!(
        judge_key_sizes_off_observations(&observations, 3).unwrap(),
        "rows=3 unknown=0 total=3 size=off"
    );
}

#[test]
fn key_sizes_off_judge_rejects_present_size() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("want unknown"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_rejects_missing_detail() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {"status": "unknown", "completions": 0},
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("detail"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_rejects_vacuous_rows() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [],
        "unknown_key_operations": [
            {"category": "sign", "completed": 3, "reason": "unbound"},
        ],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("vacuous"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_refused_run() {
    let observations = serde_json::json!({
        "status": "unavailable",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("want populated"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_unknown_reason_outside_race_buckets() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 2,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 2},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 2,
                },
            },
        ],
        "unknown_key_operations": [
            {"category": "sign", "completed": 1, "reason": "stale"},
        ],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("not a known race bucket"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_family_status() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "unknown", "value": null, "completions": 0},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family status"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_family_value() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "ec", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family value is not rsa"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_family_completions() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 2},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family completions disagree"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_wrong_size_kind() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "ec", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size kind is not rsa"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_wrong_modulus_bytes() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 128, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("modulus_bytes is not 256"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_wrong_evidence() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "encrypt_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size evidence is not sign_output"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_judge_rejects_size_completions() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 2,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size completions disagree"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_rejects_family_status() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "unknown", "value": null, "completions": 0},
                "inferred_size": {"status": "unknown", "detail": null, "completions": 0},
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family status"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_rejects_family_value() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "ec", "completions": 3},
                "inferred_size": {"status": "unknown", "detail": null, "completions": 0},
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family value is not rsa"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_rejects_family_completions() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 2},
                "inferred_size": {"status": "unknown", "detail": null, "completions": 0},
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family completions disagree"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn key_sizes_off_judge_rejects_nonzero_size_completions() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {"status": "unknown", "detail": null, "completions": 1},
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_key_sizes_off_observations(&observations, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size completions are not 0"),
        "unexpected error: {error:#}"
    );
}

/// Single-threaded RSA-2048 signs through real journal BPF to an
/// inferred size in the JSON report: `inventory --pid --capture
/// native --key-operations --key-sizes --manifest` over 1 thread x
/// 3 `mt_sign` signs lands the signs in a key row with
/// `inferred_size` RSA-2048 from `sign_output` evidence. No
/// hand-built wire records anywhere on the path: lengths arrive in
/// real END records from the length pair. Needs an observer binary
/// via `P11SCOPE_E2E_OBSERVER` or a `p11scope` sibling of this test
/// binary. Prints KEYSIZE lines. Root BPF lane, serial, about a
/// minute.
#[test]
#[ignore = "privileged: live RSA-2048 signs through real journal BPF report an inferred size"]
fn privileged_inventory_pid_key_sizes_live_sign_reports_size() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build_with(&module, &mt_sign_source(), "mt_sign", "keysize")?;
    let outcome = key_sizes_inner(&workload, &module, &observer, true);
    keep_workload_on_failure(workload, outcome, "KEYSIZE")
}

/// Twin without `--key-sizes`: the identical run reports the same
/// sign rows with no sizes (unknown status, null detail, zero
/// completions) while families still infer RSA. Prints KEYSIZE_OFF
/// lines. Root BPF lane, serial, about a minute.
#[test]
#[ignore = "privileged: live RSA-2048 signs without --key-sizes report no size"]
fn privileged_inventory_pid_key_sizes_off_live_sign_reports_no_size() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build_with(&module, &mt_sign_source(), "mt_sign", "keysize")?;
    let outcome = key_sizes_inner(&workload, &module, &observer, false);
    keep_workload_on_failure(workload, outcome, "KEYSIZE_OFF")
}

fn key_sizes_inner(
    workload: &E2eWorkload,
    module: &str,
    observer: &Path,
    key_sizes: bool,
) -> Result<()> {
    let tag = if key_sizes { "KEYSIZE" } else { "KEYSIZE_OFF" };
    let manifest = live_manifest(workload, module, MT_SIGN_FUNCTIONS, "keysize-live.json")?;
    let out = workload.path("inv.json");
    let event_log = workload.path("events.jsonl");
    let gate = workload.path("gate");
    let workload_out = workload.path("mt_sign.out");
    let observer_out = workload.path("observer.out");
    let mut target = workload.spawn_mt_sign(&workload_out, module, &gate, 1, 3)?;
    target.wait_for("READY ", Duration::from_secs(30))?;
    let pid = target.child.id();
    println!("{tag} workload spawned pid={pid} gate={}", gate.display());
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut command = Command::new(observer);
    command.args([
        "inventory",
        "--pid",
        &pid.to_string(),
        "--capture",
        "native",
        "--key-operations",
    ]);
    if key_sizes {
        command.arg("--key-sizes");
    }
    command
        .args([
            "--manifest",
            manifest.to_str().context("manifest path")?,
            "--event-log",
            event_log.to_str().context("event log path")?,
            "--duration",
            "30",
            "--json",
            "-o",
            out.to_str().context("out path")?,
        ])
        .stdin(Stdio::null())
        .stdout(observer_log.try_clone()?)
        .stderr(observer_log)
        .die_with_parent();
    let mut child = command.spawn().context("spawning observer")?;
    println!("{tag} observer spawned pid={}", child.id());
    let needle_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let active = std::fs::read_to_string(&observer_out).is_ok_and(|text| {
            text.lines()
                .any(|line| line.contains("native usage lane active"))
        });
        if active {
            break;
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the observer exited before the usage lane activated: {}",
                observer_evidence(&observer_out, &out, &format!("exited {status}"))
            );
        }
        target.ensure_alive("before the usage lane activated")?;
        ensure!(
            Instant::now() < needle_deadline,
            "usage lane never activated (observer pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let transcript = std::fs::read_to_string(&workload_out)?;
    mt_key_wait_matched(&event_log, &transcript, pid)?;
    std::fs::write(&gate, b"open\n")?;
    println!("{tag} gate opened");
    target.wait_for("LEDGER ", Duration::from_secs(120))?;
    let transcript = std::fs::read_to_string(&workload_out)?;
    let ledger_signs = mt_sign_ledger_signs(&transcript)?;
    target.ensure_alive("after LEDGER before the observer stopped")?;
    let stop_deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < stop_deadline,
            "the observer did not stop: {}",
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    ensure!(
        status.success(),
        "the observer exited with {status}: {}",
        observer_evidence(&observer_out, &out, &format!("exited {status}"))
    );
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out)?).context("observer report json")?;
    let observations = report
        .get("object_observations")
        .context("object_observations")?;
    let verdict = if key_sizes {
        judge_key_sizes_observations(observations, ledger_signs)?
    } else {
        judge_key_sizes_off_observations(observations, ledger_signs)?
    };
    println!("{tag} {verdict} ledger={ledger_signs}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Key-sizes Task 4 privacy canary: sentinel payload guards beside the live
// C_Sign length cell (S-protocol) and the live C_Verify buffers
// (V-protocol) prove no payload byte reaches the JSON report, the event
// log, the observer log (verbose text included) or any dumpable BPF map
// owned by the observer. Non-vacuity controls: every scanner must find
// an injected marker copy (positive controls), and the RSA-2048 size
// verdict must publish (the length path ran).
// ---------------------------------------------------------------------------

/// Must match `CANARY_MARK` in `tests/fixtures/public-cli/keysize_canary.c`
/// exactly; the positive-control test below pins the spelling from this
/// side, and the live cell pins it against the workload's SENTINEL line.
const KEYSIZE_CANARY_MARKER: &[u8] = b"K3YS1Z3CANARY!";

/// PKCS#11 functions the canary workload calls: setup, 3x sign+verify,
/// teardown. The cell manifest resolves exactly these.
const KEYSIZE_CANARY_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_GetSlotList",
    "C_OpenSession",
    "C_Login",
    "C_GenerateKeyPair",
    "C_SignInit",
    "C_Sign",
    "C_VerifyInit",
    "C_Verify",
    "C_DestroyObject",
    "C_Logout",
    "C_CloseSession",
    "C_Finalize",
];

fn keysize_canary_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-cli/keysize_canary.c")
}

/// The canary scanner: true when the marker appears anywhere in the
/// surface. Byte search, no decoding, so an encoded leak still matches
/// only when the raw marker bytes are present.
fn keysize_canary_scan(haystack: &[u8]) -> bool {
    haystack
        .windows(KEYSIZE_CANARY_MARKER.len())
        .any(|window| window == KEYSIZE_CANARY_MARKER)
}

/// The map-dump text scanner: the raw scan (BTF-decoded strings read
/// as ASCII) plus the hex scan (plain hex bytes of any width). It runs
/// over the `-j` document text beside the cell decoder below, covering
/// the BTF `formatted` section; it cannot read `-j` byte cells or
/// decimal renderings (pinned below), which is why the decoder exists.
fn keysize_canary_scan_map_dump(haystack: &[u8]) -> bool {
    if keysize_canary_scan(haystack) {
        return true;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut needle = Vec::with_capacity(KEYSIZE_CANARY_MARKER.len() * 2);
    for byte in KEYSIZE_CANARY_MARKER {
        needle.push(HEX[(byte >> 4) as usize]);
        needle.push(HEX[(byte & 0x0f) as usize]);
    }
    let flat: Vec<u8> = haystack
        .iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    flat.windows(needle.len()).any(|window| window == needle)
}

/// One `bpftool -j map dump` byte cell: a `"0xHH"` hex string or a
/// 0-255 int (mirrors `_raw_bytes` in
/// `scripts/dump-owned-bpf-maps.py`; bpftool versions differ).
/// Anything else fails the caller: an undecodable cell is unscanned
/// surface, not a pass.
fn keysize_canary_json_dump_cell(cell: &serde_json::Value) -> Result<u8> {
    if let Some(byte) = cell.as_u64() {
        let byte = u8::try_from(byte)
            .map_err(|_| anyhow::anyhow!("KEYCANARY: map dump cell {byte} is not a byte"))?;
        return Ok(byte);
    }
    let text = cell
        .as_str()
        .with_context(|| format!("KEYCANARY: map dump cell is not a byte: {cell}"))?;
    let hex = text
        .strip_prefix("0x")
        .with_context(|| format!("KEYCANARY: map dump cell is not 0x-hex: {text}"))?;
    ensure!(
        hex.len() == 2,
        "KEYCANARY: map dump cell is not one byte: {text}"
    );
    u8::from_str_radix(hex, 16)
        .with_context(|| format!("KEYCANARY: map dump cell is not hex: {text}"))
}

/// A `key`/`value` byte array of one `-j` entry, decoded to raw bytes.
fn keysize_canary_json_dump_array(cells: &serde_json::Value) -> Result<Vec<u8>> {
    let cells = cells
        .as_array()
        .context("KEYCANARY: map dump key/value is not an array")?;
    cells.iter().map(keysize_canary_json_dump_cell).collect()
}

/// One decoded `key`/`value` byte array of one `-j` entry: exactly
/// `expected` bytes (the map's `bytes_key`/`bytes_value` from `bpftool
/// map list -j`), or the dump fails the caller. Mirrors `_raw_bytes`
/// in `scripts/dump-owned-bpf-maps.py`, which rejects any other
/// length: a short or long cell row is a dump the cell cannot trust,
/// not a pass.
fn keysize_canary_json_dump_sized_array(
    cells: &serde_json::Value,
    expected: usize,
    what: &str,
) -> Result<Vec<u8>> {
    let bytes = keysize_canary_json_dump_array(cells)?;
    ensure!(
        bytes.len() == expected,
        "KEYCANARY: map dump {what} is not {expected} bytes: got {}",
        bytes.len()
    );
    Ok(bytes)
}

/// Raw bytes of every key/value cell in one `bpftool -j map dump`
/// document, in document order, plus the refused-cell count: entries
/// carry `key` plus `value` (or per-CPU `values`), with optional BTF
/// `formatted` the text scan already covers. Every decoded key must be
/// exactly `key_len` bytes and every readable value exactly `value_len`
/// bytes (the map's `bytes_key`/`bytes_value` from `bpftool map list
/// -j`); a short or long row fails the caller. A `value` may also be
/// the exact refusal blob `{"error": "<glibc strerror>"}` bpftool
/// emits when the kernel refuses a cell lookup (`cgroup_array`: its
/// kernel lookup returns -EOPNOTSUPP, and userspace receives -ENOTSUPP
/// because the map ops define no `map_fd_sys_lookup_elem` — see
/// `probe_refused_lookup` in `scripts/dump-owned-bpf-maps.py`); a
/// refused cell holds no bytes
/// for the decoder, so it skips the value-length check — but it still
/// counts, and its key still scans and must be exactly `key_len`
/// bytes. The caller gates the count on the map kind (only
/// `cgroup_array` may refuse): a refused cell is unscanned surface,
/// not a pass. The blob shape is exact (one `error` string key): the
/// strerror text itself is a glibc fact, not a kernel fact, so it is
/// never asserted. Per-CPU `values` must be non-empty (an empty array
/// contributes zero bytes and would pass thin); full
/// possible-CPU-set parity stays out of scope (the cell carries no
/// possible-CPU metadata). Strict shape otherwise (mirrors
/// `normalize_map_dump`): an unknown field fails the caller, so a
/// dump the cell cannot decode fails closed instead of passing thin.
///
/// The typed decode result: every decoded byte, the number of map cells
/// (entries) decoded, and the refused-cell count with the lookup error
/// strings bpftool reported. The strings stay diagnostic text; the shape
/// check above remains the strict gate.
struct KeysizeCanaryJsonDump {
    bytes: Vec<u8>,
    cells: usize,
    refused: usize,
    refusal_errors: Vec<String>,
}

fn keysize_canary_json_dump_cells(
    dump: &[u8],
    key_len: usize,
    value_len: usize,
) -> Result<KeysizeCanaryJsonDump> {
    let parsed: serde_json::Value =
        serde_json::from_slice(dump).context("KEYCANARY: map dump is not JSON")?;
    let entries = parsed
        .as_array()
        .context("KEYCANARY: map dump is not an array")?;
    let mut out = Vec::new();
    let mut cells = 0usize;
    let mut refused = 0usize;
    let mut refusal_errors = Vec::new();
    for entry in entries {
        let object = entry
            .as_object()
            .context("KEYCANARY: map dump entry is not an object")?;
        if let Some(formatted) = object.get("formatted") {
            ensure!(
                formatted.is_object(),
                "KEYCANARY: map dump formatted section is not an object"
            );
        }
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        match keys.as_slice() {
            ["formatted", "key", "value"] | ["key", "value"] => {
                out.extend(keysize_canary_json_dump_sized_array(
                    &object["key"],
                    key_len,
                    "key",
                )?);
                if let Some(blob) = object["value"].as_object() {
                    let error_text = match (
                        blob.len(),
                        blob.get("error").and_then(serde_json::Value::as_str),
                    ) {
                        (1, Some(error)) => error,
                        _ => anyhow::bail!(
                            "KEYCANARY: map dump refused cell is not {{\"error\": str}}"
                        ),
                    };
                    refused += 1;
                    refusal_errors.push(error_text.to_string());
                } else {
                    out.extend(keysize_canary_json_dump_sized_array(
                        &object["value"],
                        value_len,
                        "value",
                    )?);
                }
            }
            ["formatted", "key", "values"] | ["key", "values"] => {
                out.extend(keysize_canary_json_dump_sized_array(
                    &object["key"],
                    key_len,
                    "key",
                )?);
                let rows = object["values"]
                    .as_array()
                    .context("KEYCANARY: map dump values is not an array")?;
                ensure!(
                    !rows.is_empty(),
                    "KEYCANARY: map dump per-CPU values are empty"
                );
                for row in rows {
                    let row = row
                        .as_object()
                        .context("KEYCANARY: map dump per-CPU row is not an object")?;
                    ensure!(
                        row.len() == 2 && row.contains_key("cpu") && row.contains_key("value"),
                        "KEYCANARY: map dump per-CPU row is not {{cpu, value}}"
                    );
                    ensure!(
                        row["cpu"]
                            .as_u64()
                            .is_some_and(|cpu| cpu <= u64::from(u32::MAX)),
                        "KEYCANARY: map dump per-CPU row has no u32 cpu"
                    );
                    out.extend(keysize_canary_json_dump_sized_array(
                        &row["value"],
                        value_len,
                        "value",
                    )?);
                }
            }
            _ => anyhow::bail!("KEYCANARY: map dump entry has unexpected fields: {keys:?}"),
        }
        cells += 1;
    }
    Ok(KeysizeCanaryJsonDump {
        bytes: out,
        cells,
        refused,
        refusal_errors,
    })
}

/// Whether the marker appears in any decoded key/value cell of one
/// `-j` dump, plus the refused-cell count. Runs beside the text scan
/// (which covers BTF `formatted` ASCII); a dump that is not decodable
/// fails the caller. `key_len`/`value_len` are the map's
/// `bytes_key`/`bytes_value` widths; the caller gates `refused` on
/// the map kind.
fn keysize_canary_json_dump_marked(
    dump: &[u8],
    key_len: usize,
    value_len: usize,
) -> Result<(bool, usize)> {
    let decoded = keysize_canary_json_dump_cells(dump, key_len, value_len)?;
    Ok((keysize_canary_scan(&decoded.bytes), decoded.refused))
}

/// The refused-cell gate: refused cells are legitimate on exactly one
/// map kind. `cgroup_array` has a kernel lookup that returns
/// -EOPNOTSUPP, while userspace receives -ENOTSUPP because the map ops
/// define no `map_fd_sys_lookup_elem`; its dumps therefore carry
/// per-cell refusal blobs by kernel design. Any other kind with a
/// refused cell is unscanned surface hiding behind a "dumped" label
/// and fails the caller.
fn keysize_canary_refused_gate(kind: &str, refused: usize) -> Result<()> {
    ensure!(
        refused == 0 || kind == "cgroup_array",
        "KEYCANARY: {refused} refused cells on a {kind} map: only cgroup_array may refuse lookups"
    );
    Ok(())
}

/// The distinct refusal texts in stable order, for the failure context.
/// They are bpftool/glibc diagnostic strings, never asserted as kernel
/// facts; carrying them through only makes a refusal cause visible.
fn keysize_canary_refusal_errors_text(errors: &[String]) -> String {
    let unique: std::collections::BTreeSet<&str> = errors.iter().map(String::as_str).collect();
    unique.into_iter().collect::<Vec<_>>().join("; ")
}

/// Whether an empty dump can be the true state of this map kind. Hash
/// family maps legitimately drain to zero entries (for example PAUSE_PIDS
/// after its authorization is removed), and program arrays are sparse
/// slots (STACK_GUARD is deliberately never populated). Plain and
/// per-CPU arrays enumerate every index and therefore cannot validly
/// dump zero cells. The scan-level aggregate still requires at least one
/// decoded cell across every owned map.
fn keysize_canary_kind_may_dump_empty(kind: &str) -> bool {
    matches!(
        kind,
        "hash" | "percpu_hash" | "lru_hash" | "lru_percpu_hash" | "prog_array"
    )
}

/// Verify one raw `bpftool -j` map dump against everything the live cell
/// needs from it, without command or process I/O: the map must have both
/// widths in the same `map list` snapshot, its text and decoded cells must
/// not carry the marker, every row must decode at those widths, refusals
/// must pass the kind gate, and a kind that cannot validly be empty must
/// decode at least one map cell. Returns the decoded cell count. A refused
/// non-`cgroup_array` cell fails once — no retry — with bpftool's refusal
/// text in the message so a lookup-time churn race is distinguishable from
/// an unexplained refusal.
fn keysize_canary_verify_map_dump(
    name: &str,
    id: u32,
    kind: &str,
    dump: &[u8],
    widths: Option<(usize, usize)>,
) -> Result<usize> {
    let (key_len, value_len) = widths.with_context(|| {
        format!("KEYCANARY: owned map {name} ({id}/{kind}) has no key/value widths in the map list")
    })?;
    ensure!(
        !keysize_canary_scan_map_dump(dump),
        "KEYCANARY: canary marker leaked into BPF map {name} ({id}/{kind})"
    );
    let decoded = keysize_canary_json_dump_cells(dump, key_len, value_len).with_context(|| {
        format!("KEYCANARY: cannot decode the BPF map {name} ({id}/{kind}) dump")
    })?;
    keysize_canary_refused_gate(kind, decoded.refused).with_context(|| {
        format!(
            "KEYCANARY: BPF map {name} ({id}/{kind}) refused {} cell lookups (lookup errors: {})",
            decoded.refused,
            keysize_canary_refusal_errors_text(&decoded.refusal_errors)
        )
    })?;
    ensure!(
        decoded.cells > 0 || keysize_canary_kind_may_dump_empty(kind),
        "KEYCANARY: BPF map {name} ({id}/{kind}) decoded zero cells on a kind that cannot validly be empty"
    );
    ensure!(
        !keysize_canary_scan(&decoded.bytes),
        "KEYCANARY: canary marker leaked into BPF map {name} ({id}/{kind}) cells"
    );
    Ok(decoded.cells)
}

/// The scan-level verdict. Individual hash-family maps may be empty as
/// their true state, and program arrays may be empty as sparse state, but
/// a scan with no dumped maps, no `EVIDENCE_START` dump, or zero scanned
/// cells proves nothing and must not pass. Refused entries carry no value
/// bytes, so they do not count as scanned cells in the total.
fn keysize_canary_scan_verdict(dumped: &[String], cells: u64, refused: u64) -> Result<()> {
    ensure!(
        !dumped.is_empty(),
        "KEYCANARY: no BPF maps dumped for the observer: refusing a vacuous scan"
    );
    ensure!(
        keysize_canary_dumped_covers_evidence_start(dumped),
        "KEYCANARY: EVIDENCE_START is missing from the dumped maps: {dumped:?}"
    );
    let scanned = cells.checked_sub(refused).with_context(|| {
        format!("KEYCANARY: refused cells ({refused}) exceed decoded cells ({cells})")
    })?;
    ensure!(
        scanned > 0,
        "KEYCANARY: scanned zero cells across all owned BPF maps (decoded={cells}, refused={refused}): refusing a vacuous scan"
    );
    Ok(())
}

/// The live hex positive-control input: the marker hex-encoded in
/// `bpftool -j` cell layout. The text passes cannot read this encoding
/// (pinned below), so the control proves the JSON decode path live.
const KEYSIZE_CANARY_JSON_HEX_CONTROL: &[u8] = br#"[{"key": ["0x00"], "value": ["0x4b", "0x33", "0x59", "0x53", "0x31", "0x5a", "0x33", "0x43", "0x41", "0x4e", "0x41", "0x52", "0x59", "0x21"]}]"#;

/// Positive control, unit side: the scanner finds an injected marker in
/// an otherwise clean report copy. If this fails, the live scan is
/// vacuous and the cell must fail.
#[test]
fn keysize_canary_scanner_finds_an_injected_marker() {
    let clean = br#"{"object_observations":{"status":"populated","key_operations":[]}}"#;
    assert!(
        !keysize_canary_scan(clean),
        "the scanner is silent on a clean report"
    );
    let mut injected = clean.to_vec();
    injected.extend_from_slice(b" ");
    injected.extend_from_slice(KEYSIZE_CANARY_MARKER);
    assert!(
        keysize_canary_scan(&injected),
        "the scanner finds an injected marker"
    );
}

/// The scanner pins the marker spelling: a truncated or mistyped marker
/// is not the canary and must not match.
#[test]
fn keysize_canary_scanner_pins_the_marker_spelling() {
    assert_eq!(KEYSIZE_CANARY_MARKER, b"K3YS1Z3CANARY!");
    assert!(!keysize_canary_scan(b"K3YS1Z3CANARY"), "truncated");
    assert!(!keysize_canary_scan(b"K3YS1Z3CANARX!"), "mistyped");
    assert!(keysize_canary_scan(b"xxK3YS1Z3CANARY!yy"), "embedded");
}

/// The map-dump scanner is silent on a clean bpftool-style hex dump
/// and finds marker bytes in every dump encoding: BTF-decoded ASCII,
/// spaced lowercase hex, and uppercase hex across line breaks.
#[test]
fn keysize_canary_map_dump_scanner_finds_every_dump_encoding() {
    let clean = b"key: 00 00 00 00  value:\n01 00 00 00 00 00 00 00";
    assert!(
        !keysize_canary_scan_map_dump(clean),
        "silent on a clean hex dump"
    );
    assert!(
        !keysize_canary_scan_map_dump(b""),
        "silent on an empty dump"
    );
    assert!(
        !keysize_canary_scan_map_dump(b"key: 4b 33"),
        "silent on a short dump"
    );
    let ascii = b"value: { .buf = \"K3YS1Z3CANARY!\" }";
    assert!(
        keysize_canary_scan_map_dump(ascii),
        "finds BTF-decoded ASCII"
    );
    // K3YS1Z3CANARY! as spaced lowercase hex (one line and wrapped).
    let hex = b"key: 00 00 00 00  value: 4b 33 59 53 31 5a 33 43 41 4e 41 52 59 21";
    assert!(keysize_canary_scan_map_dump(hex), "finds spaced hex");
    let wrapped = b"value:\n4B 33 59 53 31 5A 33 43\n41 4E 41 52 59 21\n00 00 00 00";
    assert!(
        keysize_canary_scan_map_dump(wrapped),
        "finds wrapped uppercase hex"
    );
    // A truncated hex tail (13 of 14 bytes) is not the marker.
    let short = b"value: 4b 33 59 53 31 5a 33 43 41 4e 41 52 59";
    assert!(
        !keysize_canary_scan_map_dump(short),
        "a 13-byte hex tail does not match"
    );
}

/// The `-j` decoder finds the marker in raw cells, hex-string or
/// decimal-int: bpftool versions differ (mirrors `_raw_bytes` in
/// `scripts/dump-owned-bpf-maps.py`), so both encodings decode.
#[test]
fn keysize_canary_json_dump_scanner_finds_marker_in_raw_cells() {
    let hex = br#"[{"key": ["0x00", "0x00"], "value": ["0x4b", "0x33", "0x59", "0x53", "0x31", "0x5a", "0x33", "0x43", "0x41", "0x4e", "0x41", "0x52", "0x59", "0x21"], "formatted": {"key": 0, "value": {}}}]"#;
    assert!(
        keysize_canary_json_dump_marked(hex, 2, 14).unwrap().0,
        "finds the marker in 0x-hex cells beside formatted output"
    );
    let decimal =
        br#"[{"key": [0, 0], "value": [75, 51, 89, 83, 49, 90, 51, 67, 65, 78, 65, 82, 89, 33]}]"#;
    assert!(
        keysize_canary_json_dump_marked(decimal, 2, 14).unwrap().0,
        "finds the marker in decimal-int cells"
    );
    let in_key = br#"[{"key": ["0x4b", "0x33", "0x59", "0x53", "0x31", "0x5a", "0x33", "0x43", "0x41", "0x4e", "0x41", "0x52", "0x59", "0x21"], "value": ["0x00"]}]"#;
    assert!(
        keysize_canary_json_dump_marked(in_key, 14, 1).unwrap().0,
        "finds the marker in key cells too"
    );
    let upper = br#"[{"key": ["0x00"], "value": ["0x4B", "0x33", "0x59", "0x53", "0x31", "0x5A", "0x33", "0x43", "0x41", "0x4E", "0x41", "0x52", "0x59", "0x21"]}]"#;
    assert!(
        keysize_canary_json_dump_marked(upper, 1, 14).unwrap().0,
        "finds the marker in uppercase hex digits"
    );
}

/// The `-j` decoder reads per-CPU `values` rows, not just `value`.
#[test]
fn keysize_canary_json_dump_scanner_finds_marker_in_percpu_values() {
    let dump = br#"[{"key": ["0x00", "0x00", "0x00", "0x00"], "values": [{"cpu": 0, "value": ["0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00"]}, {"cpu": 1, "value": ["0x4b", "0x33", "0x59", "0x53", "0x31", "0x5a", "0x33", "0x43", "0x41", "0x4e", "0x41", "0x52", "0x59", "0x21"]}]}]"#;
    assert!(
        keysize_canary_json_dump_marked(dump, 4, 14).unwrap().0,
        "finds the marker in the second CPU row"
    );
    let clean = br#"[{"key": ["0x00"], "values": [{"cpu": 0, "value": ["0x00"]}]}]"#;
    assert!(
        !keysize_canary_json_dump_marked(clean, 1, 1).unwrap().0,
        "silent on clean per-CPU rows"
    );
}

/// Empty per-CPU values fail closed (tier-1 F1): a `values: []`
/// entry contributes zero value bytes, so accepting it would pass an
/// unscanned entry thin. The oracle rejects it (`malformed per-CPU
/// values` in `scripts/dump-owned-bpf-maps.py`); full
/// possible-CPU-set parity stays out of scope (the cell carries no
/// possible-CPU metadata).
#[test]
fn keysize_canary_json_dump_scanner_rejects_empty_percpu_values() {
    assert!(
        keysize_canary_json_dump_marked(br#"[{"key": ["0x00"], "values": []}]"#, 1, 1).is_err(),
        "empty per-CPU values fail closed"
    );
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "values": [], "formatted": {"key": 0, "value": {}}}]"#,
            1,
            1
        )
        .is_err(),
        "empty per-CPU values fail closed beside formatted output"
    );
}

/// The `-j` decoder is silent on clean cells and on empty dumps (an
/// empty map dumps `[]`, which is clean, not malformed).
#[test]
fn keysize_canary_json_dump_scanner_is_silent_on_clean_dumps() {
    let clean =
        br#"[{"key": ["0x00"], "value": ["0x00", "0x01"]}, {"key": ["0x01"], "value": [2, 3]}]"#;
    assert!(
        !keysize_canary_json_dump_marked(clean, 1, 2).unwrap().0,
        "silent on clean hex and decimal cells"
    );
    assert!(
        !keysize_canary_json_dump_marked(b"[]", 1, 1).unwrap().0,
        "silent on an empty map dump"
    );
}

/// The `-j` decoder fails closed: every malformed shape errors, so a
/// dump the cell cannot decode fails the cell instead of passing thin.
/// Plain (non-`-j`) dumps are not JSON, so a `-j` regression fails here
/// rather than silently text-scanning.
#[test]
fn keysize_canary_json_dump_scanner_fails_closed_on_malformed_dumps() {
    // Not JSON at all, and valid JSON of the wrong shape.
    assert!(keysize_canary_json_dump_marked(b"not json", 1, 1).is_err());
    assert!(keysize_canary_json_dump_marked(br#"{"key": []}"#, 1, 1).is_err());
    assert!(keysize_canary_json_dump_marked(b"[42]", 1, 1).is_err());
    // A plain-text dump (the `-j` flag dropped) is not JSON: fail closed.
    let plain = b"key: 00 00 00 00  value: 4b 33 59 53 31 5a 33 43 41 4e 41 52 59 21";
    assert!(keysize_canary_json_dump_marked(plain, 1, 1).is_err());
    // Entries with unexpected fields, and rows that are not {cpu, value}.
    assert!(keysize_canary_json_dump_marked(br#"[{"key": ["0x00"]}]"#, 1, 1).is_err());
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "value": ["0x00"], "extra": []}]"#,
            1,
            1
        )
        .is_err()
    );
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "value": ["0x00"], "formatted": []}]"#,
            1,
            1
        )
        .is_err()
    );
    assert!(
        keysize_canary_json_dump_marked(br#"[{"key": ["0x00"], "values": [{"cpu": 0}]}]"#, 1, 1)
            .is_err()
    );
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "values": [{"cpu": -1, "value": ["0x00"]}]}]"#,
            1,
            1
        )
        .is_err()
    );
    // Cells that are not bytes.
    for bad in [
        br#"[{"key": ["0x00"], "value": ["0xZZ"]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": ["0x4"]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": ["0x4b00"]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": ["0X4B"]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": ["75"]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": [""]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": [256]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": [-1]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": [true]}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": "0x00"}]"#.as_slice(),
    ] {
        assert!(
            keysize_canary_json_dump_marked(bad, 1, 1).is_err(),
            "malformed cell fails closed: {}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// The `-j` decoder accepts refused cells: a `value` that is exactly
/// `{"error": "<strerror>"}` carries no bytes (the kernel refused the
/// lookup), but the entry key still scans and a marked key still fails.
/// The blob shape is exact; anything else dict-shaped fails closed.
#[test]
fn keysize_canary_json_dump_scanner_accepts_refused_cells() {
    let refused =
        br#"[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": {"error": "Unknown error 524"}}]"#;
    assert!(
        !keysize_canary_json_dump_marked(refused, 4, 4).unwrap().0,
        "a refused cell with a clean key is clean"
    );
    let marked_key = br#"[{"key": ["0x4b", "0x33", "0x59", "0x53", "0x31", "0x5a", "0x33", "0x43", "0x41", "0x4e", "0x41", "0x52", "0x59", "0x21"], "value": {"error": "Unknown error 524"}}]"#;
    assert!(
        keysize_canary_json_dump_marked(marked_key, 14, 4)
            .unwrap()
            .0,
        "a refused cell with a marked key still fails"
    );
    let mixed = br#"[{"key": ["0x00"], "value": {"error": "Unknown error 524"}}, {"key": ["0x01"], "value": ["0x4b", "0x33", "0x59", "0x53", "0x31", "0x5a", "0x33", "0x43", "0x41", "0x4e", "0x41", "0x52", "0x59", "0x21"]}]"#;
    assert!(
        keysize_canary_json_dump_marked(mixed, 1, 14).unwrap().0,
        "a marked readable cell beside a refused cell still fails"
    );
    // Dict-shaped values that are not exactly {"error": str} fail closed.
    for bad in [
        br#"[{"key": ["0x00"], "value": {"error": 524}}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": {"error": "x", "extra": 1}}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": {"errno": 524}}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": {}}]"#.as_slice(),
        br#"[{"key": ["0x00"], "value": 42}]"#.as_slice(),
    ] {
        assert!(
            keysize_canary_json_dump_marked(bad, 1, 1).is_err(),
            "a malformed refused cell fails closed: {}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// The `-j` decoder counts refused cells: the count the live loop
/// gates on the map kind. Readable cells never count, refused cells
/// always do — an uncounted refusal would be unscanned surface
/// passing as clean.
#[test]
fn keysize_canary_json_dump_scanner_counts_refused_cells() {
    let clean = br#"[{"key": ["0x00"], "value": ["0x00"]}]"#;
    assert_eq!(
        keysize_canary_json_dump_marked(clean, 1, 1).unwrap(),
        (false, 0),
        "readable cells count zero refusals"
    );
    assert_eq!(
        keysize_canary_json_dump_marked(b"[]", 1, 1).unwrap(),
        (false, 0),
        "an empty dump counts zero refusals"
    );
    // Two refused cgroup_array-shaped entries (4-byte keys, the real
    // fd-array widths) count two.
    let two = br#"[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": {"error": "Unknown error 524"}}, {"key": ["0x01", "0x00", "0x00", "0x00"], "value": {"error": "Unknown error 524"}}]"#;
    assert_eq!(
        keysize_canary_json_dump_marked(two, 4, 4).unwrap(),
        (false, 2),
        "every refused entry counts"
    );
    let mixed = br#"[{"key": ["0x00"], "value": {"error": "Unknown error 524"}}, {"key": ["0x01"], "value": ["0x00"]}]"#;
    assert_eq!(
        keysize_canary_json_dump_marked(mixed, 1, 1).unwrap(),
        (false, 1),
        "a readable cell beside a refused cell does not count"
    );
}

/// The refused-cell gate admits refusals on exactly one map kind: a
/// refused cell on any other kind is unscanned surface hiding behind
/// a "dumped" label (a hash map whose every lookup failed would pass
/// unscanned and still count as dumped, including `EVIDENCE_START`).
#[test]
fn keysize_canary_refused_gate_admits_only_cgroup_array_refusals() {
    for kind in [
        "hash",
        "lru_hash",
        "array",
        "prog_array",
        "percpu_hash",
        "percpu_array",
        "ringbuf",
        "task_storage",
    ] {
        assert!(
            keysize_canary_refused_gate(kind, 1).is_err(),
            "{kind} with a refused cell fails closed"
        );
        assert!(
            keysize_canary_refused_gate(kind, 64).is_err(),
            "{kind} with many refused cells fails closed"
        );
        assert!(
            keysize_canary_refused_gate(kind, 0).is_ok(),
            "{kind} with zero refusals passes"
        );
    }
    for refused in [0, 1, 64] {
        assert!(
            keysize_canary_refused_gate("cgroup_array", refused).is_ok(),
            "cgroup_array with {refused} refusals passes"
        );
    }
    // The kind match is exact: a near-miss spelling does not pass.
    assert!(keysize_canary_refused_gate("CGROUP_ARRAY", 1).is_err());
    assert!(keysize_canary_refused_gate("cgroup_array ", 1).is_err());
    assert!(keysize_canary_refused_gate("", 1).is_err());
}

/// The pure per-dump verifier wires the kind gate into the live path:
/// a refused hash cell fails once (no retry), with the map identity and
/// bpftool's refusal text in the error so a lookup-time churn race is
/// diagnosable. The same refusal shape remains legitimate on exactly
/// `cgroup_array` and counts as one decoded entry, not one scanned cell.
#[test]
fn keysize_canary_verify_map_dump_rejects_refused_cells_off_cgroup_array() {
    let dump = br#"[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": {"error": "No such file or directory"}}]"#;
    let error = keysize_canary_verify_map_dump("EVIDENCE_START", 9, "hash", dump, Some((4, 4)))
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(
        error.contains("EVIDENCE_START (9/hash)"),
        "the map identity is missing: {error}"
    );
    assert!(
        error.contains("1 refused cells on a hash map"),
        "the kind gate is missing: {error}"
    );
    assert!(
        error.contains("No such file or directory"),
        "the refusal text is missing: {error}"
    );
    assert_eq!(
        keysize_canary_verify_map_dump("CGROUP_FILTER", 7, "cgroup_array", dump, Some((4, 4)))
            .unwrap(),
        1,
        "a cgroup_array refusal is admitted and counts as a decoded entry, not a scanned cell"
    );
}

/// The pure verifier owns the live width lookup: a map absent from the
/// width table cannot have its rows length-checked, so it errors before
/// decoding instead of passing thin.
#[test]
fn keysize_canary_verify_map_dump_rejects_absent_widths() {
    let dump = br#"[{"key": ["0x00"], "value": ["0x00"]}]"#;
    let error =
        keysize_canary_verify_map_dump("EVIDENCE_START", 9, "hash", dump, None).unwrap_err();
    let error = format!("{error:#}");
    assert!(
        error.contains("EVIDENCE_START (9/hash) has no key/value widths"),
        "unexpected error: {error}"
    );
}

/// The pure verifier returns the number of decoded map cells. It refuses
/// an all-empty plain-array dump (arrays enumerate every index) while
/// accepting an all-empty hash or program-array dump as a true empty or
/// sparse map. The scan-level verdict refuses zero scanned cells in total,
/// so every map dumping `[]` still fails the live cell.
#[test]
fn keysize_canary_verify_map_dump_counts_cells_and_checks_empty_dumps() {
    let dump =
        br#"[{"key": ["0x00"], "value": ["0x00", "0x01"]}, {"key": ["0x01"], "value": [2, 3]}]"#;
    assert_eq!(
        keysize_canary_verify_map_dump("EVIDENCE_START", 9, "hash", dump, Some((1, 2))).unwrap(),
        2,
        "two decoded entries count as two cells"
    );
    let error =
        keysize_canary_verify_map_dump("COUNTERS", 9, "array", b"[]", Some((1, 1))).unwrap_err();
    assert!(
        format!("{error:#}").contains("decoded zero cells"),
        "unexpected error: {error:#}"
    );
    assert_eq!(
        keysize_canary_verify_map_dump("PAUSE_PIDS", 10, "hash", b"[]", Some((1, 1))).unwrap(),
        0,
        "an empty hash-family dump is a true empty map, not a malformed dump"
    );
    assert_eq!(
        keysize_canary_verify_map_dump("STACK_GUARD", 11, "prog_array", b"[]", Some((4, 4)))
            .unwrap(),
        0,
        "an empty program array is sparse empty state, not a malformed dump"
    );
}

/// The scan-level verdict is an exact table: the dumped-list check comes
/// first, `EVIDENCE_START` coverage comes before the total, and the total
/// counts only scanned cells (`cells - refused`). An empty hash-family or
/// program-array dump can be true state, but if every map dumps empty the
/// scan is vacuous; likewise, refusals alone prove nothing because they
/// carry no value bytes.
#[test]
fn keysize_canary_scan_verdict_exact_table() {
    let verdict = |dumped: &[String], cells: u64, refused: u64| {
        keysize_canary_scan_verdict(dumped, cells, refused).map_err(|error| format!("{error:#}"))
    };
    let evidence = || vec!["EVIDENCE_START (9)".to_string()];
    let no_evidence = || vec!["PAUSE_PIDS (10)".to_string()];
    let cases = [
        (
            vec![],
            7,
            0,
            Err("KEYCANARY: no BPF maps dumped for the observer: refusing a vacuous scan"
                .to_string()),
        ),
        (
            no_evidence(),
            0,
            0,
            Err("KEYCANARY: EVIDENCE_START is missing from the dumped maps: [\"PAUSE_PIDS (10)\"]"
                .to_string()),
        ),
        (
            evidence(),
            0,
            0,
            Err("KEYCANARY: scanned zero cells across all owned BPF maps (decoded=0, refused=0): refusing a vacuous scan"
                .to_string()),
        ),
        (
            evidence(),
            2,
            2,
            Err("KEYCANARY: scanned zero cells across all owned BPF maps (decoded=2, refused=2): refusing a vacuous scan"
                .to_string()),
        ),
        (
            evidence(),
            1,
            2,
            Err("KEYCANARY: refused cells (2) exceed decoded cells (1)".to_string()),
        ),
        (evidence(), 1, 0, Ok(())),
        (evidence(), 3, 2, Ok(())),
    ];
    for (dumped, cells, refused, expected) in cases {
        assert_eq!(
            verdict(&dumped, cells, refused),
            expected,
            "dumped={dumped:?} cells={cells} refused={refused}"
        );
    }
}

/// The empty-dump kind classification is an exact accept/reject table:
/// hash-family maps may be genuinely empty and program arrays may be
/// sparse; enumerated arrays and every unknown kind fail closed.
#[test]
fn keysize_canary_empty_kind_table_is_exact() {
    const EXPECTED: &[(&str, bool)] = &[
        ("hash", true),
        ("percpu_hash", true),
        ("lru_hash", true),
        ("lru_percpu_hash", true),
        ("prog_array", true),
        ("array", false),
        ("percpu_array", false),
        ("cgroup_array", false),
        ("ringbuf", false),
        ("unknown_kind", false),
    ];
    let actual: Vec<(&str, bool)> = EXPECTED
        .iter()
        .map(|(kind, _)| (*kind, keysize_canary_kind_may_dump_empty(kind)))
        .collect();
    assert_eq!(actual.as_slice(), EXPECTED);
}

/// The verifier wires both marker scans into the live per-dump path: the
/// text scan covers BTF `formatted` ASCII, while the decoded-cell scan
/// covers hex byte cells the text scan cannot read.
#[test]
fn keysize_canary_verify_map_dump_rejects_marked_text_and_cells() {
    let formatted = br#"[{"key": ["0x00"], "value": ["0x00"], "formatted": {"key": 0, "value": "K3YS1Z3CANARY!"}}]"#;
    assert!(
        keysize_canary_verify_map_dump("EVIDENCE_START", 9, "hash", formatted, Some((1, 1)))
            .is_err(),
        "a marker in formatted text fails the dump"
    );
    assert!(
        keysize_canary_verify_map_dump(
            "EVIDENCE_START",
            9,
            "hash",
            KEYSIZE_CANARY_JSON_HEX_CONTROL,
            Some((1, 14))
        )
        .is_err(),
        "a marker in decoded hex cells fails the dump"
    );
}

/// The `-j` decoder enforces exact key/value lengths (the map's
/// `bytes_key`/`bytes_value`): a short or long row is a dump the
/// cell cannot trust. Refused entries still check the key (their
/// keys scan) and skip the value length (they carry no bytes).
#[test]
fn keysize_canary_json_dump_scanner_enforces_exact_cell_lengths() {
    // Keys: too short and too long.
    assert!(
        keysize_canary_json_dump_marked(br#"[{"key": ["0x00"], "value": ["0x00"]}]"#, 2, 1)
            .is_err(),
        "a short key fails closed"
    );
    assert!(
        keysize_canary_json_dump_marked(br#"[{"key": ["0x00", "0x01"], "value": ["0x00"]}]"#, 1, 1)
            .is_err(),
        "a long key fails closed"
    );
    // Values: too short and too long.
    assert!(
        keysize_canary_json_dump_marked(br#"[{"key": ["0x00"], "value": ["0x00"]}]"#, 1, 2)
            .is_err(),
        "a short value fails closed"
    );
    assert!(
        keysize_canary_json_dump_marked(br#"[{"key": ["0x00"], "value": ["0x00", "0x01"]}]"#, 1, 1)
            .is_err(),
        "a long value fails closed"
    );
    // A wrong length in the second entry fails too, not just the first.
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "value": ["0x00"]}, {"key": ["0x01"], "value": ["0x01", "0x02"]}]"#,
            1,
            1
        )
        .is_err(),
        "a long value in the second entry fails closed"
    );
    // Per-CPU rows: the row value must be exactly value_len.
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "values": [{"cpu": 0, "value": ["0x00", "0x01"]}]}]"#,
            1,
            1
        )
        .is_err(),
        "a long per-CPU row value fails closed"
    );
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00", "0x00"], "values": [{"cpu": 0, "value": ["0x00"]}]}]"#,
            1,
            1
        )
        .is_err(),
        "a long per-CPU entry key fails closed"
    );
    // Refused entries: the key length still binds, the value length is
    // vacuous (no bytes were returned).
    assert!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00"], "value": {"error": "Unknown error 524"}}]"#,
            4,
            4
        )
        .is_err(),
        "a short refused-entry key fails closed"
    );
    assert_eq!(
        keysize_canary_json_dump_marked(
            br#"[{"key": ["0x00", "0x00", "0x00", "0x00"], "value": {"error": "Unknown error 524"}}]"#,
            4,
            4096
        )
        .unwrap(),
        (false, 1),
        "a refused entry skips the value length"
    );
}

/// Why the cell dumps with `-j`: a BTF plain-text dump renders retained
/// marker bytes as formatted decimals, which the text passes cannot
/// read — while the same bytes in `-j` raw cells decode and match.
/// This pins the hole `-j` closes: reverting to plain dumps hides this
/// leak shape from the text scan.
#[test]
fn keysize_canary_btf_decimal_rendering_hides_the_marker_from_the_text_scanner() {
    let decimal = b"value: { .bytes = [75, 51, 89, 83, 49, 90, 51, 67, 65, 78, 65, 82, 89, 33] }";
    assert!(
        !keysize_canary_scan_map_dump(decimal),
        "the text passes miss decimal-rendered marker bytes"
    );
    let cells = br#"[{"key": ["0x00"], "value": [75, 51, 89, 83, 49, 90, 51, 67, 65, 78, 65, 82, 89, 33]}]"#;
    assert!(
        keysize_canary_json_dump_marked(cells, 1, 14).unwrap().0,
        "the -j decoder finds the same bytes as raw cells"
    );
}

/// The live hex positive-control fragment is found through the JSON
/// path and missed by the text passes, so the live control is
/// load-bearing on the decoder: a dead decoder fails the cell.
#[test]
fn keysize_canary_json_hex_control_fragment_pins_the_live_hex_control() {
    assert!(
        keysize_canary_json_dump_marked(KEYSIZE_CANARY_JSON_HEX_CONTROL, 1, 14)
            .unwrap()
            .0,
        "the decoder finds the control fragment"
    );
    assert!(
        !keysize_canary_scan_map_dump(KEYSIZE_CANARY_JSON_HEX_CONTROL),
        "the text passes cannot read the control fragment"
    );
}

/// Probe the REAL fixture source: compile `keysize_canary.c` with its
/// `main` renamed and dump 4x64 guard bytes (tags 1-4), 32 message
/// bytes and a geometry line. Returns the 288 payload bytes plus the
/// `MARK`/`FRAME` trailer. Any drift between this probe and the live
/// workload build fails loudly here first.
fn keysize_canary_c_probe() -> Result<(Vec<u8>, String)> {
    let source = std::fs::read_to_string(keysize_canary_source())?;
    let renamed = source.replacen("int main(int argc", "int fixture_main(int argc", 1);
    ensure!(
        renamed != source && !renamed.contains("int main(int argc"),
        "the fixture main rename missed: probe needs exactly one main"
    );
    let dir = tempfile::tempdir()?;
    let dumper = dir.path().join("canary_probe.c");
    std::fs::write(
        &dumper,
        format!(
            "{renamed}\n\
             #include <stddef.h>\n\
             #include <stdio.h>\n\
             int main(void) {{\n\
                 unsigned char guard[GUARD_LEN];\n\
                 unsigned char msg[32];\n\
                 for (unsigned tag = 1; tag <= 4; tag++) {{\n\
                     fill_guard(guard, tag);\n\
                     if (fwrite(guard, 1, GUARD_LEN, stdout) != GUARD_LEN) return 1;\n\
                 }}\n\
                 fill_marked(msg, sizeof msg);\n\
                 if (fwrite(msg, 1, sizeof msg, stdout) != sizeof msg) return 1;\n\
                 printf(\"MARK %s\\n\", CANARY_MARK);\n\
                 printf(\n\
                     \"FRAME siglen=%zu post=%zu size=%zu\\n\",\n\
                     offsetof(struct sign_frame, siglen),\n\
                     offsetof(struct sign_frame, post),\n\
                     sizeof(struct sign_frame));\n\
                 return 0;\n\
             }}\n"
        ),
    )?;
    let binary = dir.path().join("canary_probe");
    let status = Command::new("cc")
        .args(["-O2"])
        .arg(&dumper)
        .arg("-o")
        .arg(&binary)
        .args(["-ldl", "-lpthread"])
        .status()
        .context("compiling the canary probe")?;
    ensure!(status.success(), "the canary probe build failed");
    let output = Command::new(&binary)
        .output()
        .context("running the canary probe")?;
    ensure!(
        output.status.success(),
        "the canary probe exited {}",
        output.status
    );
    ensure!(
        output.stdout.len() > 288,
        "the canary probe printed {} bytes, want 288 plus a trailer",
        output.stdout.len()
    );
    let payload = output.stdout[..288].to_vec();
    let trailer = String::from_utf8(output.stdout[288..].to_vec())?;
    Ok((payload, trailer))
}

/// The C guards carry no aliasing word: every 8-byte window of the
/// real fixture's guard and message bytes differs from the legitimate
/// RSA-2048 length and classifies outside it, full marker copies sit
/// at offsets 0/14/28/42 of every guard, and the S length cell sits
/// exactly between the guards. Kills re-introduction of a 256-valued
/// (or any verdict-passing) word anywhere in the planted payload.
#[test]
fn keysize_canary_c_guards_carry_no_aliasing_word() {
    use crate::keymeta::{EvidenceTag, SizeDetail, SizeOutcome, classify_size};

    const RSA_SHA256_PKCS: u64 = 0x40; // CKM_SHA256_RSA_PKCS, the workload mechanism
    const RSA2048: SizeOutcome = SizeOutcome::Inferred(SizeDetail::Rsa {
        size_class: Some(2048),
        modulus_bytes: 256,
    });
    let (payload, trailer) = keysize_canary_c_probe().unwrap();
    let mut lines = trailer.lines();
    assert_eq!(
        lines.next().unwrap(),
        format!("MARK {}", String::from_utf8_lossy(KEYSIZE_CANARY_MARKER)),
        "the C marker spelling matches the Rust scanner"
    );
    let frame = lines.next().unwrap();
    let geometry: Vec<usize> = frame
        .split_whitespace()
        .skip(1)
        .map(|field| field.split('=').nth(1).unwrap().parse().unwrap())
        .collect();
    assert_eq!(
        geometry.as_slice(),
        &[64, 72, 680],
        "siglen sits between the guards (pre ends at 64, post starts at 72): {frame}"
    );
    // Guards (4x64) plus the marked message (32): every window fails.
    assert_eq!(payload.len(), 4 * 64 + 32);
    for (index, guard) in payload[..4 * 64].as_chunks::<64>().0.iter().enumerate() {
        let intact: Vec<usize> = (0..=64 - KEYSIZE_CANARY_MARKER.len())
            .filter(|off| &guard[*off..*off + KEYSIZE_CANARY_MARKER.len()] == KEYSIZE_CANARY_MARKER)
            .collect();
        assert_eq!(
            intact.as_slice(),
            &[0, 14, 28, 42],
            "guard {index} keeps four intact marker copies"
        );
        assert!(
            keysize_canary_scan(guard),
            "guard {index} trips the bulk scanner"
        );
    }
    for (offset, window) in payload.windows(8).enumerate() {
        // Windows straddling two dumped regions mix unrelated bytes;
        // the live reads never span regions, so only in-region
        // windows count. Regions: guards at 0..256, message at 256..288.
        let end = offset + 8;
        let in_region = (offset < 256 && end <= 256) || offset >= 256;
        if !in_region {
            continue;
        }
        let word = u64::from_le_bytes(window.try_into().unwrap());
        assert_ne!(
            word, 256,
            "guard word 256 at offset {offset} aliases RSA-2048"
        );
        for tag in [EvidenceTag::SignOutput, EvidenceTag::VerifyInput] {
            assert_ne!(
                classify_size(Some(RSA_SHA256_PKCS), tag, word),
                RSA2048,
                "guard word {word} at offset {offset} classifies RSA-2048 via {tag:?}"
            );
        }
    }
}

/// Parse the canary LEDGER: (signs, verifies) with the C_Sign/C_Verify
/// attempt cross-check, so a short run cannot pass as clean.
fn keysize_canary_ledger_counts(transcript: &str) -> Result<(u64, u64)> {
    for line in transcript.lines() {
        let Some(payload) = line.strip_prefix("LEDGER ") else {
            continue;
        };
        let ledger: serde_json::Value = serde_json::from_str(payload).context("LEDGER json")?;
        ensure!(
            ledger.get("complete").and_then(serde_json::Value::as_bool) == Some(true),
            "LEDGER is incomplete"
        );
        let key_ops = ledger
            .get("key_operations")
            .context("LEDGER key_operations")?;
        let signs = key_ops
            .get("signs")
            .and_then(serde_json::Value::as_u64)
            .context("LEDGER key_operations.signs")?;
        let verifies = key_ops
            .get("verifies")
            .and_then(serde_json::Value::as_u64)
            .context("LEDGER key_operations.verifies")?;
        let functions = ledger
            .get("functions")
            .and_then(serde_json::Value::as_array)
            .context("LEDGER functions")?;
        for (name, want) in [("C_Sign", signs), ("C_Verify", verifies)] {
            let attempts: u64 = functions
                .iter()
                .filter(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some(name))
                .map(|entry| {
                    entry
                        .get("attempts")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                })
                .sum();
            ensure!(
                attempts == want,
                "LEDGER {name} attempts {attempts} disagree with {want}"
            );
        }
        ensure!(
            signs == 3 && verifies == 3,
            "LEDGER is short: {signs}/{verifies}"
        );
        return Ok((signs, verifies));
    }
    anyhow::bail!("no LEDGER line in the workload transcript")
}

#[test]
fn keysize_canary_ledger_parser_accepts_the_full_ledger() {
    let transcript = "READY pid=1\nSENTINEL marker=K3YS1Z3CANARY! signs=3 verifies=3\nLEDGER {\"schema\":\"p11scope/public-cli-ledger/v2\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_SignInit\",\"attempts\":3,\"successful\":3},{\"name\":\"C_Sign\",\"attempts\":3,\"successful\":3},{\"name\":\"C_VerifyInit\",\"attempts\":3,\"successful\":3},{\"name\":\"C_Verify\",\"attempts\":3,\"successful\":3}],\"key_operations\":{\"label\":\"k\",\"signs\":3,\"verifies\":3}}\n";
    assert_eq!(keysize_canary_ledger_counts(transcript).unwrap(), (3, 3));
}

#[test]
fn keysize_canary_ledger_parser_rejects_a_short_run() {
    let transcript = "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v2\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_Sign\",\"attempts\":2},{\"name\":\"C_Verify\",\"attempts\":2}],\"key_operations\":{\"label\":\"k\",\"signs\":2,\"verifies\":2}}\n";
    let error = keysize_canary_ledger_counts(transcript).unwrap_err();
    assert!(
        format!("{error:#}").contains("short"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_ledger_parser_rejects_attempt_count_mismatch() {
    let transcript = "LEDGER {\"schema\":\"p11scope/public-cli-ledger/v2\",\"pid\":1,\"complete\":true,\"functions\":[{\"name\":\"C_Sign\",\"attempts\":2},{\"name\":\"C_Verify\",\"attempts\":3}],\"key_operations\":{\"label\":\"k\",\"signs\":3,\"verifies\":3}}\n";
    let error = keysize_canary_ledger_counts(transcript).unwrap_err();
    assert!(
        format!("{error:#}").contains("C_Sign attempts 2 disagree with 3"),
        "unexpected error: {error:#}"
    );
}

/// Judge `object_observations` for the canary run: exact sign accounting
/// with RSA-2048 from `sign_output` (the S-protocol length published),
/// plus exact verify accounting with RSA-2048 from `verify_input` (the
/// V-protocol length published). Both lengths must publish or the run is
/// vacuous: a silent length path would pass the marker scan trivially.
/// The verify half mirrors the shared sign judge clause for clause
/// (family, kind, modulus, completions, race-bucket accounting), so a
/// payload-sourced verify length fails here, not just in the scan.
fn judge_keysize_canary_observations(
    observations: &serde_json::Value,
    ledger_signs: u64,
    ledger_verifies: u64,
) -> Result<String> {
    // Signs reuse the shared sizes judge verbatim (exact accounting plus
    // RSA-2048 from `sign_output`, with its own reject suite), so the
    // S-protocol half of this verdict adds no unpinned clauses.
    let sign_verdict = judge_key_sizes_observations(observations, ledger_signs)?;
    let rows = observations
        .get("key_operations")
        .and_then(serde_json::Value::as_array)
        .context("key_operations rows")?;
    let verify_rows: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|row| {
            row.get("category").and_then(serde_json::Value::as_str) == Some("verify")
                && row
                    .get("completed")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    > 0
        })
        .collect();
    let unknown = observations
        .get("unknown_key_operations")
        .and_then(serde_json::Value::as_array)
        .context("unknown_key_operations")?;
    let mut unknown_done = 0u64;
    for bucket in unknown.iter().filter(|bucket| {
        bucket.get("category").and_then(serde_json::Value::as_str) == Some("verify")
    }) {
        let reason = bucket
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .context("unknown verify reason")?;
        ensure!(
            reason == "key_join_lost" || reason == "unbound",
            "KEYCANARY: unknown verify bucket {reason} is not a known race bucket"
        );
        unknown_done += bucket
            .get("completed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
    }
    let rows_done: u64 = verify_rows
        .iter()
        .map(|row| {
            row.get("completed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    ensure!(
        rows_done > 0,
        "KEYCANARY: no verify landed in a key row (vacuous V-protocol)"
    );
    ensure!(
        rows_done + unknown_done == ledger_verifies,
        "KEYCANARY: observer-vs-ledger verify mismatch: rows {rows_done} + unknown {unknown_done} != ledger {ledger_verifies}"
    );
    for row in &verify_rows {
        let completed = row
            .get("completed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let object = row.get("object").and_then(serde_json::Value::as_u64);
        let family = row
            .get("inferred_family")
            .context("verify row inferred_family")?;
        ensure!(
            family.get("status").and_then(serde_json::Value::as_str) == Some("inferred"),
            "KEYCANARY: object {object:?} family status is {}, want inferred",
            family.get("status").unwrap_or(&serde_json::Value::Null)
        );
        ensure!(
            family.get("value").and_then(serde_json::Value::as_str) == Some("rsa"),
            "KEYCANARY: object {object:?} family value is not rsa: {family}"
        );
        ensure!(
            family
                .get("completions")
                .and_then(serde_json::Value::as_u64)
                == Some(completed),
            "KEYCANARY: object {object:?} family completions disagree with completed {completed}: {family}"
        );
        let size = row
            .get("inferred_size")
            .context("verify row inferred_size")?;
        ensure!(
            size.get("status").and_then(serde_json::Value::as_str) == Some("inferred"),
            "KEYCANARY: object {object:?} size status is {}, want inferred",
            size.get("status").unwrap_or(&serde_json::Value::Null)
        );
        let detail = size.get("detail").context("verify size detail")?;
        ensure!(
            detail.get("kind").and_then(serde_json::Value::as_str) == Some("rsa"),
            "KEYCANARY: object {object:?} size kind is not rsa: {detail}"
        );
        ensure!(
            detail.get("size_class").and_then(serde_json::Value::as_u64) == Some(2048),
            "KEYCANARY: object {object:?} size_class is not 2048: {detail}"
        );
        ensure!(
            detail
                .get("modulus_bytes")
                .and_then(serde_json::Value::as_u64)
                == Some(256),
            "KEYCANARY: object {object:?} modulus_bytes is not 256: {detail}"
        );
        ensure!(
            detail.get("evidence").and_then(serde_json::Value::as_str) == Some("verify_input"),
            "KEYCANARY: object {object:?} size evidence is not verify_input: {detail}"
        );
        ensure!(
            size.get("completions").and_then(serde_json::Value::as_u64) == Some(completed),
            "KEYCANARY: object {object:?} size completions disagree with completed {completed}: {size}"
        );
    }
    Ok(format!(
        "{sign_verdict} verifies={rows_done} vunknown={unknown_done}"
    ))
}

#[test]
fn keysize_canary_judge_accepts_sign_and_verify_rows() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
            {
                "category": "verify",
                "completed": 3,
                "object": 4,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "verify_input"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    assert_eq!(
        judge_keysize_canary_observations(&observations, 3, 3).unwrap(),
        "rows=3 unknown=0 total=3 size=rsa2048 verifies=3 vunknown=0"
    );
}

#[test]
fn keysize_canary_judge_accepts_verify_with_a_race_bucket() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
            {
                "category": "verify",
                "completed": 2,
                "object": 4,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 2},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "verify_input"},
                    "completions": 2,
                },
            },
        ],
        "unknown_key_operations": [
            {"category": "verify", "completed": 1, "reason": "key_join_lost"},
        ],
    });
    assert_eq!(
        judge_keysize_canary_observations(&observations, 3, 3).unwrap(),
        "rows=3 unknown=0 total=3 size=rsa2048 verifies=2 vunknown=1"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_missing_verify_row() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("no verify landed"),
        "unexpected error: {error:#}"
    );
}

fn keysize_canary_verify_case(size: serde_json::Value, completed: u64) -> serde_json::Value {
    serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
            {
                "category": "verify",
                "completed": completed,
                "object": 4,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": completed},
                "inferred_size": size,
            },
        ],
        "unknown_key_operations": [],
    })
}

#[test]
fn keysize_canary_judge_rejects_an_unsized_verify_row() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({"status": "unknown", "detail": null, "completions": 0}),
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size status is")
            && format!("{error:#}").contains("want inferred"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_wrong_verify_size_class() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({
            "status": "inferred",
            "detail": {"kind": "rsa", "size_class": 3072, "modulus_bytes": 384, "evidence": "verify_input"},
            "completions": 3,
        }),
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size_class is not 2048"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_wrong_verify_evidence() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({
            "status": "inferred",
            "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
            "completions": 3,
        }),
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size evidence is not verify_input"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_wrong_verify_kind() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({
            "status": "inferred",
            "detail": {"kind": "ec", "size_class": 2048, "modulus_bytes": 256, "evidence": "verify_input"},
            "completions": 3,
        }),
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size kind is not rsa"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_wrong_verify_modulus() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({
            "status": "inferred",
            "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 384, "evidence": "verify_input"},
            "completions": 3,
        }),
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("modulus_bytes is not 256"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_short_verify_accounting() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({
            "status": "inferred",
            "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "verify_input"},
            "completions": 2,
        }),
        2,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("rows 2 + unknown 0 != ledger 3"),
        "unexpected error: {error:#}"
    );
}

fn keysize_canary_verify_case_with_family(
    family: serde_json::Value,
    size_completions: u64,
    completed: u64,
) -> serde_json::Value {
    serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
            {
                "category": "verify",
                "completed": completed,
                "object": 4,
                "inferred_family": family,
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "verify_input"},
                    "completions": size_completions,
                },
            },
        ],
        "unknown_key_operations": [],
    })
}

#[test]
fn keysize_canary_judge_rejects_an_uninferred_verify_family() {
    let observations = keysize_canary_verify_case_with_family(
        serde_json::json!({"status": "unknown", "value": null, "completions": 0}),
        3,
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family status is")
            && format!("{error:#}").contains("want inferred"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_verify_row_without_inferred_keys() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
            {
                "category": "verify",
                "completed": 3,
                "object": 4,
            },
        ],
        "unknown_key_operations": [],
    });
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("verify row inferred_family"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_verify_size_without_detail() {
    let observations = keysize_canary_verify_case(
        serde_json::json!({"status": "inferred", "completions": 3}),
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("verify size detail"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_wrong_verify_family() {
    let observations = keysize_canary_verify_case_with_family(
        serde_json::json!({"status": "inferred", "value": "ec", "completions": 3}),
        3,
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family value is not rsa"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_verify_family_completions_mismatch() {
    let observations = keysize_canary_verify_case_with_family(
        serde_json::json!({"status": "inferred", "value": "rsa", "completions": 2}),
        3,
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("family completions disagree"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_verify_size_completions_mismatch() {
    let observations = keysize_canary_verify_case_with_family(
        serde_json::json!({"status": "inferred", "value": "rsa", "completions": 3}),
        2,
        3,
    );
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("size completions disagree"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_a_non_race_verify_bucket() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
            {
                "category": "verify",
                "completed": 2,
                "object": 4,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 2},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "verify_input"},
                    "completions": 2,
                },
            },
        ],
        "unknown_key_operations": [
            {"category": "verify", "completed": 1, "reason": "metadata_unknown"},
        ],
    });
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("not a known race bucket"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn keysize_canary_judge_rejects_an_all_unknown_verify_run() {
    let observations = serde_json::json!({
        "status": "populated",
        "key_operations": [
            {
                "category": "sign",
                "completed": 3,
                "object": 3,
                "inferred_family": {"status": "inferred", "value": "rsa", "completions": 3},
                "inferred_size": {
                    "status": "inferred",
                    "detail": {"kind": "rsa", "size_class": 2048, "modulus_bytes": 256, "evidence": "sign_output"},
                    "completions": 3,
                },
            },
        ],
        "unknown_key_operations": [
            {"category": "verify", "completed": 3, "reason": "unbound"},
        ],
    });
    let error = judge_keysize_canary_observations(&observations, 3, 3).unwrap_err();
    assert!(
        format!("{error:#}").contains("no verify landed"),
        "unexpected error: {error:#}"
    );
}

/// `map_id:` values in one fdinfo file's text: the BPF maps one held
/// descriptor pins. Pure parser over text so the unit test pins it
/// without a live process.
fn keysize_canary_map_ids_in_fdinfo(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| line.strip_prefix("map_id:"))
        .filter_map(|id| id.trim().parse::<u32>().ok())
        .collect()
}

/// BPF map ids owned by a live process: every `map_id:` in its
/// `/proc/<pid>/fdinfo`, deduplicated. Unreadable entries (a closing
/// descriptor racing the scan) are skipped; a dead process yields no
/// directory and fails the caller.
fn keysize_canary_owned_map_ids(pid: u32) -> Result<Vec<u32>> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fdinfo"))
        .with_context(|| format!("KEYCANARY: /proc/{pid}/fdinfo is unreadable"))?
    {
        let Ok(text) = std::fs::read_to_string(entry?.path()) else {
            continue;
        };
        ids.extend(keysize_canary_map_ids_in_fdinfo(&text));
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// (id, name, type) for every entry of `bpftool map list -j`: one
/// call classifies the whole owned set, so the scan stays inside the
/// observer's capture window. Unnamed maps read `<unnamed>`; entries
/// without an id or a type fail the caller.
fn keysize_canary_listed_identities(listed: &[u8]) -> Result<Vec<(u32, String, String)>> {
    let parsed: serde_json::Value =
        serde_json::from_slice(listed).context("KEYCANARY: bpftool map list output is not JSON")?;
    let entries = parsed
        .as_array()
        .context("KEYCANARY: bpftool map list is not an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = entry
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
            .context("KEYCANARY: map list entry has no id")?;
        let name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unnamed>")
            .to_string();
        let kind = entry
            .get("type")
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("KEYCANARY: map {id} list entry has no type"))?
            .to_string();
        out.push((id, name, kind));
    }
    Ok(out)
}

/// (id, `bytes_key`, `bytes_value`) for every entry of `bpftool map
/// list -j`: the exact cell widths the dump decoder enforces per
/// map. Strict like the oracle's `snapshot_map_metadata` in
/// `scripts/dump-owned-bpf-maps.py` (every entry must carry a u32
/// id, `bytes_key` and `bytes_value`): a map whose widths are
/// unknown is a map whose dump cannot be length-checked, so the
/// entry fails the caller. Parsed beside the identities above
/// (same document, same ids); the live loop looks both up per id.
fn keysize_canary_listed_lengths(listed: &[u8]) -> Result<Vec<(u32, usize, usize)>> {
    let parsed: serde_json::Value =
        serde_json::from_slice(listed).context("KEYCANARY: bpftool map list output is not JSON")?;
    let entries = parsed
        .as_array()
        .context("KEYCANARY: bpftool map list is not an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = entry
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
            .context("KEYCANARY: map list entry has no id")?;
        let width = |field: &str| {
            entry
                .get(field)
                .and_then(serde_json::Value::as_u64)
                .and_then(|width| u32::try_from(width).ok())
                .and_then(|width| usize::try_from(width).ok())
                .with_context(|| format!("KEYCANARY: map {id} list entry has no u32 {field}"))
        };
        out.push((id, width("bytes_key")?, width("bytes_value")?));
    }
    Ok(out)
}

/// The owned-map scan result: dumped (and scanned) maps, ringbufs the
/// kernel cannot dump, identity task storage the kernel cannot dump,
/// the scanned dump bytes, the decoded entry count (including refused
/// entries), and the refused-cell count with the maps that refused. Only
/// names and counts ever print;
/// dump contents stay in 0600 scratch files.
struct KeysizeCanaryMapScan {
    dumped: Vec<String>,
    rings: Vec<String>,
    task_storage: Vec<String>,
    bytes: u64,
    cells: u64,
    refused: u64,
    refused_maps: Vec<String>,
}

/// Audited undumpable task storage, by bpftool-visible name.
/// Task-keyed maps are undumpable by bpftool; they hold minted identity
/// and epoch words only (no byte buffers) — `THREAD_OWNER` is the
/// identity/lease/counter struct (`crates/ebpf/native/task_owner.h`,
/// no length cell and no payload buffer),
/// `TASK_COOKIE`/`TASK_COOKIE_B`/`ROOT_AFFILIATION` are single minted
/// ticket words, `PROC_EPOCH` is the epoch record — so the cell lists
/// them instead of dumping. (`PROC_EPOCH` and `TASK_COOKIE` are read
/// through a pidfd by `record()`/`cookie()` in
/// `src/attach/instance.rs`; "undumpable" never meant "unread".) The
/// kernel truncates map names to 15 chars (`BPF_OBJ_NAME_LEN`), so
/// `ROOT_AFFILIATION` reads `ROOT_AFFILIATIO` (mirrors
/// `canonical_map_name` in `scripts/dump-owned-bpf-maps.py`). Anything
/// outside this allowlist — any other name, any other kind — dumps or
/// fails closed.
const KEYSIZE_CANARY_TASK_STORAGE_ALLOWLIST: &[&str] = &[
    "TASK_COOKIE",
    "TASK_COOKIE_B",
    "THREAD_OWNER",
    "ROOT_AFFILIATIO",
    "PROC_EPOCH",
];

/// True only for an audited undumpable task-storage map: the kind must
/// be `task_storage` and the bpftool-visible name must be allowlisted.
/// An unknown task-storage name fails the caller, never joins the
/// exclusion.
fn keysize_canary_is_audited_task_storage(name: &str, kind: &str) -> bool {
    kind == "task_storage" && KEYSIZE_CANARY_TASK_STORAGE_ALLOWLIST.contains(&name)
}

/// The length stash must be among the dumped maps: without
/// `EVIDENCE_START` the map scan never covered the surface that holds
/// retained length cells, so the cell must fail, not pass thin.
fn keysize_canary_dumped_covers_evidence_start(dumped: &[String]) -> bool {
    dumped
        .iter()
        .any(|entry| entry.starts_with("EVIDENCE_START "))
}

/// Dump every dumpable BPF map owned by the live observer with
/// `bpftool -j` and scan each dump for the canary marker, as text (BTF
/// `formatted` ASCII) plus decoded raw cells (BTF renders retained
/// bytes as formatted decimals in plain dumps, which the text passes
/// cannot read). Every decoded cell row must be exactly the map's
/// `bytes_key`/`bytes_value` widths from `bpftool map list -j`.
/// Ringbufs (`EVENTS`/`DISCOVERY`/`INFO`) are not bpftool-dumpable;
/// the observer drains them into the scanned report, event log and
/// observer log, so they are listed, not dumped. The identity task
/// storage is likewise undumpable by bpftool and listed; it holds
/// minted identity and epoch words only (no byte buffers). Per-cell
/// lookup refusals are counted and gated on the map kind (only
/// `cgroup_array` may refuse); a bpftool dump refusal, an unaudited
/// task-storage name, an empty dump of a kind that cannot validly be
/// empty, zero scanned cells in total (decoded minus refused), an empty
/// dump list, a missing `EVIDENCE_START`, or a failed positive control
/// fails the cell: an
/// unscanned map is a hole, not a pass.
fn keysize_canary_scan_owned_maps(pid: u32, dump_dir: &Path) -> Result<KeysizeCanaryMapScan> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    const TAG: &str = "KEYCANARY";
    let ids = keysize_canary_owned_map_ids(pid)?;
    ensure!(
        !ids.is_empty(),
        "{TAG}: the observer (pid {pid}) holds no BPF maps to scan"
    );
    std::fs::create_dir_all(dump_dir)?;
    let mut dumped = Vec::new();
    let mut rings = Vec::new();
    let mut task_storage = Vec::new();
    let mut bytes = 0u64;
    let mut cells = 0u64;
    let mut refused = 0u64;
    let mut refused_maps = Vec::new();
    let mut combined = Vec::new();
    let list = Command::new("bpftool")
        .args(["map", "list", "-j"])
        .output()
        .context("KEYCANARY: spawning bpftool map list")?;
    ensure!(
        list.status.success(),
        "{TAG}: bpftool map list failed: {}",
        String::from_utf8_lossy(&list.stderr)
            .chars()
            .take(200)
            .collect::<String>()
    );
    let identities: std::collections::HashMap<u32, (String, String)> =
        keysize_canary_listed_identities(&list.stdout)?
            .into_iter()
            .map(|(id, name, kind)| (id, (name, kind)))
            .collect();
    let lengths: std::collections::HashMap<u32, (usize, usize)> =
        keysize_canary_listed_lengths(&list.stdout)?
            .into_iter()
            .map(|(id, key_len, value_len)| (id, (key_len, value_len)))
            .collect();
    for id in ids {
        let (name, kind) = identities.get(&id).with_context(|| {
            format!("{TAG}: owned map {id} vanished before the scan (the observer may have exited)")
        })?;
        if kind == "ringbuf" {
            rings.push(format!("{name} ({id})"));
            continue;
        }
        if kind == "task_storage" {
            ensure!(
                keysize_canary_is_audited_task_storage(name, kind),
                "{TAG}: task-storage map {name} ({id}) is outside the audited exclusion: refusing an unscanned map"
            );
            task_storage.push(format!("{name} ({id}/{kind})"));
            continue;
        }
        let dump = Command::new("bpftool")
            .args(["-j", "map", "dump", "id", &id.to_string()])
            .output()
            .context("KEYCANARY: spawning bpftool map dump")?;
        ensure!(
            dump.status.success(),
            "{TAG}: bpftool map dump id {id} ({name}/{kind}) refused: {}",
            String::from_utf8_lossy(&dump.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        );
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dump_dir.join(format!("map-{id}.txt")))?
            .write_all(&dump.stdout)?;
        bytes += dump.stdout.len() as u64;
        let widths = lengths.get(&id).copied();
        let map_cells = keysize_canary_verify_map_dump(name, id, kind, &dump.stdout, widths)?;
        cells += map_cells as u64;
        // A successful verify proves a non-cgroup_array map had zero
        // refusals. Decode only the small cgroup_array dumps a second
        // time to report their admitted refusal count; the pure verifier
        // intentionally returns just the decoded-cell count.
        let map_refused = if kind == "cgroup_array" {
            let (key_len, value_len) = widths.with_context(|| {
                format!(
                    "{TAG}: owned map {name} ({id}/{kind}) has no key/value widths in the map list"
                )
            })?;
            keysize_canary_json_dump_cells(&dump.stdout, key_len, value_len)
                .with_context(|| {
                    format!("{TAG}: cannot recount the verified BPF map {name} ({id}/{kind}) dump")
                })?
                .refused
        } else {
            0
        };
        if map_refused > 0 {
            refused += map_refused as u64;
            refused_maps.push(format!("{name} ({id}/{kind}): {map_refused}"));
        }
        combined.extend_from_slice(&dump.stdout);
        dumped.push(format!("{name} ({id})"));
    }
    keysize_canary_scan_verdict(&dumped, cells, refused)?;
    combined.extend_from_slice(KEYSIZE_CANARY_MARKER);
    ensure!(
        keysize_canary_scan_map_dump(&combined),
        "{TAG}: map positive control failed: the scanner missed an injected marker"
    );
    // The control fragment is one key cell and fourteen value cells by
    // construction (pinned by the fragment test below).
    ensure!(
        keysize_canary_json_dump_marked(KEYSIZE_CANARY_JSON_HEX_CONTROL, 1, 14)?.0,
        "{TAG}: map hex positive control failed: the decoder missed hex-encoded marker cells"
    );
    Ok(KeysizeCanaryMapScan {
        dumped,
        rings,
        task_storage,
        bytes,
        cells,
        refused,
        refused_maps,
    })
}

#[test]
fn keysize_canary_fdinfo_parser_collects_map_ids() {
    let text = "pos:\t0\nflags:\t02000002\nmnt_id:\t12\nmap_type:\t1\nmap_id:\t7\nmemlock:\t4096\n";
    assert_eq!(keysize_canary_map_ids_in_fdinfo(text), vec![7]);
    let multi = "map_id:\t3\nmap_id:\t11\n";
    assert_eq!(keysize_canary_map_ids_in_fdinfo(multi), vec![3, 11]);
    assert!(keysize_canary_map_ids_in_fdinfo("pos:\t0\nflags:\t0\n").is_empty());
    assert!(keysize_canary_map_ids_in_fdinfo("map_id:\tnot-a-number\n").is_empty());
}

#[test]
fn keysize_canary_listed_identities_parse_the_map_list() {
    let list = br#"[{"id": 9, "type": "hash", "name": "EVIDENCE_START"},{"id": 4, "type": "ringbuf", "name": "EVENTS"},{"id": 2, "type": "array"}]"#;
    assert_eq!(
        keysize_canary_listed_identities(list).unwrap(),
        vec![
            (9, "EVIDENCE_START".to_string(), "hash".to_string()),
            (4, "EVENTS".to_string(), "ringbuf".to_string()),
            (2, "<unnamed>".to_string(), "array".to_string()),
        ]
    );
    assert!(keysize_canary_listed_identities(b"not json").is_err());
    assert!(keysize_canary_listed_identities(br#"{"id": 1}"#).is_err());
    assert!(keysize_canary_listed_identities(br#"[{"id": 1, "name": "X"}]"#).is_err());
    assert!(keysize_canary_listed_identities(br#"[{"type": "hash"}]"#).is_err());
}

#[test]
fn keysize_canary_listed_lengths_parse_key_and_value_widths() {
    let list = br#"[{"id": 9, "type": "hash", "name": "EVIDENCE_START", "bytes_key": 4, "bytes_value": 64},{"id": 4, "type": "ringbuf", "name": "EVENTS", "bytes_key": 0, "bytes_value": 0},{"id": 7, "type": "cgroup_array", "name": "CGROUP_FILTER", "bytes_key": 4, "bytes_value": 4}]"#;
    assert_eq!(
        keysize_canary_listed_lengths(list).unwrap(),
        vec![(9, 4, 64), (4, 0, 0), (7, 4, 4)]
    );
    // Widths are opaque u32s; anything missing or non-u32 fails the
    // caller.
    assert!(keysize_canary_listed_lengths(b"not json").is_err());
    assert!(keysize_canary_listed_lengths(br#"{"id": 1}"#).is_err());
    assert!(keysize_canary_listed_lengths(br#"[{"type": "hash"}]"#).is_err());
    for bad in [
        br#"[{"id": 1, "bytes_value": 4}]"#.as_slice(),
        br#"[{"id": 1, "bytes_key": 4}]"#.as_slice(),
        br#"[{"id": 1, "bytes_key": "4", "bytes_value": 4}]"#.as_slice(),
        br#"[{"id": 1, "bytes_key": 4, "bytes_value": -1}]"#.as_slice(),
        br#"[{"id": 1, "bytes_key": 4, "bytes_value": 4294967296}]"#.as_slice(),
        br#"[{"id": 1, "bytes_key": 4.0, "bytes_value": 4}]"#.as_slice(),
    ] {
        assert!(
            keysize_canary_listed_lengths(bad).is_err(),
            "a bad width fails closed: {}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn keysize_canary_evidence_start_cover_requires_the_stash() {
    let with = vec!["START (3)".to_string(), "EVIDENCE_START (9)".to_string()];
    assert!(keysize_canary_dumped_covers_evidence_start(&with));
    let without = vec!["START (3)".to_string(), "EVENTS (4)".to_string()];
    assert!(!keysize_canary_dumped_covers_evidence_start(&without));
    assert!(!keysize_canary_dumped_covers_evidence_start(&[]));
    // A prefix impostor (no blank after the name) does not count.
    let impostor = vec!["EVIDENCE_STARTERS (9)".to_string()];
    assert!(!keysize_canary_dumped_covers_evidence_start(&impostor));
}

#[test]
fn keysize_canary_task_storage_allowlist_admits_only_audited_maps() {
    // Every audited name joins the exclusion, with the exact kind.
    assert_eq!(KEYSIZE_CANARY_TASK_STORAGE_ALLOWLIST.len(), 5);
    for name in KEYSIZE_CANARY_TASK_STORAGE_ALLOWLIST {
        assert!(
            keysize_canary_is_audited_task_storage(name, "task_storage"),
            "{name} is audited and must be excludable"
        );
    }
    // An unknown task-storage name never joins: it fails the cell.
    for name in [
        "EVIL_STORAGE",
        "TASK_COOKIE_C",
        "THREAD_OWNERS",
        "ROOT_AFFILIATION",
        "root_affiliatio",
        "",
    ] {
        assert!(
            !keysize_canary_is_audited_task_storage(name, "task_storage"),
            "{name:?} is not audited and must fail closed"
        );
    }
    // An audited name of another kind dumps (or fails the cell trying).
    for kind in ["hash", "array", "ringbuf", "percpu_array", "prog_array"] {
        assert!(
            !keysize_canary_is_audited_task_storage("TASK_COOKIE", kind),
            "{kind} must not join the task-storage exclusion"
        );
    }
}

/// Task 4 privacy canary, live: `inventory --pid --capture native
/// --key-operations --key-sizes --manifest --verbose` over the
/// sentinel-guarded sign+verify workload. The S length cell and the V
/// buffers sit between pure repeated `K3YS1Z3CANARY!` guards; the cell
/// asserts the marker appears in none of the JSON report, the event
/// log, the verbose observer log or any dumpable owned BPF map (rings
/// drain into the scanned outputs; the identity task storage is
/// undumpable by bpftool and holds minted identity and epoch words
/// only; per-cell lookup refusals count and only `cgroup_array` may
/// refuse; every decoded row must match the map's `bytes_key` /
/// `bytes_value` widths), while both RSA-2048 sizes publish.
/// Needs an observer binary via `P11SCOPE_E2E_OBSERVER` or a `p11scope`
/// sibling of this test binary, plus `bpftool` for the map dumps.
/// Prints KEYCANARY lines. Root BPF lane, serial, about 80 seconds.
#[test]
#[ignore = "privileged: live key-sizes canary proves no sentinel payload byte reaches output, maps or logs"]
fn privileged_inventory_pid_key_sizes_canary_no_payload_leak() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build_with(
        &module,
        &keysize_canary_source(),
        "keysize_canary",
        "keycanary",
    )?;
    let outcome = keysize_canary_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "KEYCANARY")
}

fn keysize_canary_inner(workload: &E2eWorkload, module: &str, observer: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const TAG: &str = "KEYCANARY";
    let manifest = live_manifest(
        workload,
        module,
        KEYSIZE_CANARY_FUNCTIONS,
        "keycanary-live.json",
    )?;
    let out = workload.path("inv.json");
    let event_log = workload.path("events.jsonl");
    let gate = workload.path("gate");
    let workload_out = workload.path("keysize_canary.out");
    let observer_out = workload.path("observer.out");
    ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
    let private_log = |path: &Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    let workload_stderr = workload_out.with_extension("stderr");
    let mut target = E2eProcess {
        child: Command::new(&workload.ledger)
            .args([
                module,
                gate.to_str().context("gate path")?,
                "1234",
                "keysize-canary-key",
            ])
            .env("SOFTHSM2_CONF", &workload.conf)
            .env("MT_MIXED_HOLD", "1")
            .stdin(Stdio::null())
            .stdout(private_log(&workload_out)?)
            .stderr(private_log(&workload_stderr)?)
            .die_with_parent()
            .spawn()
            .context("spawning keysize_canary")?,
        out: workload_out.clone(),
        stderr: workload_stderr,
    };
    target.wait_for("READY ", Duration::from_secs(30))?;
    let pid = target.child.id();
    println!("{TAG} workload spawned pid={pid} gate={}", gate.display());
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut command = Command::new(observer);
    command
        .args([
            "inventory",
            "--pid",
            &pid.to_string(),
            "--capture",
            "native",
            "--key-operations",
            "--key-sizes",
            "--manifest",
            manifest.to_str().context("manifest path")?,
            "--event-log",
            event_log.to_str().context("event log path")?,
            "--duration",
            "60",
            "--json",
            "--verbose",
            "-o",
            out.to_str().context("out path")?,
        ])
        .stdin(Stdio::null())
        .stdout(observer_log.try_clone()?)
        .stderr(observer_log)
        .die_with_parent();
    let mut child = command.spawn().context("spawning observer")?;
    println!("{TAG} observer spawned pid={}", child.id());
    let needle_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let active = std::fs::read_to_string(&observer_out).is_ok_and(|text| {
            text.lines()
                .any(|line| line.contains("native usage lane active"))
        });
        if active {
            break;
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the observer exited before the usage lane activated: {}",
                observer_evidence(&observer_out, &out, &format!("exited {status}"))
            );
        }
        target.ensure_alive("before the usage lane activated")?;
        ensure!(
            Instant::now() < needle_deadline,
            "usage lane never activated (observer pid={}): {}",
            child.id(),
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let transcript = std::fs::read_to_string(&workload_out)?;
    mt_key_wait_matched(&event_log, &transcript, pid)?;
    std::fs::write(&gate, b"open\n")?;
    println!("{TAG} gate opened");
    target.wait_for("LEDGER ", Duration::from_secs(120))?;
    let transcript = std::fs::read_to_string(&workload_out)?;
    let (ledger_signs, ledger_verifies) = keysize_canary_ledger_counts(&transcript)?;
    ensure!(
        transcript
            .lines()
            .any(|line| line.starts_with("SENTINEL marker=K3YS1Z3CANARY!")),
        "the workload never planted the canary marker"
    );
    target.ensure_alive("after LEDGER before the owned-map scan")?;
    // The owned-map verdict, mid-flight: every dumpable map the live
    // observer owns is dumped with `bpftool -j` and scanned (text plus
    // decoded raw cells) while it still runs (maps die with the
    // process, so no post-stop dump exists). Rings are listed, not
    // dumped: they drain into the scanned outputs.
    let scan_started = Instant::now();
    let map_scan = keysize_canary_scan_owned_maps(child.id(), &workload.path("mapdumps"))?;
    println!(
        "{TAG} maps dumped={} rings={} taskstorage={} cells={} refused={} bytes={} secs={} rings=[{}] taskstorage=[{}] refusedmaps=[{}]",
        map_scan.dumped.len(),
        map_scan.rings.len(),
        map_scan.task_storage.len(),
        map_scan.cells,
        map_scan.refused,
        map_scan.bytes,
        scan_started.elapsed().as_secs(),
        map_scan.rings.join(", "),
        map_scan.task_storage.join(", "),
        map_scan.refused_maps.join(", ")
    );
    target.ensure_alive("after the owned-map scan before the observer stopped")?;
    let stop_deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < stop_deadline,
            "the observer did not stop: {}",
            observer_evidence(&observer_out, &out, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    ensure!(
        status.success(),
        "the observer exited with {status}: {}",
        observer_evidence(&observer_out, &out, &format!("exited {status}"))
    );
    // The no-leak verdict: the marker appears in none of the three
    // observer surfaces (the observer log carries the verbose text
    // channel too). Each surface is scanned as raw bytes, so an
    // encoded leak still fails only when the raw marker is present.
    let report_bytes = std::fs::read(&out).context("observer report bytes")?;
    let event_bytes = std::fs::read(&event_log).context("event log bytes")?;
    let observer_bytes = std::fs::read(&observer_out).context("observer log bytes")?;
    for (name, bytes) in [
        ("report", &report_bytes),
        ("event log", &event_bytes),
        ("observer log", &observer_bytes),
    ] {
        ensure!(
            !keysize_canary_scan(bytes),
            "{TAG}: canary marker leaked into the {name} ({} bytes)",
            bytes.len()
        );
    }
    // Positive control on the live surfaces: the same scanner finds an
    // injected marker in the live report copy, so a real leak would fail.
    let mut injected = report_bytes.clone();
    injected.extend_from_slice(KEYSIZE_CANARY_MARKER);
    ensure!(
        keysize_canary_scan(&injected),
        "{TAG}: positive control failed: the scanner missed an injected marker"
    );
    // Lengths published: both RSA-2048 sizes, or the clean scan is vacuous.
    let report: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&report_bytes).context("report utf8")?)
            .context("observer report json")?;
    let observations = report
        .get("object_observations")
        .context("object_observations")?;
    let verdict = judge_keysize_canary_observations(observations, ledger_signs, ledger_verifies)?;
    println!(
        "{TAG} {verdict} ledger={ledger_signs}/{ledger_verifies} scanned={}/{}/{} maps={}/{}/{}",
        report_bytes.len(),
        event_bytes.len(),
        observer_bytes.len(),
        map_scan.dumped.len(),
        map_scan.rings.len(),
        map_scan.task_storage.len(),
    );
    Ok(())
}
