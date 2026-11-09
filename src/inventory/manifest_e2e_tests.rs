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
    let callers = report
        .get("callers")
        .and_then(serde_json::Value::as_array)
        .context("callers array")?;
    let ledger_caller = callers
        .iter()
        .find(|caller| {
            caller.get("pid").and_then(serde_json::Value::as_u64) == Some(u64::from(ledger_pid))
        })
        .and_then(|caller| caller.get("id"))
        .and_then(serde_json::Value::as_str)
        .context("the ledger caller has a caller row")?;
    println!("SCALE2_E2E ledger_caller={ledger_caller}");
    let edges = report
        .get("semantic_edges")
        .and_then(serde_json::Value::as_array)
        .context("semantic_edges array")?;
    println!("SCALE2_E2E semantic_edges={}", edges.len());
    // Strict R-51 verdict for the long-running caller: a populated edge
    // (mechanisms, calls, a CKR_OK API result), never a silent drop. No
    // route-loss fallback: this cell proves edges form at scale.
    let mut populated = 0usize;
    for edge in edges.iter().filter(|edge| {
        edge.get("caller").and_then(serde_json::Value::as_str) == Some(ledger_caller)
    }) {
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
