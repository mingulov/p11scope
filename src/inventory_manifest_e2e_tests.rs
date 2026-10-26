//! SPDX-License-Identifier: GPL-3.0-or-later
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
use anyhow::ensure;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// SoftHSM2 provider layouts across guest images (Debian multiarch
/// first, then the /usr/lib layout the vng guests carry).
const SOFTHSM_CANDIDATES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
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

fn ledger_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-cli/inventory-ledger.c")
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

impl E2eWorkload {
    fn build(module: &str) -> Result<Self> {
        ensure!(
            Path::new(module).exists(),
            "SoftHSM2 provider {module} is missing"
        );
        ensure!(ledger_source().exists(), "ledger fixture is missing");
        let dir = tempfile::tempdir()?;
        let ledger = dir.path().join("ledger");
        let status = Command::new("cc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(ledger_source())
            .arg("-o")
            .arg(&ledger)
            .args(["-ldl", "-lpthread"])
            .status()
            .context("running cc")?;
        ensure!(status.success(), "ledger build failed");
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
            .args(["--init-token", "--free", "--label", "man1e2e"])
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
    ) -> Result<E2eProcess> {
        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
        let child = Command::new(&self.ledger)
            .args([
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
            ])
            .env("SOFTHSM2_CONF", &self.conf)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(out)?)
            .stderr(Stdio::null())
            .spawn()
            .context("spawning ledger")?;
        Ok(E2eProcess {
            child,
            out: out.to_path_buf(),
        })
    }
}

struct E2eProcess {
    child: Child,
    out: PathBuf,
}

impl E2eProcess {
    fn has(&self, prefix: &str) -> bool {
        std::fs::read_to_string(&self.out)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(prefix)))
    }

    fn tail(&self) -> Vec<String> {
        std::fs::read_to_string(&self.out)
            .map(|text| text.lines().take(12).map(String::from).collect())
            .unwrap_or_default()
    }

    fn wait_for(&self, prefix: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has(prefix) {
            ensure!(
                Instant::now() < deadline,
                "ledger {} never printed {prefix:?}: {:?}",
                self.out.display(),
                self.tail()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A manifest resolving exactly the ledger `mech` functions against
/// the live provider file (offsets read from the ELF, identity and
/// provenance from the held object), shaped like the discover output.
fn mech_manifest(workload: &E2eWorkload, module: &str) -> Result<PathBuf> {
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    let path = Path::new(module);
    let file = open_object(path).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(path)?;
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&elf).map_err(anyhow::Error::msg)?;
    let mut offsets = std::collections::BTreeMap::new();
    for name in MECH_FUNCTIONS {
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
        "the mech manifest is well-formed"
    );
    let manifest_path = workload.path("mech-live.json");
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
    let manifest = mech_manifest(&workload, &module)?;
    let out = workload.path("inv.json");
    let gate = workload.path("gate");
    let ledger_out = workload.path("ledger.out");
    let observer_out = workload.path("observer.out");
    let mut target = workload.spawn(&ledger_out, &module, &gate, 100_000, 2_000)?;
    // READY prints before the gate wait: the workload is up and its
    // dlopen is held until the cell opens the gate post-attach.
    target.wait_for("READY ", Duration::from_secs(30))?;
    println!(
        "MAN1_E2E workload spawned pid={} gate={}",
        target.child.id(),
        gate.display()
    );
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut child = Command::new(&observer)
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
        ensure!(
            Instant::now() < gate_deadline,
            "pass 0 never published (observer pid={})",
            child.id()
        );
        ensure!(
            child.try_wait()?.is_none(),
            "the observer exited before pass 0"
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
            "the observer never stopped (pid={})",
            child.id()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    ensure!(
        target.child.try_wait()?.is_none(),
        "the workload is still alive at the observer stop"
    );
    target.kill();
    let rc = status.code().unwrap_or(-1);
    println!("MAN1_E2E observer rc={rc}");
    ensure!(rc == 0, "inventory --system --manifest exits 0, got {rc}");
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

/// Scale target: one endpoint past the default 4,096 inventory budget,
/// so the run must carry `--max-endpoints` and the admission is real.
const SCALE_TARGET_ENDPOINTS: u64 = 4097;

/// Upper bound on distinct provider copies. The population stops as
/// soon as the resolved total reaches the target; this cap only bounds
/// a degenerate surface (a symbol-read bug resolving a handful of
/// functions must fail, never spawn thousands of copies).
const SCALE_MAX_COPIES: usize = 130;

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
}

impl ScaleHolder {
    fn spawn(holder: &Path, out: &Path, copies: &[PathBuf]) -> Result<Self> {
        let child = Command::new(holder)
            .args(copies)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(out)?)
            .stderr(Stdio::null())
            .spawn()
            .context("spawning holder")?;
        Ok(Self {
            child,
            out: out.to_path_buf(),
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
            ensure!(
                Instant::now() < deadline,
                "holder {} never printed READY",
                self.out.display()
            );
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
/// Prints SCALE2_E2E lines. Root BPF lane, serial, a few minutes.
#[test]
#[ignore = "privileged: inventory --system --manifest over 4097+ endpoints stops finitely with S1 edges for a long-running caller and the journal_unavailable disclosure"]
fn privileged_inventory_system_manifest_scale4097_softsm_edges_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = E2eWorkload::build(&module)?;
    // Distinct copies, one full-surface manifest each, until the
    // resolved total reaches the target past the default budget.
    let first_copy = workload.path("copy-0.so");
    std::fs::copy(&module, &first_copy)?;
    let first_manifest = workload.path("copy-0.json");
    let per_copy =
        full_surface_manifest(first_copy.to_str().context("copy path")?, &first_manifest)?;
    println!("SCALE2_E2E per_copy_resolved={per_copy}");
    ensure!(
        per_copy >= SCALE_MIN_SURFACE,
        "a scale copy resolves its full surface, got {per_copy}"
    );
    let mech_manifest_path = mech_manifest(&workload, &module)?;
    let mut manifests = vec![mech_manifest_path];
    let mut copies = vec![first_copy];
    manifests.push(first_manifest);
    let mut total = per_copy as u64 + MECH_FUNCTIONS.len() as u64;
    let mut index = 1usize;
    while total < SCALE_TARGET_ENDPOINTS {
        ensure!(
            copies.len() < SCALE_MAX_COPIES,
            "scale population hit the copy cap at {total} endpoints"
        );
        let copy = workload.path(&format!("copy-{index}.so"));
        std::fs::copy(&module, &copy)?;
        let manifest_path = workload.path(&format!("copy-{index}.json"));
        let resolved = full_surface_manifest(copy.to_str().context("copy path")?, &manifest_path)?;
        ensure!(
            resolved == per_copy,
            "every scale copy resolves the same surface, got {resolved}"
        );
        copies.push(copy);
        manifests.push(manifest_path);
        total += per_copy as u64;
        index += 1;
    }
    println!(
        "SCALE2_E2E copies={} endpoints_attested={total}",
        copies.len()
    );
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
    let holder = ScaleHolder::spawn(&holder_bin, &holder_out, &copies)?;
    holder.wait_ready(Duration::from_secs(60))?;
    println!(
        "SCALE2_E2E holder spawned pid={} copies={}",
        holder.child.id(),
        copies.len()
    );
    let out = workload.path("inv.json");
    let gate = workload.path("gate");
    let ledger_out = workload.path("ledger.out");
    let observer_out = workload.path("observer.out");
    let mut target = workload.spawn(&ledger_out, &module, &gate, 100_000, 2_000)?;
    target.wait_for("READY ", Duration::from_secs(30))?;
    let ledger_pid = target.child.id();
    println!(
        "SCALE2_E2E workload spawned pid={ledger_pid} gate={}",
        gate.display()
    );
    let observer_log = std::fs::File::create(&observer_out)?;
    let mut command = Command::new(&observer);
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
    let mut child = command.spawn().context("spawning observer")?;
    println!("SCALE2_E2E observer spawned pid={}", child.id());
    let gate_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let published = std::fs::read_to_string(&observer_out)
            .is_ok_and(|text| text.lines().any(|line| line.contains("p11scope: pass 0:")));
        if published {
            break;
        }
        ensure!(
            Instant::now() < gate_deadline,
            "pass 0 never published (observer pid={})",
            child.id()
        );
        ensure!(
            child.try_wait()?.is_none(),
            "the observer exited before pass 0"
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
            "the observer never stopped (pid={})",
            child.id()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    target.kill();
    drop(holder);
    let rc = status.code().unwrap_or(-1);
    println!("SCALE2_E2E observer rc={rc}");
    ensure!(rc == 0, "inventory --system --manifest exits 0, got {rc}");
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
        occupied >= SCALE_TARGET_ENDPOINTS,
        "4097+ endpoints are admitted, got {occupied}"
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
