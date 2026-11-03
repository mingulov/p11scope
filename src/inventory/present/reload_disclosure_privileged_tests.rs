//! B17 leg-2 installed cell: one `p11scope inventory --manifest` capture
//! over a two-provider fixture must publish `instance_reload_not_excluded`
//! for the sharer-churned provider and not for the clean control.
//!
//! The fixture compiles a minimal provider source twice for two distinct
//! file identities under a small two-provider driver, both embedded below.
//! The `v` command replicates the instance-continuity fixture's case-`v`
//! verbatim: a synchronous `CLONE_VM` sharer maps and unmaps one page of
//! provider A in the shared mm (`waitpid`), so the trigger carries no
//! timing dependence in the router. The driver calls both providers
//! continuously for the whole capture while the test lands one churn
//! mid-run, so the lane's own scans observe gen-0, the churn, and the
//! tainted continuation no matter when attach completes.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};

/// Minimal leg-2 provider, compiled twice for two file identities. Discovery
/// only admits a mapped file as a provider module when it exports
/// `C_GetFunctionList` with a static legacy table (the demotion-fixture
/// shape: version 2.40 plus null holes), so the instance-continuity
/// fixture — two bare functions, no table — is invisible to the scan and
/// cannot serve here. The table root plus `C_GetSlotInfo` is all the lane
/// needs: the manifest resolves the exported legacy fields for attach.
const PROVIDER_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <stddef.h>
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef struct { unsigned char major, minor; void *slot[68]; } FunctionList;
__attribute__((noinline)) static CK_ULONG pad(CK_ULONG v) { return v * 2654435761UL ^ (v >> 7); }
CK_RV C_Initialize(void *args) { (void)args; return 0; }
CK_ULONG C_GetSlotInfo(CK_ULONG slot, void *info) { (void)info; return pad(slot) == 1 ? 0 : 3; }
CK_RV C_GetFunctionList(void **out);
static FunctionList table = { .major = 2, .minor = 40, .slot = {[0] = (void *)C_Initialize, [3] = (void *)C_GetFunctionList, [5] = (void *)C_GetSlotInfo} };
CK_RV C_GetFunctionList(void **out) { if (!out) return 7; *out = &table; return 0; }
"#;

/// Two-provider leg-2 driver: `argv[1]` is the churned provider A,
/// `argv[2]` the clean control B. A worker thread calls `C_GetSlotInfo`
/// on both continuously from `READY` until `q`, so the capture observes
/// calls whenever its attach completes; commands on stdin: `v` churns A
/// through a `CLONE_VM` sharer, `q` quits. Continuous calls (not a paced
/// burst window) because a debug observer on a loaded host can take
/// ~10 s to reach its first pass — a short burst window closes before
/// attach and the capture honestly reports zero use.
const DRIVER_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG (*slot_info_fn)(CK_ULONG, void *);

static volatile int stop_calls;
static slot_info_fn call_a;
static slot_info_fn call_b;

static void *call_loop(void *unused)
{
    (void)unused;
    char info[256];
    while (!stop_calls) {
        for (int i = 0; i < 20; i++) {
            call_a(0x70000000UL, info);
            call_b(0x70000000UL, info);
        }
        usleep(50000);
    }
    return NULL;
}

static const char *sharer_provider;
static int sharer_child(void *unused)
{
    (void)unused;
    int fd = open(sharer_provider, O_RDONLY);
    if (fd < 0)
        return 1;
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return 2;
    munmap(p, 4096);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 3) {
        fprintf(stderr, "usage: leg2-driver PROVIDER_A PROVIDER_B\n");
        return 64;
    }
    void *ha = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *hb = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!ha || !hb) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    call_a = (slot_info_fn)dlsym(ha, "C_GetSlotInfo");
    call_b = (slot_info_fn)dlsym(hb, "C_GetSlotInfo");
    if (!call_a || !call_b) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 1;
    }
    pthread_t worker;
    if (pthread_create(&worker, NULL, call_loop, NULL) != 0) {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }
    printf("READY %s %s\n", argv[1], argv[2]);
    char line[64];
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == 'v') {
            static char stack[64 * 1024] __attribute__((aligned(16)));
            int status = 0;
            sharer_provider = argv[1];
            pid_t child = clone(sharer_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
            if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 0) {
                printf("SHARER_FAIL\n");
            } else {
                printf("SHARER\n");
            }
        } else if (line[0] == 'q') {
            break;
        }
    }
    stop_calls = 1;
    pthread_join(worker, NULL);
    printf("BYE\n");
    return 0;
}
"#;

/// Capture length with the churn past the slowest attach: calls flow for
/// the whole run, the churn lands mid-capture, and the tail keeps the
/// lane scanning (no re-yield).
const CAPTURE_DURATION_SECS: u64 = 32;
const CHURN_AT_SECS: u64 = 18;
const LINE_TIMEOUT: Duration = Duration::from_secs(10);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(150);

fn compile_c(source: &str, name: &str, directory: &Path, provider: bool) -> Result<PathBuf> {
    let path = directory.join(format!("{name}.c"));
    let output = directory.join(if provider {
        format!("{name}.so")
    } else {
        name.to_string()
    });
    std::fs::write(&path, source)?;
    let mut cc = Command::new("cc");
    cc.args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]);
    if provider {
        cc.args(["-fPIC", "-shared"]);
    }
    cc.arg(&path).arg("-o").arg(&output);
    if !provider {
        cc.args(["-ldl", "-lpthread"]);
    }
    let result = cc.output().context("running cc")?;
    ensure!(
        result.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(output)
}

/// The observer under test: an explicit `P11SCOPE_E2E_OBSERVER` binary or
/// the `p11scope` sibling of this test binary's directory (a local `cargo
/// build` layout). Same idiom as the manifest e2e tests.
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

/// A full-surface legacy manifest for one fixture provider file, built
/// in-process like the manifest e2e tests: every exported legacy field
/// resolves to its ELF offset, the rest are null pointers.
fn manifest_for(module: &Path, out: &Path) -> Result<()> {
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    let file = open_object(module).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(module)?;
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
    let functions = spans
        .iter()
        .flat_map(|span| span.fields())
        .map(|field| {
            let resolution = snapshot
                .defined_symbol(field.name)
                .map_err(anyhow::Error::msg)?
                .map(|fact| Resolution::Resolved {
                    object: 0,
                    file_offset: fact.file_offset,
                })
                .unwrap_or(Resolution::NullPointer);
            Ok(FunctionRecord {
                name: field.name.into(),
                resolution,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let path = module.to_str().context("provider path")?.to_string();
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
            version: Some(Version { major: 2, minor: 40 }),
            walk: WalkOutcome::Full,
            functions,
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
    };
    ensure!(
        crate::manifest_input::validate_structure(&manifest).is_empty(),
        "the leg-2 manifest is well-formed"
    );
    std::fs::write(out, serde_json::to_vec(&manifest)?)?;
    Ok(())
}

/// One owned driver process with a line-oriented protocol. Kills the child
/// on drop so no failure path leaks it.
struct Driver {
    child: Child,
    input: ChildStdin,
    lines: mpsc::Receiver<String>,
}

impl Driver {
    fn spawn(program: &Path, provider_a: &Path, provider_b: &Path) -> Result<Self> {
        let mut child = Command::new(program)
            .arg(provider_a)
            .arg(provider_b)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .context("spawning the leg-2 driver")?;
        let input = child.stdin.take().context("driver stdin")?;
        let output = child.stdout.take().context("driver stdout")?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            input,
            lines,
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn line(&self, timeout: Duration) -> Result<String> {
        self.lines
            .recv_timeout(timeout)
            .context("driver answered in time")
    }

    fn command(&mut self, byte: u8) -> Result<String> {
        self.input
            .write_all(&[byte, b'\n'])
            .context("driver stdin")?;
        self.input.flush().context("driver stdin")?;
        self.line(LINE_TIMEOUT)
    }

    fn wait(&mut self, timeout: Duration) -> Result<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            ensure!(
                Instant::now() < deadline,
                "the driver did not exit in time"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

struct Leg2Outcome {
    document: serde_json::Value,
    driver_pid: u32,
    provider_a: String,
    provider_b: String,
    capture_secs: u64,
}

/// One installed capture over the two-provider driver: bursts across the
/// run, the `v` churn of provider A in the middle when asked, then the
/// parsed output document. The driver stays alive until the capture ends.
fn run_leg2_capture(churn: bool) -> Result<Leg2Outcome> {
    let directory = tempfile::tempdir()?;
    // Two distinct file identities of one provider source.
    let provider_a = compile_c(PROVIDER_SOURCE, "providerA", directory.path(), true)?;
    let provider_b = compile_c(PROVIDER_SOURCE, "providerB", directory.path(), true)?;
    let driver = compile_c(DRIVER_SOURCE, "leg2-driver", directory.path(), false)?;
    let manifest_a = directory.path().join("a.json");
    let manifest_b = directory.path().join("b.json");
    manifest_for(&provider_a, &manifest_a)?;
    manifest_for(&provider_b, &manifest_b)?;
    let out = directory.path().join("out.json");

    let mut driver = Driver::spawn(&driver, &provider_a, &provider_b)?;
    let ready = driver.line(LINE_TIMEOUT)?;
    ensure!(
        ready.starts_with("READY"),
        "driver ready line: {ready}"
    );
    let driver_pid = driver.pid();

    let observer = observer_binary()?;
    let started = Instant::now();
    let mut capture = Command::new(&observer)
        .args([
            "inventory",
            "--pid",
            &driver_pid.to_string(),
            "--manifest",
            &manifest_a.to_string_lossy(),
            "--manifest",
            &manifest_b.to_string_lossy(),
            "--duration",
            &format!("{}s", CAPTURE_DURATION_SECS),
            "-o",
            &out.to_string_lossy(),
        ])
        .spawn()
        .context("spawning the installed capture")?;
    // The driver calls continuously; the churn lands mid-capture while the
    // capture is still running, then the tail scans on.
    let churn_at = started + Duration::from_secs(CHURN_AT_SECS);
    if churn {
        loop {
            ensure!(
                capture.try_wait()?.is_none(),
                "the capture ended before the churn"
            );
            if Instant::now() >= churn_at {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let churned = driver.command(b'v')?;
        ensure!(churned == "SHARER", "churn answer: {churned}");
    }
    let status = loop {
        if let Some(status) = capture.try_wait()? {
            break status;
        }
        ensure!(
            started.elapsed() < CAPTURE_TIMEOUT,
            "the installed capture did not finish in time"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let capture_secs = started.elapsed().as_secs();
    ensure!(status.success(), "the installed capture exited {status}");
    let quit = driver.command(b'q')?;
    ensure!(quit == "BYE", "driver quit: {quit}");
    let _ = driver.wait(Duration::from_secs(10));

    let bytes = std::fs::read(&out).context("reading the output document")?;
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).context("parsing the output document")?;
    Ok(Leg2Outcome {
        document,
        driver_pid,
        provider_a: provider_a.to_string_lossy().into_owned(),
        provider_b: provider_b.to_string_lossy().into_owned(),
        capture_secs,
    })
}

/// The module label (`mN`) for one provider file, resolved through the
/// document's own `modules[]` paths.
fn module_label_for(document: &serde_json::Value, provider: &str) -> Result<String> {
    let file = Path::new(provider)
        .file_name()
        .context("provider file name")?
        .to_string_lossy()
        .into_owned();
    let mut found = None;
    for module in document["modules"]
        .as_array()
        .context("modules[]")?
    {
        let paths = module["paths"].as_array().context("module paths")?;
        if paths
            .iter()
            .filter_map(|path| path.as_str())
            .any(|path| path.ends_with(&file))
        {
            ensure!(
                found.is_none(),
                "two modules claim {file}: {document}",
            );
            found = Some(
                module["id"]
                    .as_str()
                    .context("module id")?
                    .to_string(),
            );
        }
    }
    found.with_context(|| format!("no module row for {file}"))
}

/// The instance labels (`iN`) for one (caller pid, module) pair, resolved
/// through the document's own `callers[]` and `instances[]`.
fn instance_labels_for(
    document: &serde_json::Value,
    driver_pid: u32,
    module: &str,
) -> Result<Vec<String>> {
    let mut callers = Vec::new();
    for caller in document["callers"]
        .as_array()
        .context("callers[]")?
    {
        if caller["pid"].as_u64() == Some(u64::from(driver_pid)) {
            callers.push(caller["id"].as_str().context("caller id")?.to_string());
        }
    }
    ensure!(!callers.is_empty(), "no caller row for pid {driver_pid}");
    let mut instances = Vec::new();
    for instance in document["instances"]
        .as_array()
        .context("instances[]")?
    {
        let caller = instance["caller"].as_str().context("instance caller")?;
        let row_module = instance["module"].as_str().context("instance module")?;
        if callers.iter().any(|id| id == caller) && row_module == module {
            instances.push(instance["id"].as_str().context("instance id")?.to_string());
        }
    }
    ensure!(
        !instances.is_empty(),
        "no instance row for pid {driver_pid} module {module} (lane not live?)"
    );
    Ok(instances)
}

fn kernel_release() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|release| release.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Leg 2, churn run: the disclosure names the churned provider's module
/// with its instance, carries both capture counts, and never names the
/// clean control. One artifact, both directions.
#[test]
#[ignore = "privileged: loads BPF, runs an installed inventory capture over a fixture"]
fn privileged_inventory_reload_disclosure_lists_churned_identity() -> Result<()> {
    let outcome = run_leg2_capture(true)?;
    let document = &outcome.document;
    let key = &document["instance_reload_not_excluded"];
    ensure!(
        key.is_object(),
        "the churned capture must publish the disclosure object"
    );
    // Exact closed shape: counts plus module-grouped identities only.
    let mut top: Vec<&str> = key.as_object().context("object")?.keys().map(String::as_str).collect();
    top.sort_unstable();
    ensure!(
        top == ["continued_across_global", "identities", "joined_across_global"],
        "top-level keys: {top:?}"
    );
    let continued = key["continued_across_global"].as_u64().context("count")?;
    let joined = key["joined_across_global"].as_u64().context("count")?;
    ensure!(
        continued >= 1 && joined >= 1,
        "both counts must observe the churn: {continued}/{joined}"
    );
    let identities = key["identities"].as_array().context("identities")?;
    for identity in identities {
        let mut keys: Vec<&str> = identity
            .as_object()
            .context("identity")?
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        ensure!(
            keys == ["instances", "module"],
            "identity keys: {keys:?}"
        );
    }
    let module_a = module_label_for(document, &outcome.provider_a)?;
    let module_b = module_label_for(document, &outcome.provider_b)?;
    let instances_a = instance_labels_for(document, outcome.driver_pid, &module_a)?;
    // The control is live (its instance rows exist) but undisclosed.
    let _ = instance_labels_for(document, outcome.driver_pid, &module_b)?;
    let mut named_a = false;
    for identity in identities {
        let module = identity["module"].as_str().context("module")?;
        if module == module_b {
            anyhow::bail!("the clean control must have no entry: {key}");
        }
        if module == module_a {
            named_a = true;
            let named: Vec<&str> = identity["instances"]
                .as_array()
                .context("instances")?
                .iter()
                .map(|id| id.as_str().context("instance ref"))
                .collect::<Result<Vec<_>>>()?;
            for expected in &instances_a {
                ensure!(
                    named.iter().any(|id| id == expected),
                    "the churned instance {expected} must be named: {key}"
                );
            }
        }
    }
    ensure!(named_a, "the churned module {module_a} must be named: {key}");
    eprintln!(
        "B17_LEG2 kernel={} churned={module_a}/{instances_a:?} control={module_b} counts={continued}/{joined} capture_s={}",
        kernel_release(),
        outcome.capture_secs,
    );
    Ok(())
}

/// Leg 2, clean-control run: without churn the key stays absent, and the
/// absence means "no disclosure" — proven by the lane being live
/// (`instances[]` carries both providers) — never bare absence.
#[test]
#[ignore = "privileged: loads BPF, runs an installed inventory capture over a fixture"]
fn privileged_inventory_reload_disclosure_omits_key_without_churn() -> Result<()> {
    let outcome = run_leg2_capture(false)?;
    let document = &outcome.document;
    ensure!(
        document
            .get("instance_reload_not_excluded")
            .is_none_or(serde_json::Value::is_null),
        "the clean capture must omit the disclosure key"
    );
    let module_a = module_label_for(document, &outcome.provider_a)?;
    let module_b = module_label_for(document, &outcome.provider_b)?;
    let instances_a = instance_labels_for(document, outcome.driver_pid, &module_a)?;
    let instances_b = instance_labels_for(document, outcome.driver_pid, &module_b)?;
    eprintln!(
        "B17_LEG2_CLEAN kernel={} a={module_a}/{instances_a:?} b={module_b}/{instances_b:?} counts=0/0 capture_s={}",
        kernel_release(),
        outcome.capture_secs,
    );
    Ok(())
}
