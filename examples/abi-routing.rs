//! Privileged, explicit qualification for ordinary entry-probe ABI routing.
//!
//! This example is compiled by the normal all-targets gate, but it is never
//! run by that gate. `scripts/matrix/verify-abi-routing.sh` builds controlled
//! native and ia32 subjects and invokes it under the qualification boundary.

use anyhow::{Context as _, Result, anyhow, bail};
use aya::maps::{Array, HashMap, Map, PerCpuArray, PerCpuHashMap, RingBuf};
use aya::programs::UProbe;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeLinkId, UProbeScope};
use aya::{Ebpf, EbpfLoader};
use p11scope_ebpf_common::{
    CFG_FLAGS, CFG_TASK_NEWTASK_OFFSETS, CallStart, EVIDENCE_ABI_REFUSALS, EVIDENCE_CELLS, Event,
    FLAG_PID_FILTER, FLAG_POLICY_ALLOWLISTED, FUNCTION_NONE, MAX_SLOTS, MECH_NONE, RvKey,
    SESSION_NONE, SlotSemantics, SlotStats, StartKey, USER_TYPE_NONE, attach_cookie, event_type,
    shape, valid_config,
};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::identity::{hex, inspect_file, open_regular};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RAW_RECORDS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubjectAbi {
    Native64,
    Ia32,
}

impl SubjectAbi {
    const fn label(self) -> &'static str {
        match self {
            Self::Native64 => "native64",
            Self::Ia32 => "ia32",
        }
    }

    const fn fixture_markers(self) -> (&'static str, &'static str) {
        match self {
            Self::Native64 => ("FIXTURE_READY=64\n", "FIXTURE_DONE=64\n"),
            Self::Ia32 => ("FIXTURE_READY=32\n", "FIXTURE_DONE=32\n"),
        }
    }

    const fn elf(self) -> ElfAbi {
        match self {
            Self::Native64 => ElfAbi::Lp64,
            Self::Ia32 => ElfAbi::Ilp32,
        }
    }

    const fn vendor_rv(self) -> u64 {
        match self {
            Self::Native64 => 0x1234_5678_8000_0001,
            Self::Ia32 => 0x8000_0001,
        }
    }
}

#[derive(Clone)]
struct Inputs {
    fixture64: PathBuf,
    dso64: PathBuf,
    fixture32: PathBuf,
    dso32: PathBuf,
}

impl Inputs {
    fn for_abi(&self, abi: SubjectAbi) -> (&Path, &Path) {
        match abi {
            SubjectAbi::Native64 => (&self.fixture64, &self.dso64),
            SubjectAbi::Ia32 => (&self.fixture32, &self.dso32),
        }
    }
}

#[derive(Clone, Copy)]
struct RowSpec {
    name: &'static str,
    abi: SubjectAbi,
    entry: &'static str,
    refusals: u64,
    positive: bool,
}

#[derive(Default)]
struct StatsSum {
    entered: u64,
    returned: u64,
    errors: u64,
    total_ns: u64,
    max_ns: u64,
    buckets: [u64; p11scope_ebpf_common::LATENCY_BUCKETS],
}

#[derive(Default)]
struct Observed {
    evidence: Vec<u64>,
    stats: Vec<StatsSum>,
    starts: usize,
    rvs: BTreeMap<(u32, u64), u64>,
    events: Vec<Event>,
}

struct Cli {
    evidence: PathBuf,
    inputs: Inputs,
}

fn parse_cli() -> Result<Cli> {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    let values: Vec<_> = args.collect();
    if values.len() != 5 {
        bail!(
            "usage: {} EVIDENCE_DIR FIXTURE64 DSO64 FIXTURE32 DSO32",
            Path::new(&program).display()
        );
    }
    Ok(Cli {
        evidence: PathBuf::from(&values[0]),
        inputs: Inputs {
            fixture64: PathBuf::from(&values[1]),
            dso64: PathBuf::from(&values[2]),
            fixture32: PathBuf::from(&values[3]),
            dso32: PathBuf::from(&values[4]),
        },
    })
}

fn matrix() -> &'static [RowSpec] {
    #[cfg(feature = "unsafe-unvalidated-metadata")]
    {
        &[
            RowSpec {
                name: "native64-lp64-match",
                abi: SubjectAbi::Native64,
                entry: "p11_entry",
                refusals: 0,
                positive: true,
            },
            RowSpec {
                name: "native64-ilp32-refusal",
                abi: SubjectAbi::Native64,
                entry: "p11_entry_ia32",
                refusals: 2,
                positive: false,
            },
            RowSpec {
                name: "ia32-ilp32-match",
                abi: SubjectAbi::Ia32,
                entry: "p11_entry_ia32",
                refusals: 0,
                positive: true,
            },
            RowSpec {
                name: "ia32-lp64-refusal",
                abi: SubjectAbi::Ia32,
                entry: "p11_entry",
                refusals: 2,
                positive: false,
            },
        ]
    }
    #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
    {
        &[
            RowSpec {
                name: "native64-mixed-match",
                abi: SubjectAbi::Native64,
                entry: "p11_entry",
                refusals: 0,
                positive: true,
            },
            RowSpec {
                name: "ia32-mixed-match",
                abi: SubjectAbi::Ia32,
                entry: "p11_entry",
                refusals: 0,
                positive: true,
            },
        ]
    }
}

fn object_mode() -> &'static str {
    if cfg!(feature = "unsafe-unvalidated-metadata") {
        "diagnostic"
    } else {
        "default"
    }
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("ABI_ROUTING=NONPASS error={error:#}");
        std::process::exit(1);
    }
}

fn main_result() -> Result<()> {
    if std::env::consts::ARCH != "x86_64" {
        bail!("ABI routing qualification requires an x86_64 observer host");
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("ABI routing qualification executable requires the authorized root boundary");
    }
    let cli = parse_cli()?;
    if cli.evidence.exists() {
        bail!(
            "evidence directory already exists: {}",
            cli.evidence.display()
        );
    }
    fs::DirBuilder::new()
        .mode(0o755)
        .create(&cli.evidence)
        .with_context(|| format!("creating evidence directory {}", cli.evidence.display()))?;

    let outcome = run_matrix(&cli);
    let terminal = match &outcome {
        Ok(()) => format!(
            "result=PASS\nobject_mode={}\nrows_passed={}\nrows_required={}\n",
            object_mode(),
            matrix().len(),
            matrix().len()
        ),
        Err(error) => format!(
            "result=NONPASS\nobject_mode={}\nrows_required={}\nerror={}\n",
            object_mode(),
            matrix().len(),
            one_line(error)
        ),
    };
    write_new(&cli.evidence.join("overall.status"), terminal.as_bytes())?;
    outcome
}

fn run_matrix(cli: &Cli) -> Result<()> {
    write_new(&cli.evidence.join("embedded-bpf.o"), p11scope::EBPF_OBJECT)
        .context("exporting the exact embedded BPF object")?;
    let exported = open_regular(&cli.evidence.join("embedded-bpf.o"))
        .map_err(anyhow::Error::msg)
        .context("reopening exported embedded BPF object")?;
    let embedded_sha = verify_embedded_export(&exported, p11scope::EBPF_OBJECT)
        .context("verifying exported embedded BPF object")?;
    write_new(
        &cli.evidence.join("build-variant.status"),
        format!(
            "object_mode={}\nunsafe_unvalidated_metadata={}\nembedded_sha256={}\n",
            object_mode(),
            u8::from(cfg!(feature = "unsafe-unvalidated-metadata")),
            embedded_sha
        )
        .as_bytes(),
    )?;

    let mut failures = Vec::new();
    for spec in matrix() {
        let row_dir = cli.evidence.join(spec.name);
        fs::DirBuilder::new().mode(0o755).create(&row_dir)?;
        match run_row(*spec, &cli.inputs, &row_dir) {
            Ok(()) => println!("ROW={} RESULT=PASS", spec.name),
            Err(error) => {
                println!(
                    "ROW={} RESULT=NONPASS error={}",
                    spec.name,
                    one_line(&error)
                );
                failures.push(format!("{}: {error:#}", spec.name));
            }
        }
    }
    if failures.is_empty() {
        println!("ABI_ROUTING=PASS object_mode={}", object_mode());
        Ok(())
    } else {
        bail!("{} row(s) failed: {}", failures.len(), failures.join("; "))
    }
}

fn verify_embedded_export(file: &File, expected: &[u8]) -> Result<String> {
    let expected_len = u64::try_from(expected.len()).context("embedded BPF object is too large")?;
    let read_limit = expected_len
        .checked_add(1)
        .context("embedded BPF object read limit overflow")?;
    let actual_len = file.metadata()?.len();
    if actual_len != expected_len {
        bail!(
            "exported embedded BPF bytes differ: expected {expected_len} bytes, found {actual_len}"
        );
    }
    let mut actual = Vec::with_capacity(expected.len());
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    reader.take(read_limit).read_to_end(&mut actual)?;
    if actual != expected {
        bail!("exported embedded BPF bytes differ from the compiled object");
    }
    Ok(hex(&Sha256::digest(&actual)))
}

fn run_row(spec: RowSpec, inputs: &Inputs, row_dir: &Path) -> Result<()> {
    let mut runtime = RowRuntime::default();
    let body = run_row_body(spec, inputs, row_dir, &mut runtime);
    let normal_exit = runtime
        .child
        .as_ref()
        .is_some_and(|child| child.successful_exit);
    let cleanup = runtime.cleanup();
    let cleanup_ok = cleanup.is_ok();
    if let Some(child) = runtime.child.as_ref() {
        write_new(&row_dir.join("fixture.stdout"), &child.output)?;
    }
    let result = match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("row cleanup failed")),
        (Err(error), Err(cleanup)) => Err(anyhow!("{error:#}; row cleanup failed: {cleanup:#}")),
    };
    let status = render_row_status(
        spec,
        result.is_ok(),
        normal_exit,
        cleanup_ok,
        result.as_ref().err().map(one_line).unwrap_or_default(),
    );
    write_new(&row_dir.join("result.status"), status.as_bytes())?;
    result
}

fn render_row_status(
    spec: RowSpec,
    result_ok: bool,
    normal_exit: bool,
    cleanup_ok: bool,
    error: String,
) -> String {
    format!(
        "result={}\nabi={}\nentry={}\nexpected_refusals={}\nexpected_events={}\nnormal_exit={}\ncleanup={}\nerror={}\n",
        if result_ok { "PASS" } else { "NONPASS" },
        spec.abi.label(),
        spec.entry,
        spec.refusals,
        if spec.positive { 2 } else { 0 },
        u8::from(normal_exit),
        if cleanup_ok { "PASS" } else { "NONPASS" },
        error
    )
}

fn run_row_body(
    spec: RowSpec,
    inputs: &Inputs,
    row_dir: &Path,
    runtime: &mut RowRuntime,
) -> Result<()> {
    let (fixture_path, dso_path) = inputs.for_abi(spec.abi);
    let fixture = open_regular(fixture_path)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("opening retained fixture {}", fixture_path.display()))?;
    let dso = open_regular(dso_path)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("opening retained DSO {}", dso_path.display()))?;
    let snapshot = ElfSnapshot::read(&fixture)
        .map_err(anyhow::Error::msg)
        .context("reading fixture ELF snapshot")?;
    if snapshot.abi() != spec.abi.elf() {
        bail!("fixture ELF ABI differs from the matrix row");
    }
    let symbol = snapshot
        .defined_symbol("abi_probe")
        .map_err(anyhow::Error::msg)?
        .context("fixture has no defined abi_probe symbol")?;
    let fixture_info = inspect_file(&fixture).map_err(anyhow::Error::msg)?;
    let dso_info = inspect_file(&dso).map_err(anyhow::Error::msg)?;
    if fixture_info.abi != spec.abi.elf() || dso_info.abi != spec.abi.elf() {
        bail!("retained fixture/DSO ABI differs from the matrix row");
    }
    let fixture_meta = fixture.metadata()?;
    let dso_meta = dso.metadata()?;
    write_new(
        &row_dir.join("subjects.status"),
        format!(
            "fixture_input={}\nfixture_dev={}\nfixture_inode={}\nfixture_sha256={}\nfixture_abi={:?}\nabi_probe_file_offset={:#x}\ndso_input={}\ndso_dev={}\ndso_inode={}\ndso_sha256={}\ndso_abi={:?}\n",
            fixture_path.display(),
            fixture_meta.dev(),
            fixture_meta.ino(),
            fixture_info.identity.sha256.as_deref().context("fixture SHA-256 unavailable")?,
            fixture_info.abi,
            symbol.file_offset,
            dso_path.display(),
            dso_meta.dev(),
            dso_meta.ino(),
            dso_info.identity.sha256.as_deref().context("DSO SHA-256 unavailable")?,
            dso_info.abi,
        )
        .as_bytes(),
    )?;

    runtime.child = Some(OwnedSubject::spawn(spec.abi, fixture, dso, row_dir)?);
    let child = runtime.child.as_mut().context("owned child disappeared")?;
    child.require_stopped_identity(&fixture_meta)?;
    let child_pid = child.pid;

    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .load(p11scope::EBPF_OBJECT)
        .context("loading exact embedded BPF object")?;
    let child_pid = NonZeroU32::new(child_pid).context("owned child PID is zero")?;
    p11scope::attach::prepare_qualification_identity(&mut ebpf, child_pid)
        .context("preparing qualification identity maps")?;
    load_program(&mut ebpf, "p11_return")?;
    load_program(&mut ebpf, spec.entry)?;
    publish_inputs(&mut ebpf, child_pid.get())?;
    for name in ["CONFIG", "PID_FILTER", "DESCRIPTORS"] {
        freeze_map(&ebpf, name)?;
    }
    validate_inputs(&ebpf, child_pid.get())?;
    runtime.ebpf = Some(ebpf);

    let scope = UProbeScope::OneProcess(child_pid);
    let attach_path = format!(
        "/proc/self/fd/{}",
        runtime
            .child
            .as_ref()
            .context("owned child disappeared")?
            .fixture
            .as_raw_fd()
    );
    let point = || UProbeAttachPoint {
        location: UProbeAttachLocation::AbsoluteOffset(symbol.file_offset),
        cookie: Some(attach_cookie(0, 0)),
    };
    let return_link = attach_program(
        runtime.ebpf.as_mut().context("BPF object disappeared")?,
        "p11_return",
        point(),
        &attach_path,
        scope,
    )?;
    runtime.return_link = Some(return_link);
    let entry_link = attach_program(
        runtime.ebpf.as_mut().context("BPF object disappeared")?,
        spec.entry,
        point(),
        &attach_path,
        scope,
    )?;
    runtime.entry_link = Some((spec.entry, entry_link));

    let child = runtime.child.as_mut().context("owned child disappeared")?;
    child.resume()?;
    let status = child.wait_for_exit(EXECUTION_TIMEOUT)?;
    if !status.success() {
        bail!("fixture exited with {status}");
    }
    child.require_terminal_output()?;

    let ebpf = runtime.ebpf.as_mut().context("BPF object disappeared")?;
    let events = drain_events(ebpf, &row_dir.join("events.raw"))?;
    let observed = snapshot_maps(ebpf, events)?;
    validate_and_write_observed(spec, child_pid.get(), row_dir, &observed)?;
    Ok(())
}

fn validate_and_write_observed(
    spec: RowSpec,
    child_pid: u32,
    row_dir: &Path,
    observed: &Observed,
) -> Result<()> {
    write_observed(row_dir, observed)?;
    validate_observed(spec, child_pid, observed)
}

fn load_program(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(name)
        .with_context(|| format!("embedded object has no {name} program"))?
        .try_into()?;
    program.load().with_context(|| format!("loading {name}"))
}

fn attach_program(
    ebpf: &mut Ebpf,
    name: &str,
    point: UProbeAttachPoint<'_>,
    path: &str,
    scope: UProbeScope,
) -> Result<UProbeLinkId> {
    let program: &mut UProbe = ebpf
        .program_mut(name)
        .with_context(|| format!("embedded object has no {name} program"))?
        .try_into()?;
    program
        .attach(point, path, scope)
        .with_context(|| format!("attaching {name} to retained fixture"))
}

fn publish_inputs(ebpf: &mut Ebpf, pid: u32) -> Result<()> {
    let flags = FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED;
    if !valid_config(flags) {
        bail!("qualification CONFIG is invalid");
    }
    {
        let mut config: Array<_, u64> =
            Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map missing")?)?;
        config.set(CFG_FLAGS, flags, 0)?;
    }
    {
        let mut pids: HashMap<_, u32, u64> = HashMap::try_from(
            ebpf.map_mut("PID_FILTER")
                .context("PID_FILTER map missing")?,
        )?;
        pids.insert(pid, 1, 0)?;
    }
    {
        let mut descriptors: Array<_, SlotSemantics> = Array::try_from(
            ebpf.map_mut("DESCRIPTORS")
                .context("DESCRIPTORS map missing")?,
        )?;
        descriptors.set(0, SlotSemantics::COUNT_ONLY, 0)?;
    }
    validate_inputs(ebpf, pid)
}

fn validate_inputs(ebpf: &Ebpf, pid: u32) -> Result<()> {
    let flags = FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED;
    let config: Array<_, u64> = Array::try_from(ebpf.map("CONFIG").context("CONFIG map missing")?)?;
    if config.len() != 2
        || config.get(&CFG_FLAGS, 0)? != flags
        || config.get(&CFG_TASK_NEWTASK_OFFSETS, 0)? != 0
    {
        bail!("CONFIG exact readback differs from the qualification policy");
    }
    let pids: HashMap<_, u32, u64> =
        HashMap::try_from(ebpf.map("PID_FILTER").context("PID_FILTER map missing")?)?;
    let actual = pids.iter().collect::<Result<BTreeMap<_, _>, _>>()?;
    if actual != BTreeMap::from([(pid, 1)]) {
        bail!("PID_FILTER contains anything other than the retained child");
    }
    let descriptors: Array<_, SlotSemantics> =
        Array::try_from(ebpf.map("DESCRIPTORS").context("DESCRIPTORS map missing")?)?;
    if descriptors.get(&0, 0)? != SlotSemantics::COUNT_ONLY {
        bail!("DESCRIPTORS[0] is not explicit COUNT_ONLY");
    }
    Ok(())
}

#[repr(C)]
#[derive(Default)]
struct BpfMapFreezeAttr {
    map_fd: u32,
}

fn freeze_map(ebpf: &Ebpf, name: &str) -> Result<()> {
    let map = ebpf
        .map(name)
        .with_context(|| format!("{name} map missing"))?;
    let data = match (name, map) {
        ("CONFIG" | "DESCRIPTORS", Map::Array(data)) => data,
        ("PID_FILTER", Map::HashMap(data)) => data,
        _ => bail!("refusing unexpected {name} map variant {map:?}"),
    };
    let attr = BpfMapFreezeAttr {
        map_fd: data.fd().as_fd().as_raw_fd() as u32,
    };
    // SAFETY: attr is the complete zero-reserved BPF_MAP_FREEZE command and
    // the borrowed map descriptor remains live for the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            22u32,
            &raw const attr,
            std::mem::size_of_val(&attr),
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error()).with_context(|| format!("freezing {name}"));
    }
    Ok(())
}

fn drain_events(ebpf: &mut Ebpf, path: &Path) -> Result<Vec<Event>> {
    let mut raw = create_new(path)?;
    let mut ring = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map missing")?)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut events = Vec::new();
    loop {
        if Instant::now() >= deadline {
            bail!("EVENTS drain exceeded its monotonic deadline");
        }
        let Some(item) = ring.next() else {
            break;
        };
        let len = u32::try_from(item.len()).context("raw ring item length exceeds u32")?;
        raw.write_all(&len.to_le_bytes())?;
        raw.write_all(&item)?;
        if item.len() != std::mem::size_of::<Event>() {
            bail!("malformed EVENTS item length {}", item.len());
        }
        // SAFETY: the size check proves a complete Event is present; unaligned
        // read is required because ring records do not promise Rust alignment.
        events.push(unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<Event>()) });
        if events.len() > MAX_RAW_RECORDS {
            bail!("EVENTS contains more than {MAX_RAW_RECORDS} records");
        }
    }
    raw.sync_all()?;
    Ok(events)
}

fn snapshot_maps(ebpf: &Ebpf, events: Vec<Event>) -> Result<Observed> {
    let evidence_map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.map("EVIDENCE").context("EVIDENCE map missing")?)?;
    if evidence_map.len() != EVIDENCE_CELLS {
        bail!("EVIDENCE cell count differs from {EVIDENCE_CELLS}");
    }
    let mut evidence = Vec::with_capacity(EVIDENCE_CELLS as usize);
    for index in 0..EVIDENCE_CELLS {
        evidence.push(sum_u64(evidence_map.get(&index, 0)?.iter().copied())?);
    }

    let stats_map: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(ebpf.map("STATS").context("STATS map missing")?)?;
    if stats_map.len() != MAX_SLOTS {
        bail!("STATS slot count differs from {MAX_SLOTS}");
    }
    let mut stats = Vec::with_capacity(MAX_SLOTS as usize);
    for slot in 0..MAX_SLOTS {
        let mut sum = StatsSum::default();
        for cpu in stats_map.get(&slot, 0)?.iter() {
            sum.entered = sum
                .entered
                .checked_add(cpu.entered)
                .context("entered overflow")?;
            sum.returned = sum
                .returned
                .checked_add(cpu.returned)
                .context("returned overflow")?;
            sum.errors = sum
                .errors
                .checked_add(cpu.errors)
                .context("errors overflow")?;
            sum.total_ns = sum
                .total_ns
                .checked_add(cpu.total_ns)
                .context("total_ns overflow")?;
            sum.max_ns = sum.max_ns.max(cpu.max_ns);
            for (dst, value) in sum.buckets.iter_mut().zip(cpu.buckets) {
                *dst = dst.checked_add(value).context("latency bucket overflow")?;
            }
        }
        stats.push(sum);
    }

    let starts_map: HashMap<_, StartKey, CallStart> =
        HashMap::try_from(ebpf.map("START").context("START map missing")?)?;
    let starts = starts_map.iter().collect::<Result<Vec<_>, _>>()?.len();

    let rv_map: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(ebpf.map("RV_COUNTS").context("RV_COUNTS map missing")?)?;
    let mut rvs = BTreeMap::new();
    for entry in rv_map.iter() {
        let (key, values) = entry?;
        if key._pad != 0 {
            bail!("RV_COUNTS contains a key with nonzero padding");
        }
        let count = sum_u64(values.iter().copied())?;
        if count != 0 {
            let total = rvs.get(&(key.slot, key.rv)).copied().unwrap_or(0u64);
            rvs.insert(
                (key.slot, key.rv),
                total.checked_add(count).context("RV count overflow")?,
            );
        }
    }
    Ok(Observed {
        evidence,
        stats,
        starts,
        rvs,
        events,
    })
}

fn validate_observed(spec: RowSpec, child_pid: u32, observed: &Observed) -> Result<()> {
    if observed.evidence.len() != EVIDENCE_CELLS as usize {
        bail!("EVIDENCE has the wrong number of cells");
    }
    for (index, value) in observed.evidence.iter().copied().enumerate() {
        let expected = if index == EVIDENCE_ABI_REFUSALS as usize {
            spec.refusals
        } else {
            0
        };
        if value != expected {
            bail!("EVIDENCE[{index}]={value}, expected {expected} refusals/zero evidence");
        }
    }
    if observed.stats.len() != MAX_SLOTS as usize {
        bail!("STATS has the wrong number of slots");
    }
    let expected_calls = if spec.positive { 2 } else { 0 };
    let expected_errors = if spec.positive { 1 } else { 0 };
    let first = &observed.stats[0];
    if (first.entered, first.returned, first.errors)
        != (expected_calls, expected_calls, expected_errors)
    {
        bail!(
            "slot 0 stats are {}/{}/{}, expected {expected_calls}/{expected_calls}/{expected_errors}",
            first.entered,
            first.returned,
            first.errors
        );
    }
    let bucket_count = sum_u64(first.buckets.iter().copied())?;
    if bucket_count != expected_calls || first.max_ns > first.total_ns {
        bail!("slot 0 latency accounting is inconsistent");
    }
    if !spec.positive && (first.total_ns != 0 || first.max_ns != 0) {
        bail!("refusal row has nonzero latency accounting");
    }
    for (slot, value) in observed.stats.iter().enumerate().skip(1) {
        if !stats_zero(value) {
            bail!("unused STATS slot {slot} is nonzero");
        }
    }
    if observed.starts != 0 {
        bail!(
            "START contains {} entries after fixture exit",
            observed.starts
        );
    }
    let expected_rvs = if spec.positive {
        BTreeMap::from([((0, 0), 1), ((0, spec.abi.vendor_rv()), 1)])
    } else {
        BTreeMap::new()
    };
    if observed.rvs != expected_rvs {
        bail!("RV_COUNTS differs from the exact two-call oracle");
    }
    let expected_events = if spec.positive { 2 } else { 0 };
    if observed.events.len() != expected_events {
        bail!(
            "raw events count is {}, expected {expected_events}",
            observed.events.len()
        );
    }
    for (index, event) in observed.events.iter().enumerate() {
        validate_event(event, child_pid, [0, spec.abi.vendor_rv()][index])?;
    }
    Ok(())
}

fn validate_event(event: &Event, pid: u32, rv: u64) -> Result<()> {
    let exact_pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
    if event.ts_ns == 0
        || event.pid_tgid != exact_pid_tgid
        || event.session != SESSION_NONE
        || event.slot_id != 0
        || event.mechanism != MECH_NONE
        || event.flags != 0
        || event.rv != rv
        || event.p0 != 0
        || event.p1 != 0
        || event.p2 != 0
        || event.async_value != 0
        || event.slot != 0
        || event.target_function != FUNCTION_NONE
        || event.user_type != USER_TYPE_NONE
        || event.shape != shape::NONE
        || event.attr_types != [0; p11scope_ebpf_common::MAX_ATTRS]
        || event.attr_count != 0
        || event.attr_total != 0
        || event.attr_bools != 0
        || event.attr_bools_seen != 0
        || event.attr_types1 != [0; p11scope_ebpf_common::MAX_ATTRS]
        || event.attr_count1 != 0
        || event.attr_total1 != 0
        || event.attr_bools1 != 0
        || event.attr_bools_seen1 != 0
        || event.capture != 0
        || event.event_type != event_type::CALL
    {
        bail!("CALL event differs from the exact COUNT_ONLY wire oracle");
    }
    Ok(())
}

fn write_observed(row_dir: &Path, observed: &Observed) -> Result<()> {
    let first = &observed.stats[0];
    let evidence = observed
        .evidence
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{index}:{value}"))
        .collect::<Vec<_>>()
        .join(",");
    let rvs = observed
        .rvs
        .iter()
        .map(|((slot, rv), count)| format!("{slot}:{rv:#x}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    write_new(
        &row_dir.join("observed.status"),
        format!(
            "evidence={}\nentered={}\nreturned={}\nerrors={}\nstart_entries={}\nrv_counts={}\nraw_events={}\n",
            evidence,
            first.entered,
            first.returned,
            first.errors,
            observed.starts,
            rvs,
            observed.events.len()
        )
        .as_bytes(),
    )
}

fn stats_zero(stats: &StatsSum) -> bool {
    stats.entered == 0
        && stats.returned == 0
        && stats.errors == 0
        && stats.total_ns == 0
        && stats.max_ns == 0
        && stats.buckets == [0; p11scope_ebpf_common::LATENCY_BUCKETS]
}

fn sum_u64(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |sum, value| {
        sum.checked_add(value).context("counter sum overflow")
    })
}

#[derive(Default)]
struct RowRuntime {
    child: Option<OwnedSubject>,
    ebpf: Option<Ebpf>,
    entry_link: Option<(&'static str, UProbeLinkId)>,
    return_link: Option<UProbeLinkId>,
}

impl RowRuntime {
    fn cleanup(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some((name, link)) = self.entry_link.take()
                && let Err(error) = detach_program(ebpf, name, link)
            {
                failures.push(format!("detaching {name}: {error:#}"));
            }
            if let Some(link) = self.return_link.take()
                && let Err(error) = detach_program(ebpf, "p11_return", link)
            {
                failures.push(format!("detaching p11_return: {error:#}"));
            }
        }
        self.ebpf.take();
        if let Some(child) = self.child.as_mut()
            && let Err(error) = child.terminate()
        {
            failures.push(format!("terminating owned child: {error:#}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(failures.join("; "))
        }
    }
}

impl Drop for RowRuntime {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn detach_program(ebpf: &mut Ebpf, name: &str, link: UProbeLinkId) -> Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(name)
        .with_context(|| format!("loaded {name} program disappeared"))?
        .try_into()?;
    program
        .detach(link)
        .with_context(|| format!("detaching {name}"))
}

struct OwnedSubject {
    child: Child,
    pid: u32,
    pidfd: OwnedFd,
    fixture: File,
    _dso: File,
    stdout: ChildStdout,
    output: Vec<u8>,
    abi: SubjectAbi,
    starttime: u64,
    reaped: bool,
    successful_exit: bool,
}

impl OwnedSubject {
    fn spawn(abi: SubjectAbi, fixture: File, dso: File, row_dir: &Path) -> Result<Self> {
        let parent_pid = std::process::id();
        let fixture_exec = format!("/proc/self/fd/{}", fixture.as_raw_fd());
        let dso_arg = format!("/proc/{parent_pid}/fd/{}", dso.as_raw_fd());
        let stderr = create_new(&row_dir.join("fixture.stderr"))?;
        let mut command = Command::new(&fixture_exec);
        command
            .arg(&dso_arg)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .env_clear();
        // SAFETY: only async-signal-safe prctl/getppid calls run between fork
        // and exec. A changed parent makes exec fail, closing the setup race.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
        let mut child = command.spawn().context("spawning retained fixture")?;
        let pid = child.id();
        let pidfd = match pidfd_open(pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                // The unreaped direct Child still pins this PID generation;
                // this bootstrap-only fallback prevents a stopped orphan.
                let cleanup = terminate_unpinned_child(&mut child);
                return match cleanup {
                    Ok(()) => Err(error).context("opening mandatory pidfd for direct child"),
                    Err(cleanup) => Err(anyhow!(
                        "opening mandatory pidfd for direct child: {error}; \
                         bounded bootstrap cleanup failed: {cleanup}"
                    )),
                };
            }
        };
        let stdout = child
            .stdout
            .take()
            .expect("stdout was configured as a pipe immediately before spawn");
        let mut owned = Self {
            child,
            pid,
            pidfd,
            fixture,
            _dso: dso,
            stdout,
            output: Vec::new(),
            abi,
            starttime: 0,
            reaped: false,
            successful_exit: false,
        };
        let initialize = (|| -> Result<u64> {
            set_nonblocking(owned.stdout.as_raw_fd())?;
            let (_, ppid, starttime) = proc_stat(pid)?;
            if ppid != parent_pid {
                bail!("fixture parent changed before identity pinning");
            }
            Ok(starttime)
        })();
        owned.starttime = match initialize {
            Ok(starttime) => starttime,
            Err(error) => return Err(owned.cleanup_initialization_error(error)),
        };
        Ok(owned)
    }

    fn require_stopped_identity(&mut self, expected: &fs::Metadata) -> Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        let (ready, _) = self.abi.fixture_markers();
        loop {
            self.pump_output()?;
            let (state, ppid, starttime) = proc_stat(self.pid)?;
            if starttime != self.starttime || ppid != std::process::id() {
                bail!("fixture PID/starttime/parent identity changed before release");
            }
            if self.output == ready.as_bytes() && matches!(state, 'T' | 't') {
                let proc_exe = File::open(format!("/proc/{}/exe", self.pid))?;
                let actual = proc_exe.metadata()?;
                if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
                    bail!("stopped fixture executable identity differs from retained input");
                }
                return Ok(());
            }
            if pidfd_ready(&self.pidfd, Duration::ZERO)? {
                bail!("fixture exited before READY plus stopped-state proof");
            }
            if Instant::now() >= deadline {
                bail!("fixture did not reach READY plus stopped state before deadline");
            }
            poll_pipe(&self.stdout, &self.pidfd, deadline)?;
        }
    }

    fn resume(&self) -> Result<()> {
        pidfd_signal(&self.pidfd, libc::SIGCONT).context("resuming fixture through pidfd")
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        let mut output_error = None;
        while !pidfd_ready(&self.pidfd, Duration::ZERO)? {
            if output_error.is_none()
                && let Err(error) = self.pump_output()
            {
                output_error = Some(error);
            }
            if Instant::now() >= deadline {
                bail!("fixture execution exceeded its monotonic deadline");
            }
            poll_pipe(&self.stdout, &self.pidfd, deadline)?;
        }
        let reaped = self.reap_ready_child();
        match (output_error, reaped) {
            (None, result) => result,
            (Some(output), Ok(_)) => Err(output.context("capturing output before child exit")),
            (Some(output), Err(reap)) => Err(anyhow!(
                "capturing pre-exit child output failed: {output:#}; \
                 exited-child handling failed: {reap:#}"
            )),
        }
    }

    fn require_terminal_output(&self) -> Result<()> {
        let (ready, done) = self.abi.fixture_markers();
        let expected = format!("{ready}{done}");
        if self.output != expected.as_bytes() {
            bail!("fixture output lacks the exact READY/DONE terminal markers");
        }
        Ok(())
    }

    fn pump_output(&mut self) -> Result<()> {
        let mut bytes = [0u8; 256];
        loop {
            // SAFETY: stdout is an owned open pipe and bytes is writable.
            let read = unsafe {
                libc::read(
                    self.stdout.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if read > 0 {
                self.output.extend_from_slice(&bytes[..read as usize]);
                if self.output.len() > 4096 {
                    bail!("fixture output exceeded its bounded marker capacity");
                }
                continue;
            }
            if read == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(());
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("reading fixture markers");
            }
        }
    }

    fn terminate(&mut self) -> Result<()> {
        if self.reaped {
            return Ok(());
        }
        if !pidfd_ready(&self.pidfd, Duration::ZERO)? {
            pidfd_signal(&self.pidfd, libc::SIGKILL)
                .context("killing still-owned child through pidfd")?;
        }
        if !pidfd_ready(&self.pidfd, CLEANUP_TIMEOUT)? {
            bail!("owned child did not exit before cleanup deadline");
        }
        self.reap_ready_child().map(|_| ())
    }

    fn reap_ready_child(&mut self) -> Result<ExitStatus> {
        let output = self.pump_output();
        let wait = self.child.try_wait();
        let status = match wait {
            Ok(Some(status)) => {
                self.reaped = true;
                self.successful_exit = status.success();
                Ok(status)
            }
            Ok(None) => Err(anyhow!("pidfd was ready but direct child was not waitable")),
            Err(error) => Err(anyhow!(error).context("reaping pidfd-ready direct child")),
        };
        match (output, status) {
            (Ok(()), Ok(status)) => Ok(status),
            (Err(output), Ok(_)) => Err(output.context("capturing output from reaped child")),
            (Ok(()), Err(wait)) => Err(wait),
            (Err(output), Err(wait)) => Err(anyhow!(
                "capturing exited-child output failed: {output:#}; direct-child reap failed: {wait:#}"
            )),
        }
    }

    fn cleanup_initialization_error(mut self, error: anyhow::Error) -> anyhow::Error {
        match self.terminate() {
            Ok(()) => error,
            Err(cleanup) => {
                anyhow!("{error:#}; bounded child initialization cleanup failed: {cleanup:#}")
            }
        }
    }
}

impl Drop for OwnedSubject {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open accepts scalar PID/flags and returns a new fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful syscall returned one owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn terminate_unpinned_child(child: &mut Child) -> io::Result<()> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unreaped direct child did not exit after SIGKILL",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn pidfd_signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: pidfd is owned; siginfo is null and flags are zero.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn pidfd_ready(pidfd: &OwnedFd, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    let mut fd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let millis = i32::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(i32::MAX);
        // SAFETY: fd points to one initialized pollfd.
        let rc = unsafe { libc::poll(&mut fd, 1, millis) };
        if rc == 0 {
            return Ok(false);
        }
        if rc > 0 {
            if fd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pidfd became invalid while polling",
                ));
            }
            return Ok(fd.revents & libc::POLLIN != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

fn poll_pipe(stdout: &ChildStdout, pidfd: &OwnedFd, deadline: Instant) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = i32::try_from(remaining.min(Duration::from_millis(20)).as_millis()).unwrap_or(20);
    let mut fds = [
        libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: fds is a live initialized two-element pollfd array.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if rc >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: fd is an open pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL accepts the retrieved flags plus O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn proc_stat(pid: u32) -> io::Result<(char, u32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))?;
    let fields: Vec<_> = tail.split_ascii_whitespace().collect();
    let state = fields
        .first()
        .and_then(|value| value.chars().next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc state"))?;
    let ppid = fields
        .get(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc parent"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc parent"))?;
    let starttime = fields
        .get(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc starttime"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc starttime"))?;
    Ok((state, ppid, starttime))
}

fn create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_new(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn one_line(error: &impl std::fmt::Display) -> String {
    error.to_string().replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal_spec() -> RowSpec {
        RowSpec {
            name: "refusal",
            abi: SubjectAbi::Ia32,
            entry: "p11_entry",
            refusals: 2,
            positive: false,
        }
    }

    fn empty_observed() -> Observed {
        Observed {
            evidence: vec![0; EVIDENCE_CELLS as usize],
            stats: (0..MAX_SLOTS).map(|_| StatsSum::default()).collect(),
            ..Observed::default()
        }
    }

    fn status_field(status: &str, name: &str) -> String {
        status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .expect("status field")
            .to_string()
    }

    fn completed_output_subject(bytes: usize) -> OwnedSubject {
        let script = format!("import os; os.write(1, b'x' * {bytes})");
        let mut child = Command::new("python3")
            .args(["-I", "-c", &script])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn output child");
        let pid = child.id();
        let pidfd = pidfd_open(pid).expect("open pidfd");
        let stdout = child.stdout.take().expect("stdout");
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking stdout");
        let starttime = proc_stat(pid).expect("proc stat").2;
        OwnedSubject {
            child,
            pid,
            pidfd,
            fixture: File::open("/dev/null").unwrap(),
            _dso: File::open("/dev/null").unwrap(),
            stdout,
            output: Vec::new(),
            abi: SubjectAbi::Native64,
            starttime,
            reaped: false,
            successful_exit: false,
        }
    }

    #[test]
    fn missing_positive_refusal_is_rejected() {
        let error = validate_observed(refusal_spec(), 1, &empty_observed()).unwrap_err();
        assert!(error.to_string().contains("refusals"), "{error:#}");
    }

    #[test]
    fn a_refusal_row_rejects_an_unexpected_raw_event() {
        let mut observed = empty_observed();
        observed.evidence[EVIDENCE_ABI_REFUSALS as usize] = 2;
        observed.events.push(Event::default());
        let error = validate_observed(refusal_spec(), 1, &observed).unwrap_err();
        assert!(error.to_string().contains("events"), "{error:#}");
    }

    #[test]
    fn row_status_reports_result_and_cleanup_independently() {
        for (case, result_ok, cleanup_ok, expected_result, expected_cleanup) in [
            ("success", true, true, "PASS", "PASS"),
            ("body-only", false, true, "NONPASS", "PASS"),
            ("cleanup-only", false, false, "NONPASS", "NONPASS"),
            ("body-and-cleanup", false, false, "NONPASS", "NONPASS"),
        ] {
            let status = render_row_status(
                refusal_spec(),
                result_ok,
                false,
                cleanup_ok,
                case.to_string(),
            );
            assert_eq!(status_field(&status, "result"), expected_result, "{case}");
            assert_eq!(status_field(&status, "cleanup"), expected_cleanup, "{case}");
            assert_eq!(status_field(&status, "error"), case, "{case}");
        }
    }

    #[test]
    fn rejected_observations_are_persisted_before_validation() {
        let directory = tempfile::tempdir().unwrap();
        let error =
            validate_and_write_observed(refusal_spec(), 1, directory.path(), &empty_observed())
                .unwrap_err();
        assert!(error.to_string().contains("refusals"), "{error:#}");
        let receipt = fs::read_to_string(directory.path().join("observed.status"))
            .expect("rejected observation receipt");
        assert!(receipt.contains("evidence=0:0"), "{receipt}");
        assert!(receipt.contains("raw_events=0"), "{receipt}");
    }

    #[test]
    fn output_failure_after_pidfd_exit_still_reaps_the_child() {
        let mut subject = completed_output_subject(5000);
        let error = subject.wait_for_exit(Duration::from_secs(5)).unwrap_err();
        let error_chain = format!("{error:#}");
        assert!(error_chain.contains("bounded marker capacity"), "{error:#}");
        assert!(
            subject.reaped,
            "output failure suppressed direct-child reap"
        );
        assert!(subject.child.try_wait().unwrap().is_some());
    }

    #[test]
    fn stopped_child_is_killed_and_reaped_by_bounded_cleanup() {
        let script =
            "import os, signal, time; os.kill(os.getpid(), signal.SIGSTOP); time.sleep(30)";
        let mut child = Command::new("python3")
            .args(["-I", "-c", script])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn stopped child");
        let pid = child.id();
        let pidfd = pidfd_open(pid).expect("open pidfd");
        let stdout = child.stdout.take().expect("stdout");
        set_nonblocking(stdout.as_raw_fd()).expect("nonblocking stdout");
        let starttime = proc_stat(pid).expect("proc stat").2;
        let mut subject = OwnedSubject {
            child,
            pid,
            pidfd,
            fixture: File::open("/dev/null").unwrap(),
            _dso: File::open("/dev/null").unwrap(),
            stdout,
            output: Vec::new(),
            abi: SubjectAbi::Native64,
            starttime,
            reaped: false,
            successful_exit: false,
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if matches!(proc_stat(pid).expect("stopped proc stat").0, 'T' | 't') {
                break;
            }
            assert!(Instant::now() < deadline, "child did not stop");
            std::thread::sleep(Duration::from_millis(10));
        }
        subject.terminate().expect("bounded stopped-child cleanup");
        assert!(subject.reaped);
        assert!(subject.child.try_wait().unwrap().is_some());
    }

    #[test]
    fn real_embedded_bpf_export_is_hashed_and_mismatch_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let exact_path = directory.path().join("exact-bpf.o");
        write_new(&exact_path, p11scope::EBPF_OBJECT).unwrap();
        let independent = Command::new("sha256sum")
            .arg(&exact_path)
            .output()
            .expect("run independent sha256sum");
        assert!(independent.status.success());
        let independent = String::from_utf8(independent.stdout).unwrap();
        let expected_digest = independent
            .split_ascii_whitespace()
            .next()
            .expect("sha256sum digest");

        let mut exact = open_regular(&exact_path).unwrap();
        exact.seek(SeekFrom::End(0)).unwrap();
        let digest = verify_embedded_export(&exact, p11scope::EBPF_OBJECT).unwrap();
        assert_eq!(digest, expected_digest);

        let mut changed = p11scope::EBPF_OBJECT.to_vec();
        let changed_index = changed.len() / 2;
        changed[changed_index] ^= 1;
        let mut appended = p11scope::EBPF_OBJECT.to_vec();
        appended.push(0);
        for (name, bytes) in [
            ("changed", changed.as_slice()),
            (
                "truncated",
                &p11scope::EBPF_OBJECT[..p11scope::EBPF_OBJECT.len() - 1],
            ),
            ("appended", appended.as_slice()),
        ] {
            let path = directory.path().join(format!("{name}-bpf.o"));
            write_new(&path, bytes).unwrap();
            let export = open_regular(&path).unwrap();
            let error = verify_embedded_export(&export, p11scope::EBPF_OBJECT).unwrap_err();
            assert!(
                error.to_string().contains("bytes differ"),
                "{name}: {error:#}"
            );
        }
    }
}
