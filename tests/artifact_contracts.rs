use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("reading {path}: {error}"))
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing section end: {end}"))
        .0
}

fn contract_section<'a>(source: &'a str, start: &str, end: &str) -> Result<&'a str, String> {
    source
        .split_once(start)
        .ok_or_else(|| format!("missing contract section start: {start}"))?
        .1
        .split_once(end)
        .map(|(section, _)| section)
        .ok_or_else(|| format!("missing contract section end: {end}"))
}

fn require_contract_marker(section: &str, marker: &str, contract: &str) -> Result<(), String> {
    if section.contains(marker) {
        Ok(())
    } else {
        Err(format!("{contract} missing {marker:?}"))
    }
}

fn require_before(source: &str, first: &str, second: &str, contract: &str) -> Result<(), String> {
    let first = source
        .find(first)
        .ok_or_else(|| format!("{contract} missing first marker {first:?}"))?;
    let second = source
        .find(second)
        .ok_or_else(|| format!("{contract} missing second marker {second:?}"))?;
    if first < second {
        Ok(())
    } else {
        Err(format!("{contract} is out of order"))
    }
}

fn assert_exact_policy_map_metadata_contract(attach: &str) -> Result<(), String> {
    let declarations =
        contract_section(attach, "const BASE_POLICY_MAPS:", "const TAIL_POLICY_MAP:")?;
    let compact: String = declarations
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .replace(",)", ")");
    for expected in [
        "(\"CONFIG\",map_metadata(MapType::Array,4,8,1,BPF_F_RDONLY_PROG))",
        "(\"PID_FILTER\",map_metadata(MapType::Hash,4,8,1_024,BPF_F_RDONLY_PROG))",
        "(\"CGROUP_FILTER\",map_metadata(MapType::CgroupArray,4,4,1,0))",
        "(\"DESCRIPTORS\",map_metadata(MapType::Array,4,18,MAX_DESCRIPTORS,BPF_F_RDONLY_PROG))",
        "(\"ASYNC_FUNCTIONS\",map_metadata(MapType::Hash,32,4,128,BPF_F_RDONLY_PROG))",
        "(\"MECH_SHAPE\",map_metadata(MapType::Hash,8,4,p11scope_ebpf_common::MAX_MECH_SHAPES,BPF_F_RDONLY_PROG))",
        "(\"ATTR_BOOL_BITS\",map_metadata(MapType::Hash,4,4,16,BPF_F_RDONLY_PROG))",
        "(\"TEMPLATE_TAIL\",map_metadata(MapType::ProgramArray,4,4,1,0))",
    ] {
        if !compact.contains(expected) {
            return Err(format!("exact policy-map metadata missing {expected}"));
        }
    }

    let validator = contract_section(attach, "fn validate_map_metadata(", "fn freeze_map(")?;
    for marker in [
        "map_type: info.map_type()?",
        "key_size: info.key_size()",
        "value_size: info.value_size()",
        "max_entries: info.max_entries()",
        "flags: info.map_flags()",
        "if actual != expected",
        "for (name, expected) in BASE_POLICY_MAPS",
        "for (name, expected) in FEATURE_POLICY_MAPS",
        "{name} must be absent from the default eBPF object",
    ] {
        require_contract_marker(validator, marker, "exact policy-map metadata validator")?;
    }
    require_before(
        attach,
        "validate_policy_maps(&ebpf, object_has_unsafe)",
        "crate::scope::publish(&mut ebpf, scope, policy, generation_token)",
        "exact policy-map metadata before publication",
    )
}

fn assert_live_discovery_host_contract(
    attach: &str,
    scope: &str,
    events: &str,
    hooks: &str,
    engine: &str,
    main: &str,
    run: &str,
) -> Result<(), String> {
    assert_exact_policy_map_metadata_contract(attach)?;
    for (marker, contract) in [
        (
            "pub(crate) struct OwnedPauseGeneration {\n    tgid: u32,\n    generation: NonZeroU64,\n}",
            "opaque owned pause capability",
        ),
        ("pub(crate) ebpf: Ebpf,", "crate-only mutable Ebpf"),
        (
            "pause_generation: Option<OwnedPauseGeneration>,",
            "five-argument Session start",
        ),
        (
            "pub fn event_drain(&mut self) -> Result<events::Drain<'_>>",
            "fixed-purpose public EVENTS drain",
        ),
        (
            "pub(crate) fn discovery_dequeue(",
            "crate-only one-item DISCOVERY dequeue",
        ),
        (
            "fn arm_pause(&mut self)",
            "argument-free crate-internal pause arm",
        ),
    ] {
        require_contract_marker(attach, marker, contract)?;
    }
    for (marker, contract) in [
        (
            "struct DiscoveryDrain<'a>",
            "separate discovery drain owner",
        ),
        (
            "pub(crate) enum DiscoveryItem {\n    Record(DiscoveryRecord),\n    Malformed,\n}",
            "explicit one-item discovery outcome",
        ),
    ] {
        require_contract_marker(events, marker, contract)?;
    }
    for (marker, contract) in [
        ("pub fn id(&self, name: &str)", "stable hook ID lookup"),
        ("pub fn by_id(&self, id: u32)", "stable hook reverse lookup"),
    ] {
        require_contract_marker(hooks, marker, contract)?;
    }

    for banned in ["pub tgid:", "pub generation:", "from_parts", "into_parts"] {
        if attach.contains(banned) {
            return Err(format!("opaque pause capability exposes {banned:?}"));
        }
    }
    require_before(
        attach,
        "let pause_key = pause_key_for(",
        "Self::start_inner(",
        "owned capability validation before load",
    )?;
    require_before(
        attach,
        "crate::scope::publish(&mut ebpf, scope, policy, generation_token)",
        "freeze_published_maps(&ebpf)",
        "scope publication before base freeze",
    )?;
    require_before(
        attach,
        "freeze_published_maps(&ebpf)",
        "for prog_name in programs",
        "base freeze before program load",
    )?;
    require_before(
        attach,
        "for prog_name in programs",
        "freeze_map(\n            \"DESCRIPTORS\"",
        "all program loads before descriptor freeze",
    )?;
    require_before(
        attach,
        "publish_and_freeze_template_tail(&mut ebpf, object_has_unsafe, unsafe_enabled)",
        ".attach(\"sched\", \"sched_process_fork\")",
        "tail publication before first producer attach",
    )?;

    for (marker, contract) in [
        (
            "pub(crate) fn publish(",
            "crate-only raw generation-token publication",
        ),
        ("HashMap<_, u32, u64>", "u64 PID_FILTER value"),
        ("generation_token.unwrap_or(1)", "fixed ordinary PID token"),
        ("FLAG_PAUSE_ENABLED", "pause config bit"),
        ("File::open(path)", "opened cgroup descriptor"),
        (
            "let opened_id = directory",
            "opened cgroup inode revalidation",
        ),
        (
            "groups.set(0, directory.try_clone()?, 0)?",
            "cgroup insertion proof",
        ),
    ] {
        require_contract_marker(scope, marker, contract)?;
    }

    if main.contains("Session::start(")
        || run.contains("Session::start(")
        || engine.matches("Session::start(").count() != 1
        || engine
            .matches("Session::start(plan, scope, pinned, policy, pause_generation.take())")
            .count()
            != 1
        || engine
            .matches("self.start_session_with(policy, None, None)")
            .count()
            != 1
        || engine
            .matches("let generation = OwnedPauseGeneration::from_owned_child(child);")
            .count()
            != 1
        || attach
            .matches("fn from_owned_child(child: &OwnedChild)")
            .count()
            != 1
    {
        return Err(
            "Engine must own one shared Session::start route and one owned-child capability caller"
                .into(),
        );
    }
    // Task 8 Step 2 moved the one profile loop and the one trace loop out of
    // the binary into `src/run.rs`, so `profile`, `trace` and `run` share
    // exactly one of each. The seam contract follows the loops: neither the
    // binary nor the loop module may reach past `Session::event_drain`, and
    // the two drains are still exactly the periodic one and the terminal one.
    if main.contains("events::Drain::new(&mut session.ebpf)")
        || main.contains("session.event_drain()?")
        || run.contains("events::Drain::new(&mut session.ebpf)")
        || run.matches("session.event_drain()?").count() != 2
    {
        return Err("the binary must use only the fixed-purpose event drain seam".into());
    }
    if attach.matches("map_mut(\"PAUSE_PIDS\")").count() != 2
        || attach.matches("arm_pause(").count() != 1
        || attach.matches("pause_state(").count() != 1
        || attach.matches("remove_pause(").count() != 1
        || scope.contains("PAUSE_PIDS")
    {
        return Err("Task 7 must keep the exact internal pause authorization surface".into());
    }
    for (marker, contract) in [
        (
            "let object_has_unsafe = cfg!(feature = \"unsafe-unvalidated-metadata\");",
            "object-feature inventory selection",
        ),
        (
            "let programs = expected_programs(object_has_unsafe);",
            "complete object program load",
        ),
        (
            "publish_and_freeze_template_tail(&mut ebpf, object_has_unsafe, unsafe_enabled)",
            "safe-policy handling in the unsafe object",
        ),
    ] {
        require_contract_marker(attach, marker, contract)?;
    }
    Ok(())
}

fn assert_owned_run_pause_internal_contract(
    attach: &str,
    events: &str,
    engine: &str,
    library: &str,
    main: &str,
    pause: &str,
    run: &str,
) -> Result<(), String> {
    for (source, marker, contract) in [
        (library, "pub(crate) mod run;", "crate-private run module"),
        (
            pause,
            "pub(crate) struct PauseCoordinator",
            "crate-private pause coordinator",
        ),
        (
            pause,
            "pub(crate) struct SessionPauseIo",
            "fixed Session/Engine pause adapter",
        ),
        (
            run,
            "pub(crate) struct OwnedChild",
            "crate-private owned child",
        ),
        (
            attach,
            "fn from_owned_child(child: &OwnedChild)",
            "owned-child-only capability",
        ),
        (
            events,
            "pub(crate) enum DiscoveryItem",
            "one-item discovery result",
        ),
        (
            engine,
            "let generation = OwnedPauseGeneration::from_owned_child(child);",
            "sole present-capability construction",
        ),
        (
            pause,
            ".apply_discovery_batch_with(",
            "sole Engine discovery application authority",
        ),
        (
            pause,
            "self.child.pin().send_signal(libc::SIGCONT)",
            "original-pidfd resume authority",
        ),
    ] {
        require_contract_marker(source, marker, contract)?;
    }
    if main.contains("OwnedChild")
        || main.contains("PauseCoordinator")
        || library.contains("pub mod run;")
        || attach.contains("pub struct OwnedPauseGeneration")
        || engine
            .matches("let generation = OwnedPauseGeneration::from_owned_child(child);")
            .count()
            != 1
    {
        return Err("Task 7 machinery must remain internal and owned-child-only".into());
    }
    let timed_dequeue = contract_section(pause, "fn timed_dequeue(", "fn fail_cycle(")?;
    require_before(
        timed_dequeue,
        "let before_ns = io.now_ns().map_err(TimedDequeueError::Failure)?;",
        "let item = io.dequeue().map_err(TimedDequeueError::Failure)?;",
        "clock before each discovery dequeue",
    )?;
    require_before(
        timed_dequeue,
        "let item = io.dequeue().map_err(TimedDequeueError::Failure)?;",
        "let after_ns = io.now_ns().map_err(TimedDequeueError::Failure)?;",
        "clock after each discovery dequeue",
    )
}

fn assert_static_descriptor_cookie_contract(attach: &str, ebpf: &str) -> Result<(), String> {
    const COOKIE: &str = "cookie: Some(attach_cookie(slot.index, slot.descriptor_index)),";

    let scheduling = contract_section(
        attach,
        "fn attach_targets_with(",
        "fn standard_async_catalog",
    )?;
    require_contract_marker(
        scheduling,
        "attach(\"p11_return\", slot)",
        "return-before-entry scheduling",
    )?;
    require_contract_marker(
        scheduling,
        "for program in entry_programs {",
        "entry scheduling",
    )?;
    require_contract_marker(
        scheduling,
        "!return_attached.contains(&slot.index)",
        "return failure entry suppression",
    )?;
    let attach_targets = contract_section(
        attach,
        "pub(crate) fn attach_targets(",
        "pub fn replace_targets",
    )?;
    require_contract_marker(attach_targets, COOKIE, "shared slot attach cookie")?;
    require_contract_marker(attach_targets, "prog.attach(point", "Aya uprobe attachment")?;

    let cookie = contract_section(ebpf, "fn slot_of<C>", "/// Decode allowlisted")?;
    require_contract_marker(
        cookie,
        "cookie_slot(cookie_of(ctx))",
        "low cookie word slot decode",
    )?;
    require_contract_marker(
        cookie,
        "DESCRIPTORS\n        .get(cookie_descriptor(cookie_of(ctx)))",
        "high cookie word descriptor lookup",
    )?;
    require_contract_marker(
        cookie,
        ".unwrap_or(SlotSemantics::COUNT_ONLY)",
        "missing descriptor count-only fallback",
    )?;

    let primary_and_templates = contract_section(
        ebpf,
        "pub fn p11_entry(ctx: ProbeContext) -> u32 {",
        "pub fn p11_entry_template_second",
    )?;
    for (marker, contract) in [
        ("p11_entry_impl::<0>(ctx)", "p11_entry descriptor consumer"),
        (
            "p11_entry_impl::<1>(ctx)",
            "p11_entry_template descriptor consumer",
        ),
        (
            "p11_entry_impl::<2>(ctx)",
            "p11_entry_template_types descriptor consumer",
        ),
        (
            "p11_entry_impl::<3>(ctx)",
            "p11_entry_template_pair descriptor consumer",
        ),
    ] {
        require_contract_marker(primary_and_templates, marker, contract)?;
    }

    let template_second = contract_section(
        ebpf,
        "pub fn p11_entry_template_second(ctx: ProbeContext) -> u32 {",
        "fn store_start",
    )?;
    for (marker, contract) in [
        ("let slot = slot_of(&ctx);", "template-second low-word slot"),
        (
            "let key = StartKey {\n        pid_tgid: helpers::bpf_get_current_pid_tgid(),\n        slot,\n        _pad: 0,\n    };",
            "template-second START slot",
        ),
        ("START.get_ptr_mut(&key)", "template-second START lookup"),
        (
            "let semantics = semantics_of(&ctx);",
            "template-second descriptor consumer",
        ),
    ] {
        require_contract_marker(template_second, marker, contract)?;
    }

    let entry = contract_section(
        ebpf,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8>(ctx: ProbeContext) -> u32 {",
        "#[uretprobe]",
    )?;
    for (marker, contract) in [
        ("let slot = slot_of(&ctx);", "entry low-word slot"),
        ("STATS.get_ptr_mut(slot)", "entry STATS slot"),
        (
            "let key = StartKey {\n        pid_tgid: helpers::bpf_get_current_pid_tgid(),\n        slot,\n        _pad: 0,\n    };",
            "entry START slot",
        ),
        (
            "let semantics = semantics_of(&ctx);",
            "entry descriptor consumer",
        ),
    ] {
        require_contract_marker(entry, marker, contract)?;
    }

    let returned = contract_section(
        ebpf,
        "pub fn p11_return(ctx: RetProbeContext) -> u32 {",
        "#[tracepoint(category = \"sched\", name = \"sched_process_fork\")]",
    )?;
    for (marker, contract) in [
        ("let slot = slot_of(&ctx);", "return low-word slot"),
        (
            "let key = StartKey {\n        pid_tgid: helpers::bpf_get_current_pid_tgid(),\n        slot,\n        _pad: 0,\n    };",
            "return START slot",
        ),
        ("START.get(&key)", "return START lookup"),
        ("START.remove(&key)", "return START removal"),
        ("STATS.get_ptr_mut(slot)", "return STATS slot"),
        (
            "let rk = RvKey { slot, _pad: 0, rv };",
            "return RV_COUNTS slot",
        ),
        ("RV_COUNTS.get(&rk)", "return RV_COUNTS lookup"),
        (
            "RV_COUNTS.insert(&rk, &(prev + 1), 0)",
            "return RV_COUNTS update",
        ),
        ("\n        slot,\n        target_function:", "Event.slot"),
        (
            "let semantics = semantics_of(&ctx);",
            "return descriptor consumer",
        ),
    ] {
        require_contract_marker(returned, marker, contract)?;
    }
    Ok(())
}

fn assert_descriptor_publication_contract(attach: &str) -> Result<(), String> {
    let publication =
        contract_section(attach, "fn publish_descriptors", "fn publish_async_catalog")?;
    for (marker, contract) in [
        (
            "let expected = crate::kinds::DESCRIPTORS.to_vec();",
            "fixed descriptor inventory",
        ),
        (
            "for (index, value) in expected.iter().copied().enumerate() {",
            "complete descriptor write loop",
        ),
        (
            "semantics.set(index as u32, value, 0)?;",
            "descriptor map write",
        ),
        (
            "let actual = semantics.iter().collect::<Result<Vec<_>, _>>()?;",
            "complete descriptor readback",
        ),
        (
            "if actual != expected {",
            "exact descriptor readback comparison",
        ),
        (
            "bail!(\"DESCRIPTORS exact readback differs from the fixed inventory\");",
            "inexact descriptor readback refusal",
        ),
    ] {
        require_contract_marker(publication, marker, contract)?;
    }
    Ok(())
}

fn canary_literals(source: &str) -> std::collections::BTreeSet<String> {
    source
        .split('"')
        .filter(|value| value.starts_with("CANARY_"))
        .map(str::to_owned)
        .collect()
}

fn run_ok(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("running {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command stdout is UTF-8")
}

fn embedded_map_definitions() -> BTreeMap<String, [u32; 7]> {
    let directory = tempfile::tempdir().expect("temporary map-inspection directory");
    let object = directory.path().join("p11scope-ebpf");
    let maps = directory.path().join("maps.bin");
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");

    let symbols = Command::new("llvm-readelf")
        .args(["-sW", object.to_str().unwrap()])
        .output()
        .expect("run llvm-readelf");
    assert!(
        symbols.status.success(),
        "{}",
        String::from_utf8_lossy(&symbols.stderr)
    );
    let dump = format!("maps={}", maps.display());
    let sections = Command::new("llvm-objcopy")
        .args(["--dump-section", &dump, object.to_str().unwrap()])
        .output()
        .expect("run llvm-objcopy");
    assert!(
        sections.status.success(),
        "{}",
        String::from_utf8_lossy(&sections.stderr)
    );
    let data = fs::read(maps).expect("read legacy map definitions");

    String::from_utf8(symbols.stdout)
        .expect("UTF-8 symbol table")
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 || fields[3] != "OBJECT" || fields[6].parse::<u32>().is_err() {
                return None;
            }
            let offset = usize::from_str_radix(fields[1], 16).ok()?;
            let bytes = data.get(offset..offset + 28)?;
            let mut definition = [0; 7];
            for (value, chunk) in definition.iter_mut().zip(bytes.chunks_exact(4)) {
                *value = u32::from_le_bytes(chunk.try_into().unwrap());
            }
            Some((fields[7].to_string(), definition))
        })
        .collect()
}

fn embedded_symbols() -> String {
    let directory = tempfile::tempdir().expect("temporary symbol-inspection directory");
    let object = directory.path().join("p11scope-ebpf");
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");
    let output = Command::new("llvm-readelf")
        .args(["-sW", object.to_str().unwrap()])
        .output()
        .expect("run llvm-readelf");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 symbol table")
}

#[test]
fn official_build_is_safe_only() {
    let release = read("scripts/build-release.sh");
    assert!(release.contains("OFFICIAL_TARGET=target/release-official"));
    let official = between(
        &release,
        "=== p11scope: isolated safe-only official static build ===",
        "=== p11scope-discover: dynamic glibc + dynamic musl builds ===",
    );
    let command = [
        "CARGO_TARGET_DIR=\"$OFFICIAL_TARGET\" \\",
        "RUSTFLAGS=\"-C target-feature=+crt-static\" \\",
        "    cargo +1.88 build --locked --release --no-default-features \\",
        "        --target x86_64-unknown-linux-musl --bin p11scope",
    ]
    .join("\n");
    assert!(official.contains(&command));
    for marker in [
        "--policy-inventory \"$OFFICIAL_BPF\" \"$DIAGNOSTIC_BPF\"",
        "--unsafe-unvalidated-metadata requires a build with",
    ] {
        assert!(official.contains(marker), "official build misses {marker}");
    }
}

#[test]
fn container_provider_streams_are_byte_capped() {
    // A hostile image controls how many bytes the copy step reads. Under the
    // cap succeeds; reaching the cap and an empty stream both refuse, so a
    // truncated archive can never become an attach plan.
    let status = Command::new("sh")
        .args([
            "-c",
            ". scripts/lib.sh; \
             out=$(mktemp) || exit 1; \
             MAX_CONTAINER_TAR_BYTES=64; \
             capped_container_tar \"$out\" printf 'small' 2>/dev/null && \
             ! capped_container_tar \"$out\" sh -c 'head -c 4096 /dev/zero' 2>/dev/null && \
             ! capped_container_tar \"$out\" true 2>/dev/null; \
             result=$?; rm -f \"$out\"; exit $result",
        ])
        .status()
        .expect("exercise the container stream cap");
    assert!(status.success(), "container tar cap rejected its contract");

    // Only the knative lane still copies anything out of a container, because
    // it attaches before the pod exists and the memory scan has nothing to
    // read. Every other container lane discovers by scanning the container's
    // own mapped bytes, so it must not copy a provider at all.
    let path = "scripts/matrix/verify-knative.sh";
    let script = read(path);
    assert!(script.contains("capped_container_tar"), "{path}");
    assert!(!script.contains(". > \"$WORK/provider.tar\""), "{path}");
    for path in [
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-shared-layer.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/attach-pod.sh",
    ] {
        let script = read(path);
        for banned in [
            "capped_container_tar",
            "discover_copied_provider",
            "--manifest",
        ] {
            assert!(
                !script.contains(banned),
                "{path} still uses {banned}: the scan reads the container's own memory"
            );
        }
    }
}

#[test]
fn container_manifest_rewrite_refuses_escapes_and_rewrites_paths() {
    // Discovery runs on a host copy of the container's provider directory, so
    // every attach path must be rewritten into the container's mount view --
    // and a path that escapes the copy must never become an attach plan.
    let status = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/lib.sh
root=$(mktemp -d) || exit 1
trap 'rm -rf "$root"' EXIT
mkdir "$root/copy"
: > "$root/copy/provider.so"
: > "$root/copy/dep.so"
: > "$root/escape.so"
manifest() {
    printf '{"schema":"p11scope-manifest/4","module_path":"%s","objects":[{"id":0,"path":"%s"},{"id":1,"path":"%s"}]}\n' \
        "$root/copy/provider.so" "$root/copy/provider.so" "$1" > "$root/in.json"
}
manifest "$root/copy/dep.so"
rewrite_container_manifest "$root/in.json" "$root/out.json" "$root/copy" /proc/42/root/usr/lib
grep -Fq '"module_path": "/proc/42/root/usr/lib/provider.so"' "$root/out.json"
grep -Fq '"path": "/proc/42/root/usr/lib/dep.so"' "$root/out.json"
# set -e ignores a `!`-negated command, so every refusal is an explicit branch.
if grep -Fq "$root/copy" "$root/out.json"; then echo "copy path leaked"; exit 1; fi
manifest "$root/copy/../escape.so"
if rewrite_container_manifest "$root/in.json" "$root/bad.json" "$root/copy" /proc/42/root/usr/lib 2>/dev/null; then echo "escape accepted"; exit 1; fi
printf '{"schema":"p11scope-manifest/3","module_path":"x","objects":[]}\n' > "$root/in.json"
if rewrite_container_manifest "$root/in.json" "$root/bad.json" "$root/copy" /proc/42/root/usr/lib 2>/dev/null; then echo "schema v3 accepted"; exit 1; fi
"#,
        ])
        .status()
        .expect("exercise the container manifest rewrite");
    assert!(
        status.success(),
        "container manifest rewrite broke its contract"
    );
}

#[test]
fn pidfd_signal_is_bound_to_recorded_identity() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/lib.sh
sleep 30 & pinned_pid=$!
trap 'kill -KILL "$pinned_pid" 2>/dev/null || true; wait "$pinned_pid" 2>/dev/null || true' EXIT
pinned_start=$(process_starttime "$pinned_pid")
pinned_sid=$(process_session_id "$pinned_pid")
if signal_verified_process TERM "$pinned_pid" "$((pinned_start + 1))" 2>/dev/null; then
    exit 1
fi
if signal_verified_process TERM "$pinned_pid" "$pinned_start" "$((pinned_sid + 1))" 2>/dev/null; then
    exit 1
fi
kill -0 "$pinned_pid"
signal_verified_process STOP "$pinned_pid" "$pinned_start" "$pinned_sid"
attempt=0
while [ "$attempt" -lt 100 ]; do
    state=$(awk '$1 == "State:" { print $2; exit }' "/proc/$pinned_pid/status")
    [ "$state" = T ] && break
    attempt=$((attempt + 1))
    sleep 0.01
done
[ "$state" = T ]
signal_verified_process CONT "$pinned_pid" "$pinned_start" "$pinned_sid"
signal_verified_process TERM "$pinned_pid" "$pinned_start" "$pinned_sid"
if wait "$pinned_pid"; then exit 1; else status=$?; fi
[ "$status" -eq 143 ]
pinned_pid=
trap - EXIT
"#,
        ])
        .output()
        .expect("exercise pidfd identity signal helper");
    assert!(
        output.status.success(),
        "pidfd helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn body_signal_reaches_the_pinned_leader_before_session_inventory() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let signal = between(
        &gate,
        "lane13_signal_body_group() {",
        "\n\nlane13_outer_terminal_failure() {",
    );
    let directory = tempfile::tempdir().expect("temporary body-signal directory");
    let script = directory.path().join("body-signal.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
LANE13_BODY_PID=41
LANE13_BODY_STARTTIME=42
LANE13_BODY_SID=41
process_matches_session() {{ return 0; }}
process_matches_starttime() {{ return 0; }}
signal_verified_process() {{ printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >> {signals}; }}
snapshot_user_process_session() {{ return 1; }}
lane13_signal_body_group() {{{signal}
set +e
lane13_signal_body_group TERM
status=$?
set -e
[ "$status" -ne 0 ]
grep -Fqx 'TERM 41 42 41' {signals}
"#,
            signal = signal,
            signals = directory.path().join("signals").display(),
        ),
    )
    .expect("write body-signal regression");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise body signal before inventory");
    assert!(
        output.status.success(),
        "body leader was not signalled first: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn body_signal_never_authorizes_a_reused_sid_without_its_recorded_leader() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let signal = between(
        &gate,
        "lane13_signal_body_group() {",
        "\n\nlane13_outer_terminal_failure() {",
    );
    let directory = tempfile::tempdir().expect("temporary reused-SID directory");
    let script = directory.path().join("reused-sid.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
LANE13_BODY_PID=41
LANE13_BODY_STARTTIME=42
LANE13_BODY_SID=41
process_matches_session() {{ return 1; }}
process_matches_starttime() {{ return 1; }}
signal_verified_process() {{ printf '%s %s %s %s\n' "$1" "$2" "$3" "${{4-}}" >> {signals}; }}
snapshot_user_process_session() {{ printf '%s\n' '[{{"pid":999993,"starttime":100,"ppid":1,"pgid":999993,"sid":41,"exe_sha256":"foreign","argv":["foreign"]}}]'; }}
lane13_signal_body_group() {{{signal}
set +e
lane13_signal_body_group TERM
status=$?
set -e
[ "$status" -ne 0 ]
[ ! -e {signals} ]
"#,
            signal = signal,
            signals = directory.path().join("signals").display(),
        ),
    )
    .expect("write reused-SID regression");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise body SID authorization");
    assert!(
        output.status.success(),
        "body signal authorized a reused SID: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn user_process_session_lifecycle_is_identity_pinned() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/lib.sh
work=$(mktemp -d)
leader=
trap 'if [ -n "$leader" ]; then kill -KILL "$leader" 2>/dev/null || true; wait "$leader" 2>/dev/null || true; fi; rm -rf "$work"' EXIT
launch_user_recorded_process_group "$work/portforward.pid" "$work/portforward.log" \
    sh -c 'trap "" TERM; sleep 30 & wait'
leader=$USER_PROCESS_PID
[ "$USER_PROCESS_LAUNCH_PID" = "$leader" ]
[ "$USER_PROCESS_PGID" = "$leader" ]
[ "$USER_PROCESS_SID" = "$leader" ]
env | grep -Fqx "USER_PROCESS_SID=$leader"
python3 - "$work/portforward.pid" "$leader" "$USER_PROCESS_STARTTIME" <<'PY'
import json
import sys

record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["pid"] == int(sys.argv[2])
assert record["starttime"] == int(sys.argv[3])
assert set(record) == {"pid", "starttime", "pgid", "sid", "argv"}
assert record["pid"] == record["pgid"] == record["sid"]
assert record["argv"] == ["sh", "-c", 'trap "" TERM; sleep 30 & wait']
PY
snapshot_user_process_session "$USER_PROCESS_SID" > "$work/ready.json"
python3 - "$work/ready.json" "$leader" <<'PY'
import json
import sys

members = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(members) == 2
assert {member["pgid"] for member in members} == {int(sys.argv[2])}
assert {member["sid"] for member in members} == {int(sys.argv[2])}
assert any(member["pid"] == int(sys.argv[2]) for member in members)
assert all(member["exe_sha256"] and isinstance(member["argv"], list) for member in members)
PY
if signal_verified_process TERM "$leader" "$((USER_PROCESS_STARTTIME + 1))" 2>/dev/null; then
    exit 1
fi
kill -0 "$leader"
signal_verified_process TERM "$leader" "$USER_PROCESS_STARTTIME"
sleep 0.05
kill -0 "$leader"
signal_verified_process KILL "$leader" "$USER_PROCESS_STARTTIME"
if wait "$USER_PROCESS_LAUNCH_PID"; then exit 1; else status=$?; fi
[ "$status" -eq 137 ]
leader=
snapshot_user_process_session "$USER_PROCESS_SID" > "$work/after-leader.json"
python3 - "$work/after-leader.json" <<'PY' | while read -r pid starttime; do
import json
import sys

for member in json.load(open(sys.argv[1], encoding="utf-8")):
    print(member["pid"], member["starttime"])
PY
    signal_verified_process KILL "$pid" "$starttime"
done
attempt=0
while [ "$attempt" -lt 100 ]; do
    [ "$(snapshot_user_process_session "$USER_PROCESS_SID")" = "[]" ] && break
    attempt=$((attempt + 1))
    sleep 0.01
done
[ "$(snapshot_user_process_session "$USER_PROCESS_SID")" = "[]" ]
trap - EXIT
rm -rf "$work"
"#,
        ])
        .output()
        .expect("exercise user process-group lifecycle helpers");
    assert!(
        output.status.success(),
        "user process-group lifecycle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn failed_user_process_group_validation_never_reauthorizes_a_pid() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
real_python=$(command -v python3)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3() {
    if [ "$1" = - ]; then
        case ${3-} in
            ''|*[!0-9]*) command "$real_python" "$@"; return ;;
        esac
        "$real_python" - "$2" <<'PY'
import json
import sys

path = sys.argv[1]
record = json.load(open(path, encoding="utf-8"))
record["starttime"] += 1
open(path, "w", encoding="utf-8").write(json.dumps(record) + "\n")
PY
    fi
    command "$real_python" "$@"
}
. scripts/lib.sh
if launch_user_recorded_process_group "$work/identity.json" "$work/child.log" \
    sh -c '(sleep 0.2; : > "$1") & trap "printf killed; exit 9" TERM; while [ ! -e "$1" ]; do :; done; printf survived' \
    sh "$work/done"; then
    exit 1
fi
sleep 0.3
grep -Fqx survived "$work/child.log"
"#,
        ])
        .output()
        .expect("exercise failed process-group validation");
    assert!(
        output.status.success(),
        "failed process-group validation signalled a new identity: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lane13_port_forward_snapshot_requires_authenticated_identity() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let validator = between(
        &gate,
        "lane13_validate_port_forward_snapshot() {",
        "\nlane13_preserve_diagnostics() {",
    )
    .trim_end()
    .strip_suffix('}')
    .expect("port-forward snapshot validator closing brace");
    let directory = tempfile::tempdir().expect("temporary snapshot fixture directory");
    let ordinary = directory.path().join("ordinary.json");
    fs::write(
        &ordinary,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write ordinary snapshot fixture");
    let snap = directory.path().join("snap.json");
    fs::write(
        &snap,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","argv":["/snap/kubectl/3833/kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write Snap snapshot fixture");
    let wrong_digest = directory.path().join("wrong-digest.json");
    fs::write(
        &wrong_digest,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","argv":["/snap/kubectl/3833/kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write wrong-digest fixture");
    let another_revision = directory.path().join("another-revision.json");
    fs::write(
        &another_revision,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","argv":["/snap/kubectl/4000/kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write another-revision fixture");
    let tmp = directory.path().join("tmp.json");
    fs::write(
        &tmp,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["/tmp/kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write temporary-path fixture");
    let altered_tail = directory.path().join("altered-tail.json");
    fs::write(
        &altered_tail,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:81"]}]"#,
    )
    .expect("write altered-tail fixture");
    let extra_member = directory.path().join("extra-member.json");
    fs::write(
        &extra_member,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]},{"pid":999992,"starttime":101,"ppid":999991,"pgid":999991,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["child"]}]"#,
    )
    .expect("write extra-member fixture");
    let changed_pid = directory.path().join("changed-pid.json");
    fs::write(
        &changed_pid,
        r#"[{"pid":999992,"starttime":100,"ppid":1,"pgid":999992,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write changed-PID fixture");
    let changed_starttime = directory.path().join("changed-starttime.json");
    fs::write(
        &changed_starttime,
        r#"[{"pid":999991,"starttime":101,"ppid":1,"pgid":999991,"sid":41,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write changed-starttime fixture");
    let changed_sid = directory.path().join("changed-sid.json");
    fs::write(
        &changed_sid,
        r#"[{"pid":999991,"starttime":100,"ppid":1,"pgid":999991,"sid":42,"exe_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","argv":["kubectl","port-forward","-n","kourier-system","svc/kourier-internal","31234:80"]}]"#,
    )
    .expect("write changed-SID fixture");
    let script = directory.path().join("snapshot-contract.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
lane13_validate_port_forward_snapshot() {{{validator}
}}
run() {{
    fixture=$1
    expected_status=$2
    expected_argv0=$3
    expected_digest=$4
    leader_pid=$5
    leader_starttime=$6
    leader_sid=$7
    set +e
    lane13_validate_port_forward_snapshot "$fixture" "$leader_pid" "$leader_starttime" "$leader_sid" "$expected_argv0" "$expected_digest" 31234
    actual_status=$?
    set -e
    [ "$actual_status" -eq "$expected_status" ]
}}
ordinary_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
snap_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
run {ordinary} 0 kubectl "$ordinary_digest" 999991 100 41
run {snap} 0 /snap/kubectl/3833/kubectl "$snap_digest" 999991 100 41
run {wrong_digest} 1 /snap/kubectl/3833/kubectl "$snap_digest" 999991 100 41
run {another_revision} 1 /snap/kubectl/3833/kubectl "$snap_digest" 999991 100 41
run {tmp} 1 kubectl "$ordinary_digest" 999991 100 41
run {altered_tail} 1 kubectl "$ordinary_digest" 999991 100 41
run {extra_member} 1 kubectl "$ordinary_digest" 999991 100 41
run {changed_pid} 1 kubectl "$ordinary_digest" 999991 100 41
run {changed_starttime} 1 kubectl "$ordinary_digest" 999991 100 41
run {changed_sid} 1 kubectl "$ordinary_digest" 999991 100 41
"#,
            validator = validator,
            ordinary = ordinary.display(),
            snap = snap.display(),
            wrong_digest = wrong_digest.display(),
            another_revision = another_revision.display(),
            tmp = tmp.display(),
            altered_tail = altered_tail.display(),
            extra_member = extra_member.display(),
            changed_pid = changed_pid.display(),
            changed_starttime = changed_starttime.display(),
            changed_sid = changed_sid.display(),
        ),
    )
    .expect("write snapshot contract script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise port-forward snapshot validator");
    assert!(
        output.status.success(),
        "snapshot validator contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lane13_port_forward_resolver_binds_launch_and_validator() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let resolver = between(
        &gate,
        "lane13_resolve_port_forward() {",
        "\nlane13_validate_port_forward_snapshot() {",
    )
    .trim_end()
    .strip_suffix('}')
    .expect("port-forward resolver closing brace");
    let launch_binding = between(
        &gate,
        "lane13_resolve_port_forward\nset +e\n",
        "pf_launch_status=$?",
    );
    let validator_binding = between(
        &gate,
        "lane13_validate_port_forward_snapshot \"$PF_GROUP_SNAPSHOT\"",
        "\nprocess_matches_starttime",
    );
    let directory = tempfile::tempdir().expect("temporary resolver fixture directory");
    let calls = directory.path().join("calls");
    fs::create_dir(&calls).expect("create resolver call directory");
    let script = directory.path().join("resolver-contract.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={work}
CALLS={calls}
SNAP_PATH=/snap/kubectl/3833/kubectl
RESOLUTION=
PF_COMMAND=
PF_EXPECTED_ARGV0=
PF_EXPECTED_EXE_SHA256=
lane13_sha256() {{
    case "$1" in
        /tmp/ordinary-kubectl) printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
        "$SNAP_PATH") printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
        *) return 1 ;;
    esac
}}
command() {{
    case "$1:$RESOLUTION" in
        -v:ordinary) printf '%s\n' /tmp/ordinary-kubectl ;;
        -v:snap|-v:snap-invalid) printf '%s\n' /snap/bin/kubectl ;;
        *) return 1 ;;
    esac
}}
readlink() {{
    case "$RESOLUTION" in
        ordinary) printf '%s\n' /tmp/ordinary-kubectl ;;
        snap) printf '%s\n' "$SNAP_PATH" ;;
        snap-invalid) printf '%s\n' /snap/kubectl/not-a-revision/kubectl ;;
        *) return 1 ;;
    esac
}}
test() {{
    case "$1:$2" in
        -f:/tmp/ordinary-kubectl|-f:$SNAP_PATH) return 0 ;;
        -L:*) return 1 ;;
        *) return 1 ;;
    esac
}}
lane13_resolve_port_forward() {{{resolver}
}}
assert() {{
    expected=$1
    actual=$2
    case "$actual" in
        "$expected") ;;
        *) echo "assertion failed: expected=$expected actual=$actual" >&2; exit 1 ;;
    esac
}}
resolve() {{
    RESOLUTION=$1
    set +e
    lane13_resolve_port_forward
    status=$?
    set -e
    assert "$2" "$status"
}}
resolve ordinary 0
assert kubectl "$PF_COMMAND"
assert kubectl "$PF_EXPECTED_ARGV0"
assert aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$PF_EXPECTED_EXE_SHA256"
resolve snap 0
assert /snap/bin/kubectl "$PF_COMMAND"
assert "$SNAP_PATH" "$PF_EXPECTED_ARGV0"
assert bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "$PF_EXPECTED_EXE_SHA256"
snap_argv0=$PF_EXPECTED_ARGV0
snap_digest=$PF_EXPECTED_EXE_SHA256
resolve snap-invalid 1
launch_user_recorded_process_group() {{ printf '%s\n' "$*" > "$CALLS/launch"; }}
PORT=31234
{launch_binding}
assert "$WORK/portforward.pid $WORK/portforward.log /snap/bin/kubectl port-forward -n kourier-system svc/kourier-internal 31234:80" "$(cat "$CALLS/launch")"
lane13_validate_port_forward_snapshot() {{ printf '%s\n' "$*" > "$CALLS/validator"; }}
PF_GROUP_SNAPSHOT=$WORK/portforward.group.before.json
PF_PID=999991
PF_STARTTIME=100
PF_SID=41
PF_EXPECTED_ARGV0=$snap_argv0
PF_EXPECTED_EXE_SHA256=$snap_digest
lane13_validate_port_forward_snapshot "$PF_GROUP_SNAPSHOT"{validator_binding}
assert "$PF_GROUP_SNAPSHOT 999991 100 41 $snap_argv0 $snap_digest 31234" "$(cat "$CALLS/validator")"
"#,
            work = directory.path().display(),
            calls = calls.display(),
            resolver = resolver,
            launch_binding = launch_binding,
            validator_binding = validator_binding,
        ),
    )
    .expect("write resolver contract script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise resolver and binding contract");
    assert!(
        output.status.success(),
        "resolver and binding contract failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn port_forward_never_signals_a_member_absent_from_its_authorization_snapshot() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {");
    let terminate = terminate
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let directory = tempfile::tempdir().expect("temporary lifecycle test directory");
    let script = directory.path().join("lifecycle.sh");
    fs::write(
        &script,
        format!(
r#"#!/bin/sh
set -eu
. scripts/lib.sh
WORK={work}
PF_LAUNCH_PID=
sleep 0.01 & PF_LAUNCH_PID=$!
PF_PID=999991
PF_STARTTIME=10
PF_PGID=20
PF_SID=30
PF_GROUP_SNAPSHOT=
match_live=1
snapshot_count=0
process_matches_starttime() {{ [ "$match_live" -eq 1 ]; }}
signal_verified_process() {{
    printf '%s %s %s\n' "$1" "$2" "$3" >> "$WORK/signals"
    [ "$1" != TERM ] || match_live=0
}}
snapshot_user_process_session() {{
    snapshot_count=$((snapshot_count + 1))
    if [ "$snapshot_count" -eq 1 ] && [ "$match_live" -eq 1 ]; then
        printf '%s\n' '[{{"pid":999991,"starttime":10,"ppid":1,"pgid":20,"sid":30,"exe_sha256":"leader","argv":["kubectl"]}}]'
    else
        printf '%s\n' '[{{"pid":999992,"starttime":11,"ppid":1,"pgid":20,"sid":31,"exe_sha256":"late","argv":["foreign"]}}]'
    fi
}}
terminate_port_forward() {{
{terminate}
}}
set +e
terminate_port_forward
status=$?
set -e
[ "$status" -ne 0 ]
grep -Fqx 'TERM 999991 10' "$WORK/signals"
! grep -Fq '999992' "$WORK/signals"
"#,
            work = directory.path().display(),
            terminate = terminate,
        ),
    )
    .expect("write lifecycle test script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise port-forward authorization lifecycle");
    assert!(
        output.status.success(),
        "late process-group member was signalled: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn port_forward_uses_live_leader_snapshot_after_leader_exit_without_reauthorizing_sid() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {")
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let directory = tempfile::tempdir().expect("temporary vanished-leader directory");
    fs::write(
        directory.path().join("authorized.json"),
        r#"[{"pid":999991,"starttime":10,"ppid":1,"pgid":30,"sid":30,"exe_sha256":"leader","argv":["kubectl"]},{"pid":999992,"starttime":11,"ppid":999991,"pgid":30,"sid":30,"exe_sha256":"child","argv":["child"]}]"#,
    )
    .expect("write immutable authorization snapshot");
    let script = directory.path().join("vanished-leader.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={work}
PF_LAUNCH_PID=999991
PF_PID=999991
PF_STARTTIME=10
PF_PGID=30
PF_SID=30
PF_GROUP_SNAPSHOT=$WORK/authorized.json
PF_GROUP_SNAPSHOT_AFTER=
process_matches_starttime() {{ return 1; }}
process_matches_session() {{ [ "$1" = 999992 ]; }}
signal_verified_process() {{ printf '%s %s %s %s\n' "$1" "$2" "$3" "${{4-}}" >> "$WORK/signals"; }}
snapshot_user_process_session() {{
    [ -e "$WORK/signals" ] || {{ printf '%s\n' '[{{"pid":999993,"starttime":12,"ppid":1,"pgid":30,"sid":30,"exe_sha256":"foreign","argv":["foreign"]}}]'; return; }}
    printf '[]'
}}
wait() {{ return 0; }}
sleep() {{ :; }}
terminate_port_forward() {{{terminate}
}}
set +e
terminate_port_forward
status=$?
set -e
[ "$status" -ne 0 ]
grep -Fqx 'TERM 999992 11 30' "$WORK/signals"
! grep -Fq '999993' "$WORK/signals"
"#,
            work = directory.path().display(),
            terminate = terminate,
        ),
    )
    .expect("write vanished-leader regression");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise immutable port-forward authorization");
    assert!(
        output.status.success(),
        "port-forward reauthorized a reused SID: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn port_forward_leader_exit_race_does_not_abort_under_nounset() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {")
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let directory = tempfile::tempdir().expect("temporary leader-race directory");
    fs::write(
        directory.path().join("authorized.json"),
        r#"[{"pid":999991,"starttime":10,"ppid":1,"pgid":30,"sid":30,"exe_sha256":"leader","argv":["kubectl"]}]"#,
    )
    .expect("write leader authorization snapshot");
    let script = directory.path().join("leader-race.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={work}
PF_LAUNCH_PID=999991
PF_PID=999991
PF_STARTTIME=10
PF_PGID=30
PF_SID=30
PF_GROUP_SNAPSHOT=$WORK/authorized.json
PF_GROUP_SNAPSHOT_AFTER=
matches=0
process_matches_starttime() {{ matches=$((matches + 1)); [ "$matches" -le 2 ]; }}
process_matches_session() {{ return 0; }}
signal_verified_process() {{ printf '%s\n' "$1" >> "$WORK/signals"; }}
snapshot_user_process_session() {{ printf '[]'; }}
wait() {{ return 0; }}
sleep() {{ :; }}
terminate_port_forward() {{{terminate}
}}
terminate_port_forward
: > "$WORK/after"
[ -e "$WORK/after" ]
grep -Fqx TERM "$WORK/signals"
! grep -Fqx KILL "$WORK/signals"
"#,
            work = directory.path().display(),
            terminate = terminate,
        ),
    )
    .expect("write leader-race regression");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise leader exit race");
    assert!(
        output.status.success(),
        "leader exit triggered nounset abort: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn port_forward_term_during_launch_reaps_the_trap_visible_generation() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {")
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let cleanup = between(&gate, "cleanup() {", "\n. scripts/cleanup-traps.sh")
        .trim_end()
        .strip_suffix('}')
        .expect("cleanup function closing brace");
    let directory = tempfile::tempdir().expect("temporary launch-interrupt directory");
    let gate_script = directory.path().join("gate.sh");
    let check_script = directory.path().join("check.sh");
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).expect("create Python wrapper directory");
    let python_wrapper = bin.join("python3");
    fs::write(
        &python_wrapper,
        r#"#!/bin/sh
if [ "$1" = - ] && [ "$#" -gt 5 ]; then
    case ${3-} in
        ''|*[!0-9]*) ;;
        *)
            [ -e "$PF_TEST_WORK/validation" ] || : > "$PF_TEST_WORK/validation"
            while [ ! -e "$PF_TEST_WORK/release" ]; do :; done
            ;;
    esac
fi
exec "$PF_TEST_REAL_PYTHON" "$@"
"#,
    )
    .expect("write Python validation wrapper");
    fs::set_permissions(&python_wrapper, fs::Permissions::from_mode(0o755))
        .expect("make Python validation wrapper executable");
    fs::write(
        &gate_script,
        format!(
            r#"#!/bin/sh
set -eu
. scripts/lib.sh
WORK={work}
KUBECONFIG="$WORK/kubeconfig"
SPID=
SUPERVISOR_PID=
SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID=
ROOT_PROCESS_PID=
ROOT_PROCESS_STARTTIME=
PF_LAUNCH_PID=
PF_PID=
PF_STARTTIME=
PF_PGID=
PF_SID=
PF_GROUP_SNAPSHOT=
CLUSTER_CREATED=
IMAGE_CREATED=
PATH="$WORK/bin:$PATH"
export PATH
PF_TEST_WORK="$WORK"
PF_TEST_REAL_PYTHON="{python}"
export PF_TEST_WORK PF_TEST_REAL_PYTHON
terminate_port_forward() {{
{terminate}
}}
cleanup() {{
{cleanup}
}}
. scripts/cleanup-traps.sh
( while [ ! -e "$WORK/validation" ]; do :; done; : > "$WORK/term-sent"; kill -TERM "$$"; : > "$WORK/release" ) &
PF_PENDING_STATUS=
trap 'PF_PENDING_STATUS=${{PF_PENDING_STATUS:-130}}' INT
trap 'PF_PENDING_STATUS=${{PF_PENDING_STATUS:-143}}' TERM
set +e
launch_user_recorded_process_group "$WORK/identity.json" "$WORK/portforward.log" \
    sh -c 'trap "exit 0" TERM; while :; do :; done'
launch_status=$?
set -e
PF_LAUNCH_PID=$USER_PROCESS_LAUNCH_PID
PF_PID=$USER_PROCESS_PID
PF_STARTTIME=$USER_PROCESS_STARTTIME
PF_PGID=$USER_PROCESS_PGID
PF_SID=$USER_PROCESS_SID
PF_GROUP_SNAPSHOT=
. scripts/cleanup-traps.sh
[ -z "$PF_PENDING_STATUS" ] || exit "$PF_PENDING_STATUS"
exit "$launch_status"
"#,
            work = directory.path().display(),
            terminate = terminate,
            cleanup = cleanup,
            python = Command::new("sh")
                .args(["-c", "command -v python3"])
                .output()
                .expect("locate system Python")
                .stdout
                .strip_suffix(b"\n")
                .expect("system Python newline")
                .iter()
                .map(|&byte| char::from(byte))
                .collect::<String>(),
        ),
    )
    .expect("write launch-interrupt gate");
    fs::write(
        &check_script,
        format!(
            r#"#!/bin/sh
set -eu
. scripts/lib.sh
WORK={work}
sh "$WORK/gate.sh" & gate=$!
attempt=0
while [ ! -e "$WORK/term-sent" ] && [ "$attempt" -lt 1000 ]; do
    attempt=$((attempt + 1))
    sleep 0.01
done
[ -e "$WORK/term-sent" ]
if wait "$gate"; then exit 1; else status=$?; fi
[ "$status" -eq 143 ]
set -- $(python3 - "$WORK/identity.json" <<'PY'
import json
import sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert set(record) == {{"pid", "starttime", "pgid", "sid", "argv"}}
assert record["pid"] == record["pgid"] == record["sid"]
print(record["pid"], record["starttime"], record["sid"])
PY
)
! process_matches_starttime "$1" "$2"
[ "$(snapshot_user_process_group "$3")" = "[]" ]
"#,
            work = directory.path().display(),
        ),
    )
    .expect("write launch-interrupt check");
    let output = Command::new("timeout")
        .args(["10s", "sh"])
        .arg(&check_script)
        .output()
        .expect("exercise launch-interrupt cleanup");
    assert!(
        output.status.success(),
        "launch-interrupt cleanup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn mutated_process_group_record_never_signals_the_live_decoy_or_unvalidated_owner() {
    let directory = tempfile::tempdir().expect("temporary record-mutation directory");
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).expect("create Python wrapper directory");
    let python_wrapper = bin.join("python3");
    fs::write(
        &python_wrapper,
        r#"#!/bin/sh
if [ "$1" = - ] && [ "$#" -gt 5 ]; then
    case ${3-} in
        ''|*[!0-9]*) ;;
        *) [ -e "$PF_TEST_WORK/mutated" ||
    "$PF_TEST_REAL_PYTHON" - "$2" "$PF_TEST_WORK" <<'PY'
import json
import os
import subprocess
import sys


def stat(pid):
    raw = open(f"/proc/{pid}/stat", "rb").read()
    _, separator, tail = raw.rpartition(b") ")
    if not separator:
        raise ValueError("malformed proc stat")
    fields = tail.split()
    return int(fields[19]), int(fields[2])


record_path, work = sys.argv[1:]
original = json.load(open(record_path, encoding="utf-8"))
json.dump(original, open(os.path.join(work, "original.json"), "w", encoding="utf-8"))
decoy = subprocess.Popen(
    [
        "sh",
        "-c",
        'trap "printf decoy > \\\"$1\\\"; exit 0" TERM; while :; do :; done',
        "sh",
        os.path.join(work, "decoy-signalled"),
    ],
    start_new_session=True,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
starttime, pgid = stat(decoy.pid)
replacement = {"pid": decoy.pid, "starttime": starttime, "pgid": pgid, "argv": ["decoy"]}
json.dump(replacement, open(os.path.join(work, "decoy.json"), "w", encoding="utf-8"))
json.dump(replacement, open(record_path, "w", encoding="utf-8"))
open(os.path.join(work, "mutated"), "w", encoding="utf-8").close()
PY
        ;;
    esac
fi
exec "$PF_TEST_REAL_PYTHON" "$@"
"#,
    )
    .expect("write Python mutation wrapper");
    fs::set_permissions(&python_wrapper, fs::Permissions::from_mode(0o755))
        .expect("make Python mutation wrapper executable");
    let script = directory.path().join("lifecycle.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
. scripts/lib.sh
WORK={work}
PATH="$WORK/bin:$PATH"
PF_TEST_WORK="$WORK"
PF_TEST_REAL_PYTHON="{python}"
export PATH PF_TEST_WORK PF_TEST_REAL_PYTHON
real_pid=
real_starttime=
decoy_pid=
decoy_starttime=
cleanup() {{
    [ -z "$real_pid" ] || signal_verified_process KILL "$real_pid" "$real_starttime" 2>/dev/null || true
    [ -z "$decoy_pid" ] || signal_verified_process KILL "$decoy_pid" "$decoy_starttime" 2>/dev/null || true
    [ -z "${{USER_PROCESS_LAUNCH_PID-}}" ] || wait "$USER_PROCESS_LAUNCH_PID" 2>/dev/null || true
}}
trap cleanup EXIT
if launch_user_recorded_process_group "$WORK/identity.json" "$WORK/portforward.log" \
    sh -c 'trap "printf real > \"$1\"; exit 0" TERM; while :; do :; done' sh "$WORK/real-signalled"; then
    exit 1
fi
[ -e "$WORK/mutated" ]
set -- $(python3 - "$WORK/original.json" "$WORK/decoy.json" <<'PY'
import json
import sys
for path in sys.argv[1:]:
    record = json.load(open(path, encoding="utf-8"))
    print(record["pid"], record["starttime"], record["pgid"])
PY
)
real_pid=$1
real_starttime=$2
real_pgid=$3
decoy_pid=$4
decoy_starttime=$5
decoy_pgid=$6
process_matches_starttime "$real_pid" "$real_starttime"
process_matches_starttime "$decoy_pid" "$decoy_starttime"
[ ! -e "$WORK/real-signalled" ]
[ ! -e "$WORK/decoy-signalled" ]
signal_verified_process KILL "$real_pid" "$real_starttime"
wait "$USER_PROCESS_LAUNCH_PID" 2>/dev/null || true
signal_verified_process KILL "$decoy_pid" "$decoy_starttime"
owners_live() {{
    process_matches_starttime "$real_pid" "$real_starttime" || process_matches_starttime "$decoy_pid" "$decoy_starttime"
}}
attempt=0
while owners_live && [ "$attempt" -lt 100 ]; do
    attempt=$((attempt + 1))
    sleep 0.01
done
! process_matches_starttime "$real_pid" "$real_starttime"
! process_matches_starttime "$decoy_pid" "$decoy_starttime"
[ "$(snapshot_user_process_group "$real_pgid")" = "[]" ]
[ "$(snapshot_user_process_group "$decoy_pgid")" = "[]" ]
real_pid=
decoy_pid=
trap - EXIT
"#,
            work = directory.path().display(),
            python = run_ok("sh", &["-c", "command -v python3"]).trim(),
        ),
    )
    .expect("write record-mutation lifecycle");
    let output = Command::new("timeout")
        .args(["10s", "sh"])
        .arg(&script)
        .output()
        .expect("exercise record-mutation failure path");
    assert!(
        output.status.success(),
        "record mutation signalled an unvalidated process: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn partial_owner_signal_failures_are_bounded_and_do_not_skip_cleanup() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {")
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let directory = tempfile::tempdir().expect("temporary partial-owner directory");
    let script = directory.path().join("lifecycle.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -u
. scripts/lib.sh
WORK={work}
PF_LAUNCH_PID=999991
PF_PID=999991
PF_STARTTIME=10
PF_PGID=
PF_SID=30
PF_GROUP_SNAPSHOT=
process_matches_starttime() {{ return 0; }}
signal_verified_process() {{ printf '%s %s %s\n' "$1" "$2" "$3" >> "$WORK/signals"; return 1; }}
snapshot_user_process_session() {{ printf '%s\n' '[{{"pid":999991,"starttime":10,"ppid":1,"pgid":30,"sid":30,"exe_sha256":"x","argv":["x"]}}]'; }}
sleep() {{ :; }}
wait() {{ : > "$WORK/waited"; return 0; }}
terminate_port_forward() {{
{terminate}
}}
after_cleanup() {{ : > "$WORK/after"; }}
CLEANUP_STATUS=0
cleanup_step terminate_port_forward
cleanup_step after_cleanup
[ "$CLEANUP_STATUS" -ne 0 ]
grep -Fqx 'TERM 999991 10' "$WORK/signals"
grep -Fqx 'KILL 999991 10' "$WORK/signals"
[ ! -e "$WORK/waited" ]
[ -e "$WORK/after" ]
"#,
            work = directory.path().display(),
            terminate = terminate,
        ),
    )
    .expect("write partial-owner lifecycle");
    let output = Command::new("timeout")
        .args(["5s", "sh"])
        .arg(&script)
        .output()
        .expect("exercise partial-owner signal failures");
    assert!(
        output.status.success(),
        "partial-owner signal failure skipped cleanup: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn port_forward_reaps_an_authorized_child_after_its_leader_exits() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {")
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let directory = tempfile::tempdir().expect("temporary leader-exit directory");
    let script = directory.path().join("lifecycle.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
. scripts/lib.sh
WORK={work}
launch_user_recorded_process_group "$WORK/portforward.pid" "$WORK/portforward.log" \
    sh -c 'trap "" HUP; sleep 30 & : > "$1/ready"; while [ ! -e "$1/release" ]; do :; done' sh "$WORK"
PF_LAUNCH_PID=$USER_PROCESS_LAUNCH_PID
PF_PID=$USER_PROCESS_PID
PF_STARTTIME=$USER_PROCESS_STARTTIME
PF_PGID=$USER_PROCESS_PGID
PF_SID=$USER_PROCESS_SID
sid=$PF_SID
[ -e "$WORK/ready" ] || {{
    attempt=0
    while [ ! -e "$WORK/ready" ] && [ "$attempt" -lt 1000 ]; do
        attempt=$((attempt + 1))
        sleep 0.01
    done
}}
[ -e "$WORK/ready" ]
snapshot_user_process_session "$PF_SID" > "$WORK/authorized.json"
PF_GROUP_SNAPSHOT="$WORK/authorized.json"
python3 - "$PF_GROUP_SNAPSHOT" "$PF_PID" <<'PY'
import json
import sys

members = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(members) == 2
assert any(member["pid"] == int(sys.argv[2]) for member in members)
PY
: > "$WORK/release"
wait "$PF_LAUNCH_PID"
! process_matches_starttime "$PF_PID" "$PF_STARTTIME"
[ "$(snapshot_user_process_session "$PF_SID")" != "[]" ]
terminate_port_forward() {{
{terminate}
}}
set +e
terminate_port_forward
status=$?
set -e
[ "$status" -ne 0 ]
[ "$(snapshot_user_process_session "$sid")" = "[]" ]
[ -z "$PF_PID" ]
[ -z "$PF_SID" ]
[ -z "$USER_PROCESS_LAUNCH_PID" ]
[ -z "$USER_PROCESS_PID" ]
[ -z "$USER_PROCESS_STARTTIME" ]
[ -z "$USER_PROCESS_PGID" ]
[ -z "$USER_PROCESS_INITIAL_STARTTIME" ]
[ -z "$USER_PROCESS_PIDFILE" ]
"#,
            work = directory.path().display(),
            terminate = terminate,
        ),
    )
    .expect("write leader-exit lifecycle");
    let output = Command::new("timeout")
        .args(["10s", "sh"])
        .arg(&script)
        .output()
        .expect("exercise leader-exit cleanup");
    assert!(
        output.status.success(),
        "leader-exit cleanup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn port_forward_term_ignoring_leader_is_nonpass_without_skipping_cleanup() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let terminate = between(&gate, "terminate_port_forward() {", "\ncleanup() {")
        .trim_end()
        .strip_suffix('}')
        .expect("terminate function closing brace");
    let cleanup = between(&gate, "cleanup() {", "\n. scripts/cleanup-traps.sh")
        .trim_end()
        .strip_suffix('}')
        .expect("cleanup function closing brace");
    let directory = tempfile::tempdir().expect("temporary forced-kill directory");
    let script = directory.path().join("lifecycle.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -u
WORK={work}
(
    set -eu
    . scripts/lib.sh
    WORK={work}
    KUBECONFIG="$WORK/kubeconfig"
    SPID=1
    SUPERVISOR_PID=123
    SUPERVISOR_STARTTIME=456
    ROOT_LAUNCH_PID=
    ROOT_PROCESS_PID=
    ROOT_PROCESS_STARTTIME=
    CLUSTER_CREATED=
    IMAGE_CREATED=
    launch_user_recorded_process_group "$WORK/identity.json" "$WORK/portforward.log" \
        sh -c 'trap "" TERM; while :; do :; done'
    PF_LAUNCH_PID=$USER_PROCESS_LAUNCH_PID
    PF_PID=$USER_PROCESS_PID
    PF_STARTTIME=$USER_PROCESS_STARTTIME
    PF_PGID=$USER_PROCESS_PGID
    PF_SID=$USER_PROCESS_SID
    snapshot_user_process_session "$PF_SID" > "$WORK/authorized.json"
    PF_GROUP_SNAPSHOT="$WORK/authorized.json"
    signal_verified_root_process() {{ : > "$WORK/root-cleanup"; }}
    terminate_port_forward() {{
{terminate}
}}
    cleanup() {{
{cleanup}
}}
    cleanup
) > "$WORK/cleanup.log" 2>&1
status=$?
[ "$status" -ne 0 ]
grep -Fqx 'port-forward required or received SIGKILL' "$WORK/cleanup.log"
[ -e "$WORK/root-cleanup" ]
. scripts/lib.sh
set -- $(python3 - "$WORK/identity.json" <<'PY'
import json
import sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
print(record["pid"], record["starttime"], record["pgid"])
PY
)
! process_matches_starttime "$1" "$2"
    [ "$(snapshot_user_process_session "$3")" = "[]" ]
"#,
            work = directory.path().display(),
            terminate = terminate,
            cleanup = cleanup,
        ),
    )
    .expect("write forced-kill lifecycle");
    let output = Command::new("timeout")
        .args(["20s", "sh"])
        .arg(&script)
        .output()
        .expect("exercise forced-kill cleanup");
    assert!(
        output.status.success(),
        "forced-kill cleanup failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn capture_evidence_checker_self_test() {
    let output = Command::new("python3")
        .args(["scripts/check-capture-evidence.py", "--self-test"])
        .output()
        .expect("run capture-evidence checker self-test");
    assert!(
        output.status.success(),
        "capture-evidence checker self-test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 checker output");
    for marker in [
        "unexpected positive function rejected: OK",
        "bootstrap function exact count required: OK",
        "clean metrics multiplier is exact: OK",
        "clean metrics discovery source is exact in all three lanes: OK",
        "lane13 manifest-only shared overlay is exact: OK",
        "lane13 rejects widened skips, discovery, modes, and concrete gaps: OK",
        "lane13 rejects nested skips, provenance, malformed scalars, and aliases: OK",
        "lane13 rejects nested overlays and malformed build IDs: OK",
        "lane13 rejects a multiplier argument: OK",
        // The scan contributes three per-source table records, while exact
        // target occurrences remain deduplicated across scan and manifest.
        "canary matrix 988/104/208 with 16 mixed surfaces: OK",
        "canary scan contribution is required: OK",
        "canary freeze lane is manifest-only 988/104/208 with 13 surfaces: OK",
        "canary safe exact allowances: OK",
        "canary unsafe exact allowances: OK",
        "canary aggregate exact baseline: OK",
        "induced G1 exact allowances: OK",
        "induced G2 exact allowances: OK",
        "induced G3 exact allowances: OK",
        "induced G3 rejects state-map contamination: OK",
        "induced G3 exact function counts required: OK",
        "induced G4 exact allowances: OK",
        "induced G5 exact allowances: OK",
        "induced G5 exact 11 calls and 9 RV failures: OK",
        "unrelated evidence gap rejected: OK",
    ] {
        assert!(stdout.contains(marker), "checker self-test misses {marker}");
    }
}

#[test]
fn knative_lane_uses_the_exact_manifest_only_shared_overlay_oracle() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let invocation = [
        "python3 scripts/check-capture-evidence.py lane13-knative-metrics \\",
        "    \"$WORK/observed.json\" spike/expected.txt",
    ]
    .join("\n");
    assert!(
        gate.contains(&invocation),
        "lane 13 must use its exact manifest-only shared-overlay oracle"
    );
    assert!(
        !gate.contains("clean-metrics-manifest-only"),
        "lane 13 must not silently discard the required shared-overlay uncertainty"
    );

    let checker = read("scripts/check-capture-evidence.py");
    let lane13_dispatch = between(
        &checker,
        "if argv[0] == \"lane13-knative-metrics\"",
        "elif argv[0] == \"shared-layer-metrics\"",
    );
    assert!(
        checker.contains("validate_lane13_knative_metrics(lane13, {\"C_Initialize\": 1})"),
        "checker self-test must exercise the lane-13 oracle"
    );
    assert!(
        lane13_dispatch.contains("len(argv) == 3"),
        "lane 13 dispatch must accept exactly output and expected arguments"
    );
    assert!(
        !lane13_dispatch.contains("multiplier"),
        "lane 13 must not accept a multiplier"
    );
}

#[test]
fn every_script_parses_with_sh_n() {
    for path in [
        "scripts/lib.sh",
        "scripts/gates.sh",
        "scripts/cleanup-traps.sh",
        "scripts/bench-overhead.sh",
        "scripts/build-release.sh",
        "scripts/attach-pod.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-inspect-doctor.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/verify-discover-containers.sh",
        "scripts/verify-capability-tier.sh",
        "scripts/verify-task4-lane02.sh",
        "scripts/matrix/verify-docker.sh",
        "scripts/matrix/verify-fork-scope.sh",
        "scripts/matrix/verify-oracle.sh",
        "scripts/matrix/verify-shared-layer.sh",
        "scripts/matrix/verify-kind-pod.sh",
        "scripts/matrix/verify-knative.sh",
        "scripts/matrix/verify-proxy-stack.sh",
    ] {
        let status = Command::new("sh")
            .args(["-n", path])
            .status()
            .unwrap_or_else(|error| panic!("sh -n {path}: {error}"));
        assert!(status.success(), "sh -n failed for {path}");
    }
}

#[test]
fn lane02_initial_set_uses_a_direct_needed_harness() {
    let driver = read("scripts/verify-task4-lane02.sh");
    assert!(driver.contains("HARNESS_INITIAL=$ROOT/bin/harness-initial"));
    assert!(driver.contains("-Wl,--no-as-needed"));
    assert!(driver.contains("set -- \"$@\" \"$HARNESS_INITIAL\" \"$MODULE\" \"$go\""));
    assert!(!driver.contains("set -- \"$@\" /usr/bin/env \"LD_PRELOAD=$MODULE\""));
}

#[test]
fn lane02_cleanup_covers_both_harness_executables() {
    let driver = read("scripts/verify-task4-lane02.sh");
    assert_eq!(
        driver
            .matches("python3 - \"$HARNESS\" \"$HARNESS_INITIAL\"")
            .count(),
        2,
        "absence and termination must inspect both exact harness paths"
    );
    assert!(driver.contains("argv[0] in wanted"));
    assert!(driver.contains("os.fsencode(exe) == argv[0]"));
}

#[test]
fn lane02_checker_and_driver_self_tests_execute() {
    let checker = run_ok(
        "python3",
        &["scripts/check-capture-evidence.py", "--self-test"],
    );
    assert!(
        checker.contains("lane02 owned-run metrics self-test: OK"),
        "checker self-test misses Lane02 marker: {checker}"
    );
    let driver = run_ok("sh", &["scripts/verify-task4-lane02.sh", "--self-test"]);
    assert!(
        driver.contains("verify-task4-lane02 self-test: OK"),
        "driver self-test misses marker: {driver}"
    );
}

#[test]
fn linux_permission_denial_classifier_accepts_eacces_and_eperm_only() {
    let status = Command::new("sh")
        .args([
            "-c",
            ". scripts/lib.sh; \
             printf '%s\n' 'open failed: Permission denied' | is_linux_permission_denial && \
             printf '%s\n' 'BPF_MAP_CREATE failed: Operation not permitted' | is_linux_permission_denial && \
             ! printf '%s\n' 'BPF_MAP_CREATE failed: Invalid argument' | is_linux_permission_denial",
        ])
        .status()
        .expect("exercise the Linux permission-denial classifier");
    assert!(
        status.success(),
        "the denial classifier rejected its contract"
    );
}

/// `scripts/attach-pod.sh` runs `p11scope profile --cgroup` against a pod the
/// operator names, so every name it accepts reaches a kubectl JSONPath filter
/// and a cgroup search. Its refusals are the contract, and they must hold with
/// no cluster, no sudo and no privileges.
#[test]
fn attach_pod_refuses_bad_arguments() {
    let output = Command::new("sh")
        .args(["scripts/attach-pod.sh", "--self-test"])
        .output()
        .expect("run attach-pod self-test");
    assert!(
        output.status.success(),
        "attach-pod self-test failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("attach-pod argument self-test: OK"));

    let script = read("scripts/attach-pod.sh");
    // The rewritten script attaches by cgroup and copies nothing: no provider
    // directory leaves the pod, and no manifest is rewritten into its mount view.
    assert!(
        script.contains("profile --cgroup"),
        "attach-pod must attach by cgroup"
    );
    for gone in [
        "rewrite_container_manifest",
        "provider-safe",
        "--trusted-workload",
    ] {
        assert!(!script.contains(gone), "attach-pod still references {gone}");
    }
}

#[test]
fn immutable_policy_maps() {
    const BPF_F_RDONLY_PROG: u32 = 1 << 7;
    const FLAGS: usize = 4;
    let definitions = embedded_map_definitions();

    for name in [
        "CONFIG",
        "PID_FILTER",
        "DESCRIPTORS",
        "ASYNC_FUNCTIONS",
        "MECH_SHAPE",
    ] {
        assert_eq!(definitions[name][FLAGS], BPF_F_RDONLY_PROG, "{name}");
    }
    assert!(
        !definitions.contains_key("SLOT_SEMANTICS"),
        "the static slot policy must be selected by attach cookie"
    );
    assert_eq!(definitions["CGROUP_FILTER"][FLAGS], 0);
    assert!(!definitions.contains_key("ATTR_BOOL_BITS"));
    assert!(!definitions.contains_key("TEMPLATE_TAIL"));
    for name in [
        "STATS",
        "START",
        "RV_COUNTS",
        "EVENTS",
        "EVIDENCE",
        "DISCOVERY",
        "DISCOVERY_STATE",
        "COUNTERS",
        "PAUSE_PIDS",
    ] {
        assert_eq!(definitions[name][FLAGS], 0, "dynamic map {name}");
    }
}

#[test]
fn descriptor_cookie_and_publication_source_guard_rejects_contract_regressions() {
    let attach = read("src/attach.rs");
    let ebpf = read("crates/ebpf/src/main.rs");

    assert_static_descriptor_cookie_contract(&attach, &ebpf).unwrap();
    assert_descriptor_publication_contract(&attach).unwrap();

    let dropped_return_descriptor = attach.replacen(
        "cookie: Some(attach_cookie(slot.index, slot.descriptor_index)),",
        "cookie: Some(attach_cookie(slot.index, 0)),",
        1,
    );
    assert!(
        assert_static_descriptor_cookie_contract(&dropped_return_descriptor, &ebpf).is_err(),
        "the return attach site must carry the descriptor word"
    );

    let high_word_stats = ebpf.replacen(
        "if let Some(stats) = STATS.get_ptr_mut(slot) {",
        "if let Some(stats) = STATS.get_ptr_mut(cookie_descriptor(cookie_of(&ctx))) {",
        1,
    );
    assert!(
        assert_static_descriptor_cookie_contract(&attach, &high_word_stats).is_err(),
        "a slot consumer must not use the descriptor word"
    );

    let no_count_only_fallback =
        ebpf.replacen(".unwrap_or(SlotSemantics::COUNT_ONLY)", ".unwrap()", 1);
    assert!(
        assert_static_descriptor_cookie_contract(&attach, &no_count_only_fallback).is_err(),
        "a missing descriptor must remain count-only"
    );

    let template_second_high_word_slot = ebpf.replacen(
        "let key = StartKey {\n        pid_tgid: helpers::bpf_get_current_pid_tgid(),\n        slot,\n        _pad: 0,\n    };\n    let Some(start) = START.get_ptr_mut(&key)",
        "let key = StartKey {\n        pid_tgid: helpers::bpf_get_current_pid_tgid(),\n        slot: cookie_descriptor(cookie_of(&ctx)),\n        _pad: 0,\n    };\n    let Some(start) = START.get_ptr_mut(&key)",
        1,
    );
    let bypassed_primary_semantics = ebpf.replacen(
        "    let semantics = semantics_of(&ctx);\n    let mut start = CallStart {",
        "    let semantics = SlotSemantics::COUNT_ONLY;\n    let mut start = CallStart {",
        1,
    );
    assert_eq!(
        [
            assert_static_descriptor_cookie_contract(&attach, &template_second_high_word_slot)
                .is_err(),
            assert_static_descriptor_cookie_contract(&attach, &bypassed_primary_semantics).is_err(),
        ],
        [true, true],
        "the template-tail slot and every descriptor consumer must use the shared cookie path"
    );

    let partial_descriptor_write = attach.replacen(
        "expected.iter().copied().enumerate()",
        "expected.iter().copied().take(1).enumerate()",
        1,
    );
    assert!(
        assert_descriptor_publication_contract(&partial_descriptor_write).is_err(),
        "publication must write every fixed descriptor"
    );

    let changed_readback_refusal = attach.replacen(
        "if actual != expected {\n        bail!(\"DESCRIPTORS exact readback differs",
        "if false {\n        bail!(\"DESCRIPTORS exact readback differs",
        1,
    );
    assert!(
        assert_descriptor_publication_contract(&changed_readback_refusal).is_err(),
        "publication must refuse an inexact descriptor readback"
    );
}

#[test]
fn live_discovery_host_contract_is_opaque_fixed_purpose_and_owned_child_only() {
    let attach = read("src/attach.rs");
    let scope = read("src/scope.rs");
    let events = read("src/events.rs");
    let hooks = read("src/discovery/hooks.rs");
    let engine = read("src/discovery/engine.rs");
    let library = read("src/lib.rs");
    let main = read("src/main.rs");
    let pause = read("src/discovery/pause.rs");
    let run = read("src/run.rs");

    assert_live_discovery_host_contract(&attach, &scope, &events, &hooks, &engine, &main, &run)
        .unwrap();
    assert_owned_run_pause_internal_contract(
        &attach, &events, &engine, &library, &main, &pause, &run,
    )
    .unwrap();

    let public_run = library.replacen("pub(crate) mod run;", "pub mod run;", 1);
    assert!(
        assert_owned_run_pause_internal_contract(
            &attach,
            &events,
            &engine,
            &public_run,
            &main,
            &pause,
            &run,
        )
        .is_err(),
        "Task 7 must not broaden the public library surface"
    );

    let public_ebpf = attach.replacen("pub(crate) ebpf: Ebpf,", "pub ebpf: Ebpf,", 1);
    assert!(
        assert_live_discovery_host_contract(
            &public_ebpf,
            &scope,
            &events,
            &hooks,
            &engine,
            &main,
            &run,
        )
        .is_err(),
        "a mutable Ebpf must not escape to the binary or external callers"
    );
    let fabricated = attach.replacen("    tgid: u32,", "    pub tgid: u32,", 1);
    assert!(
        assert_live_discovery_host_contract(
            &fabricated,
            &scope,
            &events,
            &hooks,
            &engine,
            &main,
            &run,
        )
        .is_err(),
        "the owned capability fields must remain opaque"
    );
    let armed_engine = engine.replacen(
        "self.start_session_with(policy, None, None)",
        "self.start_owned_session(policy, child)",
        1,
    );
    assert!(
        assert_live_discovery_host_contract(
            &attach,
            &scope,
            &events,
            &hooks,
            &armed_engine,
            &main,
            &run,
        )
        .is_err(),
        "ordinary start must not gain an owned pause capability"
    );
    let shared_malformed =
        events.replacen("struct DiscoveryDrain<'a>", "struct GenericDrain<'a>", 1);
    assert!(
        assert_live_discovery_host_contract(
            &attach,
            &scope,
            &shared_malformed,
            &hooks,
            &engine,
            &main,
            &run,
        )
        .is_err(),
        "DISCOVERY must keep its own fixed-purpose drain owner"
    );
    let drifted_cgroup_metadata = attach.replacen(
        "map_metadata(MapType::CgroupArray, 4, 4, 1, 0)",
        "map_metadata(MapType::CgroupArray, 4, 8, 1, 0)",
        1,
    );
    assert!(
        assert_live_discovery_host_contract(
            &drifted_cgroup_metadata,
            &scope,
            &events,
            &hooks,
            &engine,
            &main,
            &run,
        )
        .is_err(),
        "CGROUP_FILTER value-width drift must fail the exact metadata contract"
    );
    let skipped_policy_barrier = attach.replacen(
        "        validate_policy_maps(&ebpf, object_has_unsafe)",
        "        skip_policy_validation(&ebpf, object_has_unsafe)",
        1,
    );
    assert!(
        assert_live_discovery_host_contract(
            &skipped_policy_barrier,
            &scope,
            &events,
            &hooks,
            &engine,
            &main,
            &run,
        )
        .is_err(),
        "policy-map metadata must be validated before publication"
    );
}

#[test]
fn live_discovery_bpf_classification_is_exact_and_output_only() {
    let source = read("crates/ebpf/src/main.rs");
    let export = between(&source, "fn emit_export(", "fn export_symbol_id");
    assert!(
        export.contains("let mut bytes = [0u8; 9];"),
        "the ninth byte must distinguish an exact standard name from a longer prefix"
    );
    assert!(
        export.contains("read == 8 && bytes[..8] == *b\"PKCS 11\\0\""),
        "interface classification must require the exact eight-byte string"
    );

    let listed = between(
        &source,
        "pub fn interface_list_return(ctx: RetProbeContext) -> u32 {",
        "#[uprobe]\npub fn interface_entry",
    );
    let output_null = listed
        .find("if state.arg0 == 0")
        .expect("the valid count-query form must not read a null output array");
    let loop_start = listed
        .find("while interface_index < 16")
        .expect("bounded interface loop");
    assert!(output_null < loop_start);

    for path in ["src/render.rs", "src/trace.rs", "src/output.rs"] {
        assert!(
            !read(path).contains("send_signal_rc"),
            "private helper result escaped into {path}"
        );
    }
}

#[test]
fn live_discovery_checker_rejects_mutations_and_noncanonical_source() {
    let output = Command::new("python3")
        .args(["scripts/check-live-discovery-object.py", "--self-test"])
        .output()
        .expect("run live-discovery checker self-test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for marker in [
        "live discovery source mutations rejected: OK",
        "live discovery object mutations rejected: OK",
        "unrelated memset positive control: OK",
    ] {
        assert!(stdout.contains(marker), "checker self-test misses {marker}");
    }

    let directory = tempfile::tempdir().expect("temporary checker directory");
    let manifest = directory.path().join("manifest.json");
    let rejected = Command::new("python3")
        .args([
            "scripts/check-live-discovery-object.py",
            "--write-test-manifest",
            "--source",
            "crates/ebpf/src/main.rs",
            "--variant",
            "default",
            "--output",
        ])
        .arg(&manifest)
        .output()
        .expect("reject noncanonical live-discovery source");
    assert!(!rejected.status.success());
    assert!(!manifest.exists());
}

#[test]
fn descriptors_are_published_read_back_and_frozen_before_probe_attachment() {
    let source = read("src/attach.rs");
    let publish = source
        .find("publish_descriptors(&mut ebpf)")
        .expect("Session must publish descriptors");
    let descriptor_freeze = source
        .find("freeze_map(\n            \"DESCRIPTORS\",")
        .expect("Session must freeze descriptors");
    let fork_attach = source
        .find(".attach(\"sched\", \"sched_process_fork\")")
        .expect("Session must attach the fork probe");
    let uprobe_attach = source
        .find("prog.attach(point")
        .expect("Session must attach uprobes");
    assert_descriptor_publication_contract(&source).unwrap();
    assert!(publish < descriptor_freeze);
    assert!(descriptor_freeze < fork_attach);
    assert!(descriptor_freeze < uprobe_attach);
}

#[test]
fn policy_specific_ebpf() {
    const KEY_SIZE: usize = 1;
    let definitions = embedded_map_definitions();
    let symbols = embedded_symbols();

    assert_eq!(definitions["ASYNC_FUNCTIONS"][KEY_SIZE], 32);
    for unsafe_map in ["ATTR_BOOL_BITS", "TEMPLATE_TAIL"] {
        assert!(
            !definitions.contains_key(unsafe_map),
            "default object contains unsafe-only map {unsafe_map}"
        );
    }
    for unsafe_symbol in [
        "p11_entry_template",
        "p11_entry_template_types",
        "p11_entry_template_pair",
        "p11_entry_template_second",
        "walk_template",
        "decode_params",
    ] {
        assert!(
            !symbols.contains(unsafe_symbol),
            "default object contains unsafe-only symbol {unsafe_symbol}"
        );
    }
}

#[test]
fn metadata_canary_matrix() {
    let canaries = read("scripts/verify-canaries.sh");
    let lane_block = canaries
        .split_once("done <<'LANES'\n")
        .expect("canary lane table")
        .1
        .split_once("\nLANES")
        .unwrap()
        .0;
    assert_eq!(
        lane_block,
        "default-safe-profile default profile\n\
default-safe-trace default trace\n\
feature-safe-profile feature profile\n\
feature-safe-trace feature trace\n\
feature-unsafe-profile feature-unsafe profile\n\
feature-unsafe-trace feature-unsafe trace\n\
aggregate-only-metrics default metrics"
    );
    let blocked_lanes = canaries
        .split_once("done <<'BLOCKED_LANES'\n")
        .expect("blocked safe-policy lane table")
        .1
        .split_once("\nBLOCKED_LANES")
        .unwrap()
        .0;
    assert_eq!(
        blocked_lanes,
        "default-safe-start default\nfeature-safe-start feature"
    );

    let induced = read("scripts/verify-induced-gaps.sh");
    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("matrix-provider.so");
    let workload = directory.path().join("canary-workload");
    run_ok(
        "cc",
        &[
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-DPRIVACY_FIXTURE=1",
            "-o",
            provider.to_str().unwrap(),
            "crates/discover/tests/fixture/version_matrix.c",
        ],
    );
    run_ok(
        "cc",
        &[
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-o",
            workload.to_str().unwrap(),
            "scripts/fixtures/canary_workload.c",
            "-ldl",
        ],
    );
    let matrix = run_ok(
        workload.to_str().unwrap(),
        &[provider.to_str().unwrap(), "matrix"],
    );
    assert_eq!(
        matrix
            .lines()
            .filter(|line| line.ends_with(" -> 0x0"))
            .count(),
        25
    );
    assert!(matrix.contains("canary_workload matrix: all calls CKR_OK"));

    let blocked = run_ok(
        workload.to_str().unwrap(),
        &[provider.to_str().unwrap(), "blocked"],
    );
    assert!(blocked.contains("blocked hostile subset: all calls CKR_OK"));
    let faults = run_ok(
        workload.to_str().unwrap(),
        &[provider.to_str().unwrap(), "faults"],
    );
    assert!(faults.contains("blocked template faults: all calls CKR_OK"));

    let lanes = run_ok("sh", &["scripts/verify-canaries.sh", "--self-test"]);
    assert!(lanes.contains("canary lane assertion self-test: OK"));
    assert!(lanes.contains("raw binary alias scanner self-test: OK"));
    assert!(lanes.contains("unsafe raw template oracle self-test: OK"));
    assert!(lanes.contains("raw policy oracle self-test: OK"));
    assert!(lanes.contains("full CallStart safe defaults self-test: OK"));
    assert!(lanes.contains("scan-only hostile output contract: OK"));
    assert!(lanes.contains("canary matrix 988/104/208 with 16 mixed surfaces: OK"));
    let mut sentinels = canary_literals(&read("scripts/fixtures/canary_workload.c"));
    sentinels.extend(canary_literals(&read(
        "scripts/fixtures/privacy-stack-workload.c",
    )));
    assert_eq!(sentinels.len(), 18, "unexpected fixture sentinel inventory");
    for sentinel in sentinels {
        assert!(
            lanes.contains(&sentinel),
            "scanner self-test omitted fixture sentinel {sentinel}"
        );
    }

    let dumper = run_ok(
        "python3",
        &["scripts/dump-owned-bpf-maps.py", "--self-test"],
    );
    assert!(dumper.contains("nonzero valid JSON rejected: OK"));
    assert!(dumper.contains("ordinary dump list validation: OK"));

    let harness = induced
        .split_once("#define _GNU_SOURCE\n")
        .unwrap()
        .1
        .split_once("\nEOF\n")
        .unwrap()
        .0;
    assert!(!harness.contains("BPF_MAP_FREEZE"));
    let source = directory.path().join("freeze-policy-maps.c");
    let binary = directory.path().join("freeze-policy-maps");
    fs::write(&source, format!("#define _GNU_SOURCE\n{harness}")).unwrap();
    let compiled = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&binary)
        .arg(source)
        .output()
        .expect("compile freeze harness");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let harness_test = Command::new(binary)
        .arg("--self-test")
        .output()
        .expect("run freeze predicate self-test");
    assert!(harness_test.status.success());
    assert!(
        String::from_utf8_lossy(&harness_test.stdout)
            .contains("freeze matched-result self-test: OK")
    );

    let inspector = run_ok("python3", &["scripts/check-bpf-map-defs.py", "--self-test"]);
    assert!(inspector.contains("policy inventory self-test: OK"));
    assert!(inspector.contains("malformed map definitions rejected: OK"));
}

/// The usage text is the contract for the manifest-free CLI, and the binary must
/// keep the exit codes that contract implies: 2 for a usage error, 0 for `--help`,
/// 1 with a single line for a target that cannot be read at all.
#[test]
fn usage_documents_every_subcommand_and_capture_needs_no_manifest() {
    for line in [
        "p11scope profile",
        "p11scope trace",
        "p11scope run",
        "--pause never|auto|always",
        "-- CMD [ARGS...]",
        "p11scope inspect --pid",
        "p11scope doctor",
        "p11scope-discover --module",
    ] {
        assert!(
            p11scope::cli::USAGE.contains(line),
            "{line} missing from usage"
        );
    }
    assert!(
        p11scope::cli::USAGE
            .contains("discovery scans the target's mapped memory — no manifest and no helper")
    );

    let bin = env!("CARGO_BIN_EXE_p11scope");
    let help = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run --help");
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stderr).contains("p11scope inspect"));

    let no_pid = Command::new(bin)
        .arg("inspect")
        .output()
        .expect("run inspect");
    let stderr = String::from_utf8_lossy(&no_pid.stderr);
    assert_eq!(no_pid.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--pid"), "{stderr}");

    // `run` refuses at the same usage exit code as every other subcommand: a
    // command it was never given, and a scope flag it does not have.
    for (arguments, expected) in [
        (vec!["run"], "-- CMD [ARGS...]"),
        (vec!["run", "--", ""], "-- CMD [ARGS...]"),
        (
            vec!["run", "--pid", "1", "--", "/bin/true"],
            "run has no --pid or --cgroup",
        ),
        (
            vec!["run", "--pause", "sometimes", "--", "/bin/true"],
            "never|auto|always",
        ),
        (
            vec!["profile", "--pid", "1", "--pause", "auto"],
            "`p11scope run`",
        ),
    ] {
        let refused = Command::new(bin)
            .args(&arguments)
            .output()
            .expect("run p11scope");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert_eq!(refused.status.code(), Some(2), "{arguments:?}: {stderr}");
        assert!(stderr.contains(expected), "{arguments:?}: {stderr}");
    }

    // A pid that names nothing: one line, exit 1, never a panic or a backtrace.
    let gone = Command::new(bin)
        .args(["inspect", "--pid", "2147483632"])
        .output()
        .expect("run inspect on a dead pid");
    let stderr = String::from_utf8_lossy(&gone.stderr);
    assert_eq!(gone.status.code(), Some(1), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn operator_docs_preserve_semantic_authority_limits() {
    for (path, statement) in [
        (
            "README.md",
            "Live and terminal evidence are PARTIAL while scan-only semantic claims remain",
        ),
        (
            "docs/usage.md",
            "P11Lab joins reject scan-only and conflict modules",
        ),
        (
            "CHANGELOG.md",
            "Slice 1b-2 live discovery is wired internally",
        ),
        ("docs/superpowers/plans/ROADMAP.md", "CI remains pending"),
    ] {
        assert!(
            read(path)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains(statement),
            "{path} is missing: {statement}"
        );
    }

    for path in [
        "README.md",
        "docs/usage.md",
        "CHANGELOG.md",
        "docs/superpowers/plans/ROADMAP.md",
    ] {
        let document = read(path).split_whitespace().collect::<Vec<_>>().join(" ");
        for statement in [
            "Final whole-range correctness/security reviews and the exact-candidate local matrix passed on 2026-08-19",
            "CI remains pending",
        ] {
            assert!(
                document.contains(statement),
                "{path} is missing: {statement}"
            );
        }
    }

    for path in ["README.md", "docs/usage.md", "CHANGELOG.md"] {
        assert!(read(path).to_lowercase().contains("unreleased"), "{path}");
    }
    for path in ["docs/usage.md", "docs/superpowers/plans/ROADMAP.md"] {
        let document = read(path).split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            document.contains("no release or security-clearance claim"),
            "{path}"
        );
    }
    for path in ["README.md", "docs/usage.md"] {
        let document = read(path).split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            document.contains(
                "Slice 1b-2 live discovery is wired internally, but public `run` is absent and the live path remains unsupported and unreleased pending Tasks 6E–10"
            ),
            "{path}"
        );
    }
}

#[test]
fn gate_scripts_pin_the_toolchain() {
    for path in [
        "scripts/verify-canaries.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/verify-inspect-doctor.sh",
        "scripts/matrix/verify-fork-scope.sh",
        "scripts/matrix/verify-proxy-stack.sh",
    ] {
        run_ok("sh", &["-n", path]);
        for line in read(path).lines().map(str::trim_start) {
            if !line.starts_with('#')
                && (line.starts_with("cargo ") || line.contains(" cargo build"))
            {
                assert!(
                    line.contains("cargo +1.88"),
                    "unpinned cargo command in {path}: {line}"
                );
            }
        }
    }
}

/// Task 8 Step 2's ordering sentence, frozen where the loops live: "Each tick
/// drains discovery, lets `Engine` extend `AttachPlan` and apply attachment
/// deltas, synchronizes immediate semantic/trace invalidations while
/// preserving unchanged retired decode metadata, drains call events, retires
/// exited process state, snapshots metrics/counters, and checks retained
/// generations/objects."
///
/// The synchronization step landing before the event drain and the snapshot is
/// what makes a slot discovered mid-capture visible to metrics and to trace in
/// the same tick it arrived; the terminal section is what keeps detach ahead of
/// the final drain and snapshot, with the in-flight honesty boundary intact.
#[test]
fn both_capture_loops_keep_the_one_frozen_per_tick_ordering() {
    let run = read("src/run.rs");
    let profile = between(&run, "fn capture_profile(", "fn write_json_report(");
    let trace = between(&run, "fn capture_trace(", "\n/// Prints (and, if given,");

    for (name, source, tick_end, sync) in [
        (
            "profile",
            profile,
            "    finish_capture_loop(",
            "state.sync_plan(engine.plan());",
        ),
        (
            "trace",
            trace,
            "    finish_capture_loop(",
            "tracer.sync_plan(engine.plan());",
        ),
    ] {
        let tick = between(
            source,
            "    loop {\n        let elapsed = clock.elapsed();",
            tick_end,
        );
        let drain_events = if name == "profile" {
            "drain_events(session, &mut state, &mut process_tracker)"
        } else {
            "drain_trace_events(\n            session,"
        };
        let snapshot = if name == "profile" {
            "metrics::kernel_evidence(session)?"
        } else {
            "report_trace_loss("
        };
        for (first, second, contract) in [
            (
                "drain_discovery_tick(engine, session,",
                sync,
                "discovery drain before its immediate invalidation sync",
            ),
            (
                sync,
                drain_events,
                "invalidation sync before the call-event drain",
            ),
            (
                drain_events,
                "retire_exited(&mut process_tracker, &mut state);",
                "call-event drain before exited-process retirement",
            ),
            (
                "retire_exited(&mut process_tracker, &mut state);",
                snapshot,
                "exited-process retirement before the metrics/counter snapshot",
            ),
            (
                snapshot,
                ".check_unchanged()",
                "metrics/counter snapshot before the retained generation/object check",
            ),
        ] {
            require_before(tick, first, second, &format!("{name} tick: {contract}")).unwrap();
        }
    }

    // Terminal: detach the producers, then drain, then snapshot. A fallible
    // provider check must not sit between the detach and its drain.
    require_before(
        profile,
        "let detach = session.detach_producers();",
        "        malformed_records += drain_events(session, &mut state, &mut process_tracker)?;\n    }\n    retire_exited",
        "profile terminal detach before the final drain",
    )
    .unwrap();
    require_before(
        profile,
        "let detach = session.detach_producers();",
        "    let reports = metrics::read(session, engine.plan())?;\n    let mut kernel_evidence",
        "profile terminal detach before the final snapshot",
    )
    .unwrap();
    require_before(
        trace,
        "let detach = session.detach_producers();",
        "    let reports = metrics::read(session, engine.plan())?;",
        "trace terminal detach before the final snapshot",
    )
    .unwrap();
    // The owned child is settled before any terminal evidence is built, so
    // `child_still_running` is reported rather than guessed after the fact.
    for source in [profile, trace] {
        require_before(
            source,
            "finish_capture_loop(",
            "let detach = session.detach_producers();",
            "owned-child settlement before terminal evidence",
        )
        .unwrap();
    }
    // And the honesty boundary the plan says to retain is still there.
    assert!(
        profile.contains("ev.mark_terminal_drain_unproven();"),
        "the profile terminal snapshot must stay explicitly unproven"
    );
    assert!(
        trace.contains("evidence.mark_terminal_drain_unproven();"),
        "the trace terminal evidence must stay explicitly unproven"
    );
}

/// CI viability (8.1 review, Important 1): after Task 8 Step 2 the extended
/// checker contract that `scripts/verify-attach-e2e.sh` runs over *real*
/// artifacts must be satisfiable by the real renderer's output.
///
/// This proves it without privileges and without a container: the document
/// below is produced by the production renderer — `render::json` over a real
/// `render::Evidence` and real `metrics::SlotReport` rows — and is then handed
/// to the checker's own extended functions, imported from the script itself
/// rather than reimplemented here. Positive control first: the real output is
/// accepted, and only then is a mutation shown to be rejected, so an accepting
/// run cannot be a broken driver.
#[test]
fn the_real_renderer_output_satisfies_the_extended_checker_contract() {
    use p11scope::plan::{ModuleId, SurfaceSummary, TableSummary};
    use p11scope::render::{DiscoveredModule, DiscoveryEvidence, Evidence, ObjectSummary};

    let object = ObjectSummary {
        dev: (8, 1),
        ino: 4242,
        sha256: Some("11".repeat(32)),
        path: "/opt/p11.so".into(),
        build_id: Some("aabb".into()),
        identity_source: "mountinfo",
        note: None,
        sources: vec!["scan"],
    };
    let module = DiscoveredModule {
        id: ModuleId(0),
        dev: object.dev,
        ino: object.ino,
        sha256: object.sha256.clone(),
        path: object.path.clone(),
        build_id: object.build_id.clone(),
        objects: vec![object],
        sources: vec!["scan"],
        corroborated: false,
        corroboration: vec!["single_source"],
        tables: vec![TableSummary {
            version: (2, 40),
            entries: 68,
            source: "scan",
        }],
        interfaces: 0,
        skipped: vec![],
    };
    let mut evidence = Evidence {
        table_entries: 68,
        slots: 68,
        attached_probes: 136,
        attach_failures: vec![],
        aliased: vec![],
        skipped: vec![],
        semantic_unverified_slots: 0,
        in_flight_at_end: 0,
        surfaces: vec![SurfaceSummary {
            source: "legacy_function_list".into(),
            walk: "full".into(),
            acquisition: "ok".into(),
            functions: 68,
        }],
        vendor_interfaces: 0,
        interface_list: "absent".into(),
        event_loss: 0,
        start_insert_failures: 0,
        unmatched_returns: 0,
        rv_update_failures: 0,
        cgroup_scope_failures: 0,
        semantic_capture_failures: 0,
        unregistered_mechanisms: 0,
        template_tail_failures: 0,
        process_tracking_fallbacks: 0,
        process_tracking_failures: 0,
        process_tracking_evictions: 0,
        state_reconciliations: 0,
        session_cancel_ambiguities: 0,
        session_cancel_unknown_flags: 0,
        operation_state_imports: 0,
        auth_state_ambiguities: 0,
        async_target_failures: 0,
        async_orphans: 0,
        async_duplicates: 0,
        async_evictions: 0,
        fork_state_ambiguities: 0,
        semantic_state_drops: 0,
        pending_at_end: 0,
        malformed_records: 0,
        orphan_ops: 0,
        unmatched_closes: 0,
        shape_decode_failures: 0,
        shape_decode_total_failures: 0,
        templates_truncated: false,
        provider_changed: false,
        // A capture that lived through live loader discovery: exactly the
        // shape a real `verify-attach-e2e.sh` lane now produces.
        attach_gap_ms: Some(7),
        pause: "none",
        pause_attempts: 0,
        pause_confirmed: 0,
        pause_partial: 0,
        child_still_running: None,
        discovery_ring_loss: 0,
        discovery_state_failures: 0,
        discovery_read_failures: 0,
        discovery_truncated: 0,
        loader_discovery: p11scope::render::LoaderDiscovery {
            strategies: p11scope::render::LoaderStrategies {
                debug_state_every_hit: 1,
                ..Default::default()
            },
            dlopen_timing: p11scope::render::LoaderTiming {
                unproven: 1,
                ..Default::default()
            },
            initial_set_timing: Default::default(),
            initial_set_capture: Default::default(),
            hits: 4,
            state_read_failures: 0,
        },
        unprotected_live_windows: 1,
        module_unresolved_slots: 0,
        discovery: DiscoveryEvidence {
            modules: vec![module],
            ..DiscoveryEvidence::default()
        },
        completeness: "UNKNOWN",
    };
    evidence.verdict();
    assert_eq!(evidence.completeness, "PARTIAL");

    let mut owned = p11scope::metrics::SlotReport {
        names: vec!["C_Sign".into()],
        aliased: false,
        semantic_authorized: true,
        module: Some(ModuleId(0)),
        module_ambiguous: false,
        module_unresolved: false,
        calls: 3,
        errors: 0,
        in_flight: 0,
        total_ns: 0,
        max_ns: 0,
        buckets: [0; p11scope_ebpf_common::LATENCY_BUCKETS],
        rv_counts: Default::default(),
    };
    let mut unresolved = owned.clone();
    unresolved.names = vec!["C_Encrypt".into()];
    unresolved.module = None;
    unresolved.module_unresolved = true;
    let mut ambiguous = owned.clone();
    ambiguous.names = vec!["C_Digest".into()];
    ambiguous.module = None;
    ambiguous.module_ambiguous = true;
    owned.calls = 1;

    let document = p11scope::render::json(
        &[owned, unresolved, ambiguous],
        &evidence,
        &p11scope::render::CaptureMeta {
            started: "1970-01-01T00:00:00Z",
            ended: "1970-01-01T00:00:01Z",
            kernel: "6.8.0",
            policy: p11scope::attach::CapturePolicy::AggregateOnly,
        },
    );

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("checker-viability");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rendered.json");
    fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

    // The driver imports the checker by path and runs exactly the extended
    // contract `exact_common`/`exact_capture_modules` now reach.
    let driver = r#"
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("checker", "scripts/check-capture-evidence.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
document = json.load(open(sys.argv[1]))
checker.exact_live_discovery_evidence(document["evidence"])
checker.exact_module_ownership(document)
checker.exact_active_to_empty(document)
checker.exact_capture_modules(document)
print("accepted")
"#;
    let accepted = std::process::Command::new("python3")
        .args(["-c", driver])
        .arg(&path)
        .output()
        .expect("running python3");
    assert!(
        accepted.status.success(),
        "the real renderer output is not checker-viable:\n{}\n{}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );

    // Positive control passed; now the same driver must reject a mutation.
    let mut broken = document.clone();
    broken["evidence"]
        .as_object_mut()
        .unwrap()
        .remove("loader_discovery");
    let broken_path = dir.join("mutated.json");
    fs::write(&broken_path, serde_json::to_vec_pretty(&broken).unwrap()).unwrap();
    let rejected = std::process::Command::new("python3")
        .args(["-c", driver])
        .arg(&broken_path)
        .output()
        .expect("running python3");
    assert!(
        !rejected.status.success(),
        "the checker accepted a document with no loader_discovery"
    );

    // The unowned row is accepted because it states its reason, not because the
    // checker stopped looking: the same row with no reason must be rejected.
    let mut reasonless = document.clone();
    reasonless["functions"][1]
        .as_object_mut()
        .unwrap()
        .insert("module_unresolved".into(), serde_json::Value::Bool(false));
    let reasonless_path = dir.join("reasonless.json");
    fs::write(
        &reasonless_path,
        serde_json::to_vec_pretty(&reasonless).unwrap(),
    )
    .unwrap();
    let rejected = std::process::Command::new("python3")
        .args(["-c", driver])
        .arg(&reasonless_path)
        .output()
        .expect("running python3");
    assert!(
        !rejected.status.success(),
        "the checker accepted an unattributed slot with no stated reason"
    );
}

/// Task 8 Step 2, "Freeze the consumer map explicitly": metrics and function
/// attribution use capture aggregate owners; semantic attachment decisions use
/// active topology; final evidence/discovery and module labels use sanitized
/// capture facts; coordinator fields use only its own finite aggregate.
#[test]
fn the_capture_loop_consumer_map_is_frozen() {
    let run = read("src/run.rs");
    let evidence = between(
        &run,
        "fn evidence_for(",
        "\n/// `SystemTime` \u{2192} an RFC3339",
    );

    // Final evidence and discovery: sanitized capture facts, never the live
    // plan's own counts.
    for marker in [
        "let facts = engine.capture_facts();",
        "table_entries: facts.table_entries()",
        "slots: facts.slots()",
        "attach_gap_ms: facts.attach_gap_ms()",
        "loader_discovery: facts.loader_discovery()",
        "discovery: facts.discovery().clone()",
        "facts.discovery_losses()",
    ] {
        assert!(evidence.contains(marker), "consumer map lost {marker:?}");
    }
    for forbidden in ["plan.entries_seen", "plan.slots.len()"] {
        assert!(
            !evidence.contains(forbidden),
            "published history was taken from active topology: {forbidden}"
        );
    }

    // Metrics and function attribution: the capture aggregate owners the
    // `SlotReport` rows already carry.
    assert!(
        evidence.contains(".filter(|report| report.module_unresolved)"),
        "ownership must come from the aggregate owner rows"
    );

    // Coordinator fields: only its own finite aggregate, never its identity.
    for marker in [
        "let pause = owned.map_or_else(Default::default, |owned| owned.coordinator.counters());",
        "pause_attempts: pause.attempts",
        "pause_confirmed: pause.confirmed",
        "pause_partial: pause.partial",
    ] {
        assert!(evidence.contains(marker), "consumer map lost {marker:?}");
    }
    for forbidden in ["child.pid()", "coordinator.generation()", "child.pin()"] {
        assert!(
            !evidence.contains(forbidden),
            "a loader/pause identity reached a render type: {forbidden}"
        );
    }

    // Module labels: capture-lifetime facts only. The old active-topology
    // label is gone, and every heading goes through the one policy.
    assert!(
        !run.contains("fn module_label("),
        "the active-topology heading must not survive"
    );
    // Two headings exist at all: the profile loop's live frame and its
    // terminal frame. The trace loop prints no heading, and its terminal
    // evidence line is rendered from the same `Evidence` the JSON uses.
    assert_eq!(
        run.matches(".heading()").count(),
        2,
        "every live and terminal heading must come from capture facts"
    );

    // Semantic attachment decisions still read the active topology.
    for marker in [
        "semantics::State::with_policy(engine.plan(), policy)",
        "state.sync_plan(engine.plan());",
        "trace::Tracer::new(engine.plan())",
        "tracer.sync_plan(engine.plan());",
    ] {
        assert!(
            run.contains(marker),
            "semantic attachment must keep active topology: {marker:?}"
        );
    }
}

#[test]
fn live_discovery_evidence_validator_rejects_every_frozen_claim_mutation() {
    let stdout = run_ok(
        "python3",
        &["scripts/check-live-discovery-evidence.py", "--self-test"],
    );
    for marker in [
        "frozen manifest binding: OK",
        "exported/hidden provider byte identities differ: OK",
        "execution manifest mutations rejected: OK",
        "campaign row mutations rejected: OK",
        "preflight PASS-list mutations rejected: OK",
    ] {
        assert!(
            stdout.contains(marker),
            "evidence validator self-test misses {marker}"
        );
    }

    // The production lifecycle oracle is not the isolated A/B spike's.
    let validator = read("scripts/check-live-discovery-evidence.py");
    assert!(
        validator.contains("AB_FOUR_MAP_ORACLE = (\"COUNTERS\", \"DISCOVERY\", \"DISCOVERY_STATE\", \"PAUSE_PIDS\")"),
        "the A/B four-map oracle must stay named and rejected by the production validator"
    );
    for claim in [
        "the A/B spike's four-map oracle is not the production lifecycle oracle",
        "lifecycle did not cover the complete production map inventory",
    ] {
        assert!(
            validator.contains(claim),
            "missing lifecycle claim: {claim}"
        );
    }
}

#[test]
fn live_discovery_gates_freeze_the_exact_command_inputs_and_fixture_flags() {
    let preflight = read("scripts/verify-live-discovery-preflight.sh");
    // The plan's frozen inputs, defined in exactly one place and never guessed.
    for input in [
        "printf 'BPF_OBJECT=%s/frozen/p11scope-ebpf\\n'",
        "printf 'BPF_INVENTORY=%s/frozen/bpf-inventory.json\\n'",
        "printf 'CAMPAIGN_ROOT=%s/campaign\\n'",
        "printf 'EXECUTION_MANIFEST=%s/execution-manifest.json\\n'",
    ] {
        assert!(preflight.contains(input), "frozen input missing: {input}");
    }
    assert!(
        preflight.contains("mode is $rfi_mode, want 700"),
        "the private root must be required to be mode 0700"
    );

    let stdout = run_ok(
        "bash",
        &["scripts/verify-live-discovery-preflight.sh", "--self-test"],
    );
    assert!(
        stdout.contains("live discovery preflight input mutations rejected: OK"),
        "preflight self-test misses its mutation lane: {stdout}"
    );

    // Frozen fixture build flags, verbatim.
    let validator = read("scripts/check-live-discovery-evidence.py");
    for flags in [
        "CFLAGS = \"-std=c11 -O2 -Wall -Wextra -Werror -fPIC\"",
        "SHARED_LDFLAGS = \"-shared -Wl,-z,defs\"",
        "DRIVER_LDFLAGS = \"-ldl -pthread\"",
    ] {
        assert!(
            validator.contains(flags),
            "frozen fixture flags differ: {flags}"
        );
    }
}

#[test]
fn live_discovery_fixtures_have_two_byte_identities_and_three_surfaces() {
    let provider = read("tests/fixtures/live-discovery-provider.c");
    let driver = read("tests/fixtures/live-discovery-driver.c");
    let first_include = provider
        .find("#include")
        .expect("provider includes system headers");
    assert!(
        provider[..first_include].contains("#define _GNU_SOURCE"),
        "provider must define _GNU_SOURCE before its first include"
    );
    assert!(
        provider.contains("#if P11SCOPE_EXPORT_TABLES")
            && provider.contains("#define TABLE_FN static"),
        "one provider source must compile into exported and hidden table identities"
    );
    for surface in ["C_GetFunctionList", "C_GetInterfaceList", "C_GetInterface"] {
        assert!(
            provider.contains(&format!("{surface}(")),
            "the provider must implement {surface}"
        );
        assert!(
            driver.contains(surface),
            "both drivers must exercise {surface}"
        );
    }
    // Per-surface constructor and application markers, never inferred timing.
    assert!(
        provider.contains("return provider_application_phase ? \"app\" : \"ctor\";"),
        "constructor and application markers must be distinguished by phase, not timing"
    );
    // One driver source, both load kinds, and the frozen lane modes.
    assert!(
        driver.contains("#if defined(P11SCOPE_DRIVER_NEEDED)"),
        "one driver source must serve DT_NEEDED and dlopen load kinds"
    );
    for mode in [
        "needed",
        "dlopen",
        "pause-partial",
        "exec-fail",
        "zero-modules",
    ] {
        assert!(driver.contains(mode), "driver lane mode missing: {mode}");
    }
}

#[test]
fn lane13_cleanup_never_removes_unowned_collision_paths() {
    // Break caught: an early collision used to flow into the EXIT trap, which
    // unlinked the caller's kubeconfig although this run never created it.
    let gate = read("scripts/matrix/verify-knative.sh");
    let cleanup = between(&gate, "cleanup() {", "\n. scripts/cleanup-traps.sh");
    let directory = tempfile::tempdir().expect("temporary lane-13 collision directory");
    let script = directory.path().join("cleanup.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -u
. scripts/lib.sh
WORK={work}/work
KUBECONFIG=$WORK/kubeconfig
mkdir "$WORK"
: > "$KUBECONFIG"
PF_PID= PF_STARTTIME= PF_PGID= PF_SID= PF_GROUP_SNAPSHOT= PF_SESSION_EMPTY=1
LANE13_BODY_PID= LANE13_BODY_STARTTIME= LANE13_BODY_PGID= LANE13_BODY_SID=
LANE13_BODY_SIGNAL= LANE13_BODY_SIGNAL_STATUS=0
SPID= SUPERVISOR_PID= SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID= ROOT_PROCESS_PID= ROOT_PROCESS_STARTTIME=
CLUSTER_CREATED= IMAGE_CREATED= KUBECONFIG_CREATED=
IMAGE_ID= CLUSTER_NODE= CLUSTER_NODE_ID=
cleanup() {{{cleanup}
false
cleanup
"#,
            work = directory.path().display(),
            cleanup = cleanup,
        ),
    )
    .expect("write collision-cleanup script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise collision cleanup");
    assert_eq!(
        output.status.code(),
        Some(1),
        "cleanup output: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        directory.path().join("work/kubeconfig").exists(),
        "cleanup removed a pre-existing kubeconfig: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lane13_pre_runtime_inputs_are_owned_and_release_bytes_stay_local() {
    // Break caught: accepting a collision, drifting base, remote release bytes,
    // ambiguous apply facts, or a post-apply mutation would hide unsafe input.
    let gate = read("scripts/matrix/verify-knative.sh");
    let canonical_kourier_url = "https://github.com/knative-extensions/net-kourier/releases/download/${KNATIVE_VERSION}/kourier.yaml";
    assert_eq!(
        gate.matches(canonical_kourier_url).count(),
        2,
        "Kourier canonical owner must be used by both the allowlist and live call"
    );
    let obsolete_kourier_url =
        "https://github.com/knative/net-kourier/releases/download/${KNATIVE_VERSION}/kourier.yaml";
    assert_eq!(
        gate.matches(obsolete_kourier_url).count(),
        0,
        "obsolete Kourier owner must not remain in production"
    );
    let d1 = between(
        &gate,
        "lane13_prepare_diagnostics() {",
        "\nterminate_port_forward() {",
    );
    let directory = tempfile::tempdir().expect("temporary lane-13 D1 directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("make lane-13 evidence parent private");
    let script = directory.path().join("d1.sh");
    let body = format!(
        "set -eu\nWORK={0}/work\nKUBECONFIG=$WORK/kubeconfig\nIMAGE=kind.local/test:unique\nCLUSTER=test-unique\nEVIDENCE={0}/evidence\nFACTS=$EVIDENCE/facts.log\nLANE13_TEST={0}\nmkdir -m 700 $EVIDENCE; : > $FACTS; chmod 600 $FACTS\nIMAGE_CREATED= CLUSTER_CREATED=\ndocker() {{ printf '%s\\n' \"$*\" >> $LANE13_TEST/docker.calls; case \"$1 $2\" in 'image inspect') [ \"$3\" = \"$IMAGE\" ] && [ -e $LANE13_TEST/image.created ] || [ \"$3\" = ubuntu:24.04 ] || return 1; if [ \"$3\" = ubuntu:24.04 ]; then printf '[{{\"Id\":\"base\",\"RepoDigests\":[\"ubuntu@sha256:base\"],\"RootFS\":{{\"Layers\":[\"a\",\"b\"]}}}}]\\n'; else printf '[{{\"Id\":\"work\",\"RepoDigests\":[\"work@sha256:work\"],\"RootFS\":{{\"Layers\":[\"a\",\"b\",\"c\"]}}}}]\\n'; fi;; pull) : > $LANE13_TEST/base.pulled;; build) printf '%s\\n' \"$*\" | grep -Fq -- --pull=false; : > $LANE13_TEST/image.created;; *) return 9;; esac; }}\nkind() {{ printf '%s\\n' \"$*\" >> $LANE13_TEST/kind.calls; case $1 in get) :;; create) : > $LANE13_TEST/cluster.created;; *) return 9;; esac; }}\ncurl() {{ if [ \"$1\" = --version ]; then printf 'curl 8.4.0\\n'; return; fi; printf '%s\\n' \"$*\" >> $LANE13_TEST/curl.calls; out= url=; while [ \"$#\" -gt 0 ]; do case $1 in --output) out=$2; shift 2;; --write-out) shift 2;; *) url=$1; shift;; esac; done; case $url in https://github.com/*) :;; *) return 9;; esac; printf release > $out; printf '%s' 'https://release-assets.githubusercontent.com/asset?secret=x'; }}\nkubectl() {{ printf '%s\\n' \"$*\" >> $LANE13_TEST/kubectl.calls; [ \"$1\" = apply ] && [ \"$2\" = -f ] && [ -f \"$3\" ] && [ \"$4\" = -o ] && [ \"$5\" = name ]; case $3 in *://*) return 9;; esac; printf 'service/example\\n'; }}\n{1}\nmkdir $WORK\nlane13_preflight\nlane13_record_base_and_build\n[ \"$IMAGE_CREATED\" = 1 ]\nlane13_create_cluster\n[ \"$CLUSTER_CREATED\" = 1 ]\nlane13_fetch_release https://github.com/knative/serving/releases/download/v1.23.0/serving-crds.yaml serving-crds.yaml\n[ ! -e $WORK/releases/serving-crds.yaml ]\ngrep -Fqx service/example $FACTS\ngrep -Fq 'release_effective=https://release-assets.githubusercontent.com/asset' $FACTS\ngrep -Fq input_sha256= $FACTS\ngrep -Fq docker_version= $FACTS\n[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 2 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 1 ]\ngrep -Fq -- --pull=false $LANE13_TEST/docker.calls\nrm -f $LANE13_TEST/docker.calls $LANE13_TEST/kind.calls\n: > $WORK/collision\nif lane13_preflight; then exit 97; fi\n[ ! -e $LANE13_TEST/docker.calls ]\n[ ! -e $LANE13_TEST/kind.calls ]\n",
        directory.path().display(),
        format_args!(
            "git() {{ case \"$1 ${{2-}}\" in 'diff --quiet'|'diff --cached'|'ls-files --others') return 0;; *) command git \"$@\";; esac; }}\ncargo() {{ printf 'cargo test\\n'; }}\nrustc() {{ printf 'rustc test\\n'; }}\nlane13_fact() {{ printf '%s\\n' \"$1\" >> \"$FACTS\"; }}\nlane13_prepare_diagnostics() {{{d1}"
        ),
    )
    .replace(
        "\nmkdir $WORK\nlane13_preflight\n",
        "\nlane13_prepare_diagnostics\nlane13_preflight\nmkdir $WORK\n",
    )
    .replace(
        "IMAGE_CREATED= CLUSTER_CREATED=\n",
        "IMAGE_CREATED= CLUSTER_CREATED=\ntimeout() { while [ \"$#\" -gt 0 ]; do case $1 in --signal=*|--kill-after=*) shift;; --signal|--kill-after) shift 2;; *s) shift; break;; *) break;; esac; done; \"$@\"; }\n",
    )
    .replace(
        "CLUSTER=test-unique\n",
        "CLUSTER=test-unique\nKNATIVE_VERSION=knative-v1.23.0\n",
    )
    .replace("case \"$1 $2\"", "case \"$1 ${2-}\"")
    .replace("fi;; pull)", "fi;; pull*)")
    .replace("pulled;; build)", "pulled;; build*)")
    .replace(
        "--pull=false; : > $LANE13_TEST/image.created;;",
        "--pull=false; : > $LANE13_TEST/image.created; printf work;;",
    )
    .replace(
        "case \"$1 ${2-}\" in 'image inspect')",
        "case \"$1 ${2-}\" in 'container inspect') printf node-id;; 'image inspect')",
    )
    .replace(
        "case $1 in get) :;; create)",
        "case \"$1 ${2-}\" in 'get clusters') :;; 'get nodes') printf node\\n;; 'create cluster')",
    )
    .replace(
        "case \"$1 ${2-}\" in 'container inspect') printf node-id;; 'image inspect')",
        "case \"$1 ${2-}\" in 'version --format') printf docker-test;; 'info --format') printf overlay;; 'container inspect') printf node-id;; 'image inspect')",
    )
    .replace(
        "case \"$1 ${2-}\" in 'version --format') printf docker-test;;",
        "case \"$1 ${2-}\" in 'version --format') printf docker-test;; 'image ls') [ \"$3\" = --no-trunc ] && [ \"$4\" = --format ] && [ \"$5\" = '{{.Repository}}\\t{{.Tag}}\\t{{.ID}}' ] && [ \"$6\" = \"$IMAGE\" ] || return 1;;",
    )
    .replace(
        "case \"$1 ${2-}\" in 'get clusters') :;; 'get nodes') printf node\\n;; 'create cluster')",
        "case \"$1 ${2-}\" in 'version ') printf kind-test;; 'get clusters') :;; 'get nodes') printf node\\n;; 'create cluster')",
    )
    .replace(
        "\nFACTS=$EVIDENCE/facts.log\n",
        "\nP11SCOPE_LANE_EVIDENCE_DIR=$EVIDENCE; export P11SCOPE_LANE_EVIDENCE_DIR\nFACTS=$EVIDENCE/facts.log\n",
    )
    .replace(
        "printf '%s' 'https://release-assets.githubusercontent.com/asset?secret=x'",
        "printf '%s\\n1' 'https://release-assets.githubusercontent.com/asset?secret=x'",
    )
    .replace(
        "curl() { if [ \"$1\" = --version ]; then printf 'curl 8.4.0\\n'; return; fi; printf '%s\\n' \"$*\" >> $LANE13_TEST/curl.calls;",
        "curl() { printf '%s\\n' \"$*\" >> $LANE13_TEST/curl.calls; if [ \"$1\" = --version ]; then printf 'curl 8.4.0\\n'; return; fi;",
    )
    .replace(
        ": > $LANE13_TEST/cluster.created;;",
        ": > $LANE13_TEST/cluster.created; : > $KUBECONFIG;;",
    )
    .replace(
        "kubectl() { printf '%s\\n' \"$*\" >> $LANE13_TEST/kubectl.calls; [ \"$1\" = apply ] && [ \"$2\" = -f ] && [ -f \"$3\" ] && [ \"$4\" = -o ] && [ \"$5\" = name ]",
        "kubectl() { if [ \"$1\" = version ]; then [ \"$#\" -eq 3 ] && [ \"$2\" = --client ] && [ \"$3\" = --output=yaml ] || return 9; printf '%s\\n' \"$*\" >> $LANE13_TEST/kubectl.calls; printf 'gitVersion: v1.33.0\\n'; return 0; fi; [ \"$1\" = apply ] && [ \"$#\" -eq 5 ] && [ \"$2\" = -f ] && [ -f \"$3\" ] && [ \"$4\" = -o ] && [ \"$5\" = name ] || return 9; case $3 in *://*) return 9;; esac; printf '%s\\n' \"$*\" >> $LANE13_TEST/kubectl.calls; printf '%s\\n' \"$3\" >> $LANE13_TEST/apply.paths; case $3 in *serving-crds.yaml) printf 'service/crds\\n';; *serving-core.yaml) printf 'configmap/core\\nservice/core\\n';; *kourier.yaml) printf 'deployment/kourier\\n';; *) return 9;; esac; if [ \"${MUTATE-}\" = 1 ]; then : > $LANE13_TEST/mutated; printf mutated >> \"$3\"; fi",
    )
    .replace(
        "case $3 in *://*) return 9;; esac; printf 'service/example\\n'; }",
        "}",
    )
    .replace("LANE13_TEST={0}\\n", "LANE13_TEST={0}\\nP11SCOPE_LANE_EVIDENCE_DIR=$EVIDENCE; export P11SCOPE_LANE_EVIDENCE_DIR\\n")
    .replace("mkdir -m 700 $EVIDENCE; : > $FACTS; chmod 600 $FACTS\n", "")
    .replace("\ngrep -Fq input_sha256= $FACTS", "")
    .replace("\ngrep -Fq docker_version= $FACTS", "")
    .replace(
        "[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 2 ]",
        "[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 1 ]",
    )
    .replace(
        "[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 1 ]",
        "[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 2 ]",
    )
    .replace(
        "releases/download/v1.23.0/serving-crds.yaml serving-crds.yaml",
        "releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml",
    )
    .replace(
        "grep -Fqx service/example $FACTS",
        "MUTATE=1\nset +e\nlane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml\nmutation_status=$?\nset -e\n[ \"$mutation_status\" -ne 0 ]\n[ -e $WORK/releases/serving-crds.yaml ]\nrm -f $WORK/releases/serving-crds.yaml\nMUTATE=\nrm -f $LANE13_TEST/curl.calls $LANE13_TEST/kubectl.calls $LANE13_TEST/apply.paths\nlane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml\nlane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-core.yaml serving-core.yaml\nlane13_fetch_release https://github.com/knative/net-kourier/releases/download/knative-v1.23.0/kourier.yaml kourier.yaml\nfor fact in \\\n    release_apply_serving-crds.yaml=service/crds \\\n    release_apply_serving-core.yaml=configmap/core \\\n    release_apply_serving-core.yaml=service/core \\\n    release_apply_kourier.yaml=deployment/kourier; do grep -Fqx \"$fact\" $FACTS; done\n! grep -Fqx service/crds $FACTS\n! grep -Fqx configmap/core $FACTS\n! grep -Fqx service/core $FACTS\n! grep -Fqx deployment/kourier $FACTS\nfor name in serving-crds.yaml serving-core.yaml kourier.yaml; do [ ! -e $WORK/releases/$name ] && [ ! -L $WORK/releases/$name ]; done\n[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 3 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 3 ]\n[ \"$(wc -l < $LANE13_TEST/apply.paths)\" -eq 3 ]\n! grep -Fq '://' $LANE13_TEST/apply.paths",
    )
    .replace(
        "grep -Fq 'release_effective=https://release-assets.githubusercontent.com/asset' $FACTS\n[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 1 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 2 ]\n",
        "",
    )
    .replace(
        "lane13_preflight\nmkdir $WORK",
        "lane13_preflight\n[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 1 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 1 ]\nrm -f $LANE13_TEST/curl.calls $LANE13_TEST/kubectl.calls\nmkdir $WORK",
    )
    .replace(
        "lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml\n[ ! -e $WORK/releases/serving-crds.yaml ]\nMUTATE=1",
        "MUTATE=1",
    )
    .replace(
        "[ \"$mutation_status\" -ne 0 ]\n[ -e $WORK/releases/serving-crds.yaml ]",
        "[ \"$mutation_status\" -ne 0 ]\n[ -e $LANE13_TEST/mutated ]\n[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 1 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 1 ]\n[ -e $WORK/releases/serving-crds.yaml ]",
    )
    .replace(
        "rm -f $WORK/releases/serving-crds.yaml\nMUTATE=\nrm -f $LANE13_TEST/curl.calls",
        "rm -f $WORK/releases/serving-crds.yaml\nMUTATE=\nrm -f $LANE13_TEST/mutated $LANE13_TEST/curl.calls",
    )
    .replace(
        "[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 3 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 3 ]",
        "[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 3 ]\n! grep -Fqx -- --version $LANE13_TEST/curl.calls\ncurl_args='--fail --silent --show-error --retry 0 --connect-timeout 30 --max-time 180 --max-filesize 16777216 --proto =https --proto-redir =https --location --max-redirs 1'\nassert_curl_download() { expected=\"$curl_args --output $WORK/releases/$1 --write-out %{url_effective}\\\\n%{num_redirects} $2\"; grep -Fqx -- \"$expected\" $LANE13_TEST/curl.calls; }\nassert_curl_download serving-crds.yaml https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml\nassert_curl_download serving-core.yaml https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-core.yaml\nassert_curl_download kourier.yaml https://github.com/knative/net-kourier/releases/download/knative-v1.23.0/kourier.yaml\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 3 ]",
    )
    .replace(
        " || [ \"$3\" = ubuntu:24.04 ] || return 1; if [ \"$3\" = ubuntu:24.04 ]; then ",
        " || [ \"$3\" = ubuntu:24.04 ] || [ \"$3\" = node-id ] || return 1; if [ \"$3\" = ubuntu:24.04 ]; then ",
    )
    .replace(
        "]; else printf '[{\"Id\":\"work\",\"RepoDigests\":[\"work@sha256:work\"],\"RootFS\":{\"Layers\":[\"a\",\"b\",\"c\"]}}]\\n'; fi;; pull)",
        "]; elif [ \"$3\" = node-id ]; then printf '[{\"Id\":\"node-id\",\"RepoDigests\":[\"kindest/node@sha256:node\"],\"RootFS\":{\"Layers\":[\"node-layer\"]}}]\\n'; else printf '[{\"Id\":\"work\",\"RepoDigests\":[\"work@sha256:work\"],\"RootFS\":{\"Layers\":[\"a\",\"b\",\"c\"]}}]\\n'; fi;; pull)",
    )
    .replace(
        "'create cluster') : > $LANE13_TEST/cluster.created;;",
        "'create cluster') : > $LANE13_TEST/cluster.created; chmod 600 $KUBECONFIG;;",
    )
    .replace(
        "rm -f $LANE13_TEST/curl.calls $LANE13_TEST/kubectl.calls\nmkdir $WORK",
        "rm -f $LANE13_TEST/curl.calls $LANE13_TEST/kubectl.calls\nmkdir $WORK\nobsolete_url=https://github.com/knative/net-kourier/releases/download/knative-v1.23.0/kourier.yaml\ncp $FACTS $LANE13_TEST/obsolete-facts.before\nset +e\nlane13_fetch_release \"$obsolete_url\" kourier.yaml\nobsolete_status=$?\nset -e\n[ \"$obsolete_status\" -ne 0 ]\n[ ! -e $WORK/releases/kourier.yaml ] && [ ! -L $WORK/releases/kourier.yaml ]\n[ ! -e $WORK/releases/.lane13-applied ]\ncmp -s $LANE13_TEST/obsolete-facts.before $FACTS\n[ ! -e $LANE13_TEST/curl.calls ]\n[ ! -e $LANE13_TEST/apply.paths ]",
    )
    .replace(
        "lane13_fetch_release https://github.com/knative/net-kourier/releases/download/knative-v1.23.0/kourier.yaml kourier.yaml",
        "lane13_fetch_release https://github.com/knative-extensions/net-kourier/releases/download/knative-v1.23.0/kourier.yaml kourier.yaml",
    )
    .replace(
        "assert_curl_download kourier.yaml https://github.com/knative/net-kourier/releases/download/knative-v1.23.0/kourier.yaml",
        "assert_curl_download kourier.yaml https://github.com/knative-extensions/net-kourier/releases/download/knative-v1.23.0/kourier.yaml",
    )
    .replace(
        "lane13_fetch_release https://github.com/knative-extensions/net-kourier/releases/download/knative-v1.23.0/kourier.yaml kourier.yaml\nfor fact in",
        "lane13_fetch_release https://github.com/knative-extensions/net-kourier/releases/download/knative-v1.23.0/kourier.yaml kourier.yaml\ngrep -Fqx 'release_redirects=1' $FACTS\nfor fact in",
    );
    let obsolete_concrete_url =
        "https://github.com/knative/net-kourier/releases/download/knative-v1.23.0/kourier.yaml";
    assert_eq!(
        body.matches(obsolete_concrete_url).count(),
        1,
        "generated fixture must retain exactly one obsolete-owner rejection probe"
    );
    assert_eq!(
        body.matches("lane13_fetch_release \"$obsolete_url\" kourier.yaml")
            .count(),
        1,
        "generated fixture must execute exactly one obsolete-owner probe"
    );
    assert_eq!(
        body.matches(
            "printf '%s\\n1' 'https://release-assets.githubusercontent.com/asset?secret=x'"
        )
        .count(),
        1,
        "successful fake release fetch must report one redirect"
    );
    assert!(
        body.contains("grep -Fqx 'release_redirects=1' $FACTS"),
        "generated fixture must assert one redirect for every successful release"
    );
    fs::write(&script, &body).expect("write lane-13 D1 test script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise lane-13 D1 controls");
    assert!(
        output.status.success(),
        "lane-13 D1 controls failed: stdout={} stderr={} script={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        body
    );
}

#[test]
fn lane13_preflight_and_release_reject_tool_error_redirect_and_cap_before_apply() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let preflight = between(&gate, "lane13_preflight() {", "\nlane13_image_facts() {");
    let require_curl = between(
        &gate,
        "lane13_require_curl() {",
        "\nlane13_record_inputs() {",
    );
    let fetch = between(&gate, "lane13_fetch_release() {", "\nlane13_sha256() {");
    let sha256 = between(&gate, "lane13_sha256() {", "\nterminate_port_forward() {");
    let directory = tempfile::tempdir().expect("temporary lane-13 negative fixture");
    let script = directory.path().join("negative.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={work}/work
KUBECONFIG=$WORK/kubeconfig
IMAGE=kind.local/test:unique
CLUSTER=test-unique
KNATIVE_VERSION=knative-v1.23.0
EVIDENCE={work}/evidence
FACTS=$EVIDENCE/facts.log
mkdir -p "$EVIDENCE"
: > "$FACTS"
docker() {{ case "$1 ${{2-}}" in 'image inspect') return 1;; 'image ls') return 9;; *) return 9;; esac; }}
kind() {{ case "$1 ${{2-}}" in 'get clusters') return 0;; *) return 9;; esac; }}
lane13_fact() {{ printf '%s\n' "$1" >> "$FACTS"; }}
lane13_preflight() {{{preflight}
set +e
lane13_preflight
preflight_status=$?
set -e
[ "$preflight_status" -ne 0 ]
[ ! -e "$WORK/kubeconfig" ]
mkdir -p "$WORK/releases"
curl() {{
  if [ "$1" = --version ]; then printf 'curl 8.4.0\n'; return; fi
  out=; while [ "$#" -gt 0 ]; do case "$1" in --output) out=$2; shift 2;; --write-out) shift 2;; *) shift;; esac; done
  case ${{CURL_MODE-redirect}} in
    redirect) printf release > "$out"; printf 'https://release-assets.githubusercontent.com:444/asset\n2\n' ;;
    cap) truncate -s 16777217 "$out"; printf 'https://release-assets.githubusercontent.com/asset\n0\n' ;;
    unsorted|sorted|duplicate|malformed|empty|nofinal|blank|control|nonascii|failure) printf release > "$out"; printf 'https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml\n0\n' ;;
  esac
}}
kubectl() {{
  : > {work}/kubectl.called
  case $CURL_MODE in
    unsorted) printf 'service/z\nservice/a\n' ;;
    sorted) printf 'service/a\nservice/z\n' ;;
    duplicate) printf 'service/a\nservice/a\n' ;;
    malformed) printf 'service/a\nservice/Bad\n' ;;
    empty) return 0 ;;
    nofinal) printf 'service/a' ;;
    blank) printf 'service/a\n\n' ;;
    control) printf 'service/a\nservice/b\001\n' ;;
    nonascii) printf 'service/a\nservice/\303\251\n' ;;
    failure) return 1 ;;
    *) exit 99 ;;
  esac
}}
timeout() {{ while [ "$#" -gt 0 ]; do case "$1" in --signal=*|--kill-after=*) shift;; --signal|--kill-after) shift 2;; *s) shift; break;; *) break;; esac; done; "$@"; }}
lane13_require_curl() {{{require_curl}
lane13_fetch_release() {{{fetch}
lane13_sha256() {{{sha256}
for curl_version in 8.4 8.4.0.1 8.x.0; do
    if lane13_require_curl "$curl_version"; then exit 91; fi
done
lane13_require_curl 8.4.0
rm -f {work}/kubectl.called
set +e
lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
release_status=$?
set -e
[ "$release_status" -ne 0 ]
[ ! -e {work}/kubectl.called ]
rm -f "$WORK/releases/serving-crds.yaml"
CURL_MODE=cap
rm -f {work}/kubectl.called
set +e
lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
release_status=$?
set -e
[ "$release_status" -ne 0 ]
[ ! -e {work}/kubectl.called ]
rm -f "$WORK/releases/serving-crds.yaml"
CURL_MODE=unsorted
FACTS=$EVIDENCE/unsorted.facts
: > "$FACTS"
rm -f {work}/kubectl.called
lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
[ -e {work}/kubectl.called ]
unsorted_projection=$(grep '^release_apply_serving-crds.yaml=' "$FACTS")
[ "$unsorted_projection" = "release_apply_serving-crds.yaml=service/a
release_apply_serving-crds.yaml=service/z" ]
[ "$(grep -Ec '^release_pre_sha256=.+$' "$FACTS")" -eq 1 ]
[ "$(grep -Ec '^release_post_sha256=.+$' "$FACTS")" -eq 1 ]
[ "$(sed -n 's/^release_pre_sha256=//p' "$FACTS")" = "$(sed -n 's/^release_post_sha256=//p' "$FACTS")" ]
[ "$(grep -Fxc 'release_apply_success_serving-crds.yaml=1' "$FACTS")" -eq 1 ]
[ ! -e "$WORK/releases/serving-crds.yaml" ] && [ ! -L "$WORK/releases/serving-crds.yaml" ]

CURL_MODE=sorted
FACTS=$EVIDENCE/sorted.facts
: > "$FACTS"
rm -f {work}/kubectl.called
lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
[ -e {work}/kubectl.called ]
cmp "$EVIDENCE/unsorted.facts" "$FACTS"

CURL_MODE=duplicate
FACTS=$EVIDENCE/duplicate.facts
: > "$FACTS"
rm -f {work}/kubectl.called
set +e
lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
release_status=$?
set -e
[ "$release_status" -ne 0 ]
[ -e {work}/kubectl.called ]
[ -e "$WORK/releases/serving-crds.yaml" ]
! grep -Fq 'release_apply_serving-crds.yaml=' "$FACTS"
! grep -Fq 'release_apply_success_serving-crds.yaml=' "$FACTS"
rm -f "$WORK/releases/serving-crds.yaml"

CURL_MODE=malformed
FACTS=$EVIDENCE/malformed.facts
: > "$FACTS"
rm -f {work}/kubectl.called
set +e
lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
release_status=$?
set -e
[ "$release_status" -ne 0 ]
[ -e {work}/kubectl.called ]
[ -e "$WORK/releases/serving-crds.yaml" ]
! grep -Fq 'release_apply_serving-crds.yaml=' "$FACTS"
! grep -Fq 'release_apply_success_serving-crds.yaml=' "$FACTS"
rm -f "$WORK/releases/serving-crds.yaml"
for invalid_mode in empty nofinal blank control nonascii failure; do
    CURL_MODE=$invalid_mode
    FACTS=$EVIDENCE/$invalid_mode.facts
    : > "$FACTS"
    rm -f {work}/kubectl.called
    set +e
    lane13_fetch_release https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml serving-crds.yaml
    release_status=$?
    set -e
    [ "$release_status" -ne 0 ]
    [ -e {work}/kubectl.called ]
    [ -e "$WORK/releases/serving-crds.yaml" ]
    ! grep -Fq 'release_apply_serving-crds.yaml=' "$FACTS"
    ! grep -Fq 'release_apply_success_serving-crds.yaml=' "$FACTS"
    rm -f "$WORK/releases/serving-crds.yaml"
done
"#,
            work = directory.path().display(),
            preflight = preflight,
            require_curl = require_curl,
            fetch = fetch,
            sha256 = sha256,
        ),
    )
    .expect("write lane-13 negative script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise lane-13 negative controls");
    assert!(
        output.status.success(),
        "lane-13 negative controls failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lane13_generated_bpf_requires_real_elf_and_rejects_text() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let generated = between(
        &gate,
        "lane13_record_generated_bpf()",
        "\nlane13_record_pod_identity() {",
    );
    let directory = tempfile::tempdir().expect("temporary generated-BPF directory");
    let bpf = directory
        .path()
        .join("product/release/build/p11scope-1/out/p11scope-ebpf");
    fs::create_dir_all(bpf.parent().unwrap()).expect("create generated-BPF directory");
    fs::write(&bpf, p11scope::EBPF_OBJECT).expect("write real embedded eBPF object");
    let source = directory.path().join("ebpf-source");
    fs::write(&source, p11scope::EBPF_OBJECT).expect("write eBPF source copy");
    let facts = directory.path().join("facts.log");
    let script = directory.path().join("generated-bpf.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={root}
PRODUCT=$WORK/product
FACTS=$WORK/facts.log
BPF=$PRODUCT/release/build/p11scope-1/out/p11scope-ebpf
SOURCE={source}
failure=0
lane13_fact() {{ printf '%s\n' "$1" >> "$FACTS"; }}
lane13_sha256() {{ /usr/bin/sha256sum "$1" | awk '{{ print $1 }}'; }}
lane13_record_generated_bpf(){generated}
if lane13_record_generated_bpf; then real_status=0; else real_status=$?; fi
printf 'real_status=%s\n' "$real_status"
[ "$real_status" -eq 0 ] || failure=1
[ "$real_status" -ne 0 ] || [ "$(wc -l < "$FACTS")" -eq 8 ] || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx "generated_bpf_path=$BPF" "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx "generated_bpf_size=$(stat -Lc %s "$BPF")" "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx "generated_bpf_sha256=$(/usr/bin/sha256sum "$BPF" | awk '{{ print $1 }}')" "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx generated_bpf_build_id=absent "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx generated_bpf_elf_class=ELF64 "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx generated_bpf_elf_data=LSB "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx generated_bpf_elf_type=ET_REL "$FACTS" || failure=1
[ "$real_status" -ne 0 ] || grep -Fqx generated_bpf_elf_machine=EM_BPF "$FACTS" || failure=1
: > "$FACTS"
printf 'arbitrary text\n' > "$BPF"
if lane13_record_generated_bpf; then text_status=0; else text_status=$?; fi
printf 'text_status=%s\n' "$text_status"
[ "$text_status" -ne 0 ] || failure=1
[ ! -s "$FACTS" ] || failure=1
/bin/cp "$SOURCE" "$BPF"
readelf() {{ [ "$1" = -n ] && return 42; /usr/bin/readelf "$@"; }}
: > "$FACTS"
if lane13_record_generated_bpf; then readelf_status=0; else readelf_status=$?; fi
printf 'readelf_status=%s\n' "$readelf_status"
[ "$readelf_status" -ne 0 ] || failure=1
[ ! -s "$FACTS" ] || failure=1
exit "$failure"
"#,
            root = directory.path().display(),
            source = source.display(),
            generated = generated,
        ),
    )
    .expect("write generated-BPF contract script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise generated-BPF contract");
    assert!(
        output.status.success(),
        "generated-BPF contract failed: stdout={} stderr={} facts={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(&facts).unwrap_or_else(|error| error.to_string())
    );
}

#[test]
fn lane13_generated_bpf_rejects_path_swap_at_final_identity() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let generated = between(
        &gate,
        "lane13_record_generated_bpf()",
        "\nlane13_record_pod_identity() {",
    );
    let directory = tempfile::tempdir().expect("temporary generated-BPF ABA directory");
    let bpf = directory
        .path()
        .join("product/release/build/p11scope-1/out/p11scope-ebpf");
    fs::create_dir_all(bpf.parent().unwrap()).expect("create generated-BPF ABA directory");
    fs::write(&bpf, p11scope::EBPF_OBJECT).expect("write original embedded eBPF object");
    let replacement = directory.path().join("replacement-ebpf");
    fs::write(&replacement, p11scope::EBPF_OBJECT).expect("write replacement eBPF object");
    let facts = directory.path().join("facts.log");
    let script = directory.path().join("generated-bpf-aba.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={root}
PRODUCT=$WORK/product
FACTS=$WORK/facts.log
BPF={bpf}
REPLACEMENT={replacement}
failure=0
STAT_CALLS=$WORK/stat-fd-calls
printf '0\n' > "$STAT_CALLS"
lane13_fact() {{ printf '%s\n' "$1" >> "$FACTS"; }}
lane13_sha256() {{ /usr/bin/sha256sum "$1" | awk '{{ print $1 }}'; }}
readelf() {{ [ "$1" = -n ] && printf '    Build ID: deadbeef\n' || /usr/bin/readelf "$@"; }}
stat() {{
    lane13_stat_target=
    for lane13_stat_arg do lane13_stat_target=$lane13_stat_arg; done
    if [ "$lane13_stat_target" = /proc/self/fd/9 ]; then
        lane13_stat_fd_calls=$(cat "$STAT_CALLS")
        lane13_stat_fd_calls=$((lane13_stat_fd_calls + 1))
        printf '%s\n' "$lane13_stat_fd_calls" > "$STAT_CALLS"
        if [ "$lane13_stat_fd_calls" -eq 3 ]; then
            /bin/mv -- "$BPF" "$BPF.aba-original"
            /bin/mv -- "$REPLACEMENT" "$BPF"
        fi
    fi
    exec /usr/bin/stat "$@"
}}
lane13_record_generated_bpf(){generated}
if lane13_record_generated_bpf; then
    aba_status=0
else
    aba_status=$?
fi
printf 'aba_status=%s\n' "$aba_status"
lane13_stat_fd_calls=$(cat "$STAT_CALLS")
printf 'pinned_fd_stat_calls=%s\n' "$lane13_stat_fd_calls"
[ "$aba_status" -ne 0 ] || failure=1
[ ! -s "$FACTS" ] || failure=1
[ "$lane13_stat_fd_calls" -eq 3 ] || failure=1
[ -f "$BPF.aba-original" ] || failure=1
[ -f "$BPF.aba-original" ] && /bin/mv -- "$BPF.aba-original" "$BPF"
exit "$failure"
"#,
            root = directory.path().display(),
            bpf = bpf.display(),
            replacement = replacement.display(),
            generated = generated,
        ),
    )
    .expect("write generated-BPF ABA contract script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise generated-BPF ABA contract");
    assert!(
        output.status.success(),
        "generated-BPF ABA contract failed: stdout={} stderr={} facts={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(&facts).unwrap_or_else(|error| error.to_string())
    );
}

#[test]
fn lane13_evidence_finalizes_only_after_owned_cleanup_synthetic_regression() {
    let gate = read("scripts/matrix/verify-knative.sh");
    for marker in [
        "lane13_outer() {",
        "lane13_record_facts() {",
        "lane13_preserve_diagnostics() {",
        "input_ledger_start=",
        "input_ledger_end=",
        "status",
    ] {
        assert!(gate.contains(marker), "lane-13 D2 marker missing: {marker}");
    }
    assert!(
        !gate.contains("knative scale-from-zero: ALL OK"),
        "lane-13 must use its decimal status as the only terminal authority"
    );

    let directory = tempfile::tempdir().expect("temporary lane-13 D2 directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("make lane-13 D2 parent private");
    let script = directory.path().join("d2.sh");
    let outer = between(&gate, "lane13_outer() {", "\nterminate_port_forward() {");
    let preserve = between(
        &gate,
        "lane13_preserve_diagnostics() {",
        "\nterminate_port_forward() {",
    );
    let inputs = between(
        &gate,
        "lane13_record_inputs() {",
        "\nlane13_record_facts() {",
    );
    let facts = between(
        &gate,
        "lane13_record_facts() {",
        "\nlane13_record_file_fact() {",
    );
    let compare_inputs = between(
        &gate,
        "lane13_compare_input_ledgers() {",
        "\nlane13_record_file_fact() {",
    );
    let validate = between(
        &gate,
        "lane13_validate_retained_root() {",
        "\nlane13_outer() {",
    );
    let sha256 = between(
        &gate,
        "lane13_sha256() {",
        "\nlane13_preserve_diagnostics() {",
    );
    let canonical = between(
        &gate,
        "lane13_canonical_script() {",
        "\nlane13_authorize_body() {",
    );
    let authorize_body = between(
        &gate,
        "lane13_authorize_body() {",
        "\nlane13_signal_body_group() {",
    );
    let remove_work = between(
        &gate,
        "lane13_remove_owned_work() {",
        "\nlane13_remove_owned_kubeconfig() {",
    );
    let remove_kubeconfig = between(
        &gate,
        "lane13_remove_owned_kubeconfig() {",
        "\nlane13_record_absence_fact() {",
    );
    let absence = between(
        &gate,
        "lane13_record_absence_fact() {",
        "\nlane13_validate_retained_root() {",
    );
    let cleanup = between(&gate, "cleanup() {", "\n. scripts/cleanup-traps.sh");
    let body = format!(
        r#"#!/bin/sh
set -eu
. scripts/lib.sh
EVIDENCE=
EVIDENCE_OWNED=0
LANE13_OUTER_EXIT_ARMED=0
LANE13_OUTER_PENDING_STATUS=
FACTS=
TOKEN=test-token
P11SCOPE_LANE_EVIDENCE_DIR={root}/evidence
MARKERS={root}/markers
WORK={root}/work
PRODUCT=$WORK/product
KUBECONFIG=$WORK/kubeconfig
WORK_CREATED=
KUBECONFIG_CREATED=
IMAGE_CREATED=
CLUSTER_CREATED=
IMAGE_CLEANUP_ARMED=
CLUSTER_CLEANUP_ARMED=
IMAGE_ID=
CLUSTER_NODE=
CLUSTER_NODE_ID=
PF_PID= PF_STARTTIME= PF_PGID= PF_SID= PF_GROUP_SNAPSHOT= PF_SESSION_EMPTY=1
LANE13_BODY_PID= LANE13_BODY_STARTTIME= LANE13_BODY_PGID= LANE13_BODY_SID=
LANE13_BODY_SIGNAL= LANE13_BODY_SIGNAL_STATUS=0
SPID= SUPERVISOR_PID= SUPERVISOR_STARTTIME=
ROOT_LAUNCH_PID= ROOT_PROCESS_PID= ROOT_PROCESS_STARTTIME=
CLEANUP_STATUS=0
BODY_STATUS=0
lane13_fact() {{ printf '%s\n' "$1" >> "$FACTS"; }}
lane13_record_inputs() {{{inputs}
lane13_record_facts() {{{facts}
lane13_compare_input_ledgers() {{{compare_inputs}
lane13_sha256() {{{sha256}
lane13_canonical_script() {{{canonical}
lane13_authorize_body() {{{authorize_body}
lane13_remove_owned_work() {{{remove_work}
lane13_remove_owned_kubeconfig() {{{remove_kubeconfig}
lane13_record_absence_fact() {{{absence}
cleanup_step() {{ "$@"; cleanup_step_status=$?; [ "$CLEANUP_STATUS" -ne 0 ] || [ "$cleanup_step_status" -eq 0 ] || CLEANUP_STATUS=$cleanup_step_status; return 0; }}
terminate_port_forward() {{ :; }}
snapshot_user_process_session() {{
    [ "${{LANE13_TEST_SNAPSHOT_FAIL-}}" != 1 ] || return 1
    printf '[]'
}}
launch_user_recorded_process_group() {{
    lurpg_pidfile=$1; lurpg_log=$2; shift 2
    "$@" >"$lurpg_log" 2>&1 &
    USER_PROCESS_LAUNCH_PID=$!
    USER_PROCESS_PID=$!
    USER_PROCESS_STARTTIME=$(awk '{{ sub(/^[0-9]+ \\(.*\\) /, ""); split($0, tail, " "); print tail[20]; exit }}' "/proc/$!/stat")
    USER_PROCESS_PGID=$!
    USER_PROCESS_SID=$!
    : > "$lurpg_pidfile"
}}
lane13_delete_owned_cluster() {{ : > "$MARKERS/cluster-identity-mismatch"; return 1; }}
lane13_delete_owned_image() {{ : > "$MARKERS/image-cleaned"; return 0; }}
reclaim_root_output() {{ :; }}
mkdir -p -m 700 "$MARKERS"
lane13_preserve_diagnostics() {{{preserve}
cleanup() {{{cleanup}
if [ "${{P11SCOPE_LANE13_BODY-}}" = 1 ]; then
    EVIDENCE=$P11SCOPE_LANE_EVIDENCE_DIR
    FACTS=$EVIDENCE/facts.log
    : > "$FACTS"; chmod 600 "$FACTS"
    printf '%s\n' body-stdout
    printf '%s\n' body-stderr >&2
    BODY_STATUS=0
    mkdir -m 700 "$WORK"; WORK_CREATED=1; WORK_DEV_INO=$(stat -Lc '%d:%i' "$WORK")
    lane13_record_facts
    : > "$WORK/observed.json"
    : > "$WORK/manifest-host.json"
    : > "$WORK/profile.log"
    : > "$WORK/portforward.log"
    : > "$WORK/portforward.group.before.json"
    : > "$WORK/portforward.group.after.json"
    : > "$WORK/foreign-unrelated.tmp"
    : > "$KUBECONFIG"; KUBECONFIG_CREATED=1; KUBECONFIG_DEV_INO=$(stat -Lc '%d:%i' "$KUBECONFIG")
    CLUSTER_CREATED=1; IMAGE_CREATED=1; IMAGE_CLEANUP_ARMED=1; CLUSTER_CLEANUP_ARMED=1
    cleanup
fi
lane13_validate_retained_root() {{{validate}
lane13_outer() {{{outer}
lane13_outer
"#,
        root = directory.path().display(),
        outer = outer,
        inputs = inputs,
        facts = facts,
        compare_inputs = compare_inputs,
        sha256 = sha256,
        canonical = canonical,
        authorize_body = authorize_body,
        remove_work = remove_work,
        remove_kubeconfig = remove_kubeconfig,
        absence = absence,
        validate = validate,
        preserve = preserve,
        cleanup = cleanup,
    );
    fs::write(&script, body).expect("write lane-13 D2 test script");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise lane-13 D2 transaction");
    assert_eq!(
        output.status.code(),
        Some(1),
        "identity mismatch must be nonzero: stdout={} stderr={} evidence={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_dir(directory.path().join("evidence"))
            .map(|entries| entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>())
            .map(|entries| format!("{entries:?}"))
            .unwrap_or_else(|error| error.to_string())
    );
    let evidence = directory.path().join("evidence");
    assert!(
        evidence.join("stdout.log").is_file(),
        "outer stdout missing: path={} status={} stdout={} stderr={}",
        directory.path().display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(evidence.join("stderr.log").is_file());
    assert!(
        fs::read_to_string(evidence.join("stdout.log"))
            .expect("read body stdout")
            .contains("body-stdout"),
        "captured stdout missing body output"
    );
    assert!(
        fs::read_to_string(evidence.join("stderr.log"))
            .expect("read body stderr")
            .contains("body-stderr")
    );
    assert!(evidence.join("facts.log").is_file());
    let facts = fs::read_to_string(evidence.join("facts.log")).expect("read final facts");
    assert!(facts.contains("input_ledger_start="));
    assert!(
        facts.contains("input_ledger_end="),
        "missing end ledger: stderr={} facts={}",
        String::from_utf8_lossy(&output.stderr),
        facts
    );
    assert!(facts.contains("cluster_absent=0"));
    assert!(facts.contains("workload_tag_absent=1"));
    assert!(
        facts.contains("work_absent=0"),
        "missing retained-work fact: {facts}"
    );
    assert!(!facts.contains(".lane13-inputs-"));
    assert_eq!(
        fs::read_to_string(evidence.join("status")).expect("read final status"),
        "1\n"
    );
    assert!(directory.path().join("work").is_dir());
    assert!(
        directory
            .path()
            .join("markers/cluster-identity-mismatch")
            .exists()
    );
    assert!(directory.path().join("markers/image-cleaned").exists());
    for name in [
        "observed.json",
        "manifest-host.json",
        "profile.log",
        "portforward.log",
        "portforward.group.before.json",
        "portforward.group.after.json",
    ] {
        assert!(
            evidence.join(name).is_file(),
            "missing retained artifact {name}"
        );
    }
    assert!(!evidence.join("foreign-unrelated.tmp").exists());
    for entry in fs::read_dir(&evidence).expect("read retained evidence root") {
        let entry = entry.expect("read retained evidence entry");
        let metadata = entry.metadata().expect("read retained evidence metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(
        fs::metadata(&evidence)
            .expect("read retained root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    fs::remove_dir_all(&evidence).expect("remove first synthetic evidence root");
    let snapshot_failure = Command::new("sh")
        .arg(&script)
        .env("LANE13_TEST_SNAPSHOT_FAIL", "1")
        .output()
        .expect("exercise unknown body-group state");
    assert!(!snapshot_failure.status.success());
    assert_eq!(
        fs::read_to_string(evidence.join("status")).expect("read snapshot-failure status"),
        "1\n"
    );
    assert!(
        evidence.join(".lane13-body.pid").is_file(),
        "unknown body-group state discarded its durable identity"
    );
    assert!(evidence.join(".lane13-body-launch.log").is_file());
}

#[test]
fn lane13_failed_queries_remove_their_private_projections() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let image_state = between(
        &gate,
        "lane13_image_state() {",
        "\n\nlane13_image_facts() {",
    );
    let container_absent = between(
        &gate,
        "lane13_container_absent() {",
        "\n\nlane13_delete_owned_cluster() {",
    );
    let directory = tempfile::tempdir().expect("temporary projection directory");
    let script = directory.path().join("projection.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
EVIDENCE={evidence}
docker() {{ return 1; }}
lane13_image_state() {{{image_state}
lane13_container_absent() {{{container_absent}
lane13_image_state example.invalid/test:token || :
[ ! -e "$EVIDENCE/.lane13-image-projection" ]
lane13_container_absent node identifier || :
[ ! -e "$EVIDENCE/.lane13-container-projection" ]
"#,
            evidence = directory.path().display(),
            image_state = image_state,
            container_absent = container_absent,
        ),
    )
    .expect("write projection cleanup regression");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise failed projection cleanup");
    assert!(
        output.status.success(),
        "failed query retained scratch state: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn lane13_diagnostics_refuse_a_replaced_work_directory() {
    let gate = read("scripts/matrix/verify-knative.sh");
    let preserve = between(
        &gate,
        "lane13_preserve_diagnostics() {",
        "\nterminate_port_forward() {",
    );
    let directory = tempfile::tempdir().expect("temporary diagnostic directory");
    let script = directory.path().join("diagnostics.sh");
    fs::write(
        &script,
        format!(
            r#"#!/bin/sh
set -eu
WORK={root}/work
EVIDENCE={root}/evidence
BODY_STATUS=1
mkdir "$WORK" "$EVIDENCE"
WORK_CREATED=1
WORK_DEV_INO=$(stat -Lc '%d:%i' "$WORK")
mv "$WORK" "$WORK-old"
mkdir "$WORK"
: > "$WORK/profile.log"
reclaim_root_output() {{ : > {root}/reclaimed; }}
lane13_preserve_diagnostics() {{{preserve}
set +e
lane13_preserve_diagnostics
status=$?
set -e
[ "$status" -ne 0 ]
[ ! -e {root}/reclaimed ]
[ ! -e "$EVIDENCE/profile.log" ]
"#,
            root = directory.path().display(),
            preserve = preserve,
        ),
    )
    .expect("write diagnostic identity regression");
    let output = Command::new("sh")
        .arg(&script)
        .output()
        .expect("exercise diagnostic work identity");
    assert!(
        output.status.success(),
        "diagnostics consumed a replaced work directory: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unbounded_gate_match_accepts_a_live_only_capability_fixture() {
    let deceptive = [
        "for gate in scripts/verify-inspect-doctor.sh; do",
        "    \"$gate\" --self-test",
        "done",
        "echo \"=== scripts/verify-capability-tier.sh ===\"",
        "scripts/verify-capability-tier.sh",
    ]
    .join("\n");
    assert!(deceptive.contains("scripts/verify-capability-tier.sh"));
    let self_test_loop = between(&deceptive, "for gate in ", "done");
    assert!(!self_test_loop.contains("scripts/verify-capability-tier.sh"));
}

#[test]
fn previous_gate_contract_accepts_live_loop_and_ci_substring_mutations() {
    let duplicate_live = [
        "for gate in scripts/verify-inspect-doctor.sh scripts/verify-capability-tier.sh; do",
        "    \"$gate\"",
        "done",
        "echo \"=== scripts/verify-capability-tier.sh ===\"",
        "scripts/verify-capability-tier.sh",
        "echo \"=== gates: ALL OK ===\"",
    ]
    .join("\n");
    let old_live_section = between(
        &duplicate_live,
        "    \"$gate\"\ndone\n",
        "echo \"=== gates: ALL OK ===\"",
    );
    assert_eq!(
        duplicate_live
            .lines()
            .filter(|line| *line == "scripts/verify-capability-tier.sh")
            .count(),
        1
    );
    assert_eq!(
        old_live_section
            .lines()
            .filter(|line| *line == "scripts/verify-capability-tier.sh")
            .count(),
        1
    );
    let live_loop = between(&duplicate_live, "for gate in ", "done");
    assert!(live_loop.contains("scripts/verify-capability-tier.sh"));

    let deceptive_ci = [
        "      # - run: scripts/verify-capability-tier.sh --self-test",
        "      - run: scripts/verify-capability-tier.sh --self-test-extra",
    ]
    .join("\n");
    let marker = "      - run: scripts/verify-capability-tier.sh --self-test";
    assert!(deceptive_ci.contains(marker));
    assert_eq!(
        deceptive_ci
            .lines()
            .map(str::trim)
            .filter(|line| *line == "- run: scripts/verify-capability-tier.sh --self-test")
            .count(),
        0
    );
}

#[test]
fn every_gate_script_self_tests_its_own_validator() {
    let gates = read("scripts/gates.sh");
    let ci = read(".github/workflows/ci.yml");
    let self_test_loop = between(
        &gates,
        "echo \"=== gate validator self-tests ===\"\nfor gate in ",
        "done\npython3 scripts/check-live-discovery-evidence.py --self-test",
    );
    let live_gate_loop = between(
        &gates,
        "# if the CLI cannot even read a target, nothing below is worth waiting for.\nfor gate in ",
        "done\n",
    );
    let ci_self_test_block = between(
        &ci,
        "      # Unprivileged validator self-tests:",
        "      - run: python3 scripts/check-live-discovery-evidence.py --self-test",
    );
    for script in [
        "scripts/verify-inspect-doctor.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-induced-gaps.sh",
        "scripts/verify-discover-containers.sh",
        "scripts/verify-live-discovery-preflight.sh",
        "scripts/verify-capability-tier.sh",
    ] {
        assert!(
            read(script).contains("--self-test"),
            "{script} has no nonprivileged validator self-test"
        );
        assert!(
            self_test_loop.contains(script),
            "{script} is not wired into scripts/gates.sh"
        );
        let expected_ci_line = format!("- run: {script} --self-test");
        assert!(
            ci_self_test_block
                .lines()
                .map(str::trim)
                .any(|line| line == expected_ci_line),
            "{script} --self-test is not wired into CI's unprivileged block"
        );
    }
    assert!(
        self_test_loop.contains("scripts/verify-capability-tier.sh; do")
            && self_test_loop.contains("\"$gate\" --self-test"),
        "the capability validator is not in the bounded gates.sh self-test loop"
    );
    assert!(
        !live_gate_loop.contains("scripts/verify-capability-tier.sh"),
        "the capability validator must not be added to the existing live gate loop"
    );
    let live_section = between(
        &gates,
        "    \"$gate\"\ndone\n",
        "echo \"=== gates: ALL OK ===\"",
    );
    let live_call = "scripts/verify-capability-tier.sh";
    assert_eq!(
        gates.lines().filter(|line| *line == live_call).count(),
        1,
        "the capability validator must have exactly one standalone live call"
    );
    assert_eq!(
        live_section
            .lines()
            .filter(|line| *line == live_call)
            .count(),
        1,
        "the standalone live capability call must follow the live gate loop"
    );
    let ci_capability_self_test = "- run: scripts/verify-capability-tier.sh --self-test";
    assert_eq!(
        ci_self_test_block
            .lines()
            .map(str::trim)
            .filter(|line| *line == ci_capability_self_test)
            .count(),
        1,
        "CI must have exactly one active capability self-test"
    );
    assert!(
        ci_self_test_block.contains(ci_capability_self_test),
        "CI capability self-test must remain in the unprivileged validator block"
    );
    assert!(
        live_section.contains(
            "echo \"=== scripts/verify-capability-tier.sh ===\"\nscripts/verify-capability-tier.sh"
        ),
        "the live capability-tier validator is not labelled at the root gate boundary"
    );
    assert!(
        ci.contains("python3 scripts/check-live-discovery-evidence.py --self-test"),
        "the frozen evidence validator self-test is not wired into CI"
    );
    // The hosted SoftHSM live-discovery lane is Task 9 Step 2, not this step.
    assert!(
        !ci.contains("--run "),
        "no privileged live-discovery lane may be enabled before the review checkpoint"
    );
}

#[test]
fn lane13_evidence_finalizes_only_after_owned_cleanup() {
    let gate = read("scripts/matrix/verify-knative.sh");
    require_before(
        &gate,
        "mkdir -p \"${WORK%/*}\"",
        "mkdir \"$WORK\"",
        "lane-13 creates only the fixed parent before exclusively creating its token work root",
    )
    .unwrap();
    assert_eq!(
        gate.matches("python3 scripts/check-capture-evidence.py lane13-knative-metrics")
            .count(),
        1,
        "the exact lane-13 checker must be invoked once"
    );
    for marker in [
        "P11SCOPE_LANE13_BODY",
        "P11SCOPE_LANE13_TOKEN",
        "P11SCOPE_LANE13_TOKEN is private lane state",
        "LANE13_BODY_STARTTIME",
        "LANE13_BODY_SIGNAL",
        "lane13_container_absent",
        "len(items) != len(set(items))",
        "for item in sorted(items):",
        "git diff --cached --quiet",
        "input_ledger_start=",
        "input_ledger_end=",
        "RepoDigests",
        "diff_ids",
        "dev_ino",
    ] {
        assert!(
            gate.contains(marker),
            "lane-13 Fix Round 1 marker missing: {marker}"
        );
    }
    assert!(!gate.contains("knative scale-from-zero: ALL OK"));
    assert!(!gate.contains("kill \"$launcher\""));
    let final_status_write = gate
        .rfind("printf '%s\\n' \"$lane13_outer_status\" > \"$EVIDENCE/status\"")
        .expect("outer terminal status write");
    let final_int_trap = gate
        .rfind("trap 'lane13_outer_signal 1' INT")
        .expect("final INT trap installation");
    let final_term_trap = gate
        .rfind("trap 'lane13_outer_signal 1' TERM")
        .expect("final TERM trap installation");
    let final_signal_check = gate
        .find("[ \"$LANE13_BODY_SIGNAL_STATUS\" -eq 0 ] || lane13_outer_status=1")
        .expect("final body signal-status check");
    assert!(final_int_trap < final_signal_check);
    assert!(final_term_trap < final_signal_check);
    assert!(final_signal_check < final_status_write);
    let terminal_failure = between(
        &gate,
        "lane13_outer_terminal_failure() {",
        "\nlane13_outer_signal() {",
    );
    let terminal_trap = terminal_failure
        .find("trap ':' EXIT")
        .expect("terminal failure keeps EXIT trap controlled");
    let terminal_failure_write = terminal_failure
        .find("printf '%s\\n' \"$lane13_terminal_status\" > \"$EVIDENCE/status\"")
        .expect("terminal failure status write");
    assert!(terminal_trap < terminal_failure_write);
    let retained_root_check = gate
        .rfind("if ! lane13_validate_retained_root; then lane13_outer_status=1; fi")
        .expect("retained-root validation");
    assert!(final_status_write > retained_root_check);

    let directory = tempfile::tempdir().expect("temporary lane-13 D2 directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("make lane-13 D2 parent private");
    let fake_bin = directory.path().join("bin");
    let state = directory.path().join("state");
    let provider = directory.path().join("provider");
    fs::create_dir(&fake_bin).expect("create fake command directory");
    fs::create_dir(&state).expect("create fake state directory");
    fs::create_dir(&provider).expect("create fake provider directory");
    fs::write(provider.join("libsofthsm2.so"), b"fake provider bytes\n")
        .expect("write fake provider");
    let ebpf_object = directory.path().join("p11scope-ebpf");
    fs::write(&ebpf_object, p11scope::EBPF_OBJECT).expect("write real embedded eBPF object");

    let dispatcher = r###"#!/bin/sh
name=${D2_COMMAND_NAME:-$(basename "$0")}
work=$(dirname "${KUBECONFIG:-/tmp/none}")
echo "$name $*" >> "$D2_STATE/calls"
cluster="p11scope-knative-$P11SCOPE_LANE13_TOKEN"
image="kind.local/p11scope-matrix-knative:$P11SCOPE_LANE13_TOKEN"
case "$name" in
mkdir)
    mkdir_target=
    for argument do
        case "$argument" in
            -*) ;;
            *) mkdir_target=$argument ;;
        esac
    done
    case "$D2_MODE" in
        mkdir-failure-symlink|mkdir-failure-symlink-signal)
            /bin/ln -s "$D2_STATE/foreign-symlink-target" "$mkdir_target"
            if [ "$D2_MODE" = mkdir-failure-symlink-signal ]; then
                kill -TERM "$PPID"
            fi
            exit 1 ;;
        mkdir-failure-directory|mkdir-failure-directory-signal)
            /bin/mkdir -m 700 "$mkdir_target"
            printf '%s\n' foreign-directory-sentinel-a > "$mkdir_target/sentinel-a"
            printf '%s\n' foreign-directory-sentinel-b > "$mkdir_target/sentinel-b"
            chmod 640 "$mkdir_target/sentinel-a"
            chmod 600 "$mkdir_target/sentinel-b"
            if [ "$D2_MODE" = mkdir-failure-directory-signal ]; then
                kill -TERM "$PPID"
            fi
            exit 1 ;;
    esac
    /bin/mkdir "$@"
    mkdir_status=$?
    if [ "$D2_MODE" = mkdir-signal ] && [ "$mkdir_status" -eq 0 ] && [ ! -e "$D2_STATE/mkdir-signal" ]; then
        : > "$D2_STATE/mkdir-signal"
        kill -TERM "$PPID"
    fi
    exit "$mkdir_status" ;;
git)
    echo "$*" >> "$D2_STATE/git.calls"
    if [ "$D2_MODE" = signal-after-root ] && [ "$1" = rev-parse ] && [ "$2" = --show-object-format ] && [ ! -e "$D2_STATE/signal-after-root" ]; then
        : > "$D2_STATE/signal-after-root"
        kill -TERM "${P11SCOPE_LANE13_OUTER_PID:?}"
    fi
    if [ "$1" = diff ]; then [ ! -e "$D2_STATE/mutate-head" ]; exit $?; fi
    if [ "$1" = rev-parse ] && [ "$2" = HEAD ]; then
        if [ -e "$D2_STATE/mutate-head" ]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi; exit 0
    fi
    if [ "$1" = rev-parse ] && [ "$2" = 'HEAD^{tree}' ]; then
        if [ -e "$D2_STATE/mutate-head" ]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi; exit 0
    fi
    case " $* " in
        *" --show-object-format "*) echo sha1; exit 0 ;;
        *" ls-files "*) exec /usr/bin/git "$@" ;;
        *" status --porcelain=v1 "*) [ ! -e "$D2_STATE/mutate-head" ] || echo ' M scripts/matrix/verify-knative.sh'; exit 0 ;;
        *" diff --quiet "*|*" diff --cached --quiet "*) [ ! -e "$D2_STATE/mutate-head" ]; exit $? ;;
    esac
    exit 1 ;;
cargo)
    if [ "$2" = --version ] || [ "$3" = --version ]; then echo 'cargo 1.88.0 (fake)'; exit 0; fi
    target=target; previous=
    for argument do [ "$previous" = --target-dir ] && target=$argument; previous=$argument; done
    mkdir -p "$target/release/build/p11scope-1/out" "$target/release"
    /bin/cp "$D2_EBPF_OBJECT" "$target/release/build/p11scope-1/out/p11scope-ebpf"
    cat > "$target/release/p11scope" <<'SCRIPT'
#!/bin/sh
if [ "$1" = profile ]; then
    case " $* " in *" --duration 1 "*) echo 'cannot inspect the file locator now (Permission denied)' >&2; exit 1 ;; esac
    output=; previous=
    for argument do [ "$previous" = -o ] && output=$argument; previous=$argument; done
    if [ -n "$output" ]; then
        /usr/bin/python3 - "$output" <<'PY'
import json
import pathlib
import runpy
import sys

check = runpy.run_path("scripts/check-capture-evidence.py")
evidence = check["evidence_fixture"](
    check["LEGACY_SURFACES"], sources=("manifest",), discovery_skipped=0
)
evidence["skipped"] = [{
    "name": check["DISCOVERY_SUBJECT"],
    "reason": check["SHARED_OVERLAY_UNCERTAINTY"],
}]
evidence.update(table_entries=68, slots=68, attached_probes=136)
document = check["document_fixture"](
    evidence,
    schema="pkcs11-scope/observed-profile/v2-metrics",
    mode="metrics",
    privacy="aggregate-only",
)
pairs = [( ["C_GetFunctionList"], 1)]
for line in pathlib.Path("spike/expected.txt").read_text().splitlines():
    name, calls = line.split()
    pairs.append(([name], int(calls)))
document["functions"] = check["function_items"](pairs)
pathlib.Path(sys.argv[1]).write_text(json.dumps(document), encoding="utf-8")
PY
    fi
    echo 'capture — privacy=aggregate-only'; exit 0
fi
exit 0
SCRIPT
    chmod 755 "$target/release/p11scope"
    cat > "$target/release/p11scope-discover" <<'SCRIPT'
#!/bin/sh
module=; output=; previous=
for argument do [ "$previous" = --module ] && module=$argument; [ "$previous" = -o ] && output=$argument; previous=$argument; done
printf '{"schema":"p11scope-manifest/4","module_path":"%s","objects":[{"path":"%s"}]}\n' "$module" "$module" > "$output"
SCRIPT
    chmod 755 "$target/release/p11scope-discover"
    [ "$D2_MODE" = sleep-build ] && sleep 30
    [ "$D2_MODE" = mutate-head ] && : > "$D2_STATE/mutate-head"
    exit 0 ;;
rustc) echo 'rustc 1.88.0 (fake)'; exit 0 ;;
python3)
    if [ "$1" = scripts/check-capture-evidence.py ]; then
        printf '%s\n' checker >> "$D2_STATE/checker.calls"
    fi
    if [ "$D2_MODE" = terminal-signal ] && [ "$1" = - ] \
        && [ "${2-}" = "${P11SCOPE_LANE_EVIDENCE_DIR-}" ] \
        && [ -e "$P11SCOPE_LANE_EVIDENCE_DIR/facts.log" ] \
        && [ ! -e "$D2_STATE/terminal-signal-ready" ]; then
        : > "$D2_STATE/terminal-signal-ready"
        while [ ! -e "$D2_STATE/terminal-signal-go" ]; do sleep 0.01; done
    fi
    if [ "$1" = -c ] && printf '%s\n' "$2" | grep -Fq socket.create_connection; then
        [ -e "$D2_STATE/portforward-ready" ]
        exit $?
    fi
    exec /usr/bin/python3 "$@" ;;
gcc)
    if [ "$1" = --version ]; then echo 'gcc (fake) 14.0.0'; exit 0; fi
    output=; previous=
    for argument do [ "$previous" = -o ] && output=$argument; previous=$argument; done
    : > "$output"; chmod 755 "$output"; exit 0 ;;
curl)
    if [ "$1" = --version ]; then echo 'curl 8.4.0'; exit 0; fi
    output=; previous=
    for argument do [ "$previous" = --output ] && output=$argument; previous=$argument; done
    [ -n "$output" ] || exit 0
    echo 'apiVersion: v1' > "$output"; printf '%s\n%s\n' 'https://github.com/knative/serving/releases/download/knative-v1.23.0/fake.yaml' 0; exit 0 ;;
docker)
    case " $* " in
        *" version --format "*) [ "$D2_MODE" = setup-failure ] && exit 1; echo 27.0.0; exit 0 ;;
        *" info --format "*) echo overlay2; exit 0 ;;
        *" image ls "*)
            [ "$D2_MODE" = image-query-failure ] && exit 1
            [ "$D2_MODE" = cleanup-image-query-failure ] && [ -e "$D2_STATE/image-created" ] && exit 1
            if [ -e "$D2_STATE/image-created" ] && [ ! -e "$D2_STATE/image-removed" ]; then
                printf '%s\t%s\tsha256:workload\n' \
                    kind.local/p11scope-matrix-knative "$P11SCOPE_LANE13_TOKEN"
            fi
            exit 0 ;;
        *" pull "*) exit 0 ;;
        *" build "*) : > "$D2_STATE/image-created"; echo sha256:workload; exit 0 ;;
        *" image rm "*) : > "$D2_STATE/image-cleaned"; [ "$D2_MODE" = cleanup-image-failure ] && exit 1; : > "$D2_STATE/image-removed"; exit 0 ;;
        *" container inspect "*)
            case " $* " in *" {{.Id}} "*) echo node-id ;; *" {{.Image}} "*) echo sha256:nodeimage ;; *) echo kindest/node:v1.33 ;; esac; exit 0 ;;
        *" container ls "*)
            [ "$D2_MODE" = cleanup-node-query-failure ] && [ -e "$D2_STATE/cluster-delete-called" ] && exit 1
            [ ! -e "$D2_STATE/cluster" ] || printf 'node-id\tfake-node\n'; exit 0 ;;
        *" image inspect "*)
            case " $* " in *" --format "*) case " $* " in *"$image"*) echo sha256:workload ;; *) echo sha256:nodeimage ;; esac; exit 0 ;; esac
            target=; for argument do target=$argument; done
            [ "$target" = "$image" ] && [ -e "$D2_STATE/image-removed" ] && exit 1
            if [ "$D2_MODE" = partial-image-creation ] && [ "$target" = "$image" ] \
                && [ ! -e "$D2_STATE/partial-image-failed" ]; then
                : > "$D2_STATE/partial-image-failed"; exit 1
            fi
            if [ "$D2_MODE" = cluster-replacement ] && [ "$target" = sha256:nodeimage ] \
                && [ ! -e "$D2_STATE/cluster-replacement-failed" ]; then
                : > "$D2_STATE/cluster-replacement-failed"; exit 1
            fi
            case "$target" in ubuntu:24.04) echo '[{"Id":"sha256:base","RepoDigests":["ubuntu@sha256:base"],"RootFS":{"Layers":["sha256:base"]}}]' ;; sha256:nodeimage) echo '[{"Id":"sha256:nodeimage","RepoDigests":["kindest/node@sha256:node"],"RootFS":{"Layers":["sha256:node-layer-1","sha256:node-layer-2"]}}]' ;; *) echo '[{"Id":"sha256:workload","RepoDigests":["kind.local/p11scope-matrix-knative@sha256:workload"],"RootFS":{"Layers":["sha256:base","sha256:work-layer"]}}]' ;; esac; exit 0 ;;
    esac
    exit 1 ;;
kind)
    case " $* " in
        *" version "*) echo kind-v0.25.0; exit 0 ;;
        *" get clusters "*)
            [ "$D2_MODE" = cleanup-cluster-query-failure ] && [ -e "$D2_STATE/cluster-delete-called" ] && exit 1
            [ ! -e "$D2_STATE/cluster" ] || echo "$cluster"; exit 0 ;;
        *" get nodes "*)
            if [ "$D2_MODE" = partial-cluster-creation ] \
                && [ ! -e "$D2_STATE/partial-cluster-failed" ]; then
                : > "$D2_STATE/partial-cluster-failed"; exit 1
            fi
            if [ "$D2_MODE" = cluster-replacement ]; then
                if [ -e "$D2_STATE/cluster-node-observed" ]; then echo decoy-node; else : > "$D2_STATE/cluster-node-observed"; echo fake-node; fi
                exit 0
            fi
            echo fake-node; exit 0 ;;
        *" create cluster "*) mkdir -p "$(dirname "$KUBECONFIG")"; : > "$KUBECONFIG"; chmod 600 "$KUBECONFIG"; : > "$D2_STATE/cluster"; exit 0 ;;
        *" load docker-image "*) exit 0 ;;
        *" delete cluster "*) : > "$D2_STATE/cluster-delete-called"; [ "$D2_MODE" = cleanup-cluster-failure ] || rm -f "$D2_STATE/cluster"; [ "$D2_MODE" = cleanup-cluster-failure ] && exit 1 || exit 0 ;;
    esac
    exit 1 ;;
kubectl)
    case " $* " in
        *" version --client "*) echo gitVersion: v1.33.0; exit 0 ;;
        *" get deployment "*) exit 1 ;;
        *" get pods -n knative-serving "*) echo knative-pod; exit 0 ;;
        *" get pods -n kourier-system "*) echo kourier-pod; exit 0 ;;
        *" get pods "*" --sort-by=.metadata.creationTimestamp "*) echo fake-cold-pod; exit 0 ;;
        *" get pods "*" -l "*) exit 0 ;;
        *" get ksvc "*) echo fake.example; exit 0 ;;
        *" exec "*" readlink -f "*) echo /usr/lib/softhsm/libsofthsm2.so; exit 0 ;;
        *" exec "*" tar "*) exec /usr/bin/tar -chC "$D2_PROVIDER" . ;;
        *" apply "*)
            file=; previous=
            for argument do [ "$previous" = -f ] && file=$argument; previous=$argument; done
            case "$file" in
                *serving-crds.yaml|*serving-core.yaml|*kourier.yaml) echo configmaps/fake; exit 0 ;;
                *ksvc.yaml) for name in observed.json manifest-host.json profile.log portforward.log portforward.group.before.json portforward.group.after.json; do : > "$work/$name"; done; : > "$work/foreign-unrelated.tmp"; case "$D2_MODE" in body-success|terminal-signal|cleanup-image-query-failure|cleanup-cluster-query-failure|cleanup-node-query-failure) exit 0 ;; esac; exit 1 ;;
                *) exit 0 ;;
            esac ;;
    esac
    if [ "$1" = get ] && [ "$2" = pod ]; then
        pod=$3; namespace=default; pod_query=$*; shift 3
        while [ "$#" -gt 0 ]; do [ "$1" = -n ] && namespace=$2 && shift; shift; done
        case " $pod_query " in
            *creationTimestamp*) /usr/bin/date -u -d '+1 minute' '+%Y-%m-%dT%H:%M:%SZ'; exit 0 ;;
            *containerID*) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; exit 0 ;;
        esac
        printf '{"metadata":{"namespace":"%s","name":"%s","uid":"uid-%s"},"spec":{"containers":[{"name":"anchor","image":"kind.local/fake:tag"}]},"status":{"containerStatuses":[{"name":"anchor","containerID":"containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","imageID":"sha256:runtime","ready":true,"restartCount":0}]}}\n' "$namespace" "$pod" "$pod"; exit 0
    fi
    case " $* " in
        *" config use-context "*|*" wait "*|*" patch "*|*" set env "*) exit 0 ;;
        *" port-forward "*) case "$D2_MODE" in body-success|terminal-signal|cleanup-image-query-failure|cleanup-cluster-query-failure|cleanup-node-query-failure) exec "$D2_PORT_FORWARD_HELPER" "$@" ;; *) sleep 30; exit 143 ;; esac ;;
    esac
    exit 0 ;;
sudo)
    [ "$1" = -n ] && shift
    if [ "$1" = timeout ]; then
        shift
        while [ "$#" -gt 0 ]; do case "$1" in --signal=*|--kill-after=*) shift ;; --signal|--kill-after) shift 2 ;; *s) shift; break ;; *) break ;; esac; done
        case "$1" in find) echo /sys/fs/cgroup/kubepods.slice/fake.scope; exit 0 ;; awk) echo 4242; exit 0 ;; stat) echo 0:123; exit 0 ;; esac
    fi
    case "$1" in
        stat) case " $* " in *" %s "*) /usr/bin/stat -Lc %s "$D2_PROVIDER/libsofthsm2.so" ;; *) echo 0:123 ;; esac; exit 0 ;;
        sha256sum) /usr/bin/sha256sum "$D2_PROVIDER/libsofthsm2.so"; exit 0 ;;
        readelf) echo '    Build ID: deadbeef'; exit 0 ;;
    esac
    exec "$@" ;;
timeout)
    while [ "$#" -gt 0 ]; do case "$1" in --signal=*|--kill-after=*) shift ;; --signal|--kill-after) shift 2 ;; *s) shift; break ;; *) break ;; esac; done
    exec "$@" ;;
readelf)
    case "$*" in
        *p11scope-ebpf|*/proc/*/fd/*) exec /usr/bin/readelf "$@" ;;
        *) echo '    Build ID: deadbeef'; exit 0 ;;
    esac ;;
cp) case "$D2_MODE:$*" in copy-failure:*observed.json*) exit 1 ;; esac; exec /bin/cp "$@" ;;
tar) exec /usr/bin/tar "$@" ;;
sha256sum) exec /usr/bin/sha256sum "$@" ;;
*) exec "/usr/bin/$name" "$@" ;;
esac
"###;
    let port_forward_source = directory.path().join("port-forward-helper.c");
    let port_forward_helper = fake_bin.join("kubectl");
    fs::write(
        &port_forward_source,
        r#"#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
static void on_signal(int signal_number) {
    (void)signal_number;
    _exit(0);
}
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "port-forward") == 0) {
        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);
        char ready[4096];
        snprintf(ready, sizeof(ready), "%s/portforward-ready", getenv("D2_STATE"));
        close(creat(ready, 0600));
        for (;;) pause();
    }
    char *dispatch = getenv("D2_DISPATCH_PATH");
    if (dispatch == 0) {
        return 127;
    }
    setenv("D2_COMMAND_NAME", "kubectl", 1);
    execve(dispatch, argv, environ);
    return 127;
}
"#,
    )
    .expect("write fake port-forward helper");
    let dispatch_path = fake_bin.join("dispatch");
    let helper_status = Command::new("/usr/bin/cc")
        .args(["-O0", "-o"])
        .arg(fake_bin.join("kubectl"))
        .arg(&port_forward_source)
        .status()
        .expect("compile fake port-forward helper");
    assert!(
        helper_status.success(),
        "fake port-forward helper did not compile"
    );
    fs::write(fake_bin.join("dispatch"), dispatcher).expect("write fake dispatcher");
    fs::set_permissions(fake_bin.join("dispatch"), fs::Permissions::from_mode(0o755))
        .expect("make fake dispatcher executable");
    for command in [
        "git",
        "cargo",
        "rustc",
        "gcc",
        "curl",
        "docker",
        "kind",
        "sudo",
        "timeout",
        "readelf",
        "cp",
        "tar",
        "sha256sum",
        "python3",
        "mkdir",
    ] {
        std::os::unix::fs::symlink("dispatch", fake_bin.join(command)).unwrap();
    }

    let run = |mode: &str, evidence: &std::path::Path| {
        for marker in [
            "cluster",
            "cluster-delete-called",
            "image-created",
            "image-cleaned",
            "image-removed",
            "partial-image-failed",
            "partial-cluster-failed",
            "cluster-node-observed",
            "cluster-replacement-failed",
            "mutate-head",
            "signal-after-root",
            "mkdir-signal",
            "portforward-ready",
        ] {
            let _ = fs::remove_file(state.join(marker));
        }
        let _ = fs::remove_file(state.join("checker.calls"));
        Command::new("sh")
            .args(["scripts/matrix/verify-knative.sh"])
            .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
            .env("D2_STATE", &state)
            .env("D2_PROVIDER", &provider)
            .env("D2_EBPF_OBJECT", &ebpf_object)
            .env("D2_MODE", mode)
            .env("D2_DISPATCH_PATH", &dispatch_path)
            .env("D2_PORT_FORWARD_HELPER", &port_forward_helper)
            .env("P11SCOPE_LANE_EVIDENCE_DIR", evidence)
            .output()
            .expect("run real lane-13 script")
    };

    let injected = directory.path().join("injected");
    let injection = Command::new("sh")
        .args(["scripts/matrix/verify-knative.sh", "--lane13-private-body"])
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("D2_STATE", &state)
        .env("D2_PROVIDER", &provider)
        .env("P11SCOPE_LANE_EVIDENCE_DIR", &injected)
        .env("P11SCOPE_LANE13_BODY", "1")
        .env("P11SCOPE_LANE13_TOKEN", "forged")
        .output()
        .expect("run direct private injection");
    assert_eq!(
        injection.status.code(),
        Some(2),
        "direct private entry was accepted: stdout={} stderr={}",
        String::from_utf8_lossy(&injection.stdout),
        String::from_utf8_lossy(&injection.stderr)
    );
    assert!(
        !injected.exists(),
        "direct private injection created evidence"
    );
    let public_token_evidence = directory.path().join("public-token");
    let public_token = Command::new("sh")
        .args(["scripts/matrix/verify-knative.sh"])
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("D2_STATE", &state)
        .env("D2_PROVIDER", &provider)
        .env("P11SCOPE_LANE_EVIDENCE_DIR", &public_token_evidence)
        .env("P11SCOPE_LANE13_TOKEN", "caller-controlled")
        .output()
        .expect("run public token injection");
    assert_eq!(public_token.status.code(), Some(2));
    assert!(!public_token_evidence.exists());

    let mkdir_signal_evidence = directory.path().join("mkdir-signal-evidence");
    let mkdir_signal = run("mkdir-signal", &mkdir_signal_evidence);
    assert!(
        !mkdir_signal.status.success(),
        "signal during root creation unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkdir_signal.stdout),
        String::from_utf8_lossy(&mkdir_signal.stderr)
    );
    let mkdir_signal_calls = fs::read_to_string(state.join("calls")).unwrap_or_default();
    assert!(
        !mkdir_signal_calls
            .lines()
            .any(|line| line.starts_with("cargo ")),
        "root-creation signal launched the body: {mkdir_signal_calls}"
    );
    assert!(
        !state.join("checker.calls").exists(),
        "root-creation signal launched the checker"
    );
    assert!(
        !mkdir_signal_calls.contains("target/matrix-knative/"),
        "root-creation signal created token WORK: {mkdir_signal_calls}"
    );
    if mkdir_signal_evidence.exists() {
        assert!(mkdir_signal_evidence.is_dir());
        assert_eq!(
            fs::metadata(&mkdir_signal_evidence)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let status_path = mkdir_signal_evidence.join("status");
        assert_eq!(
            fs::metadata(&status_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let status = fs::read_to_string(status_path).expect("retained root has terminal status");
        let status_line = status
            .strip_suffix('\n')
            .expect("terminal status has one newline");
        assert!(!status_line.contains('\n'));
        assert!(!status_line.is_empty() && status_line.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(status_line.parse::<u32>().unwrap(), 0);
    }

    let foreign_symlink_target = state.join("foreign-symlink-target");
    fs::create_dir(&foreign_symlink_target).expect("create foreign symlink target");
    fs::write(
        foreign_symlink_target.join("sentinel"),
        b"foreign symlink target\n",
    )
    .expect("write foreign symlink sentinel");
    fs::set_permissions(
        foreign_symlink_target.join("sentinel"),
        fs::Permissions::from_mode(0o640),
    )
    .expect("make foreign symlink sentinel private");
    fs::set_permissions(&foreign_symlink_target, fs::Permissions::from_mode(0o700))
        .expect("make foreign symlink target private");
    let foreign_symlink_target_mode = fs::metadata(&foreign_symlink_target)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let foreign_symlink_bytes = fs::read(foreign_symlink_target.join("sentinel")).unwrap();
    let foreign_symlink_mode = fs::metadata(foreign_symlink_target.join("sentinel"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let mkdir_symlink_evidence = directory.path().join("mkdir-failure-symlink-evidence");
    let mkdir_symlink = run("mkdir-failure-symlink-signal", &mkdir_symlink_evidence);
    assert!(!mkdir_symlink.status.success());
    assert!(
        fs::symlink_metadata(&mkdir_symlink_evidence)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(&mkdir_symlink_evidence).unwrap(),
        foreign_symlink_target
    );
    assert_eq!(
        fs::read(foreign_symlink_target.join("sentinel")).unwrap(),
        foreign_symlink_bytes
    );
    assert_eq!(
        fs::metadata(foreign_symlink_target.join("sentinel"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        foreign_symlink_mode
    );
    assert_eq!(
        fs::metadata(&foreign_symlink_target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        foreign_symlink_target_mode
    );
    assert!(!foreign_symlink_target.join("status").exists());
    assert!(!foreign_symlink_target.join("stdout.log").exists());
    assert!(!foreign_symlink_target.join("stderr.log").exists());
    assert!(!foreign_symlink_target.join("facts.log").exists());
    assert!(!state.join("checker.calls").exists());
    let symlink_calls = fs::read_to_string(state.join("calls")).unwrap_or_default();
    assert!(!symlink_calls.contains("cargo "));
    assert!(!symlink_calls.contains("target/matrix-knative/"));
    let symlink_entries = fs::read_dir(&foreign_symlink_target)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        symlink_entries,
        ["sentinel"]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect()
    );

    let mkdir_directory_evidence = directory.path().join("mkdir-failure-directory-evidence");
    let mkdir_directory = run("mkdir-failure-directory", &mkdir_directory_evidence);
    assert!(!mkdir_directory.status.success());
    assert_eq!(
        fs::metadata(&mkdir_directory_evidence)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for (name, contents, mode) in [
        (
            "sentinel-a",
            b"foreign-directory-sentinel-a\n".as_slice(),
            0o640,
        ),
        (
            "sentinel-b",
            b"foreign-directory-sentinel-b\n".as_slice(),
            0o600,
        ),
    ] {
        let path = mkdir_directory_evidence.join(name);
        assert_eq!(fs::read(&path).unwrap(), contents);
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            mode
        );
    }
    assert!(!mkdir_directory_evidence.join("status").exists());
    assert!(!mkdir_directory_evidence.join("stdout.log").exists());
    assert!(!mkdir_directory_evidence.join("stderr.log").exists());
    assert!(!mkdir_directory_evidence.join("facts.log").exists());
    assert!(!state.join("checker.calls").exists());
    let directory_calls = fs::read_to_string(state.join("calls")).unwrap_or_default();
    assert!(!directory_calls.contains("cargo "));
    assert!(!directory_calls.contains("target/matrix-knative/"));
    let directory_entries = fs::read_dir(&mkdir_directory_evidence)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        directory_entries,
        ["sentinel-a", "sentinel-b"]
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect()
    );

    let success_evidence = directory.path().join("success-evidence");
    let success = run("body-success", &success_evidence);
    assert!(
        success.status.success(),
        "full body-success dispatch failed: stdout={} stderr={}",
        String::from_utf8_lossy(&success.stdout),
        format_args!(
            "{} evidence-status={} facts-summary={} evidence-stderr={} calls={}",
            String::from_utf8_lossy(&success.stderr),
            fs::read_to_string(success_evidence.join("status")).unwrap_or_default(),
            fs::read_to_string(success_evidence.join("facts.log"))
                .unwrap_or_default()
                .lines()
                .filter(|line| line.contains("status") || line.contains("absent"))
                .collect::<Vec<_>>()
                .join("|"),
            fs::read_to_string(success_evidence.join("stderr.log")).unwrap_or_default(),
            fs::read_to_string(state.join("calls")).unwrap_or_default()
        )
    );
    assert_eq!(
        fs::read_to_string(success_evidence.join("status")).unwrap(),
        "0\n"
    );
    let success_facts = fs::read_to_string(success_evidence.join("facts.log")).unwrap();
    let success_work = success_facts
        .lines()
        .find_map(|line| line.strip_prefix("work="))
        .expect("success recorded work path");
    let expected_generated_sha = run_ok("/usr/bin/sha256sum", &[ebpf_object.to_str().unwrap()])
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let expected_generated_facts = [
        format!(
            "generated_bpf_path={success_work}/product/release/build/p11scope-1/out/p11scope-ebpf"
        ),
        format!("generated_bpf_size={}", p11scope::EBPF_OBJECT.len()),
        format!("generated_bpf_sha256={expected_generated_sha}"),
        "generated_bpf_build_id=absent".to_owned(),
        "generated_bpf_elf_class=ELF64".to_owned(),
        "generated_bpf_elf_data=LSB".to_owned(),
        "generated_bpf_elf_type=ET_REL".to_owned(),
        "generated_bpf_elf_machine=EM_BPF".to_owned(),
    ];
    assert_eq!(
        success_facts
            .lines()
            .filter(|line| line.starts_with("generated_bpf_"))
            .count(),
        expected_generated_facts.len(),
        "generated-BPF receipt must contain exactly eight facts"
    );
    for expected in expected_generated_facts {
        assert_eq!(
            success_facts
                .lines()
                .filter(|line| *line == expected)
                .count(),
            1,
            "generated-BPF receipt fact missing or duplicated: {expected}"
        );
    }
    assert!(!std::path::Path::new(success_work).exists());
    assert!(success_facts.contains("cluster_absent=1"));
    assert!(success_facts.contains("workload_tag_absent=1"));
    assert!(success_facts.contains("kubeconfig_absent=1"));
    assert!(success_facts.contains("work_absent=1"));
    let success_entries = fs::read_dir(&success_evidence)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<std::collections::HashSet<_>>();
    let allowed_entries = [
        "stdout.log",
        "stderr.log",
        "facts.log",
        "status",
        "observed.json",
        "manifest-host.json",
        "profile.log",
        "portforward.log",
        "portforward.group.before.json",
        "portforward.group.after.json",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<std::collections::HashSet<_>>();
    assert_eq!(success_entries, allowed_entries);
    assert_eq!(
        fs::read_to_string(state.join("checker.calls"))
            .unwrap()
            .lines()
            .count(),
        1,
        "exact checker must run once"
    );

    let early_signal_evidence = directory.path().join("early-signal-evidence");
    let early_signal = run("signal-after-root", &early_signal_evidence);
    assert!(
        !early_signal.status.success(),
        "post-root signal unexpectedly passed: stdout={} stderr={}",
        String::from_utf8_lossy(&early_signal.stdout),
        String::from_utf8_lossy(&early_signal.stderr)
    );
    assert_eq!(
        fs::read_to_string(early_signal_evidence.join("status")).unwrap(),
        "1\n"
    );
    let early_facts_path = early_signal_evidence.join("facts.log");
    let early_deadline = Instant::now() + Duration::from_secs(5);
    let mut early_signal_work = None;
    while Instant::now() < early_deadline {
        if let Ok(facts) = fs::read_to_string(&early_facts_path) {
            if let Some(work) = facts.lines().find_map(|line| line.strip_prefix("work=")) {
                if !std::path::Path::new(work).exists() {
                    early_signal_work = Some(work.to_owned());
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        early_signal_work.is_some(),
        "post-root signal did not record and remove WORK"
    );

    let terminal_signal_evidence = directory.path().join("terminal-signal-evidence");
    for marker in ["terminal-signal-ready", "terminal-signal-go"] {
        let _ = fs::remove_file(state.join(marker));
    }
    let mut terminal_signal = Command::new("sh")
        .args(["scripts/matrix/verify-knative.sh"])
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("D2_STATE", &state)
        .env("D2_PROVIDER", &provider)
        .env("D2_MODE", "terminal-signal")
        .env("D2_DISPATCH_PATH", &dispatch_path)
        .env("D2_PORT_FORWARD_HELPER", &port_forward_helper)
        .env("P11SCOPE_LANE_EVIDENCE_DIR", &terminal_signal_evidence)
        .spawn()
        .expect("start terminal-finalization signal scenario");
    let terminal_deadline = Instant::now() + Duration::from_secs(5);
    while !state.join("terminal-signal-ready").exists()
        && Instant::now() < terminal_deadline
        && terminal_signal.try_wait().unwrap().is_none()
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        state.join("terminal-signal-ready").exists(),
        "terminal signal boundary was not reached"
    );
    let terminal_pid = terminal_signal.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &terminal_pid]).status();
    fs::write(state.join("terminal-signal-go"), b"go\n").unwrap();
    let terminal_status = terminal_signal
        .wait()
        .expect("wait terminal signal scenario");
    assert!(!terminal_status.success());
    assert_eq!(
        fs::read_to_string(terminal_signal_evidence.join("status")).unwrap(),
        "1\n"
    );
    assert!(
        terminal_signal_evidence.join("facts.log").is_file(),
        "terminal evidence entries: {:?}",
        fs::read_dir(&terminal_signal_evidence).map(|entries| entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>())
    );
    let terminal_facts = fs::read_to_string(terminal_signal_evidence.join("facts.log")).unwrap();
    if let Some(terminal_work) = terminal_facts
        .lines()
        .find_map(|line| line.strip_prefix("work="))
    {
        assert!(!std::path::Path::new(terminal_work).exists());
    }

    for (mode, absence_fact) in [
        ("cleanup-image-query-failure", "workload_tag_absent=0"),
        ("cleanup-cluster-query-failure", "cluster_absent=0"),
        ("cleanup-node-query-failure", "cluster_absent=0"),
    ] {
        let evidence = directory.path().join(mode);
        let output = run(mode, &evidence);
        assert!(
            !output.status.success(),
            "{mode} unexpectedly passed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(evidence.join("status")).unwrap(), "1\n");
        let facts = fs::read_to_string(evidence.join("facts.log")).unwrap();
        assert!(
            facts.contains(absence_fact),
            "missing {absence_fact}: {facts}"
        );
        assert!(!facts.contains(&absence_fact.replace("=0", "=1")));
    }

    for (mode, cleanup_marker, absence_fact) in [
        (
            "partial-image-creation",
            "image-cleaned",
            "workload_tag_absent=1",
        ),
        (
            "partial-cluster-creation",
            "cluster-delete-called",
            "cluster_absent=1",
        ),
    ] {
        let evidence = directory.path().join(mode);
        let output = run(mode, &evidence);
        assert!(!output.status.success(), "{mode} unexpectedly passed");
        assert!(
            state.join(cleanup_marker).is_file(),
            "{mode} skipped cleanup: stdout={} stderr={} calls={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(state.join("calls")).unwrap_or_default()
        );
        let facts = fs::read_to_string(evidence.join("facts.log")).unwrap();
        assert!(
            facts.contains(absence_fact),
            "missing {absence_fact}: {facts}"
        );
        let work = facts
            .lines()
            .find_map(|line| line.strip_prefix("work="))
            .expect("partial creation recorded work path");
        assert!(!std::path::Path::new(work).exists());
    }

    let replacement_evidence = directory.path().join("cluster-replacement");
    let replacement = run("cluster-replacement", &replacement_evidence);
    assert!(!replacement.status.success());
    assert!(!state.join("cluster-delete-called").exists());
    let replacement_facts = fs::read_to_string(replacement_evidence.join("facts.log")).unwrap();
    assert!(replacement_facts.contains("cluster_absent=0"));
    assert!(replacement_facts.contains("work_absent=0"));
    let replacement_work = replacement_facts
        .lines()
        .find_map(|line| line.strip_prefix("work="))
        .expect("replacement recorded work path");
    assert!(std::path::Path::new(replacement_work).is_dir());

    let failure_evidence = directory.path().join("failure-evidence");
    let failure = run("cleanup-cluster-failure", &failure_evidence);
    assert!(
        !failure.status.success(),
        "body/cleanup failure unexpectedly passed"
    );
    assert!(failure_evidence.join("stdout.log").is_file());
    assert!(failure_evidence.join("stderr.log").is_file());
    assert!(
        fs::read_to_string(failure_evidence.join("stdout.log"))
            .unwrap()
            .contains("build product"),
        "failure stdout={} stderr={} outer stdout={} outer stderr={} git={}",
        fs::read_to_string(failure_evidence.join("stdout.log")).unwrap(),
        fs::read_to_string(failure_evidence.join("stderr.log")).unwrap(),
        String::from_utf8_lossy(&failure.stdout),
        String::from_utf8_lossy(&failure.stderr),
        fs::read_to_string(state.join("git.calls")).unwrap_or_default()
    );
    let facts = fs::read_to_string(failure_evidence.join("facts.log")).expect("read final facts");
    let work = facts
        .lines()
        .find_map(|line| line.strip_prefix("work="))
        .expect("recorded work path");
    assert!(std::path::Path::new(work).is_dir());
    for marker in [
        "input_ledger_start=",
        "input_ledger_end=",
        "image_cluster_node_repo_digests=",
        "image_cluster_node_diff_ids=",
        "copied_provider_size=",
        "manifest_selected_provider_sha256=",
        "capture_provider_build_id=deadbeef",
        "cluster_absent=0",
        "workload_tag_absent=1",
        "kubeconfig_absent=1",
        "work_absent=0",
        "cleanup_status=",
    ] {
        assert!(
            facts.contains(marker),
            "missing lane-13 fact {marker}: stdout={} stderr={} facts={} calls={}",
            String::from_utf8_lossy(&failure.stdout),
            String::from_utf8_lossy(&failure.stderr),
            facts,
            fs::read_to_string(state.join("calls")).unwrap_or_default()
        );
    }
    assert_eq!(
        fs::read_to_string(failure_evidence.join("status")).unwrap(),
        "1\n"
    );
    assert!(state.join("cluster-delete-called").exists());
    assert!(
        state.join("cluster").exists(),
        "foreign cluster refusal was not preserved"
    );
    assert!(
        state.join("image-cleaned").exists(),
        "cleanup did not continue after cluster refusal"
    );
    for name in [
        "observed.json",
        "manifest-host.json",
        "profile.log",
        "portforward.log",
        "portforward.group.before.json",
        "portforward.group.after.json",
    ] {
        assert!(
            failure_evidence.join(name).is_file(),
            "missing retained artifact {name}"
        );
    }
    assert!(!failure_evidence.join("foreign-unrelated.tmp").exists());
    assert_eq!(
        fs::metadata(&failure_evidence)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for entry in fs::read_dir(&failure_evidence).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let copy_evidence = directory.path().join("copy-evidence");
    let copy = run("copy-failure", &copy_evidence);
    assert!(!copy.status.success());
    assert_eq!(
        fs::read_to_string(copy_evidence.join("status")).unwrap(),
        "1\n"
    );
    assert!(
        state.join("image-cleaned").exists(),
        "cleanup stopped after copy failure"
    );

    let setup_evidence = directory.path().join("setup-evidence");
    let setup = run("setup-failure", &setup_evidence);
    assert!(!setup.status.success());
    assert_eq!(
        fs::read_to_string(setup_evidence.join("status")).unwrap(),
        "1\n"
    );

    let image_query_evidence = directory.path().join("image-query-evidence");
    let image_query = run("image-query-failure", &image_query_evidence);
    assert!(!image_query.status.success());
    assert_eq!(
        fs::read_to_string(image_query_evidence.join("status")).unwrap(),
        "1\n"
    );

    let mutate_evidence = directory.path().join("mutate-evidence");
    let mutate = run("mutate-head", &mutate_evidence);
    assert!(!mutate.status.success());
    let mutate_facts = fs::read_to_string(mutate_evidence.join("facts.log")).unwrap();
    for marker in [
        "git_head_start=",
        "git_head_end=",
        "git_tree_start=",
        "git_tree_end=",
        "git_status_end=",
        "input_ledger_start=",
        "input_ledger_end=",
    ] {
        assert!(
            mutate_facts.contains(marker),
            "missing mutation fact {marker}"
        );
    }

    let signal_evidence = directory.path().join("signal-evidence");
    let mut child = Command::new("sh")
        .args(["scripts/matrix/verify-knative.sh"])
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("D2_STATE", &state)
        .env("D2_PROVIDER", &provider)
        .env("D2_MODE", "sleep-build")
        .env("P11SCOPE_LANE_EVIDENCE_DIR", &signal_evidence)
        .spawn()
        .expect("start signal scenario");
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < ready_deadline {
        if fs::read_to_string(signal_evidence.join("facts.log"))
            .is_ok_and(|facts| facts.lines().any(|line| line.starts_with("work=")))
        {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "signal body exited before WORK"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        fs::read_to_string(signal_evidence.join("facts.log"))
            .is_ok_and(|facts| facts.lines().any(|line| line.starts_with("work="))),
        "signal body did not reach WORK"
    );
    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    if child.try_wait().unwrap().is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("outer-only signal orphaned the mutating body");
    }
    assert!(
        signal_evidence.join("status").is_file(),
        "signal path did not finalize status"
    );
    let signal_facts = fs::read_to_string(signal_evidence.join("facts.log")).unwrap();
    let signal_work = signal_facts
        .lines()
        .find_map(|line| line.strip_prefix("work="))
        .expect("signal recorded work path");
    assert!(!std::path::Path::new(signal_work).exists());
}

#[test]
fn escalated_signal_wiring_is_reap_only_and_bounded() {
    let run = read("src/run.rs");
    let forbidden_actions = [
        "kill_and_reap_tail",
        "forward_signal",
        "ensure_active_generation",
        "signal_group",
        "terminate_and_reap",
        "terminate_with_grace",
    ];
    let escalated = between(
        &run,
        "Ok(ForwardAction::Escalated) => {",
        "Ok(ForwardAction::Forwarded)",
    );
    assert_eq!(
        escalated.matches(".reap_after_escalation()").count(),
        1,
        "the escalated branch must settle its child with reap_after_escalation",
    );
    for forbidden in forbidden_actions {
        assert!(
            !escalated.contains(forbidden),
            "escalated branch contains forbidden action {forbidden:?}",
        );
    }

    let reap = between(
        &run,
        "fn reap_after_escalation(&mut self) -> io::Result<i32> {",
        "\n    pub(crate) fn still_running",
    );
    assert_eq!(
        reap.matches("self.wait_for(Some(Duration::from_secs(5)), false)?")
            .count(),
        1,
        "reap_after_escalation must use one bounded existing wait_for",
    );
    for forbidden in forbidden_actions {
        assert!(
            !reap.contains(forbidden),
            "reap_after_escalation contains forbidden action {forbidden:?}",
        );
    }
}
