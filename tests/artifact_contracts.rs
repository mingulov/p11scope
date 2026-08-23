use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

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
        || engine.matches("Session::start(").count() != 1
        || engine
            .matches("Session::start(plan, scope, pinned, policy, pause_generation.take())")
            .count()
            != 1
        || engine
            .matches("self.start_session_with(policy, None)")
            .count()
            != 1
        || engine
            .matches("Some(OwnedPauseGeneration::from_owned_child(child))")
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
    if main.contains("events::Drain::new(&mut session.ebpf)")
        || main.matches("session.event_drain()?").count() != 2
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
            "Some(OwnedPauseGeneration::from_owned_child(child))",
            "sole present-capability construction",
        ),
        (
            pause,
            ".apply_discovery_batch(self.session, records, std::mem::take(&mut self.malformed))",
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
            .matches("Some(OwnedPauseGeneration::from_owned_child(child))")
            .count()
            != 1
    {
        return Err("Task 7 machinery must remain internal and owned-child-only".into());
    }
    require_before(
        pause,
        "let before_ns = io.now_ns()?;",
        "let item = io.dequeue()?;",
        "clock before each discovery dequeue",
    )?;
    require_before(
        pause,
        "let item = io.dequeue()?;",
        "let after_ns = io.now_ns()?;",
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
if signal_verified_process TERM "$pinned_pid" "$((pinned_start + 1))" 2>/dev/null; then
    exit 1
fi
kill -0 "$pinned_pid"
signal_verified_process STOP "$pinned_pid" "$pinned_start"
attempt=0
while [ "$attempt" -lt 100 ]; do
    state=$(awk '$1 == "State:" { print $2; exit }' "/proc/$pinned_pid/status")
    [ "$state" = T ] && break
    attempt=$((attempt + 1))
    sleep 0.01
done
[ "$state" = T ]
signal_verified_process CONT "$pinned_pid" "$pinned_start"
signal_verified_process TERM "$pinned_pid" "$pinned_start"
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

    assert_live_discovery_host_contract(&attach, &scope, &events, &hooks, &engine, &main).unwrap();
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
        assert_live_discovery_host_contract(&public_ebpf, &scope, &events, &hooks, &engine, &main,)
            .is_err(),
        "a mutable Ebpf must not escape to the binary or external callers"
    );
    let fabricated = attach.replacen("    tgid: u32,", "    pub tgid: u32,", 1);
    assert!(
        assert_live_discovery_host_contract(&fabricated, &scope, &events, &hooks, &engine, &main,)
            .is_err(),
        "the owned capability fields must remain opaque"
    );
    let armed_engine = engine.replacen(
        "self.start_session_with(policy, None)",
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
            "Slice 1b-2 live acquisition remains future work",
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
                "Loader/export hooks and `run` remain Slice 1b-2 and are not present here"
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
