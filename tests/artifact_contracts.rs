use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    let declarations = contract_section(
        attach,
        "const BASE_POLICY_MAPS:",
        "const FEATURE_POLICY_MAPS:",
    )?;
    let compact: String = declarations
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .replace(",)", ")");
    for expected in [
        "(\"CONFIG\",map_metadata(MapType::Array,4,8,2,BPF_F_RDONLY_PROG))",
        "(\"PID_FILTER\",map_metadata(MapType::Hash,4,8,1_024,BPF_F_RDONLY_PROG))",
        "(\"CGROUP_FILTER\",map_metadata(MapType::CgroupArray,4,4,1,0))",
        "(\"DESCRIPTORS\",map_metadata(MapType::Array,4,18,MAX_DESCRIPTORS,BPF_F_RDONLY_PROG))",
        "(\"ASYNC_FUNCTIONS\",map_metadata(MapType::Hash,32,4,128,BPF_F_RDONLY_PROG))",
        "(\"MECH_SHAPE\",map_metadata(MapType::Hash,8,4,p11scope_ebpf_common::MAX_MECH_SHAPES,BPF_F_RDONLY_PROG))",
        "(\"TAIL_CALLS\",map_metadata(MapType::ProgramArray,4,4,2,0))",
    ] {
        if !compact.contains(expected) {
            return Err(format!("exact policy-map metadata missing {expected}"));
        }
    }

    let features = contract_section(
        attach,
        "const FEATURE_POLICY_MAPS:",
        "const TAIL_POLICY_MAP:",
    )?;
    require_contract_marker(
        attach,
        "const FEATURE_POLICY_MAPS: [(&str, ExactMapMetadata); 1]",
        "single feature policy map",
    )?;
    let compact_features: String = features
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .replace(",)", ")");
    if compact_features
        .matches("(\"ATTR_BOOL_BITS\",map_metadata(MapType::Hash,4,4,16,BPF_F_RDONLY_PROG))")
        .count()
        != 1
        || compact_features.contains("TAIL_CALLS")
    {
        return Err("FEATURE_POLICY_MAPS must contain only ATTR_BOOL_BITS".into());
    }
    require_contract_marker(
        attach,
        "const TAIL_POLICY_MAP: &str = \"TAIL_CALLS\";",
        "TAIL_CALLS policy-map alias",
    )?;
    let freeze = contract_section(
        attach,
        "fn freeze_published_maps(",
        "fn validate_runtime_map(",
    )?;
    require_contract_marker(
        freeze,
        "if defers_freeze_until_loaded(name, &meta)",
        "deferred freeze for read-only arrays and TAIL_CALLS",
    )?;
    // The rule itself, not the two names it happened to cover: freezing a
    // multi-entry BPF_F_RDONLY_PROG array before its readers load makes
    // BPF_PROG_LOAD fail with the kernel's internal ENOTSUPP.
    let defers = contract_section(
        attach,
        "fn defers_freeze_until_loaded(",
        "fn freeze_published_maps(",
    )?;
    for marker in [
        "name == TAIL_POLICY_MAP",
        "matches!(meta.map_type, MapType::Array)",
        "meta.flags & BPF_F_RDONLY_PROG != 0",
        "meta.max_entries != 1",
    ] {
        require_contract_marker(defers, marker, "deferred-freeze rule")?;
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
        "if !defers_freeze_until_loaded(name, &meta) || name == TAIL_POLICY_MAP",
        "all program loads before the deferred freezes",
    )?;
    require_before(
        attach,
        "publish_and_freeze_tail_calls(&mut ebpf, unsafe_enabled)",
        ".attach(\"task\", \"task_newtask\")",
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
            "let id = dir\n        .metadata()",
            "retained cgroup inode identity",
        ),
        (
            "publish_cgroup_fd_with(dir, |directory|",
            "retained cgroup descriptor publication seam",
        ),
        ("groups.set(0, directory, 0)?", "cgroup insertion proof"),
    ] {
        require_contract_marker(scope, marker, contract)?;
    }

    if main.contains("Session::start(")
        || run.contains("Session::start(")
        || engine.matches("Session::start(").count() != 1
        || engine
            .matches("Session::start(\n                    plan,\n                    scope,\n                    pinned,\n                    policy,\n                    pause_generation.take(),\n                    owned_child,\n                )")
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
            "publish_and_freeze_tail_calls(&mut ebpf, unsafe_enabled)",
            "safe-policy handling in the unsafe object",
        ),
        (
            "\"interface_list_worker\"",
            "interface-list worker program inventory",
        ),
    ] {
        require_contract_marker(attach, marker, contract)?;
    }
    let scheduling = contract_section(
        attach,
        "fn attach_targets_with(",
        "fn standard_async_catalog",
    )?;
    if scheduling.contains("interface_list_worker") {
        return Err("interface-list worker must be loaded but never attached".into());
    }
    let start_inner =
        contract_section(attach, "fn start_inner(", "pub(crate) fn counter_snapshot(")?;
    let dynamic_loader = contract_section(
        attach,
        "pub(crate) fn attach_dynamic_loader(",
        "pub(crate) fn attach_dynamic_export(",
    )?;
    let dynamic_export = contract_section(
        attach,
        "pub(crate) fn attach_dynamic_export(",
        "pub(crate) fn has_dynamic_export(",
    )?;
    let static_targets = contract_section(
        attach,
        "pub(crate) fn attach_targets(",
        "pub fn replace_targets(",
    )?;
    for attach_site in [start_inner, dynamic_loader, dynamic_export, static_targets] {
        if attach_site.contains("interface_list_worker") && attach_site.contains(".attach") {
            return Err("interface-list worker must never be attached".into());
        }
    }
    let tail_publication = contract_section(
        attach,
        "fn publish_and_freeze_tail_calls(",
        "/// A kernel/environment",
    )?;
    for marker in [
        ".program(\"interface_list_worker\")",
        "tails.set(TAIL_CALLS_INTERFACE_WORKER_SLOT",
        "program_array_id(TAIL_POLICY_MAP, map, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "program_array_id(TAIL_POLICY_MAP, map, TAIL_CALLS_TEMPLATE_SECOND_SLOT)",
        "tails.set(TAIL_CALLS_TEMPLATE_SECOND_SLOT, second_fd, 0)?;",
        "if actual_worker != Some(worker_id)",
        "if actual_second != expected_second",
        "freeze_map(TAIL_POLICY_MAP, map)",
    ] {
        require_contract_marker(tail_publication, marker, "TAIL_CALLS publication")?;
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
        (
            "p11_entry_impl::<0, ENTRY_ABI_MIXED>(ctx)",
            "default mixed-ABI p11_entry descriptor consumer",
        ),
        (
            "p11_entry_impl::<0, ENTRY_ABI_LP64>(ctx)",
            "diagnostic p11_entry LP64 descriptor consumer",
        ),
        (
            "p11_entry_impl::<0, ENTRY_ABI_ILP32>(ctx)",
            "diagnostic p11_entry_ia32 descriptor consumer",
        ),
        (
            "p11_entry_impl::<1, ENTRY_ABI_MIXED>(ctx)",
            "p11_entry_template descriptor consumer",
        ),
        (
            "p11_entry_impl::<2, ENTRY_ABI_MIXED>(ctx)",
            "p11_entry_template_types descriptor consumer",
        ),
        (
            "p11_entry_impl::<3, ENTRY_ABI_MIXED>(ctx)",
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
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8>(ctx: ProbeContext) -> u32 {",
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
        "#[unsafe(no_mangle)]\n#[inline(never)]\npub extern \"C\" fn p11_link_fork_allowed",
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

#[test]
fn ordinary_entry_width_specialization_refuses_before_observation() {
    let ebpf = read("crates/ebpf/src/main.rs");
    let entry = between(
        &ebpf,
        "fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8>",
        "#[uretprobe]\npub fn p11_return",
    );
    let classify = entry
        .find("let Some(actual_layout) = probe_layout(&ctx)")
        .unwrap();
    let lp64 = entry.find("ENTRY_ABI == ENTRY_ABI_LP64").unwrap();
    let ilp32 = entry.find("ENTRY_ABI == ENTRY_ABI_ILP32").unwrap();
    let entered = entry.find("STATS.get_ptr_mut(slot)").unwrap();
    let aggregate = entry.find("FLAG_POLICY_AGGREGATE").unwrap();
    assert!(classify < lp64 && lp64 < ilp32 && ilp32 < entered && entered < aggregate);
    assert_eq!(entry[..entered].matches("START.remove(&key)").count(), 3);
    assert_eq!(
        entry[..entered]
            .matches("bump_evidence(EVIDENCE_ABI_REFUSALS)")
            .count(),
        3
    );
    assert!(entry.contains("let layout = if ENTRY_ABI == ENTRY_ABI_LP64"));
    assert!(entry.contains("LinuxLayout::Lp64"));
    assert!(entry.contains("LinuxLayout::Ilp32"));

    let attach = read("src/attach.rs");
    let scheduling = between(
        &attach,
        "fn attach_targets_with(",
        "fn standard_async_catalog",
    );
    assert!(
        scheduling.find("collect::<Result<Vec<_>>>()?").unwrap()
            < scheduling.find("attach(\"p11_return\", slot)").unwrap()
    );
    assert!(scheduling.contains("entry_program(&slot.semantics, policy, object_has_unsafe, *abi)"));
    let production = between(
        &attach,
        "pub(crate) fn attach_targets(",
        "pub fn replace_targets",
    );
    assert!(production.contains("attach_path_for(slot.object)"));
    assert!(production.contains("abi_for(slot.object)"));
    assert!(
        production.find("collect::<Result<_>>()?").unwrap()
            < production.find("attach_targets_with(").unwrap()
    );
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
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");
    let output = run_ok(
        "python3",
        &[
            "-I",
            "scripts/check-bpf-map-defs.py",
            "--json",
            object.to_str().unwrap(),
        ],
    );
    let inventory: serde_json::Value =
        serde_json::from_str(&output).expect("actual map inventory JSON");
    inventory["maps"]
        .as_object()
        .expect("map definitions object")
        .iter()
        .map(|(name, fields)| {
            let definition = [
                "type",
                "key_size",
                "value_size",
                "max_entries",
                "flags",
                "id",
                "pinning",
            ]
            .map(|field| {
                fields[field]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .unwrap_or_else(|| panic!("invalid map field {name}.{field}"))
            });
            (name.clone(), definition)
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
    assert!(release.contains("OFFICIAL_TARGET=\"$WORK/release-official\""));
    let official = between(
        &release,
        "=== p11scope: isolated safe-only official static build ===",
        "=== p11scope-discover: dynamic glibc + dynamic musl builds ===",
    );
    // The rustup shim dispatches on argv[0], so its resolved non-symlink path
    // is not invocable as cargo and `+1.88` cannot survive path pinning. The
    // official build runs the recorded toolchain binaries directly, offline.
    let command = [
        "CARGO_TARGET_DIR=\"$OFFICIAL_TARGET\" \\",
        "RUSTFLAGS=\"-C target-feature=+crt-static\" \\",
        "RUSTC=\"$T4_TOOLCHAIN_RUSTC\" \\",
        "    \"$T4_TOOLCHAIN_CARGO\" build --locked --offline --release --no-default-features \\",
        "        --target x86_64-unknown-linux-musl --bin p11scope",
    ]
    .join("\n");
    assert!(official.contains(&command));
    assert!(
        !official.contains("cargo +1.88"),
        "official build resolves cargo through the argv[0]-dispatching shim"
    );
    for marker in [
        "--policy-inventory \"$OFFICIAL_BPF\" \"$DIAGNOSTIC_BPF\"",
        "--unsafe-unvalidated-metadata requires a build with",
    ] {
        assert!(official.contains(marker), "official build misses {marker}");
    }
}

#[test]
fn task4_receipt_lane14_release_work_is_private_and_single_owner() {
    let release = read("scripts/build-release.sh");
    let canaries = read("scripts/verify-canaries.sh");
    let attach = read("scripts/verify-attach-e2e.sh");

    for public_override in [
        "P11SCOPE_TASK4_BODY",
        "P11SCOPE_TASK4_DIST",
        "P11SCOPE_TASK4_OFFICIAL_TARGET",
    ] {
        assert!(
            !release.contains(public_override),
            "release exposes public re-entry/path override {public_override}"
        );
    }
    for relationship in [
        "WORK=$TASK4_ROOT/work",
        "DIST=\"$WORK/dist\"",
        "OFFICIAL_TARGET=\"$WORK/release-official\"",
        "CANARY_WORK=\"$WORK/canaries\"",
        "ATTACH_WORK=$WORK",
        "DISCOVER_BASE=$WORK",
        "DISCOVER_WORK=\"$DISCOVER_BASE/discover\"",
    ] {
        assert!(
            release.contains(relationship),
            "release misses private path relationship {relationship}"
        );
    }
    for invocation in [
        "P11SCOPE_TASK4_WORK=\"$CANARY_WORK\" sh scripts/verify-canaries.sh",
        "P11SCOPE_TASK4_WORK=\"$ATTACH_WORK\" sh scripts/verify-attach-e2e.sh",
        "P11SCOPE_TASK4_WORK=\"$DISCOVER_BASE\" \\\n    sh scripts/verify-discover-containers.sh",
        "\"$CANARY_WORK\"/feature-build/release/build/p11scope-*/out/p11scope-ebpf",
    ] {
        assert!(
            release.contains(invocation),
            "release misses private nested invocation {invocation}"
        );
    }
    assert_eq!(release.matches("trap task4_finalize EXIT").count(), 1);
    assert_eq!(release.matches("release_body_cleanup").count(), 2);
    assert!(!release.contains(". scripts/cleanup-traps.sh"));
    assert!(!release.contains("$PWD/$WORK"));

    for (script, source, default) in [
        ("verify-canaries", canaries, "target/canaries"),
        ("verify-attach-e2e", attach, "target/e2e"),
    ] {
        assert!(
            source.contains(&format!("WORK=${{P11SCOPE_TASK4_WORK-{default}}}")),
            "{script} lost its standalone default"
        );
        assert!(
            source.contains("case $WORK in /*) ;; *)"),
            "{script} accepts a relative supplied work path"
        );
        assert!(
            !source.contains("$PWD/$WORK"),
            "{script} composes an absolute work path with cwd"
        );
    }

    let fixture = tempfile::tempdir().expect("create Lane 14 poisoned-environment fixture");
    let bin = fixture.path().join("bin");
    let protected = fixture.path().join("protected");
    let sentinel = protected.join("sentinel");
    let tripwire = fixture.path().join("tripwire.log");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&protected).unwrap();
    fs::write(&sentinel, b"must survive\n").unwrap();
    fs::write(
        bin.join("rm"),
        b"#!/bin/sh\nprintf '%s\\n' rm >> \"$P11SCOPE_TASK4_TRIPWIRE_LOG\"\nexit 97\n",
    )
    .unwrap();
    fs::set_permissions(bin.join("rm"), fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new("/bin/sh")
        .arg("scripts/build-release.sh")
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("P11SCOPE_TASK4_BODY", "1")
        .env("P11SCOPE_TASK4_WORK", protected.join("work"))
        .env("P11SCOPE_TASK4_DIST", &protected)
        .env("P11SCOPE_TASK4_OFFICIAL_TARGET", &protected)
        .env("P11SCOPE_TASK4_TRIPWIRE_LOG", &tripwire)
        .output()
        .expect("run Lane 14 with poisoned public re-entry environment");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !tripwire.exists(),
        "poisoned rootless invocation reached rm"
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"must survive\n");
}

// A stateful `docker` CLI stub: `names/<name>` maps a mutable name to the
// immutable id recorded under `ids/<id>`, so a name collision is a real 125
// refusal and every subcommand the lane reaches is logged verbatim.
const LANE14_DOCKER_STUB: &str = r#"#!/bin/sh
set -u
printf '%s\n' "$*" >> "$STUB_LOG"
cmd=$1
shift

resolve() {
    if [ -f "$STUB_STATE/ids/$1" ]; then
        printf '%s\n' "$1"
    elif [ -f "$STUB_STATE/names/$1" ]; then
        cat "$STUB_STATE/names/$1"
    else
        return 1
    fi
}

case $cmd in
pull)
    exit 0
    ;;
create|run)
    name=
    prev=
    for arg in "$@"; do
        [ "$prev" = --name ] && name=$arg
        prev=$arg
    done
    if [ -n "$name" ] && { [ -n "$STUB_CONFLICT" ] || [ -f "$STUB_STATE/names/$name" ]; }; then
        echo "docker: Error response from daemon: Conflict. The container name \"/$name\" is already in use." >&2
        exit 125
    fi
    count=$(cat "$STUB_STATE/count")
    count=$((count + 1))
    printf '%s' "$count" > "$STUB_STATE/count"
    id=$(printf '%064d' "$count")
    : > "$STUB_STATE/ids/$id"
    [ -z "$name" ] || printf '%s\n' "$id" > "$STUB_STATE/names/$name"
    [ "$cmd" != create ] || printf '%s\n' "$id"
    exit 0
    ;;
start)
    target=
    for arg in "$@"; do
        case $arg in -*) ;; *) target=$arg ;; esac
    done
    resolve "$target" >/dev/null || { echo "No such container: $target" >&2; exit 1; }
    exit 0
    ;;
inspect)
    fmt=
    target=
    while [ $# -gt 0 ]; do
        case $1 in
        -f|--format) fmt=$2; shift 2 ;;
        -*) shift ;;
        *) target=$1; shift ;;
        esac
    done
    id=$(resolve "$target") || { echo "No such object: $target" >&2; exit 1; }
    [ -z "$fmt" ] || printf '%s\n' "$id"
    exit 0
    ;;
rm)
    target=
    for arg in "$@"; do
        case $arg in -*) ;; *) target=$arg ;; esac
    done
    id=$(resolve "$target") || exit 1
    rm -f "$STUB_STATE/ids/$id"
    for entry in "$STUB_STATE"/names/*; do
        [ -f "$entry" ] || continue
        [ "$(cat "$entry")" = "$id" ] && rm -f "$entry"
    done
    exit 0
    ;;
esac
exit 0
"#;

#[test]
fn lane14_container_ownership_follows_creation_not_names() {
    // csf_610b398 (Task 10 F5) registered the PID-derived `--name` as a cleanup
    // id *before* `docker run`, so a stale or concurrent foreign container
    // holding that name failed creation (125) and the EXIT trap `docker rm -f`'d
    // the foreign object. The ratified resource journal runs the other way:
    // `requested` precedes creation, `resolved` carries the immutable identity,
    // and mutable names alone never authorize deletion
    // (docs/superpowers/reports/2026-08-28-task4-receipt-architecture-decision.md:100-117).
    let fixture = tempfile::tempdir().expect("create lane 14 docker-stub fixture");
    let root = fixture.path();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    fs::write(bin.join("docker"), LANE14_DOCKER_STUB).unwrap();
    fs::write(
        bin.join("cargo"),
        "#!/bin/sh\nprintf '[source.vendored-sources]\\ndirectory = \"/stub\"\\n'\n",
    )
    .unwrap();
    for tool in ["docker", "cargo"] {
        fs::set_permissions(bin.join(tool), fs::Permissions::from_mode(0o700)).unwrap();
    }

    let lane = |phase: &str, conflict: &str| {
        let work = root.join(phase);
        let artifacts = work.join("artifacts");
        let state = work.join("state");
        fs::create_dir_all(&artifacts).unwrap();
        fs::create_dir_all(state.join("ids")).unwrap();
        fs::create_dir_all(state.join("names")).unwrap();
        fs::write(state.join("count"), b"0").unwrap();
        fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).unwrap();
        let log = work.join("docker.log");
        fs::write(&log, b"").unwrap();
        let facts = artifacts.join("discover.facts");
        let output = Command::new("/bin/sh")
            .arg("scripts/verify-discover-containers.sh")
            .arg("--lane14-facts")
            .arg(&facts)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("P11SCOPE_TASK4_WORK", &work)
            .env("STUB_LOG", &log)
            .env("STUB_STATE", &state)
            .env("STUB_CONFLICT", conflict)
            .output()
            .expect("run lane 14 against the stateful docker stub");
        (
            output,
            fs::read_to_string(&log).unwrap(),
            fs::read_to_string(&facts).unwrap_or_default(),
        )
    };

    // A foreign container already holds the lane's name: refuse, delete nothing.
    let (collision, collision_log, collision_facts) = lane("collision", "1");
    assert!(
        !collision.status.success(),
        "a name collision must refuse the lane"
    );
    assert!(
        !collision_log.lines().any(|line| line.starts_with("rm ")),
        "the lane removed a container it never created:\n{collision_log}"
    );
    assert!(
        !collision_facts.contains("container_"),
        "a refused creation was still recorded as an owned container:\n{collision_facts}"
    );

    // The lane's own containers are created, read back by exact id, recorded,
    // started, and then removed by that id.
    let (success, success_log, success_facts) = lane("success", "");
    assert!(
        success.status.success(),
        "stubbed lane failed: {}",
        String::from_utf8_lossy(&success.stderr)
    );
    assert_eq!(
        success_log
            .lines()
            .filter(|line| line.starts_with("create "))
            .count(),
        3,
        "each container must be created before it is owned:\n{success_log}"
    );
    assert!(
        !success_log.lines().any(|line| line.starts_with("run ")),
        "`docker run` creates and starts in one step, leaving no pre-start id:\n{success_log}"
    );
    let removed: Vec<&str> = success_log
        .lines()
        .filter_map(|line| line.strip_prefix("rm -f "))
        .collect();
    assert_eq!(removed.len(), 3, "cleanup log:\n{success_log}");
    for id in &removed {
        assert!(
            id.len() == 64 && id.chars().all(|character| character.is_ascii_hexdigit()),
            "cleanup removed {id}, which is not an immutable container id"
        );
        assert!(
            success_facts.contains(id),
            "cleanup removed {id}, which the receipt never recorded as owned"
        );
        require_before(
            &success_log,
            &format!("inspect -f {{{{.Id}}}} {id}"),
            &format!("start -a {id}"),
            "lane 14 exact-id readback",
        )
        .unwrap();
    }
    assert!(
        !success_facts.contains("p11scope-discover-"),
        "the receipt records a mutable container name as an identity:\n{success_facts}"
    );
    for fact in [
        "container_glibc_build",
        "container_glibc_run",
        "container_musl_build",
    ] {
        assert!(success_facts.contains(fact), "receipt misses {fact}");
    }
}

#[test]
fn task4_receipt_lane14_capture_binding_is_literal_and_checker_evidence_framed() {
    let release = read("scripts/build-release.sh");

    // csf_19fb2f: `find … '*observed*.json' | sort | head -n 1` always chose
    // the attach-e2e lane's observed-scan.json (ASCII: `-` < `.`, `c` < `t`),
    // never the release's own observed-static-smoke.json, and whole-body
    // stdout stood in for checker evidence. The ratified receipt architecture
    // forbids glob, find|head, path-order authority, and stdout-as-capture.
    assert!(
        release.contains(
            "cp \"$WORK/observed-static-smoke.json\" \"$TASK4_ROOT/artifacts/capture.json\""
        ),
        "capture.json is not bound to the literal static-smoke output path"
    );
    assert!(
        !release.contains("head -n 1"),
        "path-order authority still selects a receipt artifact"
    );
    assert!(
        !release.contains("cp \"$TASK4_ROOT/stdout.log\" \"$TASK4_ROOT/artifacts/checker.log\""),
        "aggregate body stdout still stands in for checker evidence"
    );

    // Review findings (csf_19fb2f): the framed record must also be RETAINED
    // -- the receipt copies $WORK/checker.log, records the three checker
    // facts rows, and the observed-set guard both exists and collates in C
    // so a healthy run cannot false-refuse under a UTF-8 ambient locale.
    assert!(
        release.contains("cp \"$WORK/checker.log\" \"$TASK4_ROOT/artifacts/checker.log\""),
        "the framed checker record is not retained as the receipt's checker.log"
    );
    for fact in [
        "task4_fact checker_argv \"$t4_checker_argv\"",
        "task4_fact checker_status \"$t4_checker_status\"",
        "task4_fact checker_log_sha256 \"$(task4_digest \"$TASK4_ROOT/artifacts/checker.log\")\"",
    ] {
        assert!(release.contains(fact), "receipt misses facts row {fact:?}");
    }
    assert!(
        release.contains("-name '*observed*.json' -print | LC_ALL=C sort)"),
        "the observed-set guard must collate in C, not the ambient locale"
    );
    assert!(
        release.contains(
            "|| { echo \"unexpected observed capture set under work: $t4_observed\" >&2; exit 1; }"
        ),
        "the observed-set guard refusal is missing from the receipt step"
    );

    // The framed checker record carries the exact argv line, the checker's
    // own captured stdout/stderr, and a terminal status line. Execute the
    // real framing block from release_body against a stub checker, then
    // parse and validate the structure it wrote.
    let framing = format!(
        "t4_checker_argv={}",
        between(
            &release,
            "\nt4_checker_argv=",
            "\necho \"static p11scope smoke attach OK"
        )
    );
    let fixture = tempfile::tempdir().expect("create checker-framing fixture");
    let work = fixture.path().join("work");
    fs::create_dir(&work).expect("create framing work directory");
    let stub = fixture.path().join("stub-checker");
    fs::write(
        &stub,
        b"#!/bin/sh\nprintf 'checker-stdout\\n'\nprintf 'checker-stderr\\n' >&2\nexit \"${P11SCOPE_TASK8_CHECKER_STATUS:-0}\"\n",
    )
    .expect("write stub checker");
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).expect("make stub executable");
    let runner = fixture.path().join("run-framing.sh");
    fs::write(
        &runner,
        format!(
            "#!/bin/sh\nset -eu\nT4_TOOL_python3={stub}\nWORK={work}\n{framing}\n",
            stub = stub.display(),
            work = work.display(),
        ),
    )
    .expect("write framing runner");

    let framed_checker_evidence = |log: &str| {
        let lines: Vec<&str> = log.lines().collect();
        if lines.len() < 2 {
            return false;
        }
        let argv_ok = lines[0]
            .strip_prefix("argv\t")
            .is_some_and(|argv| argv.contains("scripts/check-capture-evidence.py"));
        let status_ok = lines[lines.len() - 1]
            .strip_prefix("status\t")
            .is_some_and(|status| !status.is_empty() && status.bytes().all(|b| b.is_ascii_digit()));
        argv_ok && status_ok
    };

    let success = Command::new("/bin/sh")
        .arg(&runner)
        .output()
        .expect("run the checker framing block");
    assert!(
        success.status.success(),
        "framing block failed on a clean checker: stdout={} stderr={}",
        String::from_utf8_lossy(&success.stdout),
        String::from_utf8_lossy(&success.stderr)
    );
    let log = fs::read_to_string(work.join("checker.log")).expect("read framed checker.log");
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(
        lines[0],
        format!(
            "argv\t{} -I scripts/check-capture-evidence.py clean-metrics-manifest-only {}/observed-static-smoke.json spike/expected.txt",
            stub.display(),
            work.display()
        ),
        "framed record must open with the exact checker argv"
    );
    assert!(
        lines.contains(&"checker-stdout"),
        "framed record must capture the checker's stdout: {log:?}"
    );
    assert!(
        lines.contains(&"checker-stderr"),
        "framed record must capture the checker's stderr: {log:?}"
    );
    assert_eq!(
        lines[lines.len() - 1],
        "status\t0",
        "framed record must close with the checker's status"
    );
    assert!(framed_checker_evidence(&log));

    // A checker failure keeps its status in the frame and fails the body
    // with that same status.
    fs::remove_file(work.join("checker.log")).expect("reset framed checker.log");
    let failure = Command::new("/bin/sh")
        .arg(&runner)
        .env("P11SCOPE_TASK8_CHECKER_STATUS", "3")
        .output()
        .expect("run the checker framing block with a failing checker");
    assert_eq!(
        failure.status.code(),
        Some(3),
        "a checker failure must fail the release body with the checker's status"
    );
    let failed_log =
        fs::read_to_string(work.join("checker.log")).expect("read failed framed checker.log");
    assert_eq!(
        failed_log.lines().last(),
        Some("status\t3"),
        "the framed record must retain the checker's failure status: {failed_log:?}"
    );
    assert!(framed_checker_evidence(&failed_log));

    // Non-empty is not the bar: an unframed aggregate stdout log -- the
    // pre-fix checker.log shape -- must be rejected as checker evidence.
    let aggregate = "=== release privacy gate ===\ncanaries OK\n\
        === p11scope: dynamic-build attach correctness ===\n\
        static p11scope smoke attach OK: {}\n=== build-release: ALL OK ===\n";
    assert!(
        !framed_checker_evidence(aggregate),
        "an unframed aggregate stdout log must be rejected as checker evidence"
    );
}

#[test]
fn task4_receipt_lane14_observed_set_guard_refuses_decoys_in_any_locale() {
    // Execute the real observed-set guard block from task4_receipt_run.
    // UTF-8 collation orders observed.json BEFORE observed-scan.json (the
    // hyphen is ignored at the primary level), so a guard sorting in the
    // ambient locale false-refuses a healthy release; the guard must accept
    // the exact 3-name set under any locale and refuse a planted 4th decoy
    // and a missing member.
    let release = read("scripts/build-release.sh");
    let guard = format!(
        "t4_observed=$(find{}",
        between(
            &release,
            "\n    t4_observed=$(find",
            "\n    cp \"$WORK/observed-static-smoke.json\""
        )
    );
    let fixture = tempfile::tempdir().expect("create observed-set guard fixture");
    let work = fixture.path().join("work");
    fs::create_dir(&work).expect("create guard work directory");
    let runner = fixture.path().join("run-guard.sh");
    fs::write(
        &runner,
        format!(
            "#!/bin/sh\nset -eu\nTASK4_ROOT={root}\n{guard}\necho guard-ok\n",
            root = fixture.path().display(),
        ),
    )
    .expect("write guard runner");
    let run = |locale: &str| {
        Command::new("/bin/sh")
            .arg(&runner)
            .env("LC_ALL", locale)
            .output()
            .expect("run the observed-set guard block")
    };

    for name in [
        "observed-scan.json",
        "observed-static-smoke.json",
        "observed.json",
    ] {
        fs::write(work.join(name), b"evidence\n").expect("populate guard work directory");
    }
    for locale in ["C", "en_US.UTF-8"] {
        let output = run(locale);
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("guard-ok"),
            "guard refused the exact observed set under LC_ALL={locale}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fs::write(work.join("observed-decoy.json"), b"decoy\n").expect("plant decoy");
    let decoy = run("en_US.UTF-8");
    assert_eq!(
        decoy.status.code(),
        Some(1),
        "guard accepted a planted 4th *observed*.json"
    );
    assert!(
        String::from_utf8_lossy(&decoy.stderr)
            .contains("unexpected observed capture set under work"),
        "guard refusal must name the unexpected observed set"
    );
    fs::remove_file(work.join("observed-decoy.json")).expect("remove decoy");

    fs::remove_file(work.join("observed.json")).expect("remove a set member");
    let missing = run("C");
    assert_eq!(
        missing.status.code(),
        Some(1),
        "guard accepted a missing observed-set member"
    );
}

/// The build inputs the release driver refuses to inherit. Cargo and rustup
/// read every one of them, so a non-empty inherited value silently re-steers
/// the official build away from the recorded source tree.
const TASK7_BUILD_INPUT_VARIABLES: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTC_WRAPPER",
    "CC",
    "CFLAGS",
];

/// A one-commit repository holding the driver under test. The driver `cd`s to
/// its own parent and demands a fully clean worktree, so the preflight must be
/// exercised against a tree it owns rather than against this checkout.
fn task7_pristine_driver_repo() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("create pristine release-driver repository");
    fs::create_dir(repo.path().join("scripts")).expect("create pristine scripts directory");
    for name in ["build-release.sh", "lib.sh", "check-capture-evidence.py"] {
        fs::copy(
            format!("scripts/{name}"),
            repo.path().join("scripts").join(name),
        )
        .unwrap_or_else(|error| panic!("copy scripts/{name} into the pristine repo: {error}"));
    }
    for arguments in [
        vec!["init", "--quiet", "-b", "task7"],
        vec!["add", "-A"],
        vec![
            "-c",
            "user.email=task7@example.invalid",
            "-c",
            "user.name=task7",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "pristine release driver",
        ],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(&arguments)
            .status()
            .unwrap_or_else(|error| panic!("run git {arguments:?}: {error}"));
        assert!(status.success(), "git {arguments:?} failed");
    }
    repo
}

/// Tripwires for the mutating and build commands a preflight refusal reaches,
/// or must never reach. The log path is baked into each stub rather than read
/// from the environment: the seal drops every variable a stub could inherit,
/// so an environment-driven tripwire would pass vacuously.
fn task7_tripwire_bin(log: &std::path::Path) -> tempfile::TempDir {
    let bin = tempfile::tempdir().expect("create release preflight tripwires");
    for command in [
        "cargo", "docker", "file", "jq", "rm", "rustup", "setpriv", "sudo",
    ] {
        let path = bin.path().join(command);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"${{0##*/}}\" >> {log}\nexit 97\n",
                log = log.display()
            ),
        )
        .expect("write release preflight tripwire");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make release preflight tripwire executable");
    }
    bin
}

/// The one command a sealed refusal does legitimately reach: `task4_finalize`
/// removes the sealed bin directory once the terminal status exists. Any other
/// name in the log is a command that escaped the refusal.
const TASK7_EXPECTED_TRIPWIRES: &str = "rm\n";

/// Runs the pristine driver against an absent evidence root, with every
/// refused build input cleared and only `inherited` restored.
fn task7_run_preflight(
    repo: &tempfile::TempDir,
    home: Option<&std::path::Path>,
    bin: &tempfile::TempDir,
    root: &std::path::Path,
    inherited: &[(&str, &str)],
) -> std::process::Output {
    let mut command = Command::new("/bin/sh");
    command
        .arg(repo.path().join("scripts/build-release.sh"))
        .arg(root)
        // The whole reached-command inventory must resolve through the
        // caller's PATH for the seal to be built at all; the tripwires only
        // shadow the build and mutating commands ahead of it.
        .env(
            "PATH",
            format!(
                "{}:{}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin",
                bin.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    match home {
        Some(home) => command.env("HOME", home),
        None => command.env_remove("HOME"),
    };
    for name in TASK7_BUILD_INPUT_VARIABLES {
        command.env_remove(name);
    }
    for (name, value) in inherited {
        command.env(name, value);
    }
    command
        .output()
        .expect("run the release driver input-trust preflight")
}

/// A mode-0700 campaign parent the driver accepts, plus its tripwire log path.
fn task7_campaign() -> tempfile::TempDir {
    let campaign = tempfile::tempdir().expect("create release preflight campaign parent");
    fs::set_permissions(campaign.path(), fs::Permissions::from_mode(0o700))
        .expect("make the campaign parent private");
    campaign
}

#[test]
fn release_preflight_refuses_an_untracked_cargo_config_before_the_body() {
    // An untracked `.cargo/config.toml` is invisible to `git ls-files`, to the
    // source ledger, and to the tracked-cleanliness gate, yet Cargo obeys it.
    // The driver must refuse it before it touches a build command.
    let repo = task7_pristine_driver_repo();
    let campaign = task7_campaign();
    let tripwire = campaign.path().join("tripwire.log");
    let bin = task7_tripwire_bin(&tripwire);
    let home = tempfile::tempdir().expect("create release preflight home");
    fs::create_dir(home.path().join(".cargo")).expect("create untracked cargo home");
    fs::write(
        home.path().join(".cargo/config.toml"),
        b"[build]\nrustflags = [\"-C\", \"target-feature=-crt-static\"]\n",
    )
    .expect("write the untracked cargo config");

    let output = task7_run_preflight(
        &repo,
        Some(home.path()),
        &bin,
        &campaign.path().join("evidence"),
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(77),
        "untracked cargo config must refuse with 77: stderr={stderr:?}"
    );
    assert!(
        stderr.contains("untracked cargo config"),
        "refusal must name the untracked cargo config: stderr={stderr:?}"
    );
    assert_eq!(
        fs::read_to_string(&tripwire).unwrap_or_default(),
        TASK7_EXPECTED_TRIPWIRES,
        "refusal reached a command beyond the finalizer's sealed-directory removal"
    );
    let residue = Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .output()
        .expect("inspect the pristine repository after the refusal");
    assert!(
        residue.stdout.is_empty(),
        "refusal mutated its own worktree: {:?}",
        String::from_utf8_lossy(&residue.stdout)
    );
}

#[test]
fn release_preflight_refuses_every_inherited_build_input_variable() {
    // Each of the ten re-steers Cargo, rustup, or the C toolchain. One shared
    // clean fixture proves the refusal is per-variable and not an accident of
    // the earlier untracked-config gate.
    let repo = task7_pristine_driver_repo();
    let campaign = task7_campaign();
    let tripwire = campaign.path().join("tripwire.log");
    let bin = task7_tripwire_bin(&tripwire);
    let home = tempfile::tempdir().expect("create release preflight home");

    for (index, variable) in TASK7_BUILD_INPUT_VARIABLES.iter().enumerate() {
        let output = task7_run_preflight(
            &repo,
            Some(home.path()),
            &bin,
            &campaign.path().join(format!("evidence-{index}")),
            &[(variable, "/task7/poisoned")],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(
            output.status.code(),
            Some(77),
            "inherited {variable} must refuse with 77: stderr={stderr:?}"
        );
        assert!(
            stderr.contains(&format!("refusing inherited {variable}")),
            "refusal must name {variable}: stderr={stderr:?}"
        );
        assert!(
            !stderr.contains("untracked cargo config"),
            "{variable} refusal was preempted by the cargo-config gate: stderr={stderr:?}"
        );
        assert!(
            !tripwire.exists(),
            "inherited {variable} reached a command: {:?}",
            fs::read_to_string(&tripwire).unwrap_or_default()
        );
        assert!(
            !campaign.path().join(format!("evidence-{index}")).exists(),
            "inherited {variable} was refused only after the evidence root existed"
        );
    }
}

#[test]
fn release_preflight_refuses_an_unevaluable_cargo_home() {
    // Without HOME the preflight cannot name the effective cargo home, while
    // Cargo can still reach one through the passwd database. Checking
    // `/.cargo` instead would vouch for a location Cargo never reads.
    let repo = task7_pristine_driver_repo();
    let campaign = task7_campaign();
    let tripwire = campaign.path().join("tripwire.log");
    let bin = task7_tripwire_bin(&tripwire);
    let output = task7_run_preflight(&repo, None, &bin, &campaign.path().join("evidence"), &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(77),
        "an unevaluable cargo home must refuse with 77: stderr={stderr:?}"
    );
    assert!(
        stderr.contains("cannot evaluate the effective cargo home"),
        "refusal must name the unevaluable cargo home: stderr={stderr:?}"
    );
    assert_eq!(
        fs::read_to_string(&tripwire).unwrap_or_default(),
        TASK7_EXPECTED_TRIPWIRES,
        "unevaluable cargo home reached a command beyond the sealed-directory removal"
    );
}

#[test]
fn release_finalizer_rechecks_cargo_configs_with_pinned_tools() {
    let release = read("scripts/build-release.sh");
    let finalize = between(&release, "\ntask4_finalize() {", "\ntask4_receipt_run() {");

    // The finalizer writes the terminal receipt. A PATH-priority shadow
    // dropped mid-run must never be the binary that decides, or writes, it --
    // it runs even once the ledger recheck has already failed the run.
    assert!(
        finalize.contains("\"$T4_TOOL_python3\" -I - \"$TASK4_ROOT\""),
        "finalizer validates the evidence root through an unpinned or unisolated interpreter"
    );
    for tool in [
        "cargo",
        "docker",
        "file",
        "jq",
        "python3",
        "rustup",
        "setpriv",
        "sudo",
        "sha256sum",
    ] {
        for indent in ["\n    ", "\n        "] {
            assert!(
                !finalize.contains(&format!("{indent}{tool} ")),
                "task4_finalize invokes bare {tool} instead of its pinned path"
            );
        }
    }

    // Out-of-repo cargo configs are a TOCTOU: the body is long and the
    // effective cargo home stays writable throughout it. A `[build]`
    // rustc-wrapper or a target linker planted there is honoured by the
    // pinned cargo and overridden by none of the command-local values, so
    // the scan has to run again before the receipt is published.
    assert!(
        finalize.contains("task4_cargo_config_scan"),
        "finalizer never re-scans for cargo configs planted during the body"
    );
    assert!(
        !release.contains("task4_refuse_cargo_config"),
        "cargo-config check still exits from inside its helper, so finalization cannot reuse it"
    );
    assert_eq!(
        release.matches("task4_cargo_config_scan").count(),
        3,
        "cargo-config scan must be one definition with a preflight and a finalization call site"
    );
}

#[test]
fn release_preflight_pins_its_tools_before_the_first_digest() {
    // Every recorded digest must come from the pinned sha256sum, including
    // the driver/checker hashes and the source input ledger.
    let release = read("scripts/build-release.sh");
    let pinned = release
        .find("task4_pin_tool \"$t4_found\" \"T4_TOOL_$t4_tool\"")
        .expect("preflight pins the nine recorded tools");
    let first_digest = release
        .find("TASK4_DRIVER_HASH=$(task4_digest")
        .expect("preflight digests the driver");
    assert!(
        pinned < first_digest,
        "the first digest runs before the tool-pinning loop, so it resolves sha256sum through PATH"
    );
}

/// Every external command the receipt chain reaches, in the exact `LC_ALL=C`
/// order the driver pins, symlinks into its sealed bin directory, and
/// self-checks. Derived statically from `scripts/build-release.sh` (including
/// its `cd`/`dirname` line and `task4_finalize`), `scripts/lib.sh`, the three
/// nested gate scripts, and `build.rs`'s nightly Cargo invocation plus the
/// linker drivers rustc reaches through PATH -- then proven by execution
/// under the seal. Shell builtins are excluded. Commands that run under
/// `sudo` resolve through sudo's root-owned `secure_path`, and commands
/// inside a container resolve through the image, so neither is under the
/// caller's PATH authority and neither is a member.
const TASK11_TOOL_INVENTORY: &[&str] = &[
    "as",
    "awk",
    "bpf-linker",
    "bpftool",
    "cargo",
    "cat",
    "cc",
    "chmod",
    "cmp",
    "cp",
    "date",
    "dirname",
    "docker",
    "env",
    "file",
    "find",
    "flock",
    "gcc",
    "git",
    "grep",
    "head",
    "id",
    "jq",
    "ld",
    "ldd",
    "llvm-objcopy",
    "llvm-readelf",
    "ln",
    "ls",
    "mkdir",
    "mktemp",
    "mv",
    "python3",
    "realpath",
    "rm",
    "rustup",
    "sed",
    "setpriv",
    "sh",
    "sha256sum",
    "sleep",
    "softhsm2-util",
    "sort",
    "stat",
    "sudo",
    "sync",
    "tail",
    "timeout",
    "touch",
    "uname",
    "xargs",
];

/// The exact environment name set the sealed child may observe. `env -i`
/// supplies seven of them; dash itself adds `PWD` and nothing else.
const TASK11_SEALED_ENVIRONMENT: &[&str] = &[
    "HOME",
    "LC_ALL",
    "OLDPWD",
    "P11SCOPE_TASK4_CALLER_ARGV0",
    "P11SCOPE_TASK4_CALLER_PATH",
    "P11SCOPE_TASK4_SEALED",
    "P11SCOPE_TASK4_SEALED_BIN",
    "PATH",
    "PWD",
];

struct SealedDriverRun {
    output: std::process::Output,
    root: std::path::PathBuf,
    repo: std::path::PathBuf,
    facts: String,
    tripwire_log: std::path::PathBuf,
    environment_dump: std::path::PathBuf,
    seal_parent: std::path::PathBuf,
    _repo: tempfile::TempDir,
    _fixture: tempfile::TempDir,
}

impl SealedDriverRun {
    fn fact(&self, name: &str) -> Option<&str> {
        self.facts.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('\t'))
        })
    }

    fn tripped(&self) -> String {
        fs::read_to_string(&self.tripwire_log).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }
}

#[derive(Default)]
struct Task11FixtureOptions {
    external_rust_src_symlink: bool,
    internal_rust_src_symlink: bool,
    cargo_proxy_mismatch: bool,
    cargo_proxy_regular_mismatch: bool,
    cargo_home_raw_target_newline: bool,
    cargo_home_canonical_target_newline: bool,
    cargo_home_inventory_shadow: bool,
    missing_musl: bool,
}

/// Runs the pristine driver until it reaches the pinned `sudo -n true` probe
/// -- the first external command the receipt chain executes that a test can
/// own -- with `sudo` replaced by a stub that is the seal's positive control:
/// it records that it ran, dumps the environment it was handed, and plants a
/// tripwire named for every inventory member into a directory that is FIRST
/// in the caller's PATH. Nothing the driver runs afterwards may reach one.
/// `rustup` is stubbed too so the 1.88 toolchain probe succeeds under the
/// fixture HOME. Stub paths are baked in, never inherited: the seal drops
/// every variable a stub could otherwise read.
fn task11_run_to_the_sudo_probe(
    extra_env: &[(&str, &str)],
    options: Task11FixtureOptions,
) -> SealedDriverRun {
    let repo = task7_pristine_driver_repo();
    let fixture = tempfile::tempdir().expect("create sealed release-driver fixture");
    let fake_bin = fixture.path().join("bin");
    let tripwire_bin = fixture.path().join("tripwire-bin");
    let home = fixture.path().join("home");
    let seal_parent = fixture.path().join("tmp");
    let campaign = fixture.path().join("campaign");
    for directory in [&fake_bin, &tripwire_bin, &home, &seal_parent, &campaign] {
        fs::create_dir(directory).expect("create sealed release-driver fixture directory");
    }
    fs::set_permissions(&campaign, fs::Permissions::from_mode(0o700))
        .expect("make the campaign parent private");

    let tripwire_log = fixture.path().join("tripwire.log");
    let environment_dump = fixture.path().join("sealed-environment");

    // The nightly closure the eBPF object is actually built from: cargo,
    // rustc, its sysroot, the `rust-src` tree `-Z build-std=core` consumes,
    // and the BPF linker. `bpf-linker` lives under the effective cargo home,
    // which Cargo prepends to the PATH of every rustc it spawns.
    let sysroot = fixture.path().join("sysroot");
    let rust_src = sysroot.join("lib/rustlib/src/rust");
    fs::create_dir_all(rust_src.join("library/core/src")).expect("create rust-src fixture");
    fs::create_dir_all(sysroot.join("lib/rustlib/x86_64-unknown-linux-musl/lib"))
        .expect("create stable musl sysroot fixture");
    fs::write(sysroot.join("lib/librustc_driver.so"), b"rustc-driver\n")
        .expect("write top-level rustc driver fixture");
    fs::write(
        sysroot.join("lib/rustlib/x86_64-unknown-linux-musl/lib/libc.rlib"),
        b"musl-target\n",
    )
    .expect("write stable musl target fixture");
    if options.missing_musl {
        fs::remove_dir_all(sysroot.join("lib/rustlib/x86_64-unknown-linux-musl/lib"))
            .expect("remove stable musl target fixture");
    }
    for (name, body) in [
        ("library/core/src/lib.rs", "#![no_std]\n"),
        ("library/core/Cargo.toml", "[package]\nname = \"core\"\n"),
    ] {
        fs::write(rust_src.join(name), body).expect("write rust-src fixture file");
    }
    let cargo_bin = home.join(".cargo/bin");
    fs::create_dir_all(&cargo_bin).expect("create the fixture cargo home");
    fs::write(cargo_bin.join("bpf-linker"), b"#!/bin/sh\nexit 0\n").expect("write bpf-linker");
    fs::set_permissions(
        cargo_bin.join("bpf-linker"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("make bpf-linker executable");
    if options.internal_rust_src_symlink {
        std::os::unix::fs::symlink("lib.rs", rust_src.join("library/core/src/internal-link"))
            .expect("plant an internal rust-src symlink");
    }
    if options.external_rust_src_symlink {
        std::os::unix::fs::symlink("/etc/passwd", rust_src.join("library/core/planted"))
            .expect("plant a symlink in the rust-src fixture");
    }

    let toolchain = fixture.path().join("toolchain-binary");
    fs::write(
        &toolchain,
        format!(
            "#!/bin/sh\ncase \"$*\" in\n\"--print sysroot\") echo {sysroot} ;;\nesac\nexit 0\n",
            sysroot = sysroot.display()
        ),
    )
    .expect("write toolchain fixture binary");
    fs::set_permissions(&toolchain, fs::Permissions::from_mode(0o700))
        .expect("make the toolchain fixture binary executable");

    let stub = |name: &str, body: String| {
        let path = fake_bin.join(name);
        fs::write(&path, body).expect("write sealed release-driver stub");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make the sealed release-driver stub executable");
    };
    stub(
        "rustup",
        format!(
            r#"#!/bin/sh
case "$1 $2 $3" in
"which --toolchain 1.88"|"which --toolchain nightly-2026-05-20") echo {toolchain}; exit 0 ;;
esac
exit 1
"#,
            toolchain = toolchain.display()
        ),
    );
    let proxy_target = fake_bin.join("rustup-proxy-target");
    fs::write(&proxy_target, b"#!/bin/sh\nexit 0\n").expect("write mismatched cargo proxy");
    fs::set_permissions(&proxy_target, fs::Permissions::from_mode(0o700))
        .expect("make mismatched cargo proxy executable");
    let rustup_target = fake_bin.join("rustup");
    let cargo_target = if options.cargo_home_canonical_target_newline {
        let newline_target = fake_bin.join("rustup\n");
        fs::write(&newline_target, b"#!/bin/sh\nexit 0\n")
            .expect("write newline-terminated cargo target");
        fs::set_permissions(&newline_target, fs::Permissions::from_mode(0o700))
            .expect("make newline-terminated cargo target executable");
        let intermediate = fake_bin.join("cargo-intermediate");
        std::os::unix::fs::symlink(&newline_target, &intermediate)
            .expect("link safe-named cargo intermediate");
        intermediate
    } else {
        rustup_target.clone()
    };
    if options.cargo_proxy_regular_mismatch {
        fs::write(cargo_bin.join("cargo"), b"#!/bin/sh\nexit 0\n")
            .expect("write regular cargo proxy mismatch");
        fs::set_permissions(cargo_bin.join("cargo"), fs::Permissions::from_mode(0o700))
            .expect("make regular cargo proxy mismatch executable");
    } else {
        std::os::unix::fs::symlink(
            if options.cargo_proxy_mismatch {
                proxy_target.as_path()
            } else {
                cargo_target.as_path()
            },
            cargo_bin.join("cargo"),
        )
        .expect("link cargo proxy");
    }
    std::os::unix::fs::symlink(&rustup_target, cargo_bin.join("rustc")).expect("link rustc proxy");
    std::os::unix::fs::symlink(&rustup_target, cargo_bin.join("rustup"))
        .expect("link rustup proxy");
    let third_party = cargo_bin.join("cargo-third-party");
    fs::write(&third_party, b"#!/bin/sh\nexit 0\n").expect("write third-party cargo command");
    fs::set_permissions(&third_party, fs::Permissions::from_mode(0o700))
        .expect("make third-party cargo command executable");
    fs::write(
        cargo_bin.join("cargo-third-party-target"),
        b"#!/bin/sh\nexit 0\n",
    )
    .expect("write third-party symlink target");
    fs::set_permissions(
        cargo_bin.join("cargo-third-party-target"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("make third-party symlink target executable");
    let third_party_link_target = if options.cargo_home_raw_target_newline {
        let external_plain_target = fake_bin.join("third-party-target");
        fs::write(&external_plain_target, b"#!/bin/sh\nexit 0\n")
            .expect("write plain symlink target twin");
        fs::set_permissions(&external_plain_target, fs::Permissions::from_mode(0o700))
            .expect("make plain symlink target twin executable");
        let external_target = fake_bin.join("third-party-target\n");
        fs::write(&external_target, b"#!/bin/sh\nexit 0\n")
            .expect("write newline-terminated symlink target");
        fs::set_permissions(&external_target, fs::Permissions::from_mode(0o700))
            .expect("make newline-terminated symlink target executable");
        external_target
    } else {
        cargo_bin.join("cargo-third-party-target")
    };
    std::os::unix::fs::symlink(
        &third_party_link_target,
        cargo_bin.join("cargo-third-party-link"),
    )
    .expect("link third-party cargo command");
    if options.cargo_home_inventory_shadow {
        fs::write(cargo_bin.join("date"), b"#!/bin/sh\nexit 0\n")
            .expect("write cargo-home inventory shadow");
        fs::set_permissions(cargo_bin.join("date"), fs::Permissions::from_mode(0o700))
            .expect("make cargo-home inventory shadow executable");
    }
    stub(
        "sudo",
        format!(
            "#!/bin/sh\n\
             echo \"${{0##*/}}\" >> {log}\n\
             env > {dump}\n\
             for name in {inventory}; do\n\
             \x20   printf '#!/bin/sh\\necho \"${{0##*/}}\" >> {log}\\nexit 97\\n' > \"{bin}/$name\"\n\
             \x20   chmod 700 \"{bin}/$name\"\n\
             done\n\
             exit 1\n",
            log = tripwire_log.display(),
            dump = environment_dump.display(),
            bin = tripwire_bin.display(),
            inventory = TASK11_TOOL_INVENTORY.join(" "),
        ),
    );

    let root = campaign.join("evidence");
    let caller_path = format!(
        "{}:{}:{}:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin",
        tripwire_bin.display(),
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new("/bin/sh");
    command
        .arg(repo.path().join("scripts/build-release.sh"))
        .arg(&root)
        .env("PATH", &caller_path)
        .env("HOME", &home)
        .env("TMPDIR", &seal_parent);
    for name in TASK7_BUILD_INPUT_VARIABLES {
        command.env_remove(name);
    }
    for (name, value) in extra_env {
        command.env(name, value);
    }
    let output = command.output().expect("run the sealed release driver");
    let facts = fs::read_to_string(root.join("facts.log")).unwrap_or_default();
    SealedDriverRun {
        output,
        root,
        repo: repo.path().to_path_buf(),
        facts,
        tripwire_log,
        environment_dump,
        seal_parent,
        _repo: repo,
        _fixture: fixture,
    }
}

#[test]
fn release_seal_denies_the_caller_path_to_every_reached_command() {
    // csf_014eb65 / shadow finding 3: bare PATH-resolved commands establish
    // HEAD, the source ledger, every digest, and the receipt itself. The
    // ratified rule (W1 plan line 417) is that no inherited PATH authority
    // survives anywhere in the receipt chain, so the closure is a sealed
    // execution environment, not a longer hand-maintained tool list.
    let run = task11_run_to_the_sudo_probe(&[], Task11FixtureOptions::default());
    let stderr = run.stderr();

    assert_eq!(
        run.output.status.code(),
        Some(77),
        "the stubbed sudo probe must refuse the run: stderr={stderr:?}"
    );
    // The positive control proves the tripwire mechanism itself works: the
    // one command legitimately reached after the seal did write the log.
    assert_eq!(
        run.tripped(),
        "sudo\n",
        "exactly the positive control may appear in the tripwire log"
    );
    assert_eq!(
        fs::read_to_string(run.root.join("status"))
            .expect("the refusal still writes its terminal status"),
        "77\n"
    );

    let sealed_bin = run
        .fact("sealed_bin")
        .expect("the receipt records the sealed bin directory");
    assert!(
        !std::path::Path::new(sealed_bin).exists(),
        "finalization left the sealed bin directory behind: {sealed_bin}"
    );
    assert_eq!(
        fs::read_dir(&run.seal_parent)
            .expect("read the seal parent")
            .count(),
        0,
        "the seal parent still holds sealed-run residue"
    );
    // Every inventory member -- not the nine-name floor -- is recorded with
    // the path the seal selects, what the caller's PATH resolves it to, and
    // the pinned binary's digest.
    for tool in TASK11_TOOL_INVENTORY {
        let row = run
            .fact(&format!("tool_{tool}"))
            .unwrap_or_else(|| panic!("the receipt tool ledger omits {tool}"));
        let fields: Vec<&str> = row.split(' ').collect();
        assert_eq!(fields.len(), 3, "malformed tool_{tool} row: {row:?}");
        assert!(
            fields[0].starts_with('/') && fields[0] == fields[1],
            "tool_{tool} must pin one absolute path the caller's PATH still resolves: {row:?}"
        );
        assert!(
            fields[2].len() == 64 && fields[2].bytes().all(|b| b.is_ascii_hexdigit()),
            "tool_{tool} must carry the pinned binary's digest: {row:?}"
        );
    }

    // The nightly eBPF toolchain closure is an effective input of the release
    // artifact and is bound like one. `cc` is reached through PATH by rustc's
    // gcc-flavour linker driver, so it is an ordinary inventory member above;
    // gcc's own collect2/ld/as come from its configured prefix, not PATH
    // (verified by execve trace on this host).
    for (row, shape) in [
        ("toolchain_sysroot", 2usize),
        ("toolchain_nightly_cargo", 2usize),
        ("toolchain_nightly_rustc", 2),
        ("toolchain_nightly_sysroot", 2),
        ("toolchain_nightly_rust_src", 2),
        ("toolchain_bpf_linker", 2),
    ] {
        let value = run
            .fact(row)
            .unwrap_or_else(|| panic!("the receipt omits the {row} closure row"));
        let fields: Vec<&str> = value.split(' ').collect();
        assert_eq!(fields.len(), shape, "malformed {row} row: {value:?}");
        assert!(
            fields[0].starts_with('/'),
            "malformed {row} path: {value:?}"
        );
        if shape == 2 {
            let digest = fields[1]
                .strip_prefix("tree-sha256-v1:")
                .unwrap_or(fields[1]);
            assert!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "{row} must carry a digest: {value:?}"
            );
        }
    }
    assert!(
        run.fact("toolchain_bpf_linker")
            .is_some_and(|row| row.contains("/.cargo/bin/bpf-linker")),
        "the BPF linker must be bound where rustc actually reaches it"
    );

    let caller_path = run
        .fact("caller_path")
        .expect("the receipt records the caller's PATH");
    assert!(
        caller_path
            .split(':')
            .any(|entry| entry.ends_with("tripwire-bin")),
        "the recorded caller PATH is not the PATH the driver was handed: {caller_path}"
    );
}

#[test]
fn release_seal_exports_exactly_the_reviewed_environment() {
    // Shadow finding 6: RUSTC_WORKSPACE_WRAPPER re-steers the official build,
    // PYTHONPATH/PYTHONHOME re-steer both Python steps, and the GIT_* family
    // re-steers the source authority itself -- none of them recorded. The
    // driver runs under an explicit allowlist instead of a longer denylist.
    // A real PYTHONPATH carrier, not a placeholder: `sitecustomize` runs on
    // interpreter start-up, so the driver's own finalizer would execute it.
    let carrier = tempfile::tempdir().expect("create the PYTHONPATH carrier");
    let executed = carrier.path().join("sitecustomize-ran");
    fs::write(
        carrier.path().join("sitecustomize.py"),
        format!(
            "import pathlib\npathlib.Path({executed:?}).write_text('executed')\n",
            executed = executed.display().to_string()
        ),
    )
    .expect("write the sitecustomize carrier");
    let carrier_path = carrier.path().display().to_string();
    let planted = [
        ("RUSTC_WORKSPACE_WRAPPER", "/task11/wrapper"),
        ("P11SCOPE_SMALL_RING", "1"),
        ("PYTHONPATH", carrier_path.as_str()),
        ("PYTHONHOME", ""),
        ("GIT_DIR", "/task11/git"),
        ("GIT_WORK_TREE", "/task11/worktree"),
        ("GIT_INDEX_FILE", "/task11/index"),
        ("GIT_CONFIG_GLOBAL", "/task11/gitconfig"),
        ("DOCKER_HOST", "tcp://task11.invalid:2375"),
        ("LANG", "en_US.UTF-8"),
    ];
    let run = task11_run_to_the_sudo_probe(&planted, Task11FixtureOptions::default());
    assert_eq!(
        run.output.status.code(),
        Some(77),
        "the stubbed sudo probe must refuse the run: stderr={:?}",
        run.stderr()
    );

    let dumped = fs::read_to_string(&run.environment_dump)
        .expect("the positive control dumped the sealed environment");
    let mut names: Vec<&str> = dumped
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, _)| name)
        .collect();
    names.sort_unstable();
    assert_eq!(
        names, TASK11_SEALED_ENVIRONMENT,
        "the sealed child saw an environment outside its allowlist: {dumped:?}"
    );
    for (name, _) in planted {
        assert!(
            !dumped.contains(&format!("{name}=")),
            "planted {name} survived the seal: {dumped:?}"
        );
    }
    let value = |name: &str| {
        dumped
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(value("LC_ALL"), "C");
    assert_eq!(value("P11SCOPE_TASK4_SEALED"), "1");
    assert_eq!(
        value("PATH"),
        value("P11SCOPE_TASK4_SEALED_BIN"),
        "PATH must be exactly the sealed bin directory"
    );
    assert!(
        !executed.exists(),
        "an inherited PYTHONPATH sitecustomize executed inside the release driver"
    );

    let driver_head = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&run.repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("read the driver repository HEAD")
            .stdout,
    )
    .expect("UTF-8 HEAD");
    assert_eq!(
        run.fact("head"),
        Some(driver_head.trim()),
        "an inherited GIT_DIR must never decide the recorded HEAD"
    );
}

#[test]
fn release_runs_every_python3_in_isolated_mode() {
    // Shadow finding 6's independent carrier: the pinned interpreter was
    // launched without isolated mode, so an external `sitecustomize` or a
    // shadowed module on PYTHONPATH executed inside both capture approval and
    // the inline finalizer. The seal drops those variables; `-I` also refuses
    // them for any invocation that ever runs outside it, and drops the user
    // site directory and the script directory from sys.path as well.
    let release = read("scripts/build-release.sh");
    assert!(
        release.contains("    python3 -I - \"$REPORT\" <<'PY'"),
        "the --self-test model runner is not isolated"
    );
    let sites: Vec<&str> = release
        .match_indices("T4_TOOL_python3")
        .map(|(at, _)| &release[at..])
        .collect();
    assert_eq!(
        sites.len(),
        5,
        "the pinned-interpreter call sites moved; re-check each one for -I"
    );
    for site in sites {
        let rest = site
            .strip_prefix("T4_TOOL_python3")
            .and_then(|rest| rest.strip_prefix('"').or(Some(rest)))
            .unwrap();
        assert!(
            rest.starts_with(" -I "),
            "an unisolated pinned python3 invocation: {:?}",
            &site[..site.len().min(90)]
        );
    }
    // The framed checker record names the argv it actually ran.
    assert!(
        release.contains("t4_checker_argv=\"$T4_TOOL_python3 -I scripts/check-capture-evidence.py"),
        "the framed checker argv does not match the isolated invocation"
    );

    // Production mutation caught: removing `-I` from
    // `scripts/verify-attach-e2e.sh:16` must fail this contract. Strip shell
    // comments before checking so documentation does not count as a command;
    // `command -v python3` is a lookup, not an interpreter invocation.
    for path in [
        "scripts/lib.sh",
        "scripts/verify-canaries.sh",
        "scripts/verify-attach-e2e.sh",
        "scripts/verify-discover-containers.sh",
    ] {
        let source = read(path);
        for (line_number, line) in source.lines().enumerate() {
            let code = line.split_once('#').map_or(line, |(code, _)| code);
            if code.trim_start().starts_with("command -v python3") {
                continue;
            }
            let mut offset = 0;
            while let Some(relative) = code[offset..].find("python3") {
                let start = offset + relative;
                let end = start + "python3".len();
                let bytes = code.as_bytes();
                let token_before = start == 0
                    || !bytes[start - 1].is_ascii_alphanumeric() && bytes[start - 1] != b'_';
                let token_after =
                    end == bytes.len() || !bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_';
                if token_before && token_after {
                    let after = code[end..].trim_start();
                    let rest = after.strip_prefix("-I").unwrap_or_else(|| {
                        panic!("unisolated executable python3 in {path}:{line_number}: {line:?}")
                    });
                    assert!(
                        rest.is_empty()
                            || (!rest.as_bytes()[0].is_ascii_alphanumeric()
                                && rest.as_bytes()[0] != b'_'),
                        "python3 option is not the isolated -I token in {path}:{line_number}: {line:?}"
                    );
                }
                offset = end;
            }
        }
    }
}

#[test]
fn release_cargo_home_bin_closure_is_complete_and_refuses_shadows() {
    // The rustup proxy prepends HOME/.cargo/bin to the nightly build's PATH.
    // Every immediate entry is therefore part of the receipt: regular files,
    // internal symlinks, and the cargo/rustc/rustup proxy identity alike.
    let safe = task11_run_to_the_sudo_probe(&[], Task11FixtureOptions::default());
    assert_eq!(safe.output.status.code(), Some(77));
    for name in [
        "cargo",
        "rustc",
        "rustup",
        "bpf-linker",
        "cargo-third-party",
        "cargo-third-party-link",
        "cargo-third-party-target",
    ] {
        assert!(
            safe.fact(&format!("cargo_home_bin_{name}")).is_some(),
            "the cargo-home ledger omits {name}"
        );
    }
    assert!(
        safe.fact("cargo_home_bin_cargo-third-party-link")
            .is_some_and(|row| row.contains("cargo-third-party-target")),
        "the cargo-home symlink row must bind its raw target"
    );
    assert_eq!(
        safe.tripped(),
        "sudo\n",
        "the safe fixture reaches only the probe"
    );

    let shadow = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            cargo_home_inventory_shadow: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(shadow.output.status.code(), Some(77));
    assert!(
        shadow.tripped().is_empty(),
        "an exact inventory-name shadow reached the release body: {}",
        shadow.tripped()
    );

    let mismatch = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            cargo_proxy_mismatch: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(mismatch.output.status.code(), Some(77));
    assert!(
        mismatch.tripped().is_empty(),
        "a cargo proxy mismatch reached the release body: {}",
        mismatch.tripped()
    );

    let regular_mismatch = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            cargo_proxy_regular_mismatch: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(regular_mismatch.output.status.code(), Some(77));
    assert!(
        regular_mismatch.tripped().is_empty(),
        "a regular cargo proxy mismatch reached the release body: {}",
        regular_mismatch.tripped()
    );

    let raw_target_newline = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            cargo_home_raw_target_newline: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(raw_target_newline.output.status.code(), Some(77));
    assert!(
        raw_target_newline.tripped().is_empty(),
        "a newline-terminated raw target reached the release body: {}",
        raw_target_newline.tripped()
    );

    let canonical_target_newline = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            cargo_home_canonical_target_newline: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(canonical_target_newline.output.status.code(), Some(77));
    assert!(
        canonical_target_newline.tripped().is_empty(),
        "a newline-terminated two-hop canonical target reached the release body: {}",
        canonical_target_newline.tripped()
    );
}

#[test]
fn release_sysroot_closure_is_bound_and_missing_musl_refuses_before_body() {
    let release = read("scripts/build-release.sh");
    assert!(
        release.contains("tree-sha256-v1:"),
        "sysroot closure does not use the typed tree digest"
    );
    assert!(
        !release.contains("target add"),
        "the release body may not mutate the stable toolchain"
    );

    let safe = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            internal_rust_src_symlink: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(safe.output.status.code(), Some(77));
    for row in [
        "toolchain_sysroot",
        "toolchain_nightly_sysroot",
        "toolchain_nightly_rust_src",
    ] {
        let value = safe.fact(row).unwrap_or_else(|| panic!("missing {row}"));
        assert!(
            value.contains("tree-sha256-v1:"),
            "{row} is not a typed tree digest: {value:?}"
        );
    }
    assert_eq!(safe.tripped(), "sudo\n");

    let missing = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            missing_musl: true,
            ..Task11FixtureOptions::default()
        },
    );
    assert_eq!(missing.output.status.code(), Some(77));
    assert!(
        missing.tripped().is_empty(),
        "missing stable musl target reached the body: {}",
        missing.tripped()
    );
    assert!(
        missing.fact("toolchain_sysroot").is_none(),
        "missing stable musl target was recorded as a valid sysroot"
    );
}

#[test]
fn release_root_with_a_real_tab_is_refused_before_creation() {
    let repo = task7_pristine_driver_repo();
    let campaign = task7_campaign();
    let home = tempfile::tempdir().expect("create release preflight home");
    let bin = task7_tripwire_bin(&campaign.path().join("tripwire.log"));
    let root = campaign.path().join("evidence\troot");
    let output = task7_run_preflight(&repo, Some(home.path()), &bin, &root, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(77),
        "a real tab in the root path must refuse with 77: stderr={stderr:?}"
    );
    assert!(!root.exists(), "the tabbed root was created before refusal");
}

#[test]
fn release_refuses_an_external_nightly_rust_src_symlink() {
    // `-Z build-std=core` compiles the installed `rust-src` tree into the
    // shipped eBPF object, so the tree is an effective input and is digested
    // whole. An external symlink is outside the typed tree closure and must
    // refuse; an internal symlink is covered by the positive case above.
    let run = task11_run_to_the_sudo_probe(
        &[],
        Task11FixtureOptions {
            external_rust_src_symlink: true,
            ..Task11FixtureOptions::default()
        },
    );
    let stderr = run.stderr();
    assert_eq!(
        run.output.status.code(),
        Some(77),
        "a symlinked rust-src tree must refuse: stderr={stderr:?}"
    );
    assert!(
        run.fact("head").is_some(),
        "the refusal must come from the ledger, after the source facts"
    );
    for absent in ["toolchain_nightly_rust_src", "tool_awk", "tool_bpf-linker"] {
        assert!(
            run.fact(absent).is_none(),
            "an unbindable rust-src tree still published the {absent} ledger row"
        );
    }
    assert_eq!(
        run.tripped(),
        "",
        "the refusal ran past the ledger into the body probe"
    );
    let sealed_bin = run
        .fact("sealed_bin")
        .expect("the receipt records the sealed bin directory");
    assert!(
        !std::path::Path::new(sealed_bin).exists(),
        "finalization left the sealed bin directory behind: {sealed_bin}"
    );
}

#[test]
fn release_refuses_a_forged_seal_marker() {
    // A caller who merely exports the marker must not skip the seal: the
    // exact-name-set self-check refuses the extra variables it inherited.
    let repo = task7_pristine_driver_repo();
    let campaign = task7_campaign();
    let home = tempfile::tempdir().expect("create forged-marker home");
    let root = campaign.path().join("evidence");
    let mut command = Command::new("/bin/sh");
    command
        .arg(repo.path().join("scripts/build-release.sh"))
        .arg(&root)
        .env("HOME", home.path())
        .env("P11SCOPE_TASK4_SEALED", "1");
    for name in TASK7_BUILD_INPUT_VARIABLES {
        command.env_remove(name);
    }
    let output = command
        .output()
        .expect("run the driver with a forged marker");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(77),
        "a forged seal marker must refuse: stderr={stderr:?}"
    );
    assert!(
        stderr.contains("unsealed or forged"),
        "the refusal must name the forged seal: stderr={stderr:?}"
    );
    assert!(
        !root.exists(),
        "the forged marker created an evidence root before refusing"
    );

    // The forgery that matters: a caller who reproduces the seal's shape --
    // a private 0700 directory holding exactly the inventory as symlinks,
    // PATH pointing at it, all four markers set -- but keeps one variable of
    // its own. Only the exact-name-set check separates that from the real
    // seal, and it must refuse before any root exists.
    let forged_bin = campaign.path().join("forged-bin");
    fs::create_dir(&forged_bin).expect("create the forged sealed bin");
    fs::set_permissions(&forged_bin, fs::Permissions::from_mode(0o700)).unwrap();
    for tool in TASK11_TOOL_INVENTORY {
        let resolved = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .output()
            .expect("resolve an inventory tool");
        assert!(
            resolved.status.success(),
            "inventory member {tool} is absent from this host's PATH"
        );
        std::os::unix::fs::symlink(
            String::from_utf8_lossy(&resolved.stdout).trim(),
            forged_bin.join(tool),
        )
        .expect("link the forged sealed bin");
    }
    let forged_root = campaign.path().join("forged-evidence");
    let forged = Command::new("/bin/sh")
        .env_clear()
        .arg(repo.path().join("scripts/build-release.sh"))
        .arg(&forged_root)
        .env("PATH", &forged_bin)
        .env("HOME", home.path())
        .env("LC_ALL", "C")
        .env("P11SCOPE_TASK4_SEALED", "1")
        .env("P11SCOPE_TASK4_SEALED_BIN", &forged_bin)
        .env("P11SCOPE_TASK4_CALLER_PATH", "/forged")
        .env("P11SCOPE_TASK4_CALLER_ARGV0", "forged")
        .env("PYTHONPATH", "/task11/forged-python")
        .output()
        .expect("run the driver with a reproduced seal plus one extra variable");
    let forged_stderr = String::from_utf8_lossy(&forged.stderr);
    assert_eq!(
        forged.status.code(),
        Some(77),
        "one variable outside the allowlist must refuse: stderr={forged_stderr:?}"
    );
    assert!(
        forged_stderr.contains("unsealed or forged"),
        "the refusal must name the forged seal: stderr={forged_stderr:?}"
    );
    assert!(
        !forged_root.exists(),
        "the forged seal created an evidence root before refusing"
    );
}

#[test]
fn release_pins_its_reached_command_inventory_and_sealed_environment() {
    let release = read("scripts/build-release.sh");

    let inventory: Vec<&str> = between(&release, "\nTASK4_TOOL_INVENTORY='", "'")
        .split_whitespace()
        .collect();
    assert_eq!(
        inventory, TASK11_TOOL_INVENTORY,
        "the driver's reached-command inventory drifted from the contract"
    );
    let mut ordered = TASK11_TOOL_INVENTORY.to_vec();
    ordered.sort_unstable();
    assert_eq!(
        ordered, TASK11_TOOL_INVENTORY,
        "the inventory must stay in LC_ALL=C order: the seal compares it to `ls -A1` directly"
    );
    assert_eq!(
        between(&release, "\nTASK4_SEALED_ENVIRONMENT='", "'")
            .lines()
            .collect::<Vec<_>>(),
        TASK11_SEALED_ENVIRONMENT,
        "the driver's sealed-environment allowlist drifted from the contract"
    );

    // The seal is built in the unsealed parent, before any root, lock, git,
    // tool, or cargo-config decision -- and after the ten explicit refusals,
    // which stay recognisable named signals rather than becoming a silent drop.
    let bootstrap = between(&release, "\ntask4_seal_and_reexec() {", "\n}\n");
    let refusal = bootstrap
        .find("echo \"refusing inherited $t4_var\" >&2; exit 77;")
        .expect("the bootstrap refuses each inherited build input by name");
    let reexec = bootstrap
        .find("exec \"$t4_seal_env\" -i")
        .expect("the bootstrap re-execs under an emptied environment");
    assert!(
        refusal < reexec,
        "the inherited-build-input refusals must precede the re-exec"
    );
    let seal = release
        .find("task4_seal_and_reexec \"$1\"")
        .expect("the driver seals its environment before the receipt chain");
    for later in [
        "\n    task4_prepare_root \"$1\"",
        "TASK4_HEAD=$(git rev-parse HEAD)",
        "TASK4_CONFIGS=$(task4_cargo_config_scan)",
        "\"$T4_TOOL_sudo\" -n true",
    ] {
        assert!(
            seal < release
                .find(later)
                .unwrap_or_else(|| panic!("missing {later}")),
            "the seal must precede {later}"
        );
    }

    // The ledger covers every inventory member, not the nine-name floor.
    assert!(
        release.contains("for t4_tool in $TASK4_TOOL_INVENTORY; do"),
        "the tool ledger still walks a hand-maintained name list"
    );
    assert!(
        release.contains("PATH=\"$P11SCOPE_TASK4_CALLER_PATH\" command -v"),
        "the ledger never re-resolves the caller's PATH, so a divergence cannot refuse"
    );
    // The nightly closure is rechecked at finalization, so it lives in the
    // ledger the finalizer compares, not in a one-shot preflight block.
    let ledger = between(&release, "\ntask4_tool_ledger() {", "\n}\n");
    assert!(
        ledger.contains("task4_nightly_closure || return 1"),
        "the rechecked tool ledger does not bind the nightly closure"
    );
    let ledger = between(&release, "\ntask4_nightly_closure() {", "\n}\n");
    for row in [
        "toolchain_nightly_cargo",
        "toolchain_nightly_rustc",
        "toolchain_nightly_sysroot",
        "toolchain_nightly_rust_src",
        "toolchain_bpf_linker",
    ] {
        assert!(
            ledger.contains(row),
            "the rechecked tool ledger omits {row}"
        );
    }
    assert!(
        ledger.contains("nightly-2026-05-20"),
        "the ledger does not name the pinned nightly toolchain"
    );
    assert!(
        ledger.contains("task4_tree_digest \"$t4_src\""),
        "the rust-src closure does not use the typed tree digest"
    );
    assert!(
        ledger.contains("librustc_driver*.so"),
        "the sysroot closure does not require the top-level compiler driver"
    );

    // The sealed bin directory is evidence until the receipt status exists.
    let finalize = between(&release, "\ntask4_finalize() {", "\ntask4_receipt_run() {");
    let status = finalize
        .find("printf '%s\\n' \"$t4_result\" > \"$TASK4_ROOT/status\"")
        .expect("finalization writes the terminal status");
    let removal = finalize
        .find("rm -rf \"$P11SCOPE_TASK4_SEALED_BIN\"")
        .expect("finalization removes the sealed bin directory");
    assert!(
        status < removal,
        "the sealed bin directory is removed before the receipt status is written"
    );
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
fn capture_readiness_is_rechecked_after_observer_exit() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#"
set -eu
. scripts/lib.sh
log=$(mktemp)
trap 'rm -f "$log"' EXIT
grep_calls=0
grep() {
    grep_calls=$((grep_calls + 1))
    if [ "$grep_calls" -eq 1 ]; then
        printf '%s\n' 'capture — privacy=aggregate-only' > "$log"
        return 1
    fi
    command grep "$@"
}
kill() { return 1; }
SPID=42
wait_for_capture_ready "$log" aggregate-only metrics
[ "$grep_calls" -eq 2 ]
"#,
        ])
        .output()
        .expect("exercise capture readiness exit race");
    assert!(
        output.status.success(),
        "final readiness recheck failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
    printf '{"schema":"p11scope-manifest/5","module_path":"%s","objects":[{"id":0,"path":"%s"},{"id":1,"path":"%s"}]}\n' \
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
fn subset_oracle_requires_independent_calls_and_clean_capture() {
    run_ok(
        "python3",
        &[
            "-I",
            "tests/python/test_subset_oracle.py",
            "SubsetOracleTests.test_nonempty_report_without_trace_is_rejected",
            "SubsetOracleTests.test_empty_trace_is_rejected",
            "SubsetOracleTests.test_excluded_only_trace_is_rejected",
            "SubsetOracleTests.test_actual_trace_pair_passes",
            "SubsetOracleTests.test_call_phase_copy_is_not_double_counted",
            "SubsetOracleTests.test_missing_captured_pair_is_rejected",
            "SubsetOracleTests.test_insufficient_capture_count_is_rejected",
            "SubsetOracleTests.test_surplus_capture_passes",
            "SubsetOracleTests.test_dirty_evidence_is_rejected",
            "SubsetOracleTests.test_no_probe_evidence_is_rejected",
        ],
    );
}

#[test]
fn recorded_launcher_requires_authenticated_generations_and_bounded_cleanup() {
    run_ok(
        "python3",
        &[
            "-I",
            "tests/python/test_root_recorded_launcher.py",
            "RecordedLauncherTests.test_root_two_barriers_preserve_identity_argv_stdin_and_status",
            "RecordedLauncherTests.test_split_root_preserves_streams_identity_argv_stdin_and_status",
            "RecordedLauncherTests.test_existing_root_and_user_launchers_still_combine_streams",
            "RecordedLauncherTests.test_split_refuses_empty_stderr_path_before_prepare",
            "RecordedLauncherTests.test_split_output_open_failures_are_bounded_pending_and_finalizable",
            "RecordedLauncherTests.test_split_target_exec_failure_uses_stderr_only_and_is_nonzero",
            "RecordedLauncherTests.test_split_ack_interruption_cleans_up_original_launcher_handle",
            "RecordedLauncherTests.test_wrong_generation_never_signals_live_decoy",
            "RecordedLauncherTests.test_missing_generation_is_nonpass_without_signal",
            "RecordedLauncherTests.test_without_ack_native_wrapper_expires_without_exec",
            "RecordedLauncherTests.test_direct_user_preserves_identity_and_input",
            "RecordedLauncherTests.test_two_successful_root_launches_can_remain_live",
            "RecordedLauncherTests.test_preexisting_durable_record_never_releases_sudo",
            "RecordedLauncherTests.test_parent_acquisition_failure_never_acknowledges_launcher",
            "RecordedLauncherTests.test_launcher_fields_are_published_before_ack_failure",
            "RecordedLauncherTests.test_root_fields_are_published_before_ack_failure",
            "RecordedLauncherTests.test_control_replacement_preserves_authenticated_fields_and_foreign_files",
            "RecordedLauncherTests.test_corrupted_self_cannot_be_acknowledged",
            "RecordedLauncherTests.test_failure_after_root_ack_retains_target_cleanup_authority",
            "RecordedLauncherTests.test_missing_launcher_self_resumed_after_deadline_never_enters_sudo",
            "RecordedLauncherTests.test_missing_root_self_resumed_after_deadline_never_enters_target",
            "RecordedLauncherTests.test_missing_user_self_resumed_after_deadline_never_enters_target",
            "RecordedLauncherTests.test_parent_eof_before_ack_never_releases_command",
            "RecordedLauncherTests.test_parent_eof_before_root_ack_never_releases_target",
            "RecordedLauncherTests.test_parent_eof_before_user_ack_never_releases_target",
            "RecordedLauncherTests.test_correct_generation_terminates_real_child",
            "RecordedLauncherTests.test_stopped_term_ignoring_child_requires_pidfd_kill",
            "RecordedLauncherTests.test_wrong_generation_cont_does_not_resume_decoy",
            "RecordedLauncherTests.test_active_invalid_identity_is_unknown",
            "RecordedLauncherTests.test_active_reports_replaced_separately_from_gone",
            "RecordedLauncherTests.test_proc_permission_failure_is_unknown_without_signal",
            "RecordedLauncherTests.test_pidfd_failure_retains_pending_authenticated_identity",
            "RecordedLauncherTests.test_native_refuses_wrong_ack_identity_phase_attempt_and_expiry",
            "RecordedLauncherTests.test_native_rejects_partial_symlink_and_preexisting_sidecars",
            "RecordedLauncherTests.test_native_rejects_ack_when_self_pid_does_not_match_captured_child",
            "RecordedLauncherTests.test_user_waiting_shell_exec_preserves_session_group_and_generation",
            "RecordedLauncherTests.test_strict_durable_reader_rejects_partial_file_without_ack",
            "RecordedLauncherTests.test_prepared_state_without_captured_pid_retains_control_authority",
            "RecordedLauncherTests.test_pending_failure_refuses_second_launch_without_overwriting_identity",
            "RecordedLauncherTests.test_duplicate_json_keys_are_not_accepted_as_complete_ack",
            "RecordedLauncherTests.test_correct_ack_consumed_after_deadline_cannot_exec",
            "RecordedLauncherTests.test_partial_launcher_self_has_no_ack_or_signal_authority",
            "RecordedLauncherTests.test_mismatched_launcher_self_has_no_ack_or_signal_authority",
            "RecordedLauncherTests.test_root_self_permission_change_prevents_ack",
            "RecordedLauncherTests.test_early_exit_without_self_never_enters_sudo",
            "RecordedLauncherTests.test_symlink_durable_file_is_preserved_without_sudo",
            "RecordedLauncherTests.test_untrusted_writable_parent_is_rejected_before_spawn",
            "RecordedLauncherTests.test_adoption_wrong_generation_never_signals_or_reaps_live_decoy",
            "RecordedLauncherTests.test_adoption_deduplicates_full_tuple_and_accepts_correct_generation",
            "RecordedLauncherTests.test_adoption_gone_original_does_not_acquire_reap_authority",
            "RecordedLauncherTests.test_adoption_unreadable_generation_closes_candidate_without_signal",
            "RecordedLauncherTests.test_authenticated_adoption_reaps_only_pinned_orphan",
            "RecordedLauncherTests.test_child_pidfd_acquisition_failure_ends_reaps_and_closes_owned_child",
            "RecordedLauncherTests.test_native_entrypoint_rejects_mandatory_skip",
            "RecordedLauncherTests.test_native_entrypoint_rejects_empty_selection",
            "RecordedLauncherTests.test_prepublication_orphan_is_drained_before_late_stop",
            "RecordedLauncherTests.test_subreaper_drain_repeats_after_second_reparenting_wave",
            "RecordedLauncherTests.test_subreaper_census_denial_is_nonpass_without_signal",
            "RecordedLauncherTests.test_subreaper_pidfd_acquisition_denial_is_nonpass_without_signal",
            "RecordedLauncherTests.test_subreaper_refuses_child_not_yet_reparented",
            "RecordedLauncherTests.test_subreaper_drain_preserves_live_owned_decoy_until_teardown",
        ],
    );
}

#[test]
fn owned_process_group_native_cases_preserve_bounded_authenticated_cleanup() {
    let cases = [
        "OwnedProcessGroupTests.test_child_diagnostic_failure_cannot_enter_parent_cleanup",
        "OwnedProcessGroupTests.test_late_zero_exit_after_supervisor_stop_is_timeout",
        "OwnedProcessGroupTests.test_session_readiness_after_deadline_never_releases_workload",
        "OwnedProcessGroupTests.test_normal_zero_passes_without_treating_zombie_group_signal_as_rescue",
        "OwnedProcessGroupTests.test_nonzero_status_cannot_pass",
        "OwnedProcessGroupTests.test_exited_leader_with_live_orphan_is_killed_reaped_and_nonpass",
        "OwnedProcessGroupTests.test_preexisting_adopted_zombie_is_nonpass_with_exact_exit",
        "OwnedProcessGroupTests.test_timeout_settles_term_ignoring_leader_and_child",
        "OwnedProcessGroupTests.test_supervisor_term_settles_term_ignoring_leader_and_child",
        "OwnedProcessGroupTests.test_binary_stdout_is_preserved_exactly",
        "OwnedProcessGroupTests.test_exec_failure_is_nonpass_with_original_wait_result",
        "OwnedProcessGroupTests.test_pidfd_refusal_settles_gated_child_without_executing_workload",
        "OwnedProcessGroupTests.test_prctl_refusal_prevents_any_child_launch",
        "OwnedProcessGroupTests.test_separately_owned_same_fixture_survives_group_cleanup",
    ];
    let mut args = vec!["-I", "tests/python/test_owned_process_group.py", "-v"];
    args.extend(cases);
    run_ok("python3", &args);
}

#[test]
fn abi_routing_driver_preserves_runtime_ownership_and_failure_evidence() {
    run_ok(
        "timeout",
        &[
            "--signal=TERM",
            "--kill-after=2",
            "40",
            "sh",
            "tests/shell/test_abi_routing_driver.sh",
        ],
    );
}

#[test]
fn ia32_lifecycle_native_cases_preserve_owned_launch_and_cleanup() {
    run_ok(
        "python3",
        &[
            "-I",
            "tests/python/test_ia32_lifecycle.py",
            "Ia32LifecycleTests.test_cleanup_output_failure_is_terminal_nonpass_after_owned_cleanup",
            "Ia32LifecycleTests.test_committed_transfer_is_not_owned_by_pending_finalizers",
            "Ia32LifecycleTests.test_completion_deadline_records_exact_exit_and_clears_owned_tuple",
            "Ia32LifecycleTests.test_completion_unknown_retains_exact_tuple_until_real_cleanup",
            "Ia32LifecycleTests.test_direct_user_launch_preserves_exact_identity_argv_stdin_and_exit9",
            "Ia32LifecycleTests.test_guard_adopted_before_arming_refuses_exec",
            "Ia32LifecycleTests.test_guard_execs_exact_target_with_pdeath_identity_hash_and_stdin",
            "Ia32LifecycleTests.test_guard_rejects_missing_collision_and_capability_bearing_target",
            "Ia32LifecycleTests.test_guard_rejects_wrong_parent_generation_and_setid_target",
            "Ia32LifecycleTests.test_hup_cleanup_is_single_entry_preserves_status_and_ends_child",
            "Ia32LifecycleTests.test_killed_foreground_timeout_status_does_not_prove_command_ended",
            "Ia32LifecycleTests.test_no_ack_pending_user_is_cancelled_ended_and_reaped",
            "Ia32LifecycleTests.test_parent_death_kills_execed_guard_but_foreign_sentinel_survives",
            "Ia32LifecycleTests.test_pending_finalizers_are_both_attempted",
            "Ia32LifecycleTests.test_prepared_missing_identity_is_nonpass_without_numeric_signal",
            "Ia32LifecycleTests.test_ready_before_stop_requires_authenticated_stopped_state_then_reaps",
            "Ia32LifecycleTests.test_real_cleanup_attempts_timeout_after_guard_failure_and_is_nonpass",
            "Ia32LifecycleTests.test_real_timeout_statuses_remain_distinct",
            "Ia32LifecycleTests.test_replaced_generation_is_nonpass_and_does_not_signal_live_process",
            "Ia32LifecycleTests.test_root_launch_transfers_launcher_and_process_generations_before_wait",
            "Ia32LifecycleTests.test_runner_rejects_empty_skipped_and_unknown_selection",
            "Ia32LifecycleTests.test_self_test_retains_all_fifteen_vectors",
            "Ia32LifecycleTests.test_setarch_style_exec_keeps_authenticated_target_identity",
            "Ia32LifecycleTests.test_timeout_stop_cont_and_kill_ends_guard_command_with_status137",
            "Ia32LifecycleTests.test_unknown_observation_is_nonpass_without_signal_or_wait",
            "Ia32LifecycleTests.test_user_and_root_committed_transfer_signal_is_adopted_by_cleanup",
        ],
    );
}

#[test]
fn oracle_lifecycle_uses_owned_bounded_cleanup_and_failure_receipts() {
    run_ok(
        "python3",
        &[
            "-I",
            "tests/python/test_oracle_lifecycle.py",
            "OracleLifecycleTests.test_workload_preserves_quoted_argv_and_fresh_identity",
            "OracleLifecycleTests.test_workload_fifo_disappearance_is_bounded",
            "OracleLifecycleTests.test_cleanup_helper_probes_and_kills_through_receipt_fd",
            "OracleLifecycleTests.test_cleanup_helper_keeps_pinned_instance_after_path_replacement",
            "OracleLifecycleTests.test_cleanup_helper_rejects_identity_and_missing_control",
            "OracleLifecycleTests.test_body_runs_probe_before_fifo_and_preserves_errexit",
            "OracleLifecycleTests.test_finalizer_runs_cleanup_checks_then_one_publication",
            "OracleLifecycleTests.test_actual_publication_refuses_existing_pending_entry",
            "OracleLifecycleTests.test_cleanup_refuses_unacknowledged_launch_and_orders_owned_cleanup",
            "OracleLifecycleTests.test_owned_child_wait_has_a_deadline",
            "OracleLifecycleTests.test_hung_descendant_and_observer_first_are_bounded",
            "OracleLifecycleTests.test_authentication_pins_actual_membership_and_rejects_mismatch",
            "OracleLifecycleTests.test_identity_query_error_never_enters_bare_wait_or_touches_foreign_process",
            "OracleLifecycleTests.test_repeated_signals_cannot_interrupt_bounded_finalization",
            "OracleLifecycleTests.test_reclaim_limits_transfer_to_known_root_output_scope",
            "OracleLifecycleTests.test_reclaim_rejects_inadmissible_selected_directory_before_descent",
            "OracleLifecycleTests.test_authenticated_scope_receipt_facts_are_explicit",
        ],
    );
}

#[test]
fn user_process_session_snapshot_only_tolerates_initial_disappearance() {
    run_ok(
        "python3",
        &[
            "-I",
            "tests/python/test_process_session_snapshot.py",
            "ProcessSessionSnapshotTests.test_healthy_member_is_retained",
            "ProcessSessionSnapshotTests.test_only_initial_disappearance_is_tolerated",
            "ProcessSessionSnapshotTests.test_other_initial_errors_reject_snapshot",
        ],
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
    if [ "$1" = -I ] && [ "$2" = - ]; then
        case ${4-} in
            ''|*[!0-9]*) command "$real_python" "$@"; return ;;
        esac
        "$real_python" -I - "$3" <<'PY'
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
if [ "$1" = -I ] && [ "$2" = - ] && [ "$#" -gt 6 ]; then
    case ${4-} in
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
if [ "$1" = -I ] && [ "$2" = - ] && [ "$#" -gt 6 ]; then
    case ${4-} in
        ''|*[!0-9]*) ;;
        *) [ -e "$PF_TEST_WORK/mutated" ||
    "$PF_TEST_REAL_PYTHON" -I - "$3" "$PF_TEST_WORK" <<'PY'
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
    // The oracle's refusal check: without it, `exit 77` alone is ambiguous
    // between the env-hygiene refusal and a missing prerequisite, and reordering
    // the two loops would silently restore that masking.
    assert!(
        driver.contains(r#"grep -Fq "refusing inherited RUSTFLAGS" "$self_root/early.err""#),
        "the lane02 self-test must assert which refusal it reached"
    );
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
fn task4_receipt_drivers_execute_behavioral_self_tests() {
    const COMMON_CASES: &[&str] = &[
        "complete-success-status-0-last-once",
        "input-mutation-rejected-nonzero-status-last-once",
        "cleanup-query-failure-rejected-nonzero-status-last-once",
        "existing-root-rejected-status-77-no-touch-before-body",
        "nonprivate-parent-rejected-status-77-no-touch-before-body",
        "symlink-root-rejected-status-77-no-touch-before-body",
        "foreign-root-rejected-status-77-no-touch-before-body",
        "canonical-caller-owned-0700-parent-and-absent-root-required",
        "campaign-is-canonical-root-dirname-not-env-override",
        "missing-ephemeral-identity-rejected-nonzero-status-last-once",
        "root-artifacts-work-device-inode-mutation-rejected",
        "exact-root-tree-and-0700-directory-modes-accepted",
        "unexpected-top-level-entry-rejected",
        "0600-evidence-config-and-retained-executables-validated",
        "0700-private-executable-only-while-run-validated",
        "status-0-written-once-last",
        "missing-status-rejected",
        "early-status-rejected",
        "duplicate-status-rejected",
        "changed-head-rejected",
        "changed-input-ledger-rejected",
        "foreign-terminal-artifact-rejected",
        "missing-capture-evidence-rejected",
        "missing-checker-evidence-rejected",
        "root-preflight-blocks-body-cargo-runtime",
        "lock-contention-status-77-blocks-body-cargo-runtime",
        "released-exact-lock-success-status-0",
        "0600-lock-identity-held-through-status-validated",
        "retained-fixture-tree-validated",
        "retained-status-sequence-validated",
        "retained-source-input-ledgers-validated",
    ];
    const LANE07_CASES: &[&str] = &[
        "freeze-CONFIG-PID_FILTER-CGROUP_FILTER-DESCRIPTORS-ASYNC_FUNCTIONS-MECH_SHAPE-ATTR_BOOL_BITS-TEMPLATE_TAIL-exact-accepted",
        "freeze-missing-rejected",
        "freeze-duplicate-rejected",
        "freeze-inventory-mutation-rejected",
        "g1-161-93-186-exact-accepted",
        "g1-missing-rejected",
        "g1-duplicate-rejected",
        "g1-cardinality-mutation-rejected",
        "g2-68-2-4-exact-accepted",
        "g2-missing-rejected",
        "g2-duplicate-rejected",
        "g2-cardinality-mutation-rejected",
        "g3-68-68-136-C_GenerateRandom-200000-exact-accepted",
        "g3-missing-rejected",
        "g3-duplicate-rejected",
        "g3-cardinality-mutation-rejected",
        "g3-call-mutation-rejected",
        "g4-988-104-208-inflight-9-start-failures-8-exact-accepted",
        "g4-missing-rejected",
        "g4-duplicate-rejected",
        "g4-cardinality-mutation-rejected",
        "g4-counter-mutation-rejected",
        "g5-988-104-208-calls-11-rv-failures-9-unregistered-6-async-orphans-1-exact-accepted",
        "g5-missing-rejected",
        "g5-duplicate-rejected",
        "g5-cardinality-mutation-rejected",
        "g5-counter-mutation-rejected",
    ];
    const LANE09_CASES: &[&str] = &[
        "broad-and-a-only-b-only-68-68-136-exact-accepted",
        "broad-cardinality-mutation-rejected",
        "leaf-cardinality-mutation-rejected",
        "broad-2-C_GetFunctionList-2-uncertainty-1-leaves-1-C_GetFunctionList-1-uncertainty-0-exact-accepted",
        "multiplier-function-uncertainty-mutation-rejected",
        "image-container-identity-mutation-rejected",
    ];
    const LANE10_CASES: &[&str] = &[
        "fork-68-68-136-C_CloseSession-4-C_Digest-20-C_DigestInit-20-C_Finalize-5-C_GetInfo-1-C_GetSlotList-4-C_Initialize-5-C_OpenSession-4-and-four-capability-rows-exact-accepted",
        "fork-cardinality-mutation-rejected",
        "fork-function-count-mutation-rejected",
        "C_GetFunctionList-bootstrap-relation-exact-accepted",
        "capability-row-cardinality-mutation-rejected",
        "scan-uncorroborated-1-relationship-exact-accepted",
        "scan-uncorroborated-relationship-mutation-rejected",
    ];
    const LANE11_CASES: &[&str] = &[
        "subset-oracle-and-both-state-files-absent-start-end-exact-accepted",
        "initial-isolation-state-rejected",
        "terminal-isolation-state-rejected",
        "equal-sibling-head-tree-clean-ledgers-exact-accepted",
        "sibling-head-tree-clean-ledger-mutation-rejected",
        "equal-venv-package-ledgers-exact-accepted",
        "venv-package-ledger-mutation-rejected",
        "nonoracle-total-change-accepted",
    ];
    const LANE14_CASES: &[&str] = &[
        "single-terminal-owner-and-bound-child-facts-exact-accepted",
        "nested-lane14-facts-interface-without-second-status-exact-accepted",
        "second-terminal-owner-rejected",
        "missing-nested-facts-rejected",
        "replaced-nested-facts-rejected",
        "p11scope-p11scope-discover-p11scope-discover-glibc-p11scope-discover-musl-exact-accepted",
        "executable-inventory-mutation-rejected",
        "softhsm-record-count-68-exact-accepted",
        "softhsm-record-count-mutation-rejected",
        "fixture-68-92-104-exact-accepted",
        "fixture-cardinality-mutation-rejected",
        "static-smoke-68-68-136-exact-accepted",
        "static-smoke-cardinality-mutation-rejected",
        "fixed-private-work-descendants-exact-accepted",
        "caller-path-overrides-rejected-before-mutation",
        "same-shell-single-finalizer-exact-accepted",
        "cleanup-failure-upgrades-one-status-written-last",
        "absolute-nested-work-and-legacy-defaults-exact-accepted",
        "untracked-build-input-rejected-status-77-no-touch-before-body",
        "recorded-tool-replaced-between-preflight-and-finalization-rejected",
        "path-change-resolving-a-different-binary-rejected",
        "literal-static-smoke-capture-path-exact-accepted",
        "decoy-observed-json-under-work-rejected",
        "aggregate-stdout-as-checker-evidence-rejected",
        "sealed-command-inventory-pinned-before-root-and-git-decisions",
        "sealed-environment-allowlist-exact-accepted",
        "forged-seal-marker-rejected",
        "inventory-wide-tool-ledger-exact-accepted",
        "sealed-bin-removed-after-terminal-status",
        "nightly-toolchain-closure-exact-accepted",
        "isolated-python-invocations-exact-accepted",
        "tab-or-newline-root-rejected-status-77",
    ];
    const LANE16_CASES: &[&str] = &[
        "never-68-68-136-one-timing-zero-loss-ambiguity-inflight-child-false-none-0-0-0-exact-accepted",
        "auto-68-68-136-one-timing-zero-loss-ambiguity-inflight-child-false-sigstop-confirmed-positive-partial-0-exact-accepted",
        "never-structural-row-mutation-rejected",
        "auto-structural-row-mutation-rejected",
        "never-call-timing-performance-change-accepted",
        "auto-call-timing-performance-change-accepted",
        "bare-observer-rejected",
        "path-observer-rejected",
        "outside-ROOT-work-target-release-observer-rejected",
        "cargo-not-Rust-1.88-rejected",
        "cargo-without-locked-workspace-release-rejected",
        "private-CARGO_TARGET_DIR-ROOT-work-target-exact-accepted",
        "missing-observer-identity-ledger-rejected",
        "missing-cargo-identity-ledger-rejected",
    ];

    let drivers = [
        (
            "lane02",
            "scripts/verify-task4-lane02.sh",
            "verify-task4-lane02 self-test: OK",
            None,
        ),
        (
            "lane07",
            "scripts/verify-induced-gaps.sh",
            "verify-induced-gaps Task 4 receipt self-test: OK",
            Some(LANE07_CASES),
        ),
        (
            "lane09",
            "scripts/matrix/verify-shared-layer.sh",
            "verify-shared-layer Task 4 receipt self-test: OK",
            Some(LANE09_CASES),
        ),
        (
            "lane10",
            "scripts/matrix/verify-fork-scope.sh",
            "verify-fork-scope Task 4 receipt self-test: OK",
            Some(LANE10_CASES),
        ),
        (
            "lane11",
            "scripts/matrix/verify-oracle.sh",
            "verify-oracle Task 4 receipt self-test: OK",
            Some(LANE11_CASES),
        ),
        (
            "lane14",
            "scripts/build-release.sh",
            "build-release Task 4 receipt self-test: OK",
            Some(LANE14_CASES),
        ),
        (
            "lane16",
            "scripts/verify-task4-lane16.sh",
            "verify-task4-lane16 Task 4 receipt self-test: OK",
            Some(LANE16_CASES),
        ),
    ];
    let mut failures = Vec::new();

    let guard = tempfile::tempdir().expect("create unconditional Task 4 command tripwires");
    for command in [
        "bpftool",
        "cargo",
        "docker",
        "file",
        "p11scope",
        "p11scope-discover",
        "rustup",
        "setpriv",
        "sudo",
        "systemctl",
        "systemd-run",
    ] {
        let path = guard.path().join(command);
        fs::write(
            &path,
            b"#!/bin/sh\nprintf '%s\\n' \"${0##*/}\" >> \"$P11SCOPE_TASK4_TRIPWIRE_LOG\"\nexit 97\n",
        )
        .expect("write Task 4 command tripwire");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make Task 4 command tripwire executable");
    }
    let lane14_guard = tempfile::tempdir().expect("create Lane 14 first-mutator tripwire");
    let lane14_rm = lane14_guard.path().join("rm");
    fs::write(
        &lane14_rm,
        b"#!/bin/sh\nprintf '%s\\n' \"${0##*/}\" >> \"$P11SCOPE_TASK4_TRIPWIRE_LOG\"\nexit 97\n",
    )
    .expect("write Lane 14 rm tripwire");
    fs::set_permissions(&lane14_rm, fs::Permissions::from_mode(0o700))
        .expect("make Lane 14 rm tripwire executable");

    // A comment or unreachable branch containing `--self-test` must not turn
    // off the guard. The first mutator is caught, its sentinel survives, and
    // set -e proves the later Cargo/product runtime commands are unreachable.
    let bypass = tempfile::tempdir().expect("create unreachable-dispatch fixture");
    let bypass_script = bypass.path().join("comment-only-self-test.sh");
    let bypass_log = bypass.path().join("tripwire.log");
    let protected = bypass.path().join("protected");
    let sentinel = protected.join("sentinel");
    fs::create_dir(&protected).expect("create protected fixture directory");
    fs::write(&sentinel, b"must survive byte-identical\n").expect("write protected sentinel");
    fs::write(
        &bypass_script,
        b"#!/bin/sh\nset -eu\n# --self-test\n[ \"${1-}\" = --unreachable ] && exit 0\nrm -rf \"$P11SCOPE_TASK4_PROTECTED\"\ncargo build\np11scope run\n",
    )
    .expect("write unreachable-dispatch fixture");
    let bypass_output = Command::new("/bin/sh")
        .arg(&bypass_script)
        .arg("--self-test")
        .env(
            "PATH",
            format!(
                "{}:{}:/usr/bin:/bin",
                lane14_guard.path().display(),
                guard.path().display()
            ),
        )
        .env("P11SCOPE_TASK4_TRIPWIRE_LOG", &bypass_log)
        .env("P11SCOPE_TASK4_PROTECTED", &protected)
        .output()
        .expect("run unreachable-dispatch fixture");
    assert_eq!(bypass_output.status.code(), Some(97));
    assert_eq!(read(bypass_log.to_str().unwrap()), "rm\n");
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"must survive byte-identical\n"
    );

    for (lane, script, marker, lane_cases) in drivers {
        let fixture = tempfile::tempdir().expect("create retained Task 4 self-test fixture");
        let report = fixture.path().join("report.tsv");
        let tripwire_log = fixture.path().join("tripwire.log");
        let mut command = Command::new("/bin/sh");
        command.args([script, "--self-test"]);
        let path = if lane == "lane14" {
            format!(
                "{}:{}:/usr/bin:/bin",
                lane14_guard.path().display(),
                guard.path().display()
            )
        } else {
            format!("{}:/usr/bin:/bin", guard.path().display())
        };
        command
            .env("PATH", path)
            .env("P11SCOPE_TASK4_TRIPWIRE_LOG", &tripwire_log)
            .env("P11SCOPE_TASK4_SELF_TEST_REPORT", &report)
            .env("CARGO", guard.path().join("cargo"))
            .env("DOCKER", guard.path().join("docker"))
            .env("RUSTUP", guard.path().join("rustup"))
            .env("SUDO", guard.path().join("sudo"));
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("run {lane} self-test: {error}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tripped = fs::read_to_string(&tripwire_log).unwrap_or_default();
        if !tripped.is_empty() {
            failures.push(format!(
                "{lane} ({script}) crossed the self-test boundary: {tripped:?}"
            ));
        }
        if !output.status.success() || !(stdout.contains(marker) || stderr.contains(marker)) {
            failures.push(format!(
                "{lane} ({script}): status={:?}, marker={marker:?}, stdout={stdout:?}, stderr={stderr:?}",
                output.status.code()
            ));
        }
        if let Some(lane_cases) = lane_cases {
            match fs::symlink_metadata(&report) {
                Ok(metadata) => {
                    if !metadata.file_type().is_file()
                        || metadata.nlink() != 1
                        || metadata.permissions().mode() & 0o777 != 0o600
                    {
                        failures.push(format!(
                            "{lane} retained report must be one mode-0600 regular file"
                        ));
                    }
                    let contents = fs::read_to_string(&report).unwrap_or_default();
                    let mut observed = BTreeMap::new();
                    for line in contents.lines() {
                        *observed.entry(line).or_insert(0usize) += 1;
                    }
                    for case in COMMON_CASES.iter().chain(lane_cases.iter()) {
                        let row = format!("{case}\tOK");
                        if observed.remove(row.as_str()) != Some(1) {
                            failures.push(format!(
                                "{lane} report must retain exactly one {row:?} result"
                            ));
                        }
                    }
                    if !observed.is_empty() {
                        failures.push(format!(
                            "{lane} report contains duplicate or uncontracted rows: {observed:?}"
                        ));
                    }
                }
                Err(error) => failures.push(format!(
                    "{lane} did not retain its fixture/status/ledger report: {error}"
                )),
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Task 4 receipt self-test contract failures:\n{}",
        failures.join("\n")
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
    assert_eq!(definitions["TAIL_CALLS"][FLAGS], 0);
    assert!(!definitions.contains_key("ATTR_BOOL_BITS"));
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

/// The frozen inventory in `scripts/check-bpf-map-defs.py` is what the G3
/// privacy lane, the induced-gaps lane, and the Lane 14 receipt compare a built
/// object against, so it must match the object this crate embeds — `--self-test`
/// only ever checked the freeze against itself. Under
/// `unsafe-unvalidated-metadata` the embedded object is the diagnostic one.
#[test]
fn frozen_policy_inventory_matches_embedded_object() {
    if cfg!(feature = "unsafe-unvalidated-metadata") {
        let parsed = aya_obj::Object::parse(p11scope::EBPF_OBJECT)
            .expect("parse the embedded diagnostic object");
        let btf = parsed.btf.expect("diagnostic global helpers require BTF");
        assert!(
            parsed.btf_ext.is_some(),
            "diagnostic function info is missing"
        );
        for helper in ["p11_decode_params", "p11_walk_template"] {
            btf.id_by_type_name_kind(helper, aya_obj::btf::BtfKind::Func)
                .unwrap_or_else(|error| {
                    panic!("missing diagnostic BTF function {helper}: {error}")
                });
        }
    }
    let directory = tempfile::tempdir().expect("temporary inventory directory");
    let object = directory.path().join("p11scope-ebpf");
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");
    let (variant, maps, programs) = if cfg!(feature = "unsafe-unvalidated-metadata") {
        ("diagnostic", 23, 18)
    } else {
        ("default", 22, 13)
    };
    let report = run_ok(
        "python3",
        &[
            "-I",
            "scripts/check-bpf-map-defs.py",
            "--inventory",
            variant,
            object.to_str().unwrap(),
        ],
    );
    // Printed, not just carried in the assert message: the hosted step runs with
    // --nocapture so this line is the wave's exit evidence in the job log.
    println!("{report}");
    assert!(
        report.contains(&format!(
            "inventory {variant}: maps={maps} programs={programs} OK"
        )),
        "{report}"
    );
    // The count line alone would still print if `--inventory` stopped validating,
    // so prove the same object is rejected against the other variant's freeze.
    let other = if variant == "default" {
        "diagnostic"
    } else {
        "default"
    };
    let control = Command::new("python3")
        .args([
            "-I",
            "scripts/check-bpf-map-defs.py",
            "--inventory",
            other,
            object.to_str().unwrap(),
        ])
        .output()
        .expect("run the inventory negative control");
    let reason = String::from_utf8_lossy(&control.stderr);
    assert!(
        !control.status.success() && reason.contains(&format!("{other} map inventory differs")),
        "the {other} freeze must reject the {variant} object BY COMPARING IT: any other \
         non-zero exit (an unknown variant, a missing file) would satisfy a bare status \
         check while nothing was compared. stderr was: {reason}"
    );
}

#[test]
fn descriptor_cookie_and_consumers_source_guard_rejects_contract_regressions() {
    let attach = read("src/attach.rs");
    let ebpf = read("crates/ebpf/src/main.rs");

    assert_static_descriptor_cookie_contract(&attach, &ebpf).unwrap();
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

    let template_second_start = ebpf
        .find("pub fn p11_entry_template_second(ctx: ProbeContext) -> u32 {")
        .expect("template-second entry must exist");
    let template_second_end = ebpf[template_second_start..]
        .find("fn store_start(")
        .map(|offset| template_second_start + offset)
        .expect("template-second entry must end before store_start");
    let template_second = &ebpf[template_second_start..template_second_end];
    let low_word_slot = "        slot,\n        _pad: 0,";
    assert_eq!(
        template_second.matches(low_word_slot).count(),
        1,
        "the negative control must target exactly the template-second key"
    );
    let mutated_template_second = template_second.replacen(
        low_word_slot,
        "        slot: cookie_descriptor(cookie_of(&ctx)),\n        _pad: 0,",
        1,
    );
    assert_ne!(
        template_second, mutated_template_second,
        "the template-second negative control must actually change the source"
    );
    let template_second_high_word_slot = format!(
        "{}{}{}",
        &ebpf[..template_second_start],
        mutated_template_second,
        &ebpf[template_second_end..]
    );
    let bypassed_primary_semantics = ebpf.replacen(
        "    let semantics = semantics_of(&ctx);\n    let mut storage = MaybeUninit::<CallStart>::uninit();",
        "    let semantics = SlotSemantics::COUNT_ONLY;\n    let mut storage = MaybeUninit::<CallStart>::uninit();",
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
}

#[test]
fn compiled_birth_and_interface_name_contracts() {
    let directory = tempfile::tempdir().expect("temporary discovery-flow object");
    let object = directory.path().join("p11scope-ebpf");
    fs::write(&object, p11scope::EBPF_OBJECT).expect("write embedded eBPF object");
    let variant = if cfg!(feature = "unsafe-unvalidated-metadata") {
        "unsafe"
    } else {
        "default"
    };
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "tests/python/test_discovery_flow_object.py",
            "--object",
        ])
        .arg(&object)
        .args(["--variant", variant])
        .output()
        .expect("execute compiled birth and interface-name contracts");
    assert!(
        output.status.success(),
        "discovery-flow contracts: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
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

    let assert_rejects_attach_mutation = |source: &str, message: &str| {
        assert!(
            assert_live_discovery_host_contract(
                source, &scope, &events, &hooks, &engine, &main, &run,
            )
            .is_err(),
            "{message}"
        );
    };
    let missing_second_slot_set = attach.replacen(
        "tails.set(TAIL_CALLS_TEMPLATE_SECOND_SLOT, second_fd, 0)?;",
        "tails.set(TAIL_CALLS_INTERFACE_WORKER_SLOT, second_fd, 0)?;",
        1,
    );
    assert_rejects_attach_mutation(
        &missing_second_slot_set,
        "TAIL_CALLS slot 1 publication must be required",
    );
    let missing_worker_readback = attach.replacen(
        "if actual_worker != Some(worker_id)",
        "if actual_second != Some(worker_id)",
        1,
    );
    assert_rejects_attach_mutation(
        &missing_worker_readback,
        "TAIL_CALLS worker readback must be required",
    );
    let worker_attach = attach.replacen(
        "let programs = expected_programs(object_has_unsafe);",
        "let programs = expected_programs(object_has_unsafe);\n        let _ = ebpf.program_mut(\"interface_list_worker\").attach(...);",
        1,
    );
    assert_rejects_attach_mutation(
        &worker_attach,
        "interface-list worker must not gain an attach site",
    );

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
    let engine = read("src/discovery/engine.rs");
    let classifier = between(
        &source,
        "fn classify_direct_interface(",
        "#[inline(never)]\nfn emit_export(",
    );
    assert!(
        classifier.contains("let mut bytes = [0u8; 9];"),
        "the ninth byte must distinguish an exact standard name from a longer prefix"
    );
    assert!(
        classifier.contains("read == 8 && bytes[..8] == *b\"PKCS 11\\0\""),
        "interface classification must require the exact eight-byte string"
    );

    let export_symbol = between(
        &source,
        "fn export_symbol_id(cookie: u64)",
        "fn export_state_key<",
    );
    assert!(export_symbol.contains("decode_export_attach_cookie(cookie)?"));
    assert!(!export_symbol.contains("as u32"));
    let export_key = between(&source, "fn export_state_key<", "fn insert_export_state(");
    assert_eq!(export_key.matches("bpf_get_attach_cookie").count(), 1);
    assert!(export_key.contains("export_symbol_id(attach_cookie)?"));
    assert!(export_key.contains("attach_cookie,"));
    let export_planning = between(
        &engine,
        "let cookie = if let Some(binding) = selection_binding",
        "collected.dynamic.push(DynamicExportWork",
    );
    assert!(export_planning.contains("export_attach_cookie(object.0, context_case_id, hook_id)"));
    assert!(export_planning.contains("collected.required_seed_complete = false"));
    assert!(export_planning.contains("self.mark_partial("));
    assert!(!export_planning.contains("unwrap_or(u64::from(hook_id))"));

    let function_return = between(
        &source,
        "pub fn function_list_return(ctx: RetProbeContext) -> u32 {",
        "#[uprobe]\npub fn interface_list_entry",
    );
    assert!(function_return.contains("export_symbol_id(key.attach_cookie)"));
    assert!(!function_return.contains("key.attach_cookie as u32"));

    let listed = between(
        &source,
        "pub fn interface_list_return(ctx: RetProbeContext) -> u32 {",
        "#[uretprobe]\npub fn interface_list_worker",
    );
    assert!(!listed.contains("while interface_index < 16"));
    assert!(!listed.contains("classify_direct_interface("));
    for marker in [
        "let active_count = count.min(u64::from(DISCOVERY_INTERFACES));",
        "if active_count == 0",
        "if state.arg0 == 0",
        "checked_add((active_count - 1) * layout.interface().stride as u64)",
        "interface_continuation_pack(count, 0, symbol_id)",
        "export_symbol_id(entry_key.attach_cookie)",
        "take_export_state(&ctx, scope.is_some())",
        "StateKey {",
        "attach_cookie: 0",
        "BPF_NOEXIST",
        "TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "fail_export_state(&key)",
    ] {
        assert!(listed.contains(marker), "return contract misses {marker}");
    }

    let worker = between(
        &source,
        "pub fn interface_list_worker(ctx: RetProbeContext) -> u32 {",
        "#[uprobe]\npub fn interface_entry",
    );
    assert_eq!(
        worker.matches("classify_direct_interface(").count(),
        1,
        "worker must own the sole direct classifier call"
    );
    assert!(
        !worker.contains("export_state_key(&ctx)"),
        "worker must use a fixed zero-cookie state key"
    );
    for marker in [
        "StateKey {",
        "pid_tgid: helpers::bpf_get_current_pid_tgid()",
        "attach_cookie: 0",
        "interface_continuation_unpack(state.arg1)",
        "DISCOVERY_STATE.get(&key)",
        "DISCOVERY_INTERFACES",
        "(u64::from(symbol_id) << 32)",
        "if active_count == 0",
        "checked_mul(layout.interface().stride as u64)",
        "interface_continuation_next(state.arg1)",
        "BPF_EXIST",
        "TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT)",
        "fail_export_state(&key)",
        "finish_export_state(&key)",
    ] {
        assert!(worker.contains(marker), "worker contract misses {marker}");
    }

    assert!(source.contains("while pointer_index < 104"));

    for path in ["src/render.rs", "src/trace.rs", "src/output.rs"] {
        assert!(
            !read(path).contains("send_signal_rc"),
            "private helper result escaped into {path}"
        );
    }
}

#[test]
fn selection_transport_never_carries_name_bytes() {
    let common = read("crates/ebpf-common/src/lib.rs");
    let source = read("crates/ebpf/src/main.rs");
    for marker in [
        "pub return_rv: u64",
        "pub request_flags: u64",
        "pub binding_id: u64",
        "DISCOVERY_VERSION_V3_2",
        "record.binding_id != 0",
    ] {
        assert!(
            common.contains(marker),
            "selection transport misses {marker}"
        );
    }
    let entry = between(
        &source,
        "pub fn interface_entry(ctx: ProbeContext)",
        "#[uretprobe]\npub fn interface_return",
    );
    for marker in [
        "classify_selection_name",
        "classify_selection_version",
        "arg_u64(&ctx, 3, layout)",
        "insert_selection_state",
    ] {
        assert!(entry.contains(marker), "selection entry misses {marker}");
    }
    let gate = entry
        .find("scope_auth()")
        .expect("selection entry must gate before reading arguments");
    let first_arg = entry
        .find("arg_u64(&ctx")
        .expect("selection entry must retain only classified scalar arguments");
    assert!(
        gate < first_arg,
        "selection scope must precede argument reads"
    );
    let aggregate = entry
        .find("FLAG_POLICY_AGGREGATE")
        .expect("selection entry must gate aggregate policy");
    assert!(
        aggregate < first_arg,
        "aggregate policy must precede argument reads"
    );
    let discovery_initializer = between(
        &source,
        "// TASK5_DISCOVERY_INITIALIZER_BEGIN",
        "// TASK5_DISCOVERY_INITIALIZER_END",
    );
    assert_eq!(
        discovery_initializer
            .matches("core::ptr::write_volatile(words.add(")
            .count(),
        115,
        "the record initializer must use exactly 115 ordered stores"
    );
    assert!(!entry.contains("arg3:"));
    assert!(entry.contains("arg0: pp_interface"));
    assert!(entry.contains("arg1: selection_request_word"));
    assert!(entry.contains("arg2: flags"));
    assert!(!entry.contains("bpf_probe_read_user_str"));
    assert!(!entry.contains("name_ptr"));
    let returned = between(
        &source,
        "pub fn interface_return(ctx: RetProbeContext)",
        "fn loader_cookie_of",
    );
    for marker in ["take_selection_state", "return_rv", "binding_id"] {
        assert!(
            returned.contains(marker),
            "selection return misses {marker}"
        );
    }
    assert!(returned.contains("classify_indirect_interface"));
    assert!(returned.contains("if rv != 0"));
    let unscoped_cleanup = returned
        .find("take_selection_state(&ctx, false)")
        .expect("out-of-scope return must remove owned selection state");
    let abi_cleanup = returned
        .find("discard_export_state(&key)")
        .expect("unknown-ABI return must remove owned selection state");
    let aggregate = returned
        .find("FLAG_POLICY_AGGREGATE")
        .expect("selection return must gate aggregate policy");
    let accepted_take = returned
        .find("let Some((key, state)) = take_selection_state(&ctx, scope.is_some())")
        .expect("accepted selection return must take its paired state");
    assert!(unscoped_cleanup < abi_cleanup && abi_cleanup < aggregate);
    assert!(aggregate < accepted_take);
    let aggregate_gate = &returned[aggregate..accepted_take];
    assert!(aggregate_gate.contains("return 0;"));
    assert!(!aggregate_gate.contains("classify_indirect_interface"));
    assert!(!aggregate_gate.contains("bpf_probe_read_user"));
    assert!(!aggregate_gate.contains("take_selection_state"));
    assert!(returned.contains("let scope = scope_auth();"));
    assert!(returned.contains("take_selection_state(&ctx, scope.is_some())"));
    assert!(returned.contains("let Some(scope) = scope else"));
    let nonzero = between(returned, "if rv != 0 {", "    } else {");
    assert!(!nonzero.contains("classify_indirect_interface"));
    assert!(!nonzero.contains("bpf_probe_read_user"));
    assert!(returned.contains("pause_eligible: rv == 0"));
    let insertion = between(
        &source,
        "fn insert_selection_state(",
        "fn take_selection_state(",
    );
    assert!(insertion.contains("BPF_NOEXIST"));
    assert!(insertion.contains("DISCOVERY_STATE.remove(&key)"));
    assert!(insertion.contains("DISCOVERY_COUNTER_EXPORT_STATE_FAILURES"));
    let indirect = between(
        &source,
        "fn classify_indirect_interface(",
        "#[inline(never)]\nfn emit_export(",
    );
    assert!(indirect.contains("read_word(address, layout)"));
    assert!(indirect.contains("classify_direct_interface"));
    let selection_key = between(
        &source,
        "fn selection_state_key<",
        "fn classify_selection_name(",
    );
    assert_eq!(selection_key.matches("bpf_get_attach_cookie").count(), 1);
    assert!(selection_key.contains("attach_cookie != 0"));
    assert!(!selection_key.contains("as u32"));
    assert!(!selection_key.contains(">>"));
    assert!(!selection_key.contains("&="));
    let assert_state_key_domains = |candidate: &str| {
        assert_eq!(candidate.matches("domain: STATE_DOMAIN_EXPORT").count(), 3);
        assert_eq!(
            candidate.matches("domain: STATE_DOMAIN_SELECTION").count(),
            1
        );
    };
    assert_state_key_domains(&source);
    let missing_selection_domain = source.replacen("domain: STATE_DOMAIN_SELECTION,", "", 1);
    assert!(
        std::panic::catch_unwind(|| assert_state_key_domains(&missing_selection_domain)).is_err()
    );
    let wrong_selection_domain = source.replacen(
        "domain: STATE_DOMAIN_SELECTION",
        "domain: STATE_DOMAIN_EXPORT",
        1,
    );
    assert!(
        std::panic::catch_unwind(|| assert_state_key_domains(&wrong_selection_domain)).is_err()
    );
    let request_name = between(
        &source,
        "fn classify_selection_name(",
        "fn classify_selection_version(",
    );
    let request_version = between(
        &source,
        "fn classify_selection_version(",
        "fn selection_request_word(",
    );
    assert!(request_name.contains("DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES"));
    assert!(request_version.contains("DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES"));
    let emitter = between(
        &source,
        "fn emit_export(payload: &ExportPayload",
        "#[inline(always)]\nfn classify_export",
    );
    assert_eq!(
        emitter.matches("while pointer_index < 104").count(),
        1,
        "export emission must have one bounded table walker"
    );
    for path in ["src/metrics.rs", "src/trace.rs", "src/output.rs"] {
        let consumer = read(path);
        assert!(!consumer.contains("request_flags"));
        assert!(!consumer.contains("binding_id"));
    }
}

#[test]
fn image_identity_native_control_refuses_invalid_and_exhausted_tickets() {
    let directory = tempfile::tempdir().expect("temporary native identity test");
    let binary = directory.path().join("helper-tests");
    let compile = Command::new("clang-18")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/image-identity/helper_tests.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .expect("execute clang-18 for native identity regression");
    assert!(
        compile.status.success(),
        "native compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(binary)
        .output()
        .expect("execute native identity regression");
    assert!(
        run.status.success(),
        "native identity regression failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn call_start_initializer_is_straight_line_and_caller_owned() {
    let source = read("crates/ebpf/src/main.rs");
    assert!(source.contains("#[inline(always)]\nfn record_aggregate_start("));
    let initializer = between(
        &source,
        "// CALL_START_INITIALIZER_BEGIN",
        "// CALL_START_INITIALIZER_END",
    );
    assert_eq!(
        initializer
            .matches("core::ptr::write_volatile(words.add(")
            .count(),
        36,
        "CallStart's full 288 bytes need 36 explicit qword stores"
    );
    assert!(
        !initializer.contains("for "),
        "initializer must stay loop-free"
    );
    for index in 0..36 {
        assert!(
            initializer.contains(&format!(
                "core::ptr::write_volatile(words.add({index}), 0u64);"
            )),
            "initializer misses qword {index}"
        );
    }

    let aggregate = between(
        &source,
        "fn record_aggregate_start(",
        "#[inline(always)]\nfn p11_entry_impl",
    );
    let normal = between(
        &source,
        "fn p11_entry_impl<",
        "#[uretprobe]\npub fn p11_return",
    );
    for caller in [aggregate, normal] {
        assert!(caller.contains("MaybeUninit::<CallStart>::uninit()"));
        assert!(caller.contains("zero_call_start(&mut storage)"));
        assert!(caller.contains("storage.assume_init_mut()"));
        assert!(!caller.contains("CallStart::default()"));
        assert!(!caller.contains("let mut start = CallStart {"));
    }
    for default in [
        "start.session = SESSION_NONE;",
        "start.mechanism = MECH_NONE;",
        "start.user_type = USER_TYPE_NONE;",
        "start.target_function = FUNCTION_NONE;",
        "start.capture = capture::MECHANISM_NONE | capture::OUTPUT_NONE;",
    ] {
        assert!(normal.contains(default), "normal start misses {default}");
        assert!(
            !aggregate.contains(default),
            "aggregate start gained {default}"
        );
    }
}

#[test]
fn decode_params_narrows_output_and_reports_failure_once() {
    let source = read("crates/ebpf/src/main.rs");
    let output_definition = between(
        &source,
        "struct ParamsOutput {",
        "const PARAMS_DECODE_FAILURE: u32",
    );
    for field in ["p0: u64", "p1: u64", "p2: u64"] {
        assert_eq!(output_definition.matches(field).count(), 1);
    }
    assert!(source.contains("const _: [(); 24] = [(); core::mem::size_of::<ParamsOutput>()];"));
    assert!(
        source.contains("core::mem::align_of::<ParamsOutput>() == core::mem::align_of::<u64>()")
    );
    for assertion in [
        "core::mem::offset_of!(ParamsOutput, p0) == 0",
        "core::mem::offset_of!(ParamsOutput, p1) == 8",
        "core::mem::offset_of!(ParamsOutput, p2) == 16",
        "core::mem::offset_of!(CallStart, p1) == core::mem::offset_of!(CallStart, p0) + 8",
        "core::mem::offset_of!(CallStart, p2) == core::mem::offset_of!(CallStart, p0) + 16",
    ] {
        assert!(
            source.contains(assertion),
            "missing layout assertion: {assertion}"
        );
    }
    assert!(source.contains("const PARAMS_DECODE_FAILURE: u32 = u32::MAX;"));

    let dispatcher = between(
        &source,
        "pub unsafe extern \"C\" fn p11_decode_params(",
        "fn decode_params_impl<",
    );
    let exported_decoder = between(
        &source,
        "const PARAMS_DECODE_FAILURE: u32",
        "pub unsafe extern \"C\" fn p11_decode_params(",
    );
    assert_eq!(exported_decoder.matches("#[unsafe(no_mangle)]").count(), 1);
    assert_eq!(exported_decoder.matches("#[inline(never)]").count(), 1);
    assert!(dispatcher.contains("word_bytes: u32,"));
    assert!(dispatcher.contains("output: *mut ParamsOutput,"));
    assert!(!dispatcher.contains("*mut CallStart"));
    assert!(dispatcher.contains(") -> u32 {"));
    let null_guard = dispatcher.find("if output.is_null()").unwrap();
    let width_guard = dispatcher.find("let is_ilp32 = match word_bytes").unwrap();
    let reference = dispatcher
        .find("let output = unsafe { &mut *output };")
        .unwrap();
    let first_read = dispatcher.find("decode_params_impl::<true>").unwrap();
    assert!(null_guard < width_guard && width_guard < reference && reference < first_read);
    assert!(dispatcher.contains("4 => true,"));
    assert!(dispatcher.contains("8 => false,"));
    assert!(dispatcher[null_guard..width_guard].contains("PARAMS_DECODE_FAILURE"));
    assert!(dispatcher[width_guard..reference].contains("PARAMS_DECODE_FAILURE"));
    assert!(dispatcher.contains("decode_params_impl::<true>(pmech, sh, output)"));
    assert!(dispatcher.contains("decode_params_impl::<false>(pmech, sh, output)"));

    let decoder = between(
        &source,
        "fn decode_params_impl<",
        "/// Walk at most `MAX_ATTRS` entries",
    );
    assert!(source.contains(
        "#[cfg(feature = \"unsafe-unvalidated-metadata\")]\n#[inline(never)]\nfn decode_params_impl<"
    ));
    assert!(decoder.contains("const IS_ILP32: bool"));
    assert!(!decoder.contains("layout: LinuxLayout"));
    assert!(
        decoder.contains("output: &mut ParamsOutput,")
            || decoder.contains("output: &mut ParamsOutput)")
    );
    assert!(decoder.contains(") -> u32 {"));
    assert!(decoder.contains(
        "let layout = if IS_ILP32 {\n        LinuxLayout::Ilp32\n    } else {\n        LinuxLayout::Lp64\n    };"
    ));
    assert!(!decoder.contains("capture_failure("));
    assert!(!decoder.contains("start."));
    assert!(decoder.contains("_ => return shape::NONE,"));
    assert!(decoder.contains("if pparam == 0 {\n        return shape::NONE;"));
    assert!(decoder.matches("PARAMS_DECODE_FAILURE").count() >= 6);
    for read in [
        "let r0 = read_word(a0, layout);",
        "let r1 = read_word(a1, layout);",
        "let r2 = read_word(a2, layout);",
    ] {
        assert_eq!(
            decoder.matches(read).count(),
            1,
            "decoder must retain {read}"
        );
    }
    assert!(
        decoder.find("let r0 = read_word(a0, layout);").unwrap()
            < decoder.find("let r1 = read_word(a1, layout);").unwrap()
    );
    assert!(
        decoder.find("let r1 = read_word(a1, layout);").unwrap()
            < decoder.find("let r2 = read_word(a2, layout);").unwrap()
    );
    let final_read = decoder.find("let r2 = read_word(a2, layout);").unwrap();
    for write in ["output.p0 = a;", "output.p1 = b;", "output.p2 = c;"] {
        assert_eq!(decoder.matches(write).count(), 1);
        assert!(final_read < decoder.find(write).unwrap());
    }
    assert!(decoder.find("output.p0 = a;").unwrap() < decoder.find("output.p1 = b;").unwrap());
    assert!(decoder.find("output.p1 = b;").unwrap() < decoder.find("output.p2 = c;").unwrap());
    assert!(decoder.contains("output.p2 = c;\n        out_shape"));

    let caller = between(
        &source,
        "let parameter_shape = unsafe { MECH_SHAPE.get(&mechanism) }",
        "if semantics.output_arg != ARG_NONE",
    );
    let decode_call = caller
        .split_once("                        Err(_) => {")
        .expect("mechanism read failure branch must follow parameter decoding")
        .0;
    assert_eq!(decode_call.matches("p11_decode_params(").count(), 1);
    assert!(decode_call.contains("layout.word_bytes() as u32"));
    assert!(decode_call.contains("(start as *mut CallStart)"));
    assert!(decode_call.contains(".add(core::mem::offset_of!(CallStart, p0))"));
    assert!(decode_call.contains(".cast::<ParamsOutput>()"));
    assert!(!decode_call.contains("&mut start.p0"));
    assert!(!decode_call.contains("MaybeUninit::<ParamsOutput>"));
    assert!(decode_call.contains("let decoded_shape = unsafe {"));
    assert!(decode_call.contains("shape::RSA_PKCS_PSS | shape::GCM_V220 | shape::GCM_V240 => {"));
    assert!(decode_call.contains("start.shape = decoded_shape;"));
    assert!(decode_call.contains("shape::NONE => {}"));
    assert!(decode_call.contains("_ => capture_failure(start),"));
    assert_eq!(decode_call.matches("capture_failure(start)").count(), 1);
}

#[test]
fn async_key_initialization_and_copy_are_fixed_and_guarded() {
    let source = read("crates/ebpf/src/main.rs");
    assert!(source.contains("const _: [(); 32] = [(); core::mem::size_of::<FunctionNameKey>()];"));
    assert!(
        source.contains("const _: () = assert!(core::mem::align_of::<FunctionNameKey>() >= 4);")
    );
    let initializer = between(
        &source,
        "// ASYNC_KEY_INITIALIZER_BEGIN",
        "// ASYNC_KEY_INITIALIZER_END",
    );
    assert_eq!(
        initializer
            .matches("core::ptr::write_volatile(words.add(")
            .count(),
        8
    );
    assert!(!initializer.contains("for "));
    for index in 0..8 {
        assert!(initializer.contains(&format!(
            "core::ptr::write_volatile(words.add({index}), 0u32);"
        )));
    }

    let capture = between(
        &source,
        "fn capture_async_target(",
        "#[uprobe]\npub fn p11_entry",
    );
    assert_eq!(capture.matches("bpf_probe_read_user_str(").count(), 1);
    assert!(capture.contains("(FUNCTION_NAME_MAX_BYTES + 2) as u32"));
    assert!(capture.contains("read <= 0 || read > (FUNCTION_NAME_MAX_BYTES + 1) as _"));
    assert!(capture.contains("let len = (read - 1) as usize;"));
    assert!(capture.contains("MaybeUninit::<FunctionNameKey>::uninit()"));
    assert!(capture.contains("zero_function_name_key(&mut key_storage);"));
    assert!(capture.contains("key_storage.assume_init_mut()"));
    assert!(capture.contains("key.len = len as u32;"));
    assert!(capture.contains("if $offset < len"));
    assert!(capture.contains("core::ptr::read_volatile(name.add($offset))"));
    assert!(
        capture.contains("core::ptr::write_volatile(key.bytes.as_mut_ptr().add($offset), byte)")
    );
    assert!(!capture.contains("FunctionNameKey::default()"));
    assert!(!capture.contains("for offset in"));
    assert_eq!(capture.matches("copy_name_byte!(").count(), 27);
    for offset in 0..27 {
        assert!(capture.contains(&format!("copy_name_byte!({offset});")));
    }
    assert!(capture.contains("ASYNC_FUNCTIONS.get(key)"));
    assert!(capture.contains("Some(id) => start.target_function = id"));
    assert!(capture.contains("None => capture_failure(start)"));
}

#[test]
fn template_walker_uses_narrow_global_output_and_preserves_read_policy() {
    let source = read("crates/ebpf/src/main.rs");
    let output = between(
        &source,
        "struct TemplateOutput {",
        "const TEMPLATE_WALK_FAILURE: u32",
    );
    for field in [
        "types: [u64; MAX_ATTRS]",
        "count: u32",
        "total: u32",
        "bools: u32",
        "seen: u32",
    ] {
        assert_eq!(
            output.matches(field).count(),
            1,
            "missing output field {field}"
        );
    }
    for layout in [
        "size_of::<TemplateOutput>() == 80",
        "align_of::<TemplateOutput>() == core::mem::align_of::<u64>()",
        "offset_of!(TemplateOutput, types) == 0",
        "offset_of!(TemplateOutput, count) == 64",
        "offset_of!(TemplateOutput, total) == 68",
        "offset_of!(TemplateOutput, bools) == 72",
        "offset_of!(TemplateOutput, seen) == 76",
        "offset_of!(CallStart, attr_types) == 96",
        "offset_of!(CallStart, attr_types1) == 176",
        "offset_of!(CallStart, capture) == 256",
    ] {
        assert!(source.contains(layout), "missing layout guard {layout}");
    }

    let exported = between(
        &source,
        "pub unsafe extern \"C\" fn p11_walk_template(",
        "fn walk_template<const TYPES_ONLY: bool, const SECOND: bool>(",
    );
    assert!(exported.contains("word_bytes: u32,"));
    assert!(exported.contains("output: *mut TemplateOutput,"));
    let null = exported.find("if output.is_null()").unwrap();
    let width = exported.find("let is_ilp32 = match word_bytes").unwrap();
    let reference = exported
        .find("let output = unsafe { &mut *output };")
        .unwrap();
    let dispatch = exported.find("walk_template_impl::<true>").unwrap();
    assert!(null < width && width < reference && reference < dispatch);
    assert!(exported.contains("walk_template_impl::<false>"));

    let adapter = between(
        &source,
        "fn walk_template<const TYPES_ONLY: bool, const SECOND: bool>(",
        "fn walk_template_types<",
    );
    assert!(adapter.contains("assert!(!TYPES_ONLY || !SECOND)"));
    let types_branch = adapter.find("if TYPES_ONLY {").unwrap();
    let projection = adapter.find("(start as *mut CallStart)").unwrap();
    assert!(types_branch < projection);
    assert!(adapter.contains("walk_template_types::<true>(ptemplate, count, start)"));
    assert!(adapter.contains("walk_template_types::<false>(ptemplate, count, start)"));
    assert!(adapter[..projection].contains("return;"));
    assert!(adapter.contains("(start as *mut CallStart)"));
    assert!(adapter.contains("offset_of!(CallStart, attr_types1)"));
    assert!(adapter.contains("offset_of!(CallStart, attr_types)"));
    assert!(adapter.contains(".cast::<TemplateOutput>()"));
    assert!(!adapter.contains("MaybeUninit::<TemplateOutput>"));
    assert!(!adapter.contains("&mut start.attr_types"));
    assert!(adapter.contains("p11_walk_template("));
    assert_eq!(adapter.matches("capture_failure(start)").count(), 1);

    let types = between(&source, "fn walk_template_types<", "fn walk_template_impl<");
    assert!(types.contains("const IS_ILP32: bool"));
    assert!(types.contains("start: &mut CallStart"));
    assert!(types.contains("start.attr_total = total;"));
    assert!(types.contains("start.attr_types[i] = attr_type;"));
    assert!(types.contains("start.attr_count += 1;"));
    assert_eq!(types.matches("capture_failure(start);").count(), 2);
    assert_eq!(types.matches("break;").count(), 3);
    for forbidden in [
        "TemplateOutput",
        "ATTR_BOOL_BITS",
        "read_word_pair",
        "pvalue",
        "len != 1",
        "attr_bools",
    ] {
        assert!(
            !types.contains(forbidden),
            "types-only helper gained {forbidden}"
        );
    }
    let types_read = types
        .find("let Ok(attr_type) = read_word(base, layout)")
        .unwrap();
    let types_write = types.find("start.attr_types[i] = attr_type;").unwrap();
    let types_count = types.find("start.attr_count += 1;").unwrap();
    assert!(types_read < types_write && types_write < types_count);

    let implementation = between(&source, "fn walk_template_impl<", "fn arg_u64(");
    assert!(source.contains(
        "#[cfg(feature = \"unsafe-unvalidated-metadata\")]\n#[inline(never)]\nfn walk_template_impl<"
    ));
    assert!(implementation.contains("const IS_ILP32: bool"));
    assert!(!implementation.contains("const TYPES_ONLY"));
    assert!(!implementation.contains("const SECOND"));
    assert!(!implementation.contains("layout: LinuxLayout"));
    assert!(implementation.contains("output: &mut TemplateOutput"));
    assert!(implementation.contains(") -> u32"));
    assert!(implementation.contains(
        "let layout = if IS_ILP32 {\n        LinuxLayout::Ilp32\n    } else {\n        LinuxLayout::Lp64\n    };"
    ));
    assert_eq!(implementation.matches("for i in 0..MAX_ATTRS").count(), 1);
    assert!(!implementation.contains("if TYPES_ONLY"));
    for marker in [
        "let total = count.min(u32::MAX as u64) as u32;",
        "output.total = total;",
        "let width = layout.word_bytes() as u64;",
        "ptemplate.checked_add((i as u64) * width * 3)",
        "let Ok(t) = read_word(base, layout)",
        "output.types[i] = attr_type;",
        "output.count += 1;",
        "if attr_type > u32::MAX as u64",
        "ATTR_BOOL_BITS.get(&bool_type)",
        "let Ok([pvalue, len]) = read_word_pair(value_addr, layout)",
        "if len != 1",
        "bpf_probe_read_user(pvalue as *const u8)",
        "output.seen |= mask;",
        "output.bools |= mask;",
    ] {
        assert!(implementation.contains(marker), "walker misses {marker}");
    }
    assert_eq!(
        implementation
            .matches("return TEMPLATE_WALK_FAILURE;")
            .count(),
        5
    );
    assert!(!implementation.contains("capture_failure("));
    assert!(implementation.trim_end().ends_with("0\n}"));
    let type_read = implementation
        .find("let Ok(t) = read_word(base, layout)")
        .unwrap();
    let type_write = implementation.find("output.types[i] = attr_type;").unwrap();
    let count_write = implementation.find("output.count += 1;").unwrap();
    let high_bit = implementation
        .find("if attr_type > u32::MAX as u64")
        .unwrap();
    assert!(type_read < type_write && type_write < count_write && count_write < high_bit);
    assert!(
        high_bit
            < implementation
                .find("ATTR_BOOL_BITS.get(&bool_type)")
                .unwrap()
    );
    assert!(
        implementation
            .find("ATTR_BOOL_BITS.get(&bool_type)")
            .unwrap()
            < implementation
                .find("let Ok([pvalue, len]) = read_word_pair(value_addr, layout)")
                .unwrap()
    );
    assert!(
        implementation
            .find("let Ok([pvalue, len]) = read_word_pair(value_addr, layout)")
            .unwrap()
            < implementation.find("if len != 1").unwrap()
    );
    assert!(
        implementation.find("if len != 1").unwrap()
            < implementation
                .find("bpf_probe_read_user(pvalue as *const u8)")
                .unwrap()
    );
}

#[test]
fn failed_export_arguments_invalidate_older_pairing_state() {
    let source = read("crates/ebpf/src/main.rs");
    for (start, end, key) in [
        (
            "pub fn function_list_entry(ctx: ProbeContext) -> u32 {",
            "#[uretprobe]\npub fn function_list_return",
            "export_state_key(&ctx)",
        ),
        (
            "pub fn interface_list_entry(ctx: ProbeContext) -> u32 {",
            "#[uretprobe]\npub fn interface_list_return",
            "export_state_key(&ctx)",
        ),
        (
            "pub fn interface_entry(ctx: ProbeContext) -> u32 {",
            "#[uretprobe]\npub fn interface_return",
            "selection_state_key(&ctx)",
        ),
    ] {
        let entry = between(&source, start, end);
        let last_argument = entry.rfind("arg_u64(&ctx").expect("target argument read");
        let cleanup = entry[last_argument..]
            .find("discard_export_state(&key)")
            .map(|offset| last_argument + offset)
            .expect("argument failure must discard an older pairing");
        let counter = entry[last_argument..]
            .find("DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES")
            .map(|offset| last_argument + offset)
            .expect("argument failure must remain disclosed");
        assert!(entry[last_argument..cleanup].contains(key));
        assert!(
            cleanup < counter,
            "pairing cleanup must precede the refusal counter"
        );
    }
}

#[test]
fn scope_auth_layout_and_padding_are_explicit_and_initialized() {
    let source = read("crates/ebpf/src/main.rs");
    let assert_contract = |source: &str| {
        let struct_start = source
            .find("#[derive(Clone, Copy)]\n#[repr(C)]\nstruct ScopeAuth {")
            .expect("ScopeAuth must use an explicit C layout");
        let scope = between(&source[struct_start..], "struct ScopeAuth {", "\n}\n");
        let compact: String = scope
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert_eq!(
            compact, "flags:u64,tgid:u32,_pad:u32,generation_token:u64,",
            "ScopeAuth field order and widths must match the worker qword copy"
        );
        for assertion in [
            "const _: [(); 24] = [(); core::mem::size_of::<ScopeAuth>()];",
            "const _: [(); 0] = [(); core::mem::offset_of!(ScopeAuth, flags)];",
            "const _: [(); 8] = [(); core::mem::offset_of!(ScopeAuth, tgid)];",
            "const _: [(); 12] = [(); core::mem::offset_of!(ScopeAuth, _pad)];",
            "const _: [(); 16] = [(); core::mem::offset_of!(ScopeAuth, generation_token)];",
        ] {
            assert!(
                source.contains(assertion),
                "missing ScopeAuth layout assertion: {assertion}"
            );
        }
        let constructors = between(source, "fn scope_auth()", "fn scope_flags()");
        assert_eq!(
            constructors.matches("ScopeAuth {").count(),
            2,
            "scope_auth must retain both constructors"
        );
        assert_eq!(
            constructors.matches("_pad: 0").count(),
            2,
            "both ScopeAuth constructors must initialize padding"
        );
    };
    assert_contract(&source);

    let missing_repr = source.replacen("#[repr(C)]\nstruct ScopeAuth", "struct ScopeAuth", 1);
    assert!(
        std::panic::catch_unwind(|| assert_contract(&missing_repr)).is_err(),
        "ScopeAuth must reject implicit Rust layout"
    );
    let missing_pad = source.replacen(
        "                _pad: 0,\n                generation_token: token,",
        "                generation_token: token,",
        1,
    );
    assert!(
        std::panic::catch_unwind(|| assert_contract(&missing_pad)).is_err(),
        "ScopeAuth must reject an omitted constructor pad initializer"
    );
}

#[test]
fn live_discovery_direct_classification_precedes_record_reservation() {
    let source = read("crates/ebpf/src/main.rs");
    let assert_contract = |source: &str| {
        let classifier = between(
            source,
            "#[inline(never)]\nfn classify_direct_interface(",
            "#[inline(never)]\nfn emit_export(",
        );
        assert!(
            !classifier.contains("reserve_discovery("),
            "direct interface classification must finish before reservation"
        );
        let classify_read = classifier
            .find("bpf_probe_read_user")
            .expect("direct classifier must resolve interface fields");
        let classify_emit = classifier
            .find("emit_export(")
            .expect("direct classifier must converge on the record emitter");
        assert!(classify_read < classify_emit);

        let listed = between(
            source,
            "pub fn interface_list_return(ctx: RetProbeContext) -> u32 {",
            "#[uprobe]\npub fn interface_entry",
        );
        listed
            .find("classify_direct_interface(")
            .expect("interface list return must call the direct classifier");
        assert!(
            !listed.contains("emit_export("),
            "interface list return must not dispatch through runtime-polymorphic emit_export"
        );
    };
    assert_contract(&source);

    let without_classifier_inline = source.replacen(
        "#[inline(never)]\nfn classify_direct_interface(",
        "fn classify_direct_interface(",
        1,
    );
    assert!(
        std::panic::catch_unwind(|| assert_contract(&without_classifier_inline)).is_err(),
        "classifier inline attribute mutation must be rejected"
    );
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
    let checker = read("scripts/check-live-discovery-object.py");
    assert!(checker.contains("[\"llvm-objdump\", \"-dr\", \"--print-imm-hex\", str(path)]"));

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
fn policy_specific_ebpf() {
    const KEY_SIZE: usize = 1;
    let definitions = embedded_map_definitions();
    let symbols = embedded_symbols();

    assert_eq!(definitions["ASYNC_FUNCTIONS"][KEY_SIZE], 32);
    assert_eq!(definitions["TAIL_CALLS"][0], 3);
    assert_eq!(definitions["TAIL_CALLS"][3], 2);
    assert!(
        !definitions.contains_key("ATTR_BOOL_BITS"),
        "default object contains unsafe-only map ATTR_BOOL_BITS"
    );
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
    let checker = read("scripts/check-canary-evidence.py");
    let assert_lanes = between(
        &canaries,
        "assert_lanes() {",
        "\n}\n\nif [ \"${1-}\" = \"--self-test\" ]",
    );
    assert!(
        !assert_lanes.contains("<<'PY'")
            && canaries.contains("python3 -I scripts/check-canary-evidence.py")
            && canaries.contains("python3 -I tests/python/test_canary_evidence.py"),
        "canary shell gate must delegate to checked-in isolated Python entry points"
    );
    assert!(
        checker.contains("def main(argv=None):")
            && checker.contains("if __name__ == \"__main__\":")
            && checker.contains("SCRIPT_DIR = Path(__file__).resolve().parent"),
        "canary checker must retain an import-safe explicit entry point and source root"
    );
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
    for bits in ["32", "64"] {
        let output = Command::new("python3")
            .args([
                "-I",
                "tests/python/test_canary_evidence.py",
                "--target-bits",
                bits,
                "HostileStartTests",
                "FaultStartTests",
                "RingLayoutTests",
                "EventLayoutTests",
                "RawSafeEventTests",
                "RawDiagnosticEventTests",
                "ImportSafetyTests",
                "OwnedMapWrapperTests",
                "TargetWidthPathTests",
                "-v",
            ])
            .output()
            .unwrap_or_else(|error| panic!("run native canary tests for {bits}-bit: {error}"));
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "native {bits}-bit canary tests failed: {report}"
        );
        for family in [
            "HostileStartTests",
            "FaultStartTests",
            "RingLayoutTests",
            "EventLayoutTests",
            "RawSafeEventTests",
            "RawDiagnosticEventTests",
            "ImportSafetyTests",
            "OwnedMapWrapperTests",
            "TargetWidthPathTests",
        ] {
            assert!(
                report.contains(family),
                "native {bits}-bit suite missed {family}: {report}"
            );
        }
        assert!(
            report.contains("Ran 12 tests") && !report.contains("skipped="),
            "native {bits}-bit suite must execute every required case: {report}"
        );
    }
    let empty = Command::new("python3")
        .args([
            "-I",
            "tests/python/test_canary_evidence.py",
            "--target-bits",
            "64",
            "RequiredCanaryFamilyThatDoesNotExist",
        ])
        .output()
        .expect("run missing native canary selector");
    assert!(
        !empty.status.success(),
        "missing required native canary family must be nonpass"
    );
    let mut sentinels = canary_literals(&read("scripts/fixtures/canary_workload.c"));
    sentinels.extend(canary_literals(&read(
        "scripts/fixtures/privacy-stack-workload.c",
    )));
    assert_eq!(sentinels.len(), 21, "unexpected fixture sentinel inventory");
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
        ("CHANGELOG.md", "Public `run`, owned-child live discovery"),
        ("docs/superpowers/plans/ROADMAP.md", "exact-tip CI"),
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

    for path in ["README.md", "docs/usage.md"] {
        let document = read(path)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        assert!(
            document.contains("exact-tip runtime qualification") && document.contains("pending"),
            "{path} must say exact-tip runtime qualification is pending"
        );
    }
    for path in ["CHANGELOG.md", "docs/superpowers/plans/ROADMAP.md"] {
        let document = read(path)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        assert!(
            document.contains("exact-tip ci") && document.contains("pending"),
            "{path} must say exact-tip CI is pending"
        );
    }

    for path in ["README.md", "docs/usage.md", "CHANGELOG.md"] {
        assert!(read(path).to_lowercase().contains("unreleased"), "{path}");
    }
    let usage = read("docs/usage.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    assert!(
        usage.contains("runtime qualification") && usage.contains("remain pending"),
        "docs/usage.md must keep runtime qualification pending"
    );
    let roadmap = read("docs/superpowers/plans/ROADMAP.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    assert!(
        roadmap.contains("ci remains pending")
            && roadmap.contains("no release or security-clearance claim applies yet"),
        "ROADMAP must keep CI and release authority pending"
    );
    let readme = read("README.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    assert!(
        readme.contains("previous frozen mvp passed")
            && readme.contains("current candidate")
            && readme.contains("exact-tip runtime qualification")
            && readme.contains("pending"),
        "README must distinguish historical evidence from current exact-tip qualification"
    );
    assert!(
        usage.contains("frozen pre-w3 candidate")
            && usage.contains("not been repeated on the current candidate")
            && usage.contains("exact-tip runtime qualification")
            && usage.contains("pending"),
        "docs/usage.md must distinguish historical evidence from current exact-tip qualification"
    );
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

#[test]
fn production_bpf_toolchain_is_frozen() {
    let toolchain = read("crates/ebpf/rust-toolchain.toml");
    let build = read("build.rs");
    let ci = read(".github/workflows/ci.yml");

    assert!(toolchain.contains("channel = \"nightly-2026-05-20\""));
    assert!(build.contains("\"+nightly-2026-05-20\""));
    assert!(!build.contains("\"+nightly\""));
    assert!(ci.contains("toolchain install nightly-2026-05-20 "));
    assert!(!ci.contains("toolchain install nightly "));
}

/// The lines of the YAML block introduced by `header`, up to the next line at the
/// same or shallower indent. Blank lines and comments belong to the block.
///
/// Three guards used to bound the checks job as "everything before
/// `\n  archive-log:\n`", which is not the same thing: inserting a job between the
/// two put it inside, and renaming `archive-log` fell back to the whole file, in
/// both cases silently widening a claim that is about one job. Panicking on a
/// missing header is the point — a silent fallback is what made that invisible.
fn block_under<'a>(source: &'a str, header: &str) -> &'a str {
    let indent = header.len() - header.trim_start().len();
    let opened = format!("\n{header}\n");
    let start = source
        .find(&opened)
        .unwrap_or_else(|| panic!("ci.yml has no {:?} block", header.trim()))
        + opened.len();
    let body = &source[start..];
    let end = body
        .match_indices('\n')
        .map(|(at, _)| at + 1)
        .find(|at| {
            let line = body[*at..].split('\n').next().unwrap_or_default();
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#') && line.len() - trimmed.len() <= indent
        })
        .unwrap_or(body.len());
    &body[..end]
}

/// The `checks-and-e2e` job, bounded by its own header rather than by whatever
/// happens to follow it.
fn checks_job(ci: &str) -> &str {
    block_under(ci, "  checks-and-e2e:")
}

/// The directories the lane derivations walk, asserted to be all of them: a lane
/// dropped into a new subdirectory would otherwise get no UNRUN line and no
/// hosted self-test while the block still claims "every privileged script under
/// scripts/". `__pycache__` is generated, never tracked.
fn script_dirs() -> Vec<&'static str> {
    let mut found: Vec<String> = fs::read_dir("scripts")
        .expect("walk scripts")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name != "__pycache__")
        .collect();
    found.sort();
    assert_eq!(
        found,
        ["fixtures", "matrix"],
        "a new directory under scripts/: teach the UNRUN and self-test derivations \
         about it, or a privileged lane there is invisible to both"
    );
    vec!["scripts", "scripts/matrix"]
}

/// A step's command, with the `- run:` / `run:` shape (a `- name:` label puts the
/// command on its own line) and any trailing YAML comment normalised away, so
/// neither a label nor a comment changes what a test believes ran.
fn command_of(line: &str) -> Option<&str> {
    let line = line
        .split_once(" #")
        .map_or(line, |(code, _)| code.trim_end());
    line.trim()
        .strip_prefix("- run: ")
        .or_else(|| line.trim().strip_prefix("run: "))
}

/// The default embedded object is covered by the ordinary `cargo test` gate;
/// the diagnostic object exists only under `unsafe-unvalidated-metadata`, so it
/// needs its own hosted step — one test, not the whole target
/// (`immutable_policy_maps` correctly asserts `ATTR_BOOL_BITS` is absent).
#[test]
fn hosted_pipeline_checks_the_diagnostic_inventory() {
    let ci = read(".github/workflows/ci.yml");
    // Position is not load-bearing and pinning it made an innocent edit to a
    // neighbouring step panic inside `between()`; the step only has to be in the
    // checks job, after the clippy gate it complements.
    let checks = checks_job(&ci);
    let lines: Vec<&str> = checks.lines().map(str::trim).collect();
    let clippy_at = lines
        .iter()
        .position(|line| {
            command_of(line).is_some_and(|call| {
                call == "cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings"
            })
        })
        .expect("the checks job must run the clippy gate");
    // `--nocapture` so the inventory report the wave cites as exit evidence
    // actually reaches the hosted log.
    let prefix = "cargo +1.88 test --locked --features unsafe-unvalidated-metadata --test artifact_contracts -- ";
    let command_at = lines
        .iter()
        .position(|line| line.starts_with(prefix))
        .expect("the checks job must run the diagnostic-object inventory test");
    assert!(
        command_at > clippy_at,
        "the diagnostic-object inventory test must run after the clippy gate"
    );
    // libtest exits 0 when a filter matches nothing, and a rename, an `#[ignore]`,
    // a `#[cfg]` that excludes the test, or a deleted `#[test]` all empty the
    // filter identically. Guarding the source text against each spelling is
    // whack-a-mole, so the step itself must prove a test ran.
    assert!(
        lines.iter().any(|line| {
            *line
                == r#"grep -q "^test result: ok. 1 passed" "$RUNNER_TEMP/diagnostic-inventory.log""#
        }),
        "the diagnostic-object step must assert that exactly one test ran"
    );
    // `|| true` on that line, or continue-on-error on the step, voids the proof
    // while leaving every pin above satisfied.
    assert!(
        !ci.lines().map(str::trim).any(|line| {
            // As a step's first key it renders `- continue-on-error:`, and YAML
            // allows whitespace before the colon.
            let key = line.strip_prefix("- ").unwrap_or(line);
            !key.starts_with('#')
                && key
                    .split_once(':')
                    .is_some_and(|(name, _)| name.trim() == "continue-on-error")
        }),
        "no step in this workflow may set continue-on-error: it would turn a failed \
         proof into a green job"
    );
    let arguments = lines[command_at].strip_prefix(prefix).unwrap_or_default();
    for token in ["--exact", "--nocapture"] {
        assert!(
            arguments
                .split_whitespace()
                .any(|argument| argument == token),
            "the diagnostic step needs {token}: --nocapture puts the inventory report in \
             the log, --exact stops a future test whose name merely starts with this one \
             from making the step report `2 passed` and turning the job red"
        );
    }
    assert!(
        arguments.ends_with(r#"| tee "$RUNNER_TEMP/diagnostic-inventory.log""#),
        "the report must be teed to the log that the grep proof reads"
    );
    // The filter must still name a real test, so this fails at `cargo test` time
    // rather than only on the runner.
    let filter = lines[command_at]
        .strip_prefix(prefix)
        .unwrap_or_default()
        .split_whitespace()
        .find(|token| !token.starts_with('-'))
        .expect("the diagnostic step carries a test filter");
    let source = read("tests/artifact_contracts.rs");
    let (before, _) = source
        .split_once(&format!("\nfn {filter}()"))
        .unwrap_or_else(|| {
            panic!(
                "ci.yml filters the hosted diagnostic-object step on `{filter}`, \
                 which names no test"
            )
        });
    // Whitelist the attribute rather than blacklisting spellings: `#[ignore]`,
    // `#[ignore = "..."]`, `#[cfg(...)]` and `#[cfg_attr(..., ignore)]` all empty
    // the filter, and enumerating them is a losing game.
    let attributes: Vec<&str> = before
        .rsplit("\n}\n")
        .next()
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("#["))
        .collect();
    assert_eq!(
        attributes,
        ["#[test]"],
        "`{filter}` must carry exactly #[test] and nothing else: a conditional attribute \
         empties the hosted filter, and this whitelist is deliberately strict"
    );
}

/// Owner decision 2026-09-05: every validator self-test runs hosted, by a
/// mechanical rule rather than an enumerated list, so a lane cannot be added
/// without its hosted self-test. The rule keys on the literal `--self-test`, so
/// a validator spelling its flag any other way is invisible to it — the one that
/// does (`task4-fcntl-experiment.py`, positional `self-test`) is covered inside
/// the ordinary `cargo test` gate by `tests/task4_build_subjects.rs`. `scripts/gates.sh` is the local entry point
/// that only invokes the others; `lib.sh`, `cleanup-traps.sh` and `fixtures/`
/// are not validators.
#[test]
fn hosted_pipeline_runs_every_unprivileged_self_test() {
    let ci = read(".github/workflows/ci.yml");
    // The claim is about this job, so only its steps count.
    let ci_lines: Vec<&str> = checks_job(&ci).lines().map(str::trim).collect();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for dir in script_dirs() {
        for entry in fs::read_dir(dir).expect("walk scripts") {
            let path = entry.expect("script entry").path();
            let path = path.to_str().expect("utf-8 script path");
            let interpreter = match path.rsplit_once('.') {
                Some((_, "sh")) => "",
                Some((_, "py")) => "python3 -I ",
                _ => continue,
            };
            if [
                "scripts/gates.sh",
                "scripts/lib.sh",
                "scripts/cleanup-traps.sh",
            ]
            .contains(&path)
                // A comment merely mentioning --self-test does not make the
                // script self-test-capable; without this, a line explaining that
                // a script has no self-test would demand a hosted step for it.
                || !read(path).lines().any(|line| {
                    !line.trim_start().starts_with('#') && line.contains("--self-test")
                })
            {
                continue;
            }
            expected.insert(format!("- run: {interpreter}{path} --self-test"));
        }
    }
    // Two-way, so a count floor is not doing the work: a capable script with no
    // step and a step whose script lost its self-test both fail here. The second
    // direction matters — a stale step keeps printing green for an oracle that no
    // longer exists.
    let hosted: BTreeSet<String> = ci_lines
        .iter()
        .map(|line| {
            line.split_once(" #")
                .map_or(*line, |(code, _)| code.trim_end())
        })
        .filter_map(|line| {
            line.strip_prefix("- run: ")
                .or_else(|| line.strip_prefix("run: "))
        })
        .filter(|call| call.ends_with(" --self-test"))
        .map(|call| format!("- run: {call}"))
        .collect();
    assert_eq!(
        hosted, expected,
        "the hosted `--self-test` steps must be exactly the self-test-capable scripts"
    );
}

/// A green hosted job must never imply a privileged or container lane ran.
/// The pipeline names every such lane verbatim as `UNRUN: <path>` (the
/// `verify-capability-tier.sh` idiom) in the log and the job summary, as its
/// first step after checkout so a later failure cannot suppress the list. The
/// set is derived here — every privileged script under `scripts/` minus the
/// ones the job runs
/// in full — and the label says whether the script's `--self-test` runs in
/// this job, so a lane whose self-test is hosted is not mislabelled as absent.
#[test]
fn hosted_pipeline_names_every_unrun_privileged_lane() {
    let ci = read(".github/workflows/ci.yml");
    // A heuristic in both directions: it reads words, so an unprivileged script
    // whose prose happens to say "kind" is flagged, and a lane needing only
    // `setcap` or `runuser` is not. It errs toward declaring more UNRUN, which is
    // the honest direction; the set it produces is pinned exactly below.
    let is_privileged = |script: &str| {
        read(script)
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .any(|line| {
                line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|word| {
                        matches!(
                            word,
                            "sudo"
                                | "docker"
                                | "podman"
                                | "kind"
                                | "kubectl"
                                | "bpftool"
                                | "capsh"
                                | "nsenter"
                                | "unshare"
                        )
                    })
            })
    };
    // A python helper names sudo and bpftool in its docstrings and in the evidence
    // it parses, so scanning its own text calls every validator privileged. What
    // actually makes one privileged is how it is invoked:
    // `sudo python3 -I scripts/dump-owned-bpf-maps.py`.
    let sudo_invoked = |script: &str| {
        // Its own text counts only for a quoted `sudo` argv token; the docstrings
        // and parsed evidence that made a plain word-scan useless never quote it.
        if read(script).lines().map(str::trim).any(|line| {
            !line.starts_with('#') && (line.contains("\"sudo\"") || line.contains("'sudo'"))
        }) {
            return true;
        }
        let file = script.rsplit('/').next().unwrap_or(script).to_string();
        ["scripts", "scripts/matrix"].iter().any(|dir| {
            fs::read_dir(dir)
                .expect("walk scripts")
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|e| e == "sh"))
                .any(|entry| {
                    read(entry.path().to_str().unwrap_or_default())
                        .lines()
                        .map(str::trim)
                        .any(|line| {
                            !line.starts_with('#')
                                && line.contains("sudo")
                                && line.contains(file.as_str())
                        })
                })
        })
    };
    // Fail closed. This reads two forms only — `- run: <script>` is a full lane
    // run, `- run: <script> --self-test` is not — and every other way of invoking
    // a lane (`bash scripts/x.sh`, `./scripts/x.sh`, a call inside a `run: |`
    // block, an extra argument) is refused rather than quietly treated as "did
    // not run in full", which would leave this job printing `UNRUN:` for a lane
    // that had just run. Comments and the block's own lines are not invocations.
    // Both extensions, because the derivation below covers `.py` too — a `.py`
    // lane run in full would otherwise stay on the UNRUN list. The split is the
    // inverse of a path character rather than a list of separators: enumerating
    // separators is what let `scripts/x.sh;` through, and the list was still
    // missing backtick, brackets and comma one round later.
    let is_lane = |token: &str| {
        token.contains("scripts/") && (token.ends_with(".sh") || token.ends_with(".py"))
    };
    let names_lane = |line: &str| {
        line.split(|c: char| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '/' | '_' | '-'))
            .any(is_lane)
    };
    let mut hosted_full: BTreeSet<&str> = BTreeSet::new();
    // Scoped to the checks job: the label says "runs in this job", so a step that
    // exists only in another job must not satisfy it. The full-run sweep below
    // stays on the whole file — a lane run from any job has run.
    let checks = checks_job(&ci);
    let run_calls: BTreeSet<&str> = checks
        .lines()
        .map(str::trim)
        .filter_map(command_of)
        .collect();
    // A lane named anywhere but the checks job is refused rather than credited as
    // a full run: `hosted_full` feeds the `scope:` line, whose text is a claim
    // about THIS job, so the two must be scoped alike.
    for line in ci.replacen(checks, "", 1).lines().map(str::trim) {
        let line = line
            .split_once(" #")
            .map_or(line, |(code, _)| code.trim_end());
        assert!(
            line.starts_with('#') || !names_lane(line),
            "a lane is named outside the checks job: {line:?}. The UNRUN and scope \
             claims are about that job alone; running a lane elsewhere needs the \
             derivation taught about it first"
        );
    }
    for line in checks.lines().map(str::trim) {
        // Trailing YAML comments are not invocations.
        let line = line
            .split_once(" #")
            .map_or(line, |(code, _)| code.trim_end());
        if line.starts_with('#') || line.starts_with("UNRUN: ") || line.starts_with("scope: ") {
            continue;
        }
        if !names_lane(line) {
            continue;
        }
        // `- name:` above a step is an ordinary edit, so accept the bare `run:` form.
        let call = line
            .strip_prefix("- run: ")
            .or_else(|| line.strip_prefix("run: "))
            .unwrap_or_default();
        let call = call.strip_prefix("python3 -I ").unwrap_or(call);
        let (command, tail) = call.split_once(' ').unwrap_or((call, ""));
        match (command.starts_with("scripts/") && is_lane(command), tail) {
            (true, "") => {
                hosted_full.insert(command);
            }
            (true, "--self-test") => {}
            _ => panic!(
                "unreadable lane invocation {line:?}: the UNRUN derivation reads only \
                 `run: <script>` and `run: <script> --self-test`, optionally via \
                 `python3 -I`. If this line does not invoke a lane, keep the script path \
                 out of it; if it does, the derivation cannot tell, and the block would \
                 be wrong about what ran"
            ),
        }
    }
    let mut expected = BTreeSet::new();
    for dir in script_dirs() {
        for entry in fs::read_dir(dir).expect("walk scripts") {
            let path = entry.expect("script entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let path = path.to_str().expect("utf-8 script path").to_string();
            // Not just `verify-` lanes, and not just shell: `build-release.sh`
            // (the W8 release receipt), `attach-pod.sh`, `bench-overhead.sh` and
            // `dump-owned-bpf-maps.py` are privileged too, and each has a hosted
            // `--self-test` whose green step would otherwise stand unqualified.
            if (name.ends_with(".sh") || name.ends_with(".py"))
                && !["gates.sh", "lib.sh", "cleanup-traps.sh"].contains(&name)
                // Lazily: the walk also yields `scripts/fixtures/`, which is a
                // directory and cannot be read as a file.
                && (if name.ends_with(".py") {
                    sudo_invoked(&path)
                } else {
                    is_privileged(&path)
                })
                && !hosted_full.contains(path.as_str())
            {
                expected.insert(path);
            }
        }
    }

    // Match the action, not its version: bumping checkout is an innocent edit,
    // and pinning the tag made it fail here with a message about step order.
    // `- uses:` or, under a `- name:` label, a bare `uses:` — match the key.
    let after_checkout = checks
        .split_once("uses: actions/checkout@")
        .and_then(|(_, rest)| rest.split_once('\n'))
        .map(|(_, rest)| rest)
        .expect("the checks job must check out the repository");
    assert!(
        after_checkout
            .lines()
            .take_while(|line| !line.starts_with("      # UNRUN lanes begin"))
            // checkout's own `with:` block is indented deeper and is not a step.
            .all(|line| line.starts_with("        ")),
        "the UNRUN lanes block must be the first step after checkout"
    );
    let block = between(&ci, "# UNRUN lanes begin", "# UNRUN lanes end");
    let block_lines: Vec<&str> = block.lines().map(str::trim).collect();
    let named: BTreeSet<String> = block_lines
        .iter()
        .filter_map(|line| line.strip_prefix("UNRUN: "))
        .flat_map(|line| {
            line.split_whitespace()
                .filter(|t| t.starts_with("scripts/"))
        })
        .map(str::to_string)
        .collect();
    assert_eq!(
        named, expected,
        "UNRUN lines must name exactly the derived lane set"
    );
    // The block's positive claim is `scope:`, not a status: it is printed before
    // any of the work it names has run, so on a failed run it would otherwise be
    // archived asserting steps that never executed. Its lane list is derived in
    // both directions — it can neither omit a lane the job runs nor claim one it
    // does not.
    let scope_line = block_lines
        .iter()
        .find(|line| line.starts_with("scope: "))
        .expect("the block must also state this job's scope");
    let scope_named: BTreeSet<&str> = scope_line
        .split_whitespace()
        .map(|token| token.trim_end_matches(','))
        .filter(|token| token.starts_with("scripts/"))
        .collect();
    assert_eq!(
        scope_named, hosted_full,
        "the scope: line must name exactly the lanes this job runs in full"
    );
    // The rest of that line is prose, so pin the steps it claims.
    // Full strings: "test --locked" alone was also matched by the diagnostic
    // step, so deleting the workspace test gate left this claim standing.
    for gate in [
        "fmt --all -- --check",
        "check --locked --workspace --all-targets",
        "test --locked --workspace --all-targets",
        "clippy --locked --workspace --all-targets -- -D warnings",
    ] {
        assert!(
            checks
                .lines()
                .map(str::trim)
                .filter_map(command_of)
                .any(|call| call == format!("cargo +1.88 {gate}")),
            "the scope: line claims the {gate} gate, which no step runs"
        );
    }
    for path in &expected {
        for line in block_lines
            .iter()
            .filter(|line| line.contains(path.as_str()))
        {
            assert!(
                line.starts_with("UNRUN: "),
                "{path} appears in the block without the UNRUN: prefix: {line:?}"
            );
        }
        let interpreter = if path.ends_with(".py") {
            "python3 -I "
        } else {
            ""
        };
        let self_test = format!("{interpreter}{path} --self-test");
        let note = if run_calls.contains(self_test.as_str()) {
            "only its unprivileged self-test runs in this job"
        } else {
            "no self-test"
        };
        let expected_line = format!(
            "UNRUN: {path} (privileged/container lane body UNRUN hosted; {note}; local run needs owner approval)"
        );
        assert!(
            block_lines.contains(&expected_line.as_str()),
            "missing verbatim lane line: {expected_line}"
        );
    }
    assert!(
        block.contains(">>\"$GITHUB_STEP_SUMMARY\""),
        "the UNRUN block must append to the job summary"
    );
    // Step summaries are not archived; the job log is, and the whole archive-log
    // job exists to retain it. Dropping this `cat` would silently empty it.
    assert!(
        block_lines.contains(&"cat \"$RUNNER_TEMP/lanes.txt\""),
        "the UNRUN block must also print the list to the job log"
    );
    // A command substitution inside the heredoc cannot trip `set -e`, so a failed
    // rev-parse would render the exit anchor blank on a green step.
    assert!(
        block.contains("TREE=$(git rev-parse") && block.contains("tree $TREE"),
        "the tree hash must be assigned before the heredoc, not substituted inside it"
    );
}

/// A step cannot read its own job's log, and a `tee` wrapper would break every
/// exact-line pin above, so a second job fetches the finished job's log through
/// the Actions API and keeps it as a run artifact. Its token gets `actions:
/// read` and nothing else; the top-level `contents: read` and the checks job
/// stay as they are.
#[test]
fn hosted_pipeline_retains_the_job_log() {
    let ci = read(".github/workflows/ci.yml");
    let checks = checks_job(&ci);
    let archive = block_under(&ci, "  archive-log:");
    // Comments and blank lines are not permissions; a trailing comment on one is
    // not part of its value either.
    fn permission_lines(block: &str) -> Vec<&str> {
        block
            .lines()
            .map(|line| {
                line.split_once(" #")
                    .map_or(line, |(code, _)| code.trim_end())
            })
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .collect()
    }
    assert_eq!(
        permission_lines(block_under(&ci, "permissions:")),
        ["  contents: read"],
        "the workflow default must stay exactly contents: read — checks-and-e2e has no \
         job-level block, so it inherits this while building third-party crates"
    );
    assert!(
        !checks.contains("    permissions:"),
        "checks-and-e2e must not gain a job-level permissions block"
    );
    assert_eq!(
        permission_lines(block_under(archive, "    permissions:")),
        ["      actions: read"],
        "archive-log must hold exactly one permission, actions: read"
    );
    for required in [
        "    needs: checks-and-e2e\n",
        // Not always(): a cancelled run must not publish a truncated log under
        // the same artifact name as a complete one.
        "    if: ${{ !cancelled() }}\n",
        "- uses: actions/upload-artifact@",
        "if-no-files-found: error\n",
        "/actions/jobs/$JOB_ID/logs\"",
        "for attempt in ",
        // Without this the loop's hardcoded exit number is load-bearing: shortening
        // the attempt list would fall through with the empty file `gh api` created.
        // A simple command, not an `&&` list: only this form aborts the step.
        r#"test -s "$RUNNER_TEMP/checks-and-e2e.log""#,
        // An attempt that wrote nothing must not count as success: the retry
        // window answers 200 with an empty body, and `if-no-files-found: error`
        // only checks that the file exists.
        "&& [ -s \"$RUNNER_TEMP/checks-and-e2e.log\" ]; then",
    ] {
        assert!(archive.contains(required), "archive-log lacks {required:?}");
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
            "drain_events(\n                session,"
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
        "let plan_changed = if detach.is_ok()",
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
    use p11scope::render::{
        DiscoveredModule, DiscoveryEvidence, Evidence, InterfaceSelection, ObjectSummary,
    };

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
        abi_refusals: 0,
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
        semantic_history_drops: 0,
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
        task_uprobe_link_losses: 0,
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
        interface_selection: InterfaceSelection::default(),
        attach_mechanisms: vec!["per-offset"],
        pid_descendant_gaps: 0,
        multi_rebuild_gaps: 0,
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
        "facts: render::CaptureFacts,",
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
fn live_discovery_provider_macro_covers_all_104_table_slots() {
    let provider = read("tests/fixtures/live-discovery-provider.c");
    let macro_body = between(
        &provider,
        "#define PROVIDER_FUNCTIONS(X) \\",
        "\n\nstatic P11ScopeTable",
    );
    let names = macro_body
        .split("X(")
        .skip(1)
        .map(|entry| entry.split(')').next().expect("macro entry name"))
        .collect::<Vec<_>>();
    assert_eq!(
        names.len(),
        104,
        "provider function macro slot count changed"
    );
    assert_eq!(names[3], "P11ScopeSlot3");
    assert_eq!(names[103], "P11ScopeSlot103");
}

#[test]
fn live_discovery_fixtures_have_two_byte_identities_and_three_surfaces() {
    let provider = read("tests/fixtures/live-discovery-provider.c");
    let driver = read("tests/fixtures/live-discovery-driver.c");
    let validator = read("scripts/check-live-discovery-evidence.py");
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
    assert!(
        provider.contains("P11SCOPE_FIXTURE_INTERFACES")
            && provider.contains("P11SCOPE_FIXTURE_MAX_INTERFACES 17")
            && provider.contains("CK_INTERFACE interfaces[P11SCOPE_FIXTURE_MAX_INTERFACES]"),
        "provider must bind the exact four-value interface-count knob with a fixed bound"
    );
    assert!(
        driver.contains("P11SCOPE_FIXTURE_INTERFACES")
            && driver.contains("P11SCOPE_FIXTURE_MAX_INTERFACES 17")
            && driver.contains("CK_INTERFACE interfaces[P11SCOPE_FIXTURE_MAX_INTERFACES]"),
        "driver must validate interface counts with a fixed bound"
    );
    assert!(
        validator.contains("    \"P11SCOPE_FIXTURE_INTERFACES\","),
        "the interface-count knob must be manifest-declared"
    );
    for value in ["0", "1", "16", "17"] {
        let accepted = format!("strcmp(value, \"{value}\") == 0");
        assert_eq!(
            provider.matches(&accepted).count(),
            1,
            "provider accepted-count vocabulary changed for {value}"
        );
        assert_eq!(
            driver.matches(&accepted).count(),
            1,
            "driver accepted-count vocabulary changed for {value}"
        );
    }
    for source in [&provider, &driver] {
        assert!(
            !source.contains("strcmp(value, \"2\")"),
            "unsupported interface count entered the fixture vocabulary"
        );
    }
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
    assert!(
        provider.contains("static CK_INTERFACE provider_interface;")
            && provider.contains("provider_interface.pFunctionList = published_table();"),
        "C_GetInterface storage must not look like a discovered interface before the call"
    );
    // One driver source, both load kinds, and the frozen lane modes.
    assert!(
        driver.contains("#if defined(P11SCOPE_DRIVER_NEEDED)"),
        "one driver source must serve DT_NEEDED and dlopen load kinds"
    );

    let directory = tempfile::tempdir().expect("temporary fixture build directory");
    let provider_output = directory.path().join("provider-exported.so");
    let driver_output = directory.path().join("driver-dlopen");
    let provider_build = Command::new("gcc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC"])
        .arg("-DP11SCOPE_EXPORT_TABLES=1")
        .args(["-shared", "-Wl,-z,defs", "-o"])
        .arg(&provider_output)
        .arg("tests/fixtures/live-discovery-provider.c")
        .output()
        .expect("compile exported live-discovery provider");
    assert!(
        provider_build.status.success(),
        "provider build failed: {}",
        String::from_utf8_lossy(&provider_build.stderr)
    );
    let driver_build = Command::new("gcc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC"])
        .args(["-o"])
        .arg(&driver_output)
        .arg("tests/fixtures/live-discovery-driver.c")
        .args(["-ldl", "-pthread"])
        .output()
        .expect("compile live-discovery dlopen driver");
    assert!(
        driver_build.status.success(),
        "driver build failed: {}",
        String::from_utf8_lossy(&driver_build.stderr)
    );
    let provider_path = provider_output.to_str().expect("provider path is UTF-8");
    for requested in ["0", "1", "16", "17"] {
        let output = Command::new(&driver_output)
            .args(["dlopen", provider_path])
            .env("P11SCOPE_FIXTURE_INTERFACES", requested)
            .output()
            .expect("execute interface-count fixture row");
        assert!(
            output.status.success(),
            "interface count {requested} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

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
fn live_discovery_post_gate_reads_after_done_marker() {
    let driver = read("tests/fixtures/live-discovery-driver.c");
    let done = driver
        .find("emit(\"P11SCOPE_FIXTURE driver done\\n\");")
        .expect("driver must emit its existing done marker");
    let post_gate = driver
        .find("const char *post_gate = getenv(\"P11SCOPE_FIXTURE_POST_GATE\");")
        .expect("driver must expose the optional post-call gate");
    let post_read = post_gate
        + driver[post_gate..]
            .find("read(STDIN_FILENO, &byte, 1)")
            .expect("post-call gate must read exactly one byte");
    assert!(
        done < post_read,
        "post-call gate must read only after the successful-call done marker"
    );
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
        "set -eu\nWORK={0}/work\nKUBECONFIG=$WORK/kubeconfig\nIMAGE=kind.local/test:unique\nCLUSTER=test-unique\nEVIDENCE={0}/evidence\nFACTS=$EVIDENCE/facts.log\nLANE13_TEST={0}\nmkdir -m 700 $EVIDENCE; : > $FACTS; chmod 600 $FACTS\nIMAGE_CREATED= CLUSTER_CREATED=\ndocker() {{ printf '%s\\n' \"$*\" >> $LANE13_TEST/docker.calls; case \"$1 $2\" in 'image inspect') [ \"$3\" = \"$IMAGE\" ] && [ -e $LANE13_TEST/image.created ] || [ \"$3\" = ubuntu:24.04 ] || return 1; if [ \"$3\" = ubuntu:24.04 ]; then printf '[{{\"Id\":\"base\",\"RepoDigests\":[\"ubuntu@sha256:base\"],\"RootFS\":{{\"Layers\":[\"a\",\"b\"]}}}}]\\n'; else printf '[{{\"Id\":\"work\",\"RepoDigests\":[\"work@sha256:work\"],\"RootFS\":{{\"Layers\":[\"a\",\"b\",\"c\"]}}}}]\\n'; fi;; pull) : > $LANE13_TEST/base.pulled;; build) printf '%s\\n' \"$*\" | grep -Fq -- --pull=false; : > $LANE13_TEST/image.created;; *) return 9;; esac; }}\nkind() {{ printf '%s\\n' \"$*\" >> $LANE13_TEST/kind.calls; case $1 in get) :;; create) : > $LANE13_TEST/cluster.created;; *) return 9;; esac; }}\ncurl() {{ if [ \"$1\" = --version ]; then printf 'curl 8.4.0\\n'; return; fi; printf '%s\\n' \"$*\" >> $LANE13_TEST/curl.calls; out= url=; while [ \"$#\" -gt 0 ]; do case $1 in --output) out=$2; shift 2;; --write-out) shift 2;; *) url=$1; shift;; esac; done; case $url in https://github.com/*) :;; *) return 9;; esac; /bin/cp -- \"$D2_RELEASE_FIXTURES/${{out##*/}}\" \"$out\"; printf '%s' 'https://release-assets.githubusercontent.com/asset?secret=x'; }}\nkubectl() {{ printf '%s\\n' \"$*\" >> $LANE13_TEST/kubectl.calls; [ \"$1\" = apply ] && [ \"$2\" = -f ] && [ -f \"$3\" ] && [ \"$4\" = -o ] && [ \"$5\" = name ]; case $3 in *://*) return 9;; esac; printf 'service/example\\n'; }}\n{1}\nmkdir $WORK\nlane13_preflight\nlane13_record_base_and_build\n[ \"$IMAGE_CREATED\" = 1 ]\nlane13_create_cluster\n[ \"$CLUSTER_CREATED\" = 1 ]\nlane13_fetch_release https://github.com/knative/serving/releases/download/v1.23.0/serving-crds.yaml serving-crds.yaml\n[ ! -e $WORK/releases/serving-crds.yaml ]\ngrep -Fqx service/example $FACTS\ngrep -Fq 'release_effective=https://release-assets.githubusercontent.com/asset' $FACTS\ngrep -Fq input_sha256= $FACTS\ngrep -Fq docker_version= $FACTS\n[ \"$(wc -l < $LANE13_TEST/curl.calls)\" -eq 2 ]\n[ \"$(wc -l < $LANE13_TEST/kubectl.calls)\" -eq 1 ]\ngrep -Fq -- --pull=false $LANE13_TEST/docker.calls\nrm -f $LANE13_TEST/docker.calls $LANE13_TEST/kind.calls\n: > $WORK/collision\nif lane13_preflight; then exit 97; fi\n[ ! -e $LANE13_TEST/docker.calls ]\n[ ! -e $LANE13_TEST/kind.calls ]\n",
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
        .env(
            "D2_RELEASE_FIXTURES",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/lane13-evidence/releases"),
        )
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
    unsorted|sorted|duplicate|malformed|empty|nofinal|blank|control|nonascii|failure) /bin/cp -- "$D2_RELEASE_FIXTURES/${{out##*/}}" "$out"; printf 'https://github.com/knative/serving/releases/download/knative-v1.23.0/serving-crds.yaml\n0\n' ;;
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
        .env(
            "D2_RELEASE_FIXTURES",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/lane13-evidence/releases"),
        )
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
LANE13_START_LEDGER_ESTABLISHED=0
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
    if lane13_record_facts start; then
        LANE13_START_LEDGER_ESTABLISHED=1
    else
        lane13_start_ledger_status=$?
        exit "$lane13_start_ledger_status"
    fi
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
        "done\npython3 -I scripts/check-live-discovery-evidence.py --self-test",
    );
    let live_gate_loop = between(
        &gates,
        "# if the CLI cannot even read a target, nothing below is worth waiting for.\nfor gate in ",
        "done\n",
    );
    // The checks job, not a byte-frozen window: the end marker used to be one
    // specific self-test step, so reordering steps inside the block panicked in
    // `between()` on an innocent edit. The set itself is proved two-way by
    // `hosted_pipeline_runs_every_unprivileged_self_test`; this test only needs
    // presence, and "exactly one" still holds job-wide.
    let ci_self_test_block = checks_job(&ci);
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
    // The induced-gaps driver mirrors the capability-tier idiom: one labelled
    // standalone live call carrying its Task 4 receipt-contract argument (an
    // absent path under a fresh private mktemp -d root), never the generic loop.
    let induced_live_call = r#"scripts/verify-induced-gaps.sh "$(mktemp -d "${TMPDIR:-/tmp}/p11scope-gates-XXXXXX")/induced-gaps""#;
    assert_eq!(
        gates
            .lines()
            .filter(|line| *line == induced_live_call)
            .count(),
        1,
        "the induced-gaps driver must have exactly one standalone live call with its \
         mktemp-rooted absent-path argument"
    );
    assert_eq!(
        live_section
            .lines()
            .filter(|line| *line == induced_live_call)
            .count(),
        1,
        "the standalone live induced-gaps call must follow the live gate loop"
    );
    assert!(
        !live_gate_loop.contains("scripts/verify-induced-gaps.sh"),
        "the induced-gaps driver must not be added to the generic live gate loop"
    );
    assert!(
        live_section.contains(concat!(
            "echo \"=== scripts/verify-induced-gaps.sh ===\"\n",
            r#"scripts/verify-induced-gaps.sh "$(mktemp -d "#
        )),
        "the live induced-gaps driver is not labelled at the root gate boundary"
    );
    assert!(
        ci.contains("python3 -I scripts/check-live-discovery-evidence.py --self-test"),
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
    let directory = tempfile::tempdir().expect("temporary lane-13 bridge directory");
    let ebpf_object = directory.path().join("p11scope-ebpf");
    fs::write(&ebpf_object, p11scope::EBPF_OBJECT).expect("write real embedded eBPF object");
    let output = Command::new("python3")
        .args([
            "-I",
            "tests/python/test_lane13_evidence.py",
            "--ebpf-object",
        ])
        .arg(&ebpf_object)
        .arg("Lane13EvidenceTests")
        .output()
        .expect("run native lane-13 evidence cases");
    assert!(
        output.status.success(),
        "native lane-13 cases failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tracked_ignore_rules_cover_agent_state_and_root_binaries() {
    // Agent state and root build outputs must be ignored by rules that travel
    // with the repository. `.git/info/exclude` is local-only: a fresh clone, or
    // a reviewer's checkout, would not inherit it, so a rule living only there
    // is not a control at all.
    for path in [
        ".claude/worktrees/x",
        ".superpowers/x",
        "p11scope",
        "p11scope-discover",
    ] {
        let output = Command::new("git")
            .args(["check-ignore", "-v", path])
            .output()
            .expect("run git check-ignore");
        assert!(output.status.success(), "{path} is not ignored by any rule");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let source = stdout.split(':').next().unwrap_or_default();
        assert_eq!(
            source, ".gitignore",
            "{path} is ignored by {source}, which does not travel with the \
             repository: {stdout:?}"
        );
    }

    let tracked = Command::new("git")
        .args(["ls-files", ".claude/", ".superpowers/"])
        .output()
        .expect("run git ls-files");
    assert!(
        tracked.stdout.is_empty(),
        "agent state is tracked: {:?}",
        String::from_utf8_lossy(&tracked.stdout)
    );
}

#[test]
fn every_view_retirement_settles_its_leader_exit_assessment_first() {
    // A pending leader-exit assessment can only be answered from the retiring
    // view's own pidfd, and `settle_terminal_drain` counts every assessment
    // still pending at capture end as a lost uprobe link. So a retirement that
    // drops the view without settling turns an ordinary target exit into a
    // published capture gap that never happened. This reads every retirement
    // site rather than the two that were wrong, because the next one added is
    // the one that will forget.
    let source = read("src/discovery/engine.rs");
    // Not `split("#[cfg(test)]")`: the first one in this file guards a `use`
    // at line 49, which would leave 48 lines of "production" and pass on an
    // empty search.
    let production = source
        .split_once("#[cfg(test)]\npub(crate) mod tests {")
        .expect("engine.rs must have a test module")
        .0;
    let sites: Vec<usize> = ["self.views.retain(", "discovered.views.retain("]
        .iter()
        .flat_map(|form| production.match_indices(form).map(|(at, _)| at))
        .collect();
    assert!(
        sites.len() >= 4,
        "expected every process-view retirement to be found; got {}",
        sites.len()
    );
    for at in sites {
        let window = &production[at.saturating_sub(400)..at];
        assert!(
            window.contains("settle_leader_exits_at_removal"),
            "a process-view retirement at byte {at} drops the view without first \
             settling its pending leader-exit assessment"
        );
    }
}

/// The uretprobe hazard must never be decided by a version comparison.
///
/// Measured 2026-09-05: Ubuntu `6.11.0-17` is affected and `6.11.0-29` is not
/// — same upstream minor, one SRU apart — so any `uname` range is wrong in both
/// directions. That is the same defect `c1e1192` removed from `capability_tier`,
/// and the reason this module forks a child and runs the real mechanism instead.
/// Guarding the source keeps a later "quick fix" from reintroducing it.
#[test]
fn the_uretprobe_hazard_is_never_decided_by_a_kernel_version() {
    let source = read("src/uretprobe_hazard.rs");
    let production = source
        .split_once("#[cfg(test)]\nmod tests {")
        .expect("uretprobe_hazard.rs must have a test module")
        .0;
    // Code only. The module's own prose says it must not consult `uname`, and a
    // guard that cannot tell an explanation from an implementation would fire on
    // the sentence forbidding the thing it is forbidding.
    let code: String = production
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["uname", "KERNEL_FLOOR", "kernel_release", "utsname"] {
        assert!(
            !code.contains(banned),
            "src/uretprobe_hazard.rs must not consult {banned}: the affected set is not a \
             version range (6.11.0-17 affected, 6.11.0-29 clean)"
        );
    }
    // The positive half: it must actually run the mechanism.
    assert!(
        code.contains("libc::fork()") && code.contains("SECCOMP_SET_MODE_FILTER"),
        "the verdict must come from forking a child and arming a real seccomp filter"
    );
}

/// An affected kernel captures perfectly from every unconfined target, so the
/// hazard is a property of the kernel/target pairing, not a capability this
/// host lacks. Folding it into the tier would repeat `c1e1192` exactly.
#[test]
fn the_uretprobe_hazard_row_is_not_a_capability_tier_input() {
    let source = read("src/doctor.rs");
    let tier = source
        .split_once("fn capability_tier(")
        .expect("doctor.rs must define capability_tier")
        .1;
    let tier = tier.split_once("\nfn ").map_or(tier, |(body, _)| body);
    assert!(
        !tier.contains("uretprobe"),
        "capability_tier must not read the uretprobe row: an affected kernel is fully capable \
         against an unconfined target"
    );
    assert!(
        source.contains("\"uretprobe vs seccomp\""),
        "doctor must still report the row"
    );
}
