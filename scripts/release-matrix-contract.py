#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned release-matrix selection and fail-closed artifact judge (stdlib only)."""
import argparse
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import pwd
import re
import runpy
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

SCHEMA = "p11scope/release-matrix-contract/v1"
ROOT = Path(__file__).resolve().parents[1]
# The Fedora live-cell lane: Fedora 7.2.9 runs live cells on the real
# host through its own live-cell procedure, never as a vng guest, so
# the contract treats it like "host" (no guest boot config, no vng
# launch) while the matrix runner refuses to execute it.
FEDORA_LANE = "fedora-7.2.9"
# Older labels remain available for explicit working-backport/historical inputs;
# their version never admits live capture. The judge requires actual host proof.
LANES = ("5.15.221", "6.1.188", "6.6.157", "6.8.0-142-generic", "6.12.111", "6.18.58", "7.2.6", "host",
         FEDORA_LANE)
PID_TEST = "tests::the_pid_filter_probe_reaches_the_kernel"
# Exact source registrations; only an actual candidate list establishes membership.
DEFAULT_LIB_TESTS = (
    'attach::identity_iter::tests::anchor_maps_validate_real_handles',
    'attach::identity_iter::tests::functional_probe_proves_hardlink_match_and_copy_none',
    'attach::identity_iter::tests::whole_system_run_covers_all_children',
    'attach::identity_iter::tests::wronly_anchor_fds_refuse_reads_with_eperm',
    'attach::instance_tests::privileged_instance_attach_during_reload_loop_has_zero_false_joins',
    'attach::instance_tests::privileged_instance_exec_renews_the_instance',
    'attach::instance_tests::privileged_instance_fork_without_exec_stays_consistent',
    'attach::instance_tests::privileged_instance_hooks_attach_for_profile_but_not_metrics',
    'attach::instance_tests::privileged_instance_mapping_controls_never_join_old_state',
    'attach::instance_tests::privileged_instance_mremap_dontunmap_keeps_both_and_renews',
    'attach::instance_tests::privileged_instance_nonleader_exec_detaches_without_misrouting',
    'attach::instance_tests::privileged_instance_overflow_at_ninth_file_is_unknown',
    'attach::instance_tests::privileged_instance_pre_attachment_sharer_globalizes',
    'attach::instance_tests::privileged_instance_reload_race_has_zero_false_joins',
    'attach::instance_tests::privileged_instance_routing_separates_reload_sibling_and_mutation',
    'attach::instance_tests::privileged_instance_vfork_unmap_globalizes',
    'attach::instance_tests::privileged_instance_zombie_leader_sharer_globalizes',
    'attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_auto_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64',
    'attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_singles_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::activation::privileged_tests::privileged_detailed_auto_backend_same_cpu_preemption_keeps_frames',
    'attach::inventory::activation::privileged_tests::privileged_detailed_multithread_owner_accounting_exact',
    'attach::inventory::activation::privileged_tests::privileged_detailed_multithread_same_slot_allowlisted_exact',
    'attach::inventory::activation::privileged_tests::privileged_detailed_owner_poison_is_disclosed',
    'attach::inventory::activation::privileged_tests::privileged_detailed_same_cpu_preemption_keeps_frames',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_cgroup_separates_owned_callers',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_failure_preserves_usage_and_releases_resources',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_stop_with_owned_calls_in_progress',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_ia32',
    'attach::inventory::activation::privileged_tests::privileged_inventory_activation_system_lp64',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_cgroup_lp64',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_partial_activation_lp64',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_ia32',
    'attach::inventory::activation::privileged_tests::privileged_inventory_caller_system_lp64',
    'attach::inventory::activation::privileged_tests::privileged_stop_gate_freezes_capture_state_after_quiescence',
    'attach::inventory::activation::privileged_tests::privileged_stop_gate_keeps_calls_in_flight_as_residual',
    'attach::inventory::activation::privileged_tests::privileged_t7_detailed_hot_slot_third_rv_lp64',
    'attach::inventory::activation::privileged_tests::privileged_t7_inventory_n1024_lp64',
    'attach::inventory::activation::privileged_tests::privileged_t7_inventory_n576_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_detailed_n512_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_detailed_physical_identity_controls',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_2112_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2048_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n2049_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n511_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n512_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_n513_lp64',
    'attach::inventory::activation::privileged_tests::privileged_task4_inventory_physical_identity_controls',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_cookie_query_matches_row_and_changes_on_nonleader_exec_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_extend_late_provider_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_pid_scope_excludes_foreign_and_reused_pid_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_pid_scope_leader_exit_probe_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_stop_with_held_call_reports_unsettled_lp64',
    'attach::inventory::capture::privileged_tests::privileged_inventory_capture_stop_before_activation_repolls_custody_lp64',
    'attach::inventory::capture::privileged_tests::privileged_dr37_selected_promotion_full_loop',
    'attach::inventory::privileged_tests::privileged_inventory_caller_preparation_faults_release_exact_resources',
    'attach::inventory::privileged_tests::privileged_inventory_caller_preparation_freezes_native_maps_and_publishes_binding',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_failure_releases_owned_resources',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_freezes_all_nine_protected_maps',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_loads_multi_without_links',
    'attach::inventory::privileged_tests::privileged_inventory_preparation_loads_runtime_capacity_and_zero_links',
    'attach::lifecycle_tests::exec_tests::privileged_detailed_failed_nonleader_exec_preserves_start_and_image',
    'attach::lifecycle_tests::exec_tests::privileged_detailed_nonleader_exec_cleans_old_tid_before_same_session_rebind',
    'attach::lifecycle_tests::privileged_detailed_nonleader_exit_preserves_same_slot_sibling_start',
    'attach::lifecycle_tests::privileged_detailed_nonleader_exit_reclaims_start_and_preserves_leader',
    'discovery::confirm_shards::tests::privileged_sharded_confirmation_equals_the_serial_production_probe',
    'discovery::engine::publication_tests::broad_p11kit_admission_arithmetic',
    'discovery::inventory_workload::tests::privileged_inventory_attach_projection_n4097',
    'discovery::inventory_workload::tests::privileged_inventory_attach_projection_n6530',
    'discovery::inventory_workload::tests::privileged_inventory_attach_projection_n8192',
    'discovery::sweep_attribution::tests::privileged_a_data_only_mapper_of_an_identity_key_is_never_attributed_on_ext4',
    'discovery::sweep_attribution::tests::privileged_an_unmapped_file_whose_inode_is_reused_is_never_attributed_on_ext4',
    'events::runtime_tests::real_retained_consumer_keeps_one_cursor_across_all_drains',
    'events::runtime_tests::real_retained_discovery_consumer_owns_one_exact_map',
    'events::runtime_tests::real_uretprobe_hazard_self_probe_reaches_a_verdict',
    'inventory::privileged_tests::privileged_native_lane_pid_lp64',
    'inventory::privileged_tests::privileged_native_lane_sigint_during_extend_lp64',
    'inventory::privileged_tests::privileged_native_lane_stop_held_call_unsettled_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_late_dlopen_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_ab_first_count_lp64',
    'inventory::privileged_tests::privileged_native_lane_system_many_endpoints_lp64',
    'inventory::privileged_tests::privileged_native_lane_dashboard_slow_pty_lp64',
)

BREADTH = tuple("attach::inventory::activation::privileged_tests::" + name for name in (
    "privileged_t7_inventory_n4097_lp64", "privileged_t7_inventory_n6530_lp64",
    "privileged_t7_inventory_n6531_lp64", "privileged_t7_inventory_n8192_boundary_lp64"))
# G01/R7: the 8192 boundary cell deliberately succeeds while refusing
# the envelope. Only its exact refusal marker or its exact all-ID
# positive evidence classifies it; test success alone never does.
BOUNDARY = BREADTH[-1]
BOUNDARY_CELL = "inventory-t7-n8192-boundary"
BOUNDARY_N = 8192
BOUNDARY_PHASES = ("preflight", "post_failure_classification")
IDENTITY_POSITIVE = tuple("attach::identity_iter::tests::" + name for name in (
    "functional_probe_proves_hardlink_match_and_copy_none", "whole_system_run_covers_all_children",
    "wronly_anchor_fds_refuse_reads_with_eperm"))
# Historical G23 executable refusal selector, retained as an opt-in control.
DENIAL_515 = "inspect_system::privileged_tests::privileged_identity_515_denial_is_disclosed"
OTHER_LONG = {
    DENIAL_515: "historical/private BTF refusal control; not a current host-positive obligation",
    "attach::instance_tests::privileged_instance_continuity_experiment_softhsm":
        "separately owned SoftHSM continuity duration/rate and mapping-operation lane",
    "attach::inventory::activation::privileged_tests::privileged_bench_overhead_detailed_calls":
        "separately owned release-build timing baseline, quiet host and overhead budget",
}
PUBLIC = {
    "profile-pid": "owned-provider-counts", "metrics-pid": "owned-provider-counts",
    "mt-exact": "owned-provider-counts", "system": "owned-provider-counts",
    "names-pid": "semantic-names", "verdict-pid": "verdict-consistency",
    "doctor": "command-contract", "sigint": "command-contract",
    "second-sigint": "command-contract", "fifo-refused": "command-contract",
    "run-short": "nonqualifying", "run-cover": "nonqualifying",
    "trace-pid": "nonqualifying",
}
BASE_IDS = ("version", "doctor", "inventory-native", "pid-filter", "backend-pid", "backend-system")
EXITS = {"version.log": "version", "doctor.log": "doctor", "qual.log": "qual",
         "inv-native.log": "inv_native", "pidflt.log": "pidflt", "priv.log": "priv",
         "backend/inv-pid.stderr": "inv_pid", "backend/inv-sys.stderr": "inv_sys"}
RUNTIME_SOURCES = ("tests/fixtures/public-cli/inventory-ledger.c", "scripts/fixtures/exec_churn.c")
SOURCE_FILES = ("scripts/release-matrix-contract.py", "scripts/qualify-release-matrix.sh",
                "scripts/run-privileged-lib-tests.sh", "scripts/qualify-public-cli.sh",
                "scripts/mapped-provider-pin.py", "scripts/public-cli-oracle.py", "scripts/check-capture-evidence.py",
                "scripts/qualify-inventory-native.sh", "scripts/inventory-native-oracle.py",
                "tests/fixtures/public-cli/gated.c", "tests/fixtures/public-cli/mt.c",
                "tests/fixtures/public-cli/inventory-ledger.c")
CANARY_SOURCE_FILES = ("scripts/verify-canaries.sh", "scripts/product-build.sh", "scripts/lib.sh",
    "scripts/lane-lib-oracle-1.py", "scripts/cleanup-traps.sh", "scripts/_loader.py",
    "scripts/capture-stopped-canary.py", "scripts/canary_process_custody.py",
    "scripts/check-canary-evidence.py", "scripts/check-capture-evidence.py", "scripts/check-bpf-map-defs.py",
    "scripts/dump-owned-bpf-maps.py", "scripts/qualify-task-storage-canary.py", ".release-rust-version",
    "scripts/fixtures/canary_workload.c", "scripts/fixtures/privacy-stack-workload.c")
CANARY_RUNTIME_SOURCES = ("scripts/fixtures/canary_workload.c", "crates/discover/tests/fixture/version_matrix.c",
    "scripts/build-task-storage-reader.sh", "scripts/native/dump-task-storage.c", "scripts/native/dump-task-storage.bpf.c")
CANARY_PRODUCER_SOURCES = ("scripts/verify-canaries.sh", "scripts/product-build.sh", "scripts/cargo.sh",
    "scripts/release-matrix-contract.py", ".release-rust-version", "build.rs", "src/lib.rs")
CANARY_PAYLOADS = ("p11scope", "p11scope-discover", "canary_workload", "matrix-provider.so",
    "privacy-provider.so", "dump-task-storage", "dump-task-storage.bpf.o", "default-ebpf")
CANARY_BUILD_ENV = ("P11SCOPE_SMALL_RING", "P11SCOPE_SMALL_STATE_MAPS", "P11SCOPE_SMALL_DISCOVERY_RING",
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")
CANARY_PREPARED_TOOLS = ("P11SCOPE_PREPARED_STABLE_CARGO", "P11SCOPE_PREPARED_STABLE_RUSTC",
    "P11SCOPE_PREPARED_BPF_CARGO", "P11SCOPE_PREPARED_BPF_RUSTC")
CANARY_FACTS_MAX = 128 * 1024
TOLERANCE_ENV = ("P11SCOPE_PRIV_LIFECYCLE_LOSS", "P11SCOPE_TEST_TIME_SCALE")
CLASSIC_MULTI = "attach::inventory::activation::privileged_tests::privileged_classic_pid_scope_forced_multi_names_the_target_or_refuses_lp64"
MULTI_OUTCOMES = {
    CLASSIC_MULTI: "CLASSIC_PID_SCOPE selection=multi",
    "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_excludes_foreign_and_reused_pid_lp64": "C3_PID_SCOPE backend=Multi",
    "attach::inventory::capture::privileged_tests::privileged_inventory_capture_multi_pid_scope_leader_exit_probe_lp64": "C3_LEADER_EXIT_PROBE backend=Multi",
}
CHURN = "inventory::privileged_tests::privileged_native_lane_system_exec_churn_lp64"
BROAD = "discovery::engine::publication_tests::broad_p11kit_admission_arithmetic"


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def load(path):
    return decode(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def relative(stage, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute(), "invalid artifact path")
    path = stage / name
    require(path.resolve().is_relative_to(stage.resolve()), "artifact escapes stage: " + name)
    require(not path.is_symlink(), "symlink artifact: " + name)
    return path


def guest_boot_config(kernel):
    """Resolve only the two kernel layouts supported by the matrix runner."""
    image = Path(kernel)
    if image.is_absolute():
        require(image.is_file() and image.name.startswith("vmlinuz-"), "invalid absolute guest kernel")
        boot = image.parent
        expected = image.name.removeprefix("vmlinuz-")
    else:
        require(re.fullmatch(r"v\d+\.\d+\.\d+", kernel), "unknown guest kernel layout")
        boot = Path.home() / ".cache/virtme-ng" / kernel / "amd64/boot"
        expected = None
    configs = list(boot.glob("config-*"))
    require(len(configs) == 1 and configs[0].is_file(), "missing/ambiguous guest boot config")
    config = configs[0].resolve(strict=True)
    release = config.name.removeprefix("config-")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", release), "invalid guest osrelease")
    require(release == expected if expected is not None else
            re.fullmatch(re.escape(kernel.removeprefix("v")) + r"(?:-[A-Za-z0-9._+-]+)?", release),
            "kernel/config osrelease mismatch")
    return config, release


def validate_run_identity(identity):
    require(isinstance(identity, dict) and set(identity) == {"uid", "gid", "user"}, "invalid runner identity")
    require(type(identity["uid"]) is int and identity["uid"] > 0
            and type(identity["gid"]) is int and identity["gid"] > 0
            and isinstance(identity["user"], str) and identity["user"], "runner must be a real nonroot account")
    try:
        account = pwd.getpwnam(identity["user"])
    except KeyError as error:
        raise Invalid("runner account is absent") from error
    require((account.pw_uid, account.pw_gid) == (identity["uid"], identity["gid"]), "runner account identity mismatch")
    return account


def validate_guest_work_root(path, runner_uid=None):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True) and path.is_dir(), "invalid guest work root")
    for parent in (path, *path.parents):
        info = parent.stat()
        owners = (0, os.getuid()) if runner_uid is None else (0, os.getuid(), runner_uid)
        require(info.st_uid in owners and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                "untrusted guest work ancestor")
    fs = subprocess.run(["findmnt", "-n", "-o", "FSTYPE", "--target", str(path)],
                        text=True, capture_output=True, check=False)
    require(fs.returncode == 0 and fs.stdout.strip() in ("btrfs", "ext2", "ext3", "ext4", "xfs", "f2fs"),
            "guest work root is not a supported local disk filesystem")
    require(shutil.disk_usage(path).free >= 64 * 1024 * 1024, "insufficient guest work space")
    with tempfile.TemporaryFile(dir=path) as probe:
        probe.write(b"p11scope guest disk preflight\n"); probe.flush(); os.fsync(probe.fileno())
    return path


def validate_guest_disk_binding(disk):
    require(isinstance(disk, dict) and set(disk) == {"path", "uuid", "fstype", "device", "inode", "size"},
            "invalid guest disk binding")
    path = disk["path"]
    require(isinstance(path, str) and re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
            and str(Path(path)) == path and ".." not in Path(path).parts, "unsafe guest disk path")
    require(isinstance(disk["uuid"], str) and str(uuid.UUID(disk["uuid"])) == disk["uuid"]
            and disk["fstype"] == "ext4", "invalid guest disk UUID/type")
    require(all(type(disk[key]) is int and disk[key] > 0 for key in ("device", "inode", "size")),
            "invalid guest disk file identity")
    return disk


def probe_ext4(path, expected_uuid, allow_other=False):
    result = subprocess.run(["blkid", "-p", "-o", "export", "--", str(path)], text=True, capture_output=True)
    if allow_other and result.returncode == 2 and not result.stdout.strip() and not result.stderr.strip():
        return False  # blkid's explicit no-filesystem result, not a probe error.
    require(result.returncode == 0, "guest disk filesystem probe failed")
    facts = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        require(sep and key not in facts, "invalid guest disk filesystem probe")
        facts[key] = value
    require(facts.get("TYPE") or facts.get("PTTYPE"), "missing guest disk filesystem probe identity")
    if allow_other and facts.get("UUID") != expected_uuid:
        return False
    require(facts.get("TYPE") == "ext4" and facts.get("UUID") == expected_uuid
            and not {"PTTYPE", "PTUUID", "PART_ENTRY_UUID", "PART_ENTRY_SCHEME"} & facts.keys(),
            "guest disk must be the selected unpartitioned ext4 UUID")
    return True


def guest_disk_input(image, filesystem_uuid):
    require((image is None) == (filesystem_uuid is None), "guest disk requires paired image and UUID options")
    if image is None:
        return None
    disk = {"path": str(image), "uuid": filesystem_uuid, "fstype": "ext4", "device": 1, "inode": 1, "size": 1}
    validate_guest_disk_binding(disk)
    image = Path(image)
    require(image.is_file(), "guest disk must be an existing regular image")
    require(image == image.resolve(strict=True), "guest disk path must be canonical without symlinks")
    for path in (image, *image.parents):
        info = path.stat()
        require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or
                (path != image and info.st_mode & stat.S_ISVTX)), "untrusted guest disk path/ancestor")
    fd = os.open(image, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size > 0, "guest disk must be an existing writable regular image")
        disk.update(device=info.st_dev, inode=info.st_ino, size=info.st_size)
        validate_guest_disk_binding(disk)
        probe_ext4(image, filesystem_uuid)
        loops = subprocess.run(["losetup", "--json", "--list", "--associated", str(image), "--output", "NAME"],
                               text=True, capture_output=True)
        loop_info = decode(loops.stdout)
        require(loops.returncode == 0 and isinstance(loop_info, dict)
                and loop_info.get("loopdevices") == [], "guest disk has a host loop association or cannot be checked")
        mounted = subprocess.run(["findmnt", "-n", "-o", "SOURCE", "--source", str(image)], text=True, capture_output=True)
        require(mounted.returncode == 1 and not mounted.stdout.strip(), "guest disk has a host mount association or cannot be checked")
        after = image.stat()
        require((after.st_dev, after.st_ino, after.st_size) == (info.st_dev, info.st_ino, info.st_size),
                "guest disk changed during prerequisite checks")
    finally:
        os.close(fd)
    return disk


def launch_guest(stage, contract_path, kernel):
    contract = verify_inputs(stage, contract_path)
    require(contract["lane"] != FEDORA_LANE, "fedora lanes run via the live-cell procedure on fedora, not vng")
    require(contract["lane"] != "host" and kernel is not None, "guest launcher requires a guest kernel lane")
    config, release = guest_boot_config(kernel)
    require(release == contract["expected_osrelease"] and str(config) == contract["guest_boot_config"]["source"]
            and sha(config) == contract["guest_boot_config"]["sha256"], "guest launcher kernel/config differs from contract")
    argv = ["vng", "--run", kernel, "--user", contract["run_identity"]["user"], "--cpus", "4",
            "--memory", "6G", "--rwdir", str(stage), "--overlay-rwdir", "/boot"]
    disk = contract.get("guest_disk")
    if disk is not None:
        require(guest_disk_input(disk["path"], disk["uuid"]) == disk, "guest disk file identity changed before launch")
        argv += ["--disk", disk["path"]]
    argv += ["--exec", shlex.join(["sudo", "-n", "python3", "-I",
        str(stage / "artifacts/source/scripts/release-matrix-contract.py"), "--run-guest-inner", str(stage),
        "--contract", str(contract_path)])]
    return subprocess.run(argv).returncode


def mounted_filesystem(path):
    result = subprocess.run(["findmnt", "--json", "-o", "TARGET,SOURCE,FSTYPE,MAJ:MIN", "--mountpoint", str(path)],
                            text=True, capture_output=True)
    if result.returncode == 1 and not result.stdout.strip():
        return None
    require(result.returncode == 0, "guest disk mount inspection failed")
    rows = decode(result.stdout).get("filesystems")
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
            and rows[0].get("target") == str(path), "ambiguous guest disk mount")
    return rows[0]


def selected_guest_device(disk):
    result = subprocess.run(["lsblk", "--json", "--paths", "--nodeps", "-o", "PATH,TYPE,MAJ:MIN"],
                            text=True, capture_output=True)
    require(result.returncode == 0, "guest disk device enumeration failed")
    rows = decode(result.stdout).get("blockdevices")
    require(isinstance(rows, list), "invalid guest disk device enumeration")
    selected = []
    skipped_unreadable = []
    for row in rows:
        require(isinstance(row, dict), "invalid guest disk device")
        if row.get("type") != "disk":
            continue
        path, number = row.get("path"), row.get("maj:min")
        require(isinstance(path, str) and re.fullmatch(r"/dev/[A-Za-z0-9_./-]+", path)
                and ".." not in Path(path).parts and isinstance(number, str) and re.fullmatch(r"[0-9]+:[0-9]+", number),
                "invalid guest disk device identity")
        info = Path(path).stat()
        require(stat.S_ISBLK(info.st_mode) and number == f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}",
                "guest disk enumeration differs from actual block device")
        try:
            matched = probe_ext4(path, disk["uuid"], allow_other=True)
        except Invalid as probe_error:
            # An empty removable whole disk (QEMU's phantom /dev/fd0) fails
            # the probe because the device itself cannot be opened. A blocking
            # open is the discriminator: the floppy driver skips its media
            # check under O_NONBLOCK, so only a blocking open reports
            # ENXIO/ENOMEDIUM for a missing medium. Such a device cannot carry
            # the selected filesystem, so skip and record it; a device that
            # opens (including the expected-UUID carrier) stays strict.
            try:
                fd = os.open(path, os.O_RDONLY)
            except OSError as error:
                if error.errno not in (errno.ENXIO, errno.ENOMEDIUM):
                    raise probe_error
                skipped_unreadable.append(path)
                continue
            os.close(fd)
            raise probe_error
        if matched:
            selected.append({"path": path, "number": number, "device": info.st_rdev})
    detail = "guest disk UUID/type must identify exactly one whole block device"
    if skipped_unreadable:
        detail += "; skipped unreadable device(s): " + ", ".join(skipped_unreadable)
    require(len(selected) == 1, detail)
    selected[0]["skipped_unreadable"] = skipped_unreadable
    return selected[0]


def verify_guest_disk_mount(root, device):
    row = mounted_filesystem(root)
    require(row is not None and row.get("fstype") == "ext4" and row.get("maj:min") == device["number"],
            "guest disk mounted filesystem identity mismatch")
    source = row.get("source")
    require(isinstance(source, str) and re.fullmatch(r"/dev/[A-Za-z0-9_./-]+", source)
            and ".." not in Path(source).parts, "invalid guest disk mount source")
    info = Path(source).stat()
    require(stat.S_ISBLK(info.st_mode) and info.st_rdev == device["device"] and root.stat().st_dev == device["device"],
            "guest disk mount source/device mismatch")


def mount_guest_work_disk(stage, contract):
    # This explicit setup is confined to virtme's private guest /var/tmp.
    guest_root, temporary = mounted_filesystem(Path("/")), mounted_filesystem(Path("/var/tmp"))
    require(guest_root is not None and guest_root.get("fstype") in ("9p", "virtiofs")
            and temporary is not None and temporary.get("fstype") == "tmpfs", "guest disk setup requires a virtme guest")
    root = Path(contract["guest_work_root"])
    require(root.is_relative_to("/var/tmp") and root != Path("/var/tmp")
            and root == root.resolve() and not root.is_relative_to(stage) and not stage.is_relative_to(root),
            "protected, overlapping or noncanonical guest disk mount target")
    for parent in (root, *root.parents):
        if not parent.exists():
            continue
        info = parent.stat()
        require(parent.is_dir() and info.st_uid in (0, contract["run_identity"]["uid"])
                and (not info.st_mode & 0o022 or (parent != root and info.st_mode & stat.S_ISVTX)),
                "untrusted guest disk mount target/ancestor")
    device = selected_guest_device(contract["guest_disk"])
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    existing = mounted_filesystem(root)
    if existing is not None:
        verify_guest_disk_mount(root, device)
        return root, device, False
    require(not any(root.iterdir()), "guest disk mount target contains unrelated files")
    result = subprocess.run(["mount", "-t", "ext4", "-o", "rw,nodev,nosuid", "--", device["path"], str(root)],
                            text=True, capture_output=True)
    require(result.returncode == 0, "guest disk mount failed")
    verify_guest_disk_mount(root, device)
    return root, device, True


def run_guest_inner(stage, contract_path):
    contract = verify_inputs(stage, contract_path)
    require(contract["lane"] != FEDORA_LANE, "fedora lanes run via the live-cell procedure on fedora, not the guest inner entrypoint")
    require(os.geteuid() == 0 and contract["lane"] != "host", "guest inner launcher requires root in a guest lane")
    release = subprocess.run(["uname", "-r"], text=True, capture_output=True)
    require(release.returncode == 0 and release.stdout.strip() == contract["expected_osrelease"], "wrong executed guest osrelease")
    mounted, root, device = False, None, None
    if contract.get("guest_disk") is not None:
        root, device, mounted = mount_guest_work_disk(stage, contract)
    try:
        if root is not None:
            validate_guest_work_root(root, contract["run_identity"]["uid"])
        return subprocess.run(["bash", str(stage / "inner.sh")]).returncode
    finally:
        if mounted:
            # Only our mount, after the synchronous inner and its output copies.
            verify_guest_disk_mount(root, device)
            result = subprocess.run(["umount", "--", str(root)], text=True, capture_output=True)
            require(result.returncode == 0, "guest disk unmount failed")


def copy_guest_file(source, destination):
    source, destination = Path(source), Path(destination)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "nonregular guest output")
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IMODE(before.st_mode) & 0o777)
        with os.fdopen(out, "wb") as target, os.fdopen(os.dup(fd), "rb") as origin:
            shutil.copyfileobj(origin, target, 1024 * 1024)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "guest output changed during copy")
        require(sha(source) == sha(destination), "guest output copy changed bytes")
    finally:
        os.close(fd)


def copy_guest_tree(source, destination, kind):
    """Copy completed outputs without 9p ownership/timestamp operations."""
    source, destination = Path(source), Path(destination)
    require(kind in ("public", "native", "plain"), "unknown guest output tree")
    require(source.is_dir() and not source.is_symlink() and not destination.exists(), "invalid/existing guest output tree")
    require(not destination.resolve().is_relative_to(source.resolve()) and not source.resolve().is_relative_to(destination.resolve()),
            "overlapping guest output trees")
    def contents():
        files, directories = {}, {}
        for path in sorted(source.rglob("*")):
            name = path.relative_to(source).as_posix()
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), "symlink guest output: " + name)
            if stat.S_ISDIR(info.st_mode): directories[name] = stat.S_IMODE(info.st_mode) & 0o777
            elif stat.S_ISREG(info.st_mode): files[name] = sha(path)
            elif stat.S_ISFIFO(info.st_mode):
                if kind == "public" and name == "fifo":
                    rows = [load_json_line(line) for line in (source / "results.jsonl").read_text().splitlines()]
                    proof = [row for row in rows if row.get("cell") == "fifo-refused"]
                    require(len(proof) == 1 and proof[0].get("pass") is True, "unproved public FIFO refusal")
                else:
                    require(kind == "native" and re.fullmatch(r"c8-wl\.[^/]+/gates/release", name), "unknown guest output FIFO: " + name)
            else: raise Invalid("special guest output: " + name)
        return files, directories
    files, directories = contents()
    destination.mkdir(mode=stat.S_IMODE(source.stat().st_mode) & 0o777)
    for name, mode in directories.items(): (destination / name).mkdir(mode=mode)
    for name in files: copy_guest_file(source / name, destination / name)
    require(contents() == (files, directories), "guest output tree changed during copy")
    copied = {path.relative_to(destination).as_posix(): sha(path) for path in destination.rglob("*") if path.is_file()}
    require(copied == files, "guest output file set/bytes changed during copy")


def select_module(explicit=None):
    candidates = [explicit] if explicit is not None else (
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/softhsm/libsofthsm2.so", "/usr/lib64/pkcs11/libsofthsm2.so")
    for candidate in candidates:
        path = Path(candidate)
        if not path.exists(): continue
        path = path.resolve(strict=True)
        # This provider is loaded by the nonroot workload, not by the observer.
        # An explicit readable caller-owned provider remains selected under root.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022 and 0 < info.st_size <= 512 * 1024 * 1024,
                    "untrusted or oversized module")
            header = os.read(fd, 20)
            require(len(header) == 20 and header[:6] == b"\x7fELF\x02\x01"
                    and struct.unpack_from("<H", header, 18)[0] == 62, "module is not an x86-64 ELF")
        finally: os.close(fd)
        return path
    raise Invalid("no readable ABI-correct SoftHSM module; set MODULE explicitly")


def guest_environment(stage, contract_path):
    contract = verify_inputs(stage, contract_path)
    identity = contract["run_identity"]
    account = validate_run_identity(identity)
    def as_account(*argv):
        result = subprocess.run(["runuser", "-u", account.pw_name, "--", *map(str, argv)], text=True, capture_output=True)
        require(result.returncode == 0, "runner account preflight failed: " + " ".join(map(str, argv)))
        return result.stdout.strip()
    require(as_account("id", "-u") == str(identity["uid"]) and as_account("id", "-g") == str(identity["gid"]),
            "guest runner effective identity mismatch")
    as_account("sudo", "-n", "true")
    for name in contract["bindings"]:
        as_account("test", "-r", stage / name)
    as_account("test", "-x", stage / "artifacts/p11scope")
    root = validate_guest_work_root(contract["guest_work_root"], identity["uid"])
    require(not root.is_relative_to(stage.resolve()), "guest work root overlaps staged inputs/output")
    as_account("test", "-x", root)
    work = Path(tempfile.mkdtemp(prefix="matrix-" + contract["run_id"] + "-", dir=root))
    work.chmod(0o711)
    for name in ("qual", "priv", "backend", "tmp", "outputs", "c8-native", "c8-scan", "caller"):
        path = work / name; path.mkdir(mode=0o711 if name.startswith("c8-") or name == "qual" else 0o700)
        if name == "caller": os.chown(path, identity["uid"], identity["gid"])
    as_account("test", "-w", work / "caller")
    print(json.dumps({"work": str(work), "uid": identity["uid"], "gid": identity["gid"], "user": identity["user"]}))


def canary_fd(path, executable=False, maximum=512 * 1024 * 1024, input_uid=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid(), input_uid)
                and not info.st_mode & 0o022 and 0 < info.st_size <= maximum,
                "untrusted or oversized canary input: " + str(path))
        require(not executable or (info.st_mode & 0o100 and os.access(path, os.X_OK)),
                "nonexecutable canary input: " + str(path))
    except BaseException:
        os.close(fd)
        raise
    return fd


def validate_canary_payloads(selected, bits, full=False, work=None, temporary=None, embedded=False, input_uid=None):
    """Shared prebuilt/export validation; inspect bounded headers, never execute inputs."""
    selected = Path(selected)
    require(selected.is_absolute() and not selected.is_symlink(), "invalid canary input directory")
    inputs = selected.resolve(strict=True)
    require(inputs.is_dir() and type(bits) is int and bits in (32, 64), "invalid canary target ABI")
    for parent in (inputs, *inputs.parents):
        info = parent.stat()
        require(info.st_uid in (0, os.getuid(), input_uid) and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                "untrusted canary input ancestor")
    if work:
        work = Path(work).resolve()
        require(not work.is_relative_to(inputs) and not inputs.is_relative_to(work), "overlapping canary inputs/work")
    elif temporary:
        require(not Path(temporary).resolve().is_relative_to(inputs), "canary temporary directory is inside inputs")
    target = (1, 3) if bits == 32 else (2, 62)
    specifications = {"p11scope": ((2, 62), True), "p11scope-discover": (target, True),
        "canary_workload": (target, True), "matrix-provider.so": (target, False),
        "privacy-provider.so": (target, False), "dump-task-storage": ((2, 62), True),
        "dump-task-storage.bpf.o": ((2, 247), False), "default-ebpf": ((2, 247), False)}
    if full:
        specifications.update({"p11scope-diagnostic": ((2, 62), True),
            "diagnostic-ebpf": ((2, 247), False), "task-storage-canary": ((2, 62), True)})
    for name, (expected, executable) in specifications.items():
        fd = canary_fd(inputs / name, executable, 64 * 1024 * 1024 if expected[1] == 247 else 512 * 1024 * 1024, input_uid)
        try:
            header = os.read(fd, 20)
            require(len(header) == 20 and header[:4] == b"\x7fELF" and header[5] == 1
                    and (header[4], struct.unpack_from("<H", header, 18)[0]) == expected,
                    "wrong canary ELF ABI: " + name)
        finally:
            os.close(fd)
    if embedded:
        observer = canary_fd(inputs / "p11scope", True, input_uid=input_uid)
        try:
            obj = canary_fd(inputs / "default-ebpf", maximum=64 * 1024 * 1024, input_uid=input_uid)
            try:
                with mmap.mmap(observer, 0, access=mmap.ACCESS_READ) as image, mmap.mmap(obj, 0, access=mmap.ACCESS_READ) as elf:
                    start = image.find(elf)
                    require(start >= 0 and image.find(elf, start + 1) == -1,
                            "selected canary BPF object is not uniquely embedded in observer")
            finally:
                os.close(obj)
        finally:
            os.close(observer)
    return inputs


def load_canary_facts(path, input_uid=None):
    fd = canary_fd(path, maximum=CANARY_FACTS_MAX, input_uid=input_uid)
    with os.fdopen(fd) as stream:
        return decode(stream.read())


def canary_commands(work, mode, bits, build_mode):
    """The fixed eight-input producer command contract, including its output association."""
    work = Path(work)
    commands = [("observer", ["p11scope_product_build", build_mode, "--release", "--workspace",
        *(["--features", "stub-object-attributes"] if mode == "p0" else []),
        "--target-dir", str(work / "default-build")])]
    if bits == 32:
        commands.append(("helper", ["p11scope_product_build", build_mode, "--release", "-p", "p11scope-discover",
            "--target", "i686-unknown-linux-gnu", "--target-dir", str(work / "helper-build")]))
    commands.extend([
        ("reader", ["scripts/build-task-storage-reader.sh", str(work / "task-storage-reader")]),
        ("workload", ["gcc", f"-m{bits}", "-std=c11", "-O0", "-Wall", "-Wextra", "-o", str(work / "canary_workload"),
            "scripts/fixtures/canary_workload.c", "-ldl", "-pthread"]),
        ("matrix-provider", ["gcc", f"-m{bits}", "-shared", "-fPIC", "-Wall", "-Wextra", "-DPRIVACY_FIXTURE=1",
            "-o", str(work / "matrix-provider.so"), "crates/discover/tests/fixture/version_matrix.c"]),
        ("privacy-provider", ["gcc", f"-m{bits}", "-shared", "-fPIC", "-Wall", "-Wextra", "-DPRIVACY_FIXTURE=1", "-DPRIVACY_BLOCKS=1",
            "-o", str(work / "privacy-provider.so"), "crates/discover/tests/fixture/version_matrix.c"]),
    ])
    return commands


def original_build_source(root, name):
    require(str(root.resolve(strict=True)) == str(root) and root.is_dir(), "invalid original build root")
    return root / name


def build_root(value):
    require(isinstance(value, str) and Path(value).is_absolute() and str(Path(value)) == value
            and ".." not in Path(value).parts, "invalid build source-root provenance")
    return Path(value)


def validate_canary_inputs(facts, bundle, candidate, input_uid=None):
    return _validate_canary_inputs(facts, bundle, candidate, input_uid, original_build_source)


def _validate_canary_inputs(facts, bundle, candidate, input_uid, source):
    fields = {"producer", "source_root", "source_revision", "source_tree", "source_clean", "capture_mode",
        "target_bits", "build_mode", "prepared_tools", "release_rust", "build_environment", "builds",
        "artifacts", "runtime_sources", "producer_sources"}
    require(isinstance(facts, dict) and set(facts) == fields, "invalid canary build facts")
    require(facts["producer"] == "verify-canaries.sh --prepare-object-inputs" and facts["source_clean"] is True,
            "canary inputs need the successful clean build producer")
    for key in ("source_revision", "source_tree"):
        require(isinstance(facts[key], str) and re.fullmatch(r"[0-9a-f]{40}", facts[key])
                and facts[key] == candidate.get(key), "canary/candidate build source mismatch: " + key)
    root = build_root(facts["source_root"])
    mode, bits, build_mode = facts["capture_mode"], facts["target_bits"], facts["build_mode"]
    require(mode in ("full", "p0") and type(bits) is int and bits in (32, 64)
            and build_mode in ("ordinary", "prepared"), "invalid canary build selection")
    tools = facts["prepared_tools"]
    require(isinstance(tools, dict) and set(tools) <= set(CANARY_PREPARED_TOOLS)
            and all(isinstance(value, str) and Path(value).is_absolute() for value in tools.values())
            and (build_mode != "prepared" or set(tools) == set(CANARY_PREPARED_TOOLS)), "invalid canary prepared tool context")
    environment = facts["build_environment"]
    require(isinstance(environment, dict) and set(environment) == set(CANARY_BUILD_ENV)
            and all(value is None or isinstance(value, str) and len(value) <= 8192 for value in environment.values()),
            "invalid canary build environment")
    require(facts["release_rust"] == source(root, ".release-rust-version").read_text().strip(), "canary release compiler changed")
    for key, expected in (("runtime_sources", CANARY_RUNTIME_SOURCES), ("producer_sources", CANARY_PRODUCER_SOURCES)):
        hashes = facts[key]
        require(isinstance(hashes, dict) and set(hashes) == set(expected), "missing canary source closure: " + key)
        for name, digest in hashes.items():
            require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                    and sha(source(root, name)) == digest, "compiled canary source changed: " + name)
    require(facts["runtime_sources"]["scripts/fixtures/canary_workload.c"] == sha(ROOT / "scripts/fixtures/canary_workload.c"),
            "compiled canary sentinel source differs from scanner input")
    artifacts = facts["artifacts"]
    require(isinstance(artifacts, dict) and set(artifacts) == set(CANARY_PAYLOADS), "missing canary payload association")
    for name, item in artifacts.items():
        require(isinstance(item, dict) and set(item) == {"source", "build", "sha256"}
                and isinstance(item["source"], str) and Path(item["source"]).is_absolute()
                and ".." not in Path(item["source"]).parts and str(Path(item["source"])) == item["source"],
                "invalid canary output association")
    observer = Path(artifacts["p11scope"]["source"])
    require(observer.name == "p11scope" and observer.parent.name == "release" and observer.parent.parent.name == "default-build",
            "canary observer is not the selected build output")
    work = observer.parent.parent.parent
    commands = canary_commands(work, mode, bits, build_mode)
    builds = facts["builds"]
    require(isinstance(builds, list) and all(isinstance(step, dict) and type(step.get("exit")) is int for step in builds)
            and builds == [{"role": role, "argv": argv, "cwd": str(root), "exit": 0} for role, argv in commands],
            "canary build commands/status do not match selected inputs")
    origins = {"p11scope": (observer, "observer"),
        "p11scope-discover": (work / ("helper-build/i686-unknown-linux-gnu/release/p11scope-discover" if bits == 32 else "default-build/release/p11scope-discover"), "helper" if bits == 32 else "observer"),
        "canary_workload": (work / "canary_workload", "workload"),
        "matrix-provider.so": (work / "matrix-provider.so", "matrix-provider"),
        "privacy-provider.so": (work / "privacy-provider.so", "privacy-provider"),
        "dump-task-storage": (work / "task-storage-reader/dump-task-storage", "reader"),
        "dump-task-storage.bpf.o": (work / "task-storage-reader/dump-task-storage.bpf.o", "reader")}
    obj = Path(artifacts["default-ebpf"]["source"])
    require(obj.parent.name == "out" and obj.parent.parent.name.startswith("p11scope-")
            and obj.parent.parent.parent == work / "default-build/release/build" and obj.name == "p11scope-ebpf",
            "canary BPF is not from the observer build")
    origins["default-ebpf"] = (obj, "observer")
    validate_canary_payloads(bundle, bits, embedded=True, input_uid=input_uid)
    require({path.name for path in Path(bundle).iterdir()} in (set(CANARY_PAYLOADS), set(CANARY_PAYLOADS) | {"canary-build.json"}),
            "unexpected canary pilot payload")
    for name, (origin, role) in origins.items():
        item = artifacts[name]
        require(item["source"] == str(origin) and item["build"] == role
                and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                and sha(Path(bundle) / name) == item["sha256"], "stale/mixed canary output: " + name)
    return facts


def validate_canary_destination(destination, work=None):
    destination = Path(destination)
    require(destination.is_absolute() and not destination.exists() and not destination.is_symlink(),
            "canary export requires an absent absolute destination")
    require(destination.parent.is_dir() and str(destination.parent.resolve()) == str(destination.parent),
            "canary export requires a canonical existing parent")
    for parent in destination.parents:
        info = parent.stat()
        require(info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                "untrusted canary export ancestor")
    if work:
        work = Path(work).resolve()
        require(not work.is_relative_to(destination) and not destination.is_relative_to(work), "overlapping canary export/work")
    require(not ROOT.is_relative_to(destination), "canary export overlaps source root")
    return destination


def export_canary_inputs(destination, work, mode, bits, build_mode, revision, tree):
    """Called only after the shell's actual build steps; never performs a build or live operation."""
    destination, work = validate_canary_destination(destination, work), Path(work)
    require(subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT).returncode == 0
            and subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == revision
            and subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip() == tree,
            "source changed during canary input build")
    builds = [decode(line) for line in (work / "canary-build.commands.jsonl").read_text().splitlines()]
    obj, = (work / "default-build/release/build").glob("p11scope-*/out/p11scope-ebpf")
    origins = {"p11scope": (work / "default-build/release/p11scope", "observer"),
        "p11scope-discover": (work / ("helper-build/i686-unknown-linux-gnu/release/p11scope-discover" if bits == 32 else "default-build/release/p11scope-discover"), "helper" if bits == 32 else "observer"),
        "default-ebpf": (obj, "observer"), "canary_workload": (work / "canary_workload", "workload"),
        "matrix-provider.so": (work / "matrix-provider.so", "matrix-provider"),
        "privacy-provider.so": (work / "privacy-provider.so", "privacy-provider"),
        "dump-task-storage": (work / "task-storage-reader/dump-task-storage", "reader"),
        "dump-task-storage.bpf.o": (work / "task-storage-reader/dump-task-storage.bpf.o", "reader")}
    for name, (origin, _) in origins.items():
        fd = canary_fd(origin, maximum=64 * 1024 * 1024 if name.endswith((".bpf.o", "-ebpf")) else 512 * 1024 * 1024)
        os.close(fd)
    facts = {"producer": "verify-canaries.sh --prepare-object-inputs", "source_root": str(ROOT),
        "source_revision": revision, "source_tree": tree, "source_clean": True, "capture_mode": mode,
        "target_bits": bits, "build_mode": build_mode,
        "prepared_tools": {name: os.environ[name] for name in CANARY_PREPARED_TOOLS if os.environ.get(name)},
        "release_rust": (ROOT / ".release-rust-version").read_text().strip(),
        "build_environment": {name: os.environ.get(name) for name in CANARY_BUILD_ENV}, "builds": builds,
        "artifacts": {name: {"source": str(origin), "build": role, "sha256": sha(origin)} for name, (origin, role) in origins.items()},
        "runtime_sources": {name: sha(ROOT / name) for name in CANARY_RUNTIME_SOURCES},
        "producer_sources": {name: sha(ROOT / name) for name in CANARY_PRODUCER_SOURCES}}
    require(len((json.dumps(facts, sort_keys=True, indent=2) + "\n").encode()) <= CANARY_FACTS_MAX,
            "canary build facts exceed input bound")
    destination.mkdir(mode=0o700)
    try:
        for name, (origin, _) in origins.items():
            shutil.copy2(origin, destination / name)
        validate_canary_inputs(facts, destination, facts)
        save(destination / "canary-build.json", facts)
    except BaseException:
        shutil.rmtree(destination)
        raise


# Staged D4 file-identity registry (data only; the selection()/judge()
# wiring lands with the controller's completion). D4_CELLS maps each
# obligation to its qualifying libtest selectors; D4_LANES to the lanes
# that may qualify it; D4_READY carries the qualified (obligation, lane)
# pairs. The overlay and ext4 pairs below qualified on their lanes
# (ext4 on host, 6.1.188 and 6.6.157); D4:btrfs rows are owned by the
# zombie/batch jobs and are not staged here.
D4_CELLS = {
    "D4:overlay-6.1": ("discovery::sweep_attribution::tests::d4_overlay_cells::privileged_d4_overlay_xino_backend_parity",),
    "D4:overlay-6.6": ("discovery::sweep_attribution::tests::d4_overlay_cells::privileged_d4_overlay_xino_backend_parity",),
    "D4:overlay-6.8+": ("discovery::sweep_attribution::tests::d4_overlay_cells::privileged_d4_overlay_xino_backend_parity",),
    "D4:ext4-inode-reuse": ("discovery::sweep_attribution::tests::d4_ext4_cells::privileged_d4_ext4_inode_reuse_confirmation_parity",),
}
D4_LANES = {
    "D4:overlay-6.1": ("6.1.188",),
    "D4:overlay-6.6": ("6.6.157",),
    "D4:overlay-6.8+": ("6.8.0-142-generic", "6.12.111", "6.18.58", "7.2.6", "host",
                        FEDORA_LANE),
    "D4:ext4-inode-reuse": ("6.1.188", "6.6.157", "6.8.0-142-generic", "6.12.111", "6.18.58",
                            "7.2.6", "host", FEDORA_LANE),
}
D4_READY = frozenset(
    {
        ("D4:overlay-6.1", "6.1.188"),
        ("D4:overlay-6.6", "6.6.157"),
        ("D4:overlay-6.8+", "host"),
        ("D4:ext4-inode-reuse", "6.1.188"),
        ("D4:ext4-inode-reuse", "6.6.157"),
        ("D4:ext4-inode-reuse", "host"),
    }
)

def selection(lane, lib_tests=None, public_cells=None, scan=True, object_cells=()):
    require(lane in LANES, "unregistered kernel lane: " + lane)
    require(type(scan) is bool, "invalid scan selection")
    defaults = DEFAULT_LIB_TESTS + BREADTH
    libs = list(defaults if lib_tests is None else lib_tests)
    publics = list(PUBLIC if public_cells is None else public_cells)
    require(libs and all(isinstance(n, str) and n for n in libs), "empty lib selection")
    require(len(libs) == len(set(libs)), "duplicate selected lib ID")
    require(set(libs) <= set(DEFAULT_LIB_TESTS + BREADTH) | set(OTHER_LONG), "unknown exact lib selector")
    require(publics and len(publics) == len(set(publics)) and set(publics) <= set(PUBLIC), "invalid public selection")
    ids = list(BASE_IDS) + (["inventory-scan"] if scan else [])
    ids += ["public:" + n for n in publics] + ["lib:" + n for n in libs]
    objects = []
    selected = set()
    for mode, bits in object_cells:
        require(mode in ("full", "p0") and type(bits) is int and bits in (32, 64), "invalid object cell selection")
        require((mode, bits) not in selected, "duplicate object cell selection")
        selected.add((mode, bits))
    for mode, bits in sorted(selected):
        required = [f"object:{mode}:{bits}:complete", f"object:{mode}:{bits}:blocked"]
        objects.append({"mode": mode, "target_bits": bits, "bundle": f"artifacts/canary/{mode}-{bits}", "required_ids": required})
        ids.extend(required)
    return {"schema": SCHEMA, "claim": "selected-release-matrix", "lane": lane,
            "required_ids": ids, "lib_tests": libs, "object_cells": objects,
            "public_cells": [{"cell": n, "qualification": PUBLIC[n]} for n in publics],
            "include_scan": scan, "threads": 12, "pid_filter_test": PID_TEST,
            "tolerance_policy": {"environment": "unset-or-empty", "forbidden_environment": list(TOLERANCE_ENV),
                                 "retained_optins": "refuse", "lifecycle_loss_reported": "refuse"},
            "lib_outcomes": {name: "own-positive-or-pid-filter-refusal" if name in MULTI_OUTCOMES else
                             "rate100-lossless-and-rate1000-disclosed" if name == CHURN else
                             "selected-admission-and-broad-no-spill-or-whole-module-refusal" if name == BROAD else
                             "all-id-positive-or-envelope-refusal" if name == BOUNDARY else
                             "denial-with-zero-bpf-or-eligible-by-lane" if name == DENIAL_515 else "exact-success"
                             for name in libs},
            "lib_argv": ["--include-long", *libs],
            "pid_backend": {"proven": ["uprobe-multi", "kernel-pid+bpf"],
                            "unproven": ["per-offset", "perf-task+bpf", "expected-fallback"],
                            "preparation_refused": ["per-offset", "perf-task+bpf", "expected-fallback"]},
            "system_backend": {"linked": ["uprobe-multi", None]},
            "full_stage5_ready": False,
            "obligations": [{"id": "D4:" + substrate, "status": "unready", "libtest": None,
                             "prerequisites": "accepted D3/D4 source bodies and kernel/userspace parity selectors"}
                            for substrate in ("btrfs", "overlay-6.6", "overlay-6.8+", "ext4-inode-reuse")]
                + [{"id": "long:" + n, "status": "selected" if n in libs else "not-selected",
                    "libtest": n, "prerequisites": reason} for n, reason in OTHER_LONG.items()]}


def validate_contract(contract):
    require(isinstance(contract, dict), "contract is not an object")
    publics = contract.get("public_cells", [])
    require(isinstance(publics, list) and all(isinstance(row, dict) for row in publics), "invalid public contract")
    objects = contract.get("object_cells", [])
    require(isinstance(objects, list) and all(isinstance(row, dict) for row in objects), "invalid object contract")
    core = selection(contract.get("lane", ""), contract.get("lib_tests", []),
                     [row.get("cell") for row in publics], contract.get("include_scan"),
                     [(row.get("mode"), row.get("target_bits")) for row in objects])
    for key, value in core.items():
        require(contract.get(key) == value, "contract registration drift: " + key)
    require(isinstance(contract.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", contract["run_id"]), "invalid run binding")
    validate_run_identity(contract.get("run_identity"))
    if contract.get("guest_disk") is not None:
        require(contract["lane"] != FEDORA_LANE, "fedora lane cannot use a guest disk")
        require(contract["lane"] != "host", "host lane cannot use a guest disk")
        validate_guest_disk_binding(contract["guest_disk"])
    work_root = contract.get("guest_work_root")
    require(isinstance(work_root, str) and Path(work_root).is_absolute() and str(Path(work_root)) == work_root,
            "invalid guest work-root binding")
    boot = contract.get("guest_boot_config")
    if contract["lane"] in ("host", FEDORA_LANE):
        local = "host" if contract["lane"] == "host" else "fedora"
        require(boot is None and contract.get("expected_osrelease") is None, f"{local} lane must not stage guest boot config")
    else:
        require(isinstance(boot, dict) and set(boot) == {"source", "sha256", "osrelease"}, "invalid guest boot binding")
        require(isinstance(boot["source"], str) and Path(boot["source"]).is_absolute()
                and isinstance(boot["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", boot["sha256"]), "invalid guest boot source/hash")
        release = boot["osrelease"]
        require(isinstance(release, str) and re.fullmatch(re.escape(contract["lane"]) + r"(?:-[A-Za-z0-9._+-]+)?", release)
                and release == contract.get("expected_osrelease"), "guest boot osrelease/lane mismatch")
    return core


def listed_names(text):
    names = re.findall(r"^(.+): test$", text, re.M)
    require(names and len(names) == len(set(names)), "missing or duplicate binary --list IDs")
    return names


def curated_names(text):
    groups = {"default": [], "long": [], "skipped": []}
    group = None
    counts = {}
    for line in text.splitlines():
        match = re.fullmatch(r"(default|long|skipped) \((\d+)(?:, --include-long only)?\)", line)
        if match:
            group, count = match.groups()
            require(group not in counts, "duplicate curation section")
            counts[group] = int(count)
        elif line.startswith("verify:"):
            require(re.fullmatch(r"verify: curation matches the binary \(\d+ tests\)", line), "failed curation receipt")
        elif line.strip():
            require(group is not None and "::" in line, "invalid curation line")
            groups[group].append(line.split(" :: ", 1)[0])
    require(set(counts) == set(groups), "missing curation sections")
    for key, values in groups.items():
        require(len(values) == counts[key], "curation section count mismatch")
    all_names = sum(groups.values(), [])
    require(all_names and len(all_names) == len(set(all_names)), "duplicate curation ID")
    footer = re.findall(r"^verify: curation matches the binary \((\d+) tests\)$", text, re.M)
    require(footer == [str(len(all_names))], "missing/conflicting curation verification")
    return groups


def membership(stage, contract):
    listed = listed_names((stage / "inputs/ignored.txt").read_text())
    curated = curated_names((stage / "inputs/curation.txt").read_text())
    all_curated = sum(curated.values(), [])
    require(set(listed) == set(all_curated), "curation does not exactly cover candidate ignored list")
    for name in contract["lib_tests"]:
        require(name in listed, "required ID absent from candidate: " + name)
        require(name not in curated["skipped"], "required ID is statically skipped: " + name)
        require([n for n in all_curated if name in n] == [name], "ambiguous runner substring selector: " + name)
    require(PID_TEST in listed_names((stage / "inputs/bpfmulti-list.txt").read_text()), "missing exact PID-filter binary selector")


def prepare(args):
    stage = args.prepare.resolve()
    cells = object_arguments(args.object_input)
    core = selection(args.lane, args.lib_test, args.public_cell, not args.without_scan, [(mode, bits) for mode, bits, _ in cells])
    cells = [(mode, bits, validate_canary_payloads(bundle, bits)) for mode, bits, bundle in cells]
    for _, _, bundle in cells:
        require(not stage.is_relative_to(bundle) and not bundle.is_relative_to(stage), "overlapping canary input/stage")
    require(args.kernel is not None, "prepare requires the actual selected --kernel")
    disk = guest_disk_input(args.guest_disk, args.guest_disk_uuid)
    require(args.lane != "host" or disk is None, "host lane cannot use a guest disk")
    require(args.lane != FEDORA_LANE or disk is None, "fedora lane cannot use a guest disk")
    if args.lane in ("host", FEDORA_LANE):
        local = "host" if args.lane == "host" else "fedora"
        require(args.kernel == args.lane, f"{local} lane requires {local} kernel")
        config, release = None, None
    else:
        config, release = guest_boot_config(args.kernel)
        require(re.fullmatch(re.escape(args.lane) + r"(?:-[A-Za-z0-9._+-]+)?", release), "selected kernel differs from lane")
    identity = {"uid": os.getuid(), "gid": os.getgid(), "user": pwd.getpwuid(os.getuid()).pw_name}
    validate_run_identity(identity)
    require(args.guest_work_root.is_absolute(), "guest work root must be absolute")
    stage.mkdir(parents=True, exist_ok=True)
    require(not (stage / "contract.json").exists(), "refuse to overwrite an execution contract")
    core["run_id"] = uuid.uuid4().hex
    core["run_identity"] = identity
    core["guest_work_root"] = str(args.guest_work_root)
    core["guest_disk"] = disk
    core["expected_osrelease"] = release
    core["guest_boot_config"] = None
    bindings = {}
    sources = {"inputs/ignored.txt": args.binary_list, "inputs/curation.txt": args.curation,
               "inputs/bpfmulti-list.txt": args.bpfmulti_list}
    if config is not None:
        sources["inputs/boot-config"] = config
        core["guest_boot_config"] = {"source": str(config), "sha256": sha(config), "osrelease": release}
    require(args.bin_dir and all(sources.values()), "prepare requires exact artifacts, list and curation receipts")
    require(args.candidate_receipt is not None, "prebuilt candidate requires a build-produced source-root receipt")
    candidate = validate_candidate(load(args.candidate_receipt), args.bin_dir / "p11scope-lib")
    sources["inputs/candidate-build.json"] = args.candidate_receipt
    for name in RUNTIME_SOURCES:
        sources["artifacts/lib-source/" + name] = Path(candidate["source_root"]) / name
    # The native inventory lane passes a discover-produced manifest, so the
    # helper is staged with the candidate binaries; a bin dir without it
    # refuses here instead of failing attested delivery inside the guest.
    sources.update({"artifacts/" + name: args.bin_dir / name for name in
                    ("p11scope", "p11scope-lib", "p11scope-bpfmulti", "p11scope-discover")})
    for name in SOURCE_FILES:
        sources["artifacts/source/" + name] = ROOT / name
    canary_facts = {}
    if cells:
        for name in CANARY_SOURCE_FILES:
            sources["artifacts/source/" + name] = ROOT / name
    for mode, bits, bundle in cells:
        facts = validate_canary_inputs(load_canary_facts(bundle / "canary-build.json"), bundle, candidate)
        require((facts["capture_mode"], facts["target_bits"]) == (mode, bits), "selected canary mode/ABI differs from build")
        key = f"{mode}-{bits}"
        canary_facts[key] = facts
        sources[f"inputs/canary-build/{key}.json"] = bundle / "canary-build.json"
        for name in CANARY_PAYLOADS:
            sources[f"artifacts/canary/{key}/{name}"] = bundle / name
        for name in facts["runtime_sources"] | facts["producer_sources"]:
            sources[f"artifacts/canary-source/{key}/{name}"] = Path(facts["source_root"]) / name
    for name, origin in sources.items():
        require(origin.is_file(), "missing input: " + str(origin))
        path = relative(stage, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, path)
        bindings[name] = sha(path)
    for key, facts in canary_facts.items():
        validate_canary_inputs(load_canary_facts(stage / f"inputs/canary-build/{key}.json"), stage / f"artifacts/canary/{key}", candidate)
        for name, digest in (facts["runtime_sources"] | facts["producer_sources"]).items():
            require(bindings[f"artifacts/canary-source/{key}/{name}"] == digest, "canary source changed during staging")
    core["bindings"] = bindings
    validate_contract(core)
    if config is not None:
        require(bindings["inputs/boot-config"] == core["guest_boot_config"]["sha256"], "guest boot config changed during staging")
    membership(stage, core)
    save(stage / "contract.json", core)
    print(json.dumps({"contract": str(stage / "contract.json"), "sha256": sha(stage / "contract.json")}))


def expected_paths(contract):
    paths = set(EXITS) | {"uname.txt", "cells/results.jsonl", "run/results.txt",
                         "backend/inv-pid.json", "backend/inv-sys.json"}
    if contract["include_scan"]:
        paths.add("inv-scan.log")
    for name in contract["lib_tests"]:
        paths.add("run/logs/" + name.rsplit("::", 1)[-1] + ".log")
    for cell in contract["object_cells"]:
        prefix = f'object/{cell["mode"]}-{cell["target_bits"]}/'
        paths.update(prefix + name for name in ("run.log", "result.json"))
    return paths


def evidence_paths(stage, contract):
    paths = expected_paths(contract)
    for directory in ("cells", "run", "backend", "c8-native", "c8-scan", "object"):
        for path in (stage / directory).rglob("*"):
            if path.is_file():
                name = str(path.relative_to(stage))
                relative(stage, name)
                paths.add(name)
    return paths


def seal(stage, contract_path, guest_exit):
    contract = load(contract_path)
    validate_contract(contract)
    require(type(guest_exit) is int and 0 <= guest_exit <= 255, "invalid guest exit")
    hashes = {}
    for name in sorted(evidence_paths(stage, contract)):
        path = relative(stage, name)
        if path.is_file():
            hashes[name] = sha(path)
    save(stage / "receipt.json", {"schema": "p11scope/release-matrix-execution/v1",
                                 "run_id": contract["run_id"], "contract_sha256": sha(contract_path),
                                 "guest_exit": guest_exit, "evidence_sha256": hashes})


def process_exit(text, name, run_id):
    exits = re.findall(r"^" + re.escape(name) + r"_exit=(\d+)$", text, re.M)
    require(len(exits) == 1, "missing/conflicting " + name + "_exit")
    require(re.findall(r"^matrix_run=(\S+)$", text, re.M) == [run_id], "stale/unbound " + name + " log")
    return int(exits[0])


def exact_test(text, name):
    # Totals alone and zero-filter matches never establish the executed ID.
    require(re.findall(r"^test (\S+) \.\.\.", text, re.M) == [name], "wrong/missing exact test log: " + name)
    summaries = re.findall(r"^test result: (.+)$", text, re.M)
    require(len(summaries) == 1 and re.match(r"ok\. 1 passed; 0 failed; 0 ignored;", summaries[0]), "test did not execute exactly once: " + name)


def validate_candidate(receipt, lib):
    return _validate_candidate(receipt, lib, original_build_source)


def _validate_candidate(receipt, lib, source):
    require(isinstance(receipt, dict) and receipt.get("schema") == "p11scope/release-matrix-build/v1", "missing/invalid candidate build receipt")
    require(receipt.get("producer") == "cargo-build" and receipt.get("source_clean") is True,
            "candidate needs a clean actual Cargo build receipt, not a user declaration")
    root = build_root(receipt.get("source_root"))
    for key in ("source_revision", "source_tree"):
        require(isinstance(receipt.get(key), str) and re.fullmatch(r"[0-9a-f]{40}", receipt[key]), "missing exact build " + key)
    build = receipt.get("build", {})
    argv = build.get("argv", [])
    require(build.get("cwd") == str(root) and type(build.get("exit")) is int and build["exit"] == 0
            and isinstance(argv, list) and all(isinstance(value, str) and value for value in argv)
            and {"test", "--lib", "--no-run"} <= set(argv), "missing actual successful lib build command")
    require(receipt.get("lib_sha256") == sha(lib), "candidate build receipt binary mismatch")
    sources = receipt.get("runtime_sources", {})
    require(isinstance(sources, dict) and set(sources) == set(RUNTIME_SOURCES), "missing candidate runtime fixture closure")
    for name, digest in sources.items():
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "invalid candidate source hash")
        require(sha(source(root, name)) == digest, "compiled fixture source changed: " + name)
    return receipt


def launch_policy():
    for name in TOLERANCE_ENV:
        require(not os.environ.get(name), "disallowed qualification tolerance: " + name)


def denial_outcome(text, lane):
    """Strict lane classification of the 5.15 identity-denial cell (G23).

    Exactly one well-formed marker classifies; the 5.15 lane requires
    the denied branch (real BTF named-fix refusal with zero bpf()
    calls through the instrumented wrapper and the disclosed
    fallback), every other lane requires the eligible branch. Test
    success alone never classifies.
    """
    markers = re.findall(r"(?:^|\.\.\. )IDENTITY_515_DENIAL ([^\n]*)$", text, re.M)
    require(text.count("IDENTITY_515_DENIAL") == len(markers), "malformed denial marker")
    require(len(markers) == 1, "missing/duplicate denial marker")
    line = "IDENTITY_515_DENIAL " + markers[0]
    denied = re.fullmatch(
        r"IDENTITY_515_DENIAL outcome=denied reason=kernel_fix_missing "
        r"mm_present=false attach=(?:true|false) tasktype=(?:true|false) "
        r"bpf_delta=0 scan_bytes=[1-9][0-9]* fallback=kernel_fix_missing", line)
    # Eligible needs at least one pid_fd witness: check_kernel_identity_btf
    # returns Ok only when attach OR tasktype holds, so attach=false with
    # tasktype=false is unemittable on Ok and must not classify.
    eligible = re.fullmatch(
        r"IDENTITY_515_DENIAL outcome=eligible mm_present=true "
        r"(?:attach=true tasktype=(?:true|false)|attach=false tasktype=true) "
        r"bpf_delta=0 scan_bytes=[1-9][0-9]* sink=ok", line)
    if lane == "5.15.221":
        require(denied is not None, "5.15 lane requires the real denied refusal marker")
        return "expected-refusal", line
    require(eligible is not None, "non-5.15 lane requires the eligible marker")
    return "positive-coverage", line


def lib_outcome(name, text, lane=None):
    require("LIFECYCLE_LOSS_REPORTED" not in text, "disallowed lifecycle loss tolerance: " + name)
    if name == DENIAL_515:
        return denial_outcome(text, lane)
    if name in MULTI_OUTCOMES:
        tag = MULTI_OUTCOMES[name]
        lines = re.findall(r"(?:^|\.\.\. )(" + re.escape(tag) + r"[^\n]*)", text, re.M)
        require(len(lines) == 1, "missing/contradictory own Multi branch: " + name)
        line = lines[0]
        if " refused=" in line:
            require(re.fullmatch(re.escape(tag) + r' refused="[^\n]+"', line) and "pid filter" in line,
                    "invalid own PID-filter refusal: " + name)
            require("C3_PID_REUSE_EXCLUDED" not in text and "CLASSIC_PID_FOREIGN" not in text,
                    "own refusal contradicts positive execution evidence")
            return "expected-refusal", line
        if name == CLASSIC_MULTI:
            match = re.fullmatch(re.escape(tag) + r' multi=true scope_filter=Some\("kernel-pid\+bpf"\) fallback=None target=([1-9]\d*) target_runs=(\d+) foreign_runs=0 reused_runs=0 foreign_ns_per_call_before=[\d.]+ foreign_ns_per_call_during=[\d.]+', line)
            require(match and int(match[2]) >= 1000, "invalid own classic positive branch")
        elif tag.startswith("C3_PID_SCOPE"):
            match = re.fullmatch(re.escape(tag) + r" target=([1-9]\d*) foreign=([1-9]\d*) rows=1", line)
            reuse = re.findall(r"(?:^|\.\.\. )C3_PID_REUSE_EXCLUDED backend=Multi pid=(\d+) rows=0 custody=lost$", text, re.M)
            require(match and match[1] != match[2] and reuse == [match[1]], "missing own Multi foreign/reused-PID assertions")
        else:
            match = re.fullmatch(re.escape(tag) + r' pid=[1-9]\d* before_exit_usage1=1 leader_state=Z pidfd_alive=true after_exit_usage2_3=\[([01]), ([01])\] fired_after_exit=(true|false) custody=PidUnproven \{ at_ns: \d+, reason: "[^\n]*leader[^\n]*" \}', line)
            require(match and (match[3] == "true") == ("1" in (match[1], match[2])), "missing/conflicting own Multi leader-exit assertions")
        return "positive-coverage", line
    if name == CHURN:
        branches = re.findall(r"(?:^|\.\.\. )C57_CHURN_BRANCH rate=(\d+) branch=(\w+)([^\n]*)", text, re.M)
        require(branches and all(rate in ("100", "1000") and branch in ("starved", "lossless", "loss") for rate, branch, _ in branches), "churn skipped/unknown required assertion")
        low = [(branch, rest) for rate, branch, rest in branches if rate == "100"]
        high = [(branch, rest) for rate, branch, rest in branches if rate == "1000"]
        require(len(low) in (1, 2) and low[-1][0] == "lossless" and all(branch == "starved" for branch, _ in low[:-1])
                and re.fullmatch(r" attempt=[12]", low[-1][1])
                and (len(low) == 1 or (re.fullmatch(r" attempt=1 achieved=[\d.]+", low[0][1]) and low[-1][1] == " attempt=2"))
                and len(high) == 1 and high[0][0] in ("loss", "lossless") and not high[0][1], "missing/contradictory churn rate100 zero-loss or rate1000 disclosure")
        return "positive-coverage", "rate100=lossless; rate1000=" + high[0][0]
    if name == BROAD:
        selected = re.findall(r"(?:^|\.\.\. )A2 selected: \d+ module\(s\) \d+ table\(s\) (\d+) slot\(s\) spill=\d+ refused=\d+$", text, re.M)
        broad = re.findall(r"(?:^|\.\.\. )A2 broad: ([^\n]+)", text, re.M)
        require(len(selected) == len(broad) == 1 and int(selected[0]) > 0, "missing/contradictory own p11-kit admission evidence")
        if broad[0].startswith("total refusal:"):
            require("refusing to attach a prefix" in broad[0], "invalid broad whole-module refusal")
            return "expected-refusal", "selected admission slots=" + selected[0] + "; broad " + broad[0]
        require(re.fullmatch(r"\d+ module\(s\) \d+ table\(s\) \d+ slot\(s\) spill=0 refused=\d+", broad[0]), "invalid own broad no-spill assertion")
        return "positive-coverage", "selected admission slots=" + selected[0] + "; broad " + broad[0]
    if name == BOUNDARY:
        return boundary_outcome(text)
    return "positive-coverage", "exact ID once, exit0, one test passed"


def boundary_outcome(text):
    """Strict finite classification of the T7 8192 boundary cell (G01/R7).

    The cell succeeds on three disjoint outcomes: the exact all-ID
    positive, a preflight envelope refusal, or a post-failure envelope
    refusal. Refusals keep an explicit non-positive classification;
    missing, duplicate, contradictory or malformed branch evidence fails.
    Every marker occurrence must match its complete line: a stray or
    extra-field duplicate is rejected, never silently ignored.
    """
    refusals = re.findall(r"T7_ENVELOPE_REFUSAL cell=(\S+) n=(\d+) phase=(\S+) verdict=\"([^\n]*)\"$",
                          text, re.M)
    require(text.count("T7_ENVELOPE_REFUSAL") == len(refusals),
            "malformed boundary refusal marker")
    ledgers = re.findall(r"(?:^|\.\.\. )TASK4_LEDGER phase=after_go physical_ids=(\d+) "
                         r"completed_calls=(\d+) first=(\d+) tail=(\d+)$", text, re.M)
    raw_maps = re.findall(r"(?:^|\.\.\. )TASK4_RAW_MAPS phase=after_go usage_positive=(\d+) "
                          r"exact_ids=(\d+)\.\.(\d+)$", text, re.M)
    require(text.count("TASK4_LEDGER") == len(ledgers),
            "malformed boundary ledger evidence")
    require(text.count("TASK4_RAW_MAPS") == len(raw_maps),
            "malformed boundary raw-map evidence")
    if refusals:
        require(len(refusals) == 1, "missing/duplicate boundary refusal branch")
        cell, count, phase, verdict = refusals[0]
        require(cell == BOUNDARY_CELL and count == str(BOUNDARY_N), "boundary refusal names another cell")
        require(phase in BOUNDARY_PHASES, "boundary refusal phase is not a finite envelope branch")
        require(verdict.strip(), "boundary refusal verdict is empty")
        require(not ledgers and not raw_maps, "boundary refusal contradicts positive evidence")
        return "expected-refusal", f"cell={cell} n={count} phase={phase}"
    require(not ledgers or len(ledgers) == 1, "duplicate boundary ledger evidence")
    require(not raw_maps or len(raw_maps) == 1, "duplicate boundary raw-map evidence")
    require(len(ledgers) == len(raw_maps) == 1, "boundary positive requires all-ID population evidence")
    require(ledgers[0] == (str(BOUNDARY_N), str(BOUNDARY_N), "0", str(BOUNDARY_N - 1))
            and raw_maps[0] == (str(BOUNDARY_N), "0", str(BOUNDARY_N - 1)),
            "boundary positive population is not the exact all-ID set")
    return "positive-coverage", f"all {BOUNDARY_N} IDs latched: ledger and raw-map evidence agree"


def verify_inputs(stage, contract_path):
    return _verify_inputs(stage, contract_path, validate_candidate, validate_canary_inputs)


def _verify_object_inputs(stage, contract_path):
    # Only object dispatch selects retained sources. Full launch and judgment
    # deliberately keep the compiled Rust fixtures' original-root preflight.
    def retained(prefix):
        def source(_root, name):
            path = relative(stage, prefix + name)
            require(path.is_file() and path == path.resolve(strict=True), "invalid retained source")
            return path
        return source
    def candidate(receipt, lib):
        return _validate_candidate(receipt, lib, retained("artifacts/lib-source/"))
    def canary(facts, bundle, candidate_facts, uid):
        key = f'{facts["capture_mode"]}-{facts["target_bits"]}'
        return _validate_canary_inputs(facts, bundle, candidate_facts, uid,
                                      retained(f"artifacts/canary-source/{key}/"))
    contract = _verify_inputs(stage, contract_path, candidate, canary)
    require(contract["object_cells"], "retained source resolver requires selected object cells")
    return contract


def _verify_inputs(stage, contract_path, candidate_validator, canary_validator):
    contract = load(contract_path)
    validate_contract(contract)
    bindings = contract.get("bindings")
    required = {
        "artifacts/p11scope", "artifacts/p11scope-lib", "artifacts/p11scope-bpfmulti",
        "artifacts/p11scope-discover",
        "inputs/ignored.txt", "inputs/curation.txt", "inputs/bpfmulti-list.txt",
        "inputs/candidate-build.json"}
    required.update("artifacts/source/" + name for name in SOURCE_FILES)
    required.update("artifacts/lib-source/" + name for name in RUNTIME_SOURCES)
    if contract["guest_boot_config"] is not None:
        required.add("inputs/boot-config")
        require(isinstance(bindings, dict) and bindings.get("inputs/boot-config") == contract["guest_boot_config"]["sha256"], "guest boot hash differs from binding")
    else:
        require(isinstance(bindings, dict) and "inputs/boot-config" not in bindings, "host lane has guest boot binding")
    if contract["object_cells"]:
        required.update("artifacts/source/" + name for name in CANARY_SOURCE_FILES)
    for cell in contract["object_cells"]:
        key = f'{cell["mode"]}-{cell["target_bits"]}'
        required.add(f"inputs/canary-build/{key}.json")
        required.update(f"artifacts/canary/{key}/{name}" for name in CANARY_PAYLOADS)
        required.update(f"artifacts/canary-source/{key}/{name}" for name in (*CANARY_RUNTIME_SOURCES, *CANARY_PRODUCER_SOURCES))
    require(isinstance(bindings, dict) and set(bindings) >= required, "missing required source/artifact bindings")
    for name, digest in bindings.items():
        require(re.fullmatch(r"[0-9a-f]{64}", digest or ""), "invalid binding hash")
        require(sha(relative(stage, name)) == digest, "stale artifact hash: " + name)
        if name.startswith("artifacts/source/"):
            require(sha(ROOT / name.removeprefix("artifacts/source/")) == digest, "runtime source changed: " + name)
    require(bindings["artifacts/source/scripts/release-matrix-contract.py"] == sha(Path(__file__)), "judge source changed from contract")
    candidate = candidate_validator(load(stage / "inputs/candidate-build.json"), stage / "artifacts/p11scope-lib")
    # Root consumes files staged by the validated nonroot caller. Generic export
    # and prebuilt validation keep their original current-UID-only policy.
    input_uid = contract["run_identity"]["uid"]
    for cell in contract["object_cells"]:
        key = f'{cell["mode"]}-{cell["target_bits"]}'
        facts = canary_validator(load_canary_facts(stage / f"inputs/canary-build/{key}.json", input_uid),
                                 stage / cell["bundle"], candidate, input_uid)
        require((facts["capture_mode"], facts["target_bits"]) == (cell["mode"], cell["target_bits"]), "selected canary mode/ABI differs from build")
        for name, digest in (facts["runtime_sources"] | facts["producer_sources"]).items():
            require(bindings[f"artifacts/canary-source/{key}/{name}"] == digest, "compiled canary snapshot differs from build")
    for name, digest in candidate["runtime_sources"].items():
        require(bindings["artifacts/lib-source/" + name] == digest, "compiled fixture snapshot does not match build receipt")
    membership(stage, contract)
    return contract


def object_relative(name):
    require(isinstance(name, str) and name.startswith("evidence/")
            and str(Path(name)) == name and ".." not in Path(name).parts,
            "invalid copied object path")
    return name


def object_file_set(directory):
    require(directory.is_dir() and directory == directory.resolve(strict=True), "invalid object result directory")
    names = set()
    for path in directory.rglob("*"):
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "special/symlink object output")
        if stat.S_ISREG(mode): names.add(path.relative_to(directory).as_posix())
    return names


def object_closure(result, contract, cell, read):
    """Check copied names and immutable receipt hashes without reopening guest paths."""
    fields = {"run_id", "mode", "target_bits", "original_work_root", "runner_exit", "rows", "evidence_files"}
    require(isinstance(result, dict) and set(result) == fields, "invalid object result fields")
    mode, bits = cell["mode"], cell["target_bits"]
    require(result["run_id"] == contract["run_id"] and result["mode"] == mode
            and type(result["target_bits"]) is int and result["target_bits"] == bits,
            "stale/wrong object result selection")
    require(type(result["runner_exit"]) is int and result["runner_exit"] == 0, "object runner failed")
    original = build_root(result["original_work_root"])
    bound = build_root(contract["guest_work_root"])
    require(original != bound and original.is_relative_to(bound),
            "object original work root must be a strict descendant of bound guest work root")
    def copied(path):
        path = build_root(path)
        require(path != original and path.is_relative_to(original), "object reference escapes original work root")
        return object_relative("evidence/" + path.relative_to(original).as_posix())
    names = {"evidence/matrix-manifest.json", "evidence/privacy-manifest.json"}
    lane = "object-ia32" if bits == 32 else "object-lp64"
    rows = result["rows"]
    require(isinstance(rows, list) and len(rows) == 2, "object result requires both exact siblings")
    inventory = runpy.run_path(str(ROOT / "scripts/check-bpf-map-defs.py"))["SAFE_MAPS"]
    for row, role, current in zip(rows, ("complete", "blocked"), (lane, lane + "-blocked")):
        require(isinstance(row, dict) and set(row) == {"id", "lane", "manifest", "receipt"}, "invalid object row")
        require(row["id"] == f"object:{mode}:{bits}:{role}" and row["lane"] == current
                and row["manifest"] == f"evidence/mapdump_manifest_{current}.json", "wrong/duplicate object sibling")
        manifest_name = object_relative(row["manifest"])
        manifest = decode(read(manifest_name).decode())
        require(isinstance(manifest, list) and all(isinstance(item, dict) for item in manifest)
                and len(manifest) == len(inventory) and {item.get("name") for item in manifest} == set(inventory),
                "object manifest lacks exact owned map inventory")
        ids = [item.get("id") for item in manifest]
        require(all(type(value) is int and value > 0 for value in ids) and len(set(ids)) == len(ids), "invalid/duplicate object map ID")
        receipts = set()
        surfaces = {}
        for item in manifest:
            snapshot = item.get("snapshot")
            require(isinstance(snapshot, dict) and set(snapshot) == {"contract", "acquisition_id", "phase", "receipt"}
                    and snapshot["contract"] == "p11scope/stopped-task-storage/v1" and snapshot["phase"] == "stopped"
                    and isinstance(snapshot["acquisition_id"], str)
                    and re.fullmatch(r"[0-9a-f]{32}", snapshot["acquisition_id"]), "invalid object stopped snapshot")
            receipts.add((copied(snapshot["receipt"]), snapshot["acquisition_id"]))
            name = (f"evidence/{current}.{item['name']}.raw" if item.get("type") == "ringbuf"
                    else copied(item.get("file")))
            require(name not in surfaces.values(), "aliased object map surface")
            surfaces[item["id"]] = name
        require(len(receipts) == 1, "conflicting object stopped receipts")
        receipt_name, acquisition = next(iter(receipts))
        require(object_relative(row["receipt"]) == receipt_name, "wrong object stopped receipt reference")
        receipt = decode(read(receipt_name).decode())
        require(isinstance(receipt, dict) and set(receipt) == {"contract", "acquisition_id", "phase", "lane",
                "small_state", "expected", "before", "after", "surfaces"}
                and receipt["contract"] == "p11scope/stopped-task-storage/v1" and receipt["phase"] == "stopped"
                and receipt["acquisition_id"] == acquisition, "invalid object stopped receipt")
        recorded = receipt["surfaces"]
        require(isinstance(recorded, list) and all(isinstance(item, dict) for item in recorded)
                and len(recorded) == len(surfaces) and {item.get("id") for item in recorded} == set(surfaces),
                "object receipt surface set differs from manifest")
        for item in recorded:
            raw = read(surfaces[item["id"]])
            require(item.get("acquisition_id") == acquisition and type(item.get("size")) is int
                    and item["size"] == len(raw) and item.get("sha256") == hashlib.sha256(raw).hexdigest(),
                    "object stopped surface bytes changed")
        names.update(surfaces.values())
        names.update((manifest_name, receipt_name, f"evidence/{current}.ready"))
        names.update(f"evidence/{current}.{suffix}" for suffix in ("output", "observer.log", "workload.log"))
    files = result["evidence_files"]
    require(isinstance(files, list) and all(isinstance(name, str) for name in files)
            and files == sorted(names), "missing/duplicate/unexpected object copied file")
    for name in names: read(object_relative(name))
    return names


def object_rows(stage, contract):
    root = stage / "object"
    selected = {f'{cell["mode"]}-{cell["target_bits"]}' for cell in contract["object_cells"]}
    require(not root.exists() or (root.is_dir() and not root.is_symlink()
            and {path.name for path in root.iterdir()} == selected), "unexpected/missing object cell directory")
    rows = []
    for cell in contract["object_cells"]:
        directory = root / f'{cell["mode"]}-{cell["target_bits"]}'
        files = object_file_set(directory)
        result = load(directory / "result.json")
        names = object_closure(result, contract, cell, lambda name: relative(directory, name).read_bytes())
        require(files == names | {"run.log", "result.json"}, "object result file closure differs from copied files")
        log = (directory / "run.log").read_text()
        for process in ("object_runner", "object_semantic", "object_final"):
            require(process_exit(log, process, contract["run_id"]) == 0, "object checker/runner failed: " + process)
        rows.extend({"id": row["id"], "pass": True, "qualification": "positive-coverage",
                     "detail": "exact prebuilt sibling; guest semantic/final checkers exit0; closed stopped surfaces bound"}
                    for row in result["rows"])
    return rows


def run_objects(stage, contract_path, work_root):
    """Execute only the bound eight-input object pilots; never build an input."""
    launch_policy()
    if not load(contract_path).get("object_cells"):
        verify_inputs(stage, contract_path)
        require(not (stage / "object").exists(), "unselected object output exists")
        return
    contract = _verify_object_inputs(stage, contract_path)
    account = validate_run_identity(contract["run_identity"])
    def caller(*argv, **kwargs):
        return subprocess.run(["runuser", "-u", account.pw_name, "--", *map(str, argv)], **kwargs)
    for flag, expected in (("-u", account.pw_uid), ("-g", account.pw_gid)):
        result = caller("id", flag, text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout.strip() == str(expected), "object runner effective identity mismatch")
    require(caller("sudo", "-n", "true").returncode == 0, "object runner needs noninteractive sudo")
    require(work_root is not None, "object work root required")
    bound = validate_guest_work_root(contract["guest_work_root"], account.pw_uid)
    work_root = validate_guest_work_root(work_root, account.pw_uid)
    require(work_root != bound and work_root.is_relative_to(bound),
            "object work root must be a strict descendant of bound guest work root")
    require(work_root.stat().st_uid == account.pw_uid and not work_root.stat().st_mode & 0o077,
            "object work root must be caller-owned and private")
    require(not work_root.is_relative_to(stage) and not stage.is_relative_to(work_root), "object work/input trees overlap")
    for name in contract["bindings"]:
        require(caller("test", "-r", stage / name).returncode == 0, "object runner cannot read bound input")
    output = stage / "object"
    require(not output.exists() and not output.is_symlink(), "refuse existing object execution output")
    output.mkdir()
    source = stage / "artifacts/source"
    for cell in contract["object_cells"]:
        mode, bits = cell["mode"], cell["target_bits"]
        key = f"{mode}-{bits}"
        directory = output / key
        directory.mkdir()
        work = Path(tempfile.mkdtemp(prefix=key + "-", dir=work_root))
        temporary = work / "tmp"
        temporary.mkdir(mode=0o700)
        os.chown(temporary, account.pw_uid, account.pw_gid)
        os.chown(work, account.pw_uid, account.pw_gid)
        log_path = directory / "run.log"
        commands = []
        with log_path.open("w") as log:
            def checked(name, argv, as_caller=False):
                if as_caller:
                    result = caller(*argv, stdout=log, stderr=subprocess.STDOUT, cwd=source)
                else:
                    result = subprocess.run(list(map(str, argv)), stdout=log, stderr=subprocess.STDOUT, cwd=source)
                log.write(f"{name}_exit={result.returncode}\n"); log.flush()
                commands.append((name, result.returncode))
                require(result.returncode == 0, "object command failed: " + name)
            try:
                checked("object_runner", ["env", f"P11SCOPE_CANARY_TARGET_BITS={bits}",
                    f"P11SCOPE_RECEIPT_WORK={work}", f"TMPDIR={temporary}", source / "scripts/verify-canaries.sh",
                    "--capture-mode", mode, "--prebuilt-dir", stage / cell["bundle"], "--object-pilot"], True)
                lane = "object-ia32" if bits == 32 else "object-lp64"
                pids = []
                for current in (lane, lane + "-blocked"):
                    roster = load(work / (current + ".ready"))
                    pid = roster.get("pid")
                    require(type(pid) is int and pid > 0, "object ready roster lacks actual workload PID")
                    pids.append(pid)
                attributes = "present" if mode == "full" else "absent"
                checked("object_semantic", [sys.executable, "-I", source / "scripts/check-canary-evidence.py",
                    "--object-attributes", attributes, "--object-starts", work / f"mapdump_manifest_{lane}.json",
                    work / f"mapdump_manifest_{lane}-blocked.json", work / (lane + ".workload.log"),
                    work / (lane + "-blocked.workload.log"), *pids, bits])
                checked("object_final", [sys.executable, "-I", source / "scripts/check-canary-evidence.py",
                    "--object-attributes", attributes, "--object-pilot", work, bits])
            finally:
                log.write(f'matrix_run={contract["run_id"]}\n')
        require(commands == [("object_runner", 0), ("object_semantic", 0), ("object_final", 0)], "incomplete object command set")
        # Keep original absolute-path receipts unchanged. The final checkers ran
        # above while these guest-local paths existed; host judgment verifies
        # the copied closure, hashes and bound command statuses.
        checker = runpy.run_path(str(source / "scripts/check-canary-evidence.py"))
        checker["initialize"](bits)
        names = {"matrix-manifest.json", "privacy-manifest.json"}
        rows = []
        for role, current in (("complete", lane), ("blocked", lane + "-blocked")):
            manifest_name = f"mapdump_manifest_{current}.json"
            manifest = load(work / manifest_name)
            receipt = build_root(manifest[0]["snapshot"]["receipt"])
            require(receipt.is_relative_to(work), "object receipt escapes work")
            rows.append({"id": f"object:{mode}:{bits}:{role}", "lane": current,
                         "manifest": "evidence/" + manifest_name,
                         "receipt": "evidence/" + receipt.relative_to(work).as_posix()})
            surfaces = checker["assert_exact_owned_map_inventory"](work, current, checker["initialize"].__globals__["SAFE_MAPS"])
            names.update(path.relative_to(work).as_posix() for path in checker["final_lane_artifacts"](work, current, surfaces))
            names.add(current + ".ready")
        result = {"run_id": contract["run_id"], "mode": mode, "target_bits": bits, "original_work_root": str(work),
                  "runner_exit": 0, "rows": rows, "evidence_files": ["evidence/" + name for name in sorted(names)]}
        def original(name):
            path = work / object_relative(name).removeprefix("evidence/")
            require(path == path.resolve(strict=True) and path.is_file(), "special/symlink original object output")
            return path
        object_closure(result, contract, cell, lambda name: original(name).read_bytes())
        for name in result["evidence_files"]:
            destination = relative(directory, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy_guest_file(original(name), destination)
        _verify_object_inputs(stage, contract_path)
        object_closure(result, contract, cell, lambda name: relative(directory, name).read_bytes())
        require(object_file_set(directory) == set(result["evidence_files"]) | {"run.log"}, "object copy closure differs")
        save(directory / "result.json", result)
    object_rows(stage, contract)


def judge(stage, contract_path):
    contract = verify_inputs(stage, contract_path)
    receipt = load(stage / "receipt.json")
    require(receipt.get("schema") == "p11scope/release-matrix-execution/v1", "unknown execution receipt")
    require(receipt.get("run_id") == contract["run_id"] and receipt.get("contract_sha256") == sha(contract_path), "stale execution/contract hash")
    require(type(receipt.get("guest_exit")) is int and receipt["guest_exit"] == 0, "guest failed or timed out")
    hashes = receipt.get("evidence_sha256", {})
    require(set(hashes) == evidence_paths(stage, contract), "missing/unexpected required artifacts")
    for name, digest in hashes.items():
        require(sha(relative(stage, name)) == digest, "stale evidence hash: " + name)
    read = lambda name: relative(stage, name).read_text()
    require(contract["lane"] in ("host", FEDORA_LANE) or read("uname.txt").strip() == contract["expected_osrelease"], "wrong executed kernel osrelease")
    exits = {name: process_exit(read(path), name, contract["run_id"]) for path, name in EXITS.items()}
    if contract["include_scan"]:
        exits["inv_scan"] = process_exit(read("inv-scan.log"), "inv_scan", contract["run_id"])
        require(exits["inv_scan"] == 2, "scan must remain valid nonqualifying plumbing (exit2)")
    nonqual_public = any(row["qualification"] == "nonqualifying" for row in contract["public_cells"])
    for name, rc in exits.items():
        expected = 2 if name == "inv_scan" or (name == "qual" and nonqual_public) else 0
        require(rc == expected, "unexpected " + name + "_exit=" + str(rc))
    require("p11scope" in read("version.log").lower(), "missing observer version")
    require(len(re.findall(r"capability tier:\s*T[0-4]", read("doctor.log"))) == 1, "missing/duplicate capability tier")
    rows = []
    def row(id_, qualification, detail):
        rows.append({"id": id_, "pass": qualification != "nonqualifying", "qualification": qualification, "detail": detail})
    row("version", "command-contract", "bound candidate, exit0")
    row("doctor", "command-contract", "functional doctor ran, exit0")
    row("inventory-native", "positive-coverage", "independent native oracle exit0")
    if contract["include_scan"]:
        row("inventory-scan", "nonqualifying", "scan oracle exit2; no positive native coverage")
    public_rows = [load_json_line(line) for line in read("cells/results.jsonl").splitlines() if line.strip()]
    public_ids = [r.get("cell") for r in public_rows]
    require(len(public_ids) == len(set(public_ids)) and set(public_ids) == {r["cell"] for r in contract["public_cells"]}, "missing/duplicate/unexpected public cell ID")
    for result in public_rows:
        name = result["cell"]
        qualification = PUBLIC[name]
        require(set(result) == {"cell", "pass", "detail", "qualification"} and isinstance(result["detail"], str), "invalid public terminal row")
        require(result["qualification"] == qualification and result["pass"] is (qualification != "nonqualifying"), "failed/wrong public classification: " + name)
        row("public:" + name, qualification, result["detail"])
    exact_test(read("pidflt.log"), PID_TEST)
    proofs = re.findall(r"(?:^|\.\.\. )PIDFLT_PROBE own=(\d+) other=(\d+) proves=(true|false)$", read("pidflt.log"), re.M)
    require(len(proofs) <= 1, "duplicate PID-filter capability evidence")
    pid_proven = False
    if proofs:
        own, other, proves = proofs[0]
        require(int(own) <= 2 and int(other) <= 1, "invalid PID-filter probe counts")
        pid_proven = own == "2" and other == "0"
        require((proves == "true") == pid_proven, "conflicting functional PID-filter proof")
    row("pid-filter", "positive-coverage" if pid_proven else "expected-refusal", "own=2 other=0 proven" if pid_proven else "PID Multi unproven; fallback/refusal required")
    doctor_rows = re.findall(r"^uprobe-multi attach \(own libc\)\s*\.+\s*(ok|warn|n/a)\s*(.*)$", read("doctor.log"), re.M)
    require(len(doctor_rows) == 1, "missing/duplicate system functional probe")
    system_proven = doctor_rows[0][0] == "ok" and doctor_rows[0][1].strip() in (
        "self-link attached and detached",
        "scratch program loaded; self-link attached and detached (delivery unmeasured)")
    require(system_proven, "uprobe-multi-required: live-positive qualification requires general host load/self-link proof")
    for scope, proven in (("pid", pid_proven), ("sys", system_proven)):
        attach = load(relative(stage, "backend/inv-" + scope + ".json")).get("observation", {}).get("attach", {})
        fallback = attach.get("fallback")
        preparation_refused = (proven and isinstance(fallback, str)
                               and fallback.startswith("the uprobe-multi preparation failed: ")
                               and len(fallback) > len("the uprobe-multi preparation failed: "))
        require(scope != "sys" or not preparation_refused, "system Multi positive cannot use a preparation fallback")
        multi = proven and not preparation_refused
        expected_mechanism = "uprobe-multi" if multi else "per-offset"
        expected_filter = ("kernel-pid+bpf" if multi else "perf-task+bpf") if scope == "pid" else None
        require(attach.get("mechanism") == expected_mechanism and attach.get("scope_filter") == expected_filter, "unsupported/wrong " + scope + " backend or scope-filter")
        if multi:
            require(fallback is None, "capable backend unexpectedly fell back")
        elif not preparation_refused:
            marker = "pid filter" if scope == "pid" else "functional probe failed"
            require(isinstance(fallback, str) and marker in fallback, "missing declared " + scope + " fallback reason")
        row("backend-pid" if scope == "pid" else "backend-system", "positive-coverage" if multi else "expected-fallback", expected_mechanism + "/" + str(expected_filter))
    records = []
    require(not re.search(r"^# opt-in: (?:" + "|".join(TOLERANCE_ENV) + r")=", read("run/results.txt"), re.M), "disallowed retained qualification tolerance")
    require("LIFECYCLE_LOSS_REPORTED" not in read("priv.log"), "disallowed retained lifecycle loss tolerance")
    for line in read("run/results.txt").splitlines():
        if line.startswith(("PASS ", "FAIL ", "SKIP ")):
            match = re.fullmatch(r"PASS (\S+) rc=0 seconds=\d+ :: test result: ok\. 1 passed(?:;.*)?", line)
            require(match is not None, "failed/skipped/invalid required lib record: " + line)
            records.append(match[1])
    require(len(records) == len(set(records)) and set(records) == set(contract["lib_tests"]), "missing/duplicate/unexpected executed lib ID")
    for name in records:
        text = read("run/logs/" + name.rsplit("::", 1)[-1] + ".log")
        exact_test(text, name)
        qualification, detail = lib_outcome(name, text, contract["lane"])
        row("lib:" + name, qualification, detail)
    rows.extend(object_rows(stage, contract))
    require(len(rows) == len(contract["required_ids"]) and {r["id"] for r in rows} == set(contract["required_ids"]), "missing/duplicate/unexpected required ID")
    nonqual = any(r["qualification"] == "nonqualifying" for r in rows)
    return {"schema": "p11scope/release-matrix-verdict/v1", "claim": contract["claim"], "lane": contract["lane"],
            "pass": not nonqual, "qualification": "nonqualifying" if nonqual else "selected-coverage",
            "full_stage5_ready": False, "contract_sha256": sha(contract_path), "run_id": contract["run_id"],
            "rows": rows, "detail": "all exact selected assertions satisfied; full Stage5 remains pending"}, 2 if nonqual else 0


def load_json_line(line):
    result = decode(line)
    require(isinstance(result, dict), "non-object public row")
    return result


def object_arguments(arguments):
    cells = []
    for mode, bits, directory in arguments or []:
        require(mode in ("full", "p0") and bits in ("32", "64") and Path(directory).is_absolute(), "invalid object input selection")
        cells.append((mode, int(bits), Path(directory)))
    return cells


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--prepare", type=Path)
    modes.add_argument("--seal", type=Path)
    modes.add_argument("--judge", type=Path)
    modes.add_argument("--verify-inputs", type=Path)
    modes.add_argument("--verify-launch-policy", action="store_true")
    modes.add_argument("--guest-environment", type=Path)
    modes.add_argument("--check-guest-disk", action="store_true")
    modes.add_argument("--launch-guest", type=Path)
    modes.add_argument("--run-guest-inner", type=Path)
    modes.add_argument("--run-objects", type=Path)
    modes.add_argument("--check-work-root", type=Path)
    modes.add_argument("--copy-file", nargs=2, type=Path, metavar=("SOURCE", "DESTINATION"))
    modes.add_argument("--copy-tree", nargs=3, metavar=("KIND", "SOURCE", "DESTINATION"))
    modes.add_argument("--select-module", action="store_true")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--lane", default="host")
    parser.add_argument("--kernel")
    parser.add_argument("--guest-work-root", type=Path, default=Path("/var/tmp/p11scope-ws-tmp"))
    parser.add_argument("--guest-disk")
    parser.add_argument("--guest-disk-uuid")
    parser.add_argument("--object-work-root", type=Path)
    parser.add_argument("--module")
    parser.add_argument("--lib-test", action="append")
    parser.add_argument("--public-cell", action="append")
    parser.add_argument("--without-scan", action="store_true")
    parser.add_argument("--bin-dir", type=Path)
    parser.add_argument("--binary-list", type=Path)
    parser.add_argument("--curation", type=Path)
    parser.add_argument("--bpfmulti-list", type=Path)
    parser.add_argument("--candidate-receipt", type=Path)
    parser.add_argument("--guest-exit", type=int)
    parser.add_argument("--object-input", nargs=3, action="append", metavar=("MODE", "BITS", "ABS_DIR"))
    args = parser.parse_args(argv)
    try:
        if args.verify_launch_policy:
            launch_policy()
            return 0
        if args.check_guest_disk:
            print(json.dumps(guest_disk_input(args.guest_disk, args.guest_disk_uuid)))
            return 0
        if args.check_work_root:
            print(validate_guest_work_root(args.check_work_root))
            return 0
        if args.copy_file:
            copy_guest_file(*args.copy_file)
            return 0
        if args.copy_tree:
            kind, source, destination = args.copy_tree
            copy_guest_tree(source, destination, kind)
            return 0
        if args.select_module:
            print(select_module(args.module))
            return 0
        if args.plan:
            cells = object_arguments(args.object_input)
            print(json.dumps({"lanes": LANES, "execution": selection(args.lane, args.lib_test, args.public_cell, not args.without_scan,
                [(mode, bits) for mode, bits, _ in cells])}, indent=2))
            return 0
        if args.prepare:
            prepare(args)
            return 0
        stage = (args.seal or args.judge or args.verify_inputs or args.guest_environment or args.run_objects
                 or args.launch_guest or args.run_guest_inner).resolve()
        require(args.contract is not None, "--contract required")
        require(args.contract.resolve() == (stage / "contract.json").resolve(), "contract must be the execution copy inside stage")
        if args.launch_guest:
            return launch_guest(stage, args.contract, args.kernel)
        if args.run_guest_inner:
            return run_guest_inner(stage, args.contract)
        if args.run_objects:
            run_objects(stage, args.contract, args.object_work_root)
            return 0
        if args.guest_environment:
            guest_environment(stage, args.contract)
            return 0
        if args.verify_inputs:
            verify_inputs(stage, args.contract)
            return 0
        if args.seal:
            seal(stage, args.contract, args.guest_exit)
            return 0
        result, rc = judge(stage, args.contract)
        print(json.dumps(result, sort_keys=True))
        return rc
    except (Invalid, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps({"pass": False, "qualification": "failed", "detail": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
