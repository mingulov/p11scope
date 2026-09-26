//! SPDX-License-Identifier: GPL-3.0-or-later
//! Usability journey baseline pins (Task 1 of the 2026-09-17 usability pass).
//!
//! Each test scripts one baseline probe (B1–B7) or journey step (J1–J6) as a
//! subprocess trial and asserts the behavior observed on 2026-09-17. These
//! pins PASS on current behavior by design: where the observed behavior is a
//! friction, the test pins it (with its F-number) so the fixing task REDs the
//! pin first and then flips it. The FRICTION list itself lives in
//! `docs/superpowers/reports/2026-09-17-usability-task-1-report.md`.
//!
//! Unprivileged-safe only: environment-dependent refusals branch on the
//! observer's own doctor verdict instead of assuming this host's capture lane.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_p11scope")
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Outcome {
    let output = Command::new(bin())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run p11scope {args:?}: {error}"));
    Outcome {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr is UTF-8"),
    }
}

/// Whether this host and these privileges allow the capture lane at all —
/// asked with the observer's own doctor rather than a second copy of the rule.
fn capture_available() -> bool {
    p11scope::doctor::verdict(&p11scope::doctor::probe(None, None)) == 0
}

/// A live same-uid target the suite owns; killed and reaped on drop.
struct SleepTarget {
    child: std::process::Child,
}

impl SleepTarget {
    fn spawn() -> Self {
        let child = Command::new("sleep")
            .arg("287.4139")
            .spawn()
            .expect("spawn sleep target");
        Self { child }
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }
}

impl Drop for SleepTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A pid that named a real process and no longer does.
fn exited_pid() -> String {
    let mut child = Command::new("/bin/true").spawn().expect("spawn /bin/true");
    let pid = child.id().to_string();
    child.wait().expect("reap /bin/true");
    pid
}

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn b1_global_help_exits_zero_with_full_usage() {
    let help = run(&["--help"]);
    assert_eq!(help.code, Some(0));
    // F2 fixed (Task 2): exit-0 help goes to stdout, so
    // `p11scope --help | grep …` works.
    assert!(help.stderr.is_empty(), "stderr: {:?}", help.stderr);
    assert!(help.stdout.contains("usage:"), "{}", help.stdout);
    for subcommand in ["p11scope profile", "p11scope trace", "p11scope run"] {
        assert!(help.stdout.contains(subcommand), "{}", help.stdout);
    }
    // Global help text is byte-for-byte stable: exactly USAGE plus println!'s newline.
    assert_eq!(help.stdout, format!("{}\n", p11scope::cli::USAGE));
}

#[test]
fn b2_subcommand_help_is_scoped_to_that_subcommand() {
    let global = run(&["--help"]);
    assert_eq!(global.code, Some(0));
    for subcommand in ["profile", "trace", "run", "inspect", "doctor"] {
        let scoped = run(&[subcommand, "--help"]);
        assert_eq!(scoped.code, Some(0), "{subcommand} --help");
        // F1 fixed (Task 2): scoped help carries only that subcommand's
        // section plus the shared notes footer — never another subcommand.
        assert!(
            scoped.stderr.is_empty(),
            "{subcommand} --help: {:?}",
            scoped.stderr
        );
        let own = format!("p11scope {subcommand}");
        assert!(
            scoped.stdout.contains(&own),
            "{subcommand} --help: {}",
            scoped.stdout
        );
        for other in ["profile", "trace", "run", "inspect", "doctor"] {
            if other != subcommand {
                assert!(
                    !scoped.stdout.contains(&format!("p11scope {other}")),
                    "{subcommand} --help leaks {other}: {}",
                    scoped.stdout
                );
            }
        }
        assert_ne!(scoped.stdout, global.stdout, "{subcommand} --help");
        assert!(
            scoped.stdout.contains("notes: discovery scans"),
            "{subcommand} --help: {}",
            scoped.stdout
        );
    }
}

#[test]
fn b3_missing_or_unknown_subcommand_names_problem_exit_2() {
    let missing = run(&[]);
    assert_eq!(missing.code, Some(2));
    assert!(
        missing.stderr.contains("missing subcommand"),
        "{}",
        missing.stderr
    );
    assert!(missing.stdout.is_empty());

    let unknown = run(&["frobnicate"]);
    assert_eq!(unknown.code, Some(2));
    assert!(
        unknown.stderr.contains("unknown subcommand: frobnicate"),
        "{}",
        unknown.stderr
    );

    // `help <sub>` is not an alias today.
    let help_sub = run(&["help", "profile"]);
    assert_eq!(help_sub.code, Some(2));
    assert!(
        help_sub.stderr.contains("unknown subcommand: help"),
        "{}",
        help_sub.stderr
    );
}

#[test]
fn b4_version_prints_plain_version_exit_0() {
    let version = run(&["--version"]);
    assert_eq!(version.code, Some(0));
    assert_eq!(version.stdout, "p11scope 0.1.0\n");
    assert!(version.stderr.is_empty());
}

#[test]
fn b5_unknown_pid_names_pin_failure_exit_1() {
    let profile = run(&["profile", "--pid", "99999999", "--duration", "1"]);
    assert_eq!(profile.code, Some(1));
    assert!(
        profile.stderr.contains("cannot pin pid 99999999"),
        "{}",
        profile.stderr
    );
}

#[test]
fn b6_doctor_reports_rows_and_verdict() {
    let doctor = run(&["doctor"]);
    assert!(
        doctor.stdout.contains("capability tier:"),
        "{}",
        doctor.stdout
    );
    assert!(doctor.stdout.contains("verdict:"), "{}", doctor.stdout);
    assert!(
        doctor.stdout.contains("BPF map create"),
        "{}",
        doctor.stdout
    );
    for row in ["kernel release", "lockdown", "cgroup version"] {
        assert!(doctor.stdout.contains(row), "{}", doctor.stdout);
    }
    // F3 fixed (Task 3): the verdict line ends with `\n`, so the shell
    // prompt no longer lands on the verdict line.
    assert!(doctor.stdout.ends_with('\n'), "{:?}", doctor.stdout);
    if capture_available() {
        assert!(
            matches!(doctor.code, Some(0) | Some(1)),
            "{:?}",
            doctor.code
        );
    } else {
        assert_eq!(doctor.code, Some(1));
        assert!(
            doctor.stdout.contains("capture unavailable"),
            "{}",
            doctor.stdout
        );
    }
}

#[test]
fn b7_run_refuses_without_capture_lane() {
    if !capture_available() && unsafe { libc::geteuid() } != 0 {
        // HIGH-1 (flipped from the F-01 hazard pin): without privilege the
        // uretprobe self-probe cannot load BPF, which is a missing-privilege
        // fact, not a seccomp hazard. The refusal says so, points at doctor,
        // and never offers the override — which cannot grant privilege, so
        // taking it changes nothing.
        for args in [
            &["run", "--", "/bin/true"][..],
            &[
                "run",
                "--allow-uretprobe-on-confined-target",
                "--",
                "/bin/true",
            ][..],
        ] {
            let refused = run(args);
            assert_eq!(refused.code, Some(1), "{args:?}");
            assert!(
                refused
                    .stderr
                    .contains("cannot load p11scope's BPF programs"),
                "{args:?}: {}",
                refused.stderr
            );
            assert!(
                refused.stderr.contains("p11scope doctor"),
                "{args:?}: {}",
                refused.stderr
            );
            assert!(
                !refused
                    .stderr
                    .contains("--allow-uretprobe-on-confined-target"),
                "{args:?}: {}",
                refused.stderr
            );
            assert!(
                !refused.stderr.contains("starting attach session"),
                "{args:?}: {}",
                refused.stderr
            );
        }
    } else if capture_available() {
        let outcome = run(&["run", "--", "/bin/true"]);
        assert!(outcome.code.is_some());
    }
}

#[test]
fn j1_fresh_eyes_learn_one_subcommand() {
    // F1 fixed (Task 2), from the learner's angle: asking for one
    // subcommand's help no longer shows every other subcommand.
    let profile_help = run(&["profile", "--help"]);
    assert!(
        profile_help.stdout.contains("[--pid"),
        "{}",
        profile_help.stdout
    );
    assert!(
        !profile_help.stdout.contains("p11scope trace"),
        "{}",
        profile_help.stdout
    );
    assert!(
        !profile_help.stdout.contains("p11scope inspect"),
        "{}",
        profile_help.stdout
    );
    let doctor_help = run(&["doctor", "--help"]);
    assert!(
        doctor_help.stdout.contains("p11scope doctor"),
        "{}",
        doctor_help.stdout
    );
    assert!(
        !doctor_help.stdout.contains("p11scope profile"),
        "{}",
        doctor_help.stdout
    );
}

#[test]
fn j2_unprivileged_profile_names_inspect_and_doctor() {
    if !capture_available() {
        let target = SleepTarget::spawn();
        let refused = run(&["profile", "--pid", &target.pid(), "--duration", "1"]);
        assert_eq!(refused.code, Some(1));
        assert!(
            refused.stderr.contains("inspect --pid"),
            "{}",
            refused.stderr
        );
        assert!(
            refused.stderr.contains("doctor --pid"),
            "{}",
            refused.stderr
        );
    }
}

#[test]
fn j2_unprivileged_inspect_succeeds_with_guidance() {
    let target = SleepTarget::spawn();
    let inspect = run(&["inspect", "--pid", &target.pid()]);
    assert_eq!(inspect.code, Some(0));
    assert!(
        inspect.stdout.contains("PKCS#11 modules mapped"),
        "{}",
        inspect.stdout
    );
}

#[test]
fn j3_nonexistent_and_exited_pids_no_longer_share_one_pin_message() {
    let missing = run(&["profile", "--pid", "99999999", "--duration", "1"]);
    assert_eq!(missing.code, Some(1));
    assert!(
        missing.stderr.contains("cannot pin pid 99999999"),
        "{}",
        missing.stderr
    );

    let dead = exited_pid();
    let raced = run(&["profile", "--pid", &dead, "--duration", "1"]);
    assert_eq!(raced.code, Some(1));
    assert!(
        raced.stderr.contains(&format!("cannot pin pid {dead}")),
        "{}",
        raced.stderr
    );

    // F6 fixed (Task 3): a typo'd pid and a raced exit no longer read
    // identically — each names its own cause and next check.
    let normalize = |text: &str, pid: &str| text.replace(pid, "<pid>");
    assert_ne!(
        normalize(&missing.stderr, "99999999"),
        normalize(&raced.stderr, &dead),
    );

    let inspect = run(&["inspect", "--pid", "99999999"]);
    assert_eq!(inspect.code, Some(1));
    assert!(
        inspect.stderr.contains("cannot pin pid 99999999"),
        "{}",
        inspect.stderr
    );
}

#[test]
fn j3_script_target_names_interpreter_fix() {
    let dir = std::env::temp_dir().join(format!("ux-journeys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("hello.sh");
    std::fs::write(&script, "#!/bin/sh\necho hello-from-script\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let refused = run(&["run", "--", &script.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&dir);
    // This refusal is already specific and actionable; the pin keeps it so.
    assert_eq!(refused.code, Some(1));
    assert!(
        refused.stderr.contains("must be an ELF executable"),
        "{}",
        refused.stderr
    );
    assert!(
        refused
            .stderr
            .contains("invoke scripts through an interpreter"),
        "{}",
        refused.stderr
    );
}

#[test]
fn j4_bad_flag_values_name_flag_exit_2() {
    let target = SleepTarget::spawn();
    let pid = target.pid();
    for (flag, value, expected) in [
        (
            "--duration",
            "banana",
            "--duration: invalid value \"banana\"",
        ),
        ("--ring-bytes", "0", "--ring-bytes: invalid value \"0\""),
        (
            "--mode",
            "frobnicate",
            "--mode: invalid value \"frobnicate\"",
        ),
    ] {
        let usage = run(&["profile", "--pid", &pid, flag, value]);
        assert_eq!(usage.code, Some(2), "{flag} {value}");
        assert!(
            usage.stderr.contains(expected),
            "{flag} {value}: {}",
            usage.stderr
        );
        assert!(usage.stderr.contains("usage:"), "{flag} {value}");
    }
    // F5 fixed (Task 3): like --ring-bytes (whose error line prints its
    // 4K..64M range) and --pause, the --mode error line lists its valid
    // values inline.
    let mode = run(&["profile", "--pid", &pid, "--mode", "frobnicate"]);
    let first = mode.stderr.lines().next().unwrap_or("");
    assert_eq!(
        first,
        "--mode: invalid value \"frobnicate\" (expected profile|metrics)"
    );
    assert!(
        mode.stderr.contains("[--mode profile|metrics]"),
        "{}",
        mode.stderr
    );
}

#[test]
fn j4_run_without_separator_names_the_separator() {
    let usage = run(&["run", "/bin/true"]);
    assert_eq!(usage.code, Some(2));
    // F4 fixed (Task 3): the refusal names the missing `--` separator and
    // the concrete next command.
    assert!(
        usage.stderr.contains("unknown argument: /bin/true"),
        "{}",
        usage.stderr
    );
    assert!(usage.stderr.contains("after `--`"), "{}", usage.stderr);
    assert!(
        usage.stderr.contains("p11scope run -- /bin/true"),
        "{}",
        usage.stderr
    );
}

#[test]
fn j5_offline_build_doc_path_pins() {
    let readme = repo_file("README.md");
    assert!(
        readme.contains("third-party/archives/"),
        "offline archive path"
    );
    assert!(readme.contains("--offline"), "offline build flag");
    // F8 fixed (Task 4): the README names the exact archives the trial
    // previously had to derive from third-party/sources.json.
    assert!(readme.contains("aya-0.14.0.crate"), "archive names");
    assert!(readme.contains("aya-obj-0.3.0.crate"), "archive names");
    let guide = repo_file("docs/build-offline.md");
    assert!(
        guide.contains("scripts/build-offline.sh"),
        "export bootstrap"
    );
}

#[test]
fn t3_f3_doctor_verdict_ends_with_newline() {
    // F3 fixed (Task 3): the verdict line ends with `\n`, so the shell
    // prompt no longer lands on the verdict line. Exit codes unchanged.
    let doctor = run(&["doctor"]);
    assert!(doctor.stdout.contains("verdict:"), "{}", doctor.stdout);
    assert!(doctor.stdout.ends_with('\n'), "{:?}", doctor.stdout);
    if capture_available() {
        assert!(
            matches!(doctor.code, Some(0) | Some(1)),
            "{:?}",
            doctor.code
        );
    } else {
        assert_eq!(doctor.code, Some(1));
    }
}

#[test]
fn t3_f4_run_without_separator_names_separator_fix() {
    // F4 fixed (Task 3): a bare word after `run` is the command typed
    // without its `--` separator, so the refusal names the separator and
    // the concrete next command. Exit 2 unchanged.
    let usage = run(&["run", "/bin/true"]);
    assert_eq!(usage.code, Some(2));
    assert!(
        usage.stderr.contains("unknown argument: /bin/true"),
        "{}",
        usage.stderr
    );
    assert!(usage.stderr.contains("after `--`"), "{}", usage.stderr);
    assert!(
        usage.stderr.contains("p11scope run -- /bin/true"),
        "{}",
        usage.stderr
    );
    // A mistyped flag is not a missing separator: no `--` guidance there.
    let flag = run(&["run", "--frobnicate"]);
    assert_eq!(flag.code, Some(2));
    assert!(
        flag.stderr.contains("unknown argument: --frobnicate"),
        "{}",
        flag.stderr
    );
    assert!(!flag.stderr.contains("after `--`"), "{}", flag.stderr);
}

#[test]
fn t3_f5_mode_error_lists_valid_values_inline() {
    // F5 fixed (Task 3): like `--pause`, the `--mode` error line lists its
    // valid values inline instead of only in the appended usage. Exit 2.
    let target = SleepTarget::spawn();
    let mode = run(&["profile", "--pid", &target.pid(), "--mode", "frobnicate"]);
    assert_eq!(mode.code, Some(2));
    let first = mode.stderr.lines().next().unwrap_or("");
    assert_eq!(
        first,
        "--mode: invalid value \"frobnicate\" (expected profile|metrics)"
    );
}

#[test]
fn t3_f6_typo_and_exited_pids_read_differently() {
    // F6 fixed (Task 3): a pid above the kernel maximum never named a
    // process (a typo), while an in-range pid with no live process exited
    // or is an in-range typo — each names its own next check. Exit 1.
    let missing = run(&["profile", "--pid", "99999999", "--duration", "1"]);
    assert_eq!(missing.code, Some(1));
    assert!(
        missing.stderr.contains("cannot pin pid 99999999"),
        "{}",
        missing.stderr
    );
    assert!(missing.stderr.contains("no such pid"), "{}", missing.stderr);
    assert!(missing.stderr.contains("typo"), "{}", missing.stderr);

    let dead = exited_pid();
    let raced = run(&["profile", "--pid", &dead, "--duration", "1"]);
    assert_eq!(raced.code, Some(1));
    assert!(
        raced.stderr.contains(&format!("cannot pin pid {dead}")),
        "{}",
        raced.stderr
    );
    assert!(raced.stderr.contains("exited"), "{}", raced.stderr);
    assert!(
        raced.stderr.contains(&format!("ps -p {dead}")),
        "{}",
        raced.stderr
    );

    // The two failures no longer read identically.
    let normalize = |text: &str, pid: &str| text.replace(pid, "<pid>");
    assert_ne!(
        normalize(&missing.stderr, "99999999"),
        normalize(&raced.stderr, &dead),
    );
}

#[test]
fn t3_f7_attach_refusal_points_at_doctor() {
    // F7 fixed (Task 3): the attach hint keeps its cause list and doc
    // pointer, and now names `p11scope doctor` as the command that knows
    // which cause applies. Exit 1 unchanged.
    if !capture_available() && unsafe { libc::geteuid() } != 0 {
        // HIGH-1: `run` now stops at the self-probe with the missing
        // privilege (pinned in b7), so the attach hint is pinned where it is
        // still reached: an unconfined `--pid` target needs no self-probe.
        let target = SleepTarget::spawn();
        let refused = run(&["profile", "--pid", &target.pid(), "--duration", "1"]);
        assert_eq!(refused.code, Some(1));
        assert!(
            refused.stderr.contains("starting attach session"),
            "{}",
            refused.stderr
        );
        assert!(
            refused.stderr.contains("p11scope doctor"),
            "{}",
            refused.stderr
        );
        assert!(
            refused.stderr.contains("phase5-unsupported.md"),
            "{}",
            refused.stderr
        );
    }
}

#[test]
fn j6_k8s_doc_pins() {
    let readme = repo_file("deploy/k8s/README.md");
    // F9: the manual flow addresses `p11scope/deploy/…`, which resolves only
    // from the checkout's parent — a cwd the doc never states.
    assert!(
        readme.contains("p11scope/deploy/Dockerfile.observer"),
        "manual flow paths"
    );
    // F9/J6 fix: the manual flow now states the required cwd explicitly.
    assert!(
        readme.contains("from the parent of the checkout"),
        "k8s manual flow states required cwd"
    );
    for referenced in [
        "deploy/Dockerfile.observer",
        "deploy/Dockerfile.holder",
        "deploy/k8s/daemonset.yaml",
        "deploy/k8s/namespace.yaml",
        "scripts/k8s-profile-entry.sh",
        "scripts/verify-k8s-attach.sh",
        "scripts/attach-pod.sh",
    ] {
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(referenced);
        assert!(path.is_file(), "missing {}", path.display());
    }
}

#[derive(Clone, Copy, Debug)]
enum ClosedReader {
    Stdout,
    Stderr,
}

/// Runs p11scope with stdout or stderr connected to a pipe whose reader has
/// already gone away (`p11scope doctor | true`, or `2>&1 | tee` after the
/// operator's Ctrl-C killed `tee`), capturing the other stream. The Rust
/// runtime ignores SIGPIPE, so every write there fails with EPIPE.
fn run_with_closed_reader(args: &[&str], closed: ClosedReader) -> Outcome {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::process::Stdio;
    let mut fds = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(reader);
    let mut command = Command::new(bin());
    command.args(args);
    match closed {
        ClosedReader::Stdout => command.stdout(Stdio::from(writer)).stderr(Stdio::piped()),
        ClosedReader::Stderr => command.stderr(Stdio::from(writer)).stdout(Stdio::piped()),
    };
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("run p11scope {args:?}: {error}"));
    Outcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// HIGH-4: a reader that went away is never a panic (exit 101). Help and
/// version still exit 0, doctor still exits with its verdict, and every
/// other command keeps its own exit code.
#[test]
fn high4_a_closed_stdout_reader_never_panics() {
    let doctor_verdict = if capture_available() { 0 } else { 1 };
    for (args, expected) in [
        (&["--help"][..], Some(0)),
        (&["profile", "--help"][..], Some(0)),
        (&["--version"][..], Some(0)),
        (&["doctor"][..], None),
    ] {
        let outcome = run_with_closed_reader(args, ClosedReader::Stdout);
        assert!(
            !outcome.stderr.contains("panicked"),
            "{args:?}: {}",
            outcome.stderr
        );
        assert_ne!(outcome.code, Some(101), "{args:?}: {}", outcome.stderr);
        match expected {
            Some(code) => assert_eq!(outcome.code, Some(code), "{args:?}: {}", outcome.stderr),
            None => assert!(
                outcome.code == Some(doctor_verdict) || outcome.code == Some(0),
                "{args:?}: {:?} {}",
                outcome.code,
                outcome.stderr
            ),
        }
    }
}

#[test]
fn high4_a_closed_stderr_reader_never_panics() {
    let target = SleepTarget::spawn();
    let pid = target.pid();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = dir.path().join("observed.json");
    let out = out.to_str().unwrap();
    for (args, allowed) in [
        (&["frobnicate"][..], &[2][..]),
        (&["run", "--", "/bin/true"][..], &[0, 1][..]),
        (&["inspect", "--pid", "99999999"][..], &[1][..]),
        (
            &["profile", "--pid", &pid, "--duration", "1", "-o", out][..],
            &[0, 1][..],
        ),
        (
            &["trace", "--pid", &pid, "--duration", "1"][..],
            &[0, 1][..],
        ),
    ] {
        let outcome = run_with_closed_reader(args, ClosedReader::Stderr);
        assert!(
            outcome.code.is_some_and(|code| allowed.contains(&code)),
            "{args:?}: exit {:?} (101 is a panic on the closed stderr)",
            outcome.code
        );
    }
    let litter: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".p11scope."))
        .collect();
    assert!(litter.is_empty(), "{litter:?}");
}

/// HIGH-1: without privilege the uretprobe self-probe cannot load BPF at
/// all. That is a missing-privilege fact, not a seccomp hazard: the refusal
/// must say what privilege is missing and must never recommend the safety
/// override (which would only disable the interlock and then hit the same
/// privilege error at attach).
#[test]
fn high1_missing_privilege_is_named_and_never_offers_the_override() {
    if capture_available() || unsafe { libc::geteuid() } == 0 {
        return;
    }
    for args in [
        &["run", "--", "/bin/true"][..],
        &[
            "run",
            "--allow-uretprobe-on-confined-target",
            "--",
            "/bin/true",
        ][..],
        &["profile", "--system", "--duration", "1"][..],
        &["profile", "--cgroup", "/sys/fs/cgroup", "--duration", "1"][..],
    ] {
        let refused = run(args);
        assert_eq!(refused.code, Some(1), "{args:?}: {}", refused.stderr);
        assert!(
            !refused
                .stderr
                .contains("--allow-uretprobe-on-confined-target"),
            "{args:?}: {}",
            refused.stderr
        );
        assert!(
            !refused.stderr.contains("seccomp") && !refused.stderr.contains("trampoline"),
            "{args:?}: a privilege failure reported as a hazard: {}",
            refused.stderr
        );
        assert!(
            refused.stderr.contains("requires root") && refused.stderr.contains("sudo"),
            "{args:?}: {}",
            refused.stderr
        );
    }
}

/// HIGH-2: a target whose mappings cannot be read (pid 1 belongs to root)
/// is the documented hard error — exit 1, empty stdout, one stderr line
/// with the cause and the fix — never a clean "0 PKCS#11 modules mapped".
#[test]
fn high2_inspect_of_an_unreadable_target_exits_1_with_the_fix() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for args in [
        &["inspect", "--pid", "1"][..],
        &["inspect", "--pid", "1", "--json"][..],
    ] {
        let inspect = run(args);
        assert_eq!(inspect.code, Some(1), "{args:?}: {}", inspect.stdout);
        assert!(inspect.stdout.is_empty(), "{args:?}: {}", inspect.stdout);
        assert!(
            inspect.stderr.contains("sudo p11scope inspect --pid 1"),
            "{args:?}: {}",
            inspect.stderr
        );
    }
}
