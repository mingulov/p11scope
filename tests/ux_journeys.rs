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
    if !capture_available() {
        let refused = run(&["run", "--", "/bin/true"]);
        assert_eq!(refused.code, Some(1));
        assert!(
            refused.stderr.contains("starting attach session"),
            "{}",
            refused.stderr
        );
        // F7: the attach hint lists five possible causes on one line but
        // never points at `p11scope doctor`, which knows the actual cause.
        assert!(
            !refused.stderr.contains("p11scope doctor"),
            "{}",
            refused.stderr
        );
    } else {
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
fn j3_nonexistent_and_exited_pids_share_one_pin_message() {
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

    // F6: a typo'd pid and a raced exit read identically, so the user
    // cannot tell which happened.
    let normalize = |text: &str, pid: &str| text.replace(pid, "<pid>");
    assert_eq!(
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
    // F5: unlike --ring-bytes (whose error line prints its 4K..64M range),
    // the --mode error line never lists its valid values; they appear only
    // in the appended usage dump.
    let mode = run(&["profile", "--pid", &pid, "--mode", "frobnicate"]);
    let first = mode.stderr.lines().next().unwrap_or("");
    assert_eq!(first, "--mode: invalid value \"frobnicate\"");
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
    // F8: the README tells the user to "place the exact archives" but never
    // names them; the names below are the ones the trial derived from
    // third-party/sources.json.
    assert!(!readme.contains("aya-0.14.0.crate"), "archive names");
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
fn j6_k8s_doc_pins() {
    let readme = repo_file("deploy/k8s/README.md");
    // F9: the manual flow addresses `p11scope/deploy/…`, which resolves only
    // from the checkout's parent — a cwd the doc never states.
    assert!(
        readme.contains("p11scope/deploy/Dockerfile.observer"),
        "manual flow paths"
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
