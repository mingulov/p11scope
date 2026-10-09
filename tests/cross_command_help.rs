//! SPDX-License-Identifier: GPL-3.0-or-later
//! Public help and refusal contracts: no provider or target is opened.

use p11scope::cli::{self, Command as ParsedCommand};
use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStringExt as _;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn invoke(words: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(words)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn refusal(output: Output, cause: &str, hint: &str) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(cause), "{stderr}");
    assert_eq!(stderr.lines().count(), 2, "cause plus one hint: {stderr}");
    assert_eq!(stderr.lines().last(), Some(hint), "{stderr}");
    assert!(!stderr.contains("usage:"), "{stderr}");
    assert!(!stderr.as_bytes().contains(&0x1b), "{stderr}");
}

#[test]
fn help_routes_and_channels() {
    for topic in [
        "profile",
        "trace",
        "run",
        "inspect",
        "doctor",
        "inventory",
        "inventory diff",
    ] {
        for flag in ["--help", "-h"] {
            let mut words: Vec<_> = topic.split_whitespace().collect();
            words.push(flag);
            let output = invoke(&words);
            assert_eq!(output.status.code(), Some(0), "{topic}: {output:?}");
            assert!(output.stderr.is_empty(), "{topic}: {output:?}");
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains(&format!("p11scope {topic}")), "{text}");
            assert!(!text.as_bytes().contains(&0x1b), "{text}");
            for other in ["profile", "trace", "run", "inspect", "doctor"] {
                if topic != other {
                    assert!(
                        !text
                            .lines()
                            .any(|line| line.starts_with(&format!("  p11scope {other} "))),
                        "unrelated usage: {text}"
                    );
                }
            }
        }
    }
    let output = invoke(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Choose a task"), "{text}");
    assert!(text.contains("p11scope inventory diff"), "{text}");
    let inventory = String::from_utf8(invoke(&["inventory", "--help"]).stdout).unwrap();
    for line in inventory
        .lines()
        .filter(|line| line.starts_with("  p11scope inventory --"))
    {
        if line.contains("[--module") {
            assert!(line.contains("[--manifest <m.json>]..."), "{line}");
        }
    }
    assert!(inventory.contains("requires auto or native"), "{inventory}");
}

#[test]
fn usage_error_is_scoped() {
    for (words, cause, topic) in [
        (vec!["profile"], "is required", "profile"),
        (
            vec!["trace", "--pid", "1", "--duration", "broken"],
            "--duration: invalid value",
            "trace",
        ),
        (
            vec!["inspect", "--pid", "1", "--pid", "2"],
            "--pid given twice",
            "inspect",
        ),
        (
            vec!["doctor", "--pid", "0"],
            "--pid must be greater than zero",
            "doctor",
        ),
        (
            vec!["inventory", "--pid", "1", "--system"],
            "mutually exclusive",
            "inventory",
        ),
        (
            vec![
                "inventory",
                "--pid",
                "1",
                "--capture",
                "scan",
                "--manifest",
                "m.json",
            ],
            "--manifest requires --capture auto or native",
            "inventory",
        ),
        (
            vec![
                "inventory",
                "diff",
                "before.json",
                "after.json",
                "--pid",
                "1",
            ],
            "unknown inventory diff option",
            "inventory diff",
        ),
        (vec!["run", "echo"], "run takes its command after", "run"),
        (vec!["run", "--"], "requires a command", "run"),
    ] {
        refusal(
            invoke(&words),
            cause,
            &format!("Try 'p11scope {topic} --help'."),
        );
    }
    refusal(invoke(&[]), "missing subcommand", "Try 'p11scope --help'.");
    refusal(
        invoke(&["unknown"]),
        "unknown subcommand",
        "Try 'p11scope --help'.",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["trace", "--pid"])
        .arg(OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    refusal(output, "not valid UTF-8", "Try 'p11scope trace --help'.");
}

#[test]
fn removed_discover_points_to_helper() {
    refusal(
        invoke(&["discover"]),
        "p11scope-discover --module",
        "Try 'p11scope --help'.",
    );
    let text = String::from_utf8(invoke(&["discover"]).stderr).unwrap();
    assert!(text.contains("executes provider code"), "{text}");
}

#[test]
fn metrics_is_a_profile_mode() {
    let text = String::from_utf8(invoke(&["profile", "--help"]).stdout).unwrap();
    let example = "p11scope profile --system --mode metrics --duration 30s -o metrics.json";
    assert!(text.contains(example), "{text}");
    assert!(
        text.contains("Aggregate across the selected scope; counts are not per application"),
        "{text}"
    );
    assert!(
        !text.contains("per-process and per-module attribution is still recorded"),
        "{text}"
    );
    let ParsedCommand::Profile(args) = cli::parse(example.split_whitespace().skip(1)).unwrap()
    else {
        panic!("profile mode expected")
    };
    assert!(args.metrics);
    refusal(
        invoke(&["metrics"]),
        "unknown subcommand: metrics",
        "Try 'p11scope --help'.",
    );
}

#[test]
fn advertised_examples_parse_and_run_command_boundary_is_verbatim() {
    for (topic, example) in [
        ("doctor", "p11scope doctor --pid 4242"),
        ("inspect", "p11scope inspect --pid 4242 --json"),
        (
            "profile",
            "p11scope profile --pid 4242 --duration 30s -o profile.json",
        ),
        (
            "trace",
            "p11scope trace --pid 4242 --duration 10s --max-events 1000",
        ),
        (
            "inventory",
            "p11scope inventory --pid 4242 --capture scan --json -o inventory.json",
        ),
        ("run", "p11scope run --trace -- /absolute/path/to/program"),
    ] {
        let text = String::from_utf8(invoke(&[topic, "--help"]).stdout).unwrap();
        assert!(text.contains(example), "{topic}: {text}");
        assert!(text.contains("example"), "values must be examples: {text}");
        cli::parse(example.split_whitespace().skip(1)).unwrap();
    }
    let child_word = OsString::from_vec(b"child-\xff".to_vec());
    let words = vec![
        OsString::from("run"),
        OsString::from("--"),
        child_word.clone(),
        OsString::from("--help"),
    ];
    let ParsedCommand::Run(args) = cli::parse(words).unwrap() else {
        panic!("run expected")
    };
    assert_eq!(args.command, vec![child_word, OsString::from("--help")]);
}

#[test]
fn usage_causes_escape_terminal_controls() {
    refusal(
        invoke(&["inspect", "bad\n\x1b[31m\r\t"]),
        "unknown argument: bad",
        "Try 'p11scope inspect --help'.",
    );
}

#[test]
fn unread_usage_stderr_does_not_block_exit() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["inspect", &"bad".repeat(20_000)])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut bytes = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(2),
        "stalled stderr blocked the usage refusal"
    );
}

// The pipe belongs only to this test and its child. Fill it, then restore its
// original blocking flags: production must avoid waiting without changing them.
fn diagnostic_pipe(full: bool) -> (std::fs::File, std::fs::File) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let mut writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    if full {
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        loop {
            match writer.write(&[b'x'; 4096]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("filling owned diagnostic pipe: {error}"),
            }
        }
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags) },
            0
        );
    }
    (reader, writer)
}

#[test]
fn full_or_closed_stderr_preserves_usage_and_hard_error_exit_codes() {
    let mut observed = Vec::new();
    for full in [false, true] {
        for hard_error in [false, true] {
            let (reader, writer) = diagnostic_pipe(full);
            let retained_writer = writer.try_clone().unwrap();
            let flags = unsafe { libc::fcntl(retained_writer.as_raw_fd(), libc::F_GETFL) };
            assert!(flags >= 0);
            let reader = full.then_some(reader); // Otherwise close the reader before spawn.
            let mut command = Command::new(env!("CARGO_BIN_EXE_p11scope"));
            let expected = if hard_error {
                // Exit-0 metadata command whose output fails: no provider or target I/O.
                command.arg("--version").stdout(
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open("/dev/full")
                        .unwrap(),
                );
                1
            } else {
                command.arg("inspect").stdout(Stdio::null());
                2
            };
            let mut child = command.stdin(Stdio::null()).stderr(writer).spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            drop(reader);
            assert_eq!(
                unsafe { libc::fcntl(retained_writer.as_raw_fd(), libc::F_GETFL) },
                flags,
                "diagnostic changed inherited fd flags"
            );
            observed.push((
                full,
                hard_error,
                status.and_then(|status| status.code()),
                expected,
            ));
        }
    }
    assert!(
        observed
            .iter()
            .all(|(_, _, code, expected)| *code == Some(*expected)),
        "full/closed stderr exits: {observed:?}"
    );
}
