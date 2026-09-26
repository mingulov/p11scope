//! SPDX-License-Identifier: GPL-3.0-or-later
//! The outer owned controller supplies frozen inputs and all shared leases.
//! This body only observes; it neither starts nor stops a workload process.
use super::*;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: String,
    nonce: String,
    target: Target,
    owned_pid: u32,
    argv: Vec<String>,
    facts: PathBuf,
    loop_marker: PathBuf,
    attached_marker: Option<PathBuf>,
    fact_limit: usize,
}

fn private_file(path: &Path) -> std::io::Result<File> {
    File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn write_notice(path: &Path, nonce: &str, notice: &Notice) -> anyhow::Result<()> {
    anyhow::ensure!(notice.at_ns.is_some(), "notification clock unavailable");
    let mut file = tempfile::NamedTempFile::new_in(path.parent().expect("absolute marker"))?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({"nonce": nonce, "notice": notice}),
    )?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.persist_noclobber(path)?;
    Ok(())
}

fn validate(config: &Config) -> anyhow::Result<crate::cli::CaptureArgs> {
    anyhow::ensure!(
        config.schema == "p11scope/first-use-observer/v1",
        "unknown probe schema"
    );
    for hex in [&config.nonce, &config.target.sha256] {
        anyhow::ensure!(
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid digest or nonce"
        );
    }
    anyhow::ensure!(
        config.owned_pid > 0 && config.target.inode > 0,
        "missing owned identity"
    );
    anyhow::ensure!(
        (1..=8192).contains(&config.fact_limit),
        "invalid fact limit"
    );
    let crate::cli::Command::Profile(args) = crate::cli::parse(config.argv.clone().into_iter())
        .map_err(|error| anyhow::anyhow!("probe CLI rejected: {error:?}"))?
    else {
        anyhow::bail!("probe requires the public profile command");
    };
    anyhow::ensure!(
        args.scope == crate::cli::ScopeArg::System && !args.metrics,
        "probe requires profile --system with CALL records"
    );
    anyhow::ensure!(
        args.modules.is_empty() && args.manifests.is_empty() && !args.unsafe_requested,
        "no predeclared provider hints, manifests or unsafe metadata"
    );
    anyhow::ensure!(
        args.hooks == crate::discovery::hooks::HookRegistry::default(),
        "use the public default hook registry"
    );
    anyhow::ensure!(
        args.duration
            .is_some_and(|d| !d.is_zero() && d <= Duration::from_secs(30)),
        "bounded duration required"
    );
    let report = args
        .out
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("public JSON report required"))?;
    let mut paths = std::collections::BTreeSet::new();
    for path in [&config.facts, &config.loop_marker, report]
        .into_iter()
        .chain(&config.attached_marker)
    {
        anyhow::ensure!(path.is_absolute(), "absolute output paths required");
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("output parent required"))?
            .canonicalize()?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("output filename required"))?;
        anyhow::ensure!(
            paths.insert(parent.join(name)),
            "distinct output paths required"
        );
        anyhow::ensure!(!path.try_exists()?, "probe output already exists");
    }
    Ok(args)
}

#[test]
#[ignore = "owned root first-use observer; frozen config, supervisor and exclusive BPF lane required"]
fn system_capture_observer_facts() {
    // SAFETY: geteuid has no arguments or memory effects.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "explicit root prerequisite; no skip"
    );
    let path = std::env::var_os("P11SCOPE_FIRST_USE_PROBE_CONFIG").expect("frozen config path");
    let mut bytes = Vec::new();
    File::open(path)
        .expect("open frozen config")
        .take(8193)
        .read_to_end(&mut bytes)
        .expect("read bounded config");
    assert!(bytes.len() <= 8192, "bounded config");
    let config: Config = serde_json::from_slice(&bytes).expect("strict config");
    let args = validate(&config).expect("valid private probe boundary");
    let mut output = private_file(&config.facts).expect("exclusive private facts file");
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Notice>(2);
    let writer = std::thread::spawn(move || -> anyhow::Result<()> {
        let mut error = None;
        for notice in receiver {
            let path = match notice.kind {
                NoticeKind::LoopStarted => Some(&config.loop_marker),
                NoticeKind::TargetAttached => config.attached_marker.as_ref(),
            };
            if let Some(path) = path
                && let Err(failure) = write_notice(path, &config.nonce, &notice)
            {
                error.get_or_insert(failure);
            }
        }
        error.map_or(Ok(()), Err)
    });
    let probe = Probe::install(
        Journal::new(config.target, config.owned_pid, config.fact_limit),
        Some(sender),
    );
    // This is the same production entry point used by main.rs. No alternate
    // discovery loop or manually assembled attach plan stands in for it.
    let capture = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::capture(&args)));
    let journal = probe.finish();
    let notice_result = writer.join().expect("marker writer did not panic");
    let capture_ok = matches!(&capture, Ok(Ok(())));
    let intact = journal.intact();
    serde_json::to_writer(
        &mut output,
        &serde_json::json!({
            "schema": "p11scope/first-use-observer-facts/v1",
            "authority": "instrumented_public_profile_capture",
            "capture_returned_ok": capture_ok,
            "marker_delivery_ok": notice_result.is_ok(),
            "journal_intact": intact,
            "journal": journal,
            "first_use_verdict": "external_owned_oracle_required"
        }),
    )
    .expect("preserve journal");
    output.write_all(b"\n").expect("facts newline");
    output.flush().expect("flush facts");
    notice_result.expect("marker delivery");
    assert!(
        intact,
        "journal loss or unsupported transition invalidates evidence"
    );
    capture
        .expect("capture did not panic")
        .expect("public capture completed");
}

#[test]
fn unavailable_notice_time_cannot_release_a_workload_gate() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gate");
    let notice = Notice {
        kind: NoticeKind::TargetAttached,
        domain: 9,
        at_ns: None,
    };
    assert!(write_notice(&path, "nonce", &notice).is_err());
    assert!(!path.exists());
    let notice = Notice {
        at_ns: Some(70),
        ..notice
    };
    write_notice(&path, "nonce", &notice).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(write_notice(&path, "replacement", &notice).is_err());
    assert_eq!(
        std::fs::read(path).unwrap(),
        original,
        "exclusive marker custody"
    );
}

#[test]
fn observer_config_keeps_the_real_system_path_and_separate_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let report = directory.path().join("report.json");
    let mut config = Config {
        schema: "p11scope/first-use-observer/v1".into(),
        nonce: "ab".repeat(32),
        target: Target {
            device: 37,
            inode: 101,
            sha256: "cd".repeat(32),
            file_offset: 4586,
        },
        owned_pid: 42,
        argv: vec![
            "profile".into(),
            "--system".into(),
            "--duration".into(),
            "1s".into(),
            "-o".into(),
            report.to_str().unwrap().into(),
        ],
        facts: directory.path().join("facts.json"),
        loop_marker: directory.path().join("loop.json"),
        attached_marker: None,
        fact_limit: 64,
    };
    assert!(validate(&config).is_ok());
    let original_args = config.argv.clone();
    for extra in [
        vec!["--mode", "metrics"],
        vec!["--module", "/pretold-provider"],
        vec!["--duration", "60s"],
    ] {
        config.argv = original_args
            .iter()
            .cloned()
            .chain(extra.into_iter().map(str::to_owned))
            .collect();
        assert!(validate(&config).is_err(), "explicit fixture boundary");
    }
    config.argv = original_args;
    config.attached_marker = Some(report.clone());
    assert!(
        validate(&config).is_err(),
        "marker cannot overwrite public report"
    );
    config.attached_marker = None;
    std::fs::write(&report, "previous evidence").unwrap();
    assert!(validate(&config).is_err());
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "previous evidence"
    );
}
