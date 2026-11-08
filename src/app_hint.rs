//! SPDX-License-Identifier: GPL-3.0-or-later
//! Display-only app hints for interpreter-run callers.
//!
//! The caller label stays the exe basename; beside it the observer may show
//! a short hint (`python3 [pkcs11-check]`) from narrowly-read facts: one
//! grammar-proven argv token, comm, or the cgroup leaf. Hints are labels
//! only — never identity, admission, or join keys. See the allowlist-v3
//! "App identity hints" rows and the Phase A design spec.

/// Where an app hint came from. Rendered in `-v`/JSON, never in concise text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppHintSource {
    Argv,
    Comm,
    Unit,
    Snap,
}

impl AppHintSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Argv => "argv",
            Self::Comm => "comm",
            Self::Unit => "unit",
            Self::Snap => "snap",
        }
    }
}

/// One display hint: a short value plus its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppHint {
    pub value: String,
    pub source: AppHintSource,
}

/// Bounded `/proc/<pid>/cmdline` prefix: script tokens sit at argv[0..2].
pub(crate) const CMDLINE_PREFIX_BYTES: usize = 4096;
/// Hint values are basenames or identifiers, never longer than `NAME_MAX`.
pub(crate) const HINT_VALUE_MAX_BYTES: usize = 255;

/// Pure selection over already-read facts. RED scaffold: always `Some`.
pub(crate) fn app_hint_for(
    _exe_path: Option<&str>,
    _comm: Option<&str>,
    _cmdline: Option<&[u8]>,
    _cgroup: Option<&str>,
) -> Option<AppHint> {
    Some(AppHint {
        value: "stub".into(),
        source: AppHintSource::Argv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(exe: &str, args: &[&str]) -> AppHint {
        let mut cmd: Vec<u8> = Vec::new();
        cmd.extend_from_slice(exe.as_bytes());
        cmd.push(0);
        for arg in args {
            cmd.extend_from_slice(arg.as_bytes());
            cmd.push(0);
        }
        app_hint_for(Some(exe), None, Some(&cmd), None).expect("argv hint")
    }

    fn no_hint(exe: Option<&str>, comm: Option<&str>, cmd: Option<&[u8]>, cg: Option<&str>) {
        assert_eq!(app_hint_for(exe, comm, cmd, cg), None);
    }

    #[test]
    fn source_labels_are_stable() {
        assert_eq!(AppHintSource::Argv.label(), "argv");
        assert_eq!(AppHintSource::Comm.label(), "comm");
        assert_eq!(AppHintSource::Unit.label(), "unit");
        assert_eq!(AppHintSource::Snap.label(), "snap");
        assert_eq!(CMDLINE_PREFIX_BYTES, 4096);
        assert_eq!(HINT_VALUE_MAX_BYTES, 255);
    }

    #[test]
    fn python_explicit_script_basename_never_later_args() {
        let hint = argv("/usr/bin/python3", &["app/run.py", "--pin", "1234"]);
        assert_eq!(hint.value, "run.py");
        assert_eq!(hint.source, AppHintSource::Argv);
    }

    #[test]
    fn python_env_shebang_takes_argv1() {
        let hint = argv("/usr/bin/python3", &["./tool"]);
        assert_eq!(hint.value, "tool");
    }

    #[test]
    fn python_m_module() {
        let hint = argv("/usr/bin/python3", &["-m", "mypkg.mod"]);
        assert_eq!(hint.value, "mypkg.mod");
        assert_eq!(hint.source, AppHintSource::Argv);
    }

    #[test]
    fn python_m_attached_module() {
        let hint = argv("/usr/bin/python3", &["-mrestmod"]);
        assert_eq!(hint.value, "restmod");
    }

    #[test]
    fn python_w_and_x_values_are_skipped() {
        assert_eq!(
            argv("/usr/bin/python3", &["-W", "ignore", "app.py"]).value,
            "app.py"
        );
        assert_eq!(
            argv("/usr/bin/python3", &["-Wignore", "app.py"]).value,
            "app.py"
        );
        assert_eq!(
            argv("/usr/bin/python3", &["-X", "utf8", "app.py"]).value,
            "app.py"
        );
    }

    #[test]
    fn python_bundled_flags_then_script() {
        assert_eq!(argv("/usr/bin/python3", &["-Bu", "app.py"]).value, "app.py");
    }

    #[test]
    fn python_dashdash_ends_options() {
        assert_eq!(argv("/usr/bin/python3", &["--", "app.py", "-x"]).value, "app.py");
    }

    #[test]
    fn python_hash_pycs_flag_consumes_its_value() {
        assert_eq!(
            argv(
                "/usr/bin/python3",
                &["--check-hash-based-pycs", "always", "app.py"]
            )
            .value,
            "app.py"
        );
    }

    #[test]
    fn python_c_text_is_never_captured() {
        let mut cmd = b"python3\x00-c\x00print('--pin', 1)\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
        cmd = b"python3\x00-Bc\x00print(1)\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
    }

    #[test]
    fn python_m_rejects_digits_and_flags() {
        let mut cmd = b"python3\x00-m\x001234\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
        cmd = b"python3\x00-m\x00--pin\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
    }

    #[test]
    fn python_unknown_long_flag_bails() {
        let cmd = b"python3\x00--unknown\x00app.py\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
    }

    #[test]
    fn python_stdin_and_bare_invocation_yield_no_hint() {
        let mut cmd = b"python3\x00-\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
        cmd = b"python3\x00".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cmd), None);
    }

    #[test]
    fn python_versioned_binary_is_gated_but_threaded_is_not() {
        assert_eq!(
            argv("/usr/bin/python3.14", &["app.py"]).value,
            "app.py"
        );
        let cmd = b"python3.13t\x00app.py\x00".to_vec();
        no_hint(Some("/usr/bin/python3.13t"), None, Some(&cmd), None);
    }

    #[test]
    fn non_interpreter_gets_no_argv_read() {
        let cmd = b"pkcs11-tool\x00--pin\x001234\x00".to_vec();
        no_hint(Some("/usr/bin/pkcs11-tool"), None, Some(&cmd), None);
    }

    #[test]
    fn script_path_keeps_basename_only() {
        assert_eq!(
            argv("/usr/bin/python3", &["/opt/secret-proj/main.py"]).value,
            "main.py"
        );
    }

    #[test]
    fn non_utf8_script_is_lossy_but_bounded() {
        let cmd = b"python3\x00app\xff.py\x00".to_vec();
        let hint = app_hint_for(Some("/usr/bin/python3"), None, Some(&cmd), None)
            .expect("lossy hint");
        assert_eq!(hint.value, "app\u{fffd}.py");
        let mut overlong = b"python3\x00".to_vec();
        overlong.extend(std::iter::repeat_n(b'a', HINT_VALUE_MAX_BYTES + 1));
        overlong.push(0);
        no_hint(Some("/usr/bin/python3"), None, Some(&overlong), None);
    }

    #[test]
    fn truncated_token_is_unusable_but_complete_prefix_is_fine() {
        let cut = b"python3\x00ap".to_vec();
        no_hint(Some("/usr/bin/python3"), None, Some(&cut), None);
        let partial = b"python3\x00app.py\x00--pi".to_vec();
        let hint = app_hint_for(Some("/usr/bin/python3"), None, Some(&partial), None)
            .expect("complete script token before the cut");
        assert_eq!(hint.value, "app.py");
    }

    #[test]
    fn sh_direct_script_but_never_c_text_or_flags() {
        assert_eq!(argv("/bin/sh", &["deploy.sh", "--pin", "1"]).value, "deploy.sh");
        assert_eq!(argv("/usr/bin/dash", &["x.sh"]).value, "x.sh");
        assert_eq!(argv("/usr/bin/bash", &["y.sh"]).value, "y.sh");
        let mut cmd = b"sh\x00-c\x00echo hi\x00".to_vec();
        no_hint(Some("/bin/sh"), None, Some(&cmd), None);
        cmd = b"sh\x00-x\x00deploy.sh\x00".to_vec();
        no_hint(Some("/bin/sh"), None, Some(&cmd), None);
    }

    #[test]
    fn java_jar_and_main_class() {
        assert_eq!(
            argv("/usr/bin/java", &["-jar", "app.jar", "--pin", "1"]).value,
            "app.jar"
        );
        assert_eq!(
            argv("/usr/bin/java", &["com.example.App"]).value,
            "com.example.App"
        );
        assert_eq!(
            argv("/usr/bin/java", &["-cp", "lib/*", "com.App"]).value,
            "com.App"
        );
        assert_eq!(
            argv("/usr/bin/java", &["-Dkey=val", "-Xmx1g", "com.App"]).value,
            "com.App"
        );
        assert_eq!(
            argv("/usr/bin/java", &["--affinity=1", "com.App"]).value,
            "com.App"
        );
    }

    #[test]
    fn java_rejects_non_jar_and_unknown_flags() {
        let mut cmd = b"java\x00-jar\x00app.zip\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
        cmd = b"java\x00-Zfoo\x00com.App\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
        cmd = b"java\x00--future\x00com.App\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
        cmd = b"java\x0012bad\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
    }

    #[test]
    fn node_script_beats_flags_and_preloads() {
        assert_eq!(argv("/usr/bin/node", &["app.js"]).value, "app.js");
        assert_eq!(
            argv("/usr/bin/node", &["--inspect", "app.js"]).value,
            "app.js"
        );
        assert_eq!(
            argv("/usr/bin/node", &["-r", "preload.js", "app.js"]).value,
            "app.js"
        );
        assert_eq!(
            argv("/usr/bin/node", &["--cpu-prof-name=x", "app.js"]).value,
            "app.js"
        );
        assert_eq!(
            argv("/usr/bin/node", &["./bin/cli"]).value,
            "cli"
        );
    }

    #[test]
    fn node_never_eval_and_bails_on_unknown_or_bare_names() {
        let mut cmd = b"node\x00-e\x00code()\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00--future\x00app.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00cli\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00inspect\x00app.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
    }

    #[test]
    fn pin_values_are_never_captured_in_any_position() {
        for (exe, args, script) in [
            ("/usr/bin/python3", vec!["job.py", "--pin", "1234"], "job.py"),
            ("/usr/bin/python3", vec!["-m", "job", "--pin", "1234"], "job"),
            ("/bin/sh", vec!["job.sh", "--pin", "1234"], "job.sh"),
            (
                "/usr/bin/java",
                vec!["-jar", "job.jar", "--pin", "1234"],
                "job.jar",
            ),
            ("/usr/bin/node", vec!["job.js", "--pin", "1234"], "job.js"),
        ] {
            let hint = argv(exe, &args);
            assert_eq!(hint.value, script, "script token for {exe}");
            assert!(
                !hint.value.contains("1234"),
                "pin leaked for {exe}: {hint:?}"
            );
        }
    }

    #[test]
    fn comm_names_direct_shebang_apps() {
        let hint = app_hint_for(Some("/usr/bin/python3"), Some("pkcs11-check"), None, None)
            .expect("comm hint");
        assert_eq!(hint.value, "pkcs11-check");
        assert_eq!(hint.source, AppHintSource::Comm);
    }

    #[test]
    fn argv_beats_comm_and_equal_comm_falls_through() {
        let cmd = b"python3\x00other.py\x00".to_vec();
        let hint = app_hint_for(
            Some("/usr/bin/python3"),
            Some("pkcs11-check"),
            Some(&cmd),
            None,
        )
        .expect("argv wins");
        assert_eq!((hint.value.as_str(), hint.source), ("other.py", AppHintSource::Argv));
        no_hint(Some("/usr/bin/python3"), Some("python3"), None, None);
    }

    #[test]
    fn comm_is_refused_for_node_java_and_compiled_apps() {
        no_hint(Some("/usr/bin/node"), Some("MainThread"), None, None);
        no_hint(Some("/usr/bin/java"), Some("java-renamed"), None, None);
        no_hint(
            Some("/snap/firefox/9057/usr/lib/firefox/firefox"),
            Some("Privileged Cont"),
            None,
            None,
        );
    }

    #[test]
    fn cgroup_leaf_names_snaps_units_and_scopes() {
        let snap = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.firefox.firefox-uuid.scope\n";
        let hint = app_hint_for(
            Some("/snap/firefox/9057/usr/lib/firefox/firefox"),
            None,
            None,
            Some(snap),
        )
        .expect("snap hint");
        assert_eq!(hint.value, "snap firefox");
        assert_eq!(hint.source, AppHintSource::Snap);
        let svc = "0::/system.slice/backup-agent.service\n";
        let hint = app_hint_for(Some("/usr/bin/python3"), None, None, Some(svc))
            .expect("unit hint");
        assert_eq!(hint.value, "backup-agent");
        assert_eq!(hint.source, AppHintSource::Unit);
        let scope = "0::/user.slice/app-org.gnome.Foo-1.scope\n";
        let hint = app_hint_for(Some("/usr/bin/python3"), None, None, Some(scope))
            .expect("scope hint");
        assert_eq!(hint.value, "app-org.gnome.Foo-1");
        assert_eq!(hint.source, AppHintSource::Unit);
    }

    #[test]
    fn cgroup_leaf_skips_generic_and_container_shapes() {
        for leaf in [
            "0::/user.slice/user-1000.slice/session-c2.scope\n",
            "0::/user.slice/user-1000.slice/user@1000.service\n",
            "0::/system.slice/system-getty.slice\n",
            "0::/init.scope\n",
            "11:memory:/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
            "0::/kubepods.slice/kubepods-pod3f4 underscored.scope\n",
            "0::/system.slice/crio-0123456789abcdef.scope\n",
            "0::/user.slice/user-1000.slice/user@1000.service/user.slice/podman-pause-67e26dd7.scope\n",
            "0::/system.slice/systemd-udevd.service/udev\n",
        ] {
            no_hint(Some("/usr/bin/python3"), None, None, Some(leaf));
        }
        no_hint(Some("/usr/bin/python3"), None, None, Some(""));
    }

    #[test]
    fn hint_equal_to_basename_carries_no_information() {
        let svc = "0::/system.slice/colord.service\n";
        no_hint(Some("/usr/sbin/colord"), None, None, Some(svc));
    }

    #[test]
    fn argv_beats_cgroup_for_interpreters() {
        let cmd = b"python3\x00job.py\x00".to_vec();
        let snap = "0::/app.slice/snap.python.python-uuid.scope\n";
        let hint = app_hint_for(Some("/usr/bin/python3"), None, Some(&cmd), Some(snap))
            .expect("argv wins over cgroup");
        assert_eq!(hint.value, "job.py");
        assert_eq!(hint.source, AppHintSource::Argv);
    }
}
