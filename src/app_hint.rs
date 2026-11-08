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

/// Which interpreter grammar gates the argv/comm reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interpreter {
    Python,
    Shell,
    Java,
    Node,
}

/// Last nonempty `/`-separated component, if any.
fn basename_of(path: &str) -> Option<&str> {
    path.rsplit('/').find(|part| !part.is_empty())
}

/// Exact interpreter table (Section 4 of the design): extension needs a
/// reviewed allowlist change. `python3.<N>` is digits-only; anything
/// else (`python3.13t`, `python2`, wrappers) is not an interpreter.
fn classify_interpreter(basename: &str) -> Option<Interpreter> {
    match basename {
        "python" | "python3" => Some(Interpreter::Python),
        "sh" | "dash" | "bash" => Some(Interpreter::Shell),
        "java" => Some(Interpreter::Java),
        "node" | "nodejs" => Some(Interpreter::Node),
        _ => {
            if let Some(rest) = basename.strip_prefix("python3.")
                && !rest.is_empty()
                && rest.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Some(Interpreter::Python);
            }
            None
        }
    }
}

/// Split a bounded cmdline prefix into complete NUL-terminated tokens.
/// The final piece is always dropped: either the empty tail after the
/// last NUL, or an unterminated truncation cut (unusable).
fn complete_tokens(cmdline: &[u8]) -> Vec<&[u8]> {
    let mut pieces: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
    pieces.pop();
    pieces
}

/// Basename of a path token: lossy, last component, 1..=255 bytes, never
/// starting with `-` (a value in disguise).
fn capture_basename(token: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(token);
    let base = basename_of(&text)?;
    if base.is_empty() || base.len() > HINT_VALUE_MAX_BYTES || base.starts_with('-') {
        return None;
    }
    Some(base.to_string())
}

/// Dotted module/class identifier: `^[A-Za-z_][A-Za-z0-9_.]*$`, ≤255 bytes.
/// Digits-first tokens are values, not identifiers.
fn capture_dotted_ident(token: &[u8]) -> Option<String> {
    if token.is_empty() || token.len() > HINT_VALUE_MAX_BYTES {
        return None;
    }
    let mut bytes = token.iter();
    let first = bytes.next()?;
    if !first.is_ascii_alphabetic() && *first != b'_' {
        return None;
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'.') {
        return None;
    }
    Some(String::from_utf8_lossy(token).into_owned())
}

/// CPython option walker over complete tokens (argv[0] already skipped).
/// `-c` aborts (program text is never captured); `-m` captures the
/// module; `-W`/`-X` consume their value; unknown shapes bail.
fn python_token(tokens: &[&[u8]]) -> Option<String> {
    const NO_ARG: &[u8] = b"Bb?dEhiIOPqsSuvVx";
    let mut index = 0;
    loop {
        let token = *tokens.get(index)?;
        if token == b"--" {
            let script = tokens.get(index + 1)?;
            return capture_basename(script);
        }
        if token == b"-" || token.is_empty() {
            return None;
        }
        if let Some(long) = token.strip_prefix(b"--") {
            if long == b"check-hash-based-pycs" {
                index = index.checked_add(2)?;
                continue;
            }
            return None;
        }
        if token[0] == b'-' && token.len() > 1 {
            let mut advanced = false;
            for at in 1..token.len() {
                let flag = token[at];
                if flag == b'c' {
                    return None;
                }
                if flag == b'm' {
                    let rest = &token[at + 1..];
                    if !rest.is_empty() {
                        return capture_dotted_ident(rest);
                    }
                    return capture_dotted_ident(tokens.get(index + 1)?);
                }
                if flag == b'W' || flag == b'X' {
                    if token.len() > at + 1 {
                        index = index.checked_add(1)?;
                    } else {
                        tokens.get(index + 1)?;
                        index = index.checked_add(2)?;
                    }
                    advanced = true;
                    break;
                }
                if !NO_ARG.contains(&flag) {
                    return None;
                }
            }
            if !advanced {
                index = index.checked_add(1)?;
            }
            continue;
        }
        return capture_basename(token);
    }
}

/// Shell walker: only the direct `sh script …` shape (argv[1] without a
/// leading `-`/`+`). Every flag shape — `-c`, `-o`, `-x`, … — bails.
fn shell_token(tokens: &[&[u8]]) -> Option<String> {
    let script = tokens.first()?;
    if script.starts_with(b"-") || script.starts_with(b"+") {
        return None;
    }
    capture_basename(script)
}

/// Documented separate-value `java` launcher flags: skipped with their
/// value so a classpath is never mistaken for the main class.
const JAVA_VALUE_FLAGS: &[&[u8]] = &[
    b"-cp",
    b"-classpath",
    b"--class-path",
    b"-p",
    b"--module-path",
    b"--upgrade-module-path",
    b"--add-modules",
    b"--add-exports",
    b"--add-opens",
    b"--add-reads",
    b"--patch-module",
];

/// Attached (self-contained) single-dash `java` flags: skipped whole.
fn java_attached(token: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"-D",
        b"-X",
        b"-agent",
        b"-javaagent",
        b"-splash",
        b"-ea",
        b"-da",
        b"-esa",
        b"-dsa",
        b"-verbose",
        b"-server",
        b"-client",
        b"-showversion",
        b"-version",
        b"-help",
        b"-?",
    ];
    PREFIXES.iter().any(|prefix| token.starts_with(prefix))
}

/// `java` walker: `-jar` captures the jar basename; otherwise the first
/// non-flag token must be a dotted main class. Unknown flags bail.
fn java_token(tokens: &[&[u8]]) -> Option<String> {
    let mut index = 0;
    loop {
        let token = *tokens.get(index)?;
        if token == b"-jar" {
            let jar = tokens.get(index + 1)?;
            if jar.starts_with(b"-") || !jar.ends_with(b".jar") {
                return None;
            }
            return capture_basename(jar);
        }
        if JAVA_VALUE_FLAGS.contains(&token) {
            tokens.get(index + 1)?;
            index = index.checked_add(2)?;
            continue;
        }
        if token.starts_with(b"--") {
            if token.contains(&b'=') {
                index = index.checked_add(1)?;
                continue;
            }
            return None;
        }
        if token.first() == Some(&b'-') {
            if token.len() > 1 && java_attached(token) {
                index = index.checked_add(1)?;
                continue;
            }
            return None;
        }
        if token.is_empty() {
            return None;
        }
        return capture_dotted_ident(token);
    }
}

/// `node` flags taking a separate value: skipped with it.
const NODE_VALUE_FLAGS: &[&[u8]] = &[
    b"-r",
    b"--require",
    b"--import",
    b"--loader",
    b"--experimental-loader",
    b"--test-reporter",
    b"--test-reporter-destination",
    b"--env-file",
    b"--openssl-config",
    b"--redirect-warnings",
];

/// Curated known-boolean `node` flags (from `node --help`). Unknown bare
/// `--*` bails: a future value-taking flag must never leak its value.
const NODE_BOOL_FLAGS: &[&[u8]] = &[
    b"--inspect",
    b"--inspect-brk",
    b"--no-warnings",
    b"--no-deprecation",
    b"--pending-deprecation",
    b"--enable-source-maps",
    b"--test",
    b"--watch",
    b"--preserve-symlinks",
    b"--preserve-symlinks-main",
    b"--no-experimental-require-module",
    b"--experimental-vm-modules",
    b"--experimental-strip-types",
    b"--no-strip-types",
    b"--permission",
    b"--allow-addons",
    b"--allow-child-process",
    b"--allow-worker",
    b"--cpu-prof",
    b"--heap-prof",
];

/// A node script token must look like a path: a script suffix or a `/`.
/// Bare extensionless names are indistinguishable from an unknown
/// value-taking flag's value, so they yield no hint.
fn node_scriptish(token: &[u8]) -> bool {
    const SUFFIXES: &[&[u8]] = &[b".js", b".mjs", b".cjs", b".ts", b".mts", b".cts"];
    SUFFIXES.iter().any(|suffix| token.ends_with(suffix)) || token.contains(&b'/')
}

/// `node` walker. `-e`/`--eval`/`-p`/`--print` abort: evaluated text is
/// never captured.
fn node_token(tokens: &[&[u8]]) -> Option<String> {
    let mut index = 0;
    loop {
        let token = *tokens.get(index)?;
        if token == b"--" {
            let script = tokens.get(index + 1)?;
            if !node_scriptish(script) {
                return None;
            }
            return capture_basename(script);
        }
        if token == b"-" || token.is_empty() {
            return None;
        }
        if token == b"-e" || token == b"-p" || token == b"--eval" || token == b"--print" {
            return None;
        }
        if NODE_VALUE_FLAGS.contains(&token) {
            tokens.get(index + 1)?;
            index = index.checked_add(2)?;
            continue;
        }
        if token.starts_with(b"--") {
            if token.contains(&b'=') {
                index = index.checked_add(1)?;
                continue;
            }
            if NODE_BOOL_FLAGS.contains(&token) {
                index = index.checked_add(1)?;
                continue;
            }
            return None;
        }
        if token[0] == b'-' && token.len() > 1 {
            if matches!(token, b"-c" | b"-h" | b"-v" | b"-i") {
                index = index.checked_add(1)?;
                continue;
            }
            return None;
        }
        if !node_scriptish(token) {
            return None;
        }
        return capture_basename(token);
    }
}

/// One grammar-proven argv token for a tabled interpreter, if any.
fn argv_token(interpreter: Interpreter, cmdline: &[u8]) -> Option<String> {
    let tokens = complete_tokens(cmdline);
    let args = tokens.get(1..)?;
    match interpreter {
        Interpreter::Python => python_token(args),
        Interpreter::Shell => shell_token(args),
        Interpreter::Java => java_token(args),
        Interpreter::Node => node_token(args),
    }
}

/// Whether a cgroup leaf is container/pod-shaped (DR04 owns that display
/// under its opt-in): never a default-on hint source.
fn cgroup_container_shaped(leaf: &str) -> bool {
    leaf.contains("kubepods")
        || leaf.contains("libpod")
        || leaf.contains("podman")
        || leaf.starts_with("docker-")
        || leaf.starts_with("crio-")
        || leaf.starts_with("cri-")
        || leaf.starts_with("containerd-")
}

/// Whether `text` is a snap/scope name word (`[a-z0-9-]+`, nonempty).
fn is_name_word(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Leaf-of-`0::` cgroup hint: `snap <snap>` for snap scopes, the unit
/// name for services, the opaque leaf for `app-*.scope`. Generic
/// sessions, slices, and container shapes yield nothing.
fn cgroup_hint(cgroup: &str) -> Option<AppHint> {
    let line = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let leaf = line.rsplit('/').find(|part| !part.is_empty())?;
    let leaf = leaf.trim_end();
    if leaf.is_empty() || leaf.len() > HINT_VALUE_MAX_BYTES || cgroup_container_shaped(leaf) {
        return None;
    }
    if let Some(scope) = leaf.strip_suffix(".scope") {
        if let Some(rest) = scope.strip_prefix("snap.") {
            let (snap, app_id) = rest.split_once('.')?;
            // Only the snap name is displayed; the app/instance part is
            // validated, never published.
            let (app, _id) = app_id.split_once('-')?;
            if !is_name_word(snap) || !is_name_word(app) {
                return None;
            }
            return Some(AppHint {
                value: format!("snap {snap}"),
                source: AppHintSource::Snap,
            });
        }
        if leaf.starts_with("app-") {
            return Some(AppHint {
                value: scope.to_string(),
                source: AppHintSource::Unit,
            });
        }
        return None;
    }
    if let Some(unit) = leaf.strip_suffix(".service") {
        if unit.is_empty() || unit.starts_with("user@") {
            return None;
        }
        return Some(AppHint {
            value: unit.to_string(),
            source: AppHintSource::Unit,
        });
    }
    None
}

/// Pure selection over already-read facts.
///
/// Precedence: grammar-proven argv token, then comm (python/sh only),
/// then the cgroup leaf (every exe). A hint equal to the exe basename
/// carries no information and is dropped. `None` (missing/unreadable)
/// inputs yield `None`: the bare interpreter label as today.
pub(crate) fn app_hint_for(
    exe_path: Option<&str>,
    comm: Option<&str>,
    cmdline: Option<&[u8]>,
    cgroup: Option<&str>,
) -> Option<AppHint> {
    let basename = exe_path.and_then(basename_of)?;
    let interpreter = classify_interpreter(basename);
    if let Some(which) = interpreter {
        if let Some(cmdline) = cmdline
            && let Some(value) = argv_token(which, cmdline)
            && value != basename
        {
            return Some(AppHint {
                value,
                source: AppHintSource::Argv,
            });
        }
        if matches!(which, Interpreter::Python | Interpreter::Shell)
            && let Some(comm) = comm
        {
            let comm = comm.trim_end_matches(['\n', '\0']);
            if !comm.is_empty() && comm != basename {
                return Some(AppHint {
                    value: comm.to_string(),
                    source: AppHintSource::Comm,
                });
            }
        }
    }
    let hint = cgroup_hint(cgroup?)?;
    if hint.value == basename {
        return None;
    }
    Some(hint)
}

/// `comm` of `pid` without its trailing newline, if readable.
pub(crate) fn read_comm(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(text.trim_end_matches(['\n', '\0']).to_string())
}

/// Bounded prefix of `/proc/<pid>/cmdline` (at most
/// `CMDLINE_PREFIX_BYTES` plus one probe byte). The whole file is never
/// loaded: argv can approach `ARG_MAX`.
pub(crate) fn read_cmdline_prefix(pid: u32) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(format!("/proc/{pid}/cmdline")).ok()?;
    let mut prefix = Vec::new();
    file.take((CMDLINE_PREFIX_BYTES + 1) as u64)
        .read_to_end(&mut prefix)
        .ok()?;
    prefix.truncate(CMDLINE_PREFIX_BYTES);
    Some(prefix)
}

/// `/proc/<pid>/cgroup` text, defensively bounded (the file is a few
/// lines; anything larger is not parsed).
pub(crate) fn read_cgroup_text(pid: u32) -> Option<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(format!("/proc/{pid}/cgroup")).ok()?;
    let mut text = String::new();
    file.take(65536).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Sample one admission hint for `pid` beside its already-read `exe`.
///
/// Without a readable exe there is no hint and no read. argv/comm are
/// read only for a tabled interpreter; the cgroup leaf for every exe.
/// The exe identity is re-read after sampling and must match, so an
/// exec between the admission read and these reads drops the hint
/// instead of attributing one image's facts to another.
pub(crate) fn sample_for_pid(
    pid: u32,
    exe: Option<&crate::discovery::caller_registry::ExeIdentity>,
) -> Option<AppHint> {
    let exe = exe?;
    let basename = exe.path.as_deref().and_then(basename_of);
    let interpreter = basename.and_then(classify_interpreter);
    let (comm, cmdline) = match interpreter {
        Some(_) => (read_comm(pid), read_cmdline_prefix(pid)),
        None => (None, None),
    };
    let cgroup = read_cgroup_text(pid);
    let hint = app_hint_for(
        exe.path.as_deref(),
        comm.as_deref(),
        cmdline.as_deref(),
        cgroup.as_deref(),
    )?;
    // TOCTOU close: the sampled facts belong to the admitted image only
    // if the exe identity did not change under the reads.
    let current = crate::discovery::caller_registry::read_exe_identity(pid)?;
    if current != *exe {
        return None;
    }
    Some(hint)
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
    fn python_r_flag_takes_no_value() {
        // -R (hash randomization) takes no value: `python3 -R -c`
        // runs the program (verified live, probes-r2.txt).
        assert_eq!(argv("/usr/bin/python3", &["-R", "app.py"]).value, "app.py");
        assert_eq!(argv("/usr/bin/python3", &["-BR", "app.py"]).value, "app.py");
    }

    #[test]
    fn python_dashdash_ends_options() {
        assert_eq!(
            argv("/usr/bin/python3", &["--", "app.py", "-x"]).value,
            "app.py"
        );
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
        assert_eq!(argv("/usr/bin/python3.14", &["app.py"]).value, "app.py");
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
        let hint =
            app_hint_for(Some("/usr/bin/python3"), None, Some(&cmd), None).expect("lossy hint");
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
    fn shells_never_get_hints_not_even_for_direct_scripts() {
        // Owner correction 2026-11-08: a shell cannot load a PKCS#11
        // provider, so sh/bash/dash get no labels at all — no argv,
        // no comm, no cgroup read. "Which script launched the tool"
        // is the parent-chain lane's question, not this one.
        for exe in ["/bin/sh", "/usr/bin/dash", "/usr/bin/bash"] {
            let mut cmd = exe.as_bytes().to_vec();
            cmd.extend_from_slice(b"\x00deploy.sh\x00");
            no_hint(Some(exe), None, Some(&cmd), None);
        }
        let cmd = b"sh\x00-c\x00echo hi\x00".to_vec();
        no_hint(Some("/bin/sh"), None, Some(&cmd), None);
        // Not even a script-shaped comm or a service cgroup.
        no_hint(Some("/bin/sh"), Some("deploy.sh"), None, None);
        let svc = "0::/system.slice/backup-agent.service\n";
        no_hint(Some("/bin/sh"), None, None, Some(svc));
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
        assert_eq!(argv("/usr/bin/node", &["./bin/cli"]).value, "cli");
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
    fn node_eval_equals_forms_bail_and_eval_twins_use_scriptish_payloads() {
        // `--eval=<code>` / `--print=<code>` are real (verified live:
        // rc=0), and no script runs after them — after `--print=` the
        // next token is itself evaluated as code. The walker must bail
        // instead of capturing a later token as "the script".
        let mut cmd = b"node\x00--eval=console.log(1)\x00app.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00--print=1+1\x00app.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        // Scriptish payloads: these kill an abort→skip mutant (the eval
        // text itself would be captured as the "script").
        cmd = b"node\x00-e\x00script.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00--eval\x00script.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00--print\x00script.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00-p\x00script.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
    }

    #[test]
    fn perl_and_ruby_direct_scripts_but_only_direct() {
        // Measured (perl, probes-r2.txt): the direct shebang and the
        // explicit `perl script` shape both put the script at argv[1];
        // ruby is the same shape by construction (no ruby on the probe
        // hosts). Direct shape only: any flag bails to a safe miss —
        // comm and cgroup still apply, and flagged argv grammars are a
        // documented later step, not a guess.
        assert_eq!(
            argv("/usr/bin/perl", &["tool.pl", "--pin", "1"]).value,
            "tool.pl"
        );
        assert_eq!(argv("/usr/bin/ruby", &["app.rb"]).value, "app.rb");
        let mut cmd = b"perl\x00-w\x00tool.pl\x00".to_vec();
        no_hint(Some("/usr/bin/perl"), None, Some(&cmd), None);
        cmd = b"ruby\x00-w\x00app.rb\x00".to_vec();
        no_hint(Some("/usr/bin/ruby"), None, Some(&cmd), None);
        // Versioned spellings are a known safe miss (deferred, not guessed).
        cmd = b"ruby3.2\x00app.rb\x00".to_vec();
        no_hint(Some("/usr/bin/ruby3.2"), None, Some(&cmd), None);
    }

    #[test]
    fn perl_and_ruby_never_eval_text() {
        let mut cmd = b"perl\x00-e\x00script.pl\x00".to_vec();
        no_hint(Some("/usr/bin/perl"), None, Some(&cmd), None);
        cmd = b"perl\x00-E\x00script.pl\x00".to_vec();
        no_hint(Some("/usr/bin/perl"), None, Some(&cmd), None);
        cmd = b"ruby\x00-e\x00script.rb\x00".to_vec();
        no_hint(Some("/usr/bin/ruby"), None, Some(&cmd), None);
    }

    #[test]
    fn comm_names_direct_shebang_perl_and_ruby_apps() {
        // Direct shebang launches keep the script name in comm
        // (measured: `direct-tool` for perl).
        let hint = app_hint_for(Some("/usr/bin/perl"), Some("direct-tool"), None, None)
            .expect("perl comm hint");
        assert_eq!(hint.value, "direct-tool");
        assert_eq!(hint.source, AppHintSource::Comm);
        let hint =
            app_hint_for(Some("/usr/bin/ruby"), Some("myapp"), None, None).expect("ruby comm hint");
        assert_eq!(hint.value, "myapp");
        assert_eq!(hint.source, AppHintSource::Comm);
    }

    #[test]
    fn pin_values_are_never_captured_in_any_position() {
        for (exe, args, script) in [
            (
                "/usr/bin/python3",
                vec!["job.py", "--pin", "1234"],
                "job.py",
            ),
            (
                "/usr/bin/python3",
                vec!["-m", "job", "--pin", "1234"],
                "job",
            ),
            ("/usr/bin/perl", vec!["job.pl", "--pin", "1234"], "job.pl"),
            ("/usr/bin/ruby", vec!["job.rb", "--pin", "1234"], "job.rb"),
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
        assert_eq!(
            (hint.value.as_str(), hint.source),
            ("other.py", AppHintSource::Argv)
        );
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
    fn cgroup_leaf_names_snaps_units_and_scopes_for_runtimes_only() {
        // Native executables keep the plain name: no packaging hints
        // (owner ruling 2026-11-08 — snap firefox stays `firefox`).
        let snap = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.firefox.firefox-uuid.scope\n";
        no_hint(
            Some("/snap/firefox/9057/usr/lib/firefox/firefox"),
            None,
            None,
            Some(snap),
        );
        let svc = "0::/system.slice/backup-agent.service\n";
        no_hint(Some("/usr/bin/pkcs11-tool"), None, None, Some(svc));
        // A label ON a runtime is allowed: the same snap shape under node.
        let hint =
            app_hint_for(Some("/usr/bin/node"), None, None, Some(snap)).expect("snap hint on node");
        assert_eq!(hint.value, "snap firefox");
        assert_eq!(hint.source, AppHintSource::Snap);
        let hint =
            app_hint_for(Some("/usr/bin/python3"), None, None, Some(svc)).expect("unit hint");
        assert_eq!(hint.value, "backup-agent");
        assert_eq!(hint.source, AppHintSource::Unit);
        let scope = "0::/user.slice/app-org.gnome.Foo-1.scope\n";
        let hint =
            app_hint_for(Some("/usr/bin/python3"), None, None, Some(scope)).expect("scope hint");
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
    fn cgroup_value_equal_to_runtime_basename_is_dropped() {
        let svc = "0::/system.slice/python3.service\n";
        no_hint(Some("/usr/bin/python3"), None, None, Some(svc));
    }

    #[test]
    fn overlong_values_are_refused_at_every_source() {
        // argv tokens already refuse >255 bytes; comm and the cgroup
        // leaf enforce the same bound. An overlong comm falls through
        // to the cgroup leaf like an empty one.
        let long_comm = "c".repeat(HINT_VALUE_MAX_BYTES + 1);
        no_hint(Some("/usr/bin/python3"), Some(&long_comm), None, None);
        let svc = "0::/system.slice/backup-agent.service\n";
        let hint = app_hint_for(Some("/usr/bin/python3"), Some(&long_comm), None, Some(svc))
            .expect("cgroup wins after an overlong comm");
        assert_eq!(hint.value, "backup-agent");
        assert_eq!(hint.source, AppHintSource::Unit);
        let leaf = format!("0::/system.slice/{}.service\n", "u".repeat(300));
        no_hint(Some("/usr/bin/python3"), None, None, Some(&leaf));
    }

    #[test]
    fn longest_valid_snap_label_stays_within_the_bound() {
        // `snap.<snap>.<app>-<id>.scope` needs 15 bytes besides the
        // snap name, so a 255-byte leaf holds at most a 240-char snap;
        // the composed `snap <snap>` value must still fit NAME_MAX.
        let snap = "s".repeat(240);
        let leaf = format!("0::/app.slice/snap.{snap}.a-b.scope\n");
        assert_eq!(leaf.trim().rsplit('/').next().unwrap().len(), 255);
        let hint = app_hint_for(Some("/usr/bin/python3"), None, None, Some(&leaf))
            .expect("longest snap hint");
        assert_eq!(hint.value, format!("snap {snap}"));
        assert!(hint.value.len() <= HINT_VALUE_MAX_BYTES);
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

    #[test]
    fn readers_sample_the_test_process_itself() {
        let pid = std::process::id();
        let comm = read_comm(pid).expect("own comm is readable");
        assert!(!comm.is_empty());
        let cmdline = read_cmdline_prefix(pid).expect("own cmdline is readable");
        assert!(cmdline.contains(&0));
        assert!(cmdline.len() <= CMDLINE_PREFIX_BYTES);
        let cgroup = read_cgroup_text(pid).expect("own cgroup is readable");
        assert!(cgroup.contains("0::"));
    }

    #[test]
    fn sampler_needs_an_exe_and_a_matching_identity() {
        use crate::discovery::caller_registry::read_exe_identity;
        let pid = std::process::id();
        assert_eq!(sample_for_pid(pid, None), None);
        let mut exe = read_exe_identity(pid).expect("own exe identity");
        exe.ino = exe.ino.wrapping_add(1);
        assert_eq!(
            sample_for_pid(pid, Some(&exe)),
            None,
            "a changed identity drops the hint"
        );
        let exe = read_exe_identity(pid).expect("own exe identity");
        let cgroup = read_cgroup_text(pid);
        assert_eq!(
            sample_for_pid(pid, Some(&exe)),
            app_hint_for(exe.path.as_deref(), None, None, cgroup.as_deref()),
            "a non-interpreter test binary samples the cgroup leaf only"
        );
    }
}
