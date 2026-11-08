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

/// Which interpreter grammar gates the argv/comm/cgroup reads: only
/// runtimes that load the PKCS#11 provider into their own process
/// (owner ruling 2026-11-08; shells and native exes get no labels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Interpreter {
    Python,
    Java,
    Node,
    Perl,
    Ruby,
}

/// Whether `comm` may source a hint for `interpreter` at all. One
/// predicate gates both the `/proc/<pid>/comm` read and the comm hint
/// below: java and node get no comm read, since their task names are
/// not script names (node's main task is `MainThread`, measured).
fn comm_eligible(interpreter: Interpreter) -> bool {
    matches!(
        interpreter,
        Interpreter::Python | Interpreter::Perl | Interpreter::Ruby
    )
}

/// Last nonempty `/`-separated component, if any.
fn basename_of(path: &str) -> Option<&str> {
    path.rsplit('/').find(|part| !part.is_empty())
}

/// Exact interpreter table (final ruling 2026-11-08): extension needs
/// a reviewed allowlist change. `python3.<N>` is digits-only; anything
/// else (`python3.13t`, `python2`, wrappers, versioned `ruby3.x`) is
/// not an interpreter. Shells are excluded: a shell cannot load a
/// provider, so sh/bash/dash get no label at all.
fn classify_interpreter(basename: &str) -> Option<Interpreter> {
    match basename {
        "python" | "python3" => Some(Interpreter::Python),
        "java" => Some(Interpreter::Java),
        "node" | "nodejs" => Some(Interpreter::Node),
        "perl" => Some(Interpreter::Perl),
        "ruby" => Some(Interpreter::Ruby),
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

/// Basename of a path token: lossy, last component, 1..=255 bytes,
/// never all whitespace (title padding), never starting with `-` (a
/// value in disguise).
fn capture_basename(token: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(token);
    let base = basename_of(&text)?;
    if base.trim().is_empty() || base.len() > HINT_VALUE_MAX_BYTES || base.starts_with('-') {
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
    const NO_ARG: &[u8] = b"Bb?dEhiIOPRqsSuvVx";
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

/// Direct-shape walker for perl/ruby: only `perl script …` /
/// `ruby script …` (argv[1] without a leading `-`). Every flag shape —
/// `-e`/`-E` program text, `-w`, `-c`, … — bails to a safe miss; comm
/// and cgroup still apply. Flagged argv grammars are a documented
/// later step, not a guess.
fn direct_script_token(tokens: &[&[u8]]) -> Option<String> {
    let script = tokens.first()?;
    if script.starts_with(b"-") {
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

/// Self-contained `--name=value` java launcher forms (the JDK
/// whitespace-option lists): the value rides the token, so the whole
/// token skips. Every other `--*=*` bails — notably
/// `--module=<m>/<class>`, after which the launcher hands every later
/// token to the application: skipping it would capture the first
/// application argument as the "main class".
const JAVA_EQ_FLAGS: &[&[u8]] = &[
    b"--class-path",
    b"--module-path",
    b"--upgrade-module-path",
    b"--add-modules",
    b"--enable-native-access",
    b"--limit-modules",
    b"--add-exports",
    b"--add-opens",
    b"--add-reads",
    b"--patch-module",
    b"--enable-final-field-mutation",
    b"--illegal-native-access",
    b"--illegal-final-field-mutation",
    b"--sun-misc-unsafe-memory-access",
    b"--finalization",
    b"--source",
];

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
            if let Some(eq) = token.iter().position(|byte| *byte == b'=') {
                let name = &token[..eq];
                if JAVA_EQ_FLAGS.contains(&name) {
                    index = index.checked_add(1)?;
                    continue;
                }
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

/// Self-contained `--name=value` node forms: every `--name=...`
/// spelling `node --help` documents (v24; the `--inspect*` family takes
/// `[=...]`), except `--eval` (evaluated text, bails above) and `--run`
/// (package-script entry: later tokens are that script's arguments, not
/// node scripts), plus `--loader` (`=` acceptance probe-verified,
/// probe-r3). Each carries an attached value and leaves positional
/// parsing unchanged, so the whole token skips. Anything unlisted — V8
/// tuning flags, future options — bails to a safe miss.
const NODE_EQ_FLAGS: &[&[u8]] = &[
    b"--allow-fs-read",
    b"--allow-fs-write",
    b"--build-snapshot-config",
    b"--conditions",
    b"--cpu-prof-dir",
    b"--cpu-prof-interval",
    b"--cpu-prof-name",
    b"--diagnostic-dir",
    b"--disable-proto",
    b"--disable-warning",
    b"--dns-result-order",
    b"--env-file",
    b"--env-file-if-exists",
    b"--experimental-config-file",
    b"--experimental-loader",
    b"--experimental-package-map",
    b"--experimental-sea-config",
    b"--experimental-test-tag-filter",
    b"--heap-prof-dir",
    b"--heap-prof-interval",
    b"--heap-prof-name",
    b"--heapsnapshot-near-heap-limit",
    b"--heapsnapshot-signal",
    b"--icu-data-dir",
    b"--import",
    b"--input-type",
    b"--inspect",
    b"--inspect-brk",
    b"--inspect-port",
    b"--inspect-publish-uid",
    b"--inspect-wait",
    b"--loader",
    b"--localstorage-file",
    b"--max-http-header-size",
    b"--max-old-space-size-percentage",
    b"--network-family-autoselection-attempt-timeout",
    b"--openssl-config",
    b"--redirect-warnings",
    b"--report-dir",
    b"--report-filename",
    b"--report-signal",
    b"--require",
    b"--secure-heap",
    b"--secure-heap-min",
    b"--snapshot-blob",
    b"--test-concurrency",
    b"--test-coverage-branches",
    b"--test-coverage-exclude",
    b"--test-coverage-functions",
    b"--test-coverage-include",
    b"--test-coverage-lines",
    b"--test-global-setup",
    b"--test-isolation",
    b"--test-name-pattern",
    b"--test-random-seed",
    b"--test-reporter",
    b"--test-reporter-destination",
    b"--test-rerun-failures",
    b"--test-shard",
    b"--test-skip-pattern",
    b"--test-timeout",
    b"--title",
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
            if let Some(eq) = token.iter().position(|byte| *byte == b'=') {
                // `--eval=<code>` / `--print=<expr>` evaluate inline
                // text: no script runs (after `--print=` the next token
                // is itself evaluated as code), so bail before the
                // tabled self-contained skip.
                let name = &token[..eq];
                if name == b"--eval" || name == b"--print" {
                    return None;
                }
                if NODE_EQ_FLAGS.contains(&name) {
                    index = index.checked_add(1)?;
                    continue;
                }
                return None;
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
        Interpreter::Java => java_token(args),
        Interpreter::Node => node_token(args),
        Interpreter::Perl | Interpreter::Ruby => direct_script_token(args),
    }
}

/// Whether a cgroup path component is container/pod-shaped (DR04 owns
/// that display under its opt-in): never a default-on hint source.
/// Every component of the `0::` path is screened, not just the leaf: a
/// container running its own systemd nests services under container
/// scopes, and those service names stay behind the opt-in too.
fn cgroup_container_shaped(component: &str) -> bool {
    component.contains("kubepods")
        || component.contains("libpod")
        || component.contains("podman")
        || component.contains("lxc.payload.")
        || component.contains("systemd-nspawn@")
        || component.starts_with("docker-")
        || component.starts_with("crio-")
        || component.starts_with("cri-")
        || component.starts_with("containerd-")
}

/// Whether `text` is a snap/scope name word (`[a-z0-9-]+`, nonempty).
fn is_name_word(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Compose a hint, enforcing the `NAME_MAX` bound on the final value:
/// composed values such as `snap <snap>` are longer than the leaf they
/// parse from, so the bound is checked here, not just at the leaf.
fn bounded_hint(value: String, source: AppHintSource) -> Option<AppHint> {
    if value.len() > HINT_VALUE_MAX_BYTES {
        return None;
    }
    Some(AppHint { value, source })
}

/// Whether a `0::` path component is the user-manager service,
/// exactly `user@<digits>.service`.
fn is_user_manager_service(component: &str) -> bool {
    component
        .strip_prefix("user@")
        .and_then(|rest| rest.strip_suffix(".service"))
        .is_some_and(|uid| !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Leaf-of-`0::` cgroup hint: `snap <snap>` for snap scopes, the unit
/// name for services, the opaque leaf for `app-*.scope`. Generic
/// sessions, slices, and container shapes yield nothing.
fn cgroup_hint(cgroup: &str) -> Option<AppHint> {
    let line = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    if line
        .split('/')
        .any(|component| cgroup_container_shaped(component.trim_end()))
    {
        return None;
    }
    let mut parts = line.rsplit('/').filter(|part| !part.is_empty());
    let leaf = parts.next()?;
    // Structural rule: the leaf is accepted only when every ancestor
    // is a plain host nesting level — ending in `.slice`, except at
    // most one `user@<digits>.service`. Container scopes, container
    // services and cgroupfs directories refuse the leaf no matter
    // what the name list above knows.
    let mut user_managers = 0;
    for ancestor in parts {
        let ancestor = ancestor.trim_end();
        if is_user_manager_service(ancestor) {
            user_managers += 1;
        } else if !ancestor.ends_with(".slice") {
            return None;
        }
    }
    if user_managers > 1 {
        return None;
    }
    let leaf = leaf.trim_end();
    if leaf.is_empty() || leaf.len() > HINT_VALUE_MAX_BYTES {
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
            return bounded_hint(format!("snap {snap}"), AppHintSource::Snap);
        }
        if leaf.starts_with("app-") {
            return bounded_hint(scope.to_string(), AppHintSource::Unit);
        }
        return None;
    }
    if let Some(unit) = leaf.strip_suffix(".service") {
        if unit.is_empty() || unit.starts_with("user@") {
            return None;
        }
        // Template instances take the instance id as an argument
        // (`job@tenant.service`): publish the template name only.
        let unit = match unit.split_once('@') {
            Some((prefix, _)) if !prefix.is_empty() => format!("{prefix}@"),
            Some(_) => return None,
            None => unit.to_string(),
        };
        return bounded_hint(unit, AppHintSource::Unit);
    }
    None
}

/// Script-position token for the comm cross-check: `argv[1]`, or
/// `argv[2]` when `argv[1]` is a single dash-led shebang argument (the
/// kernel passes at most one: `perl -w` / `ruby -w` shebangs put the
/// script at `argv[2]`).
fn comm_script_token<'a>(args: &[&'a [u8]]) -> Option<&'a [u8]> {
    let first = *args.first()?;
    if first.len() > 1 && first.starts_with(b"-") {
        args.get(1).copied()
    } else {
        Some(first)
    }
}

/// Whether `comm` is the name the kernel set at exec: it must equal the
/// first 15 bytes (`TASK_COMM_LEN`) of the basename of the
/// script-position token from the same cmdline sample. comm is writable
/// by the process (`$0`, prctl), and a rewritten title arrives as a
/// single cmdline token with no script position — so an unmatched comm
/// is never published.
fn comm_matches_script(comm: &str, cmdline: &[u8]) -> bool {
    let tokens = complete_tokens(cmdline);
    let args = match tokens.get(1..) {
        Some(args) => args,
        None => return false,
    };
    let script = match comm_script_token(args) {
        Some(script) => script,
        None => return false,
    };
    let text = String::from_utf8_lossy(script);
    let base = match basename_of(&text) {
        Some(base) => base,
        None => return false,
    };
    let bytes = base.as_bytes();
    comm.as_bytes() == &bytes[..bytes.len().min(15)]
}

/// Pure selection over already-read facts.
///
/// Only a tabled runtime gets any hint: shells and native exes keep
/// the plain name (owner ruling 2026-11-08). Precedence: grammar-proven
/// argv token, then comm (python/perl/ruby, only when it matches the
/// script-position token of the same cmdline sample), then the cgroup
/// leaf of an admitted runtime. A hint equal to the exe basename
/// carries no information and is dropped. `None` (missing/unreadable)
/// inputs yield `None`: the bare label as today.
pub(crate) fn app_hint_for(
    exe_path: Option<&str>,
    comm: Option<&str>,
    cmdline: Option<&[u8]>,
    cgroup: Option<&str>,
) -> Option<AppHint> {
    let basename = exe_path.and_then(basename_of)?;
    let interpreter = classify_interpreter(basename)?;
    if let Some(cmdline) = cmdline
        && let Some(value) = argv_token(interpreter, cmdline)
        && value != basename
    {
        return Some(AppHint {
            value,
            source: AppHintSource::Argv,
        });
    }
    if comm_eligible(interpreter)
        && let Some(comm) = comm
        && let Some(cmdline) = cmdline
    {
        let comm = comm.trim_end_matches(['\n', '\0']);
        if !comm.is_empty()
            && comm != basename
            && comm.len() <= HINT_VALUE_MAX_BYTES
            && comm_matches_script(comm, cmdline)
        {
            return Some(AppHint {
                value: comm.to_string(),
                source: AppHintSource::Comm,
            });
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

/// Whether the sampled process generation is intact: the start time
/// read before the comm/cmdline/cgroup reads must equal the one read
/// after. Both must be present — an unreadable generation is dropped,
/// like an unreadable exe. (A same-binary re-exec inside the window
/// keeps both, so the label stays a point sample; see below.)
fn sampled_generation_intact(before: Option<u64>, after: Option<u64>) -> bool {
    matches!((before, after), (Some(t0), Some(t1)) if t0 == t1)
}

/// Sample one admission hint for `pid` beside its already-read `exe`.
///
/// Without a readable exe there is no hint and no read. cmdline and the
/// cgroup text are read only for a tabled runtime, comm only for
/// python/perl/ruby; shells and native exes get no read at all. The exe
/// identity and the process start time are re-read after sampling and
/// must match `admitted_start_time` — the generation admission pinned
/// — so an exec or pid reuse under the reads drops the hint instead of
/// attributing one image's or generation's facts to another.
/// The label is sampled once: a same-binary re-exec inside the sample
/// window keeps a stale label.
pub(crate) fn sample_for_pid(
    pid: u32,
    exe: Option<&crate::discovery::caller_registry::ExeIdentity>,
    _admitted_start_time: Option<u64>,
) -> Option<AppHint> {
    let exe = exe?;
    let basename = exe.path.as_deref().and_then(basename_of);
    let interpreter = basename.and_then(classify_interpreter);
    let start_before = crate::process::process_start_time(pid).ok();
    let comm = match interpreter {
        Some(interpreter) if comm_eligible(interpreter) => read_comm(pid),
        _ => None,
    };
    let (cmdline, cgroup) = match interpreter {
        Some(_) => (read_cmdline_prefix(pid), read_cgroup_text(pid)),
        None => (None, None),
    };
    let hint = app_hint_for(
        exe.path.as_deref(),
        comm.as_deref(),
        cmdline.as_deref(),
        cgroup.as_deref(),
    )?;
    // TOCTOU close: the sampled facts belong to the admitted image and
    // generation only if neither changed under the reads.
    let current = crate::discovery::caller_registry::read_exe_identity(pid)?;
    if current != *exe {
        return None;
    }
    if !sampled_generation_intact(start_before, crate::process::process_start_time(pid).ok()) {
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
    fn python_c_and_repl_yield_no_comm_hint() {
        // `python3 -c` / REPL: comm is `python3` while the exe
        // basename is `python3.14` — a useless label, and `-c` text
        // must never be captured. No script-position token matches.
        let mut cmd = b"python3\x00-c\x00print(1)\x00".to_vec();
        no_hint(
            Some("/usr/bin/python3.14"),
            Some("python3"),
            Some(&cmd),
            None,
        );
        cmd = b"python3\x00".to_vec();
        no_hint(
            Some("/usr/bin/python3.14"),
            Some("python3"),
            Some(&cmd),
            None,
        );
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
    }

    #[test]
    fn java_module_entry_never_captures_app_args() {
        // `--module=<m>/<class>` is the main-entry option: the JDK
        // launcher hands every later token to the application, so the
        // parser must bail instead of capturing the first app arg.
        let mut cmd = b"java\x00--module=app/com.Main\x00secretpw\x00--pin\x001234\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
        cmd = b"java\x00--module=app/com.Main\x00login\x00admin\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
        // Separate `-m` form: same bail (control).
        cmd = b"java\x00-m\x00app/com.Main\x00secretpw\x00".to_vec();
        no_hint(Some("/usr/bin/java"), None, Some(&cmd), None);
        // Tabled self-contained `=` forms still skip to the class.
        assert_eq!(
            argv("/usr/bin/java", &["--class-path=lib/*", "com.App"]).value,
            "com.App"
        );
        assert_eq!(
            argv(
                "/usr/bin/java",
                &["--add-opens=java.base/java.lang=ALL-UNNAMED", "com.App"]
            )
            .value,
            "com.App"
        );
        assert_eq!(
            argv(
                "/usr/bin/java",
                &["--enable-native-access=ALL-UNNAMED", "com.App"]
            )
            .value,
            "com.App"
        );
        // `--source=` runs the next token as single-file source: the
        // program file, like a script.
        assert_eq!(
            argv("/usr/bin/java", &["--source=8", "App.java"]).value,
            "App.java"
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
        // Unknown `=` options are not self-contained until tabled.
        cmd = b"java\x00--affinity=1\x00com.App\x00".to_vec();
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
    fn node_run_equals_form_never_captures_script_args() {
        // `node --run=deploy -- ./cfg/prod.json` runs the package.json
        // script `deploy`; `./cfg/prod.json` is that script's argument,
        // not a node script. Only tabled self-contained `=` forms skip.
        let mut cmd = b"node\x00--run=deploy\x00--\x00./cfg/prod.json\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00--future=1\x00app.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        cmd = b"node\x00--run\x00deploy\x00app.js\x00".to_vec();
        no_hint(Some("/usr/bin/node"), None, Some(&cmd), None);
        // Tabled `=` forms still skip to the script.
        assert_eq!(
            argv("/usr/bin/node", &["--require=./preload.js", "app.js"]).value,
            "app.js"
        );
        assert_eq!(
            argv("/usr/bin/node", &["--inspect=127.0.0.1:9229", "app.js"]).value,
            "app.js"
        );
        assert_eq!(
            argv("/usr/bin/node", &["--test-timeout=5", "--test", "app.js"]).value,
            "app.js"
        );
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
    fn perl_title_padding_is_never_a_whitespace_hint() {
        // Live bytes: a `#!/usr/bin/perl -w` script doing
        // `$0="tool --pin 99"`, run under `env -i`. The rewritten
        // title token plus a 54-space padding token: an
        // all-whitespace basename is refused, never published.
        let mut cmd = b"tool --pin 99\x00".to_vec();
        cmd.extend_from_slice(&[b' '; 54]);
        cmd.push(0);
        assert_eq!(capture_basename(&[b' '; 54]), None);
        no_hint(Some("/usr/bin/perl"), None, Some(&cmd), None);
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
    fn comm_names_flagged_shebang_perl_and_ruby_apps() {
        // `#!/usr/bin/perl -w` puts the script at argv[2]: argv bails
        // on the flag, but comm still names the script — measured
        // live (comm `plain.pl`, probe-r3). The comm value must match
        // the script-position token of the same cmdline sample; a
        // rewritten title never matches (see below).
        let mut cmd = b"perl\x00-w\x00/x/tool\x00--pin\x001\x00".to_vec();
        let hint = app_hint_for(Some("/usr/bin/perl"), Some("tool"), Some(&cmd), None)
            .expect("perl comm hint");
        assert_eq!(hint.value, "tool");
        assert_eq!(hint.source, AppHintSource::Comm);
        cmd = b"ruby\x00-w\x00/x/myapp\x00".to_vec();
        let hint = app_hint_for(Some("/usr/bin/ruby"), Some("myapp"), Some(&cmd), None)
            .expect("ruby comm hint");
        assert_eq!(hint.value, "myapp");
        assert_eq!(hint.source, AppHintSource::Comm);
    }

    #[test]
    fn rewritten_title_comm_matches_no_script_token() {
        // Blocking privacy case: a `perl -w` script runs
        // `$0 = "sign --pin 4321"`. The rewritten cmdline arrives as
        // one token, so there is no script-position token and comm —
        // the process's own writable title — must never be published.
        let cmd = b"sign --pin 4321\x00".to_vec();
        no_hint(
            Some("/usr/bin/perl"),
            Some("sign --pin 4321"),
            Some(&cmd),
            None,
        );
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
    fn pin_values_after_module_entry_are_never_captured() {
        // Module-entry extension of the `--pin` matrix: after
        // `--module=`/`-m` every token belongs to the application, so
        // there is no hint at all — the pin value is unreachable.
        for args in [
            vec!["--module=app/com.Main", "--pin", "1234"],
            vec!["-m", "app/com.Main", "--pin", "1234"],
        ] {
            let mut cmd = b"java\x00".to_vec();
            for arg in &args {
                cmd.extend_from_slice(arg.as_bytes());
                cmd.push(0);
            }
            assert_eq!(
                app_hint_for(Some("/usr/bin/java"), None, Some(&cmd), None),
                None,
                "module-entry args for {args:?}"
            );
        }
    }

    #[test]
    fn comm_without_a_matching_cmdline_sample_is_not_a_hint() {
        // Bare comm proves nothing: the process writes its own title
        // (`$0`, prctl), so comm is a hint only when it equals the
        // first 15 bytes of the script-position token's basename from
        // the same cmdline sample. Direct shebangs resolve through
        // argv instead (full basename, untruncated).
        no_hint(Some("/usr/bin/python3"), Some("pkcs11-check"), None, None);
        no_hint(Some("/usr/bin/perl"), Some("direct-tool"), None, None);
        no_hint(Some("/usr/bin/ruby"), Some("myapp"), None, None);
        let hint = argv("/usr/bin/python3", &["/opt/venv/bin/pkcs11-check"]);
        assert_eq!(hint.value, "pkcs11-check");
        assert_eq!(hint.source, AppHintSource::Argv);
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
    fn comm_is_eligible_only_for_python_perl_and_ruby() {
        // One predicate gates both the comm read and the comm hint:
        // java and node get no comm read at all.
        assert!(comm_eligible(Interpreter::Python));
        assert!(comm_eligible(Interpreter::Perl));
        assert!(comm_eligible(Interpreter::Ruby));
        assert!(!comm_eligible(Interpreter::Java));
        assert!(!comm_eligible(Interpreter::Node));
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
    fn container_ancestors_suppress_unit_hints() {
        // Structural rule: a leaf is accepted only when every ancestor
        // component ends in `.slice`, except at most one
        // `user@<digits>.service`. The name list below stays as a second
        // check. A service inside a container is never a default-on
        // hint (DR04 owns container display under its opt-in).
        for cg in [
            "0::/system.slice/docker-0123abcd.scope/system.slice/hsm-agent.service\n",
            "0::/lxc.payload.tenant-a/system.slice/billing-worker.service\n",
            "0::/machine.slice/systemd-nspawn@tenant.service/payload/system.slice/sign.service\n",
            "0::/machine.slice/systemd-nspawn@tenant.service\n",
            // nixos-container layout: nspawn with `--keep-unit` under
            // `machine.slice/container@<name>.service`.
            "0::/machine.slice/container@tenant.service/system.slice/hsm-agent.service\n",
            // Docker cgroupfs driver on cgroup v2.
            "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/system.slice/hsm-agent.service\n",
            // nspawn registered with machined (`payload` level present
            // or not).
            "0::/machine.slice/machine-tenant.scope/payload/system.slice/sign.service\n",
            "0::/machine.slice/machine-tenant.scope/system.slice/sign.service\n",
            // libvirt-lxc scope, legacy cgroupfs parent, nerdctl scope,
            // and an unknown custom parent: the rule is structural, so
            // no name list can enumerate them all.
            "0::/machine.slice/machine-lxc\\x2dtenant.scope/system.slice/agent.service\n",
            "0::/lxc/tenant/system.slice/agent.service\n",
            "0::/system.slice/nerdctl-0123456789abcdef.scope/system.slice/agent.service\n",
            "0::/tenant-a/system.slice/agent.service\n",
            // At most one `user@<digits>.service` ancestor: a nested
            // second one is not a plain user session.
            "0::/user.slice/user-1000.slice/user@1000.service/user@1001.service/agent.service\n",
        ] {
            no_hint(Some("/usr/bin/python3"), None, None, Some(cg));
        }
    }

    #[test]
    fn template_unit_instances_publish_the_template_only() {
        // The instance part is effectively a unit argument
        // (`job@tenant.service`): only `job@` is published.
        let cg = "0::/system.slice/job@tenant-a.service\n";
        let hint = app_hint_for(Some("/usr/bin/python3"), None, None, Some(cg)).expect("unit hint");
        assert_eq!(hint.value, "job@");
        assert_eq!(hint.source, AppHintSource::Unit);
        let cg = "0::/system.slice/getty@tty1.service\n";
        let hint = app_hint_for(Some("/usr/bin/python3"), None, None, Some(cg)).expect("unit hint");
        assert_eq!(hint.value, "getty@");
        // No template name at all: no hint.
        no_hint(
            Some("/usr/bin/python3"),
            None,
            None,
            Some("0::/system.slice/@foo.service\n"),
        );
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
    fn composed_values_are_bounded_at_construction() {
        // The guard itself: a composed value over NAME_MAX never
        // becomes a hint, whatever leaf it parsed from.
        let overlong = "s".repeat(HINT_VALUE_MAX_BYTES + 1);
        assert_eq!(bounded_hint(overlong, AppHintSource::Snap), None);
        let fitting = "s".repeat(HINT_VALUE_MAX_BYTES);
        assert_eq!(
            bounded_hint(fitting.clone(), AppHintSource::Snap),
            Some(AppHint {
                value: fitting,
                source: AppHintSource::Snap,
            })
        );
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
    fn sampled_generation_check_needs_matching_start_times() {
        // The sampler re-reads the process start time after its reads:
        // a changed (or unreadable) generation drops the hint instead
        // of attributing one generation's facts to another.
        assert!(sampled_generation_intact(Some(100), Some(100)));
        assert!(!sampled_generation_intact(Some(100), Some(101)));
        assert!(!sampled_generation_intact(Some(100), None));
        assert!(!sampled_generation_intact(None, Some(100)));
        assert!(!sampled_generation_intact(None, None));
    }

    #[test]
    fn sampler_refuses_a_generation_other_than_the_admitted_one() {
        use crate::discovery::caller_registry::read_exe_identity;
        use crate::process::process_start_time;
        use std::process::{Command, Stdio};
        // python3 is a documented test prerequisite
        // (docs/development.md), resolved like the console-script CLI
        // cell.
        let python = {
            let out = Command::new("sh")
                .args(["-c", "command -v python3"])
                .output()
                .expect("sh runs");
            assert!(out.status.success(), "python3 is required for this test");
            String::from_utf8(out.stdout)
                .expect("utf8 path")
                .trim()
                .to_string()
        };
        assert!(python.starts_with('/'), "python3 path: {python}");
        let script = std::env::temp_dir().join(format!(
            "p11scope-app-hint-admitted-{}.py",
            std::process::id()
        ));
        let script_name = script
            .file_name()
            .expect("script file name")
            .to_string_lossy()
            .into_owned();
        std::fs::write(&script, "import time\ntime.sleep(30)\n").expect("write script");
        let mut child = Command::new(&python)
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn python sleeper");
        let pid = child.id();
        // Readiness is state, not time: wait until the script name is
        // in the child's cmdline, so the sample below cannot race the
        // exec.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if cmdline
                .windows(script_name.len())
                .any(|window| window == script_name.as_bytes())
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "python sleeper never execed its script"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let exe = read_exe_identity(pid).expect("child exe identity");
        let admitted = process_start_time(pid).ok().expect("child start time");
        let hint = sample_for_pid(pid, Some(&exe), Some(admitted))
            .expect("the admitted generation keeps its argv hint");
        assert_eq!(hint.value, script_name);
        assert_eq!(hint.source, AppHintSource::Argv);
        assert_eq!(
            sample_for_pid(pid, Some(&exe), Some(admitted.wrapping_add(1))),
            None,
            "a generation other than the admitted one drops the hint"
        );
        assert_eq!(
            sample_for_pid(pid, Some(&exe), None),
            None,
            "an unknown admitted generation drops the hint"
        );
        child.kill().ok();
        let _ = child.wait();
        std::fs::remove_file(&script).ok();
    }

    #[test]
    fn sampler_needs_an_exe_and_a_matching_identity() {
        use crate::discovery::caller_registry::read_exe_identity;
        use crate::process::process_start_time;
        let pid = std::process::id();
        let admitted = process_start_time(pid).ok();
        assert_eq!(sample_for_pid(pid, None, admitted), None);
        let mut exe = read_exe_identity(pid).expect("own exe identity");
        exe.ino = exe.ino.wrapping_add(1);
        assert_eq!(
            sample_for_pid(pid, Some(&exe), admitted),
            None,
            "a changed identity drops the hint"
        );
        let exe = read_exe_identity(pid).expect("own exe identity");
        let cgroup = read_cgroup_text(pid);
        assert_eq!(
            sample_for_pid(pid, Some(&exe), admitted),
            app_hint_for(exe.path.as_deref(), None, None, cgroup.as_deref()),
            "a non-interpreter test binary samples nothing at all"
        );
    }
}
