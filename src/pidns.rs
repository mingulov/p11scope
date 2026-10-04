//! SPDX-License-Identifier: GPL-3.0-or-later
//! Which PID namespace this observer numbers processes in (DR-30, DR-K8S-1/2).
//!
//! BPF names every task by `bpf_get_current_pid_tgid()`: the task's tgid in
//! the **initial** PID namespace. Everything userspace reads from `/proc` —
//! the `--pid` argument, `run`'s child, every discovery and inventory view —
//! is numbered in the observer's **own** PID namespace. The two numberings
//! agree exactly when the observer runs in the initial namespace. An observer
//! in a nested namespace (a kind/k3d node, a container without the host PID
//! namespace) would publish its own-view PID into the kernel `PID_FILTER`,
//! which the kernel never matches: a capture of nothing that claimed exact
//! observation.
//!
//! The initial PID namespace has a fixed nsfs inode, `PROC_PID_INIT_INO`
//! (`include/linux/proc_ns.h`, kernel ABI since 3.8), and `/proc/self/ns/pid`
//! (`pid:[<inode>]`) names the reading task's own namespace whichever procfs
//! instance serves it. So the comparison is exact and needs no BPF: the
//! initial inode → initial; any other inode → nested; unreadable or not a
//! PID namespace link → unknown, which every caller treats like nested
//! (never assumed initial).

use std::sync::OnceLock;

use anyhow::{Result, anyhow};
use serde::Serialize;

/// `PROC_PID_INIT_INO`: the nsfs inode of the initial PID namespace.
pub const INIT_PID_NS_INODE: u64 = 0xEFFF_FFFC;

/// The named refusal every PID-scoped capture uses in a namespace mismatch.
pub const MISMATCH_CODE: &str = "pid-namespace-mismatch";

/// Where this observer runs, relative to the namespace BPF numbers tasks in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverPidNs {
    /// The initial PID namespace: `/proc` PIDs are the kernel's PIDs.
    Initial,
    /// A descendant PID namespace: `/proc` PIDs are not the kernel's PIDs.
    Nested,
    /// The namespace could not be read. Never treated as initial.
    Unknown(String),
}

impl ObserverPidNs {
    /// The published label (`pid_namespace.observer`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Nested => "nested",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Whether `/proc` PIDs and kernel (BPF) PIDs are proven to agree.
    pub fn numbering_agrees(&self) -> bool {
        matches!(self, Self::Initial)
    }
}

/// Classifies the target of `/proc/self/ns/pid` (or why it was unreadable).
///
/// The link text is `pid:[<inode>]`. Anything else is not a PID namespace
/// link and reads as unknown: a `stat` that silently resolved elsewhere (a
/// denied magic link can stat as a procfs inode) must never pass for a
/// namespace inode, so the link text is the evidence, not a bare inode.
pub fn classify(link: std::io::Result<String>) -> ObserverPidNs {
    let link = match link {
        Ok(link) => link,
        Err(error) => return ObserverPidNs::Unknown(format!("/proc/self/ns/pid: {error}")),
    };
    match parse_pid_ns_link(&link) {
        Some(INIT_PID_NS_INODE) => ObserverPidNs::Initial,
        Some(_) => ObserverPidNs::Nested,
        None => ObserverPidNs::Unknown(format!(
            "/proc/self/ns/pid: unexpected link {:?}",
            crate::render::escape_controls(&link)
        )),
    }
}

/// `pid:[4026531836]` → `4026531836`; any other shape → `None`.
fn parse_pid_ns_link(link: &str) -> Option<u64> {
    let digits = link.strip_prefix("pid:[")?.strip_suffix(']')?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Reads this process's PID namespace link. `/proc/self` always names the
/// reading task, whichever procfs instance serves it.
fn read_own_pidns_link() -> std::io::Result<String> {
    std::fs::read_link("/proc/self/ns/pid").map(|link| link.to_string_lossy().into_owned())
}

/// This observer's PID namespace. A task's own PID namespace never changes
/// (`setns`/`unshare` of `CLONE_NEWPID` move only its future children), so
/// one read serves the whole process.
pub fn observer() -> &'static ObserverPidNs {
    static OBSERVER: OnceLock<ObserverPidNs> = OnceLock::new();
    OBSERVER.get_or_init(|| classify(read_own_pidns_link()))
}

/// Whether the mounted `/proc` numbers processes the way this observer
/// does. The observer's own namespace is not enough: `nsenter -m` without
/// `-p` keeps an initial-namespace observer but serves a container's
/// `/proc`, and `unshare --pid` without `--mount-proc` serves the host's
/// `/proc` to a nested observer. Every `--pid`, `run` child and discovery
/// view is read through `/proc`, so its instance must be this namespace's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcView {
    /// `/proc/self` is `getpid()` and `/proc/<getpid()>` is this process,
    /// numbered by this namespace alone (`NSpid` is exactly `getpid()`).
    Own,
    /// Anything else, with the evidence. Never treated as `Own`.
    Foreign(String),
}

impl ProcView {
    /// The published label (`pid_namespace.proc_pids`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Own => "observer",
            Self::Foreign(_) => "foreign",
        }
    }
}

/// Classifies the mounted `/proc` from `getpid()`, `readlink /proc/self`,
/// and `/proc/<getpid()>/status`. `/proc/self` resolves in the procfs
/// instance's own namespace (ENOENT where this process is invisible), and
/// `NSpid` lists this process's PIDs from that namespace down to its own:
/// one entry equal to `getpid()` is the only shape of a `/proc` mounted for
/// this observer's namespace.
pub fn classify_proc_view(
    own_pid: u32,
    self_link: std::io::Result<String>,
    status: std::io::Result<String>,
) -> ProcView {
    let own = own_pid.to_string();
    match self_link {
        Err(error) => return ProcView::Foreign(format!("/proc/self: {error}")),
        Ok(link) if link != own => {
            return ProcView::Foreign(format!(
                "/proc/self names pid {:?}, this process is {own}",
                crate::render::escape_controls(&link)
            ));
        }
        Ok(_) => {}
    }
    let status = match status {
        Ok(status) => status,
        Err(error) => return ProcView::Foreign(format!("/proc/{own}/status: {error}")),
    };
    let Some(nspid) = status.lines().find_map(|line| line.strip_prefix("NSpid:")) else {
        return ProcView::Foreign(format!("/proc/{own}/status has no NSpid line"));
    };
    let fields: Vec<&str> = nspid.split_whitespace().collect();
    if fields != [own.as_str()] {
        return ProcView::Foreign(format!(
            "/proc/{own}/status NSpid is {:?}, not this namespace's {own} alone",
            fields.join(" ")
        ));
    }
    ProcView::Own
}

fn read_proc_view() -> ProcView {
    let own_pid = std::process::id();
    classify_proc_view(
        own_pid,
        std::fs::read_link("/proc/self").map(|link| link.to_string_lossy().into_owned()),
        std::fs::read_to_string(format!("/proc/{own_pid}/status")),
    )
}

/// Both halves of "are `/proc` PIDs the kernel's PIDs": the observer's own
/// PID namespace, and the namespace the mounted `/proc` numbers in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidNumbering {
    pub observer: ObserverPidNs,
    pub proc_view: ProcView,
}

impl PidNumbering {
    /// The one agreeing shape: initial observer, its own `/proc`.
    pub fn agreeing() -> Self {
        Self {
            observer: ObserverPidNs::Initial,
            proc_view: ProcView::Own,
        }
    }

    /// Whether `/proc` PIDs are proven to be the kernel's PIDs.
    pub fn agrees(&self) -> bool {
        self.observer.numbering_agrees() && self.proc_view == ProcView::Own
    }
}

/// This process's numbering, read once: neither half changes under a
/// running process (a remount of `/proc` mid-run is out of scope).
pub fn numbering() -> &'static PidNumbering {
    static NUMBERING: OnceLock<PidNumbering> = OnceLock::new();
    NUMBERING.get_or_init(|| PidNumbering {
        observer: observer().clone(),
        proc_view: read_proc_view(),
    })
}

/// Refuses a PID-scoped capture unless `/proc` PIDs are proven to be the
/// kernel's PIDs. `what` names the operator's request (`--pid 42`, `run`,
/// `inventory --pid 42`). The kernel-side scope filter keys on initial-
/// namespace tgids; any other numbering would capture nothing.
pub fn require_numbering_agrees(numbering: &PidNumbering, what: &str) -> Result<()> {
    let situation = match (&numbering.observer, &numbering.proc_view) {
        (ObserverPidNs::Initial, ProcView::Own) => return Ok(()),
        // A foreign /proc also hides `/proc/self/ns/pid` (an initial
        // observer is invisible in any other namespace's procfs), so it is
        // the root cause whenever the observer is not known to be nested.
        (ObserverPidNs::Initial | ObserverPidNs::Unknown(_), ProcView::Foreign(why)) => format!(
            "the mounted /proc does not number processes in this observer's PID namespace \
             ({why}; for example `nsenter -m` without `-p`)"
        ),
        (ObserverPidNs::Nested, _) => "this observer runs in a nested PID namespace (a kind/k3d \
                                       node, or a container without the host PID namespace)"
            .to_string(),
        (ObserverPidNs::Unknown(why), ProcView::Own) => {
            format!("this observer could not prove it runs in the initial PID namespace ({why})")
        }
    };
    Err(anyhow!(
        "{MISMATCH_CODE}: refusing {what}: {situation}, but the kernel-side PID filter matches \
         initial-namespace PIDs, so this PID-scoped capture would count nothing. Run p11scope \
         in the host's initial PID namespace with its own /proc (Kubernetes: hostPID on a real \
         node; docker: --pid=host; nsenter: -p with -m), or use --cgroup, whose filter does \
         not depend on PID numbering"
    ))
}

/// `pid_namespace` in capture evidence and the inventory and inspect
/// documents: which namespace numbers which PIDs, so a reader never has to
/// guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PidNamespaceEvidence {
    /// `initial`, `nested`, or `unknown`: the observer's PID namespace.
    pub observer: &'static str,
    /// PIDs the kernel reports (trace `pid`/`tid`): always the initial
    /// namespace's numbering.
    pub kernel_pids: &'static str,
    /// PIDs read from `/proc` (`--pid`, `run`'s child, inventory callers,
    /// discovery subjects): `observer` when the mounted `/proc` numbers in
    /// the observer's own namespace, `foreign` when it does not. Equal to
    /// `kernel_pids` only when `observer` is `initial` and this is `observer`.
    pub proc_pids: &'static str,
}

impl PidNamespaceEvidence {
    pub fn of(numbering: &PidNumbering) -> Self {
        Self {
            observer: numbering.observer.label(),
            kernel_pids: "initial",
            proc_pids: numbering.proc_view.label(),
        }
    }

    /// Whether the observer runs in the initial PID namespace (cause
    /// `pid_namespace` otherwise).
    pub fn observer_is_initial(&self) -> bool {
        self.observer == "initial"
    }

    /// Whether the mounted `/proc` is the observer's own (cause
    /// `proc_namespace_mismatch` otherwise).
    pub fn proc_is_own(&self) -> bool {
        self.proc_pids == "observer"
    }

    /// Whether `/proc` and kernel PIDs are proven to be the same numbering.
    /// When they are not, BPF-reported PIDs cannot be resolved through
    /// `/proc`, so live discovery keyed on them is unproven.
    pub fn numbering_agrees(&self) -> bool {
        self.observer_is_initial() && self.proc_is_own()
    }
}

/// One stderr line for a capture whose `/proc` PIDs are not the kernel's.
pub fn nested_warning(numbering: &PidNumbering) -> Option<String> {
    (!numbering.agrees()).then(|| {
        format!(
            "p11scope: WARNING: this observer's PID namespace is {} and its /proc numbers \
             processes as {}: the kernel reports initial-namespace PIDs (trace pid/tid), not \
             the PIDs this /proc shows, and live discovery cannot resolve them; the output names \
             both numberings (pid_namespace) and a capture's observation is never exact here",
            numbering.observer.label(),
            numbering.proc_view.label()
        )
    })
}

/// The scope-level gap a document without an `exact` flag (inventory)
/// carries when `/proc` PIDs are not the kernel's: subject and reason.
pub fn numbering_gap(numbering: &PidNumbering) -> Option<(&'static str, String)> {
    (!numbering.agrees()).then(|| {
        (
            "pid namespace",
            format!(
                "observer PID namespace {}, /proc numbering {}: kernel-reported PIDs cannot be \
                 resolved through /proc, so callers that load a module after a scan pass can be \
                 missed (pid_namespace)",
                numbering.observer.label(),
                numbering.proc_view.label()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(observer: ObserverPidNs) -> PidNumbering {
        PidNumbering {
            observer,
            proc_view: ProcView::Own,
        }
    }

    fn foreign_proc() -> PidNumbering {
        PidNumbering {
            observer: ObserverPidNs::Initial,
            proc_view: ProcView::Foreign("/proc/self: No such file or directory".into()),
        }
    }

    #[test]
    fn the_initial_inode_is_the_kernel_abi_constant() {
        // include/linux/proc_ns.h: PROC_PID_INIT_INO = 0xEFFFFFFCU.
        assert_eq!(INIT_PID_NS_INODE, 4_026_531_836);
    }

    fn link(inode: u64) -> std::io::Result<String> {
        Ok(format!("pid:[{inode}]"))
    }

    #[test]
    fn only_the_initial_inode_classifies_initial() {
        assert_eq!(classify(link(INIT_PID_NS_INODE)), ObserverPidNs::Initial);
        for inode in [
            0,
            1,
            INIT_PID_NS_INODE - 1,
            INIT_PID_NS_INODE + 1,
            4_026_532_196,
            u64::MAX,
        ] {
            assert_eq!(classify(link(inode)), ObserverPidNs::Nested, "{inode}");
        }
    }

    #[test]
    fn an_unreadable_namespace_is_unknown_never_initial() {
        let error = std::io::Error::from_raw_os_error(libc::EACCES);
        let observed = classify(Err(error));
        assert!(
            matches!(&observed, ObserverPidNs::Unknown(why) if why.contains("/proc/self/ns/pid"))
        );
        assert!(!observed.numbering_agrees());
        assert_eq!(observed.label(), "unknown");
    }

    /// Only the exact `pid:[<decimal>]` shape is a PID namespace; another
    /// namespace type, a bare inode, or a padded/garbled form is unknown,
    /// even when it carries the initial inode.
    #[test]
    fn a_link_that_is_not_a_pid_namespace_is_unknown() {
        for text in [
            "",
            "4026531836",
            "net:[4026531836]",
            "pid_for_children:[4026531836]",
            "pid:[]",
            "pid:[4026531836",
            "pid:4026531836]",
            "pid:[ 4026531836]",
            "pid:[4026531836] ",
            "pid:[+4026531836]",
            "pid:[0x4026531836]",
            "pid:[18446744073709551616]",
            "pid:[4026531836]\n",
        ] {
            let observed = classify(Ok(text.to_string()));
            assert!(
                matches!(&observed, ObserverPidNs::Unknown(why) if why.contains("unexpected link")),
                "{text:?} -> {observed:?}"
            );
        }
    }

    #[test]
    fn labels_are_the_published_closed_set() {
        assert_eq!(ObserverPidNs::Initial.label(), "initial");
        assert_eq!(ObserverPidNs::Nested.label(), "nested");
        assert_eq!(ObserverPidNs::Unknown(String::new()).label(), "unknown");
        assert!(ObserverPidNs::Initial.numbering_agrees());
        assert!(!ObserverPidNs::Nested.numbering_agrees());
    }

    #[test]
    fn pid_scope_is_allowed_only_in_the_initial_namespace() {
        assert!(require_numbering_agrees(&with(ObserverPidNs::Initial), "--pid 7").is_ok());
        for observed in [
            ObserverPidNs::Nested,
            ObserverPidNs::Unknown("/proc/self/ns/pid: gone".into()),
        ] {
            let error = require_numbering_agrees(&with(observed), "--pid 7")
                .expect_err("a PID scope outside the initial namespace is refused");
            let text = format!("{error:#}");
            assert!(
                text.starts_with("pid-namespace-mismatch: refusing --pid 7: "),
                "{text}"
            );
            assert!(text.contains("--cgroup"), "{text}");
            assert!(text.contains("initial PID namespace"), "{text}");
        }
        let unknown = require_numbering_agrees(
            &with(ObserverPidNs::Unknown("/proc/self/ns/pid: gone".into())),
            "run",
        )
        .unwrap_err();
        assert!(format!("{unknown:#}").contains("(/proc/self/ns/pid: gone)"));
    }

    #[test]
    fn evidence_names_both_numberings() {
        let nested = PidNamespaceEvidence::of(&with(ObserverPidNs::Nested));
        assert_eq!(
            serde_json::to_value(nested).unwrap(),
            serde_json::json!({"observer": "nested", "kernel_pids": "initial", "proc_pids": "observer"})
        );
        assert!(!nested.numbering_agrees());
        assert!(PidNamespaceEvidence::of(&with(ObserverPidNs::Initial)).numbering_agrees());
        assert!(
            !PidNamespaceEvidence::of(&with(ObserverPidNs::Unknown(String::new())))
                .numbering_agrees()
        );
    }

    #[test]
    fn only_a_mismatched_observer_warns() {
        assert_eq!(nested_warning(&with(ObserverPidNs::Initial)), None);
        let warning = nested_warning(&with(ObserverPidNs::Nested)).unwrap();
        assert!(warning.contains("PID namespace is nested"), "{warning}");
        assert!(warning.contains("pid_namespace"), "{warning}");
        assert!(nested_warning(&with(ObserverPidNs::Unknown("x".into()))).is_some());
        assert!(
            nested_warning(&foreign_proc())
                .unwrap()
                .contains("/proc numbers processes as foreign")
        );
    }

    fn status(nspid: &str) -> std::io::Result<String> {
        Ok(format!(
            "Name:\tp11scope\nTgid:\t42\nPid:\t42\nNSpid:{nspid}\n"
        ))
    }

    /// M1 (review): `/proc` must be this namespace's own instance. Only
    /// `/proc/self` = `getpid()` with `NSpid` exactly `getpid()` is own.
    #[test]
    fn only_this_namespaces_own_proc_classifies_own() {
        let own = |link: &str, nspid: &str| classify_proc_view(42, Ok(link.into()), status(nspid));
        assert_eq!(own("42", "\t42"), ProcView::Own);
        assert_eq!(own("42", " 42 "), ProcView::Own);
        for (link, nspid, why) in [
            // nsenter -m without -p: our PID in a container's /proc names
            // some other process; /proc/self resolves elsewhere or nowhere.
            ("7", "\t7", "/proc/self names pid"),
            // unshare --pid without --mount-proc: the host's /proc numbers
            // us from an ancestor namespace.
            ("42", "\t3026492\t42", "NSpid is"),
            ("42", "\t42\t1", "NSpid is"),
            ("42", "\t43", "NSpid is"),
            ("42", "", "NSpid is"),
            ("042", "\t42", "/proc/self names pid"),
            ("", "\t42", "/proc/self names pid"),
        ] {
            let view = own(link, nspid);
            assert!(
                matches!(&view, ProcView::Foreign(text) if text.contains(why)),
                "{link:?}/{nspid:?} -> {view:?}"
            );
        }
        let missing = classify_proc_view(
            42,
            Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            status("\t42"),
        );
        assert!(matches!(&missing, ProcView::Foreign(text) if text.starts_with("/proc/self:")));
        let gone = classify_proc_view(
            42,
            Ok("42".into()),
            Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
        );
        assert!(matches!(&gone, ProcView::Foreign(text) if text.starts_with("/proc/42/status:")));
        let no_nspid = classify_proc_view(42, Ok("42".into()), Ok("Name:\tx\nPid:\t42\n".into()));
        assert!(matches!(&no_nspid, ProcView::Foreign(text) if text.contains("no NSpid")));
        assert_eq!(ProcView::Own.label(), "observer");
        assert_eq!(ProcView::Foreign(String::new()).label(), "foreign");
    }

    /// A foreign `/proc` under an initial observer is a mismatch: refused
    /// for a PID scope by name, never agreeing, published as `foreign`, and
    /// a scope-level inventory gap.
    #[test]
    fn a_foreign_proc_under_an_initial_observer_is_a_mismatch() {
        let numbering = foreign_proc();
        assert!(!numbering.agrees());
        assert!(PidNumbering::agreeing().agrees());
        let error = require_numbering_agrees(&numbering, "--pid 7").unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.starts_with("pid-namespace-mismatch: refusing --pid 7: the mounted /proc"),
            "{text}"
        );
        assert!(text.contains("nsenter -m"), "{text}");
        // nsenter -m without -p, measured: /proc/self/ns/pid is ENOENT too,
        // so the observer reads unknown; the message still names /proc.
        let both = PidNumbering {
            observer: ObserverPidNs::Unknown("/proc/self/ns/pid: ENOENT".into()),
            proc_view: ProcView::Foreign("/proc/self: ENOENT".into()),
        };
        let text = format!(
            "{:#}",
            require_numbering_agrees(&both, "--pid 7").unwrap_err()
        );
        assert!(
            text.contains("refusing --pid 7: the mounted /proc"),
            "{text}"
        );
        let evidence = PidNamespaceEvidence::of(&numbering);
        assert_eq!(
            serde_json::to_value(evidence).unwrap(),
            serde_json::json!({"observer": "initial", "kernel_pids": "initial", "proc_pids": "foreign"})
        );
        assert!(evidence.observer_is_initial());
        assert!(!evidence.proc_is_own());
        assert!(!evidence.numbering_agrees());
        assert_eq!(numbering_gap(&PidNumbering::agreeing()), None);
        let (subject, reason) = numbering_gap(&numbering).unwrap();
        assert_eq!(subject, "pid namespace");
        assert!(reason.contains("/proc numbering foreign"), "{reason}");
        assert!(numbering_gap(&with(ObserverPidNs::Nested)).is_some());
    }

    /// The live read: the test runner's own link is a PID namespace link,
    /// and, where PID 1's link is readable (root), it is the same namespace.
    #[test]
    fn the_live_read_is_a_pid_namespace_link() {
        let ours = read_own_pidns_link().expect("own pid namespace link is readable");
        assert!(parse_pid_ns_link(&ours).is_some(), "{ours}");
        assert_eq!(observer(), &classify(Ok(ours.clone())));
        // The test runner reads its own /proc (no nsenter -m, no stale mount).
        assert_eq!(read_proc_view(), ProcView::Own);
        // Unprivileged, the denied magic link reads back as an empty string
        // on 7.0 (measured), which is exactly why only a parsed link counts.
        if let Ok(init) = std::fs::read_link("/proc/1/ns/pid")
            && parse_pid_ns_link(&init.to_string_lossy()).is_some()
        {
            assert_eq!(
                ours,
                init.to_string_lossy(),
                "/proc/1 shares this namespace"
            );
        }
    }
}
