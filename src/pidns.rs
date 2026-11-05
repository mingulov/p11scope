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

use anyhow::Result;
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
    /// `/proc` serves this process under other numbers, with the evidence.
    /// Never treated as `Own`.
    Foreign(String),
    /// `/proc` has no entry for this process at all (`/proc/self` does not
    /// resolve: `nsenter -m` without `-p`), with the evidence. Published as
    /// `foreign` too; unlike `Foreign`, no capture can run here, because the
    /// observer cannot read its own `/proc/self` (DR-RETRO-PIDNS-2).
    Unserved(String),
}

impl ProcView {
    /// The published label (`pid_namespace.proc_pids`).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Own => "observer",
            Self::Foreign(_) | Self::Unserved(_) => "foreign",
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
        Err(error) => return ProcView::Unserved(format!("/proc/self: {error}")),
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

/// The view of the procfs mounted at `proc_root` (normally `/proc`).
fn read_proc_view_at(proc_root: &std::path::Path) -> ProcView {
    let own_pid = std::process::id();
    classify_proc_view(
        own_pid,
        std::fs::read_link(proc_root.join("self")).map(|link| link.to_string_lossy().into_owned()),
        std::fs::read_to_string(proc_root.join(own_pid.to_string()).join("status")),
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
    #[cfg(test)]
    if let Some(injected) = test_seam::injected() {
        return injected;
    }
    static NUMBERING: OnceLock<PidNumbering> = OnceLock::new();
    NUMBERING.get_or_init(|| numbering_from(observer().clone(), std::path::Path::new("/proc")))
}

/// Both halves composed: `observer`, and the view of the procfs mounted at
/// `proc_root`. Neither half alone decides agreement.
fn numbering_from(observer: ObserverPidNs, proc_root: &std::path::Path) -> PidNumbering {
    PidNumbering {
        observer,
        proc_view: read_proc_view_at(proc_root),
    }
}

/// DR-RETRO-PIDNS-1: unprivileged tests drive every [`numbering`] call
/// site with a mismatched numbering. The injection is per thread, so a
/// test sees it on its own thread only and no other test is affected.
#[cfg(test)]
pub(crate) mod test_seam {
    use super::PidNumbering;
    use std::cell::Cell;

    thread_local! {
        static INJECTED: Cell<Option<&'static PidNumbering>> = const { Cell::new(None) };
    }

    pub(super) fn injected() -> Option<&'static PidNumbering> {
        INJECTED.with(Cell::get)
    }

    /// Runs `body` with [`super::numbering`] answering `numbering` on this
    /// thread, restoring the real answer afterwards (also on a panic).
    pub(crate) fn with_numbering<R>(numbering: PidNumbering, body: impl FnOnce() -> R) -> R {
        struct Restore(Option<&'static PidNumbering>);
        impl Drop for Restore {
            fn drop(&mut self) {
                INJECTED.with(|cell| cell.set(self.0));
            }
        }
        let leaked: &'static PidNumbering = Box::leak(Box::new(numbering));
        let _restore = Restore(INJECTED.with(|cell| cell.replace(Some(leaked))));
        body()
    }

    /// An observer in a nested PID namespace with its own `/proc`.
    pub(crate) fn nested() -> PidNumbering {
        PidNumbering {
            observer: super::ObserverPidNs::Nested,
            proc_view: super::ProcView::Own,
        }
    }
}

/// Cgroup userspace discovery and native identity share initial task numbering.
/// This refusal cannot recommend cgroup scope as a namespace workaround.
pub(crate) fn require_inventory_cgroup_numbering(numbering: &PidNumbering) -> Result<()> {
    if numbering.agrees() {
        return Ok(());
    }
    Err(anyhow::Error::new(NumberingMismatch(format!(
        "{MISMATCH_CODE}: refusing cgroup inventory: userspace discovery and native image \
         identity require the initial PID namespace and matching procfs; observer is {}, \
         procfs numbering is {}. Run with the initial task numbering and its matching /proc",
        numbering.observer.label(),
        numbering.proc_view.label(),
    ))))
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
        (
            ObserverPidNs::Initial | ObserverPidNs::Unknown(_),
            ProcView::Foreign(why) | ProcView::Unserved(why),
        ) => format!(
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
    Err(anyhow::Error::new(NumberingMismatch(format!(
        "{MISMATCH_CODE}: refusing {what}: {situation}, but the kernel-side PID filter matches \
         initial-namespace PIDs, so this PID-scoped capture would count nothing. Run p11scope \
         in the host's initial PID namespace with its own /proc (Kubernetes: hostPID on a real \
         node; docker: --pid=host; nsenter: -p with -m), or use --cgroup, whose filter does \
         not depend on PID numbering"
    ))))
}

/// Refuses every capture when the mounted `/proc` has no entry for this
/// process ([`ProcView::Unserved`]). `what` names the request. The observer
/// reads its own `/proc/self` (the uretprobe self-probe, a trace `-o` link)
/// and resolves every discovered process through `/proc`, so no scope can
/// run honestly there, and a later failure would blame something else.
pub fn require_self_served(numbering: &PidNumbering, what: &str) -> Result<()> {
    let ProcView::Unserved(why) = &numbering.proc_view else {
        return Ok(());
    };
    Err(anyhow::Error::new(NumberingMismatch(format!(
        "{MISMATCH_CODE}: refusing {what}: the mounted /proc has no entry for this observer \
         ({why}; for example `nsenter -m` without `-p`), so p11scope cannot read its own \
         /proc/self (the uretprobe self-probe, trace -o) or resolve the processes it \
         discovers. Mount a procfs of this observer's PID namespace (nsenter: -p with -m), or \
         run p11scope in the host's initial PID namespace with its own /proc"
    ))))
}

/// A `pid-namespace-mismatch` refusal. Typed so a caller that adds its own
/// context to other failures can leave this already-complete line alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumberingMismatch(String);

impl std::fmt::Display for NumberingMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for NumberingMismatch {}

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
             the PIDs this /proc shows, and live discovery cannot resolve them; processes \
             outside the PID namespace this /proc shows (the host's, for a nested observer) are \
             invisible to its scan, so a provider only they map is never discovered. The output \
             names both numberings (pid_namespace): a capture is never exact here, and an \
             inventory carries a pid namespace gap",
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
                "observer PID namespace {}, /proc numbering {}: processes outside the PID \
                 namespace this /proc shows (the host's, for a nested observer) are invisible to \
                 the /proc scan, so a module only they map is never discovered, and \
                 kernel-reported PIDs cannot be resolved through /proc, so callers that load a \
                 module after a scan pass can be missed (pid_namespace)",
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
        // DR-RETRO-PIDNS-2 (review 4): the blind spot is stated whole, and
        // the warning does not promise inventory an `exact` it never has.
        assert!(
            warning.contains("host's, for a nested observer) are invisible"),
            "{warning}"
        );
        assert!(
            warning.contains("an inventory carries a pid namespace gap"),
            "{warning}"
        );
        assert!(
            !warning.contains("a capture's observation is never exact"),
            "{warning}"
        );
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
        assert!(matches!(&missing, ProcView::Unserved(text) if text.starts_with("/proc/self:")));
        assert_eq!(missing.label(), "foreign");
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
        let (_, nested_reason) = numbering_gap(&with(ObserverPidNs::Nested)).unwrap();
        assert!(
            nested_reason
                .contains("(the host's, for a nested observer) are invisible to the /proc scan"),
            "{nested_reason}"
        );
        assert!(
            nested_reason.contains("never discovered"),
            "{nested_reason}"
        );
    }

    /// DR-RETRO-PIDNS-2: a `/proc` with no entry for this observer refuses
    /// every scope by name; a foreign but serving `/proc` refuses none here.
    #[test]
    fn an_unserved_proc_refuses_every_capture_by_name() {
        let unserved = PidNumbering {
            observer: ObserverPidNs::Unknown("/proc/self/ns/pid: ENOENT".into()),
            proc_view: ProcView::Unserved("/proc/self: ENOENT".into()),
        };
        let error = require_self_served(&unserved, "a --system capture").unwrap_err();
        assert!(error.is::<NumberingMismatch>());
        let text = format!("{error:#}");
        assert!(
            text.starts_with(
                "pid-namespace-mismatch: refusing a --system capture: the mounted /proc has no \
                 entry for this observer (/proc/self: ENOENT;"
            ),
            "{text}"
        );
        assert!(text.contains("uretprobe self-probe"), "{text}");
        assert!(!text.contains("--allow-uretprobe"), "{text}");
        assert!(!unserved.agrees());
        assert!(require_self_served(&foreign_proc(), "a --system capture").is_ok());
        assert!(require_self_served(&PidNumbering::agreeing(), "a --system capture").is_ok());
        assert!(require_self_served(&with(ObserverPidNs::Nested), "a --system capture").is_ok());
        // A PID scope names the /proc mismatch either way.
        let text = format!(
            "{:#}",
            require_numbering_agrees(&unserved, "--pid 7").unwrap_err()
        );
        assert!(
            text.contains("refusing --pid 7: the mounted /proc"),
            "{text}"
        );
    }

    /// DR-RETRO-PIDNS-1 (review P5): the composed numbering reads the
    /// mounted procfs; a `/proc` that numbers this process elsewhere makes
    /// it foreign even under an initial observer.
    #[test]
    fn the_numbering_composes_the_mounted_procs_view() {
        let own = std::process::id().to_string();
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(&own, root.path().join("self")).unwrap();
        std::fs::create_dir(root.path().join(&own)).unwrap();
        std::fs::write(
            root.path().join(&own).join("status"),
            format!("Name:\tp11scope\nNSpid:\t{own}\n"),
        )
        .unwrap();
        assert!(numbering_from(ObserverPidNs::Initial, root.path()).agrees());
        // The host's /proc under `unshare --pid` without `--mount-proc`.
        std::fs::write(
            root.path().join(&own).join("status"),
            format!("Name:\tp11scope\nNSpid:\t3026492\t{own}\n"),
        )
        .unwrap();
        let foreign = numbering_from(ObserverPidNs::Initial, root.path());
        assert!(matches!(&foreign.proc_view, ProcView::Foreign(why) if why.contains("NSpid")));
        assert!(!foreign.agrees());
        // A procfs with no entry for this process.
        let empty = tempfile::tempdir().unwrap();
        let unserved = numbering_from(ObserverPidNs::Initial, empty.path());
        assert!(matches!(&unserved.proc_view, ProcView::Unserved(_)));
        // `numbering()` is that composition over the real mount.
        let source = include_str!("pidns.rs");
        let body = source
            .split_once("pub fn numbering() -> &'static PidNumbering {")
            .unwrap()
            .1
            .split_once("\n}\n")
            .unwrap()
            .0;
        assert!(
            body.contains(
                "NUMBERING.get_or_init(|| numbering_from(observer().clone(), std::path::Path::new(\"/proc\")))"
            ),
            "{body}"
        );
        assert_eq!(
            numbering(),
            &numbering_from(observer().clone(), std::path::Path::new("/proc"))
        );
    }

    /// The seam is per thread and restores the real answer.
    #[test]
    fn the_test_seam_injects_on_this_thread_only() {
        let real = numbering().clone();
        test_seam::with_numbering(test_seam::nested(), || {
            assert_eq!(numbering(), &test_seam::nested());
            let other = real.clone();
            std::thread::spawn(move || assert_eq!(numbering(), &other))
                .join()
                .unwrap();
        });
        assert_eq!(numbering(), &real);
    }

    /// The live read: the test runner's own link is a PID namespace link,
    /// and, where PID 1's link is readable (root), it is the same namespace.
    #[test]
    fn the_live_read_is_a_pid_namespace_link() {
        let ours = read_own_pidns_link().expect("own pid namespace link is readable");
        assert!(parse_pid_ns_link(&ours).is_some(), "{ours}");
        assert_eq!(observer(), &classify(Ok(ours.clone())));
        // The test runner reads its own /proc (no nsenter -m, no stale mount).
        assert_eq!(
            read_proc_view_at(std::path::Path::new("/proc")),
            ProcView::Own
        );
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
