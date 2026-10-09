//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private scan-local executable receipts; no event naming authority.

use crate::discovery::caller_registry::{ExeIdentity, read_exe_identity};
use crate::process::{ProcessView, process_start_time};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedInspectApplication {
    exe: ExeIdentity,
    start_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InspectIdentityUnknown {
    Unavailable,
    Changed,
    Lost,
    NotExamined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InspectApplicationResult {
    Observed(ValidatedInspectApplication),
    Unknown(InspectIdentityUnknown),
}

pub(crate) trait InspectImageReader {
    fn exe_identity(&mut self) -> Option<ExeIdentity>;
    fn start_time(&mut self) -> Option<u64>;
    fn still_same(&mut self) -> bool;
    fn validate_generation(&mut self) -> Result<(), InspectIdentityUnknown> {
        if self.still_same() {
            Ok(())
        } else {
            Err(InspectIdentityUnknown::Lost)
        }
    }
}

pub(crate) struct ProcessViewImageReader<'a> {
    view: &'a ProcessView,
}

impl<'a> ProcessViewImageReader<'a> {
    pub(crate) fn new(view: &'a ProcessView) -> Self {
        Self { view }
    }
    pub(crate) fn view(&self) -> &'a ProcessView {
        self.view
    }

    // Only birth reads are injectable; liveness always uses this original view.
    // Missing evidence cannot name an image or masquerade as a lost generation.
    fn validate_generation_with(
        &mut self,
        retained: impl FnOnce(&ProcessView) -> Option<u64>,
        fresh: impl FnOnce(u32) -> Option<u64>,
    ) -> Result<(), InspectIdentityUnknown> {
        if !self.view.still_the_same() {
            return Err(InspectIdentityUnknown::Lost);
        }
        let retained = retained(self.view);
        let fresh = fresh(self.view.pid());
        // Loss takes precedence even when a read also became unavailable.
        if !self.view.still_the_same() {
            return Err(InspectIdentityUnknown::Lost);
        }
        match (retained, fresh) {
            (Some(retained), Some(fresh)) if retained == fresh => Ok(()),
            (Some(_), Some(_)) => Err(InspectIdentityUnknown::Lost),
            _ => Err(InspectIdentityUnknown::Unavailable),
        }
    }
}

impl InspectImageReader for ProcessViewImageReader<'_> {
    fn exe_identity(&mut self) -> Option<ExeIdentity> {
        read_exe_identity(self.view.pid())
    }
    fn start_time(&mut self) -> Option<u64> {
        // ProcessView::start_time is cached admission identity, not a sample.
        process_start_time(self.view.pid()).ok()
    }
    fn still_same(&mut self) -> bool {
        self.validate_generation().is_ok()
    }
    fn validate_generation(&mut self) -> Result<(), InspectIdentityUnknown> {
        self.validate_generation_with(|view| view.start_time(), |pid| process_start_time(pid).ok())
    }
}

/// An initial sample is pending until scan AND provider pinning have finished.
/// No constructor is available outside this producer module.
pub(crate) struct PendingInspectApplication {
    sample: Result<(ExeIdentity, u64), InspectIdentityUnknown>,
}

fn sample_application(
    reader: &mut impl InspectImageReader,
) -> Result<(ExeIdentity, u64), InspectIdentityUnknown> {
    let exe = reader.exe_identity();
    let start_time = reader.start_time();
    // The OS adapter distinguishes missing birth evidence from a lost generation
    // while validating the original held view before any receipt can be minted.
    reader.validate_generation()?;
    match (exe, start_time) {
        (Some(exe), Some(start_time))
            if exe.path.as_deref().is_some_and(|path| !path.is_empty()) =>
        {
            Ok((exe, start_time))
        }
        _ => Err(InspectIdentityUnknown::Unavailable),
    }
}

pub(crate) fn begin_application(reader: &mut impl InspectImageReader) -> PendingInspectApplication {
    PendingInspectApplication {
        sample: sample_application(reader),
    }
}

/// Separate producer authority: the sweep confirmation already bracketed its
/// maps and physical proof reads with matching executable samples and a held pin.
/// Raw deep-scan generation metadata cannot enter this adapter.
pub(crate) fn application_from_confirmed_member(
    member: &crate::discovery::sweep_attribution::SweptMember,
) -> InspectApplicationResult {
    if !member
        .exe
        .path
        .as_deref()
        .is_some_and(|path| !path.is_empty())
    {
        return InspectApplicationResult::Unknown(InspectIdentityUnknown::Unavailable);
    }
    InspectApplicationResult::Observed(ValidatedInspectApplication {
        exe: member.exe.clone(),
        start_time: member.start_time,
    })
}

pub(crate) fn finish_application(
    pending: PendingInspectApplication,
    reader: &mut impl InspectImageReader,
) -> InspectApplicationResult {
    let (before, start_time) = match pending.sample {
        Ok(sample) => sample,
        // A later readable image cannot repair a missing initial sample.
        Err(reason) => return InspectApplicationResult::Unknown(reason),
    };
    match sample_application(reader) {
        Ok((after, end_time)) if before == after && start_time == end_time => {
            InspectApplicationResult::Observed(ValidatedInspectApplication {
                exe: before,
                start_time,
            })
        }
        Ok(_) => InspectApplicationResult::Unknown(InspectIdentityUnknown::Changed),
        Err(reason) => InspectApplicationResult::Unknown(reason),
    }
}

impl InspectIdentityUnknown {
    const fn status(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Changed => "changed",
            Self::Lost => "lost",
            Self::NotExamined => "not_examined",
        }
    }
}

pub(crate) fn application_label(result: &InspectApplicationResult, pid: u32) -> String {
    if let InspectApplicationResult::Observed(application) = result
        && let Some(path) = application.exe.path.as_deref()
    {
        let basename = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path);
        return format!("{} (PID {pid})", crate::render::escape_controls(basename));
    }
    format!("Unknown executable (PID {pid})")
}

/// Pure detail for the same receipt as the label; no process or file lookup.
pub(crate) fn application_detail(result: &InspectApplicationResult) -> Option<String> {
    let InspectApplicationResult::Observed(application) = result else {
        return None;
    };
    let exe = &application.exe;
    let path = exe.path.as_deref()?;
    Some(format!(
        "  executable  {}\n  image       dev {} ino {} mtime {}.{:09} start-time {}\n",
        crate::render::escape_controls(path),
        exe.dev,
        exe.ino,
        exe.mtime_secs,
        exe.mtime_nanos,
        application.start_time,
    ))
}

pub(crate) fn application_json(result: &InspectApplicationResult) -> serde_json::Value {
    match result {
        InspectApplicationResult::Observed(application) => serde_json::json!({
            "application": {
                "path": application.exe.path, "dev": application.exe.dev,
                "ino": application.exe.ino, "mtime_secs": application.exe.mtime_secs,
                "mtime_nanos": application.exe.mtime_nanos,
                "start_time": application.start_time, "status": "observed",
            },
            "application_status": "observed",
        }),
        InspectApplicationResult::Unknown(reason) => serde_json::json!({
            "application": null, "application_status": reason.status(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mutations caught: accepting unequal file metadata/path/start-time, naming
    // missing samples, and treating pidfd liveness as executable validation.
    struct Reader {
        exe: Option<ExeIdentity>,
        start: Option<u64>,
        live: bool,
    }
    fn image(path: Option<&str>, ino: u64) -> ExeIdentity {
        ExeIdentity {
            dev: 12,
            ino,
            mtime_secs: 5,
            mtime_nanos: 6,
            path: path.map(str::to_owned),
        }
    }
    impl InspectImageReader for Reader {
        fn exe_identity(&mut self) -> Option<ExeIdentity> {
            self.exe.clone()
        }
        fn start_time(&mut self) -> Option<u64> {
            self.start
        }
        fn still_same(&mut self) -> bool {
            self.live
        }
    }
    fn reader(path: &str) -> Reader {
        Reader {
            exe: Some(image(Some(path), 23)),
            start: Some(100),
            live: true,
        }
    }
    fn complete(reader: &mut Reader) -> InspectApplicationResult {
        let pending = begin_application(reader);
        finish_application(pending, reader)
    }

    #[test]
    fn inspect_identity_is_same_in_text_and_json() {
        let result = complete(&mut reader("/usr/bin/python3"));
        let projected = application_json(&result);
        assert_eq!(projected["application_status"], "observed");
        assert_eq!(
            projected["application"],
            serde_json::json!({
                "path": "/usr/bin/python3", "dev": 12, "ino": 23,
                "mtime_secs": 5, "mtime_nanos": 6, "start_time": 100,
                "status": "observed"
            })
        );
        assert_eq!(application_label(&result, 4242), "python3 (PID 4242)");
    }

    #[test]
    fn inspect_changed_generation_is_unknown() {
        for change in 0..6 {
            let mut r = reader("/usr/bin/app");
            let pending = begin_application(&mut r);
            match change {
                0 => r.exe.as_mut().unwrap().ino += 1,
                1 => r.exe.as_mut().unwrap().dev += 1,
                2 => r.exe.as_mut().unwrap().mtime_secs += 1,
                3 => r.exe.as_mut().unwrap().mtime_nanos += 1,
                4 => r.exe.as_mut().unwrap().path = Some("/usr/bin/successor".into()),
                _ => r.start = Some(101),
            }
            let result = finish_application(pending, &mut r);
            assert_eq!(
                result,
                InspectApplicationResult::Unknown(InspectIdentityUnknown::Changed),
                "change={change}"
            );
            let json = application_json(&result);
            assert!(json["application"].is_null());
            assert_eq!(json["application_status"], "changed");
            assert_eq!(
                application_label(&result, 4242),
                "Unknown executable (PID 4242)"
            );
        }
    }

    #[test]
    fn inspect_identity_unreadable_samples_are_never_repaired() {
        for before in [true, false] {
            for missing in 0..3 {
                let mut r = reader("/bin/app");
                let unavailable = |r: &mut Reader| match missing {
                    0 => r.exe = None,
                    1 => r.exe.as_mut().unwrap().path = None,
                    _ => r.start = None,
                };
                if before {
                    unavailable(&mut r);
                }
                let pending = begin_application(&mut r);
                if before {
                    r = reader("/bin/app");
                } else {
                    unavailable(&mut r);
                }
                let result = finish_application(pending, &mut r);
                assert_eq!(
                    result,
                    InspectApplicationResult::Unknown(InspectIdentityUnknown::Unavailable),
                    "before={before}, missing={missing}"
                );
            }
        }
    }

    #[test]
    fn inspect_identity_lost_pin_withholds_name() {
        for before in [true, false] {
            let mut r = reader("/bin/app");
            if before {
                r.live = false;
            }
            let pending = begin_application(&mut r);
            r.live = before;
            let result = finish_application(pending, &mut r);
            assert_eq!(
                result,
                InspectApplicationResult::Unknown(InspectIdentityUnknown::Lost)
            );
            assert_eq!(application_json(&result)["application_status"], "lost");
        }
    }

    #[test]
    fn inspect_colliding_basenames_stay_separate() {
        let a = complete(&mut reader("/opt/a/app"));
        let mut other = reader("/opt/b/app");
        other.exe.as_mut().unwrap().ino = 99;
        let b = complete(&mut other);
        assert_eq!(application_label(&a, 7), "app (PID 7)");
        assert_eq!(application_label(&b, 8), "app (PID 8)");
        assert_ne!(
            application_json(&a)["application"],
            application_json(&b)["application"]
        );
        assert_eq!(application_json(&a)["application"]["path"], "/opt/a/app");
        assert_eq!(application_json(&b)["application"]["ino"], 99);
    }

    #[test]
    fn inspect_identity_controls_unicode_and_deleted_marker() {
        for (path, label) in [
            ("/opt/工具/python3", "python3 (PID 9)"),
            ("/opt/app (deleted)", "app (deleted) (PID 9)"),
            ("/opt/a\u{1b}[2J\n\rapp", "a\\u{1b}[2J\\n\\rapp (PID 9)"),
        ] {
            let result = complete(&mut reader(path));
            assert_eq!(application_label(&result, 9), label);
            assert_eq!(application_json(&result)["application"]["path"], path);
        }
    }

    #[test]
    fn inspect_identity_same_image_reexec_is_only_a_snapshot() {
        // Equal end samples cannot detect same-image re-exec or A->B->A.
        // This explicitly limits the receipt; it is never an event identity.
        let result = complete(&mut reader("/bin/app"));
        assert_eq!(application_json(&result)["application_status"], "observed");
    }
    struct BirthAdapter<'a> {
        os: ProcessViewImageReader<'a>,
        admission: Option<u64>,
        fresh: Option<u64>,
    }

    impl<'a> BirthAdapter<'a> {
        fn new(view: &'a ProcessView) -> Self {
            Self {
                os: ProcessViewImageReader::new(view),
                admission: view.start_time(),
                fresh: process_start_time(view.pid()).ok(),
            }
        }
        fn observe(&mut self) -> InspectApplicationResult {
            let pending = begin_application(self);
            finish_application(pending, self)
        }
    }

    impl InspectImageReader for BirthAdapter<'_> {
        fn exe_identity(&mut self) -> Option<ExeIdentity> {
            self.os.exe_identity()
        }
        fn start_time(&mut self) -> Option<u64> {
            self.fresh
        }
        fn still_same(&mut self) -> bool {
            self.os.still_same()
        }
        fn validate_generation(&mut self) -> Result<(), InspectIdentityUnknown> {
            let admission = self.admission;
            let fresh = self.fresh;
            self.os.validate_generation_with(|_| admission, |_| fresh)
        }
    }

    fn os_view(pid: u32) -> ProcessView {
        // Fail rather than silently pass a supposed live-pidfd control via fallback.
        let pidfd_canary = crate::process::PidPin::open(pid).unwrap();
        assert!(
            pidfd_canary.pidfd().is_ok(),
            "this lane requires a usable pidfd"
        );
        let view = ProcessView::open(crate::process::ProcessViewId(7), pid).unwrap();
        assert!(view.still_the_same());
        view
    }

    fn assert_os_unknown(
        result: InspectApplicationResult,
        want: InspectIdentityUnknown,
        status: &str,
    ) {
        assert_eq!(result, InspectApplicationResult::Unknown(want));
        let json = application_json(&result);
        assert!(json["application"].is_null());
        assert_eq!(json["application_status"], status);
    }

    // Mutation caught: folding a missing fresh read into false/Lost, skipping the
    // final read, or repairing an unavailable initial sample with a successor read.
    #[test]
    fn inspect_os_live_pin_unavailable_fresh_birth_is_unavailable() {
        let view = os_view(std::process::id());
        let actual = process_start_time(view.pid()).unwrap();
        for missing_before in [true, false] {
            let mut reader = BirthAdapter::new(&view);
            if missing_before {
                reader.fresh = None;
            }
            let pending = begin_application(&mut reader);
            reader.fresh = if missing_before { Some(actual) } else { None };
            let result = finish_application(pending, &mut reader);
            assert!(view.still_the_same(), "the original held pin stayed live");
            assert_os_unknown(result, InspectIdentityUnknown::Unavailable, "unavailable");
        }
    }

    // Mutation caught: treating a live pidfd with missing admission birth as Lost,
    // or granting Observed from readable fresh birth without retained admission.
    #[test]
    fn inspect_os_live_pin_unavailable_admission_birth_is_unavailable() {
        let view = os_view(std::process::id());
        let mut reader = BirthAdapter::new(&view);
        reader.admission = None;
        let pending = begin_application(&mut reader);
        reader.admission = view.start_time();
        let result = finish_application(pending, &mut reader);
        assert!(view.still_the_same());
        assert_os_unknown(result, InspectIdentityUnknown::Unavailable, "unavailable");
    }

    // Mutation caught: dropping the retained-vs-fresh birth check in a diagnostic fix.
    #[test]
    fn inspect_os_live_pin_birth_mismatch_is_lost() {
        let view = os_view(std::process::id());
        let mut reader = BirthAdapter::new(&view);
        reader.fresh = Some(reader.fresh.unwrap().checked_add(1).unwrap());
        let result = reader.observe();
        assert!(view.still_the_same());
        assert_os_unknown(result, InspectIdentityUnknown::Lost, "lost");
    }

    struct BirthChild(std::process::Child);
    impl Drop for BirthChild {
        fn drop(&mut self) {
            // This owned sleep child exits within 30 seconds even if kill fails.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Mutation caught: missing birth/exe evidence hiding an actually invalid pin.
    #[test]
    fn inspect_os_original_pin_exit_is_lost() {
        let mut child = BirthChild(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let view = os_view(child.0.id());
        let mut reader = BirthAdapter::new(&view);
        let pending = begin_application(&mut reader);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        reader.fresh = None;
        assert!(
            !view.still_the_same(),
            "the original held pin observed actual exit"
        );
        assert_os_unknown(
            finish_application(pending, &mut reader),
            InspectIdentityUnknown::Lost,
            "lost",
        );
    }

    // Positive refuses an unknown-only implementation of the correction seam.
    #[test]
    fn inspect_os_unchanged_birth_and_live_pin_is_observed() {
        let view = os_view(std::process::id());
        let mut reader = BirthAdapter::new(&view);
        let result = reader.observe();
        let json = application_json(&result);
        assert_eq!(json["application_status"], "observed");
        assert_eq!(
            json["application"]["start_time"],
            process_start_time(view.pid()).unwrap()
        );
        assert_eq!(
            json["application"]["path"],
            std::fs::read_link("/proc/self/exe")
                .unwrap()
                .to_string_lossy()
                .as_ref()
        );
        assert!(view.still_the_same());
    }
}
