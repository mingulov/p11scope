//! SPDX-License-Identifier: GPL-3.0-or-later
//! Public inspect presentation retains scan-local identity without usage claims.

use std::process::{Child, Command};

struct OwnedTarget(Child);
impl Drop for OwnedTarget {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn inspect_public_identity_is_same_in_text_and_json() {
    let target = OwnedTarget(Command::new("sleep").arg("30").spawn().unwrap());
    let pid = target.0.id();
    let expected = std::fs::read_link(format!("/proc/{pid}/exe"))
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let run = |json: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_p11scope"));
        command.args(["inspect", "--pid", &pid.to_string()]);
        if json {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let document: serde_json::Value = serde_json::from_slice(&run(true)).unwrap();
    let text = String::from_utf8(run(false)).unwrap();
    assert_eq!(document["schema"], "p11scope/inspect/v1");
    assert_eq!(document["application_status"], "observed");
    assert_eq!(document["application"]["path"], expected);
    assert_eq!(document["application"].as_object().unwrap().len(), 7);
    assert!(text.contains(&expected));
    let basename = std::path::Path::new(&expected)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        text.starts_with(&format!("{basename} (PID {pid})")),
        "{text}"
    );
    assert!(text.contains("activity was not captured by inspect"));
    assert!(document.get("calls").is_none());
    assert!(document.get("cmdline").is_none());
    assert!(document.get("comm").is_none());
    assert!(document.get("environ").is_none());
}
