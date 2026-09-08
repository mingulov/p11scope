use std::process::Command;

#[test]
fn production_task_owner_transactions_and_lifecycle() {
    let temporary = tempfile::tempdir().expect("native owner test directory");
    for small in [false, true] {
        let binary = temporary
            .path()
            .join(if small { "small" } else { "normal" });
        let mut compiler = Command::new("clang-18");
        compiler
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                "crates/ebpf/native",
                "tests/fixtures/task-owner/helper_tests.c",
                "-o",
            ])
            .arg(&binary);
        if small {
            compiler.arg("-DP11SCOPE_SMALL_STATE_MAPS");
        }
        let output = compiler.output().expect("execute clang-18");
        assert!(
            output.status.success(),
            "native compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary)
            .output()
            .expect("execute native owner test");
        assert!(
            output.status.success(),
            "native owner test: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
