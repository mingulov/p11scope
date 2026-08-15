use p11scope::manifest_input::{MAX_MANIFEST_BYTES, read_manifest};
use std::path::PathBuf;

fn tmpdir(name: &str) -> PathBuf {
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn manifest_input_is_regular_utf8_and_bounded() {
    let d = tmpdir("manifest_pinning_input");
    let directory = d.join("directory");
    std::fs::create_dir_all(&directory).unwrap();
    assert!(
        read_manifest(&directory)
            .unwrap_err()
            .contains("regular file")
    );

    let oversized = d.join("oversized.json");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(MAX_MANIFEST_BYTES + 1).unwrap();
    assert!(read_manifest(&oversized).unwrap_err().contains("limit"));

    let invalid = d.join("invalid.json");
    std::fs::write(&invalid, [0xff]).unwrap();
    assert!(read_manifest(&invalid).unwrap_err().contains("UTF-8"));
}
