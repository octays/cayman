use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn json_plan_is_read_only_and_estimates_delta() {
    let source = tempdir().unwrap();
    let target = tempdir().unwrap();
    fs::write(source.path().join("sample"), b"new content").unwrap();
    fs::write(target.path().join("sample"), b"old content").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cayman"))
        .arg("compare")
        .arg(source.path())
        .arg(target.path())
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["read_only"], true);
    assert_eq!(report["missing_bytes"], 11);
    assert_eq!(report["entries"][0]["action"], "update_file");
    assert_eq!(
        fs::read(target.path().join("sample")).unwrap(),
        b"old content"
    );
}

#[test]
fn invalid_arguments_and_missing_root_fail_without_plan() {
    let directory = tempdir().unwrap();
    for arguments in [vec!["--chunk-size", "0"], vec![]] {
        let output = Command::new(env!("CARGO_BIN_EXE_cayman"))
            .arg("compare")
            .arg(directory.path())
            .arg(directory.path().join("missing"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
