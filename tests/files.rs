use codepass::source_hash;
use std::fs;

#[test]
fn files_are_read_only_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.bin");
    let source = b"\xff\0print('hello')\r\n";
    fs::write(&path, source).unwrap();
    let a = source_hash(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), source);
    fs::write(&path, b"\xff\0print('hello')\n").unwrap();
    assert_ne!(a, source_hash(&path).unwrap());
    fs::write(&path, vec![0; 1024 * 1024]).unwrap();
    assert!(source_hash(&path).is_ok());
    fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
    assert!(source_hash(&path).is_err());
    assert!(source_hash(dir.path()).is_err());
    assert!(source_hash(&dir.path().join("missing")).is_err());
}

#[test]
fn git_source_ignores_working_tree_changes() {
    let dir = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.autocrlf=false"])
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    };
    git(&["init", "-q"]);
    let path = dir.path().join("main.rs");
    fs::write(&path, b"fn main() {}\n").unwrap();
    git(&["add", "main.rs"]);
    git(&["commit", "-q", "-m", "v1"]);
    git(&["tag", "pw-source"]);

    let committed = codepass::source::load(&path, Some("pw-source")).unwrap();
    assert_eq!(committed.sha256, source_hash(&path).unwrap());
    let commit = committed.git_commit.clone().unwrap();
    assert!(commit.len() == 40 || commit.len() == 64);

    // Editing the file (or CRLF conversion) changes the file hash but not the committed blob.
    fs::write(&path, b"fn main() {}\r\n// edited\r\n").unwrap();
    assert_ne!(source_hash(&path).unwrap(), committed.sha256);
    assert_eq!(codepass::source::load(&path, Some("pw-source")).unwrap().sha256, committed.sha256);
    assert_eq!(codepass::source::load(&path, Some(&commit)).unwrap().sha256, committed.sha256);

    // Even after the file is deleted from the working tree.
    fs::remove_file(&path).unwrap();
    assert_eq!(codepass::source::load(&path, Some(&commit)).unwrap().sha256, committed.sha256);

    assert!(codepass::source::load(&path, Some("no-such-tag")).is_err());
    assert!(codepass::source::load(&path, Some("--output=/tmp/x")).is_err());
    assert!(codepass::source::load(&dir.path().join("other.rs"), Some(&commit)).is_err());
}
