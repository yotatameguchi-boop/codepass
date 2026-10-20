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

fn git_in(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.autocrlf=false"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn tree_material_covers_the_whole_directory() {
    use codepass::source::{load_material, TREE_MATERIAL_ID};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("keys")).unwrap();
    fs::write(root.join("keys/a.rs"), "fn a() {}\n").unwrap();
    fs::write(root.join("README.md"), "x\n").unwrap();
    assert!(git_in(root, &["init", "-q"]).status.success());
    assert!(git_in(root, &["add", "."]).status.success());
    assert!(git_in(root, &["commit", "-q", "-m", "1"]).status.success());
    let tree = |path: &std::path::Path| {
        load_material(path, Some("HEAD"), Some(TREE_MATERIAL_ID), None).unwrap().sha256
    };
    let (whole1, keys1) = (tree(root), tree(&root.join("keys")));
    // A change outside keys/ changes the whole repository's material but not keys/.
    fs::write(root.join("README.md"), "y\n").unwrap();
    assert!(git_in(root, &["commit", "-qam", "2"]).status.success());
    assert_ne!(tree(root), whole1);
    assert_eq!(tree(&root.join("keys")), keys1);
    // A change inside keys/ changes it.
    fs::write(root.join("keys/a.rs"), "fn a() { 1 }\n").unwrap();
    assert!(git_in(root, &["commit", "-qam", "3"]).status.success());
    assert_ne!(tree(&root.join("keys")), keys1);
    // Without a commit there is no tree material.
    assert!(load_material(root, None, Some(TREE_MATERIAL_ID), None).is_err());
}

#[cfg(unix)]
#[test]
fn only_signed_commits_count_when_required() {
    use codepass::source::signer_of;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    fs::create_dir_all(&root).unwrap();
    let key = dir.path().join("key");
    let keygen = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "me", "-f"])
        .arg(&key)
        .status();
    if !keygen.is_ok_and(|s| s.success()) {
        eprintln!("ssh-keygen がないため省略");
        return;
    }
    let public = fs::read_to_string(key.with_extension("pub")).unwrap();
    let allowed = dir.path().join("allowed");
    fs::write(&allowed, format!("t@example.com namespaces=\"git\" {public}")).unwrap();
    assert!(git_in(&root, &["init", "-q"]).status.success());
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", key.with_extension("pub").to_str().unwrap()),
        ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
    ] {
        assert!(git_in(&root, &["config", k, v]).status.success());
    }
    fs::write(root.join("keys.rs"), "fn k() {}\n").unwrap();
    assert!(git_in(&root, &["add", "."]).status.success());
    let signed = git_in(&root, &["commit", "-q", "-S", "-m", "signed"]);
    if !signed.status.success() {
        eprintln!(
            "この環境の git では SSH 署名ができないため省略: {}",
            String::from_utf8_lossy(&signed.stderr)
        );
        return;
    }
    let head = |r: &std::path::Path| {
        String::from_utf8(git_in(r, &["rev-parse", "HEAD"]).stdout).unwrap().trim().to_string()
    };
    let signer = signer_of(&root.join("keys.rs"), &head(&root)).unwrap();
    assert!(signer.starts_with("SHA256:"), "{signer}");
    fs::write(root.join("keys.rs"), "fn k() { 1 }\n").unwrap();
    assert!(git_in(&root, &["commit", "-qam", "unsigned", "--no-gpg-sign"]).status.success());
    assert!(signer_of(&root.join("keys.rs"), &head(&root)).is_err());
}
