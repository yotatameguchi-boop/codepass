use std::{
    fs,
    process::{Command, Stdio},
};

fn codepass(config: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_codepass"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn init_export_import_and_safe_errors() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("profile.json");
    let source = dir.path().join("main.py");
    fs::write(&source, "print('hello')\n").unwrap();

    assert!(codepass(&config, &["init"]).status.success());
    // init must never replace an existing salt.
    assert!(!codepass(&config, &["init"]).status.success());

    let backup = dir.path().join("backup.json");
    assert!(codepass(&config, &["profile", "export", "--output", backup.to_str().unwrap()]).status.success());
    let restored = dir.path().join("restored.json");
    assert!(codepass(&restored, &["profile", "import", backup.to_str().unwrap()]).status.success());
    assert_eq!(fs::read(&config).unwrap(), fs::read(&restored).unwrap());

    // The secret is only accepted from an interactive terminal (never args/env/pipes).
    let out = codepass(&config, &["generate", source.to_str().unwrap(), "--site", "github.com"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());

    // Invalid inputs end with an error before asking for a secret.
    for args in [
        vec!["generate", source.to_str().unwrap(), "--site", "github.com", "--length", "7"],
        vec!["generate", source.to_str().unwrap(), "--site", "github.com", "--length", "65"],
        vec!["generate", source.to_str().unwrap(), "--site", "github.com", "--revision", "0"],
        vec!["generate", source.to_str().unwrap(), "--site", ""],
        vec!["generate", dir.path().to_str().unwrap(), "--site", "github.com"],
        vec!["generate", "missing.py", "--site", "github.com"],
        vec!["regenerate", source.to_str().unwrap(), "--entry", "1"],
    ] {
        let out = codepass(&config, &args);
        assert!(!out.status.success(), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }

    let corrupt = dir.path().join("corrupt.json");
    fs::write(&corrupt, "{\"format_version\":1}").unwrap();
    assert!(!codepass(&corrupt, &["profile", "list"]).status.success());
    assert_eq!(fs::read(&source).unwrap(), b"print('hello')\n");
}

#[test]
fn inspect_shows_the_syntax_material() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("profile.json");
    let a = dir.path().join("main.rs");
    let b = dir.path().join("formatted.rs");
    fs::write(&a, "fn main() { let x = 1; }\n").unwrap();
    fs::write(&b, "// note\nfn main(){\n    let x=1;\n}\n").unwrap();
    let hash_line = |path: &std::path::Path| {
        let out = codepass(&config, &["inspect", path.to_str().unwrap()]);
        assert!(out.status.success());
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .find(|l| l.starts_with("構文のハッシュ"))
            .unwrap()
            .to_string()
    };
    assert_eq!(hash_line(&a), hash_line(&b), "comments and layout do not count");
    let txt = dir.path().join("notes.txt");
    fs::write(&txt, "x").unwrap();
    assert!(!codepass(&config, &["inspect", txt.to_str().unwrap()]).status.success());
}

#[test]
fn team_init_writes_one_private_file_per_holder() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("team.json");
    let shares = dir.path().join("shares");
    let out = codepass(
        &config,
        &["team", "init", "--threshold", "2", "--shares", "3", "--share-dir", shares.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let files: Vec<String> = (1..=3)
        .map(|i| fs::read_to_string(shares.join(format!("codepass-share-{i}.txt"))).unwrap())
        .collect();
    let lines: Vec<&str> =
        files.iter().map(|f| f.lines().find(|l| l.starts_with("cpshare1-")).unwrap()).collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0] != lines[1] && lines[1] != lines[2]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(shares.join("codepass-share-1.txt")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // The settings file holds no share and no secret.
    let profile = fs::read_to_string(&config).unwrap();
    assert!(!profile.contains("cpshare1-"));
    for line in &lines {
        let y: String = line.split('-').skip(4).take(8).collect();
        assert!(!profile.contains(&y));
    }
    let status = codepass(&config, &["team", "status"]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("3 人のうち 2 人"));
    // Never overwrites an existing profile, and needs a terminal (or --share-dir) to hand out shares.
    assert!(!codepass(&config, &["team", "init", "--threshold", "2", "--shares", "3"]).status.success());
    let other = dir.path().join("other.json");
    assert!(!codepass(&other, &["team", "init", "--threshold", "2", "--shares", "3"]).status.success());
    assert!(!other.exists(), "no profile without shares handed out");
    // Nonsense thresholds are refused.
    let bad = dir.path().join("bad.json");
    assert!(!codepass(&bad, &["team", "init", "--threshold", "4", "--shares", "3", "--share-dir", "x"])
        .status
        .success());
    assert!(!codepass(&bad, &["team", "init", "--threshold", "1", "--shares", "3", "--share-dir", "x"])
        .status
        .success());
}

#[test]
fn rotate_plan_lists_the_affected_services() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("profile.json");
    assert!(codepass(&config, &["init"]).status.success());
    for reason in ["secret", "code", "member", "site"] {
        let out = codepass(&config, &["rotate", "plan", "--reason", reason]);
        assert!(out.status.success(), "{reason}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("codepass"), "{reason}");
    }
    assert!(String::from_utf8_lossy(&codepass(&config, &["rotate", "status"]).stdout).contains("ありません"));
}

#[test]
fn inspect_lists_the_keys_of_a_keyring() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("profile.json");
    let keys = dir.path().join("keys.rs");
    fs::write(&keys, "fn github_key() -> &'static str { \"a\" }\nfn aws_key() -> u64 { 42 }\n").unwrap();
    let out = codepass(&config, &["inspect", keys.to_str().unwrap(), "--symbols"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("github_key") && text.contains("aws_key") && !text.contains(" str "), "{text}");
    let one = codepass(&config, &["inspect", keys.to_str().unwrap(), "--symbol", "aws_key"]);
    assert!(String::from_utf8_lossy(&one.stdout).contains("42"));
    assert!(!codepass(&config, &["inspect", keys.to_str().unwrap(), "--symbol", "nope"]).status.success());
}
