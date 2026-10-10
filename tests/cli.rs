use std::{fs, process::{Command, Stdio}};

fn codepass(config: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_codepass")).arg("--config").arg(config).args(args)
        .stdin(Stdio::null()).output().unwrap()
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
