// Known-answer vectors for spec v1 (docs/SPEC.md). Any implementation must reproduce these.
use codepass::crypto::{derive, Charset, Settings};
use sha2::{Digest, Sha256};

const SECRET: &str = "correct horse battery staple 2026";
const SALT: [u8; 16] = *b"CodePassTestSalt";
const SOURCE: &[u8] = b"fn main() {\n    println!(\"hello\");\n}\n";

fn settings(
    site: &str,
    account: &str,
    length: usize,
    charset: Charset,
    revision: u32,
    require_classes: bool,
) -> Settings {
    Settings {
        site: site.into(),
        account: account.into(),
        length,
        charset,
        revision,
        require_classes,
        spec_version: 1,
        symbols: None,
    }
}

#[test]
fn spec_v1_vectors() {
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    assert_eq!(hex::encode(hash), "35e0393811f794547c34763eb5773d6cddb295dc4f372180ed4aae67da3ea45f");
    let cases = [
        (settings("github.com", "", 24, Charset::Strong, 1, true), r#"%EF^*4f)wo&7W!F-]@d;s:${"#),
        (settings("github.com", "personal", 24, Charset::Strong, 2, true), r#"{I;1w/U>UI_:J)Kq%[vv!->V"#),
        (settings("example.com", "", 8, Charset::Alnum, 1, true), r#"ebG0VWVW"#),
        (
            settings("caf\u{e9}.example", "\u{3086}\u{3046}\u{305f}", 64, Charset::Strong, 1, false),
            r#"+Q@&iI=1_NHvin~hRF54#^V3AHQq:+;Nu4~q:c#L}^.19dnqQ<?>(zONv3e3Eput"#,
        ),
    ];
    for (s, expected) in cases {
        let got = derive(SECRET, &SALT, &hash, &s).unwrap();
        assert_eq!(&*got, expected, "{s:?}");
    }
}

#[test]
fn nfc_equivalent_identifiers_match() {
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    let composed = settings("caf\u{e9}.example", "", 24, Charset::Strong, 1, true);
    let decomposed = settings("cafe\u{301}.example", "", 24, Charset::Strong, 1, true);
    assert_eq!(
        *derive(SECRET, &SALT, &hash, &composed).unwrap(),
        *derive(SECRET, &SALT, &hash, &decomposed).unwrap()
    );
}

#[test]
fn check_code_vector() {
    let master = codepass::crypto::master_key(SECRET, &SALT).unwrap();
    assert_eq!(codepass::crypto::check_code(&master).unwrap(), "fountain-basil-oyster");
    let typo = codepass::crypto::master_key("correct horse battery staple 2025", &SALT).unwrap();
    assert_ne!(codepass::crypto::check_code(&typo).unwrap(), "fountain-basil-oyster");
}

fn v2(site: &str, account: &str, length: usize, charset: Charset, symbols: Option<&str>) -> Settings {
    Settings {
        spec_version: 2,
        symbols: symbols.map(str::to_string),
        ..settings(site, account, length, charset, 1, true)
    }
}

#[test]
fn spec_v2_vectors() {
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    let cases = [
        (
            v2("https://www.GitHub.com/login", " personal ", 24, Charset::Strong, None),
            r#"{V%6C]_6?3LL{7WjgmK*w3d5"#,
        ),
        (v2("example.com", "", 16, Charset::Strong, Some("!#$%@")), r#"C4NjZMNsIEn1zgt!"#),
        (v2("B\u{fc}cher.example", "", 12, Charset::Alnum, None), r#"SQu45BiZtd3p"#),
    ];
    for (s, expected) in cases {
        let got = derive(SECRET, &SALT, &hash, &s).unwrap();
        assert_eq!(&*got, expected, "{s:?}");
    }
    // Any spelling of the same host gives the same v2 password.
    assert_eq!(
        *derive(SECRET, &SALT, &hash, &v2("github.com", "personal", 24, Charset::Strong, None)).unwrap(),
        *derive(
            SECRET,
            &SALT,
            &hash,
            &v2("https://www.GitHub.com/login", " personal ", 24, Charset::Strong, None)
        )
        .unwrap()
    );
}

#[test]
fn hardware_and_entry_mac_vectors() {
    use codepass::{crypto, profile::Entry};
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    let master = crypto::master_key(SECRET, &SALT).unwrap();
    assert_eq!(
        hex::encode(crypto::hardware_challenge(&SALT)),
        "741dd79e70a63cb84658f0459c4e87e06bb21a2f6b0e8a48f081a5aa32f7d228"
    );
    // A security key answering 0x11 × 32 to that challenge.
    let with_key = crypto::with_hardware(&master, &[0x11; 32]).unwrap();
    assert_eq!(crypto::check_code(&with_key).unwrap(), "tundra-arrow-koala");
    let s = Settings { spec_version: 2, ..settings("github.com", "", 24, Charset::Strong, 1, true) };
    assert_eq!(&*crypto::derive_with_master(&with_key, &hash, &s).unwrap(), r#";yhTNd&we>>dG7OSo3sC4|Or"#);

    let mut entry = Entry {
        source_sha256: hex::encode(hash),
        settings: s,
        source_path: Some("/home/me/keys/main.rs".into()),
        git_commit: Some("0123456789abcdef0123456789abcdef01234567".into()),
        mac: None,
        material: None,
        source_check: None,
    };
    entry.sign(&crypto::entry_mac_key(&master).unwrap());
    assert_eq!(
        entry.mac.as_deref(),
        Some("533acb4ee90fc06be3404a35ada8f7bf5e088816e3cf2946a7a31cfdecfd7764")
    );
}

#[test]
fn syntax_material_vectors() {
    use codepass::{crypto, syntax};
    let rust = "// comment\nfn main() {\n    let x = add(1, 2,); /* note */\n    println!(\"{x}\");\n}\n";
    let python = "def f(x, y):\n    if x:\n        return (1,)\n    return y  # done\n";
    let master = crypto::master_key(SECRET, &SALT).unwrap();
    let s = Settings { spec_version: 2, ..settings("github.com", "", 24, Charset::Strong, 1, true) };
    for (name, code, hash, password) in [
        (
            "main.rs",
            rust,
            "892edba33cdf17d1329dbfd7c07a0bba2dd219c9bd2ec6a1362c9b61bef260e4",
            r#"T8?H>m-UaDi};Yc-k_2UQvcO"#,
        ),
        (
            "app.py",
            python,
            "5c68c9909110262893530a05ec3e3801a4a0e98e0a2aeb70f817f0a6c669c400",
            r#":U.@Q}N=vN.<TK!CPAfnL)4("#,
        ),
    ] {
        let h = syntax::hash(code.as_bytes(), name).unwrap();
        assert_eq!(hex::encode(h), hash, "{name}");
        assert_eq!(&*crypto::derive_with_master(&master, &h, &s).unwrap(), password, "{name}");
    }
    // The same Rust program, reformatted by hand, gives the same hash.
    let reformatted = "fn main(){let x=add(1,2);println!(\"{x}\");}";
    assert_eq!(
        hex::encode(syntax::hash(reformatted.as_bytes(), "main.rs").unwrap()),
        "892edba33cdf17d1329dbfd7c07a0bba2dd219c9bd2ec6a1362c9b61bef260e4"
    );
}

#[test]
fn sealed_entry_vectors() {
    use codepass::{crypto, profile::Entry};
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    let master = crypto::master_key(SECRET, &SALT).unwrap();
    let check = crypto::code_check(&master, &hash).unwrap();
    assert_eq!(check, "bceb28107204dc457cc4e94a8ba0074045a6f890688efc3329e7d3e175fb0b0e");
    let mut entry = Entry {
        source_sha256: hex::encode(hash),
        settings: Settings { spec_version: 2, ..settings("github.com", "", 24, Charset::Strong, 1, true) },
        source_path: Some("/home/me/keys/main.rs".into()),
        git_commit: None,
        mac: None,
        material: None,
        source_check: None,
    };
    entry.seal(&master).unwrap();
    entry.sign(&crypto::entry_mac_key(&master).unwrap());
    assert_eq!(entry.source_check.as_deref(), Some(check.as_str()));
    assert_eq!(
        entry.mac.as_deref(),
        Some("947c4cb77a079b01028350bf17f228e5fef9ed9f20c9b2fb5c66a3fd09f1c4a1")
    );
}
