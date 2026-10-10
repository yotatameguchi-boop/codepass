// Known-answer vectors for spec v1 (docs/SPEC.md). Any implementation must reproduce these.
use codepass::crypto::{derive, Charset, Settings};
use sha2::{Digest, Sha256};

const SECRET: &str = "correct horse battery staple 2026";
const SALT: [u8; 16] = *b"CodePassTestSalt";
const SOURCE: &[u8] = b"fn main() {\n    println!(\"hello\");\n}\n";

fn settings(site: &str, account: &str, length: usize, charset: Charset, revision: u32, require_classes: bool) -> Settings {
    Settings { site: site.into(), account: account.into(), length, charset, revision, require_classes, spec_version: 1 }
}

#[test]
fn spec_v1_vectors() {
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    assert_eq!(hex::encode(hash), "35e0393811f794547c34763eb5773d6cddb295dc4f372180ed4aae67da3ea45f");
    let cases = [
        (settings("github.com", "", 24, Charset::Strong, 1, true), r#"%EF^*4f)wo&7W!F-]@d;s:${"#),
        (settings("github.com", "personal", 24, Charset::Strong, 2, true), r#"{I;1w/U>UI_:J)Kq%[vv!->V"#),
        (settings("example.com", "", 8, Charset::Alnum, 1, true), r#"ebG0VWVW"#),
        (settings("caf\u{e9}.example", "\u{3086}\u{3046}\u{305f}", 64, Charset::Strong, 1, false), r#"+Q@&iI=1_NHvin~hRF54#^V3AHQq:+;Nu4~q:c#L}^.19dnqQ<?>(zONv3e3Eput"#),
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
    assert_eq!(*derive(SECRET, &SALT, &hash, &composed).unwrap(), *derive(SECRET, &SALT, &hash, &decomposed).unwrap());
}

#[test]
fn check_code_vector() {
    let master = codepass::crypto::master_key(SECRET, &SALT).unwrap();
    assert_eq!(codepass::crypto::check_code(&master).unwrap(), "fountain-basil-oyster");
    let typo = codepass::crypto::master_key("correct horse battery staple 2025", &SALT).unwrap();
    assert_ne!(codepass::crypto::check_code(&typo).unwrap(), "fountain-basil-oyster");
}
