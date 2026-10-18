//! CodePass compiled to WebAssembly: the exact same library as the CLI, so the
//! browser reproduces the same passwords. Nothing here touches the network.

use codepass::{
    crypto::{self, Charset, Settings},
    phishing,
    profile::{MacStatus, Profile},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct Generated {
    password: String,
    check_code: String,
    site_key: String,
    code_sha256: String,
    warnings: Vec<String>,
    lookalikes: Vec<String>,
}

/// Generates a password. Returns JSON (see `Generated`), or throws a message.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn generate(
    source: &[u8],
    secret: &str,
    salt_hex: &str,
    site: &str,
    account: &str,
    length: u32,
    alnum: bool,
    symbols: &str,
    revision: u32,
    registered: &str,
    syntax_material: bool,
    file_name: &str,
) -> Result<String, JsError> {
    let err = |m: String| JsError::new(&m);
    let salt: [u8; 16] = hex::decode(salt_hex.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err("salt は16バイト（32桁の16進）で指定してください".into()))?;
    if source.len() as u64 > codepass::MAX_SOURCE_BYTES {
        return Err(err("ソースファイルの上限は1MiBです".into()));
    }
    let symbols = if alnum || symbols.trim().is_empty() {
        None
    } else {
        Some(crypto::canonical_symbols(symbols.trim()).map_err(err)?)
    };
    let settings = Settings {
        site: site.into(),
        account: account.into(),
        length: length as usize,
        charset: if alnum { Charset::Alnum } else { Charset::Strong },
        revision,
        require_classes: true,
        spec_version: crypto::LATEST_SPEC,
        symbols,
    };
    settings.validate().map_err(err)?;
    let site_key = settings.site_key();
    let registered: Vec<String> = registered
        .lines()
        .map(|l| crypto::site_key(l, crypto::LATEST_SPEC))
        .filter(|l| !l.is_empty())
        .collect();
    let lookalikes = phishing::lookalikes(&site_key, registered.iter().map(String::as_str));
    if !lookalikes.is_empty() {
        return Err(err(format!(
            "「{site_key}」は登録済みの「{}」と見た目がそっくりな別のドメインです。フィッシングの可能性があるので、パスワードは出しません",
            lookalikes.join("」「")
        )));
    }
    let mut warnings = phishing::suspicious_parts(&site_key);
    if let Some(w) = crypto::secret_warning(secret, &["codepass", site, account]) {
        warnings.push(w);
    }
    let hash: [u8; 32] = if syntax_material {
        codepass::syntax::hash(source, file_name).map_err(err)?
    } else {
        Sha256::digest(source).into()
    };
    let master = crypto::master_key(secret, &salt).map_err(err)?;
    let password = crypto::derive_with_master(&master, &hash, &settings).map_err(err)?;
    let out = Generated {
        password: password.to_string(),
        check_code: crypto::check_code(&master).map_err(err)?,
        site_key,
        code_sha256: hex::encode(hash),
        warnings,
        lookalikes,
    };
    serde_json::to_string(&out).map_err(|e| err(e.to_string()))
}

fn parse_profile(json: &str) -> Result<Profile, String> {
    let p: Profile =
        serde_json::from_str(json).map_err(|_| "設定ファイル（JSON）の形式が不正です".to_string())?;
    p.validate()?;
    Ok(p)
}

fn js<T>(r: Result<T, String>) -> Result<T, JsError> {
    r.map_err(|m| JsError::new(&m))
}

#[derive(Serialize)]
struct EntrySummary {
    index: usize,
    site: String,
    account: String,
    revision: u32,
    length: usize,
    spec_version: u32,
    source_sha256: String,
    source_path: Option<String>,
    git_commit: Option<String>,
    signed: bool,
    material: Option<String>,
}

fn summarize(index: usize, e: &codepass::profile::Entry) -> EntrySummary {
    EntrySummary {
        index,
        site: e.settings.site_key(),
        account: e.settings.account.clone(),
        revision: e.settings.revision,
        length: e.settings.length,
        spec_version: e.settings.spec_version,
        source_sha256: e.source_sha256.to_ascii_lowercase(),
        source_path: e.source_path.clone(),
        git_commit: e.git_commit.clone(),
        signed: e.mac.is_some(),
        material: e.material.clone(),
    }
}

/// The hash an entry expects from `source`: the bytes, or (syntax material) the token
/// stream, with the language taken from the file name the entry was registered with.
fn entry_material_hash(e: &codepass::profile::Entry, source: &[u8]) -> Result<[u8; 32], String> {
    match e.material.as_deref() {
        None => Ok(Sha256::digest(source).into()),
        Some(_) => {
            let path = e.source_path.as_deref().ok_or("構文の材料の登録にはファイル名が必要です")?;
            let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
            codepass::syntax::hash(source, name)
        }
    }
}

/// For the extension's settings page: the hash entry `index` would see from these
/// bytes (so a file can be matched to syntax-material entries too).
#[wasm_bindgen]
pub fn entry_hash_for(profile_json: &str, index: usize, source: &[u8]) -> Result<String, JsError> {
    js((|| {
        let p = parse_profile(profile_json)?;
        let e = p.entries.get(index).ok_or("指定された登録がありません")?;
        entry_material_hash(e, source).map(hex::encode)
    })())
}

/// The tokens syntax material keeps from `code` (for showing what counts).
#[wasm_bindgen]
pub fn syntax_preview(code: &str, file_name: &str) -> Result<String, JsError> {
    js((|| {
        let lang = codepass::syntax::lang_for(file_name)?;
        let tokens = codepass::syntax::tokens(code, lang)?;
        #[derive(Serialize)]
        struct Preview {
            lang: &'static str,
            tokens: Vec<String>,
            hash: String,
        }
        let hash = hex::encode(codepass::syntax::hash(code.as_bytes(), file_name)?);
        serde_json::to_string(&Preview { lang: lang.id(), tokens, hash }).map_err(|e| e.to_string())
    })())
}

/// Checks a profile exported by the CLI and lists its entries (no secrets involved).
#[wasm_bindgen]
pub fn inspect_profile(profile_json: &str) -> Result<String, JsError> {
    js(inspect_profile_impl(profile_json))
}

fn inspect_profile_impl(profile_json: &str) -> Result<String, String> {
    let p = parse_profile(profile_json)?;
    #[derive(Serialize)]
    struct Inspected {
        entries: Vec<EntrySummary>,
        hardware_key: bool,
    }
    let out = Inspected {
        entries: p.entries.iter().enumerate().map(|(i, e)| summarize(i, e)).collect(),
        hardware_key: p.hardware_key.is_some(),
    };
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// What the extension shows for the page it is on: the registered entries for this
/// host, or the registered names this host imitates (phishing), plus warnings.
#[wasm_bindgen]
pub fn match_site(profile_json: &str, host: &str) -> Result<String, JsError> {
    js(match_site_impl(profile_json, host))
}

fn match_site_impl(profile_json: &str, host: &str) -> Result<String, String> {
    let p = parse_profile(profile_json)?;
    let shown = phishing::decode_host(host);
    let key = crypto::site_key(&shown, crypto::LATEST_SPEC);
    let matches: Vec<EntrySummary> =
        p.entries_for_host(host).into_iter().map(|(i, e)| summarize(i, e)).collect();
    let registered: Vec<String> = p.entries.iter().map(|e| e.settings.site_key()).collect();
    let lookalikes = if matches.is_empty() {
        phishing::lookalikes(&key, registered.iter().map(String::as_str))
    } else {
        Vec::new()
    };
    #[derive(Serialize)]
    struct Matched {
        site_key: String,
        matches: Vec<EntrySummary>,
        lookalikes: Vec<String>,
        warnings: Vec<String>,
    }
    let out = Matched { warnings: phishing::suspicious_parts(&key), site_key: key, matches, lookalikes };
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Regenerates the password of one registered entry, exactly as `codepass get` does:
/// the code must hash to the registered value and the entry's signature must verify.
#[wasm_bindgen]
pub fn derive_entry(
    profile_json: &str,
    index: usize,
    source: &[u8],
    secret: &str,
) -> Result<String, JsError> {
    js(derive_entry_impl(profile_json, index, source, secret))
}

fn derive_entry_impl(
    profile_json: &str,
    index: usize,
    source: &[u8],
    secret: &str,
) -> Result<String, String> {
    let err = |m: &str| m.to_string();
    let p = parse_profile(profile_json)?;
    if p.hardware_key.is_some() {
        return Err(err("セキュリティキーを使う設定は、CLI（codepass get）で使ってください"));
    }
    let e = p.entries.get(index).ok_or_else(|| err("指定された登録がありません"))?;
    let hash = entry_material_hash(e, source)?;
    if !hex::encode(hash).eq_ignore_ascii_case(&e.source_sha256) {
        return Err(err("材料のファイルが登録時と違います。設定画面で正しいファイルを読み込んでください"));
    }
    let salt = p.salt_bytes()?;
    let master = crypto::master_key(secret, &salt)?;
    let check_code = crypto::check_code(&master)?;
    let mac_key = crypto::entry_mac_key(&master)?;
    let note = match e.verify(&mac_key) {
        MacStatus::Valid => None,
        MacStatus::Missing => Some("この登録には改ざん検知の署名がありません（v0.2以前の登録）".to_string()),
        MacStatus::Invalid => {
            return Err(format!(
                "登録内容の署名が合いません。マスターシークレットの打ち間違いか、設定が書き換えられた可能性があります（確認コード: {check_code}）"
            ))
        }
    };
    let password = crypto::derive_with_master(&master, &hash, &e.settings)?;
    #[derive(Serialize)]
    struct Derived {
        password: String,
        check_code: String,
        note: Option<String>,
    }
    serde_json::to_string(&Derived { password: password.to_string(), check_code, note })
        .map_err(|e| e.to_string())
}

/// How the CLI would name this service (spec v2 normalization).
#[wasm_bindgen]
pub fn site_key(site: &str) -> String {
    crypto::site_key(site, crypto::LATEST_SPEC)
}

/// A fresh random salt (from the browser's crypto.getRandomValues).
#[wasm_bindgen]
pub fn random_salt() -> Result<String, JsError> {
    let mut salt = [0u8; 16];
    getrandom_fill(&mut salt).map_err(|m| JsError::new(&m))?;
    Ok(hex::encode(salt))
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(target_arch = "wasm32")]
    {
        getrandom::getrandom(buf).map_err(|_| "安全な乱数を取得できません".to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        buf.fill(0);
        Ok(())
    }
}

/// The spec's known-answer vectors (tests/vectors.rs), recomputed here.
/// Returns JSON: [{ name, expected, actual, ok }].
#[wasm_bindgen]
pub fn self_test() -> String {
    serde_json::to_string(&run_vectors()).unwrap_or_default()
}

#[derive(Serialize)]
pub struct VectorResult {
    pub name: String,
    pub expected: String,
    pub actual: String,
    pub ok: bool,
}

pub fn run_vectors() -> Vec<VectorResult> {
    const SECRET: &str = "correct horse battery staple 2026";
    const SALT: [u8; 16] = *b"CodePassTestSalt";
    const SOURCE: &[u8] = b"fn main() {\n    println!(\"hello\");\n}\n";
    let hash: [u8; 32] = Sha256::digest(SOURCE).into();
    let s = |site: &str,
             account: &str,
             length,
             charset,
             revision,
             require_classes,
             spec_version,
             symbols: Option<&str>| {
        Settings {
            site: site.into(),
            account: account.into(),
            length,
            charset,
            revision,
            require_classes,
            spec_version,
            symbols: symbols.map(str::to_string),
        }
    };
    let cases = [
        (
            "v1 github.com",
            s("github.com", "", 24, Charset::Strong, 1, true, 1, None),
            "%EF^*4f)wo&7W!F-]@d;s:${",
        ),
        (
            "v1 github.com / personal / 更新2",
            s("github.com", "personal", 24, Charset::Strong, 2, true, 1, None),
            "{I;1w/U>UI_:J)Kq%[vv!->V",
        ),
        (
            "v1 example.com / 英数字8文字",
            s("example.com", "", 8, Charset::Alnum, 1, true, 1, None),
            "ebG0VWVW",
        ),
        (
            "v1 café.example / 日本語アカウント / 64文字",
            s("caf\u{e9}.example", "\u{3086}\u{3046}\u{305f}", 64, Charset::Strong, 1, false, 1, None),
            "+Q@&iI=1_NHvin~hRF54#^V3AHQq:+;Nu4~q:c#L}^.19dnqQ<?>(zONv3e3Eput",
        ),
        (
            "v2 https://www.GitHub.com/login",
            s("https://www.GitHub.com/login", " personal ", 24, Charset::Strong, 1, true, 2, None),
            "{V%6C]_6?3LL{7WjgmK*w3d5",
        ),
        (
            "v2 example.com / 記号 !#$%@",
            s("example.com", "", 16, Charset::Strong, 1, true, 2, Some("!#$%@")),
            "C4NjZMNsIEn1zgt!",
        ),
        (
            "v2 Bücher.example / 英数字12文字",
            s("B\u{fc}cher.example", "", 12, Charset::Alnum, 1, true, 2, None),
            "SQu45BiZtd3p",
        ),
    ];
    let mut out = Vec::new();
    let master = match crypto::master_key(SECRET, &SALT) {
        Ok(m) => m,
        Err(e) => {
            return vec![VectorResult {
                name: "Argon2id".into(),
                expected: "-".into(),
                actual: e,
                ok: false,
            }];
        }
    };
    for (name, settings, expected) in cases {
        let actual = crypto::derive_with_master(&master, &hash, &settings)
            .map(|p| p.to_string())
            .unwrap_or_else(|e| e);
        out.push(VectorResult {
            name: name.into(),
            ok: actual == expected,
            expected: expected.into(),
            actual,
        });
    }
    let code = crypto::check_code(&master).unwrap_or_default();
    out.push(VectorResult {
        name: "確認コード".into(),
        ok: code == "fountain-basil-oyster",
        expected: "fountain-basil-oyster".into(),
        actual: code,
    });
    out
}

#[cfg(test)]
mod tests {
    use codepass::{
        crypto::{self, Charset, Settings},
        profile::{Entry, Profile},
    };
    use sha2::{Digest, Sha256};

    /// Builds a profile the way the CLI would after `generate`, then checks that the
    /// extension's path gives the same password and refuses tampering.
    #[test]
    fn extension_path_matches_the_cli() {
        let secret = "orbit velvet quartz lagoon pickle saddle";
        let source = b"print('seed')\n";
        let hash: [u8; 32] = Sha256::digest(source).into();
        let mut p = Profile::new().unwrap();
        let settings = Settings {
            site: "github.com".into(),
            account: String::new(),
            length: 24,
            charset: Charset::Strong,
            revision: 1,
            require_classes: true,
            spec_version: 2,
            symbols: None,
        };
        let master = crypto::master_key(secret, &p.salt_bytes().unwrap()).unwrap();
        let mut e = Entry {
            source_sha256: hex::encode(hash),
            settings: settings.clone(),
            source_path: None,
            git_commit: None,
            mac: None,
            material: None,
        };
        e.sign(&crypto::entry_mac_key(&master).unwrap());
        p.entries.push(e);
        let json = serde_json::to_string(&p).unwrap();
        let expected = crypto::derive_with_master(&master, &hash, &settings).unwrap();

        let out: serde_json::Value =
            serde_json::from_str(&super::derive_entry_impl(&json, 0, source, secret).unwrap()).unwrap();
        assert_eq!(out["password"], expected.as_str());
        assert!(super::derive_entry_impl(&json, 0, b"other code", secret).is_err(), "wrong material");
        assert!(
            super::derive_entry_impl(&json, 0, source, "orbit velvet quartz lagoon pickle saddlf").is_err(),
            "typo"
        );
        let tampered = json.replace("\"length\":24", "\"length\":8");
        assert!(super::derive_entry_impl(&tampered, 0, source, secret).is_err(), "tampered length");

        let m: serde_json::Value =
            serde_json::from_str(&super::match_site_impl(&json, "login.github.com").unwrap()).unwrap();
        assert_eq!(m["matches"][0]["index"], 0);
        // A syntax-material entry accepts a reformatted, commented copy of its code.
        let code = "fn main() { let x = 1; }\n";
        let syntax_hash = codepass::syntax::hash(code.as_bytes(), "main.rs").unwrap();
        let mut p2 = p.clone();
        let mut se = p2.entries[0].clone();
        se.source_sha256 = hex::encode(syntax_hash);
        se.source_path = Some("/home/me/keys/main.rs".into());
        se.material = Some(codepass::syntax::MATERIAL_ID.into());
        se.sign(&crypto::entry_mac_key(&master).unwrap());
        p2.entries = vec![se];
        let json2 = serde_json::to_string(&p2).unwrap();
        let a: serde_json::Value =
            serde_json::from_str(&super::derive_entry_impl(&json2, 0, code.as_bytes(), secret).unwrap())
                .unwrap();
        let b: serde_json::Value = serde_json::from_str(
            &super::derive_entry_impl(&json2, 0, b"// note\nfn main(){\n  let x=1;\n}", secret).unwrap(),
        )
        .unwrap();
        assert_eq!(a["password"], b["password"]);
        assert!(super::derive_entry_impl(&json2, 0, b"fn main() { let x = 2; }", secret).is_err());

        // Browsers hand over the Punycode form; it must still be caught.
        for host in ["g\u{456}thub.com", "xn--gthub-n2e.com"] {
            let phish: serde_json::Value =
                serde_json::from_str(&super::match_site_impl(&json, host).unwrap()).unwrap();
            assert_eq!(phish["lookalikes"][0], "github.com", "{host}");
            assert!(phish["matches"].as_array().unwrap().is_empty());
            assert_eq!(phish["site_key"], "g\u{456}thub.com");
        }
    }

    #[test]
    fn vectors_match_natively() {
        for v in super::run_vectors() {
            assert!(v.ok, "{} expected {} got {}", v.name, v.expected, v.actual);
        }
    }
}
