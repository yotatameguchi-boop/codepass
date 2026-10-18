//! CodePass compiled to WebAssembly: the exact same library as the CLI, so the
//! browser reproduces the same passwords. Nothing here touches the network.

use codepass::{
    crypto::{self, Charset, Settings},
    phishing,
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
    let hash: [u8; 32] = Sha256::digest(source).into();
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
    #[test]
    fn vectors_match_natively() {
        for v in super::run_vectors() {
            assert!(v.ok, "{} expected {} got {}", v.name, v.expected, v.actual);
        }
    }
}
