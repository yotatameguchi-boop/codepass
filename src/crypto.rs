use crate::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

/// Spec used for new passwords. Older versions stay supported for regeneration.
pub const LATEST_SPEC: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Charset {
    Strong,
    Alnum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub site: String,
    pub account: String,
    pub length: usize,
    pub charset: Charset,
    pub revision: u32,
    pub require_classes: bool,
    pub spec_version: u32,
    /// Allowed symbols for `strong` (spec v2+). None means the default set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols: Option<String>,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !(1..=LATEST_SPEC).contains(&self.spec_version) {
            return Err("未対応の生成仕様バージョンです".into());
        }
        if !(8..=64).contains(&self.length) {
            return Err("文字数は8〜64です".into());
        }
        if self.revision == 0 {
            return Err("更新番号は1以上です".into());
        }
        for value in [&self.site, &self.account] {
            if value.len() > 4096 || value.chars().any(char::is_control) {
                return Err("識別子は4096バイト以下で制御文字を含めないでください".into());
            }
        }
        if self.site_key().is_empty() {
            return Err("サービス識別子は必須です".into());
        }
        if let Some(symbols) = &self.symbols {
            if self.spec_version < 2 {
                return Err("--symbols は生成仕様v2以降で使えます".into());
            }
            if self.charset != Charset::Strong {
                return Err("--symbols は --charset strong と一緒に使います".into());
            }
            if canonical_symbols(symbols)? != *symbols {
                return Err("記号の指定が正規化されていません".into());
            }
        }
        Ok(())
    }

    /// The service identifier exactly as it enters the derivation.
    pub fn site_key(&self) -> String {
        site_key(&self.site, self.spec_version)
    }
    pub fn account_key(&self) -> String {
        account_key(&self.account, self.spec_version)
    }

    fn symbol_set(&self) -> &[u8] {
        match (&self.charset, &self.symbols) {
            (Charset::Alnum, _) => b"",
            (Charset::Strong, Some(s)) => s.as_bytes(),
            (Charset::Strong, None) => SYMBOLS,
        }
    }
}

// v1: NFC only; case and whitespace are deliberately preserved.
pub fn normalize(value: &str) -> String {
    value.nfc().collect()
}

pub fn site_key(site: &str, spec_version: u32) -> String {
    if spec_version < 2 {
        normalize(site)
    } else {
        normalize_site_v2(site)
    }
}

pub fn account_key(account: &str, spec_version: u32) -> String {
    if spec_version < 2 {
        normalize(account)
    } else {
        normalize(account.trim())
    }
}

/// v2: reduce a URL or host to the bare host, so `https://www.GitHub.com/login`
/// and `github.com` are the same service. Only NFKC and Unicode lowercasing are used
/// (no IDNA library), so every implementation agrees. Lowercasing can expose new
/// structure, so passes repeat until nothing changes.
pub fn normalize_site_v2(site: &str) -> String {
    let mut current = site_pass_v2(site);
    for _ in 0..8 {
        let next = site_pass_v2(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn site_pass_v2(site: &str) -> String {
    // NFKC first, so look-alike characters such as "／" or "﹟" split the URL like their ASCII forms.
    let site: String = site.nfkc().collect();
    let mut t = site.trim();
    if let Some((_, rest)) = t.split_once("://") {
        t = rest;
    }
    t = t.split(['/', '?', '#']).next().unwrap_or("");
    if let Some((_, host)) = t.rsplit_once('@') {
        t = host;
    }
    if let Some((host, port)) = t.rsplit_once(':') {
        let bracketed = host.starts_with('[') && host.ends_with(']');
        if (bracketed || !host.contains(':')) && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
        {
            t = host;
        }
    }
    let t = t.trim_start().trim_end_matches(|c: char| c == '.' || c.is_whitespace());
    let host: String = t.to_lowercase().nfkc().collect();
    let host = host.trim_end_matches(|c: char| c == '.' || c.is_whitespace()).to_string();
    match host.strip_prefix("www.") {
        Some(rest) if rest.contains('.') => rest.to_string(),
        _ => host,
    }
}

/// Sorted, de-duplicated ASCII punctuation, so the same set always encodes the same way.
pub fn canonical_symbols(symbols: &str) -> Result<String> {
    let mut bytes: Vec<u8> = symbols.bytes().collect();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_punctuation) {
        return Err("--symbols には空白以外のASCII記号を1文字以上指定してください".into());
    }
    bytes.sort_unstable();
    bytes.dedup();
    Ok(String::from_utf8(bytes).expect("ASCII"))
}

pub fn validate_secret(secret: &str) -> Result<()> {
    if secret.chars().count() < 16 || secret.trim().chars().count() < 16 {
        return Err("マスターシークレットは16文字以上の長く推測困難なものを指定してください".into());
    }
    if secret.len() > 4096 {
        return Err("マスターシークレットの上限は4096バイトです".into());
    }
    Ok(())
}

/// A warning when the secret looks guessable (zxcvbn estimate below 10^10 guesses).
/// Not an error, so passwords made with an existing secret stay reachable.
pub fn secret_warning(secret: &str, hints: &[&str]) -> Option<String> {
    let estimate = zxcvbn::zxcvbn(secret, hints);
    (estimate.score() < zxcvbn::Score::Three).then(|| {
        format!(
        "警告: マスターシークレットが推測されやすい可能性があります（推定 約10^{:.0}回の試行で破られる）。\
        無関係な単語を5つ以上つなげたものなどを推奨します",
        estimate.guesses_log10())
    })
}

pub fn derive(
    secret: &str,
    salt: &[u8; 16],
    code_hash: &[u8; 32],
    settings: &Settings,
) -> Result<Zeroizing<String>> {
    settings.validate()?;
    derive_with_master(&*master_key(secret, salt)?, code_hash, settings)
}

/// The slow, secret-dependent step. Run once per session and reuse for every site.
pub fn master_key(secret: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    validate_secret(secret)?;
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| "Argon2設定エラー")?;
    let mut master = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.as_bytes(), salt, &mut *master)
        .map_err(|_| "鍵導出に失敗しました")?;
    Ok(master)
}

pub fn derive_with_master(
    master: &[u8; 32],
    code_hash: &[u8; 32],
    settings: &Settings,
) -> Result<Zeroizing<String>> {
    settings.validate()?;
    let v = settings.spec_version;
    let mut context = format!("CodePass/context/v{v}\0").into_bytes();
    context.extend_from_slice(code_hash);
    for s in [settings.site_key(), settings.account_key()] {
        context.extend_from_slice(&(s.len() as u32).to_be_bytes());
        context.extend_from_slice(s.as_bytes());
    }
    context.extend_from_slice(&settings.revision.to_be_bytes());
    context.push(settings.length as u8);
    context.push(match settings.charset {
        Charset::Strong => 1,
        Charset::Alnum => 2,
    });
    context.push(u8::from(settings.require_classes));
    if v >= 2 {
        let symbols = settings.symbol_set();
        context.push(symbols.len() as u8);
        context.extend_from_slice(symbols);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(format!("CodePass/HKDF/v{v}").as_bytes()), master)
        .expand(&context, &mut key[..])
        .map_err(|_| "HKDF処理に失敗しました")?;
    render(&key, settings)
}

/// Three words that depend only on the secret and salt, so a typo shows up as
/// unfamiliar words. Never stored; 24 bits are far weaker than any generated password.
pub fn check_code(master: &[u8; 32]) -> Result<String> {
    let mut out = [0u8; 3];
    Hkdf::<Sha256>::new(Some(b"CodePass/HKDF/v1"), master)
        .expand(b"CodePass/check-code/v1", &mut out)
        .map_err(|_| "HKDF処理に失敗しました")?;
    Ok(out.iter().map(|&b| crate::words::WORDS[b as usize]).collect::<Vec<_>>().join("-"))
}

fn render(key: &[u8; 32], settings: &Settings) -> Result<Zeroizing<String>> {
    let symbols = settings.symbol_set();
    let mut alphabet = Vec::new();
    alphabet.extend_from_slice(LOWER);
    alphabet.extend_from_slice(UPPER);
    alphabet.extend_from_slice(DIGITS);
    alphabet.extend_from_slice(symbols);
    let limit = 256usize / alphabet.len() * alphabet.len();
    let label = format!("CodePass/stream/v{}\0", settings.spec_version);
    let mut counter = 0u64;
    let mut block = Zeroizing::new([0u8; 32]);
    let mut offset = 32;
    // Reject whole candidates to preserve uniformity among all valid passwords.
    for _ in 0..1_000_000 {
        let mut candidate = Zeroizing::new(Vec::with_capacity(settings.length));
        while candidate.len() < settings.length {
            if offset == 32 {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "HMAC処理に失敗しました")?;
                mac.update(label.as_bytes());
                mac.update(&counter.to_be_bytes());
                block.copy_from_slice(&mac.finalize().into_bytes());
                counter = counter.checked_add(1).ok_or("生成カウンタが上限に達しました")?;
                offset = 0;
            }
            let b = block[offset] as usize;
            offset += 1;
            if b < limit {
                candidate.push(alphabet[b % alphabet.len()]);
            }
        }
        let contains = |class: &[u8]| candidate.iter().any(|b| class.contains(b));
        if !settings.require_classes
            || (contains(LOWER)
                && contains(UPPER)
                && contains(DIGITS)
                && (symbols.is_empty() || contains(symbols)))
        {
            return String::from_utf8(candidate.to_vec())
                .map(Zeroizing::new)
                .map_err(|_| "文字列生成エラー".into());
        }
    }
    Err("条件を満たすパスワードを生成できませんでした".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings {
            site: "github.com".into(),
            account: "personal".into(),
            length: 24,
            charset: Charset::Strong,
            revision: 1,
            require_classes: true,
            spec_version: 1,
            symbols: None,
        }
    }
    #[test]
    fn repeatability_and_context_separation() {
        let base = settings();
        let generate =
            |s: &Settings, h: &[u8; 32]| derive("a long master secret for tests", &[7; 16], h, s).unwrap();
        let a = generate(&base, &[1; 32]);
        assert_eq!(*a, *generate(&base, &[1; 32]));
        assert_ne!(*a, *generate(&base, &[2; 32]));
        for changed in 0..3 {
            let mut s = base.clone();
            match changed {
                0 => s.site = "example.com".into(),
                1 => s.account = "work".into(),
                _ => s.revision = 2,
            }
            assert_ne!(*a, *generate(&s, &[1; 32]));
        }
    }
    #[test]
    fn lengths_and_classes() {
        for charset in [Charset::Strong, Charset::Alnum] {
            for length in 8..=64 {
                let mut s = settings();
                s.length = length;
                s.charset = charset;
                let p = render(&[9; 32], &s).unwrap();
                assert_eq!(p.len(), length);
                assert!(p.bytes().any(|b| LOWER.contains(&b)));
                assert!(p.bytes().any(|b| UPPER.contains(&b)));
                assert!(p.bytes().any(|b| DIGITS.contains(&b)));
                if charset == Charset::Alnum {
                    assert!(p.bytes().all(|b| b.is_ascii_alphanumeric()));
                } else {
                    assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
                }
            }
        }
    }
    #[test]
    fn normalization_and_validation() {
        assert_eq!(normalize("e\u{301}"), "é");
        assert!(validate_secret("short").is_err());
        let mut s = settings();
        s.spec_version = LATEST_SPEC + 1;
        assert!(s.validate().is_err());
        s.spec_version = 1;
        s.length = 7;
        assert!(s.validate().is_err());
    }
    #[test]
    fn site_normalization_v2() {
        for input in [
            "github.com",
            "GitHub.com",
            " https://www.GitHub.com/login?x=1 ",
            "http://user@github.com:443/",
            "github.com.",
            "WWW.GITHUB.COM",
        ] {
            assert_eq!(normalize_site_v2(input), "github.com", "{input}");
        }
        assert_eq!(normalize_site_v2("https://Bücher.example/"), "bücher.example");
        assert_eq!(normalize_site_v2("ＧｉｔＨｕｂ．ｃｏｍ"), "github.com");
        assert_eq!(normalize_site_v2("www.com"), "www.com");
        assert_eq!(normalize_site_v2("My Bank"), "my bank");
        assert_eq!(normalize_site_v2("[::1]:8080"), "[::1]");
        // v1 keeps case, so existing passwords do not change.
        assert_eq!(site_key("GitHub.com", 1), "GitHub.com");
    }
    #[test]
    fn custom_symbols() {
        assert_eq!(canonical_symbols("@!#!").unwrap(), "!#@");
        assert!(canonical_symbols("").is_err());
        assert!(canonical_symbols("a!").is_err());
        assert!(canonical_symbols("! ").is_err());
        let mut s = settings();
        s.spec_version = 2;
        s.symbols = Some("!@".into());
        s.validate().unwrap();
        for length in 8..=64 {
            s.length = length;
            let p = render(&[3; 32], &s).unwrap();
            assert!(p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'!' || b == b'@'));
            assert!(p.bytes().any(|b| b == b'!' || b == b'@'));
        }
        s.symbols = Some("@!".into());
        assert!(s.validate().is_err(), "must be canonical");
        s.symbols = Some("!".into());
        s.spec_version = 1;
        assert!(s.validate().is_err());
        s.spec_version = 2;
        s.charset = Charset::Alnum;
        assert!(s.validate().is_err());
    }
    #[test]
    fn weak_secret_warning() {
        assert!(secret_warning("passwordpassword", &[]).is_some());
        assert!(secret_warning("orbit velvet quartz lagoon pickle saddle", &[]).is_none());
    }
    #[test]
    fn check_code_words_are_distinct() {
        let mut words = crate::words::WORDS.to_vec();
        words.sort();
        words.dedup();
        assert_eq!(words.len(), 256);
        assert_ne!(check_code(&[1; 32]).unwrap(), check_code(&[2; 32]).unwrap());
    }
}
