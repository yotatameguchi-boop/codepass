use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;
use crate::Result;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Charset { Strong, Alnum }

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
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.spec_version != 1 { return Err("未対応の生成仕様バージョンです".into()); }
        if !(8..=64).contains(&self.length) { return Err("文字数は8〜64です".into()); }
        if self.revision == 0 { return Err("更新番号は1以上です".into()); }
        let site = normalize(&self.site);
        if site.is_empty() { return Err("サービス識別子は必須です".into()); }
        for value in [&self.site, &self.account] {
            if value.len() > 4096 || value.chars().any(char::is_control) {
                return Err("識別子は4096バイト以下で制御文字を含めないでください".into());
            }
        }
        Ok(())
    }
}

// Both identifiers use NFC; case and whitespace are deliberately preserved.
pub fn normalize(value: &str) -> String { value.nfc().collect() }

pub fn validate_secret(secret: &str) -> Result<()> {
    if secret.chars().count() < 16 || secret.trim().chars().count() < 16 {
        return Err("マスターシークレットは16文字以上の長く推測困難なものを指定してください".into());
    }
    if secret.len() > 4096 { return Err("マスターシークレットの上限は4096バイトです".into()); }
    Ok(())
}

pub fn derive(secret: &str, salt: &[u8; 16], code_hash: &[u8; 32], settings: &Settings)
    -> Result<Zeroizing<String>> {
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

pub fn derive_with_master(master: &[u8; 32], code_hash: &[u8; 32], settings: &Settings)
    -> Result<Zeroizing<String>> {
    settings.validate()?;
    let mut context = b"CodePass/context/v1\0".to_vec();
    context.extend_from_slice(code_hash);
    for s in [normalize(&settings.site), normalize(&settings.account)] {
        context.extend_from_slice(&(s.len() as u32).to_be_bytes());
        context.extend_from_slice(s.as_bytes());
    }
    context.extend_from_slice(&settings.revision.to_be_bytes());
    context.push(settings.length as u8);
    context.push(match settings.charset { Charset::Strong => 1, Charset::Alnum => 2 });
    context.push(u8::from(settings.require_classes));
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"CodePass/HKDF/v1"), master)
        .expand(&context, &mut key[..]).map_err(|_| "HKDF処理に失敗しました")?;
    render(&key, settings)
}

/// Three words that depend only on the secret and salt, so a typo shows up as
/// unfamiliar words. Never stored; 24 bits are far weaker than any generated password.
pub fn check_code(master: &[u8; 32]) -> Result<String> {
    let mut out = [0u8; 3];
    Hkdf::<Sha256>::new(Some(b"CodePass/HKDF/v1"), master)
        .expand(b"CodePass/check-code/v1", &mut out).map_err(|_| "HKDF処理に失敗しました")?;
    Ok(out.iter().map(|&b| crate::words::WORDS[b as usize]).collect::<Vec<_>>().join("-"))
}

fn render(key: &[u8; 32], settings: &Settings) -> Result<Zeroizing<String>> {
    let mut alphabet = Vec::new();
    alphabet.extend_from_slice(LOWER);
    alphabet.extend_from_slice(UPPER);
    alphabet.extend_from_slice(DIGITS);
    if settings.charset == Charset::Strong { alphabet.extend_from_slice(SYMBOLS); }
    let limit = 256usize / alphabet.len() * alphabet.len();
    let mut counter = 0u64;
    let mut block = Zeroizing::new([0u8; 32]);
    let mut offset = 32;
    // Reject whole candidates to preserve uniformity among all valid passwords.
    for _ in 0..1_000_000 {
        let mut candidate = Zeroizing::new(Vec::with_capacity(settings.length));
        while candidate.len() < settings.length {
            if offset == 32 {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "HMAC処理に失敗しました")?;
                mac.update(b"CodePass/stream/v1\0");
                mac.update(&counter.to_be_bytes());
                block.copy_from_slice(&mac.finalize().into_bytes());
                counter = counter.checked_add(1).ok_or("生成カウンタが上限に達しました")?;
                offset = 0;
            }
            let b = block[offset] as usize;
            offset += 1;
            if b < limit { candidate.push(alphabet[b % alphabet.len()]); }
        }
        let contains = |class: &[u8]| candidate.iter().any(|b| class.contains(b));
        if !settings.require_classes || (contains(LOWER) && contains(UPPER) && contains(DIGITS)
            && (settings.charset == Charset::Alnum || contains(SYMBOLS))) {
            return String::from_utf8(candidate.to_vec()).map(Zeroizing::new)
                .map_err(|_| "文字列生成エラー".into());
        }
    }
    Err("条件を満たすパスワードを生成できませんでした".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings { Settings { site: "github.com".into(), account: "personal".into(),
        length: 24, charset: Charset::Strong, revision: 1, require_classes: true, spec_version: 1 } }
    #[test]
    fn repeatability_and_context_separation() {
        let base = settings();
        let generate = |s: &Settings, h: &[u8; 32]| derive("a long master secret for tests", &[7;16], h, s).unwrap();
        let a = generate(&base, &[1;32]);
        assert_eq!(*a, *generate(&base, &[1;32]));
        assert_ne!(*a, *generate(&base, &[2;32]));
        for changed in 0..3 {
            let mut s = base.clone();
            match changed { 0 => s.site = "example.com".into(), 1 => s.account = "work".into(), _ => s.revision = 2 }
            assert_ne!(*a, *generate(&s, &[1;32]));
        }
    }
    #[test]
    fn lengths_and_classes() {
        for charset in [Charset::Strong, Charset::Alnum] {
            for length in 8..=64 {
                let mut s = settings(); s.length = length; s.charset = charset;
                let p = render(&[9;32], &s).unwrap();
                assert_eq!(p.len(), length);
                assert!(p.bytes().any(|b| LOWER.contains(&b)));
                assert!(p.bytes().any(|b| UPPER.contains(&b)));
                assert!(p.bytes().any(|b| DIGITS.contains(&b)));
                if charset == Charset::Alnum { assert!(p.bytes().all(|b| b.is_ascii_alphanumeric())); }
                else { assert!(p.bytes().any(|b| SYMBOLS.contains(&b))); }
            }
        }
    }
    #[test]
    fn normalization_and_validation() {
        assert_eq!(normalize("e\u{301}"), "é");
        assert!(validate_secret("short").is_err());
        let mut s = settings(); s.spec_version = 2; assert!(s.validate().is_err());
        s.spec_version = 1; s.length = 7; assert!(s.validate().is_err());
    }
    #[test]
    fn check_code_words_are_distinct() {
        let mut words = crate::words::WORDS.to_vec(); words.sort(); words.dedup();
        assert_eq!(words.len(), 256);
        assert_ne!(check_code(&[1; 32]).unwrap(), check_code(&[2; 32]).unwrap());
    }
}
