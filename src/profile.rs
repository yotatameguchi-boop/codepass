use crate::{
    crypto::{account_key, site_key, Charset, Settings},
    Result,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub format_version: u32,
    pub spec_version: u32,
    pub salt: String,
    pub entries: Vec<Entry>,
    /// A FIDO2 security key whose hmac-secret output is mixed into the master key (format 3+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_key: Option<HardwareKey>,
    /// Break-glass team profile: k of n shares replace the master secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<crate::team::TeamConfig>,
    /// An ongoing rotation into this profile from an older one (`codepass rotate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<Rotation>,
}

/// Progress of moving every registration to a new secret, salt or code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    /// The old settings file, still needed for the old passwords.
    pub from: String,
    /// (index in this profile, index in the old one) of services not yet changed.
    pub pending: Vec<(usize, usize)>,
}

/// Non-secret handle to the credential on the security key. Without the physical key
/// it is useless; with it, it is required to reproduce every password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareKey {
    pub credential_id: String,
    pub rp_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The code's hash (bytes or syntax material). Empty when the entry is sealed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_sha256: String,
    pub settings: Settings,
    /// Where the code was read from (format 2+). Lets `get` find it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Full commit hash when the code was read from Git (format 2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// HMAC-SHA256 over every other field, keyed from the master key (format 3+).
    /// Detects edits to the file, and proves the secret was typed correctly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// How the code becomes the hash: absent = the raw bytes, "syntax-v1" = the
    /// token stream (crate::syntax). `source_sha256` holds whichever hash it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material: Option<String>,
    /// Sealed entries (format 3+): instead of the code's hash, a check value only the
    /// master key can verify (crypto::code_check). Then the code is a second factor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_check: Option<String>,
}

pub enum MacStatus {
    Valid,
    Missing,
    Invalid,
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_opt(out: &mut Vec<u8>, value: &Option<String>) {
    match value {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            put(out, v.as_bytes());
        }
    }
}

impl Entry {
    /// The exact bytes the MAC covers (docs/SPEC.md, "設定の改ざん検知").
    pub fn mac_input(&self) -> Vec<u8> {
        let s = &self.settings;
        let mut out = b"CodePass/entry/v1\0".to_vec();
        put(&mut out, self.source_sha256.to_ascii_lowercase().as_bytes());
        put(&mut out, s.site.as_bytes());
        put(&mut out, s.account.as_bytes());
        out.extend_from_slice(&(s.length as u32).to_be_bytes());
        out.push(match s.charset {
            Charset::Strong => 1,
            Charset::Alnum => 2,
        });
        out.extend_from_slice(&s.revision.to_be_bytes());
        out.push(u8::from(s.require_classes));
        out.extend_from_slice(&s.spec_version.to_be_bytes());
        put_opt(&mut out, &s.symbols);
        put_opt(&mut out, &self.source_path);
        put_opt(&mut out, &self.git_commit);
        // Appended only when set, so entries signed before they existed still verify.
        // Distinct tags (0x01 material, 0x02 check) keep the two apart.
        if self.material.is_some() {
            put_opt(&mut out, &self.material);
        }
        if let Some(check) = &self.source_check {
            out.push(2);
            put(&mut out, check.as_bytes());
        }
        out
    }
    pub fn sign(&mut self, key: &[u8; 32]) {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
        mac.update(&self.mac_input());
        self.mac = Some(hex::encode(mac.finalize().into_bytes()));
    }
    pub fn verify(&self, key: &[u8; 32]) -> MacStatus {
        let Some(tag) = self.mac.as_deref().and_then(|t| hex::decode(t).ok()) else {
            return if self.mac.is_none() { MacStatus::Missing } else { MacStatus::Invalid };
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length");
        mac.update(&self.mac_input());
        // verify_slice compares in constant time.
        match mac.verify_slice(&tag) {
            Ok(()) => MacStatus::Valid,
            Err(_) => MacStatus::Invalid,
        }
    }
    /// Same site and account, comparing under either entry's spec version.
    pub fn same_service(&self, other: &Settings) -> bool {
        let s = &self.settings;
        let same = |a: &str, b: &str, key: fn(&str, u32) -> String| {
            key(a, s.spec_version) == key(b, s.spec_version)
                || key(a, other.spec_version) == key(b, other.spec_version)
        };
        same(&s.site, &other.site, site_key) && same(&s.account, &other.account, account_key)
    }
    /// Entries are identified by site, account and revision, so old revisions stay recoverable.
    pub fn same_key(&self, other: &Settings) -> bool {
        self.same_service(other) && self.settings.revision == other.revision
    }
    pub fn is_sealed(&self) -> bool {
        self.source_check.is_some()
    }

    /// Compares the code of two entries. With the master key, sealed and unsealed
    /// entries compare too; without it, only like with like (None = cannot tell).
    fn material_key(&self, master: Option<&[u8; 32]>) -> Option<String> {
        match (&self.source_check, master) {
            (Some(check), _) => Some(format!("check:{check}")),
            (None, Some(m)) => {
                let hash: [u8; 32] = hex::decode(&self.source_sha256).ok()?.try_into().ok()?;
                crate::crypto::code_check(m, &hash).ok().map(|c| format!("check:{c}"))
            }
            (None, None) => Some(format!("hash:{}", self.source_sha256.to_ascii_lowercase())),
        }
    }

    /// Whether `code_hash` is this entry's code. Sealed entries need the master key.
    pub fn code_matches(&self, code_hash: &[u8; 32], master: &[u8; 32]) -> bool {
        match &self.source_check {
            None => hex::encode(code_hash).eq_ignore_ascii_case(&self.source_sha256),
            Some(check) => crate::crypto::code_check(master, code_hash).is_ok_and(|c| {
                // Constant-time comparison of the two check values.
                c.len() == check.len()
                    && c.bytes().zip(check.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }),
        }
    }

    /// Replaces the stored code hash with a check value (the password is unchanged).
    pub fn seal(&mut self, master: &[u8; 32]) -> Result<()> {
        if self.is_sealed() {
            return Ok(());
        }
        let hash: [u8; 32] = hex::decode(&self.source_sha256)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("コードハッシュが不正です")?;
        self.source_check = Some(crate::crypto::code_check(master, &hash)?);
        self.source_sha256.clear();
        Ok(())
    }

    pub fn same_password(&self, other: &Entry, master: Option<&[u8; 32]>) -> bool {
        let (a, b) = (&self.settings, &other.settings);
        self.same_key(b)
            && self.material_key(master).is_some()
            && self.material_key(master) == other.material_key(master)
            && a.length == b.length
            && a.charset == b.charset
            && a.require_classes == b.require_classes
            && a.spec_version == b.spec_version
            && a.symbols == b.symbols
    }
}

pub enum Saved {
    Added,
    Unchanged,
    Replaced,
    Conflict,
}

impl Profile {
    pub fn new() -> Result<Self> {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| "安全な乱数を取得できません")?;
        Ok(Self {
            format_version: 3,
            spec_version: 1,
            salt: hex::encode(salt),
            entries: vec![],
            hardware_key: None,
            team: None,
            rotation: None,
        })
    }
    pub fn salt_bytes(&self) -> Result<[u8; 16]> {
        let bytes = hex::decode(&self.salt).map_err(|_| "saltの形式が不正です")?;
        bytes.try_into().map_err(|_| "saltは16バイトである必要があります".into())
    }
    /// Adds or updates an entry. A different password under the same key is never
    /// overwritten unless `replace` is set, because the old one would be lost.
    pub fn upsert(&mut self, entry: Entry, replace: bool, master: Option<&[u8; 32]>) -> Saved {
        match self.entries.iter_mut().find(|e| e.same_key(&entry.settings)) {
            None => {
                self.entries.push(entry);
                Saved::Added
            }
            Some(e) if e.same_password(&entry, master) => {
                if e.source_path.is_none() || entry.git_commit.is_some() || e.mac.is_none() {
                    *e = entry;
                }
                Saved::Unchanged
            }
            Some(e) if replace => {
                *e = entry;
                Saved::Replaced
            }
            Some(_) => Saved::Conflict,
        }
    }

    /// Picks the entry for a site/account: the given revision, or the newest one.
    pub fn find(&self, site: &str, account: &str, revision: Option<u32>) -> Result<&Entry> {
        let mut matches: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.settings.site_key() == site_key(site, e.settings.spec_version))
            .collect();
        if matches.is_empty() {
            return Err(format!("{site} の設定は登録されていません。先に generate してください"));
        }
        let accounts: Vec<String> = matches.iter().map(|e| e.settings.account.clone()).collect();
        matches.retain(|e| e.settings.account_key() == account_key(account, e.settings.spec_version));
        if matches.is_empty() {
            let mut names: Vec<String> =
                accounts.into_iter().map(|a| if a.is_empty() { "（なし）".into() } else { a }).collect();
            names.sort();
            names.dedup();
            return Err(format!("アカウント「{account}」の設定はありません。登録済み: {}", names.join(", ")));
        }
        match revision {
            Some(r) => matches
                .into_iter()
                .find(|e| e.settings.revision == r)
                .ok_or_else(|| format!("更新番号 {r} の設定はありません")),
            None => Ok(matches.into_iter().max_by_key(|e| e.settings.revision).expect("non-empty")),
        }
    }

    /// Registered entries for the page a browser is on. A subdomain matches its
    /// registered domain on a label boundary (`login.github.com` → `github.com`), never
    /// a mere suffix (`evilgithub.com` does not).
    pub fn entries_for_host(&self, host: &str) -> Vec<(usize, &Entry)> {
        let host = crate::phishing::decode_host(host);
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                let registered = e.settings.site_key();
                let here = site_key(&host, e.settings.spec_version);
                !registered.is_empty() && (here == registered || here.ends_with(&format!(".{registered}")))
            })
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=3).contains(&self.format_version) || self.spec_version != 1 {
            return Err("未対応のプロファイルバージョンです。codepass を更新してください".into());
        }
        self.salt_bytes()?;
        if self.entries.len() > 10000 {
            return Err("設定の件数が上限を超えています".into());
        }
        for entry in &self.entries {
            entry.settings.validate()?;
            match &entry.source_check {
                None => {
                    if hex::decode(&entry.source_sha256).map_err(|_| "コードハッシュが不正です")?.len() != 32
                    {
                        return Err("コードハッシュは32バイトである必要があります".into());
                    }
                }
                Some(check) => {
                    if !entry.source_sha256.is_empty()
                        || check.len() != 64
                        || !check.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err("封印した登録の形式が不正です".into());
                    }
                }
            }
            if entry.source_path.as_ref().is_some_and(|p| p.len() > 4096 || p.chars().any(char::is_control)) {
                return Err("ソースファイルのパスが不正です".into());
            }
            if entry.git_commit.as_ref().is_some_and(|c| {
                !(c.len() == 40 || c.len() == 64) || !c.bytes().all(|b| b.is_ascii_hexdigit())
            }) {
                return Err("GitのコミットIDが不正です".into());
            }
            if entry.material.as_deref().is_some_and(|m| m != crate::syntax::MATERIAL_ID) {
                return Err("未対応の材料の種類です。codepass を更新してください".into());
            }
            if entry.mac.as_ref().is_some_and(|m| m.len() != 64 || !m.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err("設定の署名の形式が不正です".into());
            }
        }
        if let Some(team) = &self.team {
            team.validate()?;
            if self.hardware_key.is_some() {
                return Err("チームの設定とセキュリティキーは同時に使えません".into());
            }
        }
        if let Some(r) = &self.rotation {
            if r.from.is_empty()
                || r.from.len() > 4096
                || r.pending.iter().any(|(i, _)| *i >= self.entries.len())
            {
                return Err("パスワードの一斉更新の記録が不正です".into());
            }
        }
        if let Some(key) = &self.hardware_key {
            let id_ok = hex::decode(&key.credential_id).is_ok_and(|id| (16..=1023).contains(&id.len()));
            if !id_ok || key.rp_id.is_empty() || key.rp_id.len() > 253 || !key.rp_id.is_ascii() {
                return Err("セキュリティキーの設定が不正です".into());
            }
        }
        Ok(())
    }
}

#[cfg(feature = "cli")]
pub fn default_path() -> Result<PathBuf> {
    directories::ProjectDirs::from("", "", "codepass")
        .map(|dirs| dirs.config_dir().join("profile.json"))
        .ok_or_else(|| "設定ディレクトリを特定できません。--config を指定してください".into())
}

pub fn load(path: &Path) -> Result<Profile> {
    let file = fs::File::open(path).map_err(|_| "設定を読み込めません。codepass initを実行してください")?;
    if !file.metadata().map_err(|_| "設定情報を取得できません")?.is_file() {
        return Err("設定には通常ファイルを指定してください".into());
    }
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| "設定を読み込めません")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("設定ファイルの上限は4MiBです".into());
    }
    let profile: Profile = serde_json::from_slice(&bytes).map_err(|_| "設定JSONの形式が不正です")?;
    profile.validate()?;
    Ok(profile)
}

// Never overwrite: a changed salt makes existing passwords unrecoverable.
pub fn save_new(path: &Path, profile: &Profile) -> Result<()> {
    profile.validate()?;
    let bytes = serde_json::to_vec_pretty(profile).map_err(|_| "設定の変換に失敗しました")?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|_| "設定ディレクトリを作成できません")?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file =
        options.open(path).map_err(|_| "ファイルを新規作成できません。既存の設定は上書きしません")?;
    file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|_| "設定の保存に失敗しました".into())
}

/// Rewrites an existing profile in place. The salt can never change here, and the
/// file is replaced atomically so a crash leaves either the old or the new version.
pub fn update<T>(path: &Path, f: impl FnOnce(&mut Profile) -> Result<T>) -> Result<T> {
    let mut profile = load(path)?;
    let (salt, hardware_key) = (profile.salt.clone(), profile.hardware_key.clone());
    let team_secret = profile.team.as_ref().map(|t| t.verifier.clone());
    let out = f(&mut profile)?;
    // A team may be re-split (new shares, same secret) but never get another secret.
    if profile.salt != salt
        || profile.hardware_key != hardware_key
        || profile.team.as_ref().map(|t| t.verifier.clone()) != team_secret
    {
        return Err("salt・セキュリティキー・チームの秘密は変更できません".into());
    }
    profile.format_version = 3;
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|_| "安全な乱数を取得できません")?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", hex::encode(nonce)));
    let tmp = PathBuf::from(tmp);
    save_new(&tmp, &profile)?;
    let result = (|| {
        if load(path)?.salt != salt {
            return Err("設定ファイルが別の処理で書き換えられました".to_string());
        }
        fs::rename(&tmp, path).map_err(|_| "設定の保存に失敗しました".to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map(|_| out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_roundtrip_and_no_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let p = Profile::new().unwrap();
        save_new(&path, &p).unwrap();
        assert_eq!(p.salt, load(&path).unwrap().salt);
        assert!(save_new(&path, &Profile::new().unwrap()).is_err());
        let bytes = fs::read_to_string(path).unwrap();
        assert!(!bytes.contains("secret"));
        assert!(!bytes.contains("password"));
    }

    fn entry(site: &str, revision: u32, hash: u8) -> Entry {
        Entry {
            source_sha256: hex::encode([hash; 32]),
            source_path: Some("/x/main.rs".into()),
            git_commit: None,
            mac: None,
            material: None,
            source_check: None,
            settings: Settings {
                site: site.into(),
                account: "".into(),
                length: 24,
                charset: crate::crypto::Charset::Strong,
                revision,
                require_classes: true,
                spec_version: 1,
                symbols: None,
            },
        }
    }

    #[test]
    fn entry_signature_detects_any_edit_and_a_wrong_secret() {
        let key = [3u8; 32];
        let mut e = entry("github.com", 1, 1);
        assert!(matches!(e.verify(&key), MacStatus::Missing));
        e.sign(&key);
        assert!(matches!(e.verify(&key), MacStatus::Valid));
        assert!(matches!(e.verify(&[4u8; 32]), MacStatus::Invalid), "another master key (typo) fails");
        let edits: [fn(&mut Entry); 7] = [
            |e| e.material = Some("syntax-v1".into()),
            |e| e.settings.site = "evil.example".into(),
            |e| e.settings.length = 8,
            |e| e.settings.revision = 2,
            |e| e.source_path = Some("/tmp/attacker.rs".into()),
            |e| e.git_commit = Some("a".repeat(40)),
            |e| e.source_sha256 = hex::encode([2u8; 32]),
        ];
        for edit in edits {
            let mut t = e.clone();
            edit(&mut t);
            assert!(matches!(t.verify(&key), MacStatus::Invalid));
        }
        // Case of the hash does not matter (it is compared case-insensitively elsewhere).
        let mut upper = e.clone();
        upper.source_sha256 = upper.source_sha256.to_uppercase();
        assert!(matches!(upper.verify(&key), MacStatus::Valid));
    }

    #[test]
    fn entries_for_host_matches_subdomains_on_label_boundaries() {
        let mut p = Profile::new().unwrap();
        let mut gh = entry("github.com", 1, 1);
        gh.settings.spec_version = 2;
        p.entries = vec![gh, entry("example.com", 1, 2)];
        let hits = |host: &str| p.entries_for_host(host).iter().map(|(i, _)| *i).collect::<Vec<_>>();
        assert_eq!(hits("github.com"), [0]);
        assert_eq!(hits("www.github.com"), [0]);
        assert_eq!(hits("login.GitHub.com"), [0]);
        assert!(hits("evilgithub.com").is_empty());
        assert!(hits("github.com.evil.example").is_empty());
        assert!(hits("g\u{456}thub.com").is_empty());
        assert_eq!(hits("example.com"), [1]);
        assert!(hits("xn--gthub-n2e.com").is_empty(), "Punycode look-alike");
    }

    #[test]
    fn sealing_hides_the_hash_but_keeps_the_entry_usable() {
        let master = [7u8; 32];
        let code = [1u8; 32];
        let mut e = entry("github.com", 1, 1);
        let plain = e.clone();
        e.seal(&master).unwrap();
        e.sign(&master);
        assert!(e.is_sealed() && e.source_sha256.is_empty());
        let json = serde_json::to_string(&e).unwrap();
        assert!(!json.contains(&hex::encode(code)), "the code hash is not in the file");
        assert!(e.code_matches(&code, &master));
        assert!(!e.code_matches(&[2u8; 32], &master), "other code");
        assert!(!e.code_matches(&code, &[8u8; 32]), "other master key");
        assert!(matches!(e.verify(&master), MacStatus::Valid));
        // Without the master key a sealed and an unsealed entry cannot be compared;
        // with it, they are recognised as the same password.
        assert!(!e.same_password(&plain, None));
        assert!(e.same_password(&plain, Some(&master)));
        // Tampering with the check value is caught by the signature.
        let mut t = e.clone();
        t.source_check = Some("0".repeat(64));
        assert!(matches!(t.verify(&master), MacStatus::Invalid));
        // A sealed entry must not also carry a hash.
        let mut p = Profile::new().unwrap();
        let mut both = e.clone();
        both.source_sha256 = hex::encode(code);
        p.entries = vec![both];
        assert!(p.validate().is_err());
    }

    #[test]
    fn update_refuses_to_change_the_hardware_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        save_new(&path, &Profile::new().unwrap()).unwrap();
        let result = update(&path, |p| {
            p.hardware_key = Some(HardwareKey { credential_id: "00".repeat(32), rp_id: "codepass".into() });
            Ok(())
        });
        assert!(result.is_err());
        assert!(load(&path).unwrap().hardware_key.is_none());
    }

    #[test]
    fn update_keeps_salt_and_never_silently_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let p = Profile::new().unwrap();
        save_new(&path, &p).unwrap();
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 1, 1), false, None))).unwrap(),
            Saved::Added
        ));
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 1, 1), false, None))).unwrap(),
            Saved::Unchanged
        ));
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 1, 2), false, None))).unwrap(),
            Saved::Conflict
        ));
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 2, 2), false, None))).unwrap(),
            Saved::Added
        ));
        assert!(update(&path, |p| {
            p.salt = "00".repeat(16);
            Ok(())
        })
        .is_err());
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.salt, p.salt);
        assert_eq!(loaded.entries[0].source_sha256, hex::encode([1u8; 32]));
        assert_eq!(loaded.find("github.com", "", None).unwrap().settings.revision, 2);
        assert_eq!(loaded.find("github.com", "", Some(1)).unwrap().settings.revision, 1);
        assert!(loaded.find("example.com", "", None).is_err());
        assert!(loaded.find("github.com", "work", None).is_err());
        // v1 entries keep exact matching; v2 entries match any spelling of the host.
        assert!(loaded.find("GitHub.com", "", None).is_err());
        let mut v2 = entry("https://www.GitHub.com/login", 1, 3);
        v2.settings.spec_version = 2;
        let mut p2 = loaded.clone();
        p2.entries = vec![v2];
        assert_eq!(p2.find("github.com", "", None).unwrap().settings.revision, 1);
        assert!(p2.entries[0].same_key(&entry("GITHUB.com", 1, 3).settings));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1, "no temp files left behind");
    }
}
