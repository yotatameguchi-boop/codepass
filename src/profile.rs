use crate::{
    crypto::{account_key, site_key, Settings},
    Result,
};
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub source_sha256: String,
    pub settings: Settings,
    /// Where the code was read from (format 2+). Lets `get` find it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Full commit hash when the code was read from Git (format 2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
}

impl Entry {
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
    pub fn same_password(&self, other: &Entry) -> bool {
        let (a, b) = (&self.settings, &other.settings);
        self.same_key(b)
            && self.source_sha256.eq_ignore_ascii_case(&other.source_sha256)
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
        Ok(Self { format_version: 2, spec_version: 1, salt: hex::encode(salt), entries: vec![] })
    }
    pub fn salt_bytes(&self) -> Result<[u8; 16]> {
        let bytes = hex::decode(&self.salt).map_err(|_| "saltの形式が不正です")?;
        bytes.try_into().map_err(|_| "saltは16バイトである必要があります".into())
    }
    /// Adds or updates an entry. A different password under the same key is never
    /// overwritten unless `replace` is set, because the old one would be lost.
    pub fn upsert(&mut self, entry: Entry, replace: bool) -> Saved {
        match self.entries.iter_mut().find(|e| e.same_key(&entry.settings)) {
            None => {
                self.entries.push(entry);
                Saved::Added
            }
            Some(e) if e.same_password(&entry) => {
                if e.source_path.is_none() || entry.git_commit.is_some() {
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

    pub fn validate(&self) -> Result<()> {
        if !(1..=2).contains(&self.format_version) || self.spec_version != 1 {
            return Err("未対応のプロファイルバージョンです。codepass を更新してください".into());
        }
        self.salt_bytes()?;
        if self.entries.len() > 10000 {
            return Err("設定の件数が上限を超えています".into());
        }
        for entry in &self.entries {
            entry.settings.validate()?;
            if hex::decode(&entry.source_sha256).map_err(|_| "コードハッシュが不正です")?.len() != 32
            {
                return Err("コードハッシュは32バイトである必要があります".into());
            }
            if entry.source_path.as_ref().is_some_and(|p| p.len() > 4096 || p.chars().any(char::is_control)) {
                return Err("ソースファイルのパスが不正です".into());
            }
            if entry.git_commit.as_ref().is_some_and(|c| {
                !(c.len() == 40 || c.len() == 64) || !c.bytes().all(|b| b.is_ascii_hexdigit())
            }) {
                return Err("GitのコミットIDが不正です".into());
            }
        }
        Ok(())
    }
}

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
    let salt = profile.salt.clone();
    let out = f(&mut profile)?;
    if profile.salt != salt {
        return Err("saltは変更できません".into());
    }
    profile.format_version = 2;
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
    fn update_keeps_salt_and_never_silently_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let p = Profile::new().unwrap();
        save_new(&path, &p).unwrap();
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 1, 1), false))).unwrap(),
            Saved::Added
        ));
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 1, 1), false))).unwrap(),
            Saved::Unchanged
        ));
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 1, 2), false))).unwrap(),
            Saved::Conflict
        ));
        assert!(matches!(
            update(&path, |p| Ok(p.upsert(entry("github.com", 2, 2), false))).unwrap(),
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
