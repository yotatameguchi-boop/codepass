use crate::{crypto::Settings, Result};
use serde::{Deserialize, Serialize};
use std::{fs::{self, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

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
}

impl Profile {
    pub fn new() -> Result<Self> {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| "安全な乱数を取得できません")?;
        Ok(Self { format_version: 1, spec_version: 1, salt: hex::encode(salt), entries: vec![] })
    }
    pub fn salt_bytes(&self) -> Result<[u8; 16]> {
        let bytes = hex::decode(&self.salt).map_err(|_| "saltの形式が不正です")?;
        bytes.try_into().map_err(|_| "saltは16バイトである必要があります".into())
    }
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1 || self.spec_version != 1 { return Err("未対応のプロファイルバージョンです".into()); }
        self.salt_bytes()?;
        if self.entries.len() > 10000 { return Err("設定の件数が上限を超えています".into()); }
        for entry in &self.entries {
            entry.settings.validate()?;
            if hex::decode(&entry.source_sha256).map_err(|_| "コードハッシュが不正です")?.len() != 32 {
                return Err("コードハッシュは32バイトである必要があります".into());
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
    if !file.metadata().map_err(|_| "設定情報を取得できません")?.is_file() { return Err("設定には通常ファイルを指定してください".into()); }
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| "設定を読み込めません")?;
    if bytes.len() > 4 * 1024 * 1024 { return Err("設定ファイルの上限は4MiBです".into()); }
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
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| "ファイルを新規作成できません。既存の設定は上書きしません")?;
    file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|_| "設定の保存に失敗しました".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_roundtrip_and_no_overwrite() {
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("profile.json");
        let p = Profile::new().unwrap(); save_new(&path, &p).unwrap();
        assert_eq!(p.salt, load(&path).unwrap().salt);
        assert!(save_new(&path, &Profile::new().unwrap()).is_err());
        let bytes = fs::read_to_string(path).unwrap();
        assert!(!bytes.contains("secret")); assert!(!bytes.contains("password"));
    }
}
