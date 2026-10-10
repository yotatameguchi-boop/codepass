pub mod crypto;
pub mod profile;

use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_SOURCE_BYTES: u64 = 1024 * 1024;

pub fn source_hash(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path).map_err(|_| "ソースファイルを開けません".to_string())?;
    if !file.metadata().map_err(|_| "ファイル情報を取得できません")?.is_file() {
        return Err("通常ファイルを指定してください".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|_| "ソースファイルを読み込めません")?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("ソースファイルの上限は1MiBです".into());
    }
    Ok(Sha256::digest(bytes).into())
}
