use crate::{Result, MAX_SOURCE_BYTES};
use sha2::{Digest, Sha256};
use std::{io::Read, path::{Path, PathBuf}, process::{Command, Stdio}};

/// Where the code bytes came from, so the same bytes can be read again later.
pub struct Loaded {
    pub sha256: [u8; 32],
    /// Absolute path (the file in the working tree, or the path inside the commit).
    pub path: PathBuf,
    /// Full commit hash when read from Git.
    pub git_commit: Option<String>,
}

pub fn load(path: &Path, git_rev: Option<&str>) -> Result<Loaded> {
    match git_rev {
        None => Ok(Loaded { sha256: crate::source_hash(path)?, path: absolute(path)?, git_commit: None }),
        Some(rev) => {
            let (commit, bytes) = read_git(path, rev)?;
            Ok(Loaded { sha256: Sha256::digest(bytes).into(), path: absolute(path)?, git_commit: Some(commit) })
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    path.file_name().ok_or("ファイル名を指定してください")?;
    std::path::absolute(path).map_err(|_| "ファイルの場所を特定できません".into())
}

// Reads the blob stored in the commit, so editing the file or Git's
// line-ending conversion in the working tree never changes the password.
fn read_git(path: &Path, rev: &str) -> Result<(String, Vec<u8>)> {
    if rev.is_empty() || rev.starts_with('-') || rev.chars().any(|c| c.is_control() || c == ':') {
        return Err("--git にはコミットID・タグ・ブランチ名を指定してください".into());
    }
    let full = absolute(path)?;
    let dir = full.parent().filter(|d| d.is_dir()).ok_or("ファイルのあるディレクトリが見つかりません")?;
    let name = full.file_name().and_then(|n| n.to_str()).ok_or("ファイル名はUTF-8である必要があります")?;
    let commit = git(dir, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")])
        .map_err(|_| format!("Gitのコミット「{rev}」が見つかりません"))?;
    let commit = String::from_utf8(commit).map_err(|_| "Gitの出力が不正です")?.trim().to_string();
    if !(commit.len() == 40 || commit.len() == 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Gitのコミットを特定できません".into());
    }
    let bytes = git(dir, &["cat-file", "blob", &format!("{commit}:./{name}")])
        .map_err(|_| "そのコミットにこのファイルはありません".to_string())?;
    Ok((commit, bytes))
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut child = Command::new("git").arg("-C").arg(dir)
        .args(["-c", "core.fsmonitor=false"]).args(args)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "gitコマンドを実行できません")?;
    let mut bytes = Vec::new();
    child.stdout.take().ok_or("gitの出力を読めません")?
        .take(MAX_SOURCE_BYTES + 1).read_to_end(&mut bytes).map_err(|_| "gitの出力を読めません")?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("ソースファイルの上限は1MiBです".into());
    }
    if !child.wait().map_err(|_| "gitの終了を待てません")?.success() { return Err("gitが失敗しました".into()); }
    Ok(bytes)
}
