use crate::{Result, MAX_SOURCE_BYTES};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Where the code bytes came from, so the same bytes can be read again later.
pub struct Loaded {
    pub sha256: [u8; 32],
    /// Absolute path (the file in the working tree, or the path inside the commit).
    pub path: PathBuf,
    /// Full commit hash when read from Git.
    pub git_commit: Option<String>,
}

pub fn load(path: &Path, git_rev: Option<&str>) -> Result<Loaded> {
    load_material(path, git_rev, None)
}

/// Like `load`, with `material` choosing how the bytes become the hash
/// (None = the bytes themselves, Some("syntax-v1") = crate::syntax).
pub fn load_material(path: &Path, git_rev: Option<&str>, material: Option<&str>) -> Result<Loaded> {
    let (bytes, git_commit) = read_bytes(path, git_rev)?;
    let sha256 = material_hash(&bytes, path, material)?;
    Ok(Loaded { sha256, path: absolute(path)?, git_commit })
}

/// Whether the file sits in a Git repository that has a remote (offline check: it
/// only reads the repository's configuration). Such code may well be public.
pub fn has_git_remote(path: &Path) -> bool {
    let Ok(full) = absolute(path) else { return false };
    let Some(dir) = full.parent().filter(|d| d.is_dir()) else { return false };
    git(dir, &["remote"]).is_ok_and(|out| !out.iter().all(u8::is_ascii_whitespace))
}

/// The file's bytes, from the working tree or from a commit (with its full id).
pub fn read_bytes(path: &Path, git_rev: Option<&str>) -> Result<(Vec<u8>, Option<String>)> {
    match git_rev {
        None => Ok((crate::read_source(path)?, None)),
        Some(rev) => {
            let (commit, bytes) = read_git(path, rev)?;
            Ok((bytes, Some(commit)))
        }
    }
}

pub fn material_hash(bytes: &[u8], path: &Path, material: Option<&str>) -> Result<[u8; 32]> {
    match material {
        None => Ok(Sha256::digest(bytes).into()),
        Some(crate::syntax::MATERIAL_ID) => {
            let name =
                path.file_name().and_then(|n| n.to_str()).ok_or("ファイル名はUTF-8である必要があります")?;
            crate::syntax::hash(bytes, name)
        }
        Some(other) => Err(format!("未対応の材料の種類です: {other}")),
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
    let mut child = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "gitコマンドを実行できません")?;
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or("gitの出力を読めません")?
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "gitの出力を読めません")?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("ソースファイルの上限は1MiBです".into());
    }
    if !child.wait().map_err(|_| "gitの終了を待てません")?.success() {
        return Err("gitが失敗しました".into());
    }
    Ok(bytes)
}
