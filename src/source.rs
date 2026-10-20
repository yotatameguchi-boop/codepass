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
    load_material(path, git_rev, None, None)
}

pub const TREE_MATERIAL_ID: &str = "tree-v1";

/// Like `load`, with `material` choosing how the bytes become the hash
/// (None = the bytes themselves, Some("syntax-v1") = crate::syntax).
pub fn load_material(
    path: &Path,
    git_rev: Option<&str>,
    material: Option<&str>,
    symbol: Option<&str>,
) -> Result<Loaded> {
    if material == Some(TREE_MATERIAL_ID) {
        let rev = git_rev.ok_or("リポジトリ単位の材料（--tree）は --git でコミットを指定して使います")?;
        let (commit, tree) = read_tree(path, rev)?;
        let mut h = Sha256::new();
        h.update(format!("CodePass/{TREE_MATERIAL_ID}\0").as_bytes());
        h.update(tree.as_bytes());
        let path = std::path::absolute(path).map_err(|_| "フォルダの場所を特定できません")?;
        return Ok(Loaded { sha256: h.finalize().into(), path, git_commit: Some(commit) });
    }
    let (bytes, git_commit) = read_bytes(path, git_rev)?;
    let sha256 = material_hash(&bytes, path, material, symbol)?;
    Ok(Loaded { sha256, path: absolute(path)?, git_commit })
}

fn resolve_commit(dir: &Path, rev: &str) -> Result<String> {
    if rev.is_empty() || rev.starts_with('-') || rev.chars().any(|c| c.is_control() || c == ':') {
        return Err("--git にはコミットID・タグ・ブランチ名を指定してください".into());
    }
    let commit = git(dir, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")])
        .map_err(|_| format!("Gitのコミット「{rev}」が見つかりません"))?;
    let commit = String::from_utf8(commit).map_err(|_| "Gitの出力が不正です")?.trim().to_string();
    if !(commit.len() == 40 || commit.len() == 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Gitのコミットを特定できません".into());
    }
    Ok(commit)
}

/// The Git tree object of a directory in a commit: every file below it, by content.
/// Any change anywhere in the directory gives a different id.
fn read_tree(dir: &Path, rev: &str) -> Result<(String, String)> {
    let dir = std::path::absolute(dir).map_err(|_| "フォルダの場所を特定できません")?;
    if !dir.is_dir() {
        return Err("--tree にはフォルダ（リポジトリやその中のディレクトリ）を指定してください".into());
    }
    let commit = resolve_commit(&dir, rev)?;
    let tree = git(&dir, &["rev-parse", "--verify", "--quiet", &format!("{commit}:./")])
        .map_err(|_| "そのコミットにこのフォルダはありません".to_string())?;
    let tree = String::from_utf8(tree).map_err(|_| "Gitの出力が不正です")?.trim().to_string();
    if !(tree.len() == 40 || tree.len() == 64) || !tree.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Gitのツリーを特定できません".into());
    }
    Ok((commit, tree))
}

/// Tree id and number of files of a directory in a commit (what a tree material covers).
pub fn tree_summary(dir: &Path, rev: &str) -> Result<(String, String, usize)> {
    let (commit, tree) = read_tree(dir, rev)?;
    let dir = std::path::absolute(dir).map_err(|_| "フォルダの場所を特定できません")?;
    let list = git(&dir, &["ls-tree", "-r", "--name-only", &tree])?;
    let files = list.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count();
    Ok((commit, tree, files))
}

/// Checks that `commit` carries a good signature (Git's own verification: GPG, or SSH
/// with gpg.ssh.allowedSignersFile) and returns the signing key.
pub fn signer_of(path: &Path, commit: &str) -> Result<String> {
    let full = std::path::absolute(path).map_err(|_| "場所を特定できません")?;
    let dir = if full.is_dir() {
        full
    } else {
        full.parent().ok_or("フォルダを特定できません")?.to_path_buf()
    };
    let out = git(&dir, &["log", "-1", "--format=%G?%x00%GK", commit])?;
    let out = String::from_utf8(out).map_err(|_| "Gitの出力が不正です")?;
    let (status, key) = out.trim_end().split_once('\0').unwrap_or(("N", ""));
    match status {
        "G" if !key.is_empty() => Ok(key.to_string()),
        "N" => Err("このコミットには署名がありません（--require-signed）".into()),
        _ => Err(format!(
            "このコミットの署名を確かめられません（状態 {status}）。署名に使った鍵が信頼済みか確かめてください"
        )),
    }
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

pub fn material_hash(
    bytes: &[u8],
    path: &Path,
    material: Option<&str>,
    symbol: Option<&str>,
) -> Result<[u8; 32]> {
    let name = || path.file_name().and_then(|n| n.to_str()).ok_or("ファイル名はUTF-8である必要があります");
    match material {
        None => Ok(Sha256::digest(bytes).into()),
        Some(crate::syntax::MATERIAL_ID) => crate::syntax::hash(bytes, name()?),
        Some(crate::syntax::SYMBOL_MATERIAL_ID) => {
            crate::syntax::symbol_hash(bytes, name()?, symbol.ok_or("関数単位の材料には関数名が必要です")?)
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
    let commit = resolve_commit(dir, rev)?;
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
