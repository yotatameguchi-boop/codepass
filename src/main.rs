use clap::{Args, Parser, Subcommand};
use codepass::{crypto::{self, Charset, Settings}, profile::{self, Entry, Saved}, source, Result};
use std::{io::{self, IsTerminal, Write}, path::PathBuf, sync::mpsc, time::Duration};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "ソースコードから再現可能なパスワードを生成する実験的なオフラインCLI")]
struct Cli {
    #[arg(long, global = true, help = "設定ファイルのパス")]
    config: Option<PathBuf>,
    #[command(subcommand)] command: Command,
}

#[derive(Args)]
struct Output {
    #[arg(long, help = "生成結果を確認なしで標準出力に出す（リダイレクト可）")]
    reveal: bool,
    #[arg(long, conflicts_with = "reveal", help = "生成結果をクリップボードにコピーし、一定時間後に消す")]
    copy: bool,
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(5..=600),
        help = "クリップボードを消すまでの秒数")]
    clear_after: u64,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "saltを生成して初期設定を作る")]
    Init,
    #[command(about = "ソースコードからパスワードを生成し、設定を登録する")]
    Generate {
        source: PathBuf,
        #[arg(long)] site: String,
        #[arg(long, default_value = "")] account: String,
        #[arg(long, default_value_t = 24)] length: usize,
        #[arg(long, value_enum, default_value_t = Charset::Strong)] charset: Charset,
        #[arg(long, default_value_t = 1)] revision: u32,
        #[arg(long, default_value_t = 1)] spec_version: u32,
        #[arg(long, help = "各文字種を必ず含む条件を解除")]
        no_require_classes: bool,
        #[arg(long, value_name = "REV", help = "作業中のファイルではなく、Gitのこのコミットに入っている内容を使う")]
        git: Option<String>,
        #[arg(long, help = "設定を登録しない")]
        no_save: bool,
        #[arg(long, conflicts_with = "no_save", help = "同じサービス・更新番号の登録済み設定を置き換える")]
        replace: bool,
        #[arg(long, help = "今回の非秘密設定とsaltを新規ファイルにエクスポート")]
        export_settings: Option<PathBuf>,
        #[command(flatten)] output: Output,
    },
    #[command(about = "登録済みの設定からパスワードを呼び出す")]
    Get {
        site: String,
        #[arg(long, default_value = "")] account: String,
        #[arg(long, help = "省略時は最新の更新番号")] revision: Option<u32>,
        #[command(flatten)] output: Output,
    },
    #[command(about = "バックアップ済みの設定エントリからパスワードを再生成")]
    Regenerate {
        source: PathBuf,
        #[arg(long, help = "profile list で表示される番号")] entry: usize,
        #[command(flatten)] output: Output,
    },
    Profile { #[command(subcommand)] command: ProfileCommand },
}

#[derive(Subcommand)]
enum ProfileCommand {
    Export { #[arg(long)] output: PathBuf },
    Import { input: PathBuf },
    #[command(about = "保存済みの設定エントリを一覧表示")]
    List,
    #[command(about = "設定エントリを削除（そのパスワードは get で呼び出せなくなる）")]
    Remove { entry: usize },
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.config { Some(p) => p, None => profile::default_path()? };
    match cli.command {
        Command::Init => {
            profile::save_new(&path, &profile::Profile::new()?)?;
            eprintln!("初期設定を作成しました: {}\nprofile exportでsaltをバックアップしてください。", path.display());
        }
        Command::Profile { command } => match command {
            ProfileCommand::Export { output } => {
                profile::save_new(&output, &profile::load(&path)?)?;
                eprintln!("非秘密設定をエクスポートしました: {}", output.display());
            }
            ProfileCommand::Import { input } => {
                profile::save_new(&path, &profile::load(&input)?)?;
                eprintln!("設定を復元しました: {}", path.display());
            }
            ProfileCommand::List => {
                for (i, e) in profile::load(&path)?.entries.iter().enumerate() {
                    let s = &e.settings;
                    let from = match (&e.source_path, &e.git_commit) {
                        (Some(p), Some(c)) => format!("{p} @ {}", &c[..12]),
                        (Some(p), None) => p.clone(),
                        _ => format!("コード{}", &e.source_sha256[..16]),
                    };
                    println!("{}\t{}\t{}\t長さ{} {:?} 更新{} v{}\t{}", i + 1, s.site, s.account,
                        s.length, s.charset, s.revision, s.spec_version, from);
                }
            }
            ProfileCommand::Remove { entry } => {
                let removed = profile::update(&path, |p| {
                    let i = entry.checked_sub(1).filter(|&i| i < p.entries.len())
                        .ok_or("指定された番号の設定エントリがありません")?;
                    Ok(p.entries.remove(i))
                })?;
                eprintln!("削除しました: {} 更新{}", removed.settings.site, removed.settings.revision);
            }
        },
        Command::Get { site, account, revision, output } => {
            let p = profile::load(&path)?;
            let e = p.find(&site, &account, revision)?;
            let file = e.source_path.as_ref()
                .ok_or("この設定にはファイルの場所が記録されていません。regenerate を使ってください")?;
            let loaded = source::load(file.as_ref(), e.git_commit.as_deref())?;
            if !hex::encode(loaded.sha256).eq_ignore_ascii_case(&e.source_sha256) {
                return Err(format!("{file} の内容が登録時と変わっています（1バイトでも違うと別のパスワードになります）。\
                    元の内容に戻すか、次からは --git でコミットを指定して登録してください"));
            }
            let password = prompt_and_derive(&p, &loaded.sha256, &e.settings)?;
            present(&password, e.settings.length, &output)?;
        }
        Command::Regenerate { source, entry, output } => {
            let p = profile::load(&path)?;
            let e = entry.checked_sub(1).and_then(|i| p.entries.get(i))
                .ok_or("指定された番号の設定エントリがありません")?;
            let loaded = source::load(&source, e.git_commit.as_deref())?;
            if !hex::encode(loaded.sha256).eq_ignore_ascii_case(&e.source_sha256) {
                return Err("ソースコードの内容が保存時と一致しません（1バイトでも違うと別のパスワードになります）".into());
            }
            let password = prompt_and_derive(&p, &loaded.sha256, &e.settings)?;
            present(&password, e.settings.length, &output)?;
        }
        Command::Generate { source, site, account, length, charset, revision, spec_version,
            no_require_classes, git, no_save, replace, export_settings, output } => {
            let settings = Settings { site, account, length, charset, revision,
                require_classes: !no_require_classes, spec_version };
            settings.validate()?;
            let mut p = profile::load(&path)?;
            let loaded = source::load(&source, git.as_deref())?;
            let source_path = loaded.path.to_str().map(str::to_string);
            if source_path.is_none() && !no_save { eprintln!("警告: パスがUTF-8でないため、ファイルの場所は記録しません"); }
            let entry = Entry { source_sha256: hex::encode(loaded.sha256), settings: settings.clone(),
                source_path, git_commit: loaded.git_commit.clone() };
            // Check before asking for the secret: a mismatch usually means the file changed.
            if !no_save && !replace {
                if let Some(old) = p.entries.iter().find(|e| e.same_key(&settings) && !e.same_password(&entry)) {
                    let why = if old.source_sha256.eq_ignore_ascii_case(&entry.source_sha256) {
                        "文字数や文字種の設定"
                    } else { "コードの内容" };
                    return Err(format!(
                        "{}（更新番号{}）は登録済みですが、{}が違うので別のパスワードになります。\n  \
                        登録済みのものを出す: codepass get {}{}\n  \
                        パスワードを更新する: --revision {} を付ける\n  \
                        登録を置き換える: --replace / 登録せずに出す: --no-save",
                        settings.site, revision, why, settings.site,
                        if settings.account.is_empty() { String::new() } else { format!(" --account {}", settings.account) },
                        p.entries.iter().filter(|e| crypto::normalize(&e.settings.site) == crypto::normalize(&settings.site)
                            && crypto::normalize(&e.settings.account) == crypto::normalize(&settings.account))
                            .map(|e| e.settings.revision).max().unwrap_or(revision).saturating_add(1)));
                }
            }
            let password = prompt_and_derive(&p, &loaded.sha256, &settings)?;
            if !no_save {
                match profile::update(&path, |p| Ok(p.upsert(entry.clone(), replace)))? {
                    Saved::Added => eprintln!("設定を登録しました。次からは codepass get {} で呼び出せます", settings.site),
                    Saved::Replaced => eprintln!("登録済みの設定を置き換えました"),
                    Saved::Unchanged => {}
                    Saved::Conflict => eprintln!("警告: 登録済みの設定と違うため、登録しませんでした"),
                }
            }
            if let Some(out) = export_settings {
                p.entries.push(entry);
                profile::save_new(&out, &p)?;
                eprintln!("生成設定をエクスポートしました: {}", out.display());
            }
            present(&password, length, &output)?;
        }
    }
    Ok(())
}

fn prompt_and_derive(p: &profile::Profile, hash: &[u8; 32], settings: &Settings) -> Result<Zeroizing<String>> {
    settings.validate()?;
    if !io::stdin().is_terminal() { return Err("マスターシークレットは対話端末から入力してください".into()); }
    if settings.length < 15 { eprintln!("警告: 15文字未満です。20文字以上を推奨します。"); }
    let secret = Zeroizing::new(rpassword::prompt_password("Master secret: ")
        .map_err(|_| "非表示入力に失敗しました")?);
    let master = crypto::master_key(&secret, &p.salt_bytes()?)?;
    eprintln!("確認コード: {}（いつもと違えば打ち間違いです）", crypto::check_code(&master)?);
    let password = crypto::derive_with_master(&master, hash, settings)?;
    eprintln!("仕様: v{} / コードSHA-256: {} / 更新番号: {}", settings.spec_version, hex::encode(hash), settings.revision);
    Ok(password)
}

fn present(password: &str, length: usize, output: &Output) -> Result<()> {
    if output.copy { return copy_to_clipboard(password, output.clear_after); }
    if output.reveal { return print_password(password); }
    eprintln!("生成結果: {}", "*".repeat(length));
    if !io::stdout().is_terminal() { return Ok(()); }
    eprint!("表示するには reveal、コピーするには copy と入力してください: ");
    io::stderr().flush().map_err(|_| "端末への出力に失敗しました")?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).map_err(|_| "入力に失敗しました")?;
    match answer.trim() {
        "reveal" => print_password(password),
        "copy" => copy_to_clipboard(password, output.clear_after),
        _ => Ok(()),
    }
}

fn print_password(password: &str) -> Result<()> {
    let stdout = io::stdout(); let mut out = stdout.lock();
    writeln!(out, "{}", password).map_err(|_| "生成結果の出力に失敗しました".into())
}

#[cfg(target_os = "macos")] use arboard::SetExtApple as _;
#[cfg(windows)] use arboard::SetExtWindows as _;
#[cfg(all(unix, not(target_os = "macos")))] use arboard::SetExtLinux as _;

// Stays running until the timeout: on Linux the clipboard content lives in this process.
fn copy_to_clipboard(password: &str, clear_after: u64) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().map_err(|_| "クリップボードを使えません")?;
    clipboard.set().exclude_from_history().text(password).map_err(|_| "クリップボードにコピーできません")?;
    eprintln!("クリップボードにコピーしました。{clear_after}秒後に消去します（Enterですぐ消去）");
    let (tx, rx) = mpsc::channel();
    let on_interrupt = tx.clone();
    ctrlc::set_handler(move || { let _ = on_interrupt.send(()); })
        .map_err(|_| "Ctrl+C の処理を設定できません")?;
    if io::stdin().is_terminal() {
        std::thread::spawn(move || { let mut line = String::new(); let _ = io::stdin().read_line(&mut line); let _ = tx.send(()); });
    }
    let _ = rx.recv_timeout(Duration::from_secs(clear_after));
    // Only clear if it is still ours, so something the user copied meanwhile survives.
    let current = clipboard.get_text().map(Zeroizing::new);
    match current {
        Ok(text) if *text == password => {
            clipboard.clear().map_err(|_| "クリップボードを消去できません")?;
            eprintln!("クリップボードを消去しました");
        }
        _ => eprintln!("クリップボードの内容が変わっていたので、そのままにしました"),
    }
    Ok(())
}

fn main() {
    if let Err(message) = run() { eprintln!("codepass: {}", message); std::process::exit(1); }
}
