use clap::{Parser, Subcommand};
use codepass::{crypto::{self, Charset, Settings}, profile::{self, Entry}, source_hash, Result};
use std::{io::{self, IsTerminal, Write}, path::PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "ソースコードから再現可能なパスワードを生成する実験的なオフラインCLI")]
struct Cli {
    #[arg(long, global = true, help = "設定ファイルのパス")]
    config: Option<PathBuf>,
    #[command(subcommand)] command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
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
        #[arg(long, help = "生成結果を明示的に表示する（リダイレクト可）")]
        reveal: bool,
        #[arg(long, help = "今回の非秘密設定とsaltを新規ファイルにエクスポート")]
        export_settings: Option<PathBuf>,
    },
    #[command(about = "バックアップ済みの設定エントリからパスワードを再生成")]
    Regenerate {
        source: PathBuf,
        #[arg(long, help = "profile list で表示される番号")] entry: usize,
        #[arg(long, help = "生成結果を明示的に表示する（リダイレクト可）")]
        reveal: bool,
    },
    Profile { #[command(subcommand)] command: ProfileCommand },
}

#[derive(Subcommand)]
enum ProfileCommand {
    Export { #[arg(long)] output: PathBuf },
    Import { input: PathBuf },
    #[command(about = "保存済みの設定エントリを一覧表示")]
    List,
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
                    println!("{}\t{}\t{}\t長さ{} {:?} 更新{} v{}\tコード{}", i + 1, s.site, s.account,
                        s.length, s.charset, s.revision, s.spec_version, &e.source_sha256[..16]);
                }
            }
        },
        Command::Regenerate { source, entry, reveal } => {
            let p = profile::load(&path)?;
            let e = entry.checked_sub(1).and_then(|i| p.entries.get(i))
                .ok_or("指定された番号の設定エントリがありません")?;
            let hash = source_hash(&source)?;
            if !hex::encode(hash).eq_ignore_ascii_case(&e.source_sha256) {
                return Err("ソースコードの内容が保存時と一致しません（1バイトでも違うと別のパスワードになります）".into());
            }
            let password = prompt_and_derive(&p, &hash, &e.settings)?;
            present(&password, e.settings.length, reveal)?;
        }
        Command::Generate { source, site, account, length, charset, revision, spec_version,
            no_require_classes, reveal, export_settings } => {
            let settings = Settings { site, account, length, charset, revision,
                require_classes: !no_require_classes, spec_version };
            settings.validate()?;
            let mut p = profile::load(&path)?;
            let hash = source_hash(&source)?;
            let password = prompt_and_derive(&p, &hash, &settings)?;
            if let Some(output) = export_settings {
                p.entries.push(Entry { source_sha256: hex::encode(hash), settings });
                profile::save_new(&output, &p)?;
                eprintln!("生成設定をエクスポートしました: {}", output.display());
            }
            present(&password, length, reveal)?;
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
    let password = crypto::derive(&secret, &p.salt_bytes()?, hash, settings)?;
    eprintln!("仕様: v{} / コードSHA-256: {} / 更新番号: {}", settings.spec_version, hex::encode(hash), settings.revision);
    Ok(password)
}

fn present(password: &str, length: usize, reveal: bool) -> Result<()> {
    let show = if reveal { true } else {
        eprintln!("生成結果: {}", "*".repeat(length));
        if io::stdout().is_terminal() {
            eprint!("表示するには reveal と入力してください: ");
            io::stderr().flush().map_err(|_| "端末への出力に失敗しました")?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer).map_err(|_| "入力に失敗しました")?;
            answer.trim() == "reveal"
        } else { false }
    };
    if show {
        let stdout = io::stdout(); let mut out = stdout.lock();
        writeln!(out, "{}", password).map_err(|_| "生成結果の出力に失敗しました")?;
    }
    Ok(())
}

fn main() {
    if let Err(message) = run() { eprintln!("codepass: {}", message); std::process::exit(1); }
}
