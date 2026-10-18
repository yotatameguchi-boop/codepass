use clap::{Args, Parser, Subcommand};
use codepass::{
    crypto::{self, Charset, Settings},
    harden::{self, Locked, LockedString},
    hardware::{self, SecurityKey},
    phishing,
    profile::{self, Entry, MacStatus, Saved},
    source, Result,
};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::mpsc,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "ソースコードから再現可能なパスワードを生成する実験的なオフラインCLI")]
struct Cli {
    #[arg(long, global = true, help = "設定ファイルのパス")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Material {
    /// ファイルのバイト列そのもの（1バイト違えば別のパスワード）
    Bytes,
    /// コードの構文（整形・コメント・空白の違いでは変わらない）
    Syntax,
}

impl Material {
    fn id(self) -> Option<&'static str> {
        match self {
            Material::Bytes => None,
            Material::Syntax => Some(codepass::syntax::MATERIAL_ID),
        }
    }
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
    Init {
        #[arg(long, help = "FIDO2セキュリティキーを第2の要素として登録する（fido2機能付きのビルドが必要）")]
        hardware_key: bool,
    },
    #[command(about = "ソースコードからパスワードを生成し、設定を登録する")]
    Generate {
        source: PathBuf,
        #[arg(long)]
        site: String,
        #[arg(long, default_value = "")]
        account: String,
        #[arg(long, default_value_t = 24)]
        length: usize,
        #[arg(long, value_enum, default_value_t = Charset::Strong)]
        charset: Charset,
        #[arg(long, default_value_t = 1)]
        revision: u32,
        #[arg(long, default_value_t = crypto::LATEST_SPEC, help = "生成仕様のバージョン（古いパスワードを作り直すとき用）")]
        spec_version: u32,
        #[arg(long, value_name = "記号", help = "使える記号を限定する（例: --symbols '!@#$%'）。仕様v2以降")]
        symbols: Option<String>,
        #[arg(long, help = "各文字種を必ず含む条件を解除")]
        no_require_classes: bool,
        #[arg(
            long,
            value_name = "REV",
            help = "作業中のファイルではなく、Gitのこのコミットに入っている内容を使う"
        )]
        git: Option<String>,
        #[arg(long, value_enum, default_value_t = Material::Bytes,
            help = "コードのどこを材料にするか。syntax なら整形やコメントを変えても同じパスワード")]
        material: Material,
        #[arg(long, help = "設定を登録しない")]
        no_save: bool,
        #[arg(long, conflicts_with = "no_save", help = "同じサービス・更新番号の登録済み設定を置き換える")]
        replace: bool,
        #[arg(long, help = "今回の非秘密設定とsaltを新規ファイルにエクスポート")]
        export_settings: Option<PathBuf>,
        #[arg(long, help = "登録済みのサービスと見分けにくい名前でも登録する（フィッシング対策を解除）")]
        allow_lookalike: bool,
        #[command(flatten)]
        output: Output,
    },
    #[command(about = "登録済みの設定からパスワードを呼び出す")]
    Get {
        site: String,
        #[arg(long, default_value = "")]
        account: String,
        #[arg(long, help = "省略時は最新の更新番号")]
        revision: Option<u32>,
        #[command(flatten)]
        output: Output,
    },
    #[command(about = "バックアップ済みの設定エントリからパスワードを再生成")]
    Regenerate {
        source: PathBuf,
        #[arg(long, help = "profile list で表示される番号")]
        entry: usize,
        #[command(flatten)]
        output: Output,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    #[command(about = "このマシンで鍵導出の時間を測り、総当たり攻撃にかかる時間の目安を表示する")]
    Bench,
    #[command(about = "設定を点検し、パスワードを作り直せなくなる原因がないか調べる")]
    Doctor,
    #[command(about = "構文の材料として、コードのどこが使われるかを表示する")]
    Inspect {
        source: PathBuf,
        #[arg(long, value_name = "REV", help = "Gitのこのコミットに入っている内容を使う")]
        git: Option<String>,
        #[arg(long, help = "使われるトークンをすべて表示する")]
        all: bool,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    Export {
        #[arg(long)]
        output: PathBuf,
    },
    Import {
        input: PathBuf,
    },
    #[command(about = "保存済みの設定エントリを一覧表示")]
    List,
    #[command(about = "設定エントリを削除（そのパスワードは get で呼び出せなくなる）")]
    Remove {
        entry: usize,
    },
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.config {
        Some(p) => p,
        None => profile::default_path()?,
    };
    match cli.command {
        Command::Bench => bench()?,
        Command::Doctor => doctor(&path)?,
        Command::Inspect { source, git, all } => inspect(&source, git.as_deref(), all)?,
        Command::Init { hardware_key } => {
            let mut p = profile::Profile::new()?;
            if hardware_key {
                let key = open_security_key()?;
                let id = key.enroll(hardware::RP_ID)?;
                p.hardware_key = Some(profile::HardwareKey {
                    credential_id: hex::encode(id),
                    rp_id: hardware::RP_ID.into(),
                });
                eprintln!("セキュリティキーを登録しました。今後はキーがないとパスワードを作り直せません");
            }
            profile::save_new(&path, &p)?;
            eprintln!(
                "初期設定を作成しました: {}\n\n次にやること:\n  \
                1. saltをバックアップする    codepass profile export --output <別の場所>/codepass-backup.json\n  \
                2. 材料のファイルをコミットで固定する    git tag codepass-source\n  \
                3. パスワードを作る    codepass generate <ファイル> --site github.com --git codepass-source\n\n\
                いつでも codepass doctor で設定を点検できます。",
                path.display()
            );
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
                    let chars = match (&s.charset, &s.symbols) {
                        (Charset::Strong, Some(sym)) => format!("記号{sym}"),
                        (c, _) => format!("{c:?}"),
                    };
                    println!(
                        "{}\t{}\t{}\t長さ{} {} 更新{} v{}\t{}",
                        i + 1,
                        s.site_key(),
                        s.account,
                        s.length,
                        chars,
                        s.revision,
                        s.spec_version,
                        from
                    );
                }
            }
            ProfileCommand::Remove { entry } => {
                let removed = profile::update(&path, |p| {
                    let i = entry
                        .checked_sub(1)
                        .filter(|&i| i < p.entries.len())
                        .ok_or("指定された番号の設定エントリがありません")?;
                    Ok(p.entries.remove(i))
                })?;
                eprintln!("削除しました: {} 更新{}", removed.settings.site, removed.settings.revision);
            }
        },
        Command::Get { site, account, revision, output } => {
            let p = profile::load(&path)?;
            let e = match p.find(&site, &account, revision) {
                Ok(e) => e,
                Err(not_found) => {
                    let key = crypto::site_key(
                        &phishing::decode_host(&crypto::site_key(&site, crypto::LATEST_SPEC)),
                        crypto::LATEST_SPEC,
                    );
                    let look = phishing::lookalikes(&key, registered_sites(&p).iter().map(String::as_str));
                    if !look.is_empty() {
                        return Err(format!(
                            "「{key}」は登録済みの「{}」と見た目がそっくりな別のドメインです。\
                            フィッシングサイトの可能性が高いので、パスワードは出しません",
                            look.join("」「")
                        ));
                    }
                    return Err(not_found);
                }
            };
            let file = e
                .source_path
                .as_ref()
                .ok_or("この設定にはファイルの場所が記録されていません。regenerate を使ってください")?;
            let loaded =
                source::load_material(file.as_ref(), e.git_commit.as_deref(), e.material.as_deref())?;
            if !hex::encode(loaded.sha256).eq_ignore_ascii_case(&e.source_sha256) {
                return Err(if e.material.is_some() {
                    format!(
                        "{file} のコードの中身（構文）が登録時と変わっています。整形やコメントの違いは関係ありませんが、\
                        名前や処理・文字列が変わると別のパスワードになります。元に戻してください"
                    )
                } else {
                    format!(
                        "{file} の内容が登録時と変わっています（1バイトでも違うと別のパスワードになります）。\
                        元の内容に戻すか、次からは --git でコミットを指定するか --material syntax で登録してください"
                    )
                });
            }
            let master = unlock(&p, &e.settings)?;
            check_entry(e, &master)?;
            let password = crypto::derive_with_master(&master, &loaded.sha256, &e.settings)?;
            describe(&loaded.sha256, &e.settings);
            present(&password, e.settings.length, &output)?;
        }
        Command::Regenerate { source, entry, output } => {
            let p = profile::load(&path)?;
            let e = entry
                .checked_sub(1)
                .and_then(|i| p.entries.get(i))
                .ok_or("指定された番号の設定エントリがありません")?;
            let loaded = source::load_material(&source, e.git_commit.as_deref(), e.material.as_deref())?;
            if !hex::encode(loaded.sha256).eq_ignore_ascii_case(&e.source_sha256) {
                return Err(
                    "ソースコードの内容が保存時と一致しません（1バイトでも違うと別のパスワードになります）"
                        .into(),
                );
            }
            let master = unlock(&p, &e.settings)?;
            check_entry(e, &master)?;
            let password = crypto::derive_with_master(&master, &loaded.sha256, &e.settings)?;
            describe(&loaded.sha256, &e.settings);
            present(&password, e.settings.length, &output)?;
        }
        Command::Generate {
            source,
            site,
            account,
            length,
            charset,
            revision,
            spec_version,
            symbols,
            no_require_classes,
            git,
            material,
            no_save,
            replace,
            export_settings,
            allow_lookalike,
            output,
        } => {
            let symbols = symbols.as_deref().map(crypto::canonical_symbols).transpose()?;
            let settings = Settings {
                site,
                account,
                length,
                charset,
                revision,
                require_classes: !no_require_classes,
                spec_version,
                symbols,
            };
            settings.validate()?;
            if settings.site_key() != settings.site.trim() {
                eprintln!(
                    "サービス: {}（「{}」をこの名前として扱います）",
                    settings.site_key(),
                    settings.site
                );
            }
            let mut p = profile::load(&path)?;
            // Judge the name as it looks: a pasted Punycode URL is decoded for these checks.
            let looks_like = phishing::decode_host(&settings.site_key());
            for warning in phishing::suspicious_parts(&looks_like) {
                eprintln!("警告: {warning}");
            }
            let look = phishing::lookalikes(&looks_like, registered_sites(&p).iter().map(String::as_str));
            if !look.is_empty() && !allow_lookalike {
                return Err(format!(
                    "「{}」は登録済みの「{}」と見た目がそっくりです。フィッシングサイトのURLではないか確かめてください。\n  \
                    本当に別のサービスなら --allow-lookalike を付けてください",
                    settings.site_key(),
                    look.join("」「")
                ));
            }
            let loaded = source::load_material(&source, git.as_deref(), material.id())?;
            let source_path = loaded.path.to_str().map(str::to_string);
            if source_path.is_none() && !no_save {
                eprintln!("警告: パスがUTF-8でないため、ファイルの場所は記録しません");
            }
            let mut entry = Entry {
                source_sha256: hex::encode(loaded.sha256),
                settings: settings.clone(),
                source_path,
                git_commit: loaded.git_commit.clone(),
                mac: None,
                material: material.id().map(str::to_string),
            };
            // Check before asking for the secret: a mismatch usually means the file changed.
            if !no_save && !replace {
                if let Some(old) =
                    p.entries.iter().find(|e| e.same_key(&settings) && !e.same_password(&entry))
                {
                    let why = if old.source_sha256.eq_ignore_ascii_case(&entry.source_sha256) {
                        "文字数や文字種の設定"
                    } else {
                        "コードの内容"
                    };
                    return Err(format!(
                        "{}（更新番号{}）は登録済みですが、{}が違うので別のパスワードになります。\n  \
                        登録済みのものを出す: codepass get {}{}\n  \
                        パスワードを更新する: --revision {} を付ける\n  \
                        登録を置き換える: --replace / 登録せずに出す: --no-save",
                        settings.site_key(),
                        revision,
                        why,
                        settings.site_key(),
                        if settings.account.is_empty() {
                            String::new()
                        } else {
                            format!(" --account {}", settings.account)
                        },
                        p.entries
                            .iter()
                            .filter(|e| e.same_service(&settings))
                            .map(|e| e.settings.revision)
                            .max()
                            .unwrap_or(revision)
                            .saturating_add(1)
                    ));
                }
            }
            let master = unlock(&p, &settings)?;
            let password = crypto::derive_with_master(&master, &loaded.sha256, &settings)?;
            describe(&loaded.sha256, &settings);
            entry.sign(&*crypto::entry_mac_key(&master)?);
            if !no_save {
                match profile::update(&path, |p| Ok(p.upsert(entry.clone(), replace)))? {
                    Saved::Added => eprintln!(
                        "設定を登録しました。次からは codepass get {} で呼び出せます",
                        settings.site_key()
                    ),
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

/// Attacker model for the cost table (docs/THREAT_MODEL.md explains each number).
/// Argon2id with 64 MiB and 3 passes moves roughly 3 × 3 × 64 MiB ≈ 0.6 GB of memory
/// per guess, so a GPU is bounded by its memory bandwidth, not its compute.
const GPU_BANDWIDTH_BYTES: f64 = 1.0e12; // a high-end GPU, about 1 TB/s
const BYTES_PER_GUESS: f64 = 9.0 * 64.0 * 1024.0 * 1024.0;
const GPUS: f64 = 1000.0;
const SHA256_PER_GPU: f64 = 1.0e10; // unsalted fast hash, for comparison

fn inspect(path: &std::path::Path, git: Option<&str>, all: bool) -> Result<()> {
    use codepass::syntax;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("ファイル名はUTF-8である必要があります")?;
    let lang = syntax::lang_for(name)?;
    let (bytes, _) = source::read_bytes(path, git)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "UTF-8 のテキストファイルではありません")?;
    let toks = syntax::tokens(text, lang)?;
    let shown: Vec<&str> = toks
        .iter()
        .map(|t| match t.as_str() {
            syntax::NEWLINE => "⏎",
            syntax::INDENT => "⇥",
            syntax::DEDENT => "⇤",
            other => other,
        })
        .collect();
    let limit = if all { shown.len() } else { shown.len().min(60) };
    println!("言語: {}（{name}）", lang.id());
    println!("材料に使うトークン: {} 個（元のファイル {} バイト）", toks.len(), bytes.len());
    println!();
    println!("{}{}", shown[..limit].join(" "), if limit < shown.len() { " …" } else { "" });
    println!();
    println!("構文のハッシュ    : {}", hex::encode(syntax::hash(&bytes, name)?));
    println!("バイト列のハッシュ: {}", hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)));
    println!();
    println!("コメント・空白・改行・インデント幅・末尾のカンマを変えても、構文のハッシュ（= パスワード）は変わりません。");
    Ok(())
}

/// One line of the doctor's report.
enum Check {
    Ok(String),
    Warn(String, String),
    Bad(String, String),
}

fn doctor(path: &std::path::Path) -> Result<()> {
    let mut checks = Vec::new();
    let p = match profile::load(path) {
        Ok(p) => {
            checks.push(Check::Ok(format!(
                "設定ファイルを読めます（{}・登録 {} 件）",
                path.display(),
                p.entries.len()
            )));
            p
        }
        Err(e) => {
            println!(
                "✗ 設定ファイル: {e}\n  → codepass init で作るか、--config でバックアップを指定してください"
            );
            return Ok(());
        }
    };
    checks.push(Check::Warn(
        "salt のバックアップ".into(),
        "salt をなくすと全部作り直せません。profile export で別の場所に置いてあるか確かめてください".into(),
    ));

    match &p.hardware_key {
        Some(_) if cfg!(feature = "fido2") => {
            checks.push(Check::Ok("セキュリティキーを使う設定です（このビルドは対応しています）".into()))
        }
        Some(_) => checks.push(Check::Bad(
            "セキュリティキーを使う設定ですが、このビルドは対応していません".into(),
            "cargo install codepass --features fido2 で入れ直してください".into(),
        )),
        None => {}
    }

    for (i, e) in p.entries.iter().enumerate() {
        let s = &e.settings;
        let name = format!(
            "#{} {}{} 更新{}",
            i + 1,
            s.site_key(),
            if s.account.is_empty() { String::new() } else { format!(" / {}", s.account) },
            s.revision
        );
        let source = match &e.source_path {
            None => Err("ファイルの場所が記録されていません（regenerate でのみ使えます）".to_string()),
            Some(file) => {
                source::load_material(file.as_ref(), e.git_commit.as_deref(), e.material.as_deref())
                    .map_err(|err| format!("{file}: {err}"))
            }
        };
        match source {
            Ok(loaded) if hex::encode(loaded.sha256).eq_ignore_ascii_case(&e.source_sha256) => {
                if e.git_commit.is_some() {
                    checks.push(Check::Ok(format!("{name}: 材料はコミットで固定されています")));
                } else if e.material.is_some() {
                    checks.push(Check::Ok(format!(
                        "{name}: 材料は構文で比べます（整形やコメントの変更では変わりません）"
                    )));
                } else {
                    checks.push(Check::Warn(
                        format!("{name}: 材料が作業中のファイルです"),
                        "1バイトの編集でも作り直せなくなります。--git か --material syntax で登録し直すと安全です".into(),
                    ));
                }
            }
            Ok(_) if e.material.is_some() => checks.push(Check::Bad(
                format!("{name}: コードの中身（構文）が登録時と変わっています"),
                "整形やコメントは関係ありません。名前・処理・文字列の変更を元に戻してください".into(),
            )),
            Ok(_) => checks.push(Check::Bad(
                format!("{name}: 材料のファイルが登録時と変わっています"),
                "元に戻すか、--git で固定したコミットを使ってください".into(),
            )),
            Err(err) => checks.push(Check::Bad(format!("{name}: 材料を読めません"), err)),
        }
        if e.mac.is_none() {
            checks.push(Check::Warn(
                format!("{name}: 改ざん検知の署名がありません"),
                "generate し直すと付きます（v0.2 以前の登録）".into(),
            ));
        }
        if s.spec_version < 2 {
            checks.push(Check::Warn(
                format!("{name}: 古い生成仕様 v1 です"),
                "大文字小文字を区別します。新しい更新番号で作り直すと v2 になります".into(),
            ));
        }
        if s.length < 15 {
            checks.push(Check::Warn(
                format!("{name}: {}文字と短めです", s.length),
                "20文字以上を推奨します".into(),
            ));
        }
    }

    let names = registered_sites(&p);
    let mut pairs = Vec::new();
    for (i, a) in names.iter().enumerate() {
        for b in phishing::lookalikes(a, names[i + 1..].iter().map(String::as_str)) {
            pairs.push(format!("「{a}」と「{b}」"));
        }
    }
    pairs.sort();
    pairs.dedup();
    for pair in pairs {
        checks.push(Check::Warn(
            format!("{pair}は見た目がそっくりです"),
            "片方がフィッシングサイトのものでないか確かめてください".into(),
        ));
    }

    let probe = Locked::new([0u8; 32]);
    if probe.is_locked() {
        checks.push(Check::Ok("秘密情報をメモリに固定できます（スワップに書き出されません）".into()));
    } else {
        checks.push(Check::Warn(
            "秘密情報をメモリに固定できません".into(),
            "OS の制限（Windows では未対応）。スワップに書き出される可能性があります".into(),
        ));
    }

    let (mut ok, mut warn, mut bad) = (0, 0, 0);
    for c in &checks {
        match c {
            Check::Ok(m) => {
                ok += 1;
                println!("✓ {m}");
            }
            Check::Warn(m, hint) => {
                warn += 1;
                println!("! {m}\n  → {hint}");
            }
            Check::Bad(m, hint) => {
                bad += 1;
                println!("✗ {m}\n  → {hint}");
            }
        }
    }
    println!("\n問題なし {ok} 件 / 注意 {warn} 件 / 要対応 {bad} 件");
    if bad > 0 {
        return Err("要対応の項目があります".into());
    }
    Ok(())
}

fn bench() -> Result<()> {
    let salt = [0u8; 16];
    let runs = 3;
    let start = std::time::Instant::now();
    for i in 0..runs {
        let _ = crypto::master_key(&format!("benchmark secret number {i}"), &salt)?;
    }
    let local = start.elapsed().as_secs_f64() / runs as f64;
    let per_gpu = GPU_BANDWIDTH_BYTES / BYTES_PER_GUESS;
    let argon_rate = per_gpu * GPUS;
    let sha_rate = SHA256_PER_GPU * GPUS;
    println!("このマシンでの鍵導出（Argon2id 64MiB・3回）: {:.2} 秒/回", local);
    println!();
    println!("攻撃者の想定: GPU {GPUS:.0} 台（1台あたり帯域 約1TB/s → 約{per_gpu:.0} 回/秒）");
    println!("平均でかかる時間（探す範囲の半分を試したところで当たるとして）:");
    println!();
    let rows: [(&str, f64); 5] = [
        ("推測しやすい（zxcvbnで弱い判定）", 1e8),
        ("警告の境目（約10^10通り）", 1e10),
        ("無関係な英単語4つ（7776^4）", 7776f64.powi(4)),
        ("無関係な英単語5つ（7776^5）", 7776f64.powi(5)),
        ("ランダムな英数字16文字（62^16）", 62f64.powi(16)),
    ];
    println!(
        "  {}{}{}",
        pad_end("シークレット", 36),
        pad_start("CodePass", 14),
        pad_start("ただのSHA-256なら", 20)
    );
    for (label, space) in rows {
        println!(
            "  {}{}{}",
            pad_end(label, 36),
            pad_start(&human_time(space / 2.0 / argon_rate), 14),
            pad_start(&human_time(space / 2.0 / sha_rate), 20)
        );
    }
    println!();
    println!("セキュリティキーを登録した設定では、キーが手元にない限り試すこと自体ができません。");
    println!("数値は桁の目安です。前提と計算は docs/THREAT_MODEL.md にあります。");
    Ok(())
}

fn human_time(seconds: f64) -> String {
    const MIN: f64 = 60.0;
    const HOUR: f64 = 3600.0;
    const DAY: f64 = 86400.0;
    const YEAR: f64 = 365.25 * DAY;
    match seconds {
        s if s < 1.0 => "1秒未満".into(),
        s if s < MIN => format!("{s:.0}秒"),
        s if s < HOUR => format!("{:.0}分", s / MIN),
        s if s < DAY => format!("{:.0}時間", s / HOUR),
        s if s < YEAR => format!("{:.0}日", s / DAY),
        s if s < 1e4 * YEAR => format!("{:.0}年", s / YEAR),
        s if s < 1e8 * YEAR => format!("約{:.0}万年", s / YEAR / 1e4),
        s if s < 1e12 * YEAR => format!("約{:.0}億年", s / YEAR / 1e8),
        s if s < 1e16 * YEAR => format!("約{:.0}兆年", s / YEAR / 1e12),
        s => format!("約10^{:.0}年", (s / YEAR).log10()),
    }
}

// Terminal columns: CJK characters take two cells.
fn pad_end(text: &str, cells: usize) -> String {
    let w = unicode_width::UnicodeWidthStr::width(text);
    format!("{text}{}", " ".repeat(cells.saturating_sub(w)))
}

fn pad_start(text: &str, cells: usize) -> String {
    let w = unicode_width::UnicodeWidthStr::width(text);
    format!("{}{text}", " ".repeat(cells.saturating_sub(w)))
}

fn registered_sites(p: &profile::Profile) -> Vec<String> {
    p.entries.iter().map(|e| e.settings.site_key()).collect()
}

#[cfg(feature = "fido2")]
fn open_security_key() -> Result<Box<dyn SecurityKey>> {
    Ok(Box::new(hardware::Fido2Key::open()?))
}

#[cfg(not(feature = "fido2"))]
fn open_security_key() -> Result<Box<dyn SecurityKey>> {
    Err("このビルドはセキュリティキーに対応していません。cargo install codepass --features fido2 で入れ直してください".into())
}

/// Asks for the secret (and the security key, if enrolled) and returns the master key,
/// kept in locked memory and zeroed when dropped.
fn unlock(p: &profile::Profile, settings: &Settings) -> Result<Locked<[u8; 32]>> {
    settings.validate()?;
    if !io::stdin().is_terminal() {
        return Err("マスターシークレットは対話端末から入力してください".into());
    }
    if settings.length < 15 {
        eprintln!("警告: 15文字未満です。20文字以上を推奨します。");
    }
    let secret = LockedString::new(
        rpassword::prompt_password("Master secret: ").map_err(|_| "非表示入力に失敗しました")?,
    );
    let salt = p.salt_bytes()?;
    let mut master = Locked::new(*crypto::master_key(&secret, &salt)?);
    if let Some(warning) = crypto::secret_warning(&secret, &["codepass", &settings.site, &settings.account]) {
        eprintln!("{warning}");
    }
    drop(secret);
    if let Some(hw) = &p.hardware_key {
        let id = hex::decode(&hw.credential_id).map_err(|_| "セキュリティキーの設定が不正です")?;
        let answer = Locked::new(open_security_key()?.hmac_secret(
            &hw.rp_id,
            &id,
            &crypto::hardware_challenge(&salt),
        )?);
        master = Locked::new(*crypto::with_hardware(&master, &answer)?);
    }
    if !master.is_locked() {
        eprintln!("注意: 秘密情報をメモリに固定できませんでした（スワップに書き出される可能性があります）");
    }
    eprintln!("確認コード: {}（いつもと違えば打ち間違いです）", crypto::check_code(&master)?);
    Ok(master)
}

/// A registered entry must carry a valid signature from this master key.
fn check_entry(e: &Entry, master: &[u8; 32]) -> Result<()> {
    match e.verify(&*crypto::entry_mac_key(master)?) {
        MacStatus::Valid => Ok(()),
        MacStatus::Missing => {
            eprintln!(
                "注意: この登録には改ざん検知の署名がありません（v0.2以前の登録）。generate し直すと付きます"
            );
            Ok(())
        }
        MacStatus::Invalid => Err("登録内容の署名が合いません。マスターシークレットの打ち間違いか、\
            設定ファイルが書き換えられた可能性があります。確認コードを確かめてください"
            .into()),
    }
}

fn describe(hash: &[u8; 32], settings: &Settings) {
    eprintln!(
        "仕様: v{} / コードSHA-256: {} / 更新番号: {}",
        settings.spec_version,
        hex::encode(hash),
        settings.revision
    );
}

fn present(password: &str, length: usize, output: &Output) -> Result<()> {
    if output.copy {
        return copy_to_clipboard(password, output.clear_after);
    }
    if output.reveal {
        return print_password(password);
    }
    eprintln!("生成結果: {}", "*".repeat(length));
    if !io::stdout().is_terminal() {
        return Ok(());
    }
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
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{}", password).map_err(|_| "生成結果の出力に失敗しました".into())
}

#[cfg(target_os = "macos")]
use arboard::SetExtApple as _;
#[cfg(all(unix, not(target_os = "macos")))]
use arboard::SetExtLinux as _;
#[cfg(windows)]
use arboard::SetExtWindows as _;

// Stays running until the timeout: on Linux the clipboard content lives in this process.
fn copy_to_clipboard(password: &str, clear_after: u64) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new().map_err(|_| "クリップボードを使えません")?;
    clipboard.set().exclude_from_history().text(password).map_err(|_| "クリップボードにコピーできません")?;
    eprintln!("クリップボードにコピーしました。{clear_after}秒後に消去します（Enterですぐ消去）");
    let (tx, rx) = mpsc::channel();
    let on_interrupt = tx.clone();
    ctrlc::set_handler(move || {
        let _ = on_interrupt.send(());
    })
    .map_err(|_| "Ctrl+C の処理を設定できません")?;
    if io::stdin().is_terminal() {
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            let _ = tx.send(());
        });
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
    let failed = harden::harden_process();
    if !failed.is_empty() {
        eprintln!("注意: {}を設定できませんでした", failed.join("・"));
    }
    if let Err(message) = run() {
        eprintln!("codepass: {}", message);
        std::process::exit(1);
    }
}
