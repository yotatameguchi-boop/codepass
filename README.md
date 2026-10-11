# CodePass

ソースコードのファイルとマスターシークレットから、サービスごとに異なるパスワードを**毎回同じように**作り直すオフラインCLI。パスワードはどこにも保存しない。

```
ソースコード + マスターシークレット + サービス情報 → パスワード
```

> **実験的なOSSです。** 暗号設計の第三者レビューが終わるまで、重要なアカウントには使わないでください。
> ソースコードは公開されている可能性があるため、秘密としては扱いません。安全性はマスターシークレットの強さに依存します。

## インストール

[Releases](https://github.com/yotatameguchi-boop/codepass/releases) から、macOS（Apple Silicon / Intel）・Linux（x86_64 / ARM64）・Windows 向けの
実行ファイルを入手できます。`SHA256SUMS` でファイルが壊れていないか確かめてください。

Rust がある場合は [crates.io](https://crates.io/crates/codepass) から入れられます。

```sh
cargo install --locked codepass
```

## 使い方

```sh
# 1. 初期設定（ランダムなsaltを作る）。最初に1回だけ
codepass init
codepass profile export --output codepass-backup.json   # saltのバックアップ。必ず取る

# 2. パスワードを作る。設定は自動で登録される
codepass generate keys/main.py --site github.com --git v1

# 3. 次からはサービス名だけで呼び出せる
codepass get github.com
codepass get github.com --copy        # クリップボードへ。20秒後（またはEnter/Ctrl+C）に自動で消える
```

マスターシークレットは画面に出ない形で聞かれます。入力後に出る**確認コード**（例: `koala-torch-coconut`）を覚えておいてください。
いつもと違う単語が出たら打ち間違いです。

結果は最初 `****` で隠れていて、`reveal` で表示、`copy` でコピーできます。
`--reveal` を付けると確認なしで標準出力に出します。

### 材料のファイルは Git のコミットで固定する

ソースコードは**1バイトでも変わると別のパスワードになります**。`--git <タグやコミット>` を付けると、作業中のファイルではなく
コミットに入っている内容を使うので、ファイルを編集しても、改行コードが変換されても、ファイルを消しても同じパスワードが出ます。

```sh
git tag codepass-source            # 材料にするコミットに印を付けておく
codepass generate main.py --site github.com --git codepass-source
```

`--git` なしで登録したファイルが変わっていた場合、`get` はパスワードを出さずにエラーで止まります。

### その他のオプション

```sh
codepass generate main.py --site github.com --length 32
codepass generate main.py --site github.com --account work
codepass generate main.py --site example.com --charset alnum     # 記号を使えないサービス向け
codepass generate main.py --site bank.example --symbols '!@#$%'   # 使える記号が決まっているサービス向け

# パスワードを変えたいときは更新番号を上げる（古い番号も登録に残る）
codepass generate main.py --site github.com --git codepass-source --revision 2
codepass get github.com                 # 最新の更新番号
codepass get github.com --revision 1    # 古いもの

codepass profile list                   # 登録の一覧
codepass profile remove 3               # 登録の削除
```

同じサービス・更新番号で内容が違う登録をしようとすると、シークレットを聞く前に止まって理由を表示します
（多くはファイルが変わっていたとき）。意図的なら `--replace`、登録せずに出すだけなら `--no-save`。

### サービス名の書き方

`https://www.GitHub.com/login` も `GITHUB.COM` も `github.com` として扱います（URLから取り出したホスト名を、小文字・全角→半角に
そろえ、先頭の `www.` を除く）。ブラウザのアドレス欄からそのまま貼り付けて大丈夫です。どの名前として扱ったかは毎回表示されます。

> v0.1 で作ったパスワード（生成仕様v1）はこの正規化の対象外で、これまでどおり大文字・小文字を区別します。
> 登録済みのものは `get` でそのまま呼び出せ、値は変わりません。

### バックアップと復元

**saltをなくすと、すべてのパスワードを作り直せなくなります。** バックアップには秘密情報（マスターシークレット・パスワード）は含まれません。

```sh
codepass profile export --output codepass-backup.json      # 登録した設定もまとめて書き出す
codepass profile import codepass-backup.json               # 別の端末で復元
codepass --config codepass-backup.json regenerate main.py --entry 1   # ファイルの場所が違う端末で
```

既存の設定ファイルは決して丸ごと上書きしません。登録の追加・削除でも salt は変わらないことを確かめてから書き換えます。

## 気をつけること

- **ソースコードは1バイトでも変わると別のパスワードになります。** `--git` で固定するのがおすすめです。
- `xn--` で始まる表記（Punycode）と、それを日本語などで書いた表記は別のサービスとして扱います。普段見ている表記で統一してください。
- マスターシークレットが推測されやすそうな場合は警告を出します（パスワードは作ります）。無関係な単語を5つ以上つなげたものなどがおすすめです。
- マスターシークレットを打ち間違えてもエラーにはならず、別のパスワードが出ます。確認コードで気づけます。
- クリップボードはコピー履歴に残さないよう指定していますが、対応していないクリップボード管理ツールでは残る場合があります。
- マスターシークレットはコマンド引数・環境変数・パイプからは受け取りません（履歴に残さないため）。
- 端末のマルウェア、フィッシング、画面やクリップボードの盗み見は防げません。パスキーや多要素認証の代わりにはなりません。

## 仕組み

SHA-256（コード）→ Argon2id（マスターシークレット, 64MiB / 3回 / 並列度1）→ HKDF-SHA256（コードのハッシュ・サービス・アカウント・更新番号などを混ぜる）→ HMAC-SHA256 の出力から棄却サンプリングで文字を選ぶ。

詳細は [docs/SPEC.md](docs/SPEC.md)。仕様だけから書いた別実装 [docs/reference.py](docs/reference.py) が
[tests/vectors.rs](tests/vectors.rs) のテストベクターと一致することを、CIで毎回確かめています。
文字の偏りがないことの統計的な検定や、ランダムな入力に対する性質テスト（proptest）も入っています。

## 使用技術

**言語**: Rust（2021 edition）。外部との通信は一切なく、オフラインで動きます。

### 暗号

独自の暗号は作らず、広く使われている [RustCrypto](https://github.com/RustCrypto) の実装を組み合わせています。

| 用途 | 方式 | ライブラリ |
|---|---|---|
| コードのハッシュ | SHA-256 | [`sha2`](https://crates.io/crates/sha2) |
| マスターシークレットからの鍵導出 | Argon2id（64MiB / 3回 / 並列度1） | [`argon2`](https://crates.io/crates/argon2) |
| サービスごとの鍵の導出・確認コード | HKDF-SHA256 | [`hkdf`](https://crates.io/crates/hkdf) |
| 文字列生成のための乱数列 | HMAC-SHA256 | [`hmac`](https://crates.io/crates/hmac) |
| salt の生成 | OS の安全な乱数 | [`getrandom`](https://crates.io/crates/getrandom) |
| 使い終わった秘密情報の消去 | メモリのゼロ埋め | [`zeroize`](https://crates.io/crates/zeroize) |

### CLI・入出力

| 用途 | ライブラリ |
|---|---|
| コマンドと引数の解析 | [`clap`](https://crates.io/crates/clap) |
| 画面に出さないシークレット入力 | [`rpassword`](https://crates.io/crates/rpassword) |
| クリップボード（履歴除外つき） | [`arboard`](https://crates.io/crates/arboard) |
| Ctrl+C でもクリップボードを消す | [`ctrlc`](https://crates.io/crates/ctrlc) |
| シークレットの推測されやすさの判定 | [`zxcvbn`](https://crates.io/crates/zxcvbn) |
| サービス名・アカウント名の Unicode 正規化（NFC / NFKC） | [`unicode-normalization`](https://crates.io/crates/unicode-normalization) |
| 設定ファイル（JSON）の読み書き | [`serde`](https://crates.io/crates/serde) / [`serde_json`](https://crates.io/crates/serde_json) / [`hex`](https://crates.io/crates/hex) |
| OS ごとの設定ファイルの置き場所 | [`directories`](https://crates.io/crates/directories) |
| コミットからのファイル読み込み | `git` コマンド（`rev-parse` / `cat-file` のみ） |

### テスト・品質管理

| 内容 | 使っているもの |
|---|---|
| 単体・結合テスト、テストベクター | Rust 標準のテスト、[`tempfile`](https://crates.io/crates/tempfile) |
| ランダムな入力での性質テスト | [`proptest`](https://crates.io/crates/proptest) |
| 仕様だけから書いた別実装との突き合わせ | Python 3 ＋ [`argon2-cffi`](https://pypi.org/project/argon2-cffi/)（[docs/reference.py](docs/reference.py)） |
| 整形・静的解析 | rustfmt / Clippy |
| 依存ライブラリの脆弱性検査 | [RustSec](https://rustsec.org/)（`rustsec/audit-check`） |
| CI（Linux / macOS / Windows） | GitHub Actions |
| 配布（5種類の実行ファイルと `SHA256SUMS`） | GitHub Actions ＋ GitHub Releases |

## 開発

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
python docs/reference.py | diff - docs/reference-expected.txt   # pip install argon2-cffi
```

[CONTRIBUTING.md](CONTRIBUTING.md) と [SECURITY.md](SECURITY.md) も見てください。ライセンスは [MIT](LICENSE)。
