# CodePass

ソースコードのファイルとマスターシークレットから、サービスごとに異なるパスワードを**毎回同じように**作り直すオフラインCLI。パスワードはどこにも保存しない。

```
ソースコード + マスターシークレット + サービス情報 → パスワード
```

> **実験的なOSSです。** 暗号設計の第三者レビューが終わるまで、重要なアカウントには使わないでください。
> ソースコードは公開されている可能性があるため、秘密としては扱いません。安全性はマスターシークレットの強さに依存します。

## インストール

```sh
cargo install --git https://github.com/yotatameguchi-boop/codepass
```

## 使い方

```sh
# 1. 初期設定（ランダムなsaltを作る）。最初に1回だけ
codepass init

# 2. GitHub用のパスワードを作る。マスターシークレットは画面に出ない形で聞かれる
codepass generate main.py --site github.com

# 文字数・アカウント・更新番号を指定
codepass generate main.py --site github.com --length 32
codepass generate main.py --site github.com --account personal --revision 2

# 記号を使えないサービス向け
codepass generate main.py --site example.com --charset alnum
```

結果は最初 `****` で隠れていて、`reveal` と入力すると表示されます。
`--reveal` を付けると確認なしで標準出力に出します（`| pbcopy` などに渡す場合）。

### バックアップと復元

**saltをなくすと、すべてのパスワードを作り直せなくなります。** 必ずバックアップしてください。
バックアップには秘密情報（マスターシークレット・パスワード）は含まれません。

```sh
codepass profile export --output codepass-backup.json      # saltのバックアップ
codepass profile import codepass-backup.json               # 別の端末で復元

# 生成に使った設定（サービス名・文字数など）もまとめて残す
codepass generate main.py --site github.com --export-settings github-settings.json
codepass --config github-settings.json profile list
codepass --config github-settings.json regenerate main.py --entry 1
```

既存の設定ファイルは決して上書きしません（saltが入れ替わる事故を防ぐため）。

## 気をつけること

- **ソースコードは1バイトでも変わると別のパスワードになります。** 改行コード（LF/CRLF）、末尾の空白、Gitの自動変換に注意。使うファイルはコミットIDやタグで固定しておくのがおすすめです。
- サービス名は大文字・小文字を区別します（`GitHub.com` と `github.com` は別物）。
- マスターシークレットを打ち間違えても、エラーにはならず別のパスワードが出ます。
- マスターシークレットはコマンド引数・環境変数・パイプからは受け取りません（履歴に残さないため）。
- 端末のマルウェア、フィッシング、画面やクリップボードの盗み見は防げません。パスキーや多要素認証の代わりにはなりません。

## 仕組み

SHA-256（コード）→ Argon2id（マスターシークレット, 64MiB / 3回 / 並列度1）→ HKDF-SHA256（コードのハッシュ・サービス・アカウント・更新番号などを混ぜる）→ HMAC-SHA256 の出力から棄却サンプリングで文字を選ぶ。

詳細は [docs/SPEC.md](docs/SPEC.md)。仕様だけから書いた別実装 [docs/reference.py](docs/reference.py) が、[tests/vectors.rs](tests/vectors.rs) のテストベクターと一致することを確認しています。

## 開発

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

[CONTRIBUTING.md](CONTRIBUTING.md) と [SECURITY.md](SECURITY.md) も見てください。ライセンスは [MIT](LICENSE)。
