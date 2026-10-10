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

# パスワードを変えたいときは更新番号を上げる（古い番号も登録に残る）
codepass generate main.py --site github.com --git codepass-source --revision 2
codepass get github.com                 # 最新の更新番号
codepass get github.com --revision 1    # 古いもの

codepass profile list                   # 登録の一覧
codepass profile remove 3               # 登録の削除
```

同じサービス・更新番号で内容が違う登録をしようとすると、シークレットを聞く前に止まって理由を表示します
（多くはファイルが変わっていたとき）。意図的なら `--replace`、登録せずに出すだけなら `--no-save`。

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
- サービス名は大文字・小文字を区別します（`GitHub.com` と `github.com` は別物）。
- マスターシークレットを打ち間違えてもエラーにはならず、別のパスワードが出ます。確認コードで気づけます。
- クリップボードはコピー履歴に残さないよう指定していますが、対応していないクリップボード管理ツールでは残る場合があります。
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
