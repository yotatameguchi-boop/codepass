# CodePass 生成仕様（v1 / v2）

この文書だけで、別の言語・別の実装からも同じパスワードを再現できることを目的とする。
仕様を変える場合は `spec_version` を上げ、古い版の処理は残す（古いパスワードを再生成するため）。

- **v1**: 最初の仕様。サービス名は大文字小文字を区別する。
- **v2**: 新しいパスワードの既定。サービス名をURLやホスト名から正規化し、使える記号を指定できる。

v1とv2の違いは「識別子の正規化」「context」「記号の集合」「ラベルの版番号」だけで、Argon2id・確認コード・
棄却サンプリングの手順は共通。

> 実験段階の設計であり、第三者による暗号レビューは未実施。

## 入力

| 名前 | 型 | 説明 |
|---|---|---|
| `source` | バイト列（≤ 1 MiB） | ソースファイルの内容そのもの。改行コード・空白・コメント・BOMも含む |
| `secret` | UTF-8 文字列 | マスターシークレット。16文字以上・4096バイト以下 |
| `salt` | 16バイト | `codepass init` で OS の安全な乱数から生成。非秘密 |
| `site` | UTF-8 文字列 | サービス識別子。必須、4096バイト以下、制御文字なし |
| `account` | UTF-8 文字列 | アカウント識別子。空でもよい |
| `revision` | u32（≥ 1） | 更新番号 |
| `length` | 8〜64 | 文字数 |
| `charset` | `strong` / `alnum` | 文字種プロファイル |
| `require_classes` | 真偽 | 各文字種を最低1文字含めるか（既定: 真） |
| `symbols` | ASCII記号の文字列 | v2のみ・任意。`strong` で使う記号を限定する。バイト値の昇順・重複なしに正規化して保存 |

### 識別子の正規化（v1）

`site` と `account` は Unicode NFC に正規化してから UTF-8 バイト列にする。
大文字小文字・前後の空白は**変更しない**（`GitHub.com` と `github.com` は別物）。

### 識別子の正規化（v2）

`account` は前後の空白（Unicode White_Space）を除いて NFC。大文字小文字は区別する。

`site` は次の1回分の処理 `pass` を、結果が変わらなくなるまで繰り返す（最大で初回＋8回）。

1. NFKC に正規化し、前後の空白を除く
2. `://` を含めば、最初の `://` より後ろだけを残す
3. 最初の `/` `?` `#` より前だけを残す
4. `@` を含めば、最後の `@` より後ろだけを残す
5. 最後の `:` より後ろが1文字以上の ASCII 数字で、その前が `:` を含まない（または `[` で始まり `]` で終わる）なら、`:` 以降を除く
6. 先頭の空白と、末尾の `.` と空白を除く
7. Unicode の小文字化（`String::to_lowercase` / Python `str.lower`）をしてから NFKC に正規化し、もう一度末尾の `.` と空白を除く
8. `www.` で始まり、残りに `.` を含む間、先頭の `www.` を除き続ける（v0.3 で修正。v0.2 までは1回だけ除いていたため、`www.` が10個以上続く名前だけ結果が違う）

例: `https://user@WWW.GitHub.com:443/login?x` → `github.com`、`ＧｉｔＨｕｂ．ｃｏｍ` → `github.com`、
`Bücher.example` → `bücher.example`、`My Bank` → `my bank`。

IDNA（Punycode）変換はライブラリごとに挙動が違うため**使わない**。`xn--bcher-kva.example` と `bücher.example` は別のサービスとして扱う。

## 処理

v1:

```
code_hash = SHA-256(source)
master    = Argon2id(password = secret, salt = salt,
                     m = 65536 KiB, t = 3, p = 1, version = 0x13, out = 32 bytes)
context   = "CodePass/context/v1" || 0x00
          || code_hash                                  (32 bytes)
          || u32be(len(site_nfc))    || site_nfc
          || u32be(len(account_nfc)) || account_nfc
          || u32be(revision)
          || u8(length)
          || u8(charset)          -- strong = 1, alnum = 2
          || u8(require_classes)  -- 0 or 1
key       = HKDF-SHA256(salt = "CodePass/HKDF/v1", ikm = master, info = context, L = 32)
```

v2（`site_key` / `account_key` は上記v2の正規化、`symset` は `strong` なら `symbols`（未指定なら SYMBOLS）、`alnum` なら空）:

```
context   = "CodePass/context/v2" || 0x00
          || code_hash
          || u32be(len(site_key))    || site_key
          || u32be(len(account_key)) || account_key
          || u32be(revision) || u8(length) || u8(charset) || u8(require_classes)
          || u8(len(symset)) || symset
key       = HKDF-SHA256(salt = "CodePass/HKDF/v2", ikm = master, info = context, L = 32)
```

### 文字列の生成

文字集合（この順に連結したものを `alphabet` とする）:

```
LOWER   = abcdefghijklmnopqrstuvwxyz
UPPER   = ABCDEFGHIJKLMNOPQRSTUVWXYZ
DIGITS  = 0123456789
SYMBOLS = !#$%&()*+,-./:;<=>?@[]^_{|}~      (strong のみ。28文字。" ' ` \ と空白は含まない)
```

- v1: `strong` は LOWER+UPPER+DIGITS+SYMBOLS の90文字、`alnum` は62文字
- v2: LOWER+UPPER+DIGITS+`symset`
- `limit = floor(256 / |alphabet|) * |alphabet|`（v1 の strong = 180, alnum = 248）

バイト列は `block_i = HMAC-SHA256(key, "CodePass/stream/v{版}" || 0x00 || u64be(i))`（i = 0, 1, 2, …）を
順につなげたもの。1バイト `b` ずつ読み、`b < limit` なら `alphabet[b mod |alphabet|]` を採用、
それ以外は捨てる（棄却サンプリング。剰余による偏りを避ける）。

`length` 文字たまったら候補とする。`require_classes` が真で、候補が LOWER・UPPER・DIGITS
（記号を使うなら記号の集合も）をそれぞれ1文字以上含まない場合は候補ごと捨て、**バイト列の続きから**
次の候補を作る。候補単位で捨てるので、条件を満たすパスワード全体の中で一様になる。

候補の試行は 1,000,000 回で打ち切ってエラーにする（実際には到達しない）。

## セキュリティキー（任意の第2要素）

プロファイルに `hardware_key` があるときは、上の `master` をそのまま使わず、FIDO2 セキュリティキーの
hmac-secret 拡張の出力を混ぜたものを `master` とする。以降の処理（確認コード・context・署名）はすべてこの値を使う。

```
challenge = SHA-256("CodePass/hw-challenge/v1" || 0x00 || salt)          (32 bytes)
hw_output = hmac-secret(credential_id, rp_id = "codepass", salt1 = challenge) (32 bytes)
master'   = HKDF-SHA256(salt = "CodePass/hw-factor/v1", ikm = master || hw_output,
                        info = "CodePass/master/v1", L = 32)
```

`hw_output` はキーの中にしかない秘密から作られ、キーの外に取り出せない。`credential_id` は秘密ではないが、
同じキー・同じ資格情報でないと同じ値は返らない。

## 確認コード

マスターシークレットの打ち間違いに気づくための3単語。`salt` と `secret`（セキュリティキーを使う設定ではキーの応答も）
だけで決まり、どこにも保存しない。

```
code = HKDF-SHA256(salt = "CodePass/HKDF/v1", ikm = master, info = "CodePass/check-code/v1", L = 3)
check_code = WORDS[code[0]] + "-" + WORDS[code[1]] + "-" + WORDS[code[2]]
```

`WORDS` は `src/words.rs` の256語（並び順も仕様の一部）。24ビットしかないため、総当たりの手がかりとしては
生成済みパスワード1つよりはるかに弱い。

## 設定の改ざん検知（エントリの署名）

プロファイルの各エントリに、`master` から導いた鍵で HMAC-SHA256 の署名（`mac`、64桁の16進）を付ける。
`get` / `regenerate` は、パスワードを出す前にこれを確かめ、合わなければ出さない。
シークレットを打ち間違えても鍵が変わるので、登録済みのサービスでは打ち間違いも確実に検出できる。

```
mac_key = HKDF-SHA256(salt = "CodePass/HKDF/v1", ikm = master, info = "CodePass/entry-mac/v1", L = 32)
data    = "CodePass/entry/v1" || 0x00
        || lp(lowercase(source_sha256))
        || lp(site) || lp(account)                 -- 入力されたまま（正規化前）
        || u32be(length) || u8(charset) || u32be(revision) || u8(require_classes)
        || u32be(spec_version)
        || opt(symbols) || opt(source_path) || opt(git_commit)
mac     = HMAC-SHA256(mac_key, data)

lp(x)  = u32be(len(x)) || x                        -- x は UTF-8 バイト列
opt(x) = 0x00（なし） または 0x01 || lp(x)
```

比較は定数時間で行う。v0.2 以前に登録したエントリには署名がなく、その場合は注意を表示して続行する。

## Gitからの読み込み

`--git REV` を付けると、作業中のファイルではなくコミットに入っている内容（`git cat-file blob <commit>:./<file>`
の出力）を `source` として使う。Gitの改行コード変換やファイルの編集の影響を受けない。
登録時は `REV` を完全なコミットID（40または64桁の16進）に解決して保存する。

## テストベクター

`tests/vectors.rs` に固定入力と期待される出力（v1を4件・v2を3件、確認コード、セキュリティキーの応答を混ぜた場合、
エントリの署名）を置いている。
別実装はこれと一致することを確認すること。仕様だけから書いた Python 版 `docs/reference.py` の出力は
`docs/reference-expected.txt` と一致し、CIで毎回確かめている。

正規化については、Rust版とPython版に記号・全角文字・各種言語の文字を混ぜた25,000件のランダムな入力を与え、
結果が完全に一致することを確認した（Unicodeのバージョン差で、新しく追加された文字の扱いが変わる可能性は残る）。

## プロファイル（バックアップ）形式

`codepass init` / `profile export` が書く JSON。秘密情報（マスターシークレット・生成済みパスワード）は含まない。

```json
{
  "format_version": 3,
  "spec_version": 1,
  "salt": "<16バイトの16進>",
  "entries": [
    {
      "source_sha256": "<32バイトの16進>",
      "settings": { "site": "github.com", "account": "", "length": 24, "charset": "strong",
                    "revision": 1, "require_classes": true, "spec_version": 2, "symbols": "!#@" },
      "source_path": "/Users/me/keys/main.py",
      "git_commit": "<コミットID。Gitから読んだときだけ>",
      "mac": "<署名。64桁の16進>"
    }
  ],
  "hardware_key": { "credential_id": "<16進>", "rp_id": "codepass" }
}
```

- `format_version` 1 は `source_path` / `git_commit` を、2 は `mac` / `hardware_key` を持たない旧形式。どれも読み込める。
- `hardware_key` は `init --hardware-key` のときだけ設定でき、salt と同じく後から変更できない。
- `site` は入力されたまま保存し、照合のたびにそのエントリの版の正規化をかける。
- エントリは「サービス・アカウント・更新番号」で区別する。同じ組み合わせで内容が違う登録は、明示しない限り置き換えない。
- `init` / `profile export` / `profile import` は既存ファイルを上書きしない。登録の追加・削除は一時ファイルに書いてから
  置き換え、その前後で salt と `hardware_key` が変わっていないことを確かめる（変わると全パスワードを再生成できなくなるため）。
