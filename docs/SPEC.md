# CodePass 生成仕様 v1

この文書だけで、別の言語・別の実装からも同じパスワードを再現できることを目的とする。
仕様を変える場合は `spec_version` を上げ、v1 の処理は残す（古いパスワードを再生成するため）。

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

### 識別子の正規化

`site` と `account` は Unicode NFC に正規化してから UTF-8 バイト列にする。
大文字小文字・前後の空白は**変更しない**（`GitHub.com` と `github.com` は別物）。

## 処理

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

### 文字列の生成

文字集合（この順に連結したものを `alphabet` とする）:

```
LOWER   = abcdefghijklmnopqrstuvwxyz
UPPER   = ABCDEFGHIJKLMNOPQRSTUVWXYZ
DIGITS  = 0123456789
SYMBOLS = !#$%&()*+,-./:;<=>?@[]^_{|}~      (strong のみ。28文字。" ' ` \ と空白は含まない)
```

- `strong`: 90文字 / `alnum`: 62文字
- `limit = floor(256 / |alphabet|) * |alphabet|`（strong = 180, alnum = 248）

バイト列は `block_i = HMAC-SHA256(key, "CodePass/stream/v1" || 0x00 || u64be(i))`（i = 0, 1, 2, …）を
順につなげたもの。1バイト `b` ずつ読み、`b < limit` なら `alphabet[b mod |alphabet|]` を採用、
それ以外は捨てる（棄却サンプリング。剰余による偏りを避ける）。

`length` 文字たまったら候補とする。`require_classes` が真で、候補が LOWER・UPPER・DIGITS
（strong なら SYMBOLS も）をそれぞれ1文字以上含まない場合は候補ごと捨て、**バイト列の続きから**
次の候補を作る。候補単位で捨てるので、条件を満たすパスワード全体の中で一様になる。

候補の試行は 1,000,000 回で打ち切ってエラーにする（実際には到達しない）。

## 確認コード

マスターシークレットの打ち間違いに気づくための3単語。`salt` と `secret` だけで決まり、どこにも保存しない。

```
code = HKDF-SHA256(salt = "CodePass/HKDF/v1", ikm = master, info = "CodePass/check-code/v1", L = 3)
check_code = WORDS[code[0]] + "-" + WORDS[code[1]] + "-" + WORDS[code[2]]
```

`WORDS` は `src/words.rs` の256語（並び順も仕様の一部）。24ビットしかないため、総当たりの手がかりとしては
生成済みパスワード1つよりはるかに弱い。

## Gitからの読み込み

`--git REV` を付けると、作業中のファイルではなくコミットに入っている内容（`git cat-file blob <commit>:./<file>`
の出力）を `source` として使う。Gitの改行コード変換やファイルの編集の影響を受けない。
登録時は `REV` を完全なコミットID（40または64桁の16進）に解決して保存する。

## テストベクター

`tests/vectors.rs` に固定入力と期待される出力（パスワード4件と確認コード）を置いている。別実装はこれと一致することを確認すること。

## プロファイル（バックアップ）形式

`codepass init` / `profile export` が書く JSON。秘密情報（マスターシークレット・生成済みパスワード）は含まない。

```json
{
  "format_version": 2,
  "spec_version": 1,
  "salt": "<16バイトの16進>",
  "entries": [
    {
      "source_sha256": "<32バイトの16進>",
      "settings": { "site": "github.com", "account": "", "length": 24, "charset": "strong",
                    "revision": 1, "require_classes": true, "spec_version": 1 },
      "source_path": "/Users/me/keys/main.py",
      "git_commit": "<コミットID。Gitから読んだときだけ>"
    }
  ]
}
```

- `format_version` 1 は `source_path` / `git_commit` を持たない旧形式。どちらも読み込める。
- エントリは「サービス・アカウント・更新番号」で区別する。同じ組み合わせで内容が違う登録は、明示しない限り置き換えない。
- `init` / `profile export` / `profile import` は既存ファイルを上書きしない。登録の追加・削除は一時ファイルに書いてから
  置き換え、その前後で salt が変わっていないことを確かめる（salt が変わると全パスワードを再生成できなくなるため）。
