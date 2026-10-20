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

## 構文の材料（`material = "syntax-v1"`）

`--material syntax` で登録したエントリは、`code_hash` をファイルのバイト列ではなく、コードを字句（トークン）に
分けた列から作る。コメント・空白・改行・インデントの幅・末尾のカンマは捨て、名前・演算子・リテラル・
（Python では）インデントの構造は残す。**整形やコメントを変えてもパスワードは変わらず、処理を変えると変わる。**

構文解析器（tree-sitter など）は使わない。版によって結果が変わりうるうえ、別の言語で同じ結果を再現できないため。
以下の規則がすべてで、`docs/reference_syntax.py` はこの節だけから書いた別実装である。

```
code_hash = SHA-256("CodePass/syntax-v1" || 0x00 || lang || 0x00 || Σ (u32be(len(tok)) || tok))
```

`tok` は UTF-8 のバイト列。`source_sha256` にはこの値が入り、`mac` の対象にも `material` が加わる（下記）。

### 言語（拡張子で決める。大文字小文字は区別しない）

| lang | 拡張子 | 行コメント | ブロックコメント | 入れ子 | 引用 |
|---|---|---|---|---|---|
| `c` | c h cc cpp cxx hpp hh cs java | `//` | `/* */` | なし | `"` `'` |
| `js` | js jsx mjs cjs ts tsx | `//` | `/* */` | なし | `"` `'` `` ` `` |
| `go` | go | `//` | `/* */` | なし | `"` `'` `` ` `` |
| `rust` | rs | `//` | `/* */` | あり | `"`（`'` は下記） |
| `nested-c` | kt kts scala swift dart | `//` | `/* */` | あり | `"` `'` |
| `python` | py pyi | `#` | なし | — | `"` `'` |

それ以外の拡張子は構文の材料にできない（エラー）。入力は UTF-8 でなければならず、先頭の U+FEFF は除く。

### 文字の分類

- 空白: U+0009〜U+000D、U+0020、U+0085、U+00A0、U+1680、U+2000〜U+200A、U+2028、U+2029、U+202F、U+205F、U+3000、U+FEFF
  （U+FEFF は先頭以外にあっても空白。ファジングで、途中の U+FEFF が字句の一部になる不整合が見つかったため）
- 語の文字: ASCII の英数字、`_`、`$`、および空白でない U+0080 以上のすべての文字
- 改行: U+000A だけ（U+000D は空白として捨てる。CRLF も LF と同じ）

### 字句の切り出し（先頭から順に、最初に当てはまった規則を使う）

1. Python で、`\` の直後が改行（LF または CRLF）なら、両方を捨てて次の行につなぐ。
2. 改行は捨てる。Python で括弧の外なら、その行に字句があれば `NEWLINE` を出し、次の行の先頭でインデントを測る。
3. 空白は捨てる。
4. コメント（上の表）は終わりまで捨てる。行コメントは改行の手前まで。入れ子ありのブロックコメントは `/*` と `*/` を数える。
   閉じていなければエラー。
5. 引用: `"`、（Rust 以外の）`'`、（js・go の）`` ` `` で始まる。同じ文字が3つ続けば三重引用（`` ` `` 以外。Python 以外では `"""` だけ）。
   `\` は常に次の1文字を飛ばす。閉じ引用まで（改行をまたいでもよい）を、引用符ごと1つの字句にする。閉じていなければエラー。
6. Rust の `'`: 次が `\` なら文字リテラル（5と同じ規則）。2文字先が `'` なら3文字で1つの文字リテラル。どちらでもなければ
   `'` だけを1つの字句にする（ライフタイム）。
7. 語の文字の連続を1つの字句にする。ただし直後が引用なら前置きとして引用と1つにする:
   Rust の `r` `br` `cr` に `#`*`"` が続く生文字列（同じ数の `#` が付いた `"` で閉じる）、Rust の `b"` `c"` `b'`、
   Python の `rRbBfFuU` からなる1〜2文字。
8. それ以外の文字は、その1文字を1つの字句にする（`<=` も `<` と `=` の2つ）。Python では `([{` で括弧の深さを1増やし、
   `)]}` で1減らす（0未満にはしない）。

### Python のインデント

括弧の外で新しい行を始めるたびに、行頭の空白を幅として数える（空白=1、タブ=次の8の倍数まで、U+000C=0にもどす）。
空行とコメントだけの行は数えない。幅が直前より大きければ `INDENT` を出して積み、小さければ一致するまで `DEDENT` を出して
降ろす。一致する幅がなければエラー。終わりに、最後の行に字句があれば `NEWLINE`、積まれた数だけ `DEDENT` を出す。
`NEWLINE` `INDENT` `DEDENT` はそれぞれ U+0000 に続けて `NEWLINE` `INDENT` `DEDENT` と書いた字句として扱う
（実際のコードの字句と重ならない）。

### 末尾のカンマ

閉じ括弧（`)` `]` `}`）の直前に続くカンマはまとめて捨てる。ただし Python で、閉じ括弧が `)` で、その括弧の中のカンマが
ちょうど1つでそれが直前にある場合（要素1つのタプル `(x,)`）は残す。関数の引数が1つで末尾にカンマがある場合も
同じ形なので残る（構文解析をしない以上、タプルと区別できないため、意味を変えない側に倒す）。

### 区別しない（設計上の割り切り）

- 改行の意味（Go や JavaScript で改行が文の区切りになる場合、Python の括弧内）
- 引用符の種類の違いは区別する（`'a'` と `"a"` は別）。数値の書き方の違い（`1_000` と `1000`）も区別する
- C++ の生文字列 `R"(...)"` と C# の逐語的文字列 `@"..."` は、上の規則どおりに機械的に切る（結果は決まっている）

## チームの共有（緊急用アカウント）

チームの設定（`team` がある設定）では、マスターシークレットの代わりに、ランダムな32バイトのチームの秘密を使う。
チームの秘密は Shamir の秘密分散で n 個の共有に分け、どれか k 個があれば復元でき、k-1 個以下では何もわからない。
チームの秘密そのものはどこにも保存しない。分割には `blahaj` クレートを使う（独自に実装しない）。

```
分割      : 各バイトについて、定数項が秘密で残りがランダムな k-1 次多項式を GF(2^8)（既約多項式 0x11d）上で作り、
            x = 1, 2, …, n での値を共有とする
復元      : k 個の共有から、x = 0 でのラグランジュ補間で各バイトを求める
master    = HKDF-SHA256(salt = 設定の salt, ikm = チームの秘密, info = "CodePass/team-master/v1", L = 32)
verifier  = HKDF-SHA256(salt = "CodePass/team/v1", ikm = チームの秘密, info = "CodePass/team-verifier/v1", L = 16)
```

チームの秘密は256ビットの乱数なので、Argon2id は通さない。`master` 以降（確認コード・生成・署名・封印）は個人の設定と同じ。

共有の書式（人が書き写す前提。空白・改行・大文字小文字は無視する）:

```
cpshare1-<set_id 8桁>-<k>-<x 2桁>-<y を4バイトずつ8組>-<checksum 8桁>
checksum = SHA-256("CodePass/share/v1" || 0x00 || set_id || u8(k) || u8(x) || y) の先頭4バイト
```

- `set_id` は分割のたびに新しくなるランダムな4バイト。違う分割の共有を混ぜると拒否する。
- 復元したら `verifier` と比べ、合わなければ何も作らない（Shamir は単独では誤りを検出できないため）。
- 配り直し（`team reshare`）は同じ秘密を新しい `set_id` で分け直す。古い共有も k 個集めれば数学的には同じ秘密を復元できるので、
  共有が漏れた・持っていた人が抜けたときは、秘密ごと更新する（`rotate start --threshold --shares`）。

## パスワードの一斉更新

`rotate start --to <新しい設定>` は、新しい salt と、新しいシークレット（または新しいチームの秘密、必要なら新しいコード）で
新しい設定を作り、古い設定の全登録を同じ設定値のまま写して署名し直す（封印していたものは封印する）。新しい設定には
`rotation = { from: 古い設定ファイル, pending: [(新しい番号, 古い番号), …] }` を記録し、`rotate next` が1件ずつ
古いパスワードと新しいパスワードを出して、終わったものを `pending` から外す。全件終われば `rotation` を消す。

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

## 関数単位の材料（`material = "symbol-v1"`）

`--symbol <名前>` で登録したエントリは、ファイルの中の1つの定義（関数・クラス・定数など）の字句だけを材料にする。
同じファイルのほかの部分を書き換えても、この材料は変わらない。1つのファイルを、サービスごとに関数を割り当てた「鍵束」にできる。

```
code_hash = SHA-256("CodePass/symbol-v1" || 0x00 || lang || 0x00 || 名前 || 0x00 || Σ (u32be(len(tok)) || tok))
```

字句は上の「構文の材料」の規則で切り出した列。その中で、次の規則で見つかった**最初の**定義の範囲を使う
（各字句について、1→2→3 の順に試す）:

1. 字句 `w` が語で、直前の字句が定義語（`fn func function def class struct enum trait interface type impl mod module
   object fun val var let const static union namespace record mut`）であり、`w` 自身は定義語でなく、直後の字句が語でなく、
   2つ前の字句が `'` でない（`&'static str` を除くため）とき、`w` を名前とする。範囲は定義語から:
   - Python の `def` `class`: その行の `NEWLINE` まで。直後に `INDENT` があれば、対応する `DEDENT` まで
   - Python のそれ以外: その行の `NEWLINE` まで
   - それ以外の言語: `w` の後で、`(` `[` の外にある最初の `{` に対応する `}` まで。それより先に `;` があればその `;` まで。
     どちらもなければ最後まで
2. Python で、文の先頭（直前が `NEWLINE` `INDENT` `DEDENT` か、ファイルの最初）の語のすぐ後が `=` のとき、その語から行の `NEWLINE` まで。
3. Python 以外で、語 `w` の直後が `(` で、直前が語（`if while for switch return else catch sizeof new case do throw await` を除く）か
   `* & > ] )` のいずれかであり、1 の規則の `{` が `;` より先に見つかるとき（C・Java・Go のメソッドなど）、`w` から対応する `}` まで。

`definitions` はこれらを順に集めた一覧で、`inspect --symbols` が表示する。`docs/reference_syntax.py` はこの規則だけから
書いた別実装で、ランダムな3万件の入力について、定義の一覧と各定義のハッシュが Rust 版と完全に一致することを CI で確かめている。

## リポジトリ単位の材料（`material = "tree-v1"`）

`--tree --git <REV>` で、フォルダ（リポジトリ全体やその中のディレクトリ）を材料にする。

```
tree      = git rev-parse <commit>:./     -- そのフォルダの Git のツリーオブジェクトの ID（40 または 64 桁の16進）
code_hash = SHA-256("CodePass/tree-v1" || 0x00 || tree)
```

ツリーの ID は、その下のすべてのファイルの中身と名前から Git が計算する。どれか1つでも変われば別の値になる。
コミットの指定が必須（作業中のフォルダは材料にしない）。Git の外では計算できないので、ブラウザ版・拡張では使えない。
封印と組み合わせると、非公開のリポジトリ全体が第2の要素になる。

## 署名したコミットだけを材料にする（`signer`）

`--require-signed`（`--git` と一緒に使う）で登録すると、コミットに有効な署名があることを Git 自身の検証
（`git log -1 --format=%G?%x00%GK <commit>` が `G` を返すこと。GPG、または `gpg.ssh.allowedSignersFile` を使った SSH 署名）で確かめ、
署名した鍵（`%GK`）を `signer` に記録する。`get` などのたびに同じ鍵で署名されていることを確かめる。
誰かがリポジトリに別のコミットを入れても、自分の鍵で署名されていなければ材料として使われない。

## 材料の封印（コードを第2の要素にする）

通常の登録は、生成に使う `code_hash` を `source_sha256` としてそのまま保存する。これだと設定ファイルとシークレットを
盗まれれば、コードがなくてもパスワードを作れる。封印した登録は `source_sha256` を空にし、代わりに次の値を
`source_check` として保存する。

```
check_key    = HKDF-SHA256(salt = "CodePass/HKDF/v1", ikm = master, info = "CodePass/code-check/v1", L = 32)
source_check = HMAC-SHA256(check_key, code_hash)        -- 64桁の16進
```

- 生成には `code_hash` をこれまでどおり使うので、**封印してもパスワードは変わらない**。
- 照合は、シークレットから `master` を作った後に、材料から計算した `code_hash` で `source_check` を作り直して
  定数時間で比べる。シークレットなしでは照合も推測もできない。
- 設定ファイル＋シークレットを手に入れた攻撃者は、コードを推測で当てる必要がある。コードが公開されていたり
  短かったりすると意味がないため、非公開で十分な長さのコードに使う。
- `generate --seal-code` で最初から封印、`profile seal-code` で既存の登録をまとめて封印する（署名も付け直す）。

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
        || opt(material)                           -- material があるときだけ付ける
        || 0x02 || lp(source_check)                -- 封印した登録だけ付ける
        || 0x03 || lp(symbol)                      -- 関数単位の材料だけ付ける
        || 0x04 || lp(signer)                      -- 署名したコミットだけを認める登録だけ付ける
mac     = HMAC-SHA256(mac_key, data)

lp(x)  = u32be(len(x)) || x                        -- x は UTF-8 バイト列
opt(x) = 0x00（なし） または 0x01 || lp(x)
```

比較は定数時間で行う。v0.2 以前に登録したエントリには署名がなく、その場合は注意を表示して続行する。

## ページとの照合（生成には使わない）

ブラウザ拡張と `get` は、開いているページや入力された URL がどの登録に当たるかを決めるとき、`xn--` で始まる
ラベルだけを Punycode から Unicode に戻し（IDNA の ToUnicode は使わない）、そのうえで v2 の正規化をかけて比べる。
`login.github.com` のように、登録した名前の前にラベルが付いたものも同じ登録として扱う（`evilgithub.com` は扱わない）。
この変換は**照合とそっくり判定だけ**に使い、パスワードの生成（context）には影響しない。

## Gitからの読み込み

`--git REV` を付けると、作業中のファイルではなくコミットに入っている内容（`git cat-file blob <commit>:./<file>`
の出力）を `source` として使う。Gitの改行コード変換やファイルの編集の影響を受けない。
登録時は `REV` を完全なコミットID（40または64桁の16進）に解決して保存する。

## テストベクター

`tests/vectors.rs` に固定入力と期待される出力（v1を4件・v2を3件、確認コード、セキュリティキーの応答を混ぜた場合、
エントリの署名、構文の材料の Rust・Python 各1件）を置いている。構文の材料は、ランダムに作った3万件の入力で
Rust 版と Python 版の結果（エラーになるかどうかも含めて）が完全に一致することを CI で確かめている（`docs/syntax_corpus.py`）。
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
      "mac": "<署名。64桁の16進>",
      "material": "<構文の材料のときだけ syntax-v1>",
      "source_check": "<封印した登録だけ。このとき source_sha256 は書かない>"
    }
  ],
  "hardware_key": { "credential_id": "<16進>", "rp_id": "codepass" }
}
```

- `format_version` 1 は `source_path` / `git_commit` を、2 は `mac` / `hardware_key` を持たない旧形式。どれも読み込める。
- `hardware_key` は `init --hardware-key` のときだけ設定でき、salt と同じく後から変更できない。
- `team`（`threshold`・`shares`・`set_id`・`verifier`）はチームの設定だけにある。配り直しで `set_id` 等は変わるが、`verifier`（秘密）は変えられない。
  `hardware_key` とは同時に使えない。
- `rotation` は一斉更新の途中にだけある。
- `site` は入力されたまま保存し、照合のたびにそのエントリの版の正規化をかける。
- エントリは「サービス・アカウント・更新番号」で区別する。同じ組み合わせで内容が違う登録は、明示しない限り置き換えない。
- `init` / `profile export` / `profile import` は既存ファイルを上書きしない。登録の追加・削除は一時ファイルに書いてから
  置き換え、その前後で salt と `hardware_key` が変わっていないことを確かめる（変わると全パスワードを再生成できなくなるため）。
