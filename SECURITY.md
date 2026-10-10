# セキュリティポリシー

CodePassは実験段階で、暗号設計の第三者レビューはまだ受けていません。

## 脆弱性の報告

公開のIssueには書かず、GitHubの [Security Advisories（非公開の報告）](https://github.com/yotatameguchi-boop/codepass/security/advisories/new) から送ってください。

特に知りたいこと:

- 生成仕様（[docs/SPEC.md](docs/SPEC.md)）の弱点や、偏りのある文字選択
- マスターシークレットや生成結果がログ・ファイル・プロセス引数などに漏れる経路
- 同じ入力なのにOSや環境で結果が変わるケース

## 対象外

端末自体の侵害、マスターシークレットの盗難、フィッシング、画面・クリップボードの盗み見、saltや入力ファイルの紛失。
