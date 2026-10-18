**実験的なリリースです。** 暗号設計の第三者レビューが終わるまで、重要なアカウントには使わないでください。

## v0.4.0 — ブラウザ拡張と、使い続けられる完成度

- **ブラウザ拡張（Chrome / Edge）**: ログイン画面でアイコンを押し、シークレットを入れるだけ。CLI と同じ Rust を WebAssembly にして使うので、同じパスワードになる
  - 手入力ではなく、ブラウザが開いているドメインで判定。Punycode（`xn--…`）のそっくりな偽ドメインも見抜いて、パスワードを作らない
  - `login.github.com` のようなサブドメインは登録済みの `github.com` として扱う（`evilgithub.com` は扱わない）
  - 権限は activeTab・scripting・storage だけ。マスターシークレットは保存しない
- **`codepass doctor`**: 材料のファイルが変わっていないか、署名・短すぎる設定・そっくりな登録の有無などを点検し、直し方を表示
- **初期設定後の案内**: `init` のあとに、バックアップ・材料の固定・最初の登録の3ステップを表示
- CLI でも Punycode の URL を貼った場合にそっくり判定するよう修正

### v0.3 からの主な変更（まとめ）

- フィッシング対策（Unicode TR39）、設定の改ざん検知（HMAC 署名）、メモリ保護、セキュリティキー（実験的）
- `codepass bench`、脅威モデル（docs/THREAT_MODEL.md）、Kani による形式検証、4種類のファジング
- 配布物に Sigstore 署名の SLSA build provenance と SBOM を添付（`gh attestation verify` で確認できる）
- ブラウザ版デモ: https://yotatameguchi-boop.github.io/codepass/

既存のパスワードは変わりません（v1・v2 のテストベクターはそのまま）。

インストール方法と使い方は [README](https://github.com/yotatameguchi-boop/codepass#readme) を見てください。
各ファイルのハッシュは `SHA256SUMS` にあります。
