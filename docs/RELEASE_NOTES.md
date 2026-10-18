**実験的なリリースです。** 暗号設計の第三者レビューが終わるまで、重要なアカウントには使わないでください。

## v0.3.0 — セキュリティの強化と「証拠で示す」検証

新しい機能:

- **フィッシング対策**: 登録済みサービスと見た目がそっくりな別ドメイン（キリル文字の `і` を使った `gіthub.com`、`paypa1.com` など）を検出し、`get` はパスワードを出さない
- **設定の改ざん検知**: 各登録にマスター鍵から作った HMAC 署名を付け、書き換えを検知。登録済みのサービスではシークレットの打ち間違いも確実に検出
- **セキュリティキー（任意・実験的）**: `init --hardware-key` で FIDO2 キーの hmac-secret を鍵導出に混ぜる（`--features fido2` のビルド。実機での確認はまだ）
- **メモリ保護**: コアダンプ無効化、鍵を置くメモリの mlock とゼロ埋め、Linux では ptrace を拒否
- **`codepass bench`**: このマシンでの鍵導出時間と、総当たりにかかる時間の目安を表示
- **ブラウザ版デモ**: CLI と同じ Rust を WebAssembly にした体験ページ（通信なし）

検証と配布:

- 脅威モデルと攻撃コストの試算（docs/THREAT_MODEL.md）
- Kani による形式検証（文字選択が厳密に一様であることの証明など）、4種類のファジング
- 配布物に Sigstore 署名の SLSA build provenance と SBOM を添付（`gh attestation verify` で確認できる）
- cargo-deny・OpenSSF Scorecard・Actions のコミットID固定

既存のパスワードは変わりません（v1・v2 のテストベクターはそのまま）。設定ファイルの形式は3になります（古い形式も読めます）。

インストール方法と使い方は [README](https://github.com/yotatameguchi-boop/codepass#readme) を見てください。
各ファイルのハッシュは `SHA256SUMS` にあります。
