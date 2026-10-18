#!/usr/bin/env bash
# Builds the WebAssembly core once and places it in the web demo and the extension.
# Needs: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli
# (same version as the wasm-bindgen crate in Cargo.lock).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked --release -p codepass-web --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript --out-dir web/www/pkg \
  target/wasm32-unknown-unknown/release/codepass_web.wasm
rm -rf extension/pkg
cp -R web/www/pkg extension/pkg
echo "web/www/pkg と extension/pkg を更新しました"
