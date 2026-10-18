import init, { inspect_profile, entry_hash_for } from "./pkg/codepass_web.js";

const $ = (id) => document.getElementById(id);
const MAX_SOURCE_BYTES = 1024 * 1024;

function toBase64(bytes) {
  let raw = "";
  for (let i = 0; i < bytes.length; i += 0x8000) raw += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(raw);
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function gitHint(e) {
  if (!e.git_commit || !e.source_path) return "";
  const slash = Math.max(e.source_path.lastIndexOf("/"), e.source_path.lastIndexOf("\\"));
  const dir = e.source_path.slice(0, slash);
  const name = e.source_path.slice(slash + 1);
  return `git -C "${dir}" show ${e.git_commit.slice(0, 12)}:./${name} > ${name}`;
}

async function render() {
  const { profile, sources = {} } = await chrome.storage.local.get(["profile", "sources"]);
  const body = $("entries").querySelector("tbody");
  body.replaceChildren();
  if (!profile) {
    $("empty").hidden = false;
    $("profile-status").textContent = "未読み込み";
    return;
  }
  const info = JSON.parse(inspect_profile(profile));
  $("empty").hidden = info.entries.length > 0;
  const have = info.entries.filter((e) => sources[e.source_sha256]).length;
  $("profile-status").textContent = `読み込み済み: 登録 ${info.entries.length} 件（材料あり ${have} 件）` +
    (info.hardware_key ? "。セキュリティキーを使う設定は CLI で使ってください" : "");
  for (const e of info.entries) {
    const tr = document.createElement("tr");
    const ok = Boolean(sources[e.source_sha256]);
    const kind = e.material ? "（構文）" : "";
    const cells = [e.site, e.account || "—", String(e.revision), (ok ? "✓ 読み込み済み" : "未読み込み") + kind];
    for (const text of cells) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.append(td);
    }
    tr.lastChild.className = ok ? "ok" : "warn";
    if (!ok && gitHint(e)) {
      const hint = document.createElement("p");
      hint.className = "mono code";
      hint.textContent = gitHint(e);
      tr.lastChild.append(hint);
    }
    body.append(tr);
  }
}

async function main() {
  await init();
  await render();

  $("profile").addEventListener("change", async () => {
    $("error").textContent = "";
    const file = $("profile").files[0];
    if (!file) return;
    try {
      const text = await file.text();
      inspect_profile(text); // throws on anything the CLI would reject
      await chrome.storage.local.set({ profile: text });
      await render();
    } catch (e) {
      $("error").textContent = "設定ファイルを読み込めません: " + String(e.message ?? e);
    }
  });

  $("sources").addEventListener("change", async () => {
    $("error").textContent = "";
    const { profile, sources = {} } = await chrome.storage.local.get(["profile", "sources"]);
    if (!profile) {
      $("error").textContent = "先に設定ファイルを読み込んでください";
      return;
    }
    const entries = JSON.parse(inspect_profile(profile)).entries;
    let added = 0;
    let skipped = 0;
    for (const file of $("sources").files) {
      if (file.size > MAX_SOURCE_BYTES) {
        skipped++;
        continue;
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      const byteHash = await sha256Hex(bytes);
      let matched = false;
      for (const e of entries) {
        // Syntax-material entries compare the token stream, so a reformatted or
        // commented copy of the registered code still matches.
        let h = byteHash;
        if (e.material) {
          try {
            h = entry_hash_for(profile, e.index, bytes);
          } catch {
            continue;
          }
        }
        if (h === e.source_sha256) {
          sources[e.source_sha256] = toBase64(bytes);
          matched = true;
        }
      }
      if (matched) added++;
      else skipped++;
    }
    await chrome.storage.local.set({ sources });
    $("sources-status").textContent = `保存 ${added} 件` + (skipped ? `・どの登録とも中身が一致しないため保存しなかったもの ${skipped} 件` : "");
    await render();
  });

  $("clear").addEventListener("click", async () => {
    await chrome.storage.local.clear();
    $("sources-status").textContent = "";
    await render();
  });
}

main().catch((e) => {
  $("error").textContent = String(e.message ?? e);
});
