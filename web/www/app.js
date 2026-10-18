import init, { generate, site_key, random_salt, self_test } from "./pkg/codepass_web.js";

const $ = (id) => document.getElementById(id);
const encoder = new TextEncoder();
let sourceBytes = encoder.encode($("source").value);
let password = "";
let shown = false;

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function refreshHash() {
  $("hash").textContent = "SHA-256: " + (await sha256Hex(sourceBytes)).slice(0, 32) + "…";
}

function refreshSiteKey() {
  $("sitekey").textContent = site_key($("site").value) || "（空）";
}

function clearResult() {
  password = "";
  shown = false;
  $("password").textContent = "—";
  $("check").textContent = "—";
  $("reveal").disabled = $("copy").disabled = true;
  $("reveal").textContent = "表示";
  $("warnings").replaceChildren();
  $("error").textContent = "";
  $("time").textContent = "";
}

// Let the browser paint "計算中…" before the blocking Argon2id call.
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));

async function run() {
  clearResult();
  $("go").disabled = true;
  $("password").textContent = "計算中…";
  await nextFrame();
  const started = performance.now();
  try {
    const out = JSON.parse(
      generate(
        sourceBytes,
        $("secret").value,
        $("salt").value,
        $("site").value,
        $("account").value,
        Number($("length").value),
        $("charset").value === "alnum",
        $("symbols").value,
        Number($("revision").value),
        $("registered").value,
      ),
    );
    password = out.password;
    $("check").textContent = out.check_code;
    $("password").textContent = "•".repeat(password.length);
    $("reveal").disabled = $("copy").disabled = false;
    $("time").textContent = `Argon2id（64MiB・3回）込みで ${((performance.now() - started) / 1000).toFixed(2)} 秒 · サービス: ${out.site_key}`;
    for (const w of out.warnings) {
      const li = document.createElement("li");
      li.textContent = w;
      $("warnings").append(li);
    }
  } catch (e) {
    $("password").textContent = "—";
    $("error").textContent = String(e.message ?? e);
  } finally {
    $("go").disabled = false;
  }
}

async function selfTest() {
  $("selftest").disabled = true;
  $("selftest").textContent = "検証中…";
  await nextFrame();
  const results = JSON.parse(self_test());
  const body = $("vectors").querySelector("tbody");
  body.replaceChildren();
  for (const r of results) {
    const tr = document.createElement("tr");
    for (const [text, cls] of [
      [r.name, ""],
      [r.expected, "mono"],
      [r.actual, "mono"],
      [r.ok ? "✓ 一致" : "✗ 不一致", r.ok ? "ok" : "ng"],
    ]) {
      const td = document.createElement("td");
      td.textContent = text;
      if (cls) td.className = cls;
      tr.append(td);
    }
    body.append(tr);
  }
  $("vectors").hidden = false;
  const passed = results.filter((r) => r.ok).length;
  $("selftest").textContent = `${passed} / ${results.length} 一致`;
  $("selftest").disabled = false;
}

async function main() {
  await init();
  $("salt").value = random_salt();
  refreshSiteKey();
  await refreshHash();
  $("badge").textContent = "通信なし · このブラウザ内で計算";

  $("source").addEventListener("input", async () => {
    sourceBytes = encoder.encode($("source").value);
    await refreshHash();
  });
  $("file").addEventListener("change", async () => {
    const f = $("file").files[0];
    if (!f) return;
    sourceBytes = new Uint8Array(await f.arrayBuffer());
    $("source").value = f.size <= 20000 ? new TextDecoder().decode(sourceBytes) : `（${f.name}・${f.size} バイト）`;
    await refreshHash();
  });
  $("site").addEventListener("input", refreshSiteKey);
  $("newsalt").addEventListener("click", () => {
    $("salt").value = random_salt();
  });
  $("go").addEventListener("click", run);
  $("phish").addEventListener("click", () => {
    // Cyrillic і (U+0456) in place of the Latin i.
    $("site").value = "https://gіthub.com/login";
    refreshSiteKey();
    run();
  });
  $("reveal").addEventListener("click", () => {
    shown = !shown;
    $("password").textContent = shown ? password : "•".repeat(password.length);
    $("reveal").textContent = shown ? "隠す" : "表示";
  });
  $("copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(password);
    $("copy").textContent = "コピーしました（20秒後に消去）";
    setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === password) await navigator.clipboard.writeText("");
      } catch {
        // Reading the clipboard can be refused; then leave it as is.
      }
      $("copy").textContent = "コピー";
    }, 20000);
  });
  $("selftest").addEventListener("click", selfTest);
}

main().catch((e) => {
  $("badge").textContent = "読み込みに失敗しました";
  $("error").textContent = String(e.message ?? e);
});
