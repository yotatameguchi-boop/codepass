import init, { match_site, derive_entry } from "./pkg/codepass_web.js";

const $ = (id) => document.getElementById(id);
const show = (id, on = true) => ($(id).hidden = !on);

let tab = null;
let host = "";
let password = "";

function fromBase64(text) {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

async function activeTab() {
  const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
  return t;
}

// Runs inside the page (top frame only). Fills the focused password field, or the
// first visible one, the way a person typing would, so frameworks notice the value.
function fillPassword(value) {
  const usable = (el) =>
    el instanceof HTMLInputElement && el.type === "password" && !el.disabled && !el.readOnly && el.offsetParent !== null;
  const field = usable(document.activeElement)
    ? document.activeElement
    : [...document.querySelectorAll("input[type=password]")].find(usable);
  if (!field) return "no-field";
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  setter.call(field, value);
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
  field.focus();
  return "filled";
}

async function main() {
  $("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());

  tab = await activeTab();
  let url;
  try {
    url = new URL(tab?.url ?? "");
  } catch {
    url = null;
  }
  if (!url || !["https:", "http:"].includes(url.protocol)) {
    $("host").textContent = "（このページでは使えません）";
    return;
  }
  host = url.hostname;
  $("host").textContent = host;
  $("scheme").textContent = url.protocol === "https:" ? "HTTPS で接続されています" : "注意: HTTPS ではありません";
  if (url.protocol !== "https:") $("scheme").classList.add("warn");

  const { profile, sources } = await chrome.storage.local.get(["profile", "sources"]);
  if (!profile) {
    show("setup");
    return;
  }
  await init();
  const m = JSON.parse(match_site(profile, host));
  if (host.split(".").some((label) => label.toLowerCase().startsWith("xn--"))) {
    // Browsers show Punycode; say what the name looks like to a reader.
    $("looks").textContent = `見た目の表記: ${m.site_key}`;
    show("looks");
  }
  for (const w of m.warnings) {
    const li = document.createElement("li");
    li.textContent = w;
    $("warnings").append(li);
  }
  if (m.lookalikes.length > 0) {
    $("danger-text").textContent =
      `このページ（${m.site_key}）は、登録済みの「${m.lookalikes.join("」「")}」と見た目がそっくりな別のドメインです。` +
      "フィッシングサイトの可能性が高いため、パスワードは作りません。";
    show("danger");
    return;
  }
  if (m.matches.length === 0) {
    $("register-cmd").textContent = `codepass generate <材料のファイル> --site ${m.site_key} --git <タグ>`;
    show("unregistered");
    return;
  }
  for (const e of m.matches) {
    const opt = document.createElement("option");
    opt.value = String(e.index);
    opt.textContent = `${e.site}${e.account ? " / " + e.account : ""}（更新${e.revision}・${e.length}文字）`;
    opt.dataset.sha = e.source_sha256;
    $("entry").append(opt);
  }
  show("form");
  $("secret").focus();

  $("form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("error").textContent = "";
    show("result", false);
    const opt = $("entry").selectedOptions[0];
    const source = sources?.[opt.dataset.sha];
    if (!source) {
      $("error").textContent = "この登録の材料のファイルが読み込まれていません。設定画面で読み込んでください。";
      return;
    }
    $("go").disabled = true;
    $("go").textContent = "計算中…";
    await new Promise((r) => setTimeout(r, 0));
    try {
      const out = JSON.parse(derive_entry(profile, Number(opt.value), fromBase64(source), $("secret").value));
      password = out.password;
      $("check").textContent = out.check_code;
      $("note").textContent = out.note ?? "";
      show("result");
    } catch (e) {
      $("error").textContent = String(e.message ?? e);
    } finally {
      $("secret").value = "";
      $("go").disabled = false;
      $("go").textContent = "パスワードを作る";
    }
  });

  $("fill").addEventListener("click", async () => {
    // The page may have navigated since the popup opened: fill only the same host.
    const now = await activeTab();
    let nowHost = "";
    try {
      nowHost = new URL(now?.url ?? "").hostname;
    } catch {
      nowHost = "";
    }
    if (!now || now.id !== tab.id || nowHost !== host) {
      $("error").textContent = "ページが変わったため入力しませんでした。もう一度開いてください。";
      return;
    }
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillPassword,
      args: [password],
    });
    if (res?.result === "filled") {
      password = "";
      $("fill").textContent = "入力しました";
      setTimeout(() => window.close(), 900);
    } else {
      $("error").textContent = "パスワードの入力欄が見つかりませんでした。入力欄をクリックしてからもう一度試してください。";
    }
  });

  $("copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(password);
    $("copy").textContent = "コピーしました";
    $("note").textContent = "20秒後に消します（それまでこの画面を開いたままにしてください）";
    setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === password) await navigator.clipboard.writeText("");
      } catch {
        // Reading the clipboard can be refused; then leave it as is.
      }
      $("copy").textContent = "コピー";
    }, 20000);
  });
}

main().catch((e) => {
  $("error").textContent = String(e.message ?? e);
});
