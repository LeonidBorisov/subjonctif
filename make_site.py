"""Build the password-protected GitHub Pages site from the rendered practicum.
Usage: venv/bin/python make_site.py APP_HTML OUT_DIR PASSWORD
The app HTML is encrypted (PBKDF2-SHA256 -> AES-256-GCM); index.html only holds the ciphertext."""
import base64
import json
import os
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 310000
app_path, out, password = sys.argv[1], sys.argv[2], sys.argv[3]
app = open(app_path, encoding="utf-8").read()

PWA_HEAD = """<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#2b55c9">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Французский">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<link rel="manifest" href="manifest.webmanifest">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<link rel="icon" type="image/png" href="icon-192.png">"""

# extras inside the decrypted app: install hint on phones, "log out" on the progress page
APP_EXTRA = """<script>
(function () {
  var standalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone;
  var ios = /iPhone|iPad|iPod/.test(navigator.userAgent), android = /Android/.test(navigator.userAgent);
  var hidden = false; try { hidden = localStorage.getItem("subjonctif.hint") === "off"; } catch (e) {}
  if ((ios || android) && !standalone && !hidden) {
    var d = document.createElement("div");
    d.style.cssText = "margin:0 0 16px;padding:12px 32px 12px 14px;border-radius:12px;background:var(--accent-soft);font-size:14.5px;line-height:1.45;position:relative";
    d.innerHTML = "<b>Как приложение:</b> " + (ios ? "в Safari нажмите «Поделиться» → «На экран „Домой“»." : "в Chrome откройте меню ⋮ → «Добавить на главный экран».") +
      " Появится иконка, практикум будет открываться на весь экран и работать без интернета." +
      "<button style='position:absolute;top:6px;right:8px;border:0;background:none;font-size:18px;color:var(--muted)' aria-label='Скрыть'>×</button>";
    d.querySelector("button").onclick = function () { d.remove(); try { localStorage.setItem("subjonctif.hint", "off"); } catch (e) {} };
    var home = document.getElementById("v-train"); if (home) home.insertBefore(d, home.firstChild);
  }
  var st = document.getElementById("v-stats");
  if (st) {
    var p = document.createElement("p");
    p.innerHTML = "<button class='btn'>Выйти на этом устройстве</button> <span class='muted small'>понадобится снова ввести пароль; прогресс сохранится</span>";
    p.querySelector("button").onclick = function () { try { localStorage.removeItem("subjonctif.key"); } catch (e) {} location.reload(); };
    st.appendChild(p);
  }
})();
</script>"""

assert app.count("</head>") == 1 and app.count("</body>") == 1
app = app.replace("</head>", PWA_HEAD + "\n</head>").replace("</body>", APP_EXTRA + "\n</body>")

salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())
ct = AESGCM(key).encrypt(iv, app.encode("utf-8"), None)
payload = {"salt": base64.b64encode(salt).decode(), "iv": base64.b64encode(iv).decode(),
           "it": ITER, "ct": base64.b64encode(ct).decode()}

WRAPPER = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Французский практикум</title>
__PWA__
<style>
:root { --bg:#f6f4ef; --surface:#fff; --text:#1d1b18; --muted:#6a655c; --line:#e3ded3; --accent:#2b55c9; --bad:#bf3a2f; color-scheme: light; }
@media (prefers-color-scheme: dark) { :root { --bg:#15161a; --surface:#1e2025; --text:#ebebec; --muted:#9b9ea6; --line:#33363e; --accent:#7fa3ff; --bad:#ff8073; color-scheme: dark; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text);
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; padding: 16px; }
.box { width: 100%; max-width: 380px; background: var(--surface); border: 1px solid var(--line); border-radius: 18px; padding: 28px 24px; box-shadow: 0 6px 24px rgba(0,0,0,.07); }
.logo { width: 64px; height: 64px; border-radius: 16px; display: block; margin: 0 0 14px; }
h1 { font: 600 26px Georgia, "Times New Roman", serif; margin: 0 0 4px; }
p { margin: 0 0 18px; color: var(--muted); }
input[type=password] { width: 100%; font-size: 18px; padding: 12px 14px; border-radius: 11px; border: 1.5px solid var(--line); background: var(--bg); color: var(--text); outline: none; }
input[type=password]:focus { border-color: var(--accent); }
label { display: flex; gap: 8px; align-items: center; margin: 12px 0 18px; font-size: 15px; color: var(--muted); }
label input { width: 18px; height: 18px; accent-color: var(--accent); }
button { width: 100%; font: 600 17px inherit; font-family: inherit; padding: 12px; border: 0; border-radius: 11px; background: var(--accent); color: #fff; cursor: pointer; }
button:disabled { opacity: .6; }
.err { color: var(--bad); font-size: 14.5px; min-height: 22px; margin-top: 10px; }
</style>
</head>
<body>
<form class="box" id="f" autocomplete="on">
  <img class="logo" src="icon-192.png" alt="">
  <h1>Французский практикум</h1>
  <p>Введите пароль.</p>
  <input type="text" name="username" value="subjonctif" autocomplete="username" hidden>
  <input type="password" id="pw" autocomplete="current-password" placeholder="Пароль" required>
  <label><input type="checkbox" id="rem" checked> Запомнить на этом устройстве</label>
  <button id="go">Войти</button>
  <div class="err" id="err"></div>
</form>
<script>
var P = __PAYLOAD__;
var KEY = "subjonctif.key";
function b64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
function toB64(u) { var s = ""; u.forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s); }
async function derive(pw) {
  var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: b64(P.salt), iterations: P.it, hash: "SHA-256" }, base, 256));
}
async function openWith(raw) {
  var key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(P.iv) }, key, b64(P.ct));
  var html = new TextDecoder().decode(pt);
  var doc = new DOMParser().parseFromString(html, "text/html");
  document.replaceChild(document.importNode(doc.documentElement, true), document.documentElement);
  // imported scripts do not run: re-create them so they execute in document order
  Array.prototype.slice.call(document.querySelectorAll("script")).forEach(function (old) {
    var s = document.createElement("script");
    Array.prototype.slice.call(old.attributes).forEach(function (a) { s.setAttribute(a.name, a.value); });
    s.textContent = old.textContent;
    old.parentNode.replaceChild(s, old);
  });
}
if ("serviceWorker" in navigator && location.protocol === "https:") navigator.serviceWorker.register("sw.js").catch(function () {});
(async function () {
  if (!window.crypto || !crypto.subtle) { document.getElementById("err").textContent = "Браузер не поддерживает расшифровку. Откройте страницу в Safari или Chrome по https."; return; }
  var saved = null; try { saved = localStorage.getItem(KEY); } catch (e) {}
  if (saved) { try { await openWith(b64(saved)); return; } catch (e) { try { localStorage.removeItem(KEY); } catch (x) {} } }
  document.getElementById("pw").focus();
})();
document.getElementById("f").addEventListener("submit", async function (e) {
  e.preventDefault();
  var btn = document.getElementById("go"), err = document.getElementById("err");
  btn.disabled = true; btn.textContent = "Проверяю…"; err.textContent = "";
  var remember = document.getElementById("rem").checked;
  try {
    var raw = await derive(document.getElementById("pw").value);
    await openWith(raw);
    if (remember) { try { localStorage.setItem(KEY, toB64(raw)); } catch (x) {} }
  } catch (x) {
    err.textContent = "Неверный пароль. Попробуйте ещё раз.";
    btn.disabled = false; btn.textContent = "Войти";
  }
});
</script>
</body>
</html>
"""

os.makedirs(out, exist_ok=True)
page = WRAPPER.replace("__PWA__", PWA_HEAD).replace("__PAYLOAD__", json.dumps(payload))
open(os.path.join(out, "index.html"), "w", encoding="utf-8").write(page)

manifest = {
    "name": "Французский практикум", "short_name": "Французский", "lang": "ru",
    "start_url": "./", "scope": "./", "display": "standalone",
    "background_color": "#f6f4ef", "theme_color": "#2b55c9",
    "icons": [{"src": "icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
              {"src": "icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"}],
}
open(os.path.join(out, "manifest.webmanifest"), "w", encoding="utf-8").write(json.dumps(manifest, ensure_ascii=False, indent=2))

SW = """const CACHE = "subjonctif-" + "__VER__";
const ASSETS = ["./", "./index.html", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png", "./apple-touch-icon.png"];
self.addEventListener("install", e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS))); self.skipWaiting(); });
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET" || new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(fetch(e.request).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true }).then(r => r || caches.match("./index.html"))));
});
"""
open(os.path.join(out, "sw.js"), "w", encoding="utf-8").write(SW.replace("__VER__", secrets.token_hex(4)))
open(os.path.join(out, ".nojekyll"), "w").close()
print("site written:", sorted(os.listdir(out)), os.path.getsize(os.path.join(out, "index.html")) // 1024, "KB")
