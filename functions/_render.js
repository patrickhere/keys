// key parsing, fingerprinting, randomart, and html rendering. no external deps, runs on the workers runtime.

const ALGO_LABELS = {
  "ssh-ed25519": "ed25519",
  "ssh-rsa": "rsa",
  "ssh-dss": "dsa",
  "ecdsa-sha2-nistp256": "ecdsa p-256",
  "ecdsa-sha2-nistp384": "ecdsa p-384",
  "ecdsa-sha2-nistp521": "ecdsa p-521",
  "sk-ssh-ed25519@openssh.com": "ed25519 (fido2)",
  "sk-ecdsa-sha2-nistp256@openssh.com": "ecdsa (fido2)",
};

// split an openssh public key line into its parts.
export function parseKey(line) {
  const parts = line.trim().split(/\s+/);
  const algo = parts[0] || "";
  const blob = parts[1] || "";
  const comment = parts.slice(2).join(" ");
  return { algo, blob, comment, label: ALGO_LABELS[algo] || algo };
}

// raw sha256 digest bytes of the key blob.
async function sha256(blob) {
  const raw = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  return new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
}

// openssh-style SHA256 fingerprint: base64(digest), no padding.
function fpString(bytes) {
  return "SHA256:" + btoa(String.fromCharCode(...bytes)).replace(/=+$/, "");
}

export async function fingerprint(blob) {
  return fpString(await sha256(blob));
}

// header shown on the randomart border, e.g. "ED25519 256".
function algoHeader(algo) {
  if (algo === "ssh-ed25519") return "ED25519 256";
  if (algo === "ssh-rsa") return "RSA";
  if (algo === "ssh-dss") return "DSA";
  if (algo.startsWith("ecdsa-sha2-nistp")) return "ECDSA " + algo.slice(-3);
  if (algo.startsWith("sk-ssh-ed25519")) return "ED25519-SK 256";
  if (algo.startsWith("sk-ecdsa")) return "ECDSA-SK 256";
  return algo.toUpperCase();
}

// drunken-bishop randomart from the sha256 digest, matching `ssh-keygen -lv`.
function randomart(bytes, header) {
  const X = 17, Y = 9, aug = " .o+=*BOX@%&#/^SE";
  const len = aug.length - 1; // 16
  const field = Array.from({ length: X }, () => new Array(Y).fill(0));
  let x = X >> 1, y = Y >> 1;
  for (let i = 0; i < bytes.length; i++) {
    let inp = bytes[i];
    for (let b = 0; b < 4; b++) {
      x += inp & 1 ? 1 : -1;
      y += inp & 2 ? 1 : -1;
      x = Math.max(0, Math.min(X - 1, x));
      y = Math.max(0, Math.min(Y - 1, y));
      if (field[x][y] < len - 2) field[x][y]++;
      inp >>= 2;
    }
  }
  field[X >> 1][Y >> 1] = len - 1; // 'S'
  field[x][y] = len; // 'E'
  const border = (label) => {
    const tag = label ? "[" + label + "]" : "";
    if (tag.length >= X) return "+" + tag.slice(0, X) + "+";
    const pad = X - tag.length, l = pad >> 1;
    return "+" + "-".repeat(l) + tag + "-".repeat(pad - l) + "+";
  };
  const rows = [border(header)];
  for (let j = 0; j < Y; j++) {
    let row = "|";
    for (let i = 0; i < X; i++) row += aug[field[i][j]];
    rows.push(row + "|");
  }
  rows.push(border("SHA256"));
  return rows.join("\n");
}

// mm-dd-yyyy authored dates (user-facing); pass through as-is.
function fmtDate(d) {
  return d || "";
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// the raw text served at /<handle>.keys — one pubkey line each, ready for authorized_keys.
export function rawKeys(identity) {
  return identity.keys.map((k) => k.line.trim()).join("\n") + "\n";
}

// the installer served at /<handle>.sh — syncs a managed block, safe to curl | sh repeatedly.
// re-running adds new keys AND removes revoked ones (anything dropped upstream), while
// leaving keys outside the block untouched. echoes each key's fingerprint for confirmation.
export async function installScript(identity, origin) {
  const marker = `keys.hartforge.dev/${identity.handle}`;
  const body = identity.keys.map((k) => k.line.trim()).join("\n");
  const summary = await Promise.all(
    identity.keys.map(async (k) => {
      const p = parseKey(k.line);
      const fp = fpString(await sha256(p.blob));
      const name = k.label || p.comment || p.label;
      return `echo "  ${fp}  ${name}"`;
    })
  );
  return `#!/bin/sh
# ${identity.name} — sync ssh public keys into authorized_keys (managed block, idempotent)
# source: ${origin}/${identity.handle}
# re-run anytime: adds new keys, removes revoked ones, never duplicates.
set -eu
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
AK="$HOME/.ssh/authorized_keys"
touch "$AK" && chmod 600 "$AK"
BEGIN="# >>> ${marker} >>>"
END="# <<< ${marker} <<<"

KEYS_TMP="$HOME/.ssh/.keys.$$"
cat > "$KEYS_TMP" <<'KEYS'
${body}
KEYS

# rebuild authorized_keys: drop the old managed block and any stray copies of these keys,
# keep everything else, then append a fresh block. this is what enables revocation.
AK_TMP="$AK.sync.$$"
awk -v b="$BEGIN" -v e="$END" '
  FNR==NR { if ($0 != "") managed[$0]=1; next }
  $0==b { skip=1; next }
  $0==e { skip=0; next }
  skip==1 { next }
  ($0 in managed) { next }
  { print }
' "$KEYS_TMP" "$AK" > "$AK_TMP"
{
  echo "$BEGIN"
  cat "$KEYS_TMP"
  echo "$END"
} >> "$AK_TMP"
rm -f "$KEYS_TMP"
mv "$AK_TMP" "$AK"
chmod 600 "$AK"

echo "${identity.handle}: synced ${identity.keys.length} key(s) into authorized_keys:"
${summary.join("\n")}
`;
}

// security headers applied to every response.
export const SEC_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

export function htmlHeaders() {
  return {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "public, max-age=300",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    ...SEC_HEADERS,
  };
}

export function textHeaders(ct) {
  return { "content-type": ct, "cache-control": "public, max-age=300", ...SEC_HEADERS };
}

const STYLE = `
:root{color-scheme:dark light}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#0c0e12;color:#e6e6e6;-webkit-font-smoothing:antialiased}
.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace}
.wrap{max-width:760px;margin:0 auto;padding:56px 20px 80px}
header{display:flex;align-items:center;gap:16px;margin-bottom:8px}
.avatar{width:56px;height:56px;border-radius:14px;flex:none;display:grid;place-items:center;
  background:linear-gradient(135deg,#f0883e,#c2410c);color:#1a1200;font-weight:700;font-size:24px}
h1{font-size:24px;margin:0;letter-spacing:-.01em}
.handle{color:#8a94a6;font-size:14px;margin-top:2px}
.tagline{color:#f0883e;font-size:13px;text-transform:lowercase;letter-spacing:.04em;margin-top:2px}
.count{color:#8a94a6;font-size:13px;margin:28px 0 12px}
.card{background:#14171d;border:1px solid #232830;border-radius:12px;padding:16px 18px;margin-bottom:12px}
.card .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.badge{font-size:12px;font-weight:600;color:#f0883e;background:#2a1a10;border:1px solid #452612;
  padding:2px 9px;border-radius:999px}
.klabel{font-weight:600}
.kmeta{color:#6b7484;font-size:12.5px;margin-left:auto}
.fp{color:#a9b3c4;font-size:12.5px;word-break:break-all}
.fp b{color:#e6e6e6;font-weight:600}
.comment{color:#6b7484;font-size:12.5px;margin-top:4px}
.body{display:flex;gap:20px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;margin-top:12px}
.kinfo{flex:1 1 300px;min-width:0}
.randomart{font-size:10.5px;line-height:1.15;color:#6b7484;margin:0;white-space:pre;flex:0 0 auto;
  background:#0a0c10;border:1px solid #232830;border-radius:8px;padding:8px 10px}
.qr{width:104px;height:104px;flex:none;background:#fff;border-radius:8px;padding:6px}
.qr svg{display:block;width:100%;height:100%}
.keyactions{margin-top:16px}
.mini{background:#1c2129;border:1px solid #2e3542;color:#a9b3c4;border-radius:6px;
  padding:4px 10px;font-size:11.5px;cursor:pointer}
.mini:hover{color:#fff;border-color:#f0883e}
.mini.ok{color:#6ee787;border-color:#6ee787}
.usage{margin-top:32px;background:#0f1319;border:1px solid #232830;border-radius:12px;padding:18px}
.usage h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#8a94a6;margin:0 0 6px}
.usage p{color:#6b7484;font-size:12.5px;margin:0 0 12px}
.cmd{position:relative;background:#0a0c10;border:1px solid #232830;border-radius:8px;
  padding:12px 60px 12px 14px;font-size:12.5px;color:#cdd5e0;overflow-x:auto;margin-bottom:10px}
.cmd:last-child{margin-bottom:0}
.copy{position:absolute;top:8px;right:8px;background:#1c2129;border:1px solid #2e3542;color:#a9b3c4;
  border-radius:6px;padding:4px 8px;font-size:11px;cursor:pointer}
.copy:hover{color:#fff;border-color:#f0883e}
.copy.ok{color:#6ee787;border-color:#6ee787}
footer{margin-top:44px;color:#4a515e;font-size:12px}
a{color:#f0883e}
@media(prefers-color-scheme:light){
  body{background:#f7f8fa;color:#1a1d23}
  .card{background:#fff;border-color:#e4e7ec}
  .usage{background:#fff;border-color:#e4e7ec}
  .cmd,.randomart{background:#f2f3f6;border-color:#e4e7ec;color:#333}
  .randomart{color:#5b6473}
  .handle,.kmeta,.comment,.count,.usage p{color:#6b7484}
  .fp{color:#3a4150}.fp b{color:#1a1d23}
  .copy,.mini{background:#eef0f3;border-color:#d8dce2}
}
`;

const COPY_JS = `
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',()=>{
  navigator.clipboard.writeText(b.dataset.copy).then(()=>{
    const t=b.textContent;b.textContent='copied';b.classList.add('ok');
    setTimeout(()=>{b.textContent=t;b.classList.remove('ok')},1200);
  });
}));
`;

// qrSvg is injected by the caller (built in [handle].js from _qr.js) so this module
// stays dependency-light; pass "" to omit.
export async function renderIdentity(identity, origin, qrSvg = "") {
  const url = `${origin}/${identity.handle}`;
  const keyCards = await Promise.all(
    identity.keys.map(async (k) => {
      const p = parseKey(k.line);
      const bytes = await sha256(p.blob);
      const fp = fpString(bytes);
      const art = randomart(bytes, algoHeader(p.algo));
      const meta = k.added ? `added ${esc(fmtDate(k.added))}` : "";
      const line = esc(k.line.trim());
      return `<div class="card">
        <div class="top">
          <span class="badge">${esc(p.label)}</span>
          <span class="klabel">${esc(k.label || p.comment || "key")}</span>
          ${meta ? `<span class="kmeta">${meta}</span>` : ""}
        </div>
        <div class="body">
          <div class="kinfo">
            <div class="fp mono"><b>fingerprint</b> ${esc(fp)}</div>
            ${p.comment ? `<div class="comment mono">${esc(p.comment)}</div>` : ""}
            <div class="keyactions"><button class="mini" data-copy="${line}">copy public key</button></div>
          </div>
          <pre class="randomart mono">${esc(art)}</pre>
        </div>
      </div>`;
    })
  );

  const curl = `curl -fsSL ${url}.keys >> ~/.ssh/authorized_keys`;
  const install = `curl -fsSL ${url}.sh | sh`;
  const n = identity.keys.length;
  const initial = esc((identity.name || identity.handle)[0].toUpperCase());
  const desc = `ssh public keys for ${identity.name}`;

  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(identity.name)} · keys.hartforge.dev</title>
<meta name="description" content="${esc(desc)}">
<meta property="og:title" content="${esc(identity.name)} · keys.hartforge.dev">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${esc(url)}">
<meta name="twitter:card" content="summary">
<link rel="icon" href="/favicon.svg?v=1">
<style>${STYLE}</style></head><body><div class="wrap">
<header>
  <div class="avatar">${initial}</div>
  <div>
    <h1>${esc(identity.name)}</h1>
    <div class="handle mono">@${esc(identity.handle)}</div>
    ${identity.tagline ? `<div class="tagline">${esc(identity.tagline)}</div>` : ""}
  </div>
</header>
<div class="count">${n} public key${n === 1 ? "" : "s"}</div>
${keyCards.join("\n")}
<div class="usage">
  <h2>install on a host</h2>
  <p>idempotent sync — re-run anytime; adds new keys, removes revoked ones, never dupes</p>
  <div class="cmd mono">${esc(install)}<button class="copy" data-copy="${esc(install)}">copy</button></div>
  <h2 style="margin-top:18px">or append manually</h2>
  <div class="cmd mono">${esc(curl)}<button class="copy" data-copy="${esc(curl)}">copy</button></div>
</div>
${qrSvg ? `<div class="usage"><h2>raw keys</h2><p>scan for ${esc(url)}.keys</p><div class="qr">${qrSvg}</div></div>` : ""}
<footer>keys.hartforge.dev · raw at <a href="${esc(url)}.keys">/${esc(identity.handle)}.keys</a> · installer at <a href="${esc(url)}.sh">/${esc(identity.handle)}.sh</a></footer>
</div><script>${COPY_JS}</script></body></html>`;
}
