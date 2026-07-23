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
      "default-src 'none'; style-src 'self'; script-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    ...SEC_HEADERS,
  };
}

export function textHeaders(ct) {
  return { "content-type": ct, "cache-control": "public, max-age=300", ...SEC_HEADERS };
}

const SPARK = `<svg class="spark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 0l2.1 9.9L24 12l-9.9 2.1L12 24l-2.1-9.9L0 12l9.9-2.1z" fill="#ff6a1f"/></svg>`;

const COPY_JS = `
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',()=>{
  navigator.clipboard.writeText(b.dataset.copy).then(()=>{
    const t=b.textContent;b.textContent='copied';b.classList.add('ok');
    setTimeout(()=>{b.textContent=t;b.classList.remove('ok')},1200);
  });
}));
`;

// hart forge design system (workshop). styling is served from /hartforge.css.
export async function renderIdentity(identity, origin) {
  const url = `${origin}/${identity.handle}`;
  const keyPanels = await Promise.all(
    identity.keys.map(async (k) => {
      const p = parseKey(k.line);
      const bytes = await sha256(p.blob);
      const fp = fpString(bytes);
      const art = randomart(bytes, algoHeader(p.algo));
      const line = esc(k.line.trim());
      return `<div class="key">
        <div class="keyhd"><span class="badge">${esc(p.label)}</span><span class="kname">${esc(k.label || p.comment || "key")}</span>${k.added ? `<span class="kdate">added ${esc(fmtDate(k.added))}</span>` : ""}</div>
        <div class="keybody">
          <div class="kmain">
            <dl class="spec"><dt>fingerprint</dt><dd><b>${esc(fp)}</b></dd>${p.comment ? `<dt>comment</dt><dd>${esc(p.comment)}</dd>` : ""}</dl>
            <button class="copy" data-copy="${line}">copy key</button>
          </div>
          <pre class="art">${esc(art)}</pre>
        </div>
      </div>`;
    })
  );

  const curl = `curl -fsSL ${url}.keys >> ~/.ssh/authorized_keys`;
  const install = `curl -fsSL ${url}.sh | sh`;
  const n = identity.keys.length;
  const desc = `ssh public keys for ${identity.name}`;

  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(identity.name)} · keys.hartforge.dev</title>
<meta name="description" content="${esc(desc)}">
<meta name="theme-color" content="#0f1113">
<link rel="canonical" href="${esc(url)}">
<meta property="og:title" content="${esc(identity.name)} · keys.hartforge.dev">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${esc(url)}">
<meta property="og:image" content="${esc(origin)}/og/${esc(identity.handle)}.png">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="2400">
<meta property="og:image:height" content="1260">
<meta property="og:image:alt" content="${esc(desc)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(identity.name)} · keys.hartforge.dev">
<meta name="twitter:description" content="${esc(desc)}">
<meta name="twitter:image" content="${esc(origin)}/og/${esc(identity.handle)}.png">
<link rel="icon" href="/favicon.svg?v=2">
<link rel="stylesheet" href="/hartforge.css">
</head><body><div class="page">
<div class="banner">
  <a class="brand" href="https://hartforge.dev">${SPARK}<span class="wordmark">hart forge</span></a>
  <span class="rev">keys</span>
</div>

<div class="sec">
  <div class="lbl">keys</div>
  <div class="who"><h1>${esc(identity.name)}</h1><span class="handle">@${esc(identity.handle)}</span></div>
  <div class="count">${n} public key${n === 1 ? "" : "s"} · authorized for ssh</div>
  ${keyPanels.join("\n")}
</div>

<div class="sec">
  <div class="lbl">install</div>
  <div class="note">idempotent sync — re-run anytime; adds new keys, removes revoked ones, never dupes.</div>
  <div class="cmd"><span class="sig">$</span> curl <span class="flag">-fsSL</span> ${esc(url)}.sh | sh<button class="cbtn" data-copy="${esc(install)}">copy</button></div>
  <div class="cmd"><span class="sig">$</span> curl <span class="flag">-fsSL</span> ${esc(url)}.keys &gt;&gt; ~/.ssh/authorized_keys<button class="cbtn" data-copy="${esc(curl)}">copy</button></div>
</div>

<footer>keys.hartforge.dev · raw <a href="${esc(url)}.keys">/${esc(identity.handle)}.keys</a> · installer <a href="${esc(url)}.sh">/${esc(identity.handle)}.sh</a></footer>
</div><script>${COPY_JS}</script></body></html>`;
}
