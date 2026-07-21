// key parsing, fingerprinting, and html rendering. no external deps, runs on the workers runtime.

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

// openssh-style SHA256 fingerprint: base64(sha256(raw key blob)), no padding.
export async function fingerprint(blob) {
  const raw = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  const b64 = btoa(String.fromCharCode(...digest)).replace(/=+$/, "");
  return "SHA256:" + b64;
}

// dates are authored mm-dd-yyyy (user-facing format); pass through as-is.
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
.usage{margin-top:32px;background:#0f1319;border:1px solid #232830;border-radius:12px;padding:18px}
.usage h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#8a94a6;margin:0 0 12px}
.cmd{position:relative;background:#0a0c10;border:1px solid #232830;border-radius:8px;
  padding:12px 44px 12px 14px;font-size:12.5px;color:#cdd5e0;overflow-x:auto;margin-bottom:10px}
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
  .cmd{background:#f2f3f6;border-color:#e4e7ec;color:#333}
  .handle,.kmeta,.comment,.count{color:#6b7484}
  .fp{color:#3a4150}.fp b{color:#1a1d23}
  .copy{background:#eef0f3;border-color:#d8dce2}
}
`;

const COPY_JS = `
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',()=>{
  navigator.clipboard.writeText(b.dataset.copy).then(()=>{
    const t=b.textContent;b.textContent='copied';b.classList.add('ok');
    setTimeout(()=>{b.textContent=t;b.classList.remove('ok')},1200);
  });
}));
`;

export async function renderIdentity(identity, origin) {
  const url = `${origin}/${identity.handle}`;
  const keyCards = await Promise.all(
    identity.keys.map(async (k) => {
      const p = parseKey(k.line);
      const fp = await fingerprint(p.blob);
      const meta = [k.added && fmtDate(k.added)].filter(Boolean).join("");
      return `<div class="card">
        <div class="top">
          <span class="badge">${esc(p.label)}</span>
          <span class="klabel">${esc(k.label || p.comment || "key")}</span>
          ${meta ? `<span class="kmeta">added ${esc(meta)}</span>` : ""}
        </div>
        <div class="fp mono"><b>fingerprint</b> ${esc(fp)}</div>
        ${p.comment ? `<div class="comment mono">${esc(p.comment)}</div>` : ""}
      </div>`;
    })
  );

  const curl = `curl -fsSL ${url}.keys >> ~/.ssh/authorized_keys`;
  const n = identity.keys.length;
  const initial = esc((identity.name || identity.handle)[0].toUpperCase());

  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(identity.name)} · keys.hartforge.dev</title>
<meta name="description" content="ssh public keys for ${esc(identity.name)}">
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
  <h2>authorize these keys on a host</h2>
  <div class="cmd mono">${esc(curl)}<button class="copy" data-copy="${esc(curl)}">copy</button></div>
  <div class="cmd mono">${esc(url + ".keys")}<button class="copy" data-copy="${esc(url + ".keys")}">copy</button></div>
</div>
<footer>keys.hartforge.dev · raw keys at <a href="${esc(url)}.keys">/${esc(identity.handle)}.keys</a></footer>
</div><script>${COPY_JS}</script></body></html>`;
}
