// landing page at / — lists the identities served here.
import { identities } from "./_identities.js";

export function onRequestGet(context) {
  const origin = new URL(context.request.url).origin;
  const rows = Object.values(identities)
    .map(
      (id) =>
        `<a class="row" href="/${id.handle}">
          <span class="av">${(id.name || id.handle)[0].toUpperCase()}</span>
          <span class="nm">${escapeHtml(id.name)}<span class="hd">@${escapeHtml(id.handle)}</span></span>
          <span class="ct">${id.keys.length} key${id.keys.length === 1 ? "" : "s"}</span>
        </a>`
    )
    .join("\n");

  const html = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>keys.hartforge.dev</title>
<link rel="icon" href="/favicon.svg?v=1">
<style>
:root{color-scheme:dark light}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:#0c0e12;color:#e6e6e6;min-height:100vh}
.wrap{max-width:560px;margin:0 auto;padding:64px 20px}
h1{font-size:20px;letter-spacing:-.01em;margin:0 0 4px}
.sub{color:#8a94a6;font-size:13px;margin-bottom:28px}
.sub b{color:#f0883e;font-weight:600}
.row{display:flex;align-items:center;gap:14px;text-decoration:none;color:inherit;
  background:#14171d;border:1px solid #232830;border-radius:12px;padding:14px 16px;margin-bottom:10px}
.row:hover{border-color:#f0883e}
.av{width:40px;height:40px;border-radius:10px;flex:none;display:grid;place-items:center;
  background:linear-gradient(135deg,#f0883e,#c2410c);color:#1a1200;font-weight:700}
.nm{font-weight:600;display:flex;flex-direction:column}
.hd{font-weight:400;color:#8a94a6;font-size:12.5px;font-family:ui-monospace,monospace}
.ct{margin-left:auto;color:#6b7484;font-size:12.5px}
@media(prefers-color-scheme:light){
  body{background:#f7f8fa;color:#1a1d23}.row{background:#fff;border-color:#e4e7ec}
}
</style></head><body><div class="wrap">
<h1>keys.hartforge.dev</h1>
<div class="sub">ssh public key identities · fetch any with <b>curl ${escapeHtml(origin)}/&lt;handle&gt;.keys</b></div>
${rows}
</div></body></html>`;

  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=300" },
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
