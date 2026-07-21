// landing page at / — lists the identities served here. hart forge design system (workshop).
import { identities } from "./_identities.js";
import { htmlHeaders } from "./_render.js";

const SPARK = `<svg class="spark" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 0l2.1 9.9L24 12l-9.9 2.1L12 24l-2.1-9.9L0 12l9.9-2.1z" fill="#ff6a1f"/></svg>`;

export function onRequestGet(context) {
  const rows = Object.values(identities)
    .map((id) => {
      const n = id.keys.length;
      return `<li><span class="arw">-&gt;</span><a href="/${escapeHtml(id.handle)}">${escapeHtml(id.name)}</a><span class="desc">@${escapeHtml(id.handle)} · ${n} key${n === 1 ? "" : "s"}</span></li>`;
    })
    .join("\n");

  const html = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>keys.hartforge.dev</title>
<meta name="description" content="ssh public key identities for hart forge">
<meta name="theme-color" content="#0f1113">
<link rel="icon" href="/favicon.svg?v=2">
<link rel="stylesheet" href="/hartforge.css">
</head><body><div class="page">
<div class="banner">
  <a class="brand" href="https://hartforge.dev">${SPARK}<span class="wordmark">hart forge</span></a>
  <span class="rev">keys</span>
</div>
<p class="tagline">ssh public key identities · curl any handle with /&lt;handle&gt;.keys</p>

<div class="sec">
  <div class="lbl">identities</div>
  <ul class="rows">
${rows}
  </ul>
</div>

<footer>keys.hartforge.dev · self-hosted on cloudflare pages</footer>
</div></body></html>`;

  return new Response(html, { headers: htmlHeaders() });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
