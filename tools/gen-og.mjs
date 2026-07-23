// renders the social preview card (og:image) for each identity, in the forge
// palette, via headless chrome. run it whenever _identities.js changes:
//
//   node tools/gen-og.mjs
//
// output is public/og/<handle>.png, served by cloudflare pages at
// keys.hartforge.dev/og/<handle>.png and pointed at by the og:image meta in
// _render.js. committed to the repo (not built in CI) so the deploy needs no
// chrome; the image only changes when an identity's keys or name do.
//
// the preview shows the real primary-key SHA256 fingerprint (reusing the site's
// own parseKey/fingerprint), because "here is my key, verifiably" is the whole
// point of keys - a generic card would undersell it.

import { parseKey, fingerprint } from "../functions/_render.js";
import { identities } from "../functions/_identities.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const HERE = dirname(fileURLToPath(import.meta.url));
const OUTDIR = join(HERE, "..", "public", "og");
mkdirSync(OUTDIR, { recursive: true });

const esc = (s) =>
  String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const SPARK =
  '<svg viewBox="0 0 24 24" width="52" height="52" aria-hidden="true">' +
  '<path d="M12 0l2.1 9.9L24 12l-9.9 2.1L12 24l-2.1-9.9L0 12l9.9-2.1z" fill="#ff6a1f"/></svg>';

function template(id, fp, keyType, n) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  *{margin:0;padding:0;box-sizing:border-box}
  html,body{width:1200px;height:630px}
  body{background:#0f1113;color:#e7eaec;position:relative;
    font-family:"SF Mono",ui-monospace,"JetBrains Mono",Menlo,monospace;
    display:flex;flex-direction:column;padding:76px 88px}
  .brand{display:flex;align-items:center;gap:16px}
  .wm{font-size:30px;letter-spacing:.06em;color:#e7eaec}
  .rev{margin-left:auto;color:#6b7075;font-size:26px}
  .mid{flex:1;display:flex;flex-direction:column;justify-content:center}
  h1{font-size:80px;font-weight:600;letter-spacing:-0.02em;line-height:1}
  .handle{color:#a3a9ad;font-size:32px;margin-top:18px}
  .count{color:#6b7075;font-size:26px;margin-top:12px}
  .fp{margin-top:0;display:flex;align-items:baseline;gap:16px;flex-wrap:wrap}
  .fp .k{color:#6d90ac;font-size:24px}
  .fp .v{color:#e7eaec;font-size:26px;word-break:break-all}
  .foot{color:#6b7075;font-size:26px}
  .foot b{color:#ff6a1f;font-weight:600}
  .rule{position:absolute;left:0;right:0;bottom:0;height:6px;background:#ff6a1f}
  </style></head><body>
  <div class="brand">${SPARK}<span class="wm">hart forge</span><span class="rev">keys</span></div>
  <div class="mid">
    <h1>${esc(id.name)}</h1>
    <div class="handle">@${esc(id.handle)}</div>
    <div class="count">${n} ssh public key${n === 1 ? "" : "s"} &middot; authorized for ssh</div>
  </div>
  <div class="fp"><span class="k">${esc(keyType)}</span><span class="v">${esc(fp)}</span></div>
  <div class="foot" style="margin-top:28px">keys.hartforge.dev<b>/${esc(id.handle)}</b></div>
  <div class="rule"></div>
  </body></html>`;
}

for (const id of Object.values(identities)) {
  const primary = parseKey(id.keys[0].line);
  const fp = await fingerprint(primary.blob);
  const tmp = join(tmpdir(), `og-keys-${id.handle}.html`);
  writeFileSync(tmp, template(id, fp, primary.label, id.keys.length));
  const out = join(OUTDIR, `${id.handle}.png`);
  execFileSync(
    CHROME,
    ["--headless", "--disable-gpu", "--force-device-scale-factor=1",
     "--hide-scrollbars", "--window-size=1200,630",
     `--screenshot=${out}`, `file://${tmp}`],
    { stdio: "ignore" }
  );
  console.log("rendered", out, "(" + fp + ")");
}
