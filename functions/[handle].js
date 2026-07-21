// serves /<handle> (identity page), /<handle>.keys (raw authorized_keys), /<handle>.sh (idempotent installer).
import { getIdentity } from "./_identities.js";
import { renderIdentity, rawKeys, installScript, htmlHeaders, textHeaders } from "./_render.js";

export async function onRequestGet(context) {
  const { params, request } = context;
  const origin = new URL(request.url).origin;
  let handle = params.handle || "";

  let kind = "page";
  if (handle.endsWith(".keys")) { kind = "keys"; handle = handle.slice(0, -5); }
  else if (handle.endsWith(".sh")) { kind = "sh"; handle = handle.slice(0, -3); }

  const identity = getIdentity(handle);
  if (!identity) {
    // not a known handle — let pages serve a matching static asset (favicon, etc), else 404.
    return context.next();
  }

  if (kind === "keys")
    return new Response(rawKeys(identity), { headers: textHeaders("text/plain; charset=utf-8") });
  if (kind === "sh")
    return new Response(await installScript(identity, origin), {
      headers: textHeaders("text/x-shellscript; charset=utf-8"),
    });

  const html = await renderIdentity(identity, origin);
  return new Response(html, { headers: htmlHeaders() });
}
