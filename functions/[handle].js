// serves both /<handle> (identity page) and /<handle>.keys (raw authorized_keys text).
import { getIdentity } from "./_identities.js";
import { renderIdentity, rawKeys } from "./_render.js";

export async function onRequestGet(context) {
  const { params, request } = context;
  const origin = new URL(request.url).origin;
  let handle = params.handle || "";

  const wantsRaw = handle.endsWith(".keys");
  if (wantsRaw) handle = handle.slice(0, -".keys".length);

  const identity = getIdentity(handle);
  if (!identity) {
    // not a known handle — let pages serve a matching static asset (favicon, etc),
    // or fall through to the default 404 if there is none.
    return context.next();
  }

  if (wantsRaw) {
    return new Response(rawKeys(identity), {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "public, max-age=300",
      },
    });
  }

  const html = await renderIdentity(identity, origin);
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, max-age=300",
    },
  });
}
