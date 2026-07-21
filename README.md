# keys

self-hosted ssh public key identity pages, like sshid.io but ours. serves your authorized public keys at a curl-able endpoint plus a rendered identity page, on cloudflare pages.

live at **https://keys.hartforge.dev**

## what it does

- `keys.hartforge.dev/<handle>` -> identity page: key-type badges, live sha256 fingerprints, randomart, per-key copy. styled with the hart forge design system (`public/hartforge.css`)
- `keys.hartforge.dev/<handle>.keys` -> raw pubkey lines, ready for authorized_keys
- `keys.hartforge.dev/<handle>.sh` -> installer that syncs a managed block: re-run adds new keys, removes revoked ones, dedupes, echoes each key's fingerprint. keys outside the block are left alone

the point is one command to authorize all your devices on any box:

```
curl -fsSL https://keys.hartforge.dev/patrick.sh | sh          # idempotent, recommended
curl -fsSL https://keys.hartforge.dev/patrick.keys >> ~/.ssh/authorized_keys   # plain append
```

only public keys live here. the private halves never leave your devices.

## how it works

- proxied CNAME `keys.hartforge.dev` -> `keys-f1y.pages.dev`, a cloudflare pages project
- one pages function `functions/[handle].js` serves both routes (the `.keys` suffix branches to raw text; unknown handles fall through to a 404)
- `functions/_render.js` computes the openssh sha256 fingerprint in the worker runtime (webcrypto sha-256 over the decoded key blob, base64, strip padding - matches `ssh-keygen -lf` exactly), so you never hand-maintain fingerprints
- `functions/_identities.js` is the only file you edit to add people or keys

## add a device / key

1. on the device, grab its public key:
   ```
   cat ~/.ssh/id_ed25519.pub      # or generate one: ssh-keygen -t ed25519
   ```
2. paste the line into `functions/_identities.js` under the right handle:
   ```js
   {
     line: "ssh-ed25519 AAAA... you@device",
     label: "patricks-newbox",
     added: "07-21-2026",           // mm-dd-yyyy
   },
   ```
3. deploy (below). fingerprint, badge and date render automatically.

## add a person

add a new handle to the `identities` object in `functions/_identities.js` with a `name`, `handle` and `keys` list. they get their own `/handle` page and `/handle.keys` endpoint.

## deploy

push to forgejo -> it mirrors to github -> the `deploy` github action runs `wrangler pages deploy`. that's it. edit `functions/_identities.js`, `git push`, done.

to deploy by hand:

```
npx wrangler pages deploy public --project-name keys --branch main --commit-dirty=true
```

needs `CLOUDFLARE_API_TOKEN` (the pages-scoped token) and `CLOUDFLARE_ACCOUNT_ID` in the env. edge cache is 5 min, so the live page lags a redeploy briefly - the unique deployment url is instant.

## layout

```
functions/
  _identities.js   source of truth (edit this)
  _render.js       parsing, fingerprints, randomart, html
  [handle].js      /<handle>, /<handle>.keys, /<handle>.sh
  index.js         landing
public/
  hartforge.css    the hart forge design system (workshop) - shared tokens + components
  favicon.svg
.github/workflows/deploy.yml
wrangler.toml
```
