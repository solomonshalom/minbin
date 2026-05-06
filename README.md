# minbin

a minimal, ephemeral, end-to-end encrypted pastebin.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fsolomonshalom%2Fminbin&project-name=minbin&repository-name=minbin&env=APP_DOMAIN&envDescription=Public%20domain%20used%20in%20generated%20paste%20URLs%20%28e.g.%20your-app.vercel.app%29&stores=%5B%7B%22type%22%3A%22kv%22%7D%5D)

## use

The web UI encrypts pastes **in your browser** before uploading (AES-256-GCM, key never leaves your machine — see [SECURITY.md](./SECURITY.md) for the full threat model). The server stores ciphertext only and cannot decrypt it. Three modes, all running a Skiff-style protocol (see [Skiff Whitepaper, Dec 2022](https://skiff-org.github.io/whitepaper/Skiff_Whitepaper_2022.pdf), §3.2 / §6.5 / §7):

- **random-key** — a 256-bit `link_key` lives in the URL fragment (`#k=…`). HKDF splits it into an `enc_key` (AES-GCM) and an `auth_key`. The server only releases the ciphertext after the recipient completes an SRP-6a handshake using `auth_key`, so a paste-ID guesser cannot fish the ciphertext out of `/raw/:id`.
- **password (Argon2id + SRP)** — Argon2id derives a master from your passphrase, HKDF expands it into `enc_key` + `auth_key`, and the server holds an SRP verifier. The recipient enters the passphrase, derives the same keys, and completes SRP before the server hands over chunks.
- **send to pubkey (multi-recipient)** — encrypt to one or more recipients' published Curve25519 public keys. A random per-paste content key is wrapped for each recipient using X25519 ECDH + HKDF + AES-GCM (Skiff §6.5). Only the holder of a matching private key can decrypt — the link is not the secret.

Pastes can self-destruct after the first successful decrypt (the `one-time` toggle) **or** after a fixed `max views` count, whichever you prefer (combined with the time expiry, the paste vanishes whichever comes first). Bodies above 64 KiB are split into authenticated chunks (Skiff §7) so the server cannot reorder, drop, or splice chunks without breaking AES-GCM authentication.

```bash
# plaintext pastes (legacy curl path — server reads the body):
curl -d "hello from the terminal" https://your-deployment
curl --data-binary @file.txt https://your-deployment
curl --data-binary @file.txt "https://your-deployment/?once"
curl --data-binary @file.txt "https://your-deployment/?maxAccesses=5"

# encrypted pastes are best created from the web UI; the API also accepts
# encrypted records directly (see SECURITY.md for the wire format).
```

## environment

### core

| Variable         | Default        | Description                            |
| ---------------- | -------------- | -------------------------------------- |
| `APP_DOMAIN`     | `minb.in`      | public domain used in generated links  |
| `REDIS_URL`      | *(unset)*      | full redis connection string (preferred; auto-set by Vercel KV / Upstash) |
| `DB_HOST`        | `dragonfly`    | redis host (used when `REDIS_URL` is unset) |
| `DB_PORT`        | `6379`         | redis port                             |
| `DB_USER`        | *(optional)*   | redis username                         |
| `DB_PASS`        | *(optional)*   | redis password                         |
| `PASTE_EXPIRY`   | `60`           | paste expiry in **minutes**            |
| `MAX_PASTE_SIZE` | `26214400`     | max paste size in **bytes** (25 MB)    |
| `PASTE_ID_BYTES` | `8`            | paste ID width in bytes (default = 16 hex chars / 64 bits) |
| `PASTE_ID_MAX_TRIES` | `8`        | retry budget on `SET NX` collision before falling back to wider IDs |
| `MAX_RECIPIENTS` | `16`           | max recipients in a multi-recipient pubkey paste |
| `MAX_ACCESS_COUNT` | `1000`       | hard upper bound on `maxAccesses`      |

### security / hardening

| Variable                  | Default                          | Description                                                                  |
| ------------------------- | -------------------------------- | ---------------------------------------------------------------------------- |
| `TRUST_PROXY`             | `127.0.0.1/8,::1/128`            | who to trust for `X-Forwarded-For`. Set to `true` on Vercel/Cloudflare.       |
| `HSTS_MAX_AGE`            | `63072000` (2 yr)                | `Strict-Transport-Security` lifetime in seconds                              |
| `HSTS_INCLUDE_SUBDOMAINS` | `true`                           | include `includeSubDomains` directive                                        |
| `HSTS_PRELOAD`            | `false`                          | include `preload` (off-by-default — preload is permanent across browsers)    |
| `RATE_LIMIT_ENABLED`      | `true`                           | global toggle for the rate limiter                                            |
| `RATE_LIMIT_WINDOW_MS`    | `60000` (1 min)                  | sliding window for all rate limits                                            |
| `RATE_LIMIT_POST_MAX`     | `30`                             | max paste creations per IP per window                                         |
| `RATE_LIMIT_GET_MAX`      | `120`                            | max GET /:id and /raw/:id per IP per window                                  |
| `RATE_LIMIT_SRP_MAX`      | `10`                             | max SRP init/verify per (IP, paste_id) AND per paste_id per window           |
| `RATE_LIMIT_BURN_MAX`     | `60`                             | max burn (delete) calls per IP per window                                     |
| `RATE_LIMIT_REPORT_MAX`   | `5`                              | max abuse reports per IP per window                                           |
| `RATE_LIMIT_CAPTCHA_MAX`  | `60`                             | max `/captcha` issuances per IP per window                                    |
| `RATE_LIMIT_ACCESS_MAX`   | `60`                             | max `/:id/access` calls per IP per window                                     |
| `DAILY_BYTE_BUDGET`       | `0` (disabled)                   | per-IP cumulative upload bytes per UTC day; rejects with 402 above the cap   |

### abuse mitigation

| Variable                   | Default                  | Description                                                                  |
| -------------------------- | ------------------------ | ---------------------------------------------------------------------------- |
| `CAPTCHA_BITS`             | `0` (disabled)           | hashcash PoW bits required on plaintext POST `/`. Recommended **16-20** for production-facing deployments (~50 ms-1 s on commodity hardware). Encrypted POSTs are exempt. |
| `CAPTCHA_SECRET`           | *(auto, in-memory)*      | HMAC secret for stateless challenges; **set explicitly** for multi-host deployments so all instances accept each other's tokens |
| `CAPTCHA_TTL_SECONDS`      | `300`                    | challenge token freshness window in seconds                                   |
| `ABUSE_REPORT_EMAIL`       | `abuse@minb.in`          | displayed to reporters; operators should override with a real address        |
| `ABUSE_REPORTS_TTL_SECONDS`| `2592000` (30 days)      | TTL on the `abuse:reports` Redis list                                         |
| `ABUSE_REPORTS_MAX`        | `10000`                  | Redis list `LTRIM` cap                                                        |

### endpoints introduced in this release

- `GET /captcha` — issues a stateless PoW challenge (used when `CAPTCHA_BITS > 0`).
- `POST /report` — operator-facing abuse drop-box (Redis list `abuse:reports`). Drain with `redis-cli LRANGE abuse:reports 0 -1`.
- `POST /:id/access` — bumps the encrypted-paste access counter for `maxAccesses`-capped pastes; idempotent. Plaintext counters are server-driven on read.

See `/api` (or [the api template](./templates/api.html)) for the full per-deployment docs page, and `GET /openapi` for the machine-readable spec.

## self-host

```bash
docker compose up
```

or run it locally:

```bash
npm install
npm run build
npm start
```

For a development server backed by an in-process Redis mock:

```bash
npm run build && node tests/dev-server.mjs
# → http://127.0.0.1:8765
```

## audit & security

- **Subresource Integrity (SRI sha512)** is pinned on every `<script>`/`<link>` tag pointing at `/assets/vendor/`. Hashes are recomputed at server boot from the actual bytes on disk, so a tampered git push or compromised CI cannot silently swap a different bundle.
- See [SECURITY.md](./SECURITY.md) for the full threat model and cipher choices.
- See [AUDIT.md](./AUDIT.md) for audit-readiness scope, test-coverage matrix, and reproducible-build instructions.
- Report vulnerabilities via GitHub's private vulnerability reporting tool (see [SECURITY.md](./SECURITY.md)).

## credit

based on [minbin](https://github.com/berrysauce/minbin) by [berrysauce](https://berrysauce.dev/) — this fork is a TypeScript / Fastify rewrite of the original Python / FastAPI backend, with Skiff-aligned end-to-end encryption.

licensed under [GPL-3.0](LICENSE).
