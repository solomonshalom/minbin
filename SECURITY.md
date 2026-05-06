# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately so it can be fixed before public disclosure.

- Use [GitHub's private vulnerability reporting tool](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository.
- Or email [security@minb.in](mailto:security@minb.in).

> [!IMPORTANT]
> Please do **not** open public issues for security-related concerns.

We aim to respond quickly and fix issues responsibly.

## Reporting Abuse

For illegal, harmful, or otherwise abusive content (phishing, malware, hate speech), email [abuse@minb.in](mailto:abuse@minb.in). Note: encrypted pastes are opaque to operators — abuse reports must include the full link (with fragment) for the operator to view content; otherwise the operator can only delete by paste ID.

---

# How minbin protects your data

The web UI uses a Skiff-inspired protocol (see [Skiff Whitepaper, December 2022](https://skiff-org.github.io/whitepaper/Skiff_Whitepaper_2022.pdf), §3.2 / §6.5 / §7) for end-to-end encrypted, link-shared pastes.

minbin supports four storage modes:

1. **Plaintext (curl-friendly):** the body is stored as-is in Redis with a TTL. Anyone with database access can read it. Use this only for non-sensitive content.
2. **Random-key (default in the web UI):** the browser generates a 256-bit `link_key`, splits it via HKDF-SHA256 into `enc_key` (AES-256-GCM) and `auth_key` (SRP password), encrypts the body in authenticated chunks, and stores an SRP-6a verifier server-side. The `link_key` lives in the URL fragment (`#k=…`) and never reaches the server.
3. **Password:** the browser derives a master from the user's passphrase via Argon2id (m=64 MiB, t=3, p=1), HKDF-SHA256 splits master into `enc_key` and `auth_key`, and posts an SRP verifier to the server. The recipient enters the passphrase, derives the same keys, and completes SRP before the server hands over the ciphertext.
4. **Recipient public-key (multi-recipient by default):** the sender generates a random per-paste `content_key`. For each recipient, an ephemeral X25519 keypair is generated, a shared secret is derived via ECDH, HKDF expands it to a per-recipient KEK, and the `content_key` is wrapped with AES-256-GCM under that KEK. Each recipient's wrapped key + the sender's ephemeral pubkey are recorded in the `recipients` array; the recipient's browser unwraps using its private key. Up to 16 recipients per paste (Skiff §6.5). Legacy single-recipient records (`recipient: {pubkey, epk}`, direct ECDH→enc_key) continue to read for backward compatibility.

## Cipher and parameter choices

| Primitive | Choice | Why |
|---|---|---|
| Symmetric cipher | AES-256-GCM (WebCrypto) | Authenticated, hardware-accelerated, what TLS 1.3 / Signal storage / 1Password use |
| IV length | 96 bits, random per chunk | NIST SP 800-38D recommended size; never reused (each chunk has its own IV) |
| Chunk plaintext size | 64 KiB | Smaller chunks let large pastes stream-decrypt; AAD binds (seq, total, final) |
| Chunk AAD | `"minbin/v3/chunk" \|\| seq_BE32 \|\| total_BE32 \|\| final_byte` | Tag covers AAD: server cannot reorder, drop, or splice chunks (Skiff §7) |
| Key length | 256 bits | Matches AES-256 cipher |
| KDF (password mode) | Argon2id | OWASP-recommended memory-hard KDF, winner of the Password Hashing Competition |
| Argon2id params | m=64 MiB, t=3, p=1 | Strong on phones; hash-wasm in-browser; same params used Node-side in tests |
| HKDF | HKDF-SHA256, no salt, info=`"minbin/v3/{enc,auth,box}"` | Skiff §3.2: one master, multiple downstream keys; no key reuse across roles |
| Salt length (Argon2id) | 128 bits, random per paste | NIST SP 800-132 minimum |
| Salt length (SRP) | 128 bits, random per paste | Independent of the Argon2id salt |
| SRP group | RFC 5054 Group 2048 (g=2), SHA-256 | Skiff's choice in §3.2; widely audited; pure BigInt + WebCrypto SHA-256 |
| SRP verifier range | 1 ≤ v < N | Server rejects out-of-range submissions at upload time |
| Asymmetric (pubkey mode) | X25519 (WebCrypto) ECDH + HKDF-SHA256 + AES-GCM-wrap of a per-paste `content_key` | Follows Skiff's Curve25519 choice; multi-recipient via Skiff §6.5 wrapping pattern; supported on all evergreen browsers since 2024 |
| Wrap-key HKDF info | `"minbin/v3/wrap"` | Distinct from the legacy `"minbin/v3/box"` info, so a wrapped-key entry can never be confused with a direct enc_key derivation |
| Wrap AAD | `"minbin/v3/wrap-aad"` | Bound into AES-GCM so a server-side swap of `epk`/`wrappedKey` between entries is detected |
| Pubkey fingerprint | First 16 bytes of SHA-256(pubkey), 8 hex groups of 4 | Skiff §11 verification phrase analogue |
| Compression | gzip before encrypt | Smaller ciphertext; adds no length oracle (single paste per key) |
| Encoding | base64url (no padding) | URL-safe; used in fragment, JSON record, and SRP transport |

The crypto library (`hash-wasm`) is **vendored** at `templates/assets/vendor/argon2.umd.min.js` rather than loaded from a CDN — a CDN compromise would otherwise leak every user's password. The SRP-6a implementation is dependency-free (TypeScript BigInt + `node:crypto` SHA-256, mirrored in the browser by BigInt + WebCrypto). All vendored assets (Bootstrap, qrcodejs, canvas-confetti, hash-wasm) are pinned with **Subresource Integrity (SRI sha512)** on every `<script>`/`<link>` tag — a tampered git push or compromised CI cannot silently swap a different bundle past the browser's integrity check. Hashes are recomputed at server boot from the bytes on disk (see `src/utils/sri.ts`).

## Threat model

### What end-to-end encryption protects against

| Attacker | Plaintext | Random-key | Password | Pubkey |
|---|---|---|---|---|
| Network eavesdropper without TLS | reads paste | reads ciphertext only; SRP exchange is zero-knowledge | reads ciphertext only; SRP exchange is zero-knowledge | reads ciphertext only |
| Compromised server / malicious operator | reads everything | sees ciphertext, salt, verifier — no offline brute force on link_key (256-bit) | sees ciphertext, salt, verifier — must Argon2id-bruteforce the password | sees ciphertext + epk — no key (recipient holds it) |
| Stolen Redis dump (offline) | full plaintext | ciphertext + verifier; cannot brute-force link_key (256-bit, full entropy) | ciphertext + verifier; offline Argon2id brute force at ~10⁹ ops/$ — only weak passwords are at risk | ciphertext + epk; cannot derive key without recipient private key |
| Random link guesser (16-bit ID space) | reads paste | gets header (no chunks); must complete SRP using link_key to access ciphertext | gets header (no chunks); must complete SRP and pass Argon2id | gets ciphertext, can't decrypt |
| Person with the link, no password | n/a | reads paste | must brute-force Argon2id — infeasible for a real password | needs the recipient private key, not the link |
| Person with the link AND password | reads paste | reads paste (intended) | reads paste (intended) | n/a |
| Person with the link, no recipient private key | n/a | reads paste | reads paste with the password | cannot decrypt — pubkey mode is link-independent |

The notable Skiff-derived improvement over v2: an attacker who can guess a paste ID (16 bits) cannot exfiltrate the ciphertext from `/raw/:id` for SRP-gated v3 pastes. The server returns only the public header (mode, KDF params, SRP salt) and demands a successful SRP-6a handshake before serving chunks. This converts an offline attack against the password into an online one, which the operator can rate-limit.

### What end-to-end encryption does **not** protect against

This is the inherent ceiling for any browser-delivered crypto, and we're upfront about it:

- **Malicious server-served JavaScript.** The same operator who can read plaintext pastes could in principle modify the encrypted-mode HTML/JS to exfiltrate keys before encryption or after decryption. This is the same trust limitation as Bitwarden Web Vault, Proton Mail, MEGA, Skiff, and every other web-based E2EE app. If you don't trust the operator that far, self-host or use the CLI with a verified static client.
- **Endpoint compromise.** Malware on your device, a malicious browser extension, or a hostile party with shoulder-surfing access can read plaintext after decryption.
- **Weak passwords.** Argon2id raises the cost of brute force enormously, but a 4-character password is still guessable. Use a generated passphrase (3–4 random words minimum) for sensitive content.
- **Link leakage.** Anyone with the full URL (including the `#k=…` fragment) can complete SRP for a random-key v3 paste. Treat the link like a credential.
- **Traffic analysis.** A network observer can see *that* a paste exists, its size, and your access pattern — only the *content* is hidden.
- **Compromise of the vendored Argon2 / crypto bundle in this repository.** We pin and review the bundle, and **every `<script>`/`<link>` tag pointing at `/assets/vendor/` carries an `integrity="sha512-…"` attribute** that the browser verifies against the fetched bytes. This blocks a tampered git push, compromised CI, or future CDN-cached static asset from silently swapping a different bundle. It does **not** defend against a malicious commit that simultaneously updates both the vendor bytes and the template that emits the integrity hash — the hashes are computed at server boot from the same files the static-file plugin serves. Long-term, an external audit (see `AUDIT.md`) is the answer for the latter class.
- **Pubkey-mode identity theft.** Pubkey mode requires the recipient to publish their pubkey. If the sender accepts a forged pubkey (an attacker's, not the recipient's), the sender encrypts to the attacker. Verify out-of-band using the displayed fingerprint (Skiff §11).

## ID space and rate limiting

New paste IDs are **16 hex chars (64 bits, ~1.8e19)** — matching Yopass's design where the URL itself is the credential for non-SRP-gated pastes. Legacy 4-hex (16 bits) and 8-hex (32 bits) IDs continue to resolve until expiry for backward compatibility, but no new pastes are issued at those widths. ID allocation uses Redis `SET NX EX` and retries on collision so two concurrent uploads can never silently overwrite each other; if the configured width fills up, the allocator falls back to wider IDs.

- **For SRP-gated random-key + password modes**, the ID alone is useless: the server only returns a public header, then demands SRP-6a using `auth_key` derived from the link key (or password). An adversary scanning IDs gets ~no signal.
- **For pubkey mode**, the ID gets the attacker the ciphertext, but they cannot decrypt without the recipient's X25519 private key.
- **For plaintext** the ID alone gets the body. The server-side rate limiter (see below) bounds enumeration; deployments handling sensitive plaintext should also add rate limits at the proxy/CDN layer.

### Server-side rate limiting

The server enforces per-route rate limits backed by Redis (configurable via env, defaults shown):

| Endpoint                         | Default cap (per minute) | Key dimension(s)                   |
|---------------------------------|--------------------------|------------------------------------|
| `POST /` (create paste)         | 30                       | client IP                          |
| `GET /:id`, `GET /raw/:id`      | 120                      | client IP                          |
| `POST /:id/srp/init`            | 10                       | (client IP, paste_id) AND paste_id |
| `POST /:id/srp/verify`          | 10                       | (client IP, paste_id) AND paste_id |
| `POST /:id/burn`                | 60                       | client IP                          |
| `POST /:id/access`              | 60                       | client IP                          |
| `POST /report`                  | 5                        | client IP                          |
| `GET /captcha`                  | 60                       | client IP                          |

The SRP endpoints have **two** rate-limit dimensions:
- A **per-(IP, paste_id)** tuple cap (the standard Fastify rate-limit), so an attacker scanning many pastes from one IP is bounded per paste, and one paste hit from many IPs is bounded per IP.
- A **per-paste** cap regardless of source IP, defending against distributed brute force on a single paste from a botnet.

Both caps fail open if Redis is unreachable. The plugin emits standardized `RateLimit-*` headers per the IETF draft.

### Per-IP daily byte budget

`DAILY_BYTE_BUDGET` (env, default `0` = disabled) caps cumulative upload bytes per IP per UTC day. The counter is `INCRBY`'d on each upload; if the cumulative bytes would exceed the cap, the upload is rejected with `402 Payment Required` and the counter is rolled back so a smaller subsequent upload still succeeds. Production deployments handling open POST traffic should set this to a sensible value (e.g. 100 MB/day) so a single abusive IP cannot grind through the per-minute rate limit indefinitely.

### Proof-of-work captcha (anti-spam on plaintext POSTs)

When `CAPTCHA_BITS > 0`, plaintext `POST /` requires a solved hashcash-style captcha:

1. Client `GET /captcha` → `{ token, bits, expiresAt }`. The token is opaque: 1-byte version + 8-byte ms timestamp + 16 random bytes + 32-byte HMAC, all base64url-encoded. Server-side state is **HMAC-only** (stateless) on the issue path.
2. Client finds a 64-bit nonce such that `SHA-256(rand_part_of_token || be64(nonce))` has at least `bits` leading zero bits. 16 bits ≈ 50 ms on a server / ~300 ms on a phone; 20 bits ≈ 1 s / ~5 s.
3. Client `POST /` with `X-Captcha-Token: <token>` and `X-Captcha-Nonce: <nonce_b64u>` (or the same in the query string).
4. Server verifies the HMAC, checks freshness (within `CAPTCHA_TTL_SECONDS`, default 300), checks the work proof, and atomically inserts the random part into a Redis dedup set (`SET NX` with TTL = challenge lifetime) so a single solved challenge cannot be replayed.

Encrypted `POST /` is exempt — the SRP+Argon2 cost already raises the per-paste work for an attacker. Plaintext mode is the open abuse surface (think ransomware-payment-instruction blasts), which is what the captcha defends against.

No third-party JS, no IP leak to a SaaS, no fingerprinting. `curl` users solve the PoW with a small bash + python helper.

### Abuse-reporting endpoint

`POST /report` accepts `{ paste_id, reason, contact?, link? }` and pushes a JSON record onto the Redis list `abuse:reports`. The list is capped at `ABUSE_REPORTS_MAX` (default 10000) and TTL'd at `ABUSE_REPORTS_TTL_SECONDS` (default 30 days). Operators drain reports with `redis-cli LRANGE abuse:reports 0 -1` and follow up via the configured `ABUSE_REPORT_EMAIL` (returned to the reporter as `contact_email` so they know where to escalate if the operator doesn't respond).

Encrypted pastes are opaque to the operator; reports must include the full link (with the URL fragment, e.g. `https://your-deployment/abcdef0123456789#k=…`) for the operator to view content. The submission UI pre-fills the link from `window.location.href` so reporters don't need to remember to include the fragment.

The endpoint is rate-limited per IP, validates input strictly (10..1000-char reason, 4..32 lowercase hex paste_id, ≤256-char contact, ≤2048-char link), and is gated by the same `Origin` / `Sec-Fetch-Site` CSRF check as every other write endpoint.

`X-Forwarded-For` is honored only when `TRUST_PROXY` is configured to trust the upstream proxy. Default for self-hosted Docker is loopback only (so XFF cannot be spoofed by a remote attacker); on Vercel/Cloudflare set `TRUST_PROXY=true`.

## Wire format

Stored in Redis as JSON. SRP-gated modes (random, password) are returned by `GET /raw/:id` only as a public header — the chunks are held back until the client completes SRP-6a at `POST /:id/srp/verify`.

```json
{
  "v": 3,
  "enc": "aes-256-gcm",
  "mode": "random" | "password" | "pubkey",

  "kdf":     "argon2id",                           // password mode only
  "kdfSalt": "<base64url-16B>",                    // password mode only
  "argon2":  { "m": 65536, "t": 3, "p": 1 },       // password mode only

  "srp": {                                         // random + password modes
    "group":    "2048-sha256",
    "salt":     "<base64url-16B>",
    "verifier": "<base64url-(<=256B)>"             // SRP v = g^x mod N
  },

  // pubkey mode: exactly one of `recipient` (legacy single, direct ECDH→enc_key)
  // or `recipients` (new multi, wrapped per-paste content_key) must be present.
  "recipient": {                                   // legacy single recipient
    "pubkey": "<base64url-32B X25519 pubkey>",
    "epk":    "<base64url-32B sender ephemeral pubkey>"
  },
  "recipients": [                                  // multi-recipient (Skiff §6.5)
    {
      "pubkey":     "<base64url-32B recipient X25519 pubkey>",
      "epk":        "<base64url-32B per-recipient sender ephemeral pubkey>",
      "wrappedKey": "<base64url AES-GCM(content_key, kek, wrapIv)>",
      "wrapIv":     "<base64url-12B>"
    }
    // ... up to MAX_RECIPIENTS (default 16)
  ],

  "total": <int>,
  "chunks": [
    { "seq": 0, "iv": "<b64u-12B>", "ct": "<b64u-(>=16B)>" },
    ...
  ],

  "once":        true | false,
  "maxAccesses": <int 1..MAX_ACCESS_COUNT>          // optional; auto-deletes once cap is reached
}
```

The server validates this shape strictly and refuses to store malformed records. It never inspects, parses, or transforms the chunk ciphertexts.

## SRP-6a flow

Two stateful endpoints with ephemeral state in Redis (90 s TTL):

```
POST /:id/srp/init   { A: <b64u> }
                  -> { challengeId: <b64u>, salt: <b64u>, B: <b64u> }

POST /:id/srp/verify { challengeId, M1: <b64u> }
                  -> { M2: <b64u>, record: <full v3 record minus verifier> }
```

The challenge state is consumed on every `verify` call regardless of outcome — wrong-M1 retries require a fresh `init`. This bounds an online attacker to one Argon2id-cost guess per init+verify round trip.

The client verifies `M2 = H(PAD(A) || M1 || K)` before trusting the returned record. A server that returns a malformed record but a valid M1-style payload would still fail this check, so an active MITM cannot trick the client into decrypting against a poisoned ciphertext without also forging the SRP key K (which they cannot, by SRP's PAKE properties).

## Burn / max-access semantics

Three independent paths can delete a paste before its TTL elapses:

1. **`once` flag (legacy single-use)**: For plaintext pastes the server deletes on first read of `/:id` or `/raw/:id`. For encrypted pastes the server does **not** delete on read (because a wrong-password attempt would otherwise destroy the paste); instead the client calls `POST /:id/burn` after a successful decrypt.
2. **`maxAccesses` cap (new)**: Auto-deletes after the Nth successful access. For plaintext pastes the counter is server-driven on the read path (the server increments and writes back the bumped counter while preserving TTL; on the access that pushes the counter to >= cap, the paste is deleted). For encrypted pastes the client calls `POST /:id/access` after a successful decrypt; the server atomically increments a Redis counter (`acc:<paste_id>`) and deletes the paste when the cap is reached. The endpoint is idempotent — a dropped network response can never accidentally re-burn a paste.
3. **TTL expiry**: The Redis `EX` on the paste key fires after `PASTE_EXPIRY` minutes. Counter keys (`acc:<paste_id>`) and SRP challenge state (`srp:<challenge_id>`) carry their own short TTLs and clean themselves up.

When `once` and `maxAccesses` are both set, `maxAccesses` wins (it's the more specific cap; `once` is just shorthand for `maxAccesses=1`). The web UI makes the two toggles mutually exclusive to avoid surprising users.

## Transport and platform hardening

The server emits the following on every response (see `src/app.ts`):

| Header                          | Value                                                                                                    | Purpose                                                                                  |
|---------------------------------|----------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `Strict-Transport-Security`     | `max-age=63072000; includeSubDomains` (preload off-by-default, env-gated `HSTS_PRELOAD=true`)            | Locks browsers to HTTPS for two years; defeats active-MITM downgrade.                    |
| `Content-Security-Policy`       | `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; …`          | No `'unsafe-inline'` for scripts, no third-party CDN allowlist. All assets are vendored. |
| `Cross-Origin-Opener-Policy`    | `same-origin`                                                                                            | Isolates browsing context (window.opener / Spectre-class).                               |
| `Cross-Origin-Resource-Policy`  | `same-origin`                                                                                            | Prevents cross-origin embedding of HTML/JSON.                                            |
| `X-Frame-Options`               | `DENY`                                                                                                   | Belt-and-braces clickjacking prevention.                                                 |
| `X-Content-Type-Options`        | `nosniff`                                                                                                | Disables MIME-sniffing.                                                                  |
| `Referrer-Policy`               | `no-referrer`                                                                                            | Prevents leaking paste IDs in `Referer`.                                                 |
| `X-Robots-Tag`                  | `noindex, nofollow, noarchive, nosnippet`                                                                | Keeps Google/Bing/Wayback out of paste pages and `/raw/`.                                |
| `Cache-Control`                 | `no-store` (dynamic) / `public, max-age=31536000, immutable` (`/assets/*`)                               | Prevents intermediary caches from retaining ciphertext or KDF parameters.                |
| `Permissions-Policy`            | Denies camera, microphone, geolocation, payment, USB, MIDI, sensors, etc. (~35 features)                 | Strips unused browser feature surface.                                                   |
| `Server`, `X-Powered-By`        | (stripped)                                                                                               | Reduces fingerprinting.                                                                  |

### Vendored third-party assets

Bootstrap, qrcodejs, canvas-confetti, and hash-wasm (Argon2) are **all vendored** under `templates/assets/vendor/` and committed to git. The CSP grants no permission to load scripts or styles from any CDN, so a CDN compromise cannot inject anything into a paste page. Updates require a deliberate vendoring step, audited via the normal PR review.

### Cross-origin / CSRF defense

There is no auth state to forge, but encrypted pastes are still cheap to spam. The server enforces an `Origin` and `Sec-Fetch-Site` check on POST/DELETE-class requests:

- If `Origin` is present, it must match `APP_DOMAIN`.
- If `Sec-Fetch-Site` is present, it must be `same-origin`, `same-site`, or `none`.
- Both absent (typical for `curl` / CLI tools) is allowed.

This is defense-in-depth; the primary anti-spam control is the rate limiter.

### Stored-record re-validation on read

`GET /raw/:id` and `GET /:id` re-validate the full encrypted-record shape (chunk count, IV/ct base64url decode lengths, mode-specific fields, total ≤ MAX_PASTE_SIZE) before serving — defending against the unlikely case where a malformed record was inserted via a buggy code path or direct Redis write. A failure returns 500, not partial data.

### SRP RNG

Server-side `b` (the SRP private exponent) is sampled by full-width rejection over `randomBytes(256)` matching the 2048-bit modulus, eliminating modulo bias entirely (vs the prior 32-byte mod-N approach, whose bias was negligible but non-zero).

## Supported versions

Latest release only. Run the most recent build before reporting a vulnerability.
