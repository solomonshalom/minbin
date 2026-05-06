# Audit Readiness

This document is the briefing pack for an external security audit of minbin.
It exists so an auditor can scope, price, and start work without a synchronous
back-and-forth with the project.

minbin has not yet been audited by a third party. This file describes what
*would* be in scope, what we believe the security properties are, and what
artifacts we ship to support that belief. Pull requests adding an audit
report are welcome.

---

## 1. What minbin is

A minimal, ephemeral, end-to-end encrypted pastebin. ~3000 lines of
TypeScript on the server, ~1500 lines of vanilla JavaScript in the browser,
plus vendored Bootstrap / hash-wasm (Argon2id) / qrcodejs / canvas-confetti.
Storage is Redis-compatible (Vercel KV, Upstash, Dragonfly, etc.).

Three encrypted modes (`random`, `password`, `pubkey`) plus a legacy
plaintext mode for `curl` users. The encrypted protocol is a Skiff-aligned
implementation (see [Skiff Whitepaper, Dec 2022][skiff], §3.2 / §6.5 / §7).

[skiff]: https://skiff-org.github.io/whitepaper/Skiff_Whitepaper_2022.pdf

---

## 2. Recommended scope for an external audit

### In scope (priority order)

1. **`src/utils/encrypted-record.ts`** — wire-format validator. Single point
   where untrusted JSON crosses into typed code. Bugs here can let
   malformed records into Redis or break decryption invariants on read.
2. **`src/utils/srp.ts`** — server-side SRP-6a (RFC 5054 group 2048,
   SHA-256). Pure BigInt + `node:crypto`; no third-party crypto deps. Verify
   modular arithmetic, range checks (1 ≤ A,B,v < N), `b` sampling
   (full-width rejection), constant-time M1 comparison.
3. **`templates/assets/js/minbin-crypto.js`** — browser crypto: AES-GCM
   chunking with AAD-bound `(seq, total, final)`; HKDF-SHA256 expansion;
   Argon2id; X25519 ECDH wrap/unwrap for multi-recipient pubkey mode; SRP-6a
   client; PoW captcha solver. Mirror of the server-side SRP code by
   construction (constants identical).
4. **`src/utils/captcha.ts`** — stateless hashcash with HMAC-bound tokens
   and Redis-backed replay protection. Verify HMAC correctness, replay
   window, leading-zero-bits check.
5. **`src/app.ts`** — Fastify routing, Origin/Sec-Fetch-Site enforcement,
   per-route rate limits, per-paste cross-IP cap, daily byte budget,
   plaintext access-counter logic, security headers (CSP, HSTS, COOP, CORP,
   Permissions-Policy), error handler.
6. **Vendored asset integrity** — verify the SRI sha512 hashes embedded in
   every `<script>`/`<link>` tag pointing at `/assets/vendor/` actually
   match the bytes shipped in git. See §5.

### Out of scope (worth noting)

- Bootstrap CSS / canvas-confetti / qrcodejs runtime correctness — vendored
  third-party libraries with their own audit history.
- The Argon2id implementation (`hash-wasm`, vendored). Audited upstream;
  we rely on it as a black-box KDF.
- Operator infrastructure (Vercel KV, Upstash, network path).
- Browser CryptoSubtle correctness.

### Supporting deliverables for the auditor

- `SECURITY.md` — threat model + cipher choices.
- This file (`AUDIT.md`) — scope + coverage matrix.
- `tests/integration.test.mjs` + `tests/ratelimit.test.mjs` — 340+
  assertions covering crypto round-trips, schema rejection, rate limits,
  captcha, byte budget, max-views, multi-recipient, SRI presence + match.
- Vendored asset SRI manifest (computed at runtime from the same bytes the
  templates serve; matches what the browser sees).
- Reproducible build: `npm install && npm run build && npm test`.

---

## 3. Threat model summary

The full table is in [SECURITY.md](./SECURITY.md). The five threats we
take most seriously:

| Threat | Defense | Where in code |
|---|---|---|
| Operator reads E2E-encrypted paste content | Browser-side AES-256-GCM under HKDF-derived keys; server stores only ciphertext + verifier | `templates/assets/js/minbin-crypto.js`, `src/utils/encrypted-record.ts` |
| Stolen Redis dump enables offline brute force | SRP-6a verifier + Argon2id (m=64MiB, t=3, p=1) for password mode | `src/utils/srp.ts`, `templates/assets/js/minbin-crypto.js` (Argon2id) |
| Compromised CDN serves backdoored Argon2 / Bootstrap | All third-party JS/CSS vendored under `templates/assets/vendor/`, **pinned with sha512 SRI** on every script/link tag | `src/utils/sri.ts`, every template |
| Open POST `/` abused for ransomware payment notes | Per-IP rate limit (30/min), per-IP daily byte budget, optional PoW captcha (16-20 bits typical), abuse-report endpoint | `src/app.ts` (POST /), `src/utils/captcha.ts` |
| Active MITM tampers with served encrypted record | Client verifies SRP server proof M2 before trusting returned record; chunk AAD binds `(seq, total, final)` so reorder/drop fails AES-GCM auth | `src/utils/srp.ts`, `templates/assets/js/minbin-crypto.js` (`decryptChunks`) |

---

## 4. Crypto and parameter choices

| Primitive | Choice | Rationale |
|---|---|---|
| Symmetric cipher | AES-256-GCM (WebCrypto) | TLS 1.3 / Signal storage / 1Password baseline |
| AEAD AAD | `"minbin/v3/chunk" \|\| be32(seq) \|\| be32(total) \|\| final_byte` | Skiff §7 binding so server can't reorder/drop chunks |
| KDF (password mode) | Argon2id (hash-wasm) m=64MiB, t=3, p=1 | OWASP-recommended memory-hard; same params client+server-side tests |
| HKDF | SHA-256, no salt, info=`"minbin/v3/{enc,auth,box,wrap}"` | Skiff §3.2 master-then-expand; no key reuse across roles |
| SRP group | RFC 5054 Group 2048 (g=2), SHA-256 | Skiff §3.2; pure BigInt + `node:crypto` |
| SRP server `b` | `randomBytes(256)` rejection-sampled to [1, N-1] | Eliminates modulo bias from naive `% N` |
| Asymmetric (pubkey mode) | X25519 ECDH (WebCrypto) | Skiff §6.5 |
| Pubkey mode wrapping (multi-recipient) | Per-recipient ephemeral X25519, HKDF→KEK, AES-GCM-wrap content_key | Skiff §6.5 link-sharing analogue |
| Salt lengths | 128 bits (Argon2id, SRP) | NIST SP 800-132 minimum |
| Compression | gzip before encrypt | Smaller ciphertext; one paste per key, so no length oracle |
| Encoding | base64url, no padding | URL-safe; used in fragment + JSON wire + SRP |
| PoW captcha | SHA-256 leading-zero-bits, HMAC-bound stateless tokens, Redis nonce dedup | hashcash; no third-party JS / fingerprinting; works for `curl` with a small helper |
| Paste ID | 64-bit (16 hex) random, allocated via `SET NX EX` | Yopass pattern (URL-as-credential) |

---

## 5. Vendored asset integrity (SRI)

Every `<script src>` / `<link href>` pointing into
`templates/assets/vendor/` carries `integrity="sha512-…"
crossorigin="anonymous"`. Hashes are computed at server boot from the
files on disk (see `src/utils/sri.ts`) and inlined into rendered templates
via the Nunjucks global `sri`. The integration test
`SRI: integrity matches actual file contents` independently re-hashes the
vendor file and confirms the rendered HTML carries the matching digest.

A tampered git push, compromised CI, or future CDN-cached asset cannot
silently swap a different bundle without breaking the browser's integrity
check.

---

## 6. Test coverage matrix

| Area | Test file | # assertions (≈) |
|---|---|---|
| Plaintext create / read / once / max-views | `integration.test.mjs` | ~35 |
| v3 SRP random-key round-trip | `integration.test.mjs` | ~12 |
| v3 SRP password round-trip | `integration.test.mjs` | ~10 |
| v3 SRP wrong-password rejection + single-use challenge | `integration.test.mjs` | ~5 |
| v3 chunk tamper / reorder / truncation detection | `integration.test.mjs` | ~6 |
| v3 pubkey mode (legacy single-recipient back-compat) | `integration.test.mjs` | ~6 |
| v3 pubkey mode (multi-recipient: 1 and 3 recipients) | `integration.test.mjs` | ~14 |
| v3 record validation (16+ malformed-input rejections) | `integration.test.mjs` | ~16 |
| Security headers (CSP, HSTS, COOP, CORP, X-*, Permissions-Policy) | `integration.test.mjs` | ~25 |
| Origin / Sec-Fetch-Site CSRF gate | `integration.test.mjs` | ~6 |
| SRI hashes present + match file bytes | `integration.test.mjs` | ~12 |
| `/captcha` issue + verify + replay + bad MAC + insufficient work | `integration.test.mjs` + `ratelimit.test.mjs` | ~12 |
| `/report` validation + storage + cross-origin gate + cap | `integration.test.mjs` + `ratelimit.test.mjs` | ~14 |
| `/:id/access` counter (encrypted) + idempotence + missing paste | `integration.test.mjs` + `ratelimit.test.mjs` | ~12 |
| Per-IP daily byte budget (trip + rollback) | `ratelimit.test.mjs` | ~7 |
| Captcha required when `CAPTCHA_BITS>0` (rejected without; accepted with) | `ratelimit.test.mjs` | ~5 |
| Per-route rate limits (POST, GET, SRP, burn, report, access) | `ratelimit.test.mjs` | ~16 |
| Cross-IP per-paste SRP cap | `ratelimit.test.mjs` | ~2 |
| Legacy 4-hex and 8-hex paste IDs continue to resolve | `integration.test.mjs` | ~4 |
| **Total** | | **~340** |

Run all of it with: `npm test` (~10s on a M-series Mac).

---

## 7. Reproducible build

```bash
git clone https://github.com/solomonshalom/minbin
cd minbin
npm install --no-audit --no-fund
npm run build       # tsc -> dist/
npm test            # build + integration + rate-limit suites
npm start           # node dist/server.js (needs a real Redis)
```

Vendored assets in `templates/assets/vendor/` are committed verbatim.
Their SRI hashes are computed at runtime in `src/utils/sri.ts` from the
exact bytes the static-file plugin serves. To upgrade a vendored asset:

1. Replace the file in `templates/assets/vendor/`.
2. Rebuild and run the integration tests; the `SRI: integrity matches
   actual file contents` assertion will fail if the templates' rendered
   `integrity=` doesn't match the new bytes.
3. Commit the new file. (No separate hash file to keep in sync — SRI is
   computed at boot.)

Node 20 minimum (`engines.node` in `package.json`). Dependency surface:
`fastify`, `@fastify/rate-limit`, `@fastify/static`, `@fastify/swagger`,
`hash-wasm`, `ioredis`, `nunjucks`, `dotenv`. No native modules.

---

## 8. Deltas from the Skiff whitepaper

| Skiff §  | minbin equivalent | Notes |
|---|---|---|
| §3.1 (per-account keys) | `localStorage` X25519 identity for pubkey mode | No accounts, so the identity is browser-local; export/import is on the roadmap |
| §3.2 (HKDF master expansion) | `INFO_ENC` / `INFO_AUTH` / `INFO_BOX` / `INFO_WRAP` separation | Identical pattern |
| §6.5 (link-sharing via SRP) | random-key + password modes | Identical pattern; verifier stored, ciphertext gated |
| §6.5 (multi-recipient wrapping) | per-paste content_key wrapped per-recipient via X25519+HKDF+AES-GCM | New in this release |
| §7 (chunked authenticated body) | 64 KiB chunks; AAD = `(seq, total, final)` | Identical pattern |
| §11 (verification phrase) | First 16 bytes of SHA-256(pubkey), 8×4-hex-group display | UI helper for out-of-band check |

minbin does **not** implement: per-paste team / org permission lists,
account recovery, file storage, or Skiff's editor sync layer. Pastes are
ephemeral (Redis TTL); long-lived sharing is out of scope.

---

## 9. Known limitations

- **Browser-served crypto**: same trust ceiling as Bitwarden Web Vault,
  Proton Mail, MEGA, Skiff. A malicious operator could in principle modify
  the served HTML/JS to exfiltrate keys before encryption / after
  decryption. SRI on third-party assets does not defend against the
  operator themselves modifying first-party JS. If you don't trust the
  operator that far, self-host or use the CLI with a verified static
  client.
- **No third-party audit yet**. We follow recognized patterns (Skiff,
  RFC 5054, NIST SP 800-132 / 800-38D, OWASP) and our test suite
  exercises every E2EE invariant we can name, but the project has not yet
  been formally audited. Cure53 is the realistic target (~€20k for a
  focused E2EE pastebin scope).
- **Pubkey mode requires the recipient to publish their pubkey** out of
  band. Sender must verify the fingerprint against a trusted channel
  before encrypting (Skiff §11 phrase analogue is rendered next to each
  recipient input).
- **Endpoint compromise** (malware on the user's device, hostile browser
  extension) defeats E2EE by design. Same for shoulder surfing.
- **Network observers** can see *that* a paste exists, *its size*, and
  *access patterns* — the *content* is hidden.
- **Plaintext mode** is operator-readable by design (curl support). Use
  encrypted mode for anything sensitive.

---

## 10. Configuration knobs an auditor should test

All from `src/config.ts`. Defaults shown:

| Variable | Default | What an auditor should poke at |
|---|---|---|
| `MAX_PASTE_SIZE` | `26214400` (25 MB) | Body limit + chunk-sum re-validation |
| `PASTE_ID_BYTES` | `8` (16 hex) | Collision math, allocation retry budget |
| `PASTE_ID_MAX_TRIES` | `8` | Falls back to wider IDs after retries exhaust |
| `RATE_LIMIT_*` | various | Per-IP, per-paste, cross-IP caps |
| `DAILY_BYTE_BUDGET` | `0` (off) | UTC-day rolling; counter rollback on rejection |
| `CAPTCHA_BITS` | `0` (off) | PoW required on plaintext POST when > 0 |
| `CAPTCHA_SECRET` | (auto) | HMAC secret; multi-host deployments must set this |
| `CAPTCHA_TTL_SECONDS` | `300` | Token freshness window |
| `MAX_RECIPIENTS` | `16` | Multi-recipient pubkey-mode upper bound |
| `MAX_ACCESS_COUNT` | `1000` | Max-views upper bound |
| `ABUSE_REPORTS_TTL_SECONDS` | `30 * 86400` | Redis list TTL |
| `ABUSE_REPORTS_MAX` | `10000` | Redis list trim cap |
| `TRUST_PROXY` | loopback only | Set `true` on Vercel/Cloudflare |
| `HSTS_*` | 2 yr / includeSubDomains / no preload | Preload off-by-default to avoid locking out HTTP-only `.lan` |

---

## 11. Contact

Security disclosures: GitHub private vulnerability reporting on the repo,
or email the address in `SECURITY.md`. We commit to:
- ack within 72 hours,
- patch within 30 days for critical issues,
- credit in the release notes (or CVE) if the reporter wants it.
