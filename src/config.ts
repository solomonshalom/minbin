/**
 * src/config.ts
 *
 * Configuration settings for the minbin application.
 */

import 'dotenv/config';

function envStr(key: string, defaultValue: string): string {
    const v = process.env[key];
    return v === undefined || v === '' ? defaultValue : v;
}

function envOpt(key: string): string | undefined {
    const v = process.env[key];
    return v === undefined || v === '' ? undefined : v;
}

function envInt(key: string, defaultValue: number): number {
    const v = process.env[key];
    if (v === undefined || v === '') return defaultValue;
    const n = parseInt(v, 10);
    if (Number.isNaN(n) || !Number.isFinite(n)) {
        throw new Error(`Invalid integer value for env var "${key}": "${v}"`);
    }
    return n;
}

function envBool(key: string, defaultValue: boolean): boolean {
    const v = process.env[key];
    if (v === undefined || v === '') return defaultValue;
    const lower = v.trim().toLowerCase();
    if (lower === '1' || lower === 'true' || lower === 'yes' || lower === 'on') return true;
    if (lower === '0' || lower === 'false' || lower === 'no' || lower === 'off') return false;
    throw new Error(`Invalid boolean value for env var "${key}": "${v}"`);
}

/**
 * `TRUST_PROXY` controls how Fastify resolves `request.ip` from
 * X-Forwarded-For. On Vercel/Cloudflare we trust all hops (`true`); on
 * self-hosted Docker behind a user-supplied reverse proxy we restrict to
 * loopback only so XFF can't be spoofed.
 *
 * Accepted values:
 *   - "true"        -> trust all hops (Vercel default)
 *   - "false"       -> trust none, use socket peer
 *   - CIDR list     -> e.g. "127.0.0.1/8,::1/128,10.0.0.0/8"
 *   - integer       -> hop count (Fastify-supported form)
 */
function parseTrustProxy(raw: string): boolean | string | number {
    const lower = raw.trim().toLowerCase();
    if (lower === 'true') return true;
    if (lower === 'false') return false;
    if (/^\d+$/.test(lower)) return parseInt(lower, 10);
    return raw.trim();
}

export const Config = {
    APP_DOMAIN: envStr('APP_DOMAIN', 'minb.in'),

    // single connection string (preferred for Vercel KV / Upstash / managed Redis).
    REDIS_URL: envOpt('REDIS_URL') ?? envOpt('KV_URL'),

    // discrete fields (used when REDIS_URL is not provided).
    DB_HOST: envStr('DB_HOST', 'dragonfly'),
    DB_PORT: envInt('DB_PORT', 6379),
    DB_USER: envOpt('DB_USER'),
    DB_PASS: envOpt('DB_PASS'),

    PASTE_EXPIRY: envInt('PASTE_EXPIRY', 60),
    // 25 MB default. Chunked AES-GCM streaming can handle much larger payloads,
    // but Vercel function memory + CDN bandwidth costs make 25 MB a sensible
    // ceiling out-of-the-box. Self-hosters routinely bump this to 100 MB+.
    MAX_PASTE_SIZE: envInt('MAX_PASTE_SIZE', 1024 * 1024 * 25),

    // Security headers / hardening.
    // Default: loopback-only (safe for bare Docker). Set TRUST_PROXY=true on Vercel.
    TRUST_PROXY: parseTrustProxy(envStr('TRUST_PROXY', '127.0.0.1/8,::1/128')),

    // HSTS lifetime in seconds (default = 2 years; matches Chromium preload requirement).
    HSTS_MAX_AGE: envInt('HSTS_MAX_AGE', 63072000),
    // `preload` is permanent across browser updates -- off-by-default to avoid
    // locking self-hosters out of HTTP-only `.lan`/`.local` deployments.
    HSTS_PRELOAD: envBool('HSTS_PRELOAD', false),
    HSTS_INCLUDE_SUBDOMAINS: envBool('HSTS_INCLUDE_SUBDOMAINS', true),

    // New paste IDs are 16 hex chars (64 bits, ~1.8e19). Legacy 4-hex and 8-hex
    // IDs continue to resolve until expiry (the read path tolerates any width
    // 4..32 hex). 64 bits matches Yopass's design where the URL itself is the
    // credential for non-SRP-gated pastes.
    PASTE_ID_BYTES: envInt('PASTE_ID_BYTES', 8),
    // Bound the SET-NX retry loop so we never deadlock on a saturated keyspace.
    PASTE_ID_MAX_TRIES: envInt('PASTE_ID_MAX_TRIES', 8),

    // Per-route rate limit caps. Disable globally with RATE_LIMIT_ENABLED=false.
    RATE_LIMIT_ENABLED: envBool('RATE_LIMIT_ENABLED', true),
    RATE_LIMIT_WINDOW_MS: envInt('RATE_LIMIT_WINDOW_MS', 60_000),
    RATE_LIMIT_POST_MAX: envInt('RATE_LIMIT_POST_MAX', 30),
    RATE_LIMIT_GET_MAX: envInt('RATE_LIMIT_GET_MAX', 120),
    RATE_LIMIT_SRP_MAX: envInt('RATE_LIMIT_SRP_MAX', 10),
    RATE_LIMIT_BURN_MAX: envInt('RATE_LIMIT_BURN_MAX', 60),
    RATE_LIMIT_REPORT_MAX: envInt('RATE_LIMIT_REPORT_MAX', 5),
    RATE_LIMIT_CAPTCHA_MAX: envInt('RATE_LIMIT_CAPTCHA_MAX', 60),
    RATE_LIMIT_ACCESS_MAX: envInt('RATE_LIMIT_ACCESS_MAX', 60),

    // Per-IP daily byte budget. Cumulative across all uploads from one IP per
    // UTC day. Default 0 (disabled) so single-user self-hosters aren't
    // surprised; production deployments should set this (typical: 100MB-1GB).
    DAILY_BYTE_BUDGET: envInt('DAILY_BYTE_BUDGET', 0),

    // Hashcash-style proof-of-work captcha. Bits of leading-zero work the
    // client must produce on a server-issued challenge before a plaintext
    // upload is accepted. 0 = disabled; recommended 16-20 (~50ms-1s on
    // commodity hardware) when you need to harden the open POST surface.
    // Encrypted uploads bypass the captcha because the SRP+Argon2 cost
    // already raises the per-paste work for an attacker.
    CAPTCHA_BITS: envInt('CAPTCHA_BITS', 0),
    // HMAC secret for stateless captcha challenges. Auto-generated on boot if
    // unset; set explicitly to share across multi-instance deployments.
    CAPTCHA_SECRET: envOpt('CAPTCHA_SECRET'),
    // Lifetime of an issued captcha challenge before the server refuses it.
    CAPTCHA_TTL_SECONDS: envInt('CAPTCHA_TTL_SECONDS', 300),

    // Abuse reporting: stored in a Redis list `abuse:reports`. Operators can
    // drain via `LRANGE abuse:reports 0 -1`. Capped + TTL'd so the list
    // cannot grow unbounded.
    ABUSE_REPORT_EMAIL: envStr('ABUSE_REPORT_EMAIL', 'abuse@minb.in'),
    ABUSE_REPORTS_TTL_SECONDS: envInt('ABUSE_REPORTS_TTL_SECONDS', 30 * 86400),
    ABUSE_REPORTS_MAX: envInt('ABUSE_REPORTS_MAX', 10000),

    // Sane bounds for the new max-access-count and multi-recipient features.
    MAX_ACCESS_COUNT: envInt('MAX_ACCESS_COUNT', 1000),
    MAX_RECIPIENTS: envInt('MAX_RECIPIENTS', 16),
} as const;
