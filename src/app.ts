/**
 * src/app.ts
 *
 * Builds the Fastify application with all routes wired up. The Redis client is
 * injected so tests can pass an in-memory mock without touching the network.
 *
 * v1 (plaintext) records remain readable on the existing endpoints for
 * backward compatibility (and continue to be writable via the curl path).
 *
 * v3 records (Skiff-aligned) are gated behind an SRP-6a handshake (see
 * src/utils/srp.ts and SECURITY.md). Flow:
 *
 *   GET  /:id                    -> render the encrypted-paste shell (HTML).
 *   GET  /raw/:id                -> v3: return only the public header.
 *                                   v1: return the plaintext (legacy).
 *   POST /:id/srp/init           -> client sends A; server stores ephemeral b
 *                                   and returns salt + B.
 *   POST /:id/srp/verify         -> client sends M1; server returns M2 and the
 *                                   full ciphertext record.
 *   POST /:id/burn               -> idempotent delete (after a good decrypt).
 *   POST /:id/access             -> increment access counter (used by encrypted
 *                                   pastes with maxAccesses set; deletes when
 *                                   the cap is reached).
 *   POST /report                 -> abuse report drop-box (Redis-backed).
 *   GET  /captcha                -> issue a stateless PoW challenge.
 */

import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import Fastify, {
    type FastifyError,
    type FastifyInstance,
    type FastifyReply,
    type FastifyRequest,
} from 'fastify';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import fastifySwagger from '@fastify/swagger';
import nunjucks from 'nunjucks';
import type { Redis } from 'ioredis';

import { Config } from './config.js';
import {
    ENCRYPTED_CONTENT_TYPE,
    isEncryptedRecord,
    parseEncryptedRecord,
    publicView,
    type EncryptedRecord,
} from './utils/encrypted-record.js';
import {
    bigIntToMinBE,
    bytesToBigInt,
    isValidVerifier,
    N as SRP_N,
    srpServerInit,
    srpServerVerify,
} from './utils/srp.js';
import { computeSriMap, type SriMap } from './utils/sri.js';
import {
    getCaptchaSecret,
    issueChallenge,
    verifyChallenge,
} from './utils/captcha.js';
import { getVersion } from './version.js';

/**
 * Best-effort cross-origin detection: if the request supplies an Origin or
 * Sec-Fetch-Site header, validate that it is same-origin (or none/null).
 * Missing both headers is allowed -- curl, http servers, and CLI tools do
 * not set them. We never reject a request purely because the headers are
 * absent; we only reject when they are present AND inconsistent.
 *
 * This is defense-in-depth on top of CORS (we don't grant any) and
 * SameSite=Lax cookies (we don't set any). The actual CSRF threat here is
 * limited because there is no auth state to forge -- we are protecting
 * Redis from being filled by an attacker's victim's browser.
 */
function isOriginAllowed(request: FastifyRequest, appDomain: string): boolean {
    const origin = String(request.headers.origin ?? '').trim();
    const sfs = String(request.headers['sec-fetch-site'] ?? '').trim();

    if (origin) {
        try {
            const u = new URL(origin);
            const host = u.host.toLowerCase();
            const expected = appDomain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
            // Allow exact match against APP_DOMAIN. Many deployments terminate
            // TLS at a CDN/proxy so we allow the host portion alone; APP_DOMAIN
            // may be set with or without a scheme.
            const matchesConfigured =
                host === expected || host === expected.split(':')[0];
            // Also allow requests where the Origin matches the actual Host
            // we're being reached on. This handles localhost vs. 127.0.0.1
            // (and any reverse-proxy alias) without forcing operators to
            // enumerate every name in APP_DOMAIN. The browser sets Origin
            // from the initiating document and Host from the URL being
            // fetched, so a true cross-origin attacker still mismatches.
            const requestHost = String(request.headers.host ?? '').toLowerCase();
            const matchesRequestHost = !!requestHost && host === requestHost;
            if (!matchesConfigured && !matchesRequestHost) {
                return false;
            }
        } catch {
            return false;
        }
    }

    if (sfs) {
        // Per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site
        // valid values are 'same-origin', 'same-site', 'cross-site', 'none'.
        // 'none' is what direct URL bar / bookmark / curl would set if the
        // browser sent it (typically the browser sends it on top-level navs).
        if (sfs !== 'same-origin' && sfs !== 'same-site' && sfs !== 'none') {
            return false;
        }
    }

    return true;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function resolveTemplatesDir(): string {
    const candidates = [
        resolve(__dirname, '..', 'templates'),
        resolve(process.cwd(), 'templates'),
    ];
    for (const candidate of candidates) {
        if (existsSync(candidate)) return candidate;
    }
    return candidates[0];
}

const TEMPLATES_DIR = resolveTemplatesDir();
const ASSETS_DIR = resolve(TEMPLATES_DIR, 'assets');
const VENDOR_DIR = resolve(ASSETS_DIR, 'vendor');

const HTML_CONTENT_TYPE = 'text/html; charset=utf-8';
const TEXT_CONTENT_TYPE = 'text/plain; charset=utf-8';
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

// SRP ephemeral state TTL. Long enough for a slow phone to compute Argon2id,
// short enough that abandoned handshakes don't pile up.
const SRP_STATE_TTL_SECONDS = 90;

type LegacyPlaintext = {
    body?: unknown;
    once?: unknown;
    maxAccesses?: unknown;
};
type StoredRecord = LegacyPlaintext | EncryptedRecord;

type PlaintextAccessVerdict =
    | { kind: 'ok' }       // body should be returned, paste still alive
    | { kind: 'last' }     // body should be returned, paste should be deleted
    | { kind: 'over' };    // cap already reached; return 404

/**
 * Atomically reserve one access slot for a maxAccesses-capped plaintext
 * paste. Same Redis key shape (`acc:<id>`) as the encrypted-mode
 * `/:id/access` endpoint. Strict semantics: under concurrent reads, only
 * the first `cap` readers ever get the body — the rest see 404. This
 * matches the user's intuition for "max 2 views" much better than a
 * loose counter that overshoots under load.
 *
 * Returns:
 *   - `over`: counter already past `cap` (concurrent reader lost the race)
 *   - `last`: counter just hit `cap` (this reader is the last legitimate one)
 *   - `ok`:   counter incremented under the cap
 *
 * Fails open on Redis errors (returns `ok`) so a transient hiccup doesn't
 * 404 a legitimate reader.
 */
async function reservePlaintextAccessSlot(
    redis: Redis,
    pasteId: string,
    cap: number,
    pasteTtlSeconds: number,
): Promise<PlaintextAccessVerdict> {
    const counterKey = `acc:${pasteId}`;
    try {
        const used = await redis.incr(counterKey);
        if (used === 1 && pasteTtlSeconds > 0) {
            // Tie counter TTL to the paste TTL so it cleans up on its own.
            await redis.expire(counterKey, pasteTtlSeconds);
        }
        if (used > cap) {
            // Lost the race -- another concurrent reader was the cap-th one.
            // Don't decrement so we keep monotonic semantics; the counter
            // expires with the paste anyway.
            return { kind: 'over' };
        }
        if (used === cap) {
            // This reader is the last legitimate one. Caller should delete.
            await redis.del(counterKey);
            return { kind: 'last' };
        }
        return { kind: 'ok' };
    } catch {
        // Fail open: a Redis hiccup on the counter shouldn't 500 a read.
        return { kind: 'ok' };
    }
}

function tryParseStored(raw: string): StoredRecord | null {
    try {
        return JSON.parse(raw) as StoredRecord;
    } catch {
        return null;
    }
}

function b64uEncode(buf: Buffer | Uint8Array): string {
    return Buffer.from(buf).toString('base64url');
}

function b64uDecode(s: string): Buffer {
    if (typeof s !== 'string') throw new Error('expected base64url string');
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('invalid base64url');
    return Buffer.from(s, 'base64url');
}

function isValidPasteIdShape(s: string): boolean {
    // 4..32 hex chars: covers the legacy 4-hex IDs, the previous 8-hex default,
    // the new 16-hex default, and any operator who bumps PASTE_ID_BYTES higher.
    return /^[0-9a-f]{4,32}$/.test(s);
}

interface SrpChallengeState {
    paste_id: string;
    A: string; // base64url big-endian client ephemeral
    b: string; // base64url big-endian server private exponent
    B: string; // base64url big-endian server public ephemeral
}

/**
 * Allocate a fresh paste ID using SET NX EX. Retries on collision so two
 * concurrent uploads can never silently overwrite each other in the
 * ID keyspace. Falls back to a wider ID if the configured width fills up
 * (astronomically unlikely at 64 bits).
 */
async function allocatePasteId(
    redis: Redis,
    payload: string,
    ttlSeconds: number,
): Promise<string> {
    const widths: number[] = [Config.PASTE_ID_BYTES];
    if (Config.PASTE_ID_BYTES < 8) widths.push(8); // safety net for narrow keyspaces
    if (Config.PASTE_ID_BYTES < 16) widths.push(16);
    for (const width of widths) {
        for (let i = 0; i < Config.PASTE_ID_MAX_TRIES; i++) {
            const id = randomBytes(width).toString('hex');
            // SET key value NX EX ttl: atomic insert-only with TTL.
            const result = await redis.set(id, payload, 'EX', ttlSeconds, 'NX');
            if (result === 'OK') return id;
        }
    }
    throw new Error('failed to allocate a unique paste ID after retries');
}

/**
 * Defense-in-depth re-validation on read. `parseEncryptedRecord` runs at
 * upload time, but if a record was inserted via a buggy code path (or an
 * attacker with direct Redis access mutated one) the read path should
 * refuse to serve a malformed record rather than ship partial data.
 *
 * Returns the validated record on success, or null on any failure.
 */
function revalidateEncryptedRecord(raw: unknown): EncryptedRecord | null {
    try {
        return parseEncryptedRecord(raw, Config.MAX_PASTE_SIZE, {
            maxRecipients: Config.MAX_RECIPIENTS,
            maxAccessCount: Config.MAX_ACCESS_COUNT,
        });
    } catch {
        return null;
    }
}

export interface AppOptions {
    redis: Redis;
    logger?: boolean | object;
}

export async function createApp(opts: AppOptions): Promise<FastifyInstance> {
    const { redis } = opts;

    // Pre-compute Subresource Integrity hashes for every vendored asset. This
    // happens once at boot. Templates reference them via `sri['<filename>']`
    // so a tampered git push or compromised CI cannot inject a different
    // bundle without breaking the browser's integrity check (see
    // src/utils/sri.ts).
    const SRI: SriMap = computeSriMap(VENDOR_DIR);

    const njEnv = nunjucks.configure(TEMPLATES_DIR, {
        autoescape: true,
        noCache: process.env.NODE_ENV !== 'production',
        throwOnUndefined: false,
    });
    njEnv.addGlobal('sri', SRI);
    njEnv.addGlobal('app_domain', Config.APP_DOMAIN);
    njEnv.addGlobal('abuse_email', Config.ABUSE_REPORT_EMAIL);
    njEnv.addGlobal('captcha_bits', Config.CAPTCHA_BITS);

    const renderTemplate = (
        name: string,
        ctx: Record<string, unknown> = {},
    ): string => njEnv.render(name, ctx);

    const captchaSecret = getCaptchaSecret(Config.CAPTCHA_SECRET);

    const fastify = Fastify({
        logger:
            opts.logger === undefined
                ? {
                      level: process.env.LOG_LEVEL ?? 'info',
                      // Avoid persisting sensitive headers in logs. Paste IDs
                      // are still emitted via req.url -- we keep that for
                      // debugability since IDs are public identifiers, not
                      // secrets (and SRP+pubkey gates protect ciphertext).
                      redact: {
                          paths: [
                              'req.headers.authorization',
                              'req.headers.cookie',
                              'req.headers["x-forwarded-for"]',
                              'req.headers["x-real-ip"]',
                              'req.headers["cf-connecting-ip"]',
                              'res.headers["set-cookie"]',
                          ],
                          censor: '[redacted]',
                      },
                  }
                : opts.logger,
        bodyLimit: Config.MAX_PASTE_SIZE,
        // Configurable: defaults to loopback for self-hosted Docker (safe
        // against XFF spoofing). Set TRUST_PROXY=true on Vercel.
        trustProxy: Config.TRUST_PROXY,
        disableRequestLogging: false,
        // AJV strict mode: catches schema authoring mistakes (unknown
        // keywords, ambiguous formats). `removeAdditional: false` means
        // schemas marked `additionalProperties: false` will reject (not
        // silently strip) unknown fields, surfacing probe attempts in
        // logs. Type coercion stays enabled so querystring booleans (e.g.
        // `?relative=true`) continue to coerce. The encrypted-record body
        // bypasses AJV entirely (hand-parsed via parseEncryptedRecord).
        ajv: {
            customOptions: {
                strict: true,
                removeAdditional: false,
                coerceTypes: true,
                useDefaults: true,
                allErrors: false,
            },
        },
    });

    redis.on('error', (err: Error) => {
        fastify.log.error({ err }, 'redis client error');
    });
    redis.on('connect', () => {
        fastify.log.info(
            { host: Config.DB_HOST, port: Config.DB_PORT },
            'redis connected',
        );
    });
    redis.on('reconnecting', () => {
        fastify.log.warn('redis reconnecting');
    });

    // Pre-build the static security-header values that don't vary per request.
    const HSTS_VALUE = (() => {
        const parts = [`max-age=${Config.HSTS_MAX_AGE}`];
        if (Config.HSTS_INCLUDE_SUBDOMAINS) parts.push('includeSubDomains');
        if (Config.HSTS_PRELOAD) parts.push('preload');
        return parts.join('; ');
    })();

    // Permissions-Policy: deny everything we don't actively use. Each
    // feature is `=()` (no allowed origins). This complements CSP by
    // preventing browser features (camera, mic, USB, etc.) even if a
    // script somehow runs.
    const PERMISSIONS_POLICY = [
        'accelerometer=()',
        'ambient-light-sensor=()',
        'autoplay=()',
        'battery=()',
        'bluetooth=()',
        'camera=()',
        'clipboard-read=(self)',
        'clipboard-write=(self)',
        'cross-origin-isolated=()',
        'display-capture=()',
        'document-domain=()',
        'encrypted-media=()',
        'execution-while-not-rendered=()',
        'execution-while-out-of-viewport=()',
        'fullscreen=(self)',
        'geolocation=()',
        'gyroscope=()',
        'hid=()',
        'identity-credentials-get=()',
        'idle-detection=()',
        'interest-cohort=()',
        'keyboard-map=()',
        'magnetometer=()',
        'microphone=()',
        'midi=()',
        'navigation-override=()',
        'payment=()',
        'picture-in-picture=()',
        'publickey-credentials-get=()',
        'screen-wake-lock=()',
        'serial=()',
        'sync-xhr=()',
        'usb=()',
        'web-share=()',
        'window-management=()',
        'xr-spatial-tracking=()',
    ].join(', ');

    // CSP: no `'unsafe-inline'` for scripts or styles. All third-party
    // dependencies are vendored under /assets/vendor/. `'wasm-unsafe-eval'`
    // is required for the Argon2 WASM module (hash-wasm). Worker blob: is
    // for any future Web Worker use; we don't ship one today, but the cost
    // of allowing it on the same-origin page is zero.
    const CSP = [
        "default-src 'self'",
        "script-src 'self' 'wasm-unsafe-eval'",
        "worker-src 'self' blob:",
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self' data:",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "manifest-src 'self'",
    ].join('; ');

    fastify.addHook('onSend', async (request, reply, payload) => {
        const ct = String(reply.getHeader('content-type') ?? '');
        const url = String(request.url ?? '');
        const isAsset = url.startsWith('/assets/');

        if (ct.startsWith('text/html')) {
            reply.header('content-security-policy', CSP);
        }
        reply.header('referrer-policy', 'no-referrer');
        reply.header('x-content-type-options', 'nosniff');
        reply.header('x-frame-options', 'DENY');
        reply.header('permissions-policy', PERMISSIONS_POLICY);
        reply.header('strict-transport-security', HSTS_VALUE);
        reply.header('cross-origin-opener-policy', 'same-origin');
        reply.header('cross-origin-resource-policy', 'same-origin');
        // Robots: noindex, nofollow, noarchive, nosnippet on every response,
        // belt and braces alongside <meta name="robots"> in HTML and the
        // /robots.txt route. Honored by Google, Bing, DuckDuckGo, and the
        // Internet Archive.
        reply.header('x-robots-tag', 'noindex, nofollow, noarchive, nosnippet');

        if (isAsset) {
            // Assets are content-addressable (filenames carry hashes) so
            // they can be cached aggressively.
            reply.header('cache-control', 'public, max-age=31536000, immutable');
        } else {
            // Pastes, SRP responses, and HTML must never be cached -- both
            // for privacy (a downstream proxy could leak ciphertext + KDF
            // params) and freshness (TTL-based expiry).
            reply.header('cache-control', 'no-store');
        }

        // Strip server-fingerprint headers that some platforms inject.
        reply.removeHeader('server');
        reply.removeHeader('x-powered-by');

        return payload;
    });

    // Origin / Sec-Fetch-Site enforcement on state-changing endpoints.
    // Defense-in-depth on top of: no auth state, no SameSite cookies, no
    // CORS grant. We allow missing Origin/Sec-Fetch-Site (curl, mobile
    // Safari fetch under some conditions) and only reject when those
    // headers are present and inconsistent with the configured APP_DOMAIN.
    fastify.addHook('onRequest', async (request, reply) => {
        const method = (request.method ?? '').toUpperCase();
        if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
            return;
        }
        if (!isOriginAllowed(request, Config.APP_DOMAIN)) {
            await reply
                .code(403)
                .type(JSON_CONTENT_TYPE)
                .send({ detail: 'Cross-origin request blocked.' });
            return reply;
        }
    });

    /**
     * Per-paste-ID rate limit on SRP endpoints. The per-route @fastify/rate-limit
     * key already includes paste_id (IP|paste_id), but that limits each
     * (IP, paste) tuple independently. A botnet hitting one paste from many
     * IPs would not trip the per-tuple cap. This hook adds a second
     * dimension: max RATE_LIMIT_SRP_MAX requests/min per paste regardless of
     * source IP. Implemented as Redis INCR with TTL.
     */
    if (Config.RATE_LIMIT_ENABLED) {
        fastify.addHook('preHandler', async (request, reply) => {
            const url = String(request.url ?? '');
            // Only apply to SRP endpoints.
            const m = url.match(/^\/([0-9a-f]+)\/srp\/(init|verify)\b/);
            if (!m) return;
            const pasteId = m[1];
            const key = `rl:paste:${pasteId}`;
            try {
                const count = await redis.incr(key);
                if (count === 1) {
                    await redis.pexpire(
                        key,
                        Config.RATE_LIMIT_WINDOW_MS,
                    );
                }
                if (count > Config.RATE_LIMIT_SRP_MAX) {
                    const ttl = await redis.pttl(key);
                    const retryMs = ttl > 0 ? ttl : Config.RATE_LIMIT_WINDOW_MS;
                    await reply
                        .code(429)
                        .header('retry-after', Math.ceil(retryMs / 1000).toString())
                        .type(JSON_CONTENT_TYPE)
                        .send({
                            detail: 'Too many SRP attempts on this paste; try again later.',
                        });
                    return reply;
                }
            } catch (err) {
                // Fail open: a Redis hiccup shouldn't block legitimate users.
                request.log.warn({ err }, 'per-paste rate-limit Redis error; failing open');
            }
        });
    }

    await fastify.register(fastifySwagger, {
        openapi: {
            info: {
                title: 'minbin',
                description: 'a minimal, ephemeral pastebin service',
                version: getVersion(),
            },
        },
    });

    // Rate limiting: per-route caps on top of a permissive global default.
    // Backed by Redis so caps are shared across Vercel serverless instances
    // and Docker replicas. `skipOnError: true` means we fail open if Redis
    // is unreachable (a rate-limit failure shouldn't take the service down).
    if (Config.RATE_LIMIT_ENABLED) {
        await fastify.register(fastifyRateLimit, {
            global: false, // per-route opt-in via `config.rateLimit`
            redis,
            nameSpace: 'rl:',
            skipOnError: true,
            keyGenerator: (req: FastifyRequest) => req.ip,
            addHeaders: {
                'x-ratelimit-limit': true,
                'x-ratelimit-remaining': true,
                'x-ratelimit-reset': true,
                'retry-after': true,
            },
            // Standardized RateLimit-* headers per IETF httpapi draft.
            enableDraftSpec: true,
        });
    }

    await fastify.register(fastifyStatic, {
        root: ASSETS_DIR,
        prefix: '/assets/',
        decorateReply: false,
        wildcard: true,
        index: false,
        list: false,
    });

    fastify.removeAllContentTypeParsers();
    fastify.addContentTypeParser(
        '*',
        { parseAs: 'buffer' },
        (_req, body, done) => {
            done(null, body);
        },
    );

    fastify.setErrorHandler((
        error: FastifyError,
        request: FastifyRequest,
        reply: FastifyReply,
    ) => {
        if (
            error.code === 'FST_ERR_CTP_BODY_TOO_LARGE' ||
            error.statusCode === 413
        ) {
            return reply
                .code(400)
                .type(TEXT_CONTENT_TYPE)
                .send('Paste body is empty or exceeds maximum size.');
        }

        if (error.validation) {
            return reply
                .code(error.statusCode ?? 422)
                .type(JSON_CONTENT_TYPE)
                .send({ detail: error.message });
        }

        request.log.error({ err: error }, 'unhandled error');
        const status = error.statusCode && error.statusCode >= 400 ? error.statusCode : 500;
        return reply
            .code(status)
            .type(JSON_CONTENT_TYPE)
            .send({
                detail:
                    status >= 500
                        ? 'Internal Server Error'
                        : (error.message ?? 'Error'),
            });
    });

    fastify.setNotFoundHandler((_request, reply) => {
        return reply
            .code(404)
            .type(JSON_CONTENT_TYPE)
            .send({ detail: 'Not Found' });
    });

    fastify.get(
        '/openapi',
        { schema: { hide: true } },
        async (_request, reply) => {
            return reply.type(JSON_CONTENT_TYPE).send(fastify.swagger());
        },
    );

    // /robots.txt: keep search engines and the Internet Archive out of paste
    // pages and the raw API. Paired with X-Robots-Tag and <meta name="robots">
    // for belt-and-braces. The Wayback Machine respects the explicit named
    // user-agents below; Googlebot/Bingbot honor the wildcard Disallow.
    const ROBOTS_TXT = [
        'User-agent: *',
        'Disallow: /',
        '',
        'User-agent: ia_archiver',
        'Disallow: /',
        '',
        'User-agent: archive.org_bot',
        'Disallow: /',
        '',
        'User-agent: Wayback',
        'Disallow: /',
        '',
    ].join('\n');
    fastify.get('/robots.txt', { schema: { hide: true } }, async (_req, reply) => {
        return reply.code(200).type(TEXT_CONTENT_TYPE).send(ROBOTS_TXT);
    });

    fastify.get(
        '/',
        {
            schema: {
                summary: 'Get the index page.',
                description: 'Get the index page.',
                response: {
                    200: { type: 'string', description: 'HTML page' },
                },
            },
        },
        async (_request, reply) => {
            const html = renderTemplate('index.html', {
                max_access_count: Config.MAX_ACCESS_COUNT,
                max_recipients: Config.MAX_RECIPIENTS,
                captcha_bits: Config.CAPTCHA_BITS,
            });
            return reply.code(200).type(HTML_CONTENT_TYPE).send(html);
        },
    );

    fastify.get(
        '/api',
        {
            schema: {
                summary: 'Get the human-friendly API documentation page.',
                description:
                    'Renders /api as an HTML docs page. The machine-readable OpenAPI document remains available at /openapi.',
                response: {
                    200: { type: 'string', description: 'HTML page' },
                },
            },
        },
        async (_request, reply) => {
            const html = renderTemplate('api.html', {
                current_year: new Date().getFullYear(),
                max_paste_size_mb: Math.floor(Config.MAX_PASTE_SIZE / (1024 * 1024)),
                paste_expiry_minutes: Config.PASTE_EXPIRY,
            });
            return reply.code(200).type(HTML_CONTENT_TYPE).send(html);
        },
    );

    /**
     * GET /captcha
     *
     * Issues a fresh PoW challenge token. When CAPTCHA_BITS=0 (default for
     * fresh installs) the endpoint still works but returns bits=0 so a
     * client doesn't have to special-case the absence of a captcha.
     */
    fastify.get(
        '/captcha',
        {
            bodyLimit: 256,
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_CAPTCHA_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Issue a proof-of-work captcha challenge.',
                description:
                    'Returns { token, bits, expiresAt }. Solve by finding a base64url-encoded 64-bit nonce such that SHA-256(rand_part_of_token || nonce) has at least `bits` leading zero bits. Submit on plaintext POST / via X-Captcha-Token + X-Captcha-Nonce headers (or `?captchaToken=&captchaNonce=` query). When CAPTCHA_BITS=0 the captcha is disabled and uploads pass without it.',
            },
        },
        async (_request, reply) => {
            const challenge = issueChallenge(
                captchaSecret,
                Config.CAPTCHA_BITS,
                Config.CAPTCHA_TTL_SECONDS,
            );
            return reply
                .code(200)
                .type(JSON_CONTENT_TYPE)
                .send(challenge);
        },
    );

    /**
     * POST /report
     *
     * Operator-facing abuse drop-box. Reports are pushed onto a Redis list
     * `abuse:reports`, capped at ABUSE_REPORTS_MAX entries with a
     * ABUSE_REPORTS_TTL_SECONDS expiry. Operators drain via:
     *
     *   redis-cli LRANGE abuse:reports 0 -1
     *
     * The endpoint accepts JSON: { paste_id, reason, contact?, link? }.
     * Encrypted pastes are opaque to the operator; the link (with fragment)
     * is the only way for them to evaluate content -- include it in `link`.
     */
    fastify.post(
        '/report',
        {
            bodyLimit: 4096,
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_REPORT_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Submit an abuse report for a paste.',
                description:
                    'Body: { paste_id, reason, contact?, link? }. Reports are stored in Redis (TTL ABUSE_REPORTS_TTL_SECONDS, max ABUSE_REPORTS_MAX entries). For encrypted pastes the operator cannot view content without the full link (URL fragment), so include it under `link` if you can.',
            },
        },
        async (request, reply) => {
            const body = parseJsonBody(request.body) as {
                paste_id?: unknown;
                reason?: unknown;
                contact?: unknown;
                link?: unknown;
            } | null;
            if (!body) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Body must be JSON.' });
            }
            const pasteId = typeof body.paste_id === 'string' ? body.paste_id.trim() : '';
            const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
            const contact = typeof body.contact === 'string' ? body.contact.trim().slice(0, 256) : '';
            const link = typeof body.link === 'string' ? body.link.trim().slice(0, 2048) : '';
            if (!pasteId || !isValidPasteIdShape(pasteId)) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'paste_id must be 4..32 lowercase hex chars.' });
            }
            if (!reason || reason.length < 10 || reason.length > 1000) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'reason must be 10..1000 chars.' });
            }
            const report = JSON.stringify({
                ts: new Date().toISOString(),
                ip: request.ip,
                paste_id: pasteId,
                reason: reason.slice(0, 1000),
                contact,
                link,
            });
            try {
                await redis.lpush('abuse:reports', report);
                if (Config.ABUSE_REPORTS_MAX > 0) {
                    await redis.ltrim('abuse:reports', 0, Config.ABUSE_REPORTS_MAX - 1);
                }
                if (Config.ABUSE_REPORTS_TTL_SECONDS > 0) {
                    await redis.expire('abuse:reports', Config.ABUSE_REPORTS_TTL_SECONDS);
                }
            } catch (err) {
                request.log.error({ err }, 'failed to store abuse report');
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Could not record the report; try again later.' });
            }
            return reply
                .code(201)
                .type(JSON_CONTENT_TYPE)
                .send({
                    ok: true,
                    contact_email: Config.ABUSE_REPORT_EMAIL,
                });
        },
    );

    fastify.post<{
        Querystring: {
            once?: string;
            relative?: boolean;
            maxAccesses?: number;
            captchaToken?: string;
            captchaNonce?: string;
        };
    }>(
        '/',
        {
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_POST_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Create a new paste.',
                description:
                    'Plaintext or v3 encrypted paste. Encrypted records (Content-Type: ' +
                    ENCRYPTED_CONTENT_TYPE +
                    ') carry the `once` and `maxAccesses` flags inside the record, not the query string. When CAPTCHA_BITS > 0, plaintext POSTs require a solved PoW token via X-Captcha-Token + X-Captcha-Nonce headers (or ?captchaToken=&captchaNonce=). DAILY_BYTE_BUDGET caps cumulative per-IP per-day upload bytes.',
                querystring: {
                    type: 'object',
                    additionalProperties: false,
                    properties: {
                        once: {
                            type: 'string',
                            description:
                                'If true, plaintext paste will self-destruct after one view.',
                        },
                        relative: {
                            type: 'boolean',
                            description:
                                'If true, only return the paste ID instead of the full URL.',
                            default: false,
                        },
                        maxAccesses: {
                            type: 'integer',
                            minimum: 1,
                            maximum: Config.MAX_ACCESS_COUNT,
                            description:
                                'Plaintext only: max times the paste may be read before auto-deletion. Encrypted pastes set this inside the record.',
                        },
                        captchaToken: {
                            type: 'string',
                            description:
                                'Solved PoW token (alternative to X-Captcha-Token header).',
                        },
                        captchaNonce: {
                            type: 'string',
                            description:
                                'Solved PoW nonce (alternative to X-Captcha-Nonce header).',
                        },
                    },
                },
                response: {
                    201: { type: 'string', description: 'Paste URL or ID' },
                    400: { type: 'string', description: 'Bad request' },
                    402: {
                        type: 'object',
                        description: 'Daily byte budget exceeded',
                        properties: { detail: { type: 'string' } },
                    },
                    422: {
                        type: 'object',
                        description: 'Captcha required or rejected',
                        properties: { detail: { type: 'string' } },
                    },
                },
            },
        },
        async (request, reply) => {
            const body = request.body as Buffer | undefined | null;

            if (
                !body ||
                body.length === 0 ||
                body.length > Config.MAX_PASTE_SIZE
            ) {
                return reply
                    .code(400)
                    .type(TEXT_CONTENT_TYPE)
                    .send('Paste body is empty or exceeds maximum size.');
            }

            const relative = request.query.relative === true;
            const pasteExpirySeconds = Config.PASTE_EXPIRY * 60;

            const contentType = String(request.headers['content-type'] ?? '');
            const isEncryptedUpload = contentType.toLowerCase().startsWith(ENCRYPTED_CONTENT_TYPE);

            // Captcha is required (when configured) only on plaintext POSTs
            // because that's the open abuse surface -- encrypted pastes
            // already cost a 64 MiB Argon2id (or a 256-bit SRP) per upload,
            // which is the natural rate gate. The captcha runs BEFORE the
            // byte budget so an attacker can't drain a victim's daily byte
            // allowance by sending unsolved captcha attempts.
            if (!isEncryptedUpload && Config.CAPTCHA_BITS > 0) {
                const tokenHeader = String(request.headers['x-captcha-token'] ?? '').trim();
                const nonceHeader = String(request.headers['x-captcha-nonce'] ?? '').trim();
                const token = tokenHeader || (request.query.captchaToken ?? '');
                const nonce = nonceHeader || (request.query.captchaNonce ?? '');
                if (!token || !nonce) {
                    return reply
                        .code(422)
                        .type(JSON_CONTENT_TYPE)
                        .send({
                            detail: `This deployment requires a proof-of-work captcha (${Config.CAPTCHA_BITS} bits). GET /captcha for a token, solve the PoW, and resubmit with X-Captcha-Token + X-Captcha-Nonce headers.`,
                        });
                }
                const verdict = await verifyChallenge(token, nonce, {
                    secret: captchaSecret,
                    bits: Config.CAPTCHA_BITS,
                    ttlSeconds: Config.CAPTCHA_TTL_SECONDS,
                    redis,
                });
                if (!verdict.ok) {
                    return reply
                        .code(422)
                        .type(JSON_CONTENT_TYPE)
                        .send({
                            detail: `Captcha rejected (${verdict.reason}). GET /captcha for a fresh token and try again.`,
                        });
                }
            }

            // Per-IP daily byte budget runs AFTER the captcha (so an
            // unauthenticated attacker can't drain a victim's allowance with
            // garbage POSTs) but BEFORE the actual store, so a budget
            // rejection is observable before we hit Redis writes.
            //
            // Default 0 (disabled). Production deployments should set
            // DAILY_BYTE_BUDGET to a sensible cap (e.g. 100 MB/day) so a
            // single abusive IP can't grind through the rate limit
            // indefinitely.
            if (Config.DAILY_BYTE_BUDGET > 0) {
                const day = Math.floor(Date.now() / 86_400_000);
                const key = `bb:${request.ip}:${day}`;
                try {
                    const used = await redis.incrby(key, body.length);
                    if (used === body.length) {
                        // First touch this UTC day -- attach a TTL slightly
                        // longer than 24h so we don't have to reason about
                        // clock skew at midnight boundaries.
                        await redis.expire(key, 26 * 3600);
                    }
                    if (used > Config.DAILY_BYTE_BUDGET) {
                        // Roll back so legitimate retries with smaller bodies
                        // (or after midnight UTC) succeed.
                        await redis.decrby(key, body.length);
                        const ttl = await redis.ttl(key);
                        const retryAfter = ttl > 0 ? ttl : 24 * 3600;
                        return reply
                            .code(402)
                            .header('retry-after', String(retryAfter))
                            .type(JSON_CONTENT_TYPE)
                            .send({
                                detail:
                                    'Daily upload byte budget exceeded for this IP. Retry after the UTC day rolls over.',
                            });
                    }
                } catch (err) {
                    // Fail open on Redis errors -- the per-route rate limit
                    // is the primary defense; the byte budget is layered.
                    request.log.warn({ err }, 'byte-budget Redis error; failing open');
                }
            }

            if (isEncryptedUpload) {
                let raw: unknown;
                try {
                    raw = JSON.parse(body.toString('utf8'));
                } catch {
                    return reply
                        .code(400)
                        .type(TEXT_CONTENT_TYPE)
                        .send('Encrypted paste body is not valid JSON.');
                }

                let record: EncryptedRecord;
                try {
                    record = parseEncryptedRecord(raw, Config.MAX_PASTE_SIZE, {
                        maxRecipients: Config.MAX_RECIPIENTS,
                        maxAccessCount: Config.MAX_ACCESS_COUNT,
                    });
                } catch (err) {
                    const message =
                        err instanceof Error ? err.message : 'invalid record';
                    return reply
                        .code(400)
                        .type(TEXT_CONTENT_TYPE)
                        .send(`Encrypted paste rejected: ${message}.`);
                }

                if (record.srp) {
                    const v = bytesToBigInt(b64uDecode(record.srp.verifier));
                    if (!isValidVerifier(v)) {
                        return reply
                            .code(400)
                            .type(TEXT_CONTENT_TYPE)
                            .send(
                                'Encrypted paste rejected: SRP verifier out of range.',
                            );
                    }
                }

                const pasteId = await allocatePasteId(
                    redis,
                    JSON.stringify(record),
                    pasteExpirySeconds,
                );

                reply.code(201).type(TEXT_CONTENT_TYPE);
                if (relative) return pasteId;
                return `${Config.APP_DOMAIN}/${pasteId}`;
            }

            const onceFlag = request.query.once !== undefined;
            const maxAccesses = request.query.maxAccesses;
            const accessCap =
                typeof maxAccesses === 'number' &&
                Number.isInteger(maxAccesses) &&
                maxAccesses >= 1 &&
                maxAccesses <= Config.MAX_ACCESS_COUNT
                    ? maxAccesses
                    : undefined;

            const pasteContent = JSON.stringify({
                body: body.toString('utf8'),
                once: onceFlag,
                ...(accessCap ? { maxAccesses: accessCap } : {}),
            });

            const pasteId = await allocatePasteId(
                redis,
                pasteContent,
                pasteExpirySeconds,
            );

            reply.code(201).type(TEXT_CONTENT_TYPE);
            if (relative) {
                return pasteId;
            }
            return `${Config.APP_DOMAIN}/${pasteId}`;
        },
    );

    /**
     * GET /raw/:id
     *
     * v1 plaintext: returns text/plain, burns on read for `once` pastes.
     * v3 encrypted: returns ONLY the public header. The ciphertext is held
     *   back until the client completes SRP-6a at /:id/srp/verify.
     */
    fastify.get<{ Params: { paste_id: string } }>(
        '/raw/:paste_id',
        {
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_GET_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Get the raw paste content (or its public header for v3).',
                description:
                    'For plaintext (v1) returns text/plain. For v3 encrypted returns only the public header (KDF params + recipient pubkey, no ciphertext, no verifier).',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            if (!isValidPasteIdShape(paste_id)) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: `Paste with ID '${paste_id}' not found.` });
            }
            const pasteContent = await redis.get(paste_id);

            if (pasteContent === null) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({
                        detail: `Paste with ID '${paste_id}' not found.`,
                    });
            }

            const parsed = tryParseStored(pasteContent);
            if (parsed === null) {
                request.log.error(
                    { paste_id },
                    'failed to parse paste content from redis',
                );
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }

            if (isEncryptedRecord(parsed)) {
                // Re-validate full shape on read; refuse to serve a malformed
                // record even if it slipped past the upload guard.
                const valid = revalidateEncryptedRecord(parsed);
                if (valid === null) {
                    request.log.error(
                        { paste_id },
                        'stored encrypted record failed re-validation',
                    );
                    return reply
                        .code(500)
                        .type(JSON_CONTENT_TYPE)
                        .send({ detail: 'Internal Server Error' });
                }
                return reply
                    .code(200)
                    .type(JSON_CONTENT_TYPE)
                    .send(publicView(valid));
            }

            const v1 = parsed as LegacyPlaintext;
            const pasteBody = typeof v1.body === 'string' ? v1.body : '';

            // Two independent burn paths: `once` (single-use) or maxAccesses
            // counter reaching its cap. once short-circuits the counter.
            const shouldBurnOnce = v1.once === true;
            const cap = typeof v1.maxAccesses === 'number'
                && Number.isInteger(v1.maxAccesses)
                && v1.maxAccesses >= 1
                    ? v1.maxAccesses
                    : 0;
            if (!shouldBurnOnce && cap > 0) {
                const ttl = await redis.ttl(paste_id);
                const verdict = await reservePlaintextAccessSlot(
                    redis, paste_id, cap, ttl,
                );
                if (verdict.kind === 'over') {
                    // Concurrent reader took the last slot.
                    return reply
                        .code(404)
                        .type(JSON_CONTENT_TYPE)
                        .send({ detail: `Paste with ID '${paste_id}' not found.` });
                }
                if (verdict.kind === 'last') {
                    await redis.del(paste_id);
                }
            } else if (shouldBurnOnce) {
                await redis.del(paste_id);
            }

            return reply
                .code(200)
                .type(TEXT_CONTENT_TYPE)
                .send(pasteBody);
        },
    );

    /**
     * POST /:id/srp/init
     *
     * Body: { A: base64url(big-endian client ephemeral) }
     *
     * Returns 200 { challengeId, salt, B } on success.
     * Returns 400 if A is malformed or A mod N == 0 (RFC abort).
     * Returns 404 if the paste is missing or not v3.
     */
    fastify.post<{ Params: { paste_id: string } }>(
        '/:paste_id/srp/init',
        {
            // SRP init carries one base64url 256-byte BigInt (~344 chars
            // when encoded) plus JSON envelope. 4 KiB is generous; bigger
            // bodies are abuse, not legitimate clients.
            bodyLimit: 4096,
            // Rate limit on the (IP, paste_id) tuple so an attacker
            // brute-forcing one paste from many IPs is bounded per-IP, and
            // an attacker scanning many pastes from one IP is bounded per
            // paste. The cross-IP per-paste cap is enforced separately by
            // the onRequest hook below.
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_SRP_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                          keyGenerator: (req: FastifyRequest) => {
                              const params = req.params as { paste_id?: string };
                              return `${req.ip}|${params?.paste_id ?? ''}`;
                          },
                      },
                  }
                : undefined,
            schema: {
                summary: 'Begin an SRP-6a handshake for a v3 encrypted paste.',
                description:
                    'Submit your A = g^a mod N. Receive the per-paste salt and B = (kv + g^b) mod N. Skiff §6.5 link-sharing flow, adapted for ephemeral pastes.',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            if (!isValidPasteIdShape(paste_id)) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Paste not found.' });
            }
            const bodyJson = parseJsonBody(request.body) as { A?: unknown };
            if (!bodyJson) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Body must be JSON.' });
            }

            const A_str = bodyJson.A;
            if (typeof A_str !== 'string' || A_str.length === 0) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Missing A.' });
            }

            let A_bytes: Buffer;
            try {
                A_bytes = b64uDecode(A_str);
            } catch {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Invalid A.' });
            }
            if (A_bytes.length === 0 || A_bytes.length > 256) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'A out of range.' });
            }

            const A = bytesToBigInt(A_bytes);
            if (A <= 0n || A % SRP_N === 0n) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'A mod N is zero.' });
            }

            const stored = await redis.get(paste_id);
            if (stored === null) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Paste not found.' });
            }

            const parsed = tryParseStored(stored);
            if (
                parsed === null ||
                !isEncryptedRecord(parsed) ||
                !parsed.srp
            ) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({
                        detail:
                            'Paste does not support SRP (use GET /raw/:id instead).',
                    });
            }

            const verifier = bytesToBigInt(b64uDecode(parsed.srp.verifier));
            if (!isValidVerifier(verifier)) {
                request.log.error({ paste_id }, 'stored verifier is invalid');
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }

            const { b, B } = srpServerInit(verifier);

            const challengeId = randomBytes(16).toString('base64url');
            const challengeKey = `srp:${challengeId}`;
            const challengeValue: SrpChallengeState = {
                paste_id,
                A: b64uEncode(A_bytes),
                b: b64uEncode(bigIntToMinBE(b)),
                B: b64uEncode(bigIntToMinBE(B)),
            };
            await redis.set(
                challengeKey,
                JSON.stringify(challengeValue),
                'EX',
                SRP_STATE_TTL_SECONDS,
            );

            return reply
                .code(200)
                .type(JSON_CONTENT_TYPE)
                .send({
                    challengeId,
                    salt: parsed.srp.salt,
                    B: b64uEncode(bigIntToMinBE(B)),
                });
        },
    );

    /**
     * POST /:id/srp/verify
     *
     * Body: { challengeId, M1: base64url }
     *
     * Returns 200 { M2, record } on success. The returned record contains
     * everything the client needs to decrypt (chunks, kdfSalt for password
     * mode, recipient for pubkey mode) but the verifier is stripped.
     *
     * The SRP challenge state is consumed on every call regardless of
     * outcome, so wrong-M1 retries require a fresh /srp/init.
     */
    fastify.post<{ Params: { paste_id: string } }>(
        '/:paste_id/srp/verify',
        {
            // SRP verify carries a 32-byte M1 hash (43 base64url chars) and a
            // 16-byte challengeId. 4 KiB is generous.
            bodyLimit: 4096,
            // Same (IP, paste_id) keying as /srp/init.
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_SRP_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                          keyGenerator: (req: FastifyRequest) => {
                              const params = req.params as { paste_id?: string };
                              return `${req.ip}|${params?.paste_id ?? ''}`;
                          },
                      },
                  }
                : undefined,
            schema: {
                summary: 'Complete the SRP-6a handshake and receive ciphertext.',
                description:
                    'Submit M1 = client proof. On success the server returns M2 (server proof) and the encrypted record (sans verifier).',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            if (!isValidPasteIdShape(paste_id)) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Paste not found.' });
            }
            const bodyJson = parseJsonBody(request.body) as {
                challengeId?: unknown;
                M1?: unknown;
            };
            if (!bodyJson) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Body must be JSON.' });
            }

            const challengeId = bodyJson.challengeId;
            const M1_b64 = bodyJson.M1;
            if (typeof challengeId !== 'string' || typeof M1_b64 !== 'string') {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Missing challengeId or M1.' });
            }

            const challengeKey = `srp:${challengeId}`;
            const challengeStr = await redis.get(challengeKey);
            if (challengeStr !== null) {
                await redis.del(challengeKey);
            }
            if (challengeStr === null) {
                return reply
                    .code(401)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'SRP challenge expired or unknown.' });
            }

            let challenge: SrpChallengeState;
            try {
                challenge = JSON.parse(challengeStr) as SrpChallengeState;
            } catch {
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }

            if (challenge.paste_id !== paste_id) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Challenge does not match paste.' });
            }

            const stored = await redis.get(paste_id);
            if (stored === null) {
                return reply
                    .code(404)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Paste not found.' });
            }

            const parsed = tryParseStored(stored);
            if (
                parsed === null ||
                !isEncryptedRecord(parsed) ||
                !parsed.srp
            ) {
                return reply
                    .code(400)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Paste does not support SRP.' });
            }

            const verifier = bytesToBigInt(b64uDecode(parsed.srp.verifier));
            const A = bytesToBigInt(b64uDecode(challenge.A));
            const b = bytesToBigInt(b64uDecode(challenge.b));
            const B = bytesToBigInt(b64uDecode(challenge.B));

            let M2: Buffer;
            try {
                const result = srpServerVerify({
                    A,
                    b,
                    B,
                    verifier,
                    salt: b64uDecode(parsed.srp.salt),
                    M1: b64uDecode(M1_b64),
                });
                M2 = result.M2;
            } catch {
                return reply
                    .code(401)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'SRP authentication failed.' });
            }

            // Strip the verifier from the returned record so the client never
            // gets a copy. Keep everything else (chunks, kdfSalt, argon2,
            // recipient if any) so the client can derive enc_key and decrypt.
            const sanitized: EncryptedRecord = {
                ...parsed,
                srp: {
                    group: parsed.srp.group,
                    salt: parsed.srp.salt,
                    verifier: '',
                },
            };

            return reply
                .code(200)
                .type(JSON_CONTENT_TYPE)
                .send({
                    M2: b64uEncode(M2),
                    record: sanitized,
                });
        },
    );

    fastify.get<{ Params: { paste_id: string } }>(
        '/:paste_id',
        {
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_GET_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Get the paste content by ID.',
                description: 'Get the paste content by ID.',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
                response: {
                    200: {
                        type: 'string',
                        description: 'HTML page with paste content',
                    },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            if (!isValidPasteIdShape(paste_id)) {
                const html = renderTemplate('404.html');
                return reply
                    .code(404)
                    .type(HTML_CONTENT_TYPE)
                    .send(html);
            }

            const [pasteContent, pasteTtl] = await Promise.all([
                redis.get(paste_id),
                redis.ttl(paste_id),
            ]);

            if (pasteContent === null) {
                const html = renderTemplate('404.html');
                return reply
                    .code(404)
                    .type(HTML_CONTENT_TYPE)
                    .send(html);
            }

            const parsed = tryParseStored(pasteContent);
            if (parsed === null) {
                request.log.error(
                    { paste_id },
                    'failed to parse paste content from redis',
                );
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }

            if (isEncryptedRecord(parsed)) {
                const valid = revalidateEncryptedRecord(parsed);
                if (valid === null) {
                    request.log.error(
                        { paste_id },
                        'stored encrypted record failed re-validation',
                    );
                    return reply
                        .code(500)
                        .type(JSON_CONTENT_TYPE)
                        .send({ detail: 'Internal Server Error' });
                }
                const html = renderTemplate('paste-encrypted.html', {
                    paste_id,
                    paste_expiry: pasteTtl,
                    app_domain: Config.APP_DOMAIN,
                    needs_password: valid.mode === 'password',
                    once: valid.once,
                    is_pubkey: valid.mode === 'pubkey',
                    max_accesses: valid.maxAccesses ?? 0,
                });
                return reply.code(200).type(HTML_CONTENT_TYPE).send(html);
            }

            const v1 = parsed as LegacyPlaintext;
            const pasteBody = typeof v1.body === 'string' ? v1.body : '';

            const shouldBurnOnce = v1.once === true;
            const cap = typeof v1.maxAccesses === 'number'
                && Number.isInteger(v1.maxAccesses)
                && v1.maxAccesses >= 1
                    ? v1.maxAccesses
                    : 0;
            if (!shouldBurnOnce && cap > 0) {
                const verdict = await reservePlaintextAccessSlot(
                    redis, paste_id, cap, pasteTtl,
                );
                if (verdict.kind === 'over') {
                    const html404 = renderTemplate('404.html');
                    return reply
                        .code(404)
                        .type(HTML_CONTENT_TYPE)
                        .send(html404);
                }
                if (verdict.kind === 'last') {
                    await redis.del(paste_id);
                }
            } else if (shouldBurnOnce) {
                await redis.del(paste_id);
            }

            const html = renderTemplate('paste.html', {
                paste_id,
                paste_body: pasteBody,
                paste_expiry: pasteTtl,
                app_domain: Config.APP_DOMAIN,
            });

            return reply.code(200).type(HTML_CONTENT_TYPE).send(html);
        },
    );

    fastify.post<{ Params: { paste_id: string } }>(
        '/:paste_id/burn',
        {
            // Burn takes no body; reject anything beyond a small ceiling.
            bodyLimit: 1024,
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_BURN_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Burn (delete) a paste by ID.',
                description:
                    'Delete a paste after the client has successfully decrypted it. Idempotent: returns 204 whether or not the paste existed.',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
                response: {
                    204: { type: 'null', description: 'Burned' },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            if (!isValidPasteIdShape(paste_id)) {
                return reply.code(204).send();
            }
            await redis.del(paste_id);
            return reply.code(204).send();
        },
    );

    /**
     * POST /:id/access
     *
     * Encrypted-paste access counter. Called by the client after a successful
     * decrypt when the record carries a `maxAccesses` field. The server
     * atomically increments the counter; once the cap is reached the paste
     * is deleted.
     *
     * For plaintext pastes the counter is server-driven on the read path so
     * this endpoint is a no-op (returns 204). Idempotent — retrying a
     * dropped network response will never accidentally re-burn a paste.
     */
    fastify.post<{ Params: { paste_id: string } }>(
        '/:paste_id/access',
        {
            bodyLimit: 1024,
            config: Config.RATE_LIMIT_ENABLED
                ? {
                      rateLimit: {
                          max: Config.RATE_LIMIT_ACCESS_MAX,
                          timeWindow: Config.RATE_LIMIT_WINDOW_MS,
                      },
                  }
                : undefined,
            schema: {
                summary: 'Bump the access counter for a paste.',
                description:
                    'For encrypted pastes with `maxAccesses` set: atomically increments the counter; deletes the paste on the call that reaches the cap. Returns { remaining: int, expired: bool }.',
                params: {
                    type: 'object',
                    required: ['paste_id'],
                    properties: { paste_id: { type: 'string' } },
                },
            },
        },
        async (request, reply) => {
            const { paste_id } = request.params;
            if (!isValidPasteIdShape(paste_id)) {
                return reply.code(404).type(JSON_CONTENT_TYPE).send({ detail: 'Paste not found.' });
            }
            const stored = await redis.get(paste_id);
            if (stored === null) {
                return reply
                    .code(200)
                    .type(JSON_CONTENT_TYPE)
                    .send({ remaining: 0, expired: true });
            }
            const parsed = tryParseStored(stored);
            if (parsed === null) {
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Internal Server Error' });
            }
            // Plaintext: server-side counter; no-op here.
            if (!isEncryptedRecord(parsed)) {
                return reply
                    .code(200)
                    .type(JSON_CONTENT_TYPE)
                    .send({ remaining: 0, expired: false, applies: false });
            }
            const cap = parsed.maxAccesses;
            if (!cap || cap < 1) {
                return reply
                    .code(200)
                    .type(JSON_CONTENT_TYPE)
                    .send({ remaining: 0, expired: false, applies: false });
            }
            const counterKey = `acc:${paste_id}`;
            try {
                const used = await redis.incr(counterKey);
                if (used === 1) {
                    // Tie counter TTL to the paste TTL so it cleans up itself.
                    const ttl = await redis.ttl(paste_id);
                    if (ttl > 0) await redis.expire(counterKey, ttl);
                }
                if (used >= cap) {
                    await redis.del(paste_id);
                    await redis.del(counterKey);
                    return reply
                        .code(200)
                        .type(JSON_CONTENT_TYPE)
                        .send({ remaining: 0, expired: true });
                }
                return reply
                    .code(200)
                    .type(JSON_CONTENT_TYPE)
                    .send({ remaining: cap - used, expired: false });
            } catch (err) {
                request.log.error({ err, paste_id }, 'access counter Redis error');
                return reply
                    .code(500)
                    .type(JSON_CONTENT_TYPE)
                    .send({ detail: 'Could not advance counter.' });
            }
        },
    );

    return fastify;
}

function parseJsonBody(body: unknown): Record<string, unknown> | null {
    if (Buffer.isBuffer(body)) {
        try {
            const parsed = JSON.parse(body.toString('utf8'));
            return typeof parsed === 'object' && parsed !== null
                ? (parsed as Record<string, unknown>)
                : null;
        } catch {
            return null;
        }
    }
    if (typeof body === 'object' && body !== null) {
        return body as Record<string, unknown>;
    }
    return null;
}

