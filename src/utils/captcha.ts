/**
 * src/utils/captcha.ts
 *
 * Stateless hashcash-style proof-of-work captcha.
 *
 * Why PoW and not reCAPTCHA / hCaptcha / Turnstile?
 *   - No third-party JS on the page (CSP stays `script-src 'self'`).
 *   - Zero-knowledge of the user (no IPs leaked to a SaaS, no fingerprint).
 *   - Works for curl users with a tiny shell helper (documented in README).
 *
 * Mechanism:
 *   - Server hands out a fresh challenge: 16 random bytes + a millisecond
 *     timestamp + an HMAC tag binding the two with a server-side secret.
 *     The whole thing is base64url-encoded into a single token.
 *   - Client finds a 64-bit nonce such that
 *         SHA-256(challenge || be64(nonce))
 *     starts with at least `bits` zero bits. (16 bits ≈ 50 ms on a server,
 *     ~300 ms on a phone; 20 bits ≈ 1 s / 5 s.)
 *   - Client submits the original token, the nonce, and the body.
 *   - Server verifies the HMAC, the freshness, the work, and atomically
 *     consumes the challenge ID against a Redis dedup set so the same
 *     solved challenge can't be replayed.
 *
 * The HMAC keeps it stateless on the issue path (no Redis hit on /captcha,
 * fast). The dedup set on verify is the only Redis op for an upload, on top
 * of the existing rate-limit counters.
 */

import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';

import type { Redis } from 'ioredis';

const TOKEN_VERSION = 1;
// 16 bytes random + 8 bytes ms timestamp + 32 bytes HMAC = 56 bytes total.
const RAND_LEN = 16;
const TS_LEN = 8;
const MAC_LEN = 32;
const TOKEN_LEN = RAND_LEN + TS_LEN + MAC_LEN;

/**
 * Auto-generate a captcha secret if one wasn't supplied via env. Single-host
 * deployments are fine; multi-host deployments (e.g. multi-region Vercel)
 * should set CAPTCHA_SECRET so all instances accept each other's tokens.
 */
let runtimeSecret: Buffer | null = null;
export function getCaptchaSecret(envSecret: string | undefined): Buffer {
    if (envSecret && envSecret.length > 0) {
        // Hash to 32 bytes regardless of input length.
        return createHash('sha256').update(envSecret, 'utf8').digest();
    }
    if (!runtimeSecret) {
        runtimeSecret = randomBytes(32);
    }
    return runtimeSecret;
}

export interface CaptchaChallenge {
    token: string; // base64url, opaque to the client
    bits: number;
    expiresAt: number; // unix ms
}

export function issueChallenge(
    secret: Buffer,
    bits: number,
    ttlSeconds: number,
): CaptchaChallenge {
    const now = Date.now();
    const tsBuf = Buffer.alloc(TS_LEN);
    tsBuf.writeBigUInt64BE(BigInt(now));
    const rand = randomBytes(RAND_LEN);
    const body = Buffer.concat([Buffer.from([TOKEN_VERSION]), tsBuf, rand]);
    const mac = createHmac('sha256', secret).update(body).digest();
    const token = Buffer.concat([body, mac]).toString('base64url');
    return {
        token,
        bits,
        expiresAt: now + ttlSeconds * 1000,
    };
}

export interface CaptchaVerifyOptions {
    secret: Buffer;
    bits: number;
    ttlSeconds: number;
    redis: Redis;
}

export type CaptchaVerifyResult =
    | { ok: true }
    | { ok: false; reason: 'malformed' | 'bad_mac' | 'expired' | 'replay' | 'insufficient_work' };

function leadingZeroBits(buf: Buffer | Uint8Array, want: number): boolean {
    if (want <= 0) return true;
    let bitsLeft = want;
    for (let i = 0; i < buf.length && bitsLeft > 0; i++) {
        const byte = buf[i];
        if (bitsLeft >= 8) {
            if (byte !== 0) return false;
            bitsLeft -= 8;
        } else {
            const mask = 0xff << (8 - bitsLeft);
            if ((byte & mask) !== 0) return false;
            bitsLeft = 0;
        }
    }
    return bitsLeft === 0;
}

/**
 * Verify a (token, nonce) pair. Consumes the token's challenge ID against a
 * Redis dedup set so a single solved challenge cannot be replayed.
 *
 * Returns granular failure reasons so the caller can surface a useful error.
 * Verify is fully atomic w.r.t. replay: dedup is via SET NX; if the key
 * already exists, the call returns 'replay'.
 */
export async function verifyChallenge(
    token: string,
    nonceB64u: string,
    opts: CaptchaVerifyOptions,
): Promise<CaptchaVerifyResult> {
    let buf: Buffer;
    try {
        buf = Buffer.from(token, 'base64url');
    } catch {
        return { ok: false, reason: 'malformed' };
    }
    if (buf.length !== TOKEN_LEN + 1) return { ok: false, reason: 'malformed' };
    if (buf[0] !== TOKEN_VERSION) return { ok: false, reason: 'malformed' };

    const body = buf.subarray(0, TOKEN_LEN - MAC_LEN + 1);
    const presentedMac = buf.subarray(TOKEN_LEN - MAC_LEN + 1);
    const expectedMac = createHmac('sha256', opts.secret).update(body).digest();
    if (
        presentedMac.length !== expectedMac.length ||
        !timingSafeEqual(presentedMac, expectedMac)
    ) {
        return { ok: false, reason: 'bad_mac' };
    }

    const ts = Number(body.readBigUInt64BE(1));
    if (!Number.isFinite(ts) || ts <= 0) return { ok: false, reason: 'malformed' };
    const ageMs = Date.now() - ts;
    if (ageMs < -5000 || ageMs > opts.ttlSeconds * 1000) {
        return { ok: false, reason: 'expired' };
    }

    let nonceBytes: Buffer;
    try {
        nonceBytes = Buffer.from(nonceB64u, 'base64url');
    } catch {
        return { ok: false, reason: 'malformed' };
    }
    // Cap nonce size: we only encode 64-bit nonces, never more. A pathological
    // client offering a 1MB nonce would let the attacker stretch SHA-256
    // hashes server-side. Tight bound = no DoS lever.
    if (nonceBytes.length === 0 || nonceBytes.length > 16) {
        return { ok: false, reason: 'malformed' };
    }

    // Replay protection: rand portion of the token uniquely identifies it.
    const rand = body.subarray(1 + TS_LEN, 1 + TS_LEN + RAND_LEN);
    const dedupKey = `cap:${rand.toString('hex')}`;
    // SET NX with TTL = challenge lifetime. If the key exists, this is a replay.
    const setResult = await opts.redis.set(
        dedupKey,
        '1',
        'EX',
        opts.ttlSeconds + 60,
        'NX',
    );
    if (setResult !== 'OK') return { ok: false, reason: 'replay' };

    // Check the work proof itself.
    const challengeBytes = Buffer.concat([rand]);
    const digest = createHash('sha256')
        .update(challengeBytes)
        .update(nonceBytes)
        .digest();
    if (!leadingZeroBits(digest, opts.bits)) {
        // Roll back the dedup so a legitimate retry with a better nonce works
        // and we don't lock out a slow phone.
        await opts.redis.del(dedupKey);
        return { ok: false, reason: 'insufficient_work' };
    }

    return { ok: true };
}

/**
 * Server-side computation of a valid nonce — used by tests + curl helpers.
 * For production loads this runs in the browser.
 */
export function solveChallenge(token: string, bits: number): string {
    const buf = Buffer.from(token, 'base64url');
    if (buf.length !== TOKEN_LEN + 1) throw new Error('malformed token');
    const rand = buf.subarray(1 + TS_LEN, 1 + TS_LEN + RAND_LEN);
    const nonce = Buffer.alloc(8);
    let counter = 0n;
    while (true) {
        nonce.writeBigUInt64BE(counter);
        const digest = createHash('sha256').update(rand).update(nonce).digest();
        if (leadingZeroBits(digest, bits)) {
            return nonce.toString('base64url');
        }
        counter += 1n;
        if (counter > 0xffff_ffff_ffff_ffffn) {
            throw new Error('PoW search exhausted');
        }
    }
}
