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
    MAX_PASTE_SIZE: envInt('MAX_PASTE_SIZE', 1024 * 1024 * 5),
} as const;
