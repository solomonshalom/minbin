/**
 * src/utils/db.ts
 *
 * Utility functions for database interactions.
 */

import { Redis, type RedisOptions } from 'ioredis';

import { Config } from '../config.js';

const SHARED_OPTIONS: RedisOptions = {
    retryStrategy: (times: number) => Math.min(times * 200, 2000),
    maxRetriesPerRequest: 3,
    connectTimeout: 10_000,
    commandTimeout: 10_000,
};

/**
 * Get a Redis client instance.
 *
 * Prefers REDIS_URL / KV_URL when set (Vercel KV, Upstash, managed Redis).
 * Falls back to discrete DB_HOST / DB_PORT / DB_USER / DB_PASS fields.
 */
export function getRedisClient(): Redis {
    if (Config.REDIS_URL) {
        return new Redis(Config.REDIS_URL, SHARED_OPTIONS);
    }

    const opts: RedisOptions = {
        ...SHARED_OPTIONS,
        host: Config.DB_HOST,
        port: Config.DB_PORT,
    };

    if (Config.DB_USER) {
        opts.username = Config.DB_USER;
        if (Config.DB_PASS !== undefined) {
            opts.password = Config.DB_PASS;
        }
    }

    return new Redis(opts);
}
