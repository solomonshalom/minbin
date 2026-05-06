// Vercel serverless entrypoint.
// Boots Fastify on the first request, then forwards each request to the
// underlying Node http.Server through `app.server.emit('request', ...)`.

import Redis from 'ioredis';

import { createApp } from '../dist/app.js';

const REDIS_URL = process.env.REDIS_URL || process.env.KV_URL;

let appPromise = null;

async function init() {
    if (!REDIS_URL) {
        throw new Error(
            'REDIS_URL (or KV_URL) is not set. Add a Vercel KV / Upstash Redis integration or set REDIS_URL manually.',
        );
    }

    const redis = new Redis(REDIS_URL, {
        maxRetriesPerRequest: 3,
        connectTimeout: 10_000,
        commandTimeout: 10_000,
        lazyConnect: false,
    });

    const app = await createApp({ redis, logger: false });
    await app.ready();
    return app;
}

export default async function handler(req, res) {
    if (!appPromise) {
        appPromise = init().catch((err) => {
            // surface the error to the client and let the next request retry init.
            appPromise = null;
            throw err;
        });
    }

    try {
        const app = await appPromise;
        app.server.emit('request', req, res);
    } catch (err) {
        const message = err && err.message ? err.message : 'Internal Server Error';
        res.statusCode = 500;
        res.setHeader('content-type', 'application/json; charset=utf-8');
        res.end(JSON.stringify({ detail: message }));
    }
}
