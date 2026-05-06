/**
 * src/server.ts
 *
 * Entry point: wires up redis, builds the app, listens on the configured port,
 * and handles graceful shutdown signals.
 */

import { createApp } from './app.js';
import { getRedisClient } from './utils/db.js';

const port = (() => {
    const v = process.env.PORT;
    if (v === undefined || v === '') return 8000;
    const n = parseInt(v, 10);
    return Number.isNaN(n) ? 8000 : n;
})();
const host = process.env.HOST ?? '0.0.0.0';

const redis = getRedisClient();
const app = await createApp({ redis });

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');
    try {
        await app.close();
    } catch (err) {
        app.log.error({ err }, 'error while closing fastify');
    }
    try {
        await redis.quit();
    } catch (err) {
        app.log.error({ err }, 'error while closing redis');
        try {
            redis.disconnect();
        } catch {
            // ignore
        }
    }
    process.exit(0);
}

process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
});
process.on('SIGINT', () => {
    void shutdown('SIGINT');
});
process.on('uncaughtException', (err: Error) => {
    app.log.error({ err }, 'uncaught exception');
});
process.on('unhandledRejection', (reason: unknown) => {
    app.log.error({ reason }, 'unhandled rejection');
});

try {
    await app.listen({ port, host });
} catch (err) {
    app.log.error({ err }, 'failed to start server');
    process.exit(1);
}
