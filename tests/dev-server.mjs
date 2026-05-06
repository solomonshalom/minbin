// Local dev harness: runs the built app with ioredis-mock so it works without
// a real Redis instance. Pastes live in-process and disappear on restart.
//
//   npm run build && node tests/dev-server.mjs
//
// or:
//   PORT=3000 LOG_LEVEL=debug node tests/dev-server.mjs
import RedisMock from 'ioredis-mock';

const port = parseInt(process.env.PORT ?? '8765', 10);

process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? 'info';
process.env.APP_DOMAIN = process.env.APP_DOMAIN ?? `127.0.0.1:${port}`;
process.env.PASTE_EXPIRY = process.env.PASTE_EXPIRY ?? '60';
process.env.MAX_PASTE_SIZE = process.env.MAX_PASTE_SIZE ?? String(1024 * 1024 * 5);
// Render templates fresh on every request so edits are reflected without restart.
process.env.NODE_ENV = process.env.NODE_ENV ?? 'development';

const { createApp } = await import('../dist/app.js');
const redis = new RedisMock();
const app = await createApp({ redis });

await app.listen({ port, host: '127.0.0.1' });
console.log(`\n  minbin (mock-backed) → http://127.0.0.1:${port}\n`);
