// End-to-end test of the minbin TypeScript backend using Fastify's `inject`
// API and `ioredis-mock` -- no real Redis or HTTP socket needed.
import RedisMock from 'ioredis-mock';

process.env.LOG_LEVEL = 'silent';
process.env.APP_DOMAIN = 'minb.in';
process.env.PASTE_EXPIRY = '60';
process.env.MAX_PASTE_SIZE = String(1024 * 1024 * 5);
process.env.NODE_ENV = 'test';

const { createApp } = await import('../dist/app.js');

const redis = new RedisMock();
const app = await createApp({ redis, logger: false });
await app.ready();

let passed = 0;
let failed = 0;
function check(label, cond, info) {
    if (cond) {
        passed++;
        console.log(`  PASS  ${label}`);
    } else {
        failed++;
        console.log(`  FAIL  ${label}${info ? ` -- ${info}` : ''}`);
    }
}

async function inject(opts) {
    return app.inject(opts);
}

console.log('\n== GET / ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    check('status 200', r.statusCode === 200);
    check('text/html', /^text\/html/.test(r.headers['content-type']));
    check('html body', /<!DOCTYPE html>/i.test(r.body));
    check('contains paste-content textarea', r.body.includes('id="paste-content"'));
    check('contains main-form', r.body.includes('id="main-form"'));
}

console.log('\n== POST / (default returns full URL) ==');
let pasteId;
{
    const r = await inject({
        method: 'POST',
        url: '/',
        headers: { 'content-type': 'text/plain' },
        payload: 'hello world',
    });
    check('status 201', r.statusCode === 201);
    check('text/plain', /^text\/plain/.test(r.headers['content-type']));
    check('returns minb.in/<id>', r.body.startsWith('minb.in/'));
    pasteId = r.body.split('/')[1];
    check('id is 4 hex chars', /^[0-9a-f]{4}$/.test(pasteId), pasteId);
}

console.log('\n== POST /?relative=true (returns id only) ==');
let relativeId;
{
    const r = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'relative paste',
    });
    check('status 201', r.statusCode === 201);
    relativeId = r.body;
    check('id is 4 hex chars', /^[0-9a-f]{4}$/.test(relativeId), relativeId);
    check('content-type text/plain', /^text\/plain/.test(r.headers['content-type']));
}

console.log('\n== POST /?relative=false ==');
{
    const r = await inject({
        method: 'POST',
        url: '/?relative=false',
        headers: { 'content-type': 'text/plain' },
        payload: 'falsey relative',
    });
    check('status 201', r.statusCode === 201);
    check('returns full URL', r.body.startsWith('minb.in/'));
}

console.log('\n== POST / empty body returns 400 ==');
{
    const r = await inject({
        method: 'POST',
        url: '/',
        headers: { 'content-type': 'text/plain' },
        payload: '',
    });
    check('status 400', r.statusCode === 400, `got ${r.statusCode}`);
    check('error message', r.body.includes('Paste body is empty'));
    check('text/plain', /^text\/plain/.test(r.headers['content-type']));
}

console.log('\n== POST / no body at all returns 400 ==');
{
    const r = await inject({ method: 'POST', url: '/' });
    check('status 400', r.statusCode === 400, `got ${r.statusCode}`);
}

console.log('\n== POST / oversize body returns 400 ==');
{
    const big = Buffer.alloc(1024 * 1024 * 5 + 100, 'a');
    const r = await inject({
        method: 'POST',
        url: '/',
        headers: { 'content-type': 'application/octet-stream' },
        payload: big,
    });
    check('status 400', r.statusCode === 400, `got ${r.statusCode}`);
    check('error mentions size', r.body.includes('exceeds maximum size'));
}

console.log('\n== POST / max size at exact limit succeeds ==');
{
    const exact = Buffer.alloc(1024 * 1024 * 5, 'a');
    const r = await inject({
        method: 'POST',
        url: '/',
        headers: { 'content-type': 'application/octet-stream' },
        payload: exact,
    });
    check('status 201 at exact limit', r.statusCode === 201, `got ${r.statusCode}`);
}

console.log('\n== GET /<id> (HTML view) ==');
{
    const r = await inject({ method: 'GET', url: '/' + pasteId });
    check('status 200', r.statusCode === 200);
    check('text/html', /^text\/html/.test(r.headers['content-type']));
    check('contains paste body in textarea', r.body.includes('hello world'));
    check('contains expiry timer', r.body.includes('expires in'));
    check('contains share button', r.body.includes('share'));
    check('paste_id rendered in raw href', r.body.includes('/raw/' + pasteId));
}

console.log('\n== GET /raw/<id> ==');
{
    const r = await inject({ method: 'GET', url: '/raw/' + pasteId });
    check('status 200', r.statusCode === 200);
    check('text/plain', /^text\/plain/.test(r.headers['content-type']));
    check('exact body returned', r.body === 'hello world', r.body);
}

console.log('\n== Persistent paste readable multiple times ==');
{
    const r1 = await inject({ method: 'GET', url: '/raw/' + pasteId });
    const r2 = await inject({ method: 'GET', url: '/raw/' + pasteId });
    check('first 200', r1.statusCode === 200);
    check('second 200', r2.statusCode === 200);
    check('body unchanged', r1.body === 'hello world' && r2.body === 'hello world');
}

console.log('\n== GET /<unknown-id> -> 404.html ==');
{
    const r = await inject({ method: 'GET', url: '/zzzz' });
    check('status 404', r.statusCode === 404);
    check('text/html', /^text\/html/.test(r.headers['content-type']));
    check('404 page rendered', r.body.includes('404'));
    check('contains 404 description', r.body.includes('does not exist or has expired'));
}

console.log('\n== GET /raw/<unknown-id> -> JSON 404 ==');
{
    const r = await inject({ method: 'GET', url: '/raw/zzzz' });
    check('status 404', r.statusCode === 404);
    check('json content-type', /^application\/json/.test(r.headers['content-type']));
    const j = JSON.parse(r.body);
    check('detail message', j.detail === "Paste with ID 'zzzz' not found.", JSON.stringify(j));
}

console.log('\n== POST /?once=true then GET twice (one-time-view) ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?once=true&relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'self-destruct please',
    });
    check('create status 201', create.statusCode === 201);
    const id = create.body;
    const first = await inject({ method: 'GET', url: '/raw/' + id });
    check('first read 200', first.statusCode === 200);
    check('first text matches', first.body === 'self-destruct please');
    const second = await inject({ method: 'GET', url: '/raw/' + id });
    check('second read 404', second.statusCode === 404, `got ${second.statusCode}`);
}

console.log('\n== POST /?once (no value) is also one-time ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?once&relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'no value once',
    });
    const id = create.body;
    const r1 = await inject({ method: 'GET', url: '/raw/' + id });
    check('first read 200', r1.statusCode === 200);
    const r2 = await inject({ method: 'GET', url: '/raw/' + id });
    check('second read 404', r2.statusCode === 404);
}

console.log('\n== POST /?once=false STILL one-time (matches python presence semantics) ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?once=false&relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'once-false',
    });
    const id = create.body;
    const r1 = await inject({ method: 'GET', url: '/raw/' + id });
    check('first 200', r1.statusCode === 200);
    const r2 = await inject({ method: 'GET', url: '/raw/' + id });
    check('second 404 (presence-only flag like python)', r2.statusCode === 404, `got ${r2.statusCode}`);
}

console.log('\n== once-paste also self-destructs through the HTML route ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?once=true&relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'html one-time',
    });
    const id = create.body;
    const r1 = await inject({ method: 'GET', url: '/' + id });
    check('first html 200', r1.statusCode === 200);
    check('html contains body', r1.body.includes('html one-time'));
    const r2 = await inject({ method: 'GET', url: '/' + id });
    check('second html 404', r2.statusCode === 404);
}

console.log('\n== UTF-8 round trip ==');
{
    const body = 'こんにちは 🦊 hello — 日本語テスト';
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain; charset=utf-8' },
        payload: Buffer.from(body, 'utf8'),
    });
    const id = create.body;
    const r = await inject({ method: 'GET', url: '/raw/' + id });
    check('round-trip 200', r.statusCode === 200);
    check('utf-8 body intact', r.body === body, `${r.body} vs ${body}`);
}

console.log('\n== HTML escaping in template (XSS protection) ==');
{
    const xss = '<script>alert(1)</script>';
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: xss,
    });
    const id = create.body;
    const html = await inject({ method: 'GET', url: '/' + id });
    check('html 200', html.statusCode === 200);
    check('script tag escaped (no raw)', !html.body.includes('<script>alert(1)</script>'));
    check('contains escaped form', html.body.includes('&lt;script&gt;'));
}

console.log('\n== Body containing newlines preserved ==');
{
    const text = 'line1\nline2\r\nline3\n\nfinal';
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: text,
    });
    const id = create.body;
    const r = await inject({ method: 'GET', url: '/raw/' + id });
    check('round trip preserves bytes', r.body === text, JSON.stringify(r.body));
}

console.log('\n== TTL is reflected in paste.html ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'check ttl',
    });
    const id = create.body;
    const r = await inject({ method: 'GET', url: '/' + id });
    check('html 200', r.statusCode === 200);
    const m = r.body.match(/parseInt\("(-?\d+)"\)/);
    check('expiry parsed', m !== null);
    if (m) {
        const ttl = parseInt(m[1], 10);
        check('ttl positive and <= 3600', ttl > 0 && ttl <= 3600, `ttl=${ttl}`);
    }
}

console.log('\n== GET /openapi (OpenAPI spec) ==');
{
    const r = await inject({ method: 'GET', url: '/openapi' });
    check('status 200', r.statusCode === 200);
    check('json content-type', /^application\/json/.test(r.headers['content-type']));
    const spec = JSON.parse(r.body);
    check('openapi field', spec.openapi !== undefined);
    check('title minbin', spec.info && spec.info.title === 'minbin');
    check('version 0.1.2', spec.info && spec.info.version === '0.1.2');
    check('has POST /', spec.paths && spec.paths['/'] && spec.paths['/'].post);
    check('has GET /raw/{paste_id}', spec.paths && spec.paths['/raw/{paste_id}']);
    check('has GET /{paste_id}', spec.paths && spec.paths['/{paste_id}']);
}

console.log('\n== Static assets served ==');
{
    const r = await inject({ method: 'GET', url: '/assets/css/styles.css' });
    check('status 200', r.statusCode === 200);
    check('content-type css', /^text\/css/.test(r.headers['content-type']));
}

console.log('\n== Static asset traversal blocked ==');
{
    const r = await inject({ method: 'GET', url: '/assets/../../etc/passwd' });
    check('not 200', r.statusCode !== 200, `got ${r.statusCode}`);
}

console.log('\n== Unmatched route returns generic 404 JSON ==');
{
    const r = await inject({ method: 'GET', url: '/foo/bar/baz' });
    check('status 404', r.statusCode === 404);
    check('json detail Not Found', JSON.parse(r.body).detail === 'Not Found');
}

console.log('\n== Trailing slash on /foo/ no match ==');
{
    const r = await inject({ method: 'GET', url: '/foo/' });
    check('status 404 for /foo/', r.statusCode === 404, `got ${r.statusCode}`);
}

console.log('\n== Method-not-allowed: PUT / ==');
{
    const r = await inject({ method: 'PUT', url: '/' });
    check('PUT not allowed', r.statusCode === 404 || r.statusCode === 405, `got ${r.statusCode}`);
}

console.log('\n== ID generation uniqueness sample ==');
{
    const ids = new Set();
    for (let i = 0; i < 50; i++) {
        const r = await inject({
            method: 'POST',
            url: '/?relative=true',
            headers: { 'content-type': 'text/plain' },
            payload: 'collision-test-' + i,
        });
        ids.add(r.body);
    }
    check('IDs unique across 50 (best-effort)', ids.size === 50, `unique=${ids.size}`);
    check('All ids are 4-hex format', [...ids].every((id) => /^[0-9a-f]{4}$/.test(id)));
}

console.log('\n== Direct-from-redis: key has TTL set ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'ttl-check',
    });
    const id = create.body;
    const ttl = await redis.ttl(id);
    check('ttl > 0', ttl > 0, `ttl=${ttl}`);
    check('ttl <= 3600', ttl <= 3600, `ttl=${ttl}`);
    const raw = await redis.get(id);
    const obj = JSON.parse(raw);
    check('stored as json', typeof obj === 'object');
    check('body field correct', obj.body === 'ttl-check');
    check('once flag is false', obj.once === false);
}

console.log('\n== Once flag stored as true ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?once=true&relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'once-flag-check',
    });
    const id = create.body;
    const raw = await redis.get(id);
    const obj = JSON.parse(raw);
    check('once is true', obj.once === true);
}

await app.close();
await redis.quit();

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed === 0 ? 0 : 1);
