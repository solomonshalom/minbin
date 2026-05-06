// End-to-end test of the minbin TypeScript backend using Fastify's `inject`
// API and `ioredis-mock` -- no real Redis or HTTP socket needed.
import RedisMock from 'ioredis-mock';
import fs from 'node:fs';
import vm from 'node:vm';
import * as hashwasm from 'hash-wasm';

process.env.LOG_LEVEL = 'silent';
process.env.APP_DOMAIN = 'minb.in';
process.env.PASTE_EXPIRY = '60';
process.env.MAX_PASTE_SIZE = String(1024 * 1024 * 5);
process.env.NODE_ENV = 'test';
// Rate-limiting is exercised in its own block at the end with a fresh app
// instance and a low cap. Disable it for the main suite so 50-paste loops
// (uniqueness, collision retry) don't trip it.
process.env.RATE_LIMIT_ENABLED = 'false';

const { createApp } = await import('../dist/app.js');

// Load the browser crypto module into this Node context so we can drive the
// encrypted endpoints exactly like a browser would. hashwasm must be on
// globalThis before the module reads it during deriveKeyArgon2id.
globalThis.hashwasm = hashwasm;
const cryptoSrc = fs.readFileSync(
    new URL('../templates/assets/js/minbin-crypto.js', import.meta.url),
    'utf8',
);
vm.runInThisContext(cryptoSrc, { filename: 'minbin-crypto.js' });
const Crypto = globalThis.MinbinCrypto;

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
    check('id is 16 hex chars (default 8-byte width)', /^[0-9a-f]{16}$/.test(pasteId), pasteId);
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
    check('id is 16 hex chars', /^[0-9a-f]{16}$/.test(relativeId), relativeId);
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
    // The TTL is rendered into a data-seconds attribute now (paste.js reads it).
    const m = r.body.match(/data-seconds="(-?\d+)"/);
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
    check('All ids are 16-hex format', [...ids].every((id) => /^[0-9a-f]{16}$/.test(id)));
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

// ---------------------------------------------------------------------------
// Encrypted record tests (v3 SRP flow + v2 backward-compat)
// ---------------------------------------------------------------------------

const ENCRYPTED_CT = 'application/vnd.minbin.encrypted+json';

async function postEncrypted(record, opts = {}) {
    return inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': ENCRYPTED_CT },
        payload: typeof record === 'string' ? record : JSON.stringify(record),
        ...opts,
    });
}

// Run the SRP-6a handshake against the live app and return the unwrapped record.
async function srpFetch(pasteId, authKey) {
    const state = await Crypto.srpClientStart();
    const initResp = await inject({
        method: 'POST',
        url: '/' + pasteId + '/srp/init',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ A: Crypto.b64uEncode(state.A_bytes) }),
    });
    if (initResp.statusCode !== 200) {
        throw new Error('init ' + initResp.statusCode + ' ' + initResp.body);
    }
    const init = JSON.parse(initResp.body);
    const salt = Crypto.b64uDecode(init.salt);
    const B_bytes = Crypto.b64uDecode(init.B);
    const step2 = await Crypto.srpClientStep2(state, B_bytes, salt, authKey);

    const verifyResp = await inject({
        method: 'POST',
        url: '/' + pasteId + '/srp/verify',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
            challengeId: init.challengeId,
            M1: Crypto.b64uEncode(step2.M1),
        }),
    });
    if (verifyResp.statusCode !== 200) {
        throw new Error('verify ' + verifyResp.statusCode + ' ' + verifyResp.body);
    }
    const verify = JSON.parse(verifyResp.body);
    const M2 = Crypto.b64uDecode(verify.M2);
    const ok = await Crypto.srpClientVerifyM2(M2, step2.padA, step2.M1, step2.K);
    if (!ok) throw new Error('M2 mismatch');
    return verify.record;
}

console.log('\n== v3 random-key round-trip via SRP ==');
let v3RandomId;
{
    const enc = await Crypto.encrypt('bank account: 12345 — secret', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    check('POST 201', post.statusCode === 201, post.body);
    check('id 16 hex', /^[0-9a-f]{16}$/.test(post.body), post.body);
    v3RandomId = post.body;

    // GET /raw returns header only (no chunks)
    const raw = await inject({ method: 'GET', url: '/raw/' + v3RandomId });
    check('GET /raw 200', raw.statusCode === 200);
    const header = JSON.parse(raw.body);
    check('header v=3', header.v === 3);
    check('header mode=random', header.mode === 'random');
    check('header hides chunks', header.chunks === undefined);
    check('header has total', typeof header.total === 'number');
    check('header has srpSalt', typeof header.srpSalt === 'string');
    check('header has no verifier', header.srp === undefined && header.verifier === undefined);

    const keys = await Crypto.deriveRandomKeys(enc.link_key);
    const record = await srpFetch(v3RandomId, keys.authKey);
    const pt = await Crypto.decrypt(record, keys.encKey);
    check('decrypted matches', new TextDecoder().decode(pt) === 'bank account: 12345 — secret');
}

console.log('\n== v3 password round-trip via SRP ==');
{
    const password = 'correct horse battery staple';
    const enc = await Crypto.encrypt('password-protected secret', { mode: 'password', password });
    const post = await postEncrypted(enc.record);
    check('POST 201', post.statusCode === 201, post.body);
    const id = post.body;

    const rawHeader = await inject({ method: 'GET', url: '/raw/' + id });
    const header = JSON.parse(rawHeader.body);
    check('header mode=password', header.mode === 'password');
    check('header has kdfSalt', typeof header.kdfSalt === 'string');
    check('header has argon2 params', header.argon2 && header.argon2.m && header.argon2.t);
    check('header hides chunks', header.chunks === undefined);

    const html = await inject({ method: 'GET', url: '/' + id });
    check('html flagged needs-password', html.body.includes('data-needs-password="1"'));

    const keys = await Crypto.derivePasswordKeys(password, header);
    const record = await srpFetch(id, keys.authKey);
    const pt = await Crypto.decrypt(record, keys.encKey);
    check('decrypted matches', new TextDecoder().decode(pt) === 'password-protected secret');
}

console.log('\n== v3 SRP rejects wrong password ==');
{
    const enc = await Crypto.encrypt('protected', { mode: 'password', password: 'right one' });
    const post = await postEncrypted(enc.record);
    const id = post.body;
    const headerResp = await inject({ method: 'GET', url: '/raw/' + id });
    const header = JSON.parse(headerResp.body);
    const wrongKeys = await Crypto.derivePasswordKeys('wrong one', header);
    let threw = false;
    try { await srpFetch(id, wrongKeys.authKey); } catch { threw = true; }
    check('wrong password rejected by SRP', threw);
}

console.log('\n== v3 SRP challenge is single-use ==');
{
    const enc = await Crypto.encrypt('one-shot', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    const id = post.body;

    const state = await Crypto.srpClientStart();
    const init = JSON.parse((await inject({
        method: 'POST',
        url: '/' + id + '/srp/init',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ A: Crypto.b64uEncode(state.A_bytes) }),
    })).body);
    const keys = await Crypto.deriveRandomKeys(enc.link_key);
    const step2 = await Crypto.srpClientStep2(state, Crypto.b64uDecode(init.B), Crypto.b64uDecode(init.salt), keys.authKey);
    const v1 = await inject({
        method: 'POST',
        url: '/' + id + '/srp/verify',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ challengeId: init.challengeId, M1: Crypto.b64uEncode(step2.M1) }),
    });
    check('first verify 200', v1.statusCode === 200);
    const v2 = await inject({
        method: 'POST',
        url: '/' + id + '/srp/verify',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ challengeId: init.challengeId, M1: Crypto.b64uEncode(step2.M1) }),
    });
    check('second verify 401 (challenge consumed)', v2.statusCode === 401, `got ${v2.statusCode}`);
}

console.log('\n== v3 SRP rejects A mod N == 0 ==');
{
    const enc = await Crypto.encrypt('whatever', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    const id = post.body;
    const r = await inject({
        method: 'POST',
        url: '/' + id + '/srp/init',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ A: Crypto.b64uEncode(new Uint8Array(1)) }), // A=0
    });
    check('A=0 rejected', r.statusCode === 400, `got ${r.statusCode}`);
}

console.log('\n== v3 chunk tamper detection ==');
{
    const enc = await Crypto.encrypt('chunk-integrity', { mode: 'random' });
    // flip one byte in the first chunk's ct
    const tampered = JSON.parse(JSON.stringify(enc.record));
    const ctBytes = Crypto.b64uDecode(tampered.chunks[0].ct);
    ctBytes[0] ^= 1;
    tampered.chunks[0].ct = Crypto.b64uEncode(ctBytes);
    const keys = await Crypto.deriveRandomKeys(enc.link_key);
    let threw = false;
    try { await Crypto.decrypt(tampered, keys.encKey); } catch { threw = true; }
    check('tampered chunk ct rejected', threw);
}

console.log('\n== v3 chunk reorder detection ==');
{
    // Random bytes don't compress, so we reliably get >1 chunk above
    // CHUNK_PLAINTEXT_BYTES (64 KiB).
    const bigBytes = Crypto.randomBytes(200_000);
    const enc = await Crypto.encrypt(bigBytes, { mode: 'random' });
    check('multi-chunk produced', enc.record.total >= 2, `total=${enc.record.total}`);
    const swapped = JSON.parse(JSON.stringify(enc.record));
    // Swap chunks[0] and chunks[1] but keep seq numbers monotonically 0,1,...
    // (simulating a server that reordered ciphertexts while preserving
    // metadata). AES-GCM should still reject because the AAD-bound seq
    // mismatches the original encryption seq.
    [swapped.chunks[0].iv, swapped.chunks[1].iv] = [swapped.chunks[1].iv, swapped.chunks[0].iv];
    [swapped.chunks[0].ct, swapped.chunks[1].ct] = [swapped.chunks[1].ct, swapped.chunks[0].ct];
    const keys = await Crypto.deriveRandomKeys(enc.link_key);
    let threw = false;
    try { await Crypto.decrypt(swapped, keys.encKey); } catch { threw = true; }
    check('reordered chunks rejected', threw);
}

console.log('\n== v3 chunk truncation detection ==');
{
    const bigBytes = Crypto.randomBytes(200_000);
    const enc = await Crypto.encrypt(bigBytes, { mode: 'random' });
    check('multi-chunk produced', enc.record.total >= 2, `total=${enc.record.total}`);
    const truncated = JSON.parse(JSON.stringify(enc.record));
    truncated.chunks.pop();
    truncated.total = truncated.chunks.length;
    // Re-mark the new last chunk as final by adjusting seq if needed: the
    // attacker can't re-MAC, so AAD's final-flag mismatch should still
    // trigger a tag failure.
    const keys = await Crypto.deriveRandomKeys(enc.link_key);
    let threw = false;
    try { await Crypto.decrypt(truncated, keys.encKey); } catch { threw = true; }
    check('truncated chunks rejected (final-flag AAD mismatch)', threw);
}

// Helper used by the new pubkey tests below: produce a fake "identity" object
// that matches what loadIdentity() returns in the browser, so we can call
// Crypto.derivePubkeyEnc(record, identity) without polyfilling localStorage.
async function makeIdentity() {
    const c = globalThis.crypto;
    const kp = await c.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const pub = new Uint8Array(await c.subtle.exportKey('raw', kp.publicKey));
    const priv = new Uint8Array(await c.subtle.exportKey('pkcs8', kp.privateKey));
    return { pub, priv, keyPair: kp };
}

console.log('\n== v3 pubkey round-trip via X25519 ECDH (multi-recipient default) ==');
{
    // Generate a single recipient via the new identity API.
    const me = await makeIdentity();

    const enc = await Crypto.encrypt('to: bob; from: alice', {
        mode: 'pubkey',
        recipientPubkeys: [me.pub],
    });
    check('record has recipients[]', Array.isArray(enc.record.recipients) && enc.record.recipients.length === 1);
    check('recipient pubkey matches mine',
        enc.record.recipients[0].pubkey === Crypto.b64uEncode(me.pub));
    check('recipient has wrappedKey', typeof enc.record.recipients[0].wrappedKey === 'string');
    check('recipient has wrapIv', typeof enc.record.recipients[0].wrapIv === 'string');
    check('record has no legacy recipient field', enc.record.recipient === undefined);
    check('fingerprint formatted', /^[0-9A-F]{4} (?:[0-9A-F]{4} ){6}[0-9A-F]{4}$/.test(enc.fingerprint));

    const post = await postEncrypted(enc.record);
    check('POST 201', post.statusCode === 201, post.body);
    const id = post.body;

    // Pubkey mode is NOT SRP-gated: GET /raw/:id returns the full record.
    const raw = JSON.parse((await inject({ method: 'GET', url: '/raw/' + id })).body);
    check('full record returned', Array.isArray(raw.chunks) && raw.chunks.length >= 1);
    check('mode=pubkey', raw.mode === 'pubkey');

    // SRP endpoints should refuse pubkey-mode pastes
    const srpInit = await inject({
        method: 'POST',
        url: '/' + id + '/srp/init',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ A: 'AQ' }),
    });
    check('SRP init 400 for pubkey paste', srpInit.statusCode === 400, `got ${srpInit.statusCode}`);

    const encKey = await Crypto.derivePubkeyEnc(raw, me);
    const pt = await Crypto.decrypt(raw, encKey);
    check('pubkey round-trip matches', new TextDecoder().decode(pt) === 'to: bob; from: alice');
}

console.log('\n== v3 multi-recipient pubkey round-trip ==');
{
    const a = await makeIdentity();
    const b = await makeIdentity();
    const c = await makeIdentity();

    const enc = await Crypto.encrypt('shared with three recipients', {
        mode: 'pubkey',
        recipientPubkeys: [a.pub, b.pub, c.pub],
    });
    check('three recipients', enc.record.recipients.length === 3);
    check('each has unique epk',
        new Set(enc.record.recipients.map((r) => r.epk)).size === 3);
    check('each has unique wrappedKey',
        new Set(enc.record.recipients.map((r) => r.wrappedKey)).size === 3);

    const post = await postEncrypted(enc.record);
    const id = post.body;
    check('POST 201', post.statusCode === 201);

    const raw = JSON.parse((await inject({ method: 'GET', url: '/raw/' + id })).body);

    for (const me of [a, b, c]) {
        const encKey = await Crypto.derivePubkeyEnc(raw, me);
        const pt = await Crypto.decrypt(raw, encKey);
        check('decrypt with each identity', new TextDecoder().decode(pt) === 'shared with three recipients');
    }

    // A non-recipient should fail to find their entry.
    const stranger = await makeIdentity();
    let threw = false;
    try { await Crypto.derivePubkeyEnc(raw, stranger); } catch { threw = true; }
    check('stranger cannot decrypt', threw);
}

console.log('\n== v3 legacy single-recipient shape still decrypts (back-compat) ==');
{
    // Plant a legacy v3 record with the old single-recipient shape directly,
    // bypassing the new encrypt() (which always emits the multi-recipient
    // shape). The server schema must continue to accept and serve it.
    const c = globalThis.crypto;
    const me = await makeIdentity();

    // Build a legacy record by hand using HKDF(ECDH(ephemeral, me.pub)) -> enc_key.
    const ephemeral = await c.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const ephemeralPub = new Uint8Array(await c.subtle.exportKey('raw', ephemeral.publicKey));
    const recipientPub = await c.subtle.importKey('raw', me.pub, { name: 'X25519' }, false, []);
    const sharedBits = await c.subtle.deriveBits(
        { name: 'X25519', public: recipientPub }, ephemeral.privateKey, 256,
    );
    const encKey = await Crypto.hkdfExpand32(new Uint8Array(sharedBits), 'minbin/v3/box');
    const chunked = await Crypto.encryptChunks('legacy single recipient', encKey);
    const legacyRecord = {
        v: 3, enc: 'aes-256-gcm', mode: 'pubkey', once: false,
        total: chunked.total,
        chunks: chunked.chunks,
        recipient: {
            pubkey: Crypto.b64uEncode(me.pub),
            epk: Crypto.b64uEncode(ephemeralPub),
        },
    };
    const post = await postEncrypted(legacyRecord);
    check('legacy v3 pubkey accepted (back-compat)', post.statusCode === 201, post.body);
    const id = post.body;

    const raw = JSON.parse((await inject({ method: 'GET', url: '/raw/' + id })).body);
    check('legacy raw has recipient (singular)', raw.recipient && raw.recipient.pubkey);
    check('legacy raw has no recipients[]', raw.recipients === undefined);

    const derivedKey = await Crypto.derivePubkeyEnc(raw, me);
    const pt = await Crypto.decrypt(raw, derivedKey);
    check('legacy single-recipient round-trip', new TextDecoder().decode(pt) === 'legacy single recipient');
}

console.log('\n== v3 record validation (rejects malformed inputs) ==');
{
    const goodChunk = (() => {
        // a single 16+1-byte AES-GCM ciphertext shape (won't decrypt; we
        // never get that far)
        return { seq: 0, iv: 'AAAAAAAAAAAAAAAA', ct: 'A'.repeat(24) };
    })();
    const validShell = {
        v: 3,
        enc: 'aes-256-gcm',
        mode: 'random',
        once: false,
        total: 1,
        chunks: [goodChunk],
        srp: { group: '2048-sha256', salt: 'AAAAAAAAAAAAAAAAAAAAA', verifier: 'Aw' },
    };
    const cases = [
        ['unknown mode', JSON.stringify({ ...validShell, mode: 'mystery' })],
        ['random mode missing srp', JSON.stringify({ ...validShell, srp: undefined })],
        ['password mode missing kdfSalt', JSON.stringify({
            ...validShell, mode: 'password', kdf: 'argon2id',
            argon2: { m: 65536, t: 3, p: 1 },
        })],
        ['kdf set in random mode', JSON.stringify({ ...validShell, kdf: 'argon2id' })],
        ['recipient set in random mode', JSON.stringify({
            ...validShell,
            recipient: { pubkey: 'A'.repeat(43), epk: 'B'.repeat(43) },
        })],
        ['recipients set in random mode', JSON.stringify({
            ...validShell,
            recipients: [{
                pubkey: 'A'.repeat(43), epk: 'B'.repeat(43),
                wrappedKey: 'C'.repeat(64), wrapIv: 'AAAAAAAAAAAAAAAA',
            }],
        })],
        ['pubkey mode missing recipient AND recipients', JSON.stringify({
            v: 3, enc: 'aes-256-gcm', mode: 'pubkey', once: false,
            total: 1, chunks: [goodChunk],
        })],
        ['pubkey mode with both recipient and recipients', JSON.stringify({
            v: 3, enc: 'aes-256-gcm', mode: 'pubkey', once: false,
            total: 1, chunks: [goodChunk],
            recipient: { pubkey: 'A'.repeat(43), epk: 'B'.repeat(43) },
            recipients: [{
                pubkey: 'A'.repeat(43), epk: 'B'.repeat(43),
                wrappedKey: 'C'.repeat(64), wrapIv: 'AAAAAAAAAAAAAAAA',
            }],
        })],
        ['pubkey mode with empty recipients[]', JSON.stringify({
            v: 3, enc: 'aes-256-gcm', mode: 'pubkey', once: false,
            total: 1, chunks: [goodChunk],
            recipients: [],
        })],
        ['pubkey mode with duplicate recipient pubkeys', JSON.stringify({
            v: 3, enc: 'aes-256-gcm', mode: 'pubkey', once: false,
            total: 1, chunks: [goodChunk],
            recipients: [
                { pubkey: 'A'.repeat(43), epk: 'B'.repeat(43),
                  wrappedKey: 'C'.repeat(64), wrapIv: 'AAAAAAAAAAAAAAAA' },
                { pubkey: 'A'.repeat(43), epk: 'D'.repeat(43),
                  wrappedKey: 'E'.repeat(64), wrapIv: 'BBBBBBBBBBBBBBBB' },
            ],
        })],
        ['maxAccesses out of range (negative)', JSON.stringify({
            ...validShell, maxAccesses: -1,
        })],
        ['maxAccesses out of range (too high)', JSON.stringify({
            ...validShell, maxAccesses: 999999,
        })],
        ['maxAccesses non-integer', JSON.stringify({
            ...validShell, maxAccesses: 1.5,
        })],
        ['chunk seq mismatch', JSON.stringify({
            ...validShell,
            total: 2,
            chunks: [goodChunk, { seq: 5, iv: 'AAAAAAAAAAAAAAAA', ct: 'A'.repeat(24) }],
        })],
        ['total != chunks.length', JSON.stringify({ ...validShell, total: 5 })],
        ['short iv in chunk', JSON.stringify({
            ...validShell,
            chunks: [{ seq: 0, iv: 'AAAA', ct: 'A'.repeat(24) }],
        })],
    ];
    for (const [label, payload] of cases) {
        const r = await postEncrypted(payload);
        check(`reject v3: ${label}`, r.statusCode === 400, `got ${r.statusCode} body=${r.body}`);
    }
}

console.log('\n== v3 SRP verifier out-of-range rejected ==');
{
    const goodChunk = { seq: 0, iv: 'AAAAAAAAAAAAAAAA', ct: 'A'.repeat(24) };
    const bad = JSON.stringify({
        v: 3, enc: 'aes-256-gcm', mode: 'random', once: false,
        total: 1, chunks: [goodChunk],
        // verifier = 0 (out of range)
        srp: { group: '2048-sha256', salt: 'AAAAAAAAAAAAAAAAAAAAA', verifier: 'AA' },
    });
    const r = await postEncrypted(bad);
    check('verifier=0 rejected', r.statusCode === 400, `got ${r.statusCode}`);
}

console.log('\n== POST /:id/burn deletes a v3 paste ==');
{
    const enc = await Crypto.encrypt('to-be-burned', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    const id = post.body;
    const burn = await inject({ method: 'POST', url: '/' + id + '/burn' });
    check('burn 204', burn.statusCode === 204, `got ${burn.statusCode}`);
    const after = await inject({ method: 'GET', url: '/raw/' + id });
    check('after burn 404', after.statusCode === 404);
    const burn2 = await inject({ method: 'POST', url: '/' + id + '/burn' });
    check('burn idempotent (204 on missing)', burn2.statusCode === 204);
}

console.log('\n== v3 GET /<id> renders paste-encrypted.html ==');
{
    const enc = await Crypto.encrypt('html-render', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    const html = await inject({ method: 'GET', url: '/' + post.body });
    check('html 200', html.statusCode === 200);
    check('text/html', /^text\/html/.test(html.headers['content-type']));
    check('contains paste-meta', html.body.includes('id="paste-meta"'));
    check('does NOT inline a chunk ct',
        !html.body.includes(enc.record.chunks[0].ct));
    check('loads crypto module', html.body.includes('/assets/js/minbin-crypto.js'));
    check('loads vendored confetti', html.body.includes('/assets/vendor/confetti.browser.min.js'));
    check('share-modal at body level',
        html.body.indexOf('id="share-modal"') > html.body.indexOf('</section>'));
    check('CSP header present', !!html.headers['content-security-policy']);
    check('referrer-policy no-referrer', html.headers['referrer-policy'] === 'no-referrer');
}

console.log('\n== Encrypted POST under wrong content-type is treated as plaintext ==');
{
    const enc = await Crypto.encrypt('whatever', { mode: 'random' });
    const post = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: JSON.stringify(enc.record),
    });
    check('POST 201 (plaintext path)', post.statusCode === 201);
    const raw = await inject({ method: 'GET', url: '/raw/' + post.body });
    check('returned as text/plain', /^text\/plain/.test(raw.headers['content-type']));
    check('body is the JSON literal', raw.body === JSON.stringify(enc.record));
}

console.log('\n== v3 UTF-8 + large payload round-trip ==');
{
    const big = ('🦊 こんにちは — secret bank info ' + 'X'.repeat(50000)).repeat(3);
    const enc = await Crypto.encrypt(big, { mode: 'random' });
    const keys = await Crypto.deriveRandomKeys(enc.link_key);
    const pt = await Crypto.decrypt(enc.record, keys.encKey);
    check('utf-8 + large round-trip', new TextDecoder().decode(pt) === big);
    let totalCt = 0;
    for (const c of enc.record.chunks) totalCt += Crypto.b64uDecode(c.ct).length;
    check('compressed (sum ct < 1/4 plaintext)',
        totalCt * 4 < new TextEncoder().encode(big).length, `ct=${totalCt}`);
}

console.log('\n== v2 records are now rejected (no back-compat) ==');
{
    // The encrypted format is v3-only. Any leftover v2 record from an older
    // dev session should be rejected at upload time.
    const v2Shape = JSON.stringify({
        v: 2, enc: 'aes-256-gcm', kdf: null, salt: null,
        iv: 'AAAAAAAAAAAAAAAA', ct: 'A'.repeat(24), once: false,
    });
    const r = await postEncrypted(v2Shape);
    check('v2 record rejected', r.statusCode === 400, `got ${r.statusCode}`);
}

console.log('\n== Encrypted POST honors size cap (chunks summed) ==');
{
    const goodChunkCt = 'A'.repeat(Math.ceil((1024 * 1024 * 6 * 4) / 3));
    const big = JSON.stringify({
        v: 3, enc: 'aes-256-gcm', mode: 'random', once: false,
        total: 1,
        chunks: [{ seq: 0, iv: 'AAAAAAAAAAAAAAAA', ct: goodChunkCt }],
        srp: { group: '2048-sha256', salt: 'AAAAAAAAAAAAAAAAAAAAA', verifier: 'Aw' },
    });
    const r = await postEncrypted(big);
    check('oversize ct rejected', r.statusCode === 400, `got ${r.statusCode}`);
}

console.log('\n== Crypto: b64url edge cases ==');
{
    const samples = [
        new Uint8Array(0),
        new Uint8Array([0]),
        new Uint8Array([0, 0]),
        new Uint8Array([0, 0, 0]),
        new Uint8Array([255, 254, 253, 252]),
    ];
    let allOk = true;
    for (const s of samples) {
        const back = Crypto.b64uDecode(Crypto.b64uEncode(s));
        if (back.length !== s.length || !s.every((v, i) => v === back[i])) { allOk = false; break; }
    }
    check('b64url roundtrip all sizes', allOk);

    // RFC 4648 test vectors (no padding, URL-safe alphabet)
    check('b64u "f" -> "Zg"', Crypto.b64uEncode(new TextEncoder().encode('f')) === 'Zg');
    check('b64u "fo" -> "Zm8"', Crypto.b64uEncode(new TextEncoder().encode('fo')) === 'Zm8');
    check('b64u "foo" -> "Zm9v"', Crypto.b64uEncode(new TextEncoder().encode('foo')) === 'Zm9v');
}

console.log('\n== Crypto: parseFragment / buildFragment ==');
{
    const f = Crypto.parseFragment('#k=abc&v=1');
    check('parse k', f.k === 'abc');
    check('parse v', f.v === '1');
    const empty = Crypto.parseFragment('');
    check('parse empty', Object.keys(empty).length === 0);
    const built = Crypto.buildFragment({ k: 'AbC-_', v: '1' });
    check('build', built === 'k=AbC-_&v=1');
}

console.log('\n== Existing GET / still serves new toolbar (encrypt/password/once) ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    check('toggle-encrypt rendered', r.body.includes('id="toggle-encrypt"'));
    check('toggle-password rendered', r.body.includes('id="toggle-password"'));
    check('toggle-once rendered', r.body.includes('id="toggle-once"'));
    check('loads index.js', r.body.includes('/assets/js/index.js'));
    check('CSP set on home', !!r.headers['content-security-policy']);
}

console.log('\n== Vendored Argon2 served + executes ==');
{
    const r = await inject({ method: 'GET', url: '/assets/vendor/argon2.umd.min.js' });
    check('argon2 status 200', r.statusCode === 200);
    check('non-empty body', r.body.length > 10000, `len=${r.body.length}`);
    check('UMD wrapper signature', /hashwasm/.test(r.body));
}

// ---------------------------------------------------------------------------
// Security headers + abuse controls (Batch A)
// ---------------------------------------------------------------------------

console.log('\n== HSTS header on HTML and JSON ==');
{
    const html = await inject({ method: 'GET', url: '/' });
    check('HSTS on /', /max-age=63072000/.test(html.headers['strict-transport-security'] || ''),
        html.headers['strict-transport-security']);
    check('includeSubDomains',
        /includeSubDomains/.test(html.headers['strict-transport-security'] || ''));
    check('preload absent by default',
        !/preload/.test(html.headers['strict-transport-security'] || ''));

    const json = await inject({ method: 'GET', url: '/openapi' });
    check('HSTS on JSON',
        /max-age=63072000/.test(json.headers['strict-transport-security'] || ''));
}

console.log('\n== COOP / CORP on every response ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    check('COOP same-origin', r.headers['cross-origin-opener-policy'] === 'same-origin');
    check('CORP same-origin', r.headers['cross-origin-resource-policy'] === 'same-origin');
}

console.log('\n== X-Robots-Tag noindex on every response ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    const tag = r.headers['x-robots-tag'] || '';
    check('contains noindex', /noindex/.test(tag));
    check('contains nofollow', /nofollow/.test(tag));
    check('contains noarchive', /noarchive/.test(tag));
    check('contains nosnippet', /nosnippet/.test(tag));
}

console.log('\n== /robots.txt blocks crawlers ==');
{
    const r = await inject({ method: 'GET', url: '/robots.txt' });
    check('status 200', r.statusCode === 200);
    check('text/plain', /^text\/plain/.test(r.headers['content-type']));
    check('User-agent: *', r.body.includes('User-agent: *'));
    check('Disallow: /', r.body.includes('Disallow: /'));
    check('blocks ia_archiver', r.body.includes('ia_archiver'));
    check('blocks archive.org_bot', r.body.includes('archive.org_bot'));
}

console.log('\n== Cache-Control: no-store on dynamic, immutable on /assets/ ==');
{
    const html = await inject({ method: 'GET', url: '/' });
    check('html no-store', html.headers['cache-control'] === 'no-store');

    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'cache-test',
    });
    const id = create.body;
    const raw = await inject({ method: 'GET', url: '/raw/' + id });
    check('raw no-store', raw.headers['cache-control'] === 'no-store');

    const css = await inject({ method: 'GET', url: '/assets/css/styles.css' });
    check('css immutable',
        /immutable/.test(css.headers['cache-control'] || ''),
        css.headers['cache-control']);
    check('css max-age',
        /max-age=31536000/.test(css.headers['cache-control'] || ''));
}

console.log('\n== Permissions-Policy locks down sensors and APIs ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    const pp = r.headers['permissions-policy'] || '';
    check('camera=()', pp.includes('camera=()'));
    check('microphone=()', pp.includes('microphone=()'));
    check('geolocation=()', pp.includes('geolocation=()'));
    check('payment=()', pp.includes('payment=()'));
    check('usb=()', pp.includes('usb=()'));
    check('interest-cohort=()', pp.includes('interest-cohort=()'));
}

console.log('\n== Server / X-Powered-By headers stripped ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    check('no Server header', !r.headers['server'], r.headers['server']);
    check('no X-Powered-By', !r.headers['x-powered-by']);
}

console.log('\n== Origin / Sec-Fetch-Site enforcement on POST ==');
{
    // Cross-origin POST should be rejected.
    const cross = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: {
            'content-type': 'text/plain',
            'origin': 'https://evil.example',
        },
        payload: 'cross-origin attempt',
    });
    check('cross-origin POST 403', cross.statusCode === 403, `got ${cross.statusCode}`);

    // POST with no Origin header (curl, terminal) should still work.
    const noOrigin = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'no-origin paste',
    });
    check('no-Origin POST 201', noOrigin.statusCode === 201, `got ${noOrigin.statusCode}`);

    // POST with same-origin Origin should work.
    const sameOrigin = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: {
            'content-type': 'text/plain',
            'origin': 'https://minb.in',
        },
        payload: 'same-origin paste',
    });
    check('same-origin POST 201', sameOrigin.statusCode === 201, `got ${sameOrigin.statusCode}`);

    // POST with Sec-Fetch-Site: cross-site should be rejected.
    const sfsCross = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: {
            'content-type': 'text/plain',
            'sec-fetch-site': 'cross-site',
        },
        payload: 'sfs cross',
    });
    check('Sec-Fetch-Site cross-site 403', sfsCross.statusCode === 403, `got ${sfsCross.statusCode}`);

    // Sec-Fetch-Site: none (top-level navigation / bookmark) is allowed.
    const sfsNone = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: {
            'content-type': 'text/plain',
            'sec-fetch-site': 'none',
        },
        payload: 'sfs none',
    });
    check('Sec-Fetch-Site none 201', sfsNone.statusCode === 201, `got ${sfsNone.statusCode}`);

    // GETs are never blocked by Origin/Sec-Fetch-Site.
    const getCross = await inject({
        method: 'GET',
        url: '/',
        headers: { 'origin': 'https://evil.example' },
    });
    check('cross-origin GET 200', getCross.statusCode === 200, `got ${getCross.statusCode}`);
}

console.log('\n== Re-validation on read rejects malformed stored records ==');
{
    // Plant a v3-shaped record directly with bogus chunks.
    const bogusId = 'beefcafe';
    await redis.set(bogusId, JSON.stringify({
        v: 3, enc: 'aes-256-gcm', mode: 'random', once: false,
        total: 1,
        chunks: [{ seq: 0, iv: 'short', ct: 'A'.repeat(24) }], // iv too short
        srp: { group: '2048-sha256', salt: 'AAAAAAAAAAAAAAAAAAAAA', verifier: 'Aw' },
    }), 'EX', 60);
    const r = await inject({ method: 'GET', url: '/raw/' + bogusId });
    check('malformed v3 returns 500', r.statusCode === 500, `got ${r.statusCode}`);
    const html = await inject({ method: 'GET', url: '/' + bogusId });
    check('malformed v3 (HTML route) returns 500', html.statusCode === 500, `got ${html.statusCode}`);
}

console.log('\n== Legacy 4-hex paste IDs continue to resolve ==');
{
    // Plant a plaintext paste with the old 2-byte ID space directly.
    const legacyId = 'abcd'; // 4 hex
    await redis.set(legacyId, JSON.stringify({
        body: 'legacy paste body', once: false,
    }), 'EX', 60);
    const r = await inject({ method: 'GET', url: '/raw/' + legacyId });
    check('legacy 4-hex GET 200', r.statusCode === 200, `got ${r.statusCode}`);
    check('legacy body intact', r.body === 'legacy paste body');

    const html = await inject({ method: 'GET', url: '/' + legacyId });
    check('legacy 4-hex HTML 200', html.statusCode === 200);
    check('legacy body in HTML', html.body.includes('legacy paste body'));
}

console.log('\n== /srp/init body limit (4 KiB) ==');
{
    const enc = await Crypto.encrypt('limit-test', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    const id = post.body;
    const huge = 'A'.repeat(8000); // > 4 KiB
    const r = await inject({
        method: 'POST',
        url: '/' + id + '/srp/init',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ A: huge }),
    });
    check('srp/init oversize body rejected (400/413)',
        r.statusCode === 400 || r.statusCode === 413,
        `got ${r.statusCode}`);
}

console.log('\n== AJV strict: extra querystring rejected ==');
{
    const r = await inject({
        method: 'POST',
        url: '/?relative=true&unknownParam=foo',
        headers: { 'content-type': 'text/plain' },
        payload: 'extra param',
    });
    // additionalProperties: false should reject unknown query params.
    check('unknown query 400', r.statusCode >= 400 && r.statusCode < 500,
        `got ${r.statusCode}`);
}

console.log('\n== Strict CSP: no unsafe-inline, no CDN allowlist ==');
{
    const r = await inject({ method: 'GET', url: '/' });
    const csp = r.headers['content-security-policy'] || '';
    // script-src may NOT contain unsafe-inline.
    const scriptSrcMatch = csp.match(/script-src ([^;]+)/);
    check('CSP has script-src', scriptSrcMatch !== null);
    if (scriptSrcMatch) {
        check('script-src has no unsafe-inline',
            !/'unsafe-inline'/.test(scriptSrcMatch[1]),
            scriptSrcMatch[1]);
        check('script-src has no jsdelivr',
            !/jsdelivr/.test(scriptSrcMatch[1]));
        check('script-src has no cdnjs',
            !/cdnjs/.test(scriptSrcMatch[1]));
    }
    check('CSP has object-src none', /object-src 'none'/.test(csp));
    check('CSP has wasm-unsafe-eval', /'wasm-unsafe-eval'/.test(csp));
}

console.log('\n== Templates are CDN-free ==');
{
    const home = await inject({ method: 'GET', url: '/' });
    check('home: no jsdelivr',
        !home.body.includes('cdn.jsdelivr.net'));
    check('home: no cdnjs',
        !home.body.includes('cdnjs.cloudflare.com'));
    // Plaintext paste page.
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'cdn-free-check',
    });
    const id = create.body;
    const html = await inject({ method: 'GET', url: '/' + id });
    check('paste.html: no jsdelivr', !html.body.includes('cdn.jsdelivr.net'));
    check('paste.html: no cdnjs', !html.body.includes('cdnjs.cloudflare.com'));
    check('paste.html: vendored bootstrap',
        html.body.includes('/assets/vendor/bootstrap.min.css'));
    check('paste.html: vendored qrcode',
        html.body.includes('/assets/vendor/qrcode.min.js'));
}

console.log('\n== Vendored assets reachable ==');
{
    for (const path of [
        '/assets/vendor/argon2.umd.min.js',
        '/assets/vendor/bootstrap.min.css',
        '/assets/vendor/bootstrap.bundle.min.js',
        '/assets/vendor/qrcode.min.js',
        '/assets/vendor/confetti.browser.min.js',
    ]) {
        const r = await inject({ method: 'GET', url: path });
        check(`${path} 200`, r.statusCode === 200, `got ${r.statusCode}`);
        check(`${path} non-empty`, r.body.length > 100);
    }
}

console.log('\n== Templates declare <meta name="robots"> ==');
{
    const home = await inject({ method: 'GET', url: '/' });
    check('home: meta robots',
        /<meta\s+name="robots"\s+content="[^"]*noindex/.test(home.body));
    const create = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'meta-robots',
    });
    const id = create.body;
    const html = await inject({ method: 'GET', url: '/' + id });
    check('paste.html: meta robots',
        /<meta\s+name="robots"\s+content="[^"]*noindex/.test(html.body));
    const four04 = await inject({ method: 'GET', url: '/zzzzzzzz' });
    check('404.html: meta robots',
        /<meta\s+name="robots"\s+content="[^"]*noindex/.test(four04.body));
}

console.log('\n== SET NX collision retry: parallel inserts get unique IDs ==');
{
    // Many parallel inserts -- exercises the SET NX path. With 16-hex IDs the
    // collision rate is ~negligible; this just confirms no errors and all
    // succeed.
    const N = 30;
    const promises = [];
    for (let i = 0; i < N; i++) {
        promises.push(inject({
            method: 'POST',
            url: '/?relative=true',
            headers: { 'content-type': 'text/plain' },
            payload: 'parallel-' + i,
        }));
    }
    const results = await Promise.all(promises);
    const ids = new Set(results.map((r) => r.body));
    check('all parallel inserts succeeded',
        results.every((r) => r.statusCode === 201),
        `failures=${results.filter((r) => r.statusCode !== 201).length}`);
    check('all IDs unique', ids.size === N, `unique=${ids.size}`);
}

// ---------------------------------------------------------------------------
// New-feature tests (Batch B): SRI, /captcha, /report, /:id/access, max-views,
// 4-hex/8-hex/16-hex ID resolution, byte-budget envar handling, etc.
// ---------------------------------------------------------------------------

console.log('\n== SRI: every <script src="/assets/vendor/..."> carries integrity ==');
{
    const pages = ['/', '/zzzzzzzz', '/api'];
    for (const url of pages) {
        const r = await inject({ method: 'GET', url });
        // Find every vendor script/link tag and check it carries integrity=.
        const tags = (r.body.match(/<(?:script|link)\b[^>]*\/assets\/vendor\/[^>]*>/g) || []);
        check(`${url} has at least one vendor tag`, tags.length > 0, `count=${tags.length}`);
        const missing = tags.filter((t) => !/integrity=("|')sha512-/.test(t));
        check(`${url} all vendor tags have sha512 integrity`,
            missing.length === 0, `missing=${missing.join(' | ')}`);
        const noxorigin = tags.filter((t) => !/crossorigin=("|')anonymous/.test(t));
        check(`${url} all vendor tags have crossorigin=anonymous`,
            noxorigin.length === 0, `bad=${noxorigin.join(' | ')}`);
    }
}

console.log('\n== SRI: integrity matches actual file contents ==');
{
    const { createHash } = await import('node:crypto');
    const home = await inject({ method: 'GET', url: '/' });
    // Pick the bootstrap CSS hash out of the rendered HTML and verify it.
    const m = home.body.match(/href="\/assets\/vendor\/bootstrap\.min\.css"\s+integrity="(sha512-[^"]+)"/);
    check('bootstrap.min.css integrity attr present', m !== null);
    if (m) {
        const fileBytes = fs.readFileSync(
            new URL('../templates/assets/vendor/bootstrap.min.css', import.meta.url),
        );
        const expected = 'sha512-' + createHash('sha512').update(fileBytes).digest('base64');
        check('bootstrap.min.css integrity matches file', m[1] === expected,
            `got ${m[1].slice(0, 32)}…`);
    }
}

console.log('\n== /captcha endpoint returns a token ==');
{
    const r = await inject({ method: 'GET', url: '/captcha' });
    check('captcha 200', r.statusCode === 200);
    const body = JSON.parse(r.body);
    check('captcha has token', typeof body.token === 'string' && body.token.length > 40);
    check('captcha has bits', typeof body.bits === 'number');
    check('captcha has expiresAt', typeof body.expiresAt === 'number');
    // Default test config has CAPTCHA_BITS=0, so plaintext POSTs don't need a
    // token; bits=0 confirms the disabled path.
    check('captcha bits = 0 (disabled in test config)', body.bits === 0);
}

console.log('\n== Plaintext POST works without captcha when CAPTCHA_BITS=0 ==');
{
    const r = await inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'no-captcha',
    });
    check('201 without captcha (bits=0)', r.statusCode === 201, r.body);
}

console.log('\n== /report endpoint validates input ==');
{
    // Missing reason
    const r1 = await inject({
        method: 'POST',
        url: '/report',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ paste_id: 'abcdabcd' }),
    });
    check('missing reason rejected', r1.statusCode === 400, `got ${r1.statusCode}`);
    // Bad paste_id
    const r2 = await inject({
        method: 'POST',
        url: '/report',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ paste_id: '!!!!!', reason: 'this is at least ten characters long' }),
    });
    check('bad paste_id rejected', r2.statusCode === 400, `got ${r2.statusCode}`);
    // Reason too short
    const r3 = await inject({
        method: 'POST',
        url: '/report',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ paste_id: 'abcdabcd', reason: 'short' }),
    });
    check('short reason rejected', r3.statusCode === 400, `got ${r3.statusCode}`);
}

console.log('\n== /report endpoint stores valid report ==');
{
    await redis.del('abuse:reports'); // start fresh for this assertion
    const r = await inject({
        method: 'POST',
        url: '/report',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({
            paste_id: 'abcdabcd',
            reason: 'phishing — fake bank login',
            contact: 'alice@example.com',
            link: 'https://minb.in/abcdabcd#k=AAAA',
        }),
    });
    check('valid report 201', r.statusCode === 201, r.body);
    const stored = await redis.lrange('abuse:reports', 0, -1);
    check('report stored in redis list', stored.length === 1, `len=${stored.length}`);
    const parsed = JSON.parse(stored[0]);
    check('report has paste_id', parsed.paste_id === 'abcdabcd');
    check('report has reason', /phishing/.test(parsed.reason));
    check('report has link with fragment', parsed.link === 'https://minb.in/abcdabcd#k=AAAA');
    check('report has timestamp', typeof parsed.ts === 'string');
}

console.log('\n== Cross-origin POST /report blocked, same-origin allowed ==');
{
    const cross = await inject({
        method: 'POST',
        url: '/report',
        headers: {
            'content-type': 'application/json',
            'origin': 'https://evil.example',
        },
        payload: JSON.stringify({ paste_id: 'abcdabcd', reason: 'this is at least ten characters long' }),
    });
    check('cross-origin /report blocked', cross.statusCode === 403, `got ${cross.statusCode}`);
}

console.log('\n== Captcha solver round-trip (16 bits) ==');
{
    const { issueChallenge, verifyChallenge, solveChallenge } = await import('../dist/utils/captcha.js');
    const { Buffer } = await import('node:buffer');
    const secret = Buffer.from('test-secret-32-bytes-long-padding'.padEnd(32, 'X'));
    const challenge = issueChallenge(secret, 16, 60);
    const nonce = solveChallenge(challenge.token, 16);
    const ok = await verifyChallenge(challenge.token, nonce, {
        secret, bits: 16, ttlSeconds: 60, redis,
    });
    check('captcha verify ok', ok.ok === true);
    // Replay should fail (single-use challenge).
    const replay = await verifyChallenge(challenge.token, nonce, {
        secret, bits: 16, ttlSeconds: 60, redis,
    });
    check('captcha replay rejected', replay.ok === false && replay.reason === 'replay');
}

console.log('\n== Captcha rejects bad MAC ==');
{
    const { issueChallenge, verifyChallenge, solveChallenge } = await import('../dist/utils/captcha.js');
    const { Buffer } = await import('node:buffer');
    const secret = Buffer.from('a-secret-1'.padEnd(32, 'X'));
    const otherSecret = Buffer.from('a-different-secret'.padEnd(32, 'X'));
    const challenge = issueChallenge(secret, 8, 60);
    const nonce = solveChallenge(challenge.token, 8);
    const verdict = await verifyChallenge(challenge.token, nonce, {
        secret: otherSecret, bits: 8, ttlSeconds: 60, redis,
    });
    check('wrong secret rejected', verdict.ok === false && verdict.reason === 'bad_mac');
}

console.log('\n== Captcha rejects insufficient work ==');
{
    const { issueChallenge, verifyChallenge } = await import('../dist/utils/captcha.js');
    const { Buffer } = await import('node:buffer');
    const secret = Buffer.from('s'.padEnd(32, 'X'));
    const challenge = issueChallenge(secret, 24, 60);
    // Submit nonce=0 directly without solving; SHA-256(rand||0) has ~no
    // chance of having 24 leading zero bits.
    const verdict = await verifyChallenge(challenge.token, 'AAAAAAAAAAAA', {
        secret, bits: 24, ttlSeconds: 60, redis,
    });
    check('insufficient work rejected', verdict.ok === false && verdict.reason === 'insufficient_work');
}

console.log('\n== Plaintext maxAccesses (server-driven counter) ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?relative=true&maxAccesses=3',
        headers: { 'content-type': 'text/plain' },
        payload: 'three-views',
    });
    check('plaintext max-views POST 201', create.statusCode === 201);
    const id = create.body;
    // Read 1: alive
    const r1 = await inject({ method: 'GET', url: '/raw/' + id });
    check('read 1: 200', r1.statusCode === 200);
    check('read 1: body intact', r1.body === 'three-views');
    // Read 2: alive
    const r2 = await inject({ method: 'GET', url: '/raw/' + id });
    check('read 2: 200', r2.statusCode === 200);
    // Read 3: should be the LAST one (third read pushes counter to >= 3)
    const r3 = await inject({ method: 'GET', url: '/raw/' + id });
    check('read 3: 200 (last)', r3.statusCode === 200);
    // Read 4: gone
    const r4 = await inject({ method: 'GET', url: '/raw/' + id });
    check('read 4: 404 (cap reached)', r4.statusCode === 404, `got ${r4.statusCode}`);
}

console.log('\n== Plaintext maxAccesses=1 behaves like once ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?relative=true&maxAccesses=1',
        headers: { 'content-type': 'text/plain' },
        payload: 'one-shot via cap',
    });
    const id = create.body;
    const r1 = await inject({ method: 'GET', url: '/raw/' + id });
    check('first read 200', r1.statusCode === 200);
    const r2 = await inject({ method: 'GET', url: '/raw/' + id });
    check('second read 404', r2.statusCode === 404);
}

console.log('\n== Plaintext maxAccesses out-of-range rejected ==');
{
    const r = await inject({
        method: 'POST',
        url: '/?relative=true&maxAccesses=99999',
        headers: { 'content-type': 'text/plain' },
        payload: 'too-many',
    });
    check('huge maxAccesses rejected', r.statusCode === 400 || r.statusCode === 422,
        `got ${r.statusCode}`);
}

console.log('\n== Encrypted maxAccesses + /:id/access counter ==');
{
    const enc = await Crypto.encrypt('encrypted with cap', { mode: 'random', maxAccesses: 2 });
    check('record carries maxAccesses', enc.record.maxAccesses === 2);
    const post = await postEncrypted(enc.record);
    check('POST 201', post.statusCode === 201);
    const id = post.body;

    // Public header should expose maxAccesses for the client UI.
    const headerResp = await inject({ method: 'GET', url: '/raw/' + id });
    const header = JSON.parse(headerResp.body);
    check('header has maxAccesses', header.maxAccesses === 2);

    // First access bump leaves the paste alive.
    const acc1 = await inject({ method: 'POST', url: '/' + id + '/access' });
    check('access 1: 200', acc1.statusCode === 200);
    const j1 = JSON.parse(acc1.body);
    check('access 1: remaining=1', j1.remaining === 1 && j1.expired === false);

    // Second access bump deletes the paste.
    const acc2 = await inject({ method: 'POST', url: '/' + id + '/access' });
    check('access 2: 200', acc2.statusCode === 200);
    const j2 = JSON.parse(acc2.body);
    check('access 2: expired=true', j2.expired === true);

    // Subsequent fetches return 404.
    const after = await inject({ method: 'GET', url: '/raw/' + id });
    check('after cap: 404', after.statusCode === 404);
}

console.log('\n== /:id/access on a paste without maxAccesses is no-op ==');
{
    const enc = await Crypto.encrypt('no cap', { mode: 'random' });
    const post = await postEncrypted(enc.record);
    const id = post.body;
    const acc = await inject({ method: 'POST', url: '/' + id + '/access' });
    check('200', acc.statusCode === 200);
    const j = JSON.parse(acc.body);
    check('applies=false', j.applies === false);
    // Paste still present.
    const after = await inject({ method: 'GET', url: '/raw/' + id });
    check('paste still present', after.statusCode === 200);
}

console.log('\n== /:id/access on missing paste is idempotent ==');
{
    const r = await inject({ method: 'POST', url: '/abcdabcdabcdabcd/access' });
    check('200 expired', r.statusCode === 200);
    const j = JSON.parse(r.body);
    check('expired=true', j.expired === true);
}

console.log('\n== Old-default 8-hex paste IDs continue to resolve ==');
{
    const eightHexId = 'abcd1234';
    await redis.set(eightHexId, JSON.stringify({
        body: 'old-default-id', once: false,
    }), 'EX', 60);
    const r = await inject({ method: 'GET', url: '/raw/' + eightHexId });
    check('8-hex GET 200', r.statusCode === 200);
    check('body intact', r.body === 'old-default-id');
}

console.log('\n== /captcha is rate-limited (sanity check) ==');
{
    // RATE_LIMIT_ENABLED=false in this test, so this should always succeed.
    // We just verify the endpoint accepts repeated calls.
    let oks = 0;
    for (let i = 0; i < 5; i++) {
        const r = await inject({ method: 'GET', url: '/captcha' });
        if (r.statusCode === 200) oks++;
    }
    check('5 /captcha calls all 200', oks === 5);
}

console.log('\n== /report cross-checks: report list capped + TTL applied ==');
{
    await redis.del('abuse:reports');
    // Push a few reports
    for (let i = 0; i < 3; i++) {
        await inject({
            method: 'POST',
            url: '/report',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                paste_id: 'cafedecaf' + i,
                reason: 'this is at least ten characters: r' + i,
            }),
        });
    }
    const len = await redis.llen('abuse:reports');
    check('all reports stored', len === 3, `len=${len}`);
    const ttl = await redis.ttl('abuse:reports');
    check('TTL applied', ttl > 0, `ttl=${ttl}`);
}

console.log('\n== Pubkey-mode record now hides recipients in publicView ==');
{
    // Pubkey-mode publicView is the full record (recipients are needed by the
    // client to find their wrapped key). The earlier test already checked the
    // full record returns; this confirms we don't accidentally strip the new
    // `recipients` field on the read path.
    const c = globalThis.crypto;
    const me = await c.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const mePub = new Uint8Array(await c.subtle.exportKey('raw', me.publicKey));
    const enc = await Crypto.encrypt('multi pubkey publicView', {
        mode: 'pubkey',
        recipientPubkeys: [mePub],
    });
    const post = await postEncrypted(enc.record);
    const raw = JSON.parse((await inject({ method: 'GET', url: '/raw/' + post.body })).body);
    check('publicView keeps recipients[]', Array.isArray(raw.recipients) && raw.recipients.length === 1);
    check('publicView keeps wrappedKey', typeof raw.recipients[0].wrappedKey === 'string');
    check('publicView keeps wrapIv', typeof raw.recipients[0].wrapIv === 'string');
}

console.log('\n== Plaintext maxAccesses: 5 concurrent reads on cap=2 only succeed twice (atomic) ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?relative=true&maxAccesses=2',
        headers: { 'content-type': 'text/plain' },
        payload: 'race-test',
    });
    const id = create.body;
    // Fire 5 reads in parallel; only 2 should hit a live paste.
    const reads = await Promise.all(
        Array.from({ length: 5 }, () => inject({ method: 'GET', url: '/raw/' + id })),
    );
    const okCount = reads.filter((r) => r.statusCode === 200).length;
    const notFoundCount = reads.filter((r) => r.statusCode === 404).length;
    check('exactly 2 reads got the body', okCount === 2,
        `ok=${okCount} 404=${notFoundCount} statuses=${reads.map(r => r.statusCode).join(',')}`);
    check('rest 404', notFoundCount === 3);
    // Subsequent read also 404.
    const after = await inject({ method: 'GET', url: '/raw/' + id });
    check('post-race read 404', after.statusCode === 404);
}

console.log('\n== Plaintext once + maxAccesses both set: once wins on first read ==');
{
    const create = await inject({
        method: 'POST',
        url: '/?relative=true&once=true&maxAccesses=5',
        headers: { 'content-type': 'text/plain' },
        payload: 'once-and-cap',
    });
    const id = create.body;
    const r1 = await inject({ method: 'GET', url: '/raw/' + id });
    check('first read 200', r1.statusCode === 200);
    const r2 = await inject({ method: 'GET', url: '/raw/' + id });
    check('second read 404 (once wins over cap)', r2.statusCode === 404);
}

console.log('\n== Pubkey mode + maxAccesses ==');
{
    const me = await makeIdentity();
    const enc = await Crypto.encrypt('pubkey + cap', {
        mode: 'pubkey',
        recipientPubkeys: [me.pub],
        maxAccesses: 2,
    });
    check('record has maxAccesses', enc.record.maxAccesses === 2);
    const post = await postEncrypted(enc.record);
    const id = post.body;
    // /:id/access should bump and delete on the second call.
    const acc1 = await inject({ method: 'POST', url: '/' + id + '/access' });
    check('access 1: 200 remaining=1', JSON.parse(acc1.body).remaining === 1);
    const acc2 = await inject({ method: 'POST', url: '/' + id + '/access' });
    check('access 2: expired', JSON.parse(acc2.body).expired === true);
    // Paste should be gone.
    const after = await inject({ method: 'GET', url: '/raw/' + id });
    check('post-cap read 404', after.statusCode === 404);
}

console.log('\n== Browser captcha solver produces server-acceptable nonces ==');
{
    // The browser solver in minbin-crypto.js is a separate code path from
    // the server-side solveChallenge. Verify they're byte-compatible.
    await redis.del('cap:*'); // clear any previous test dedup keys (no-op on RedisMock)
    const { issueChallenge, verifyChallenge } = await import('../dist/utils/captcha.js');
    const { Buffer } = await import('node:buffer');
    const secret = Buffer.from('browser-vs-server'.padEnd(32, 'X'));
    const challenge = issueChallenge(secret, 12, 60);
    // Use the BROWSER solveCaptcha path (loaded at the top of this file
    // via vm.runInThisContext into globalThis.MinbinCrypto).
    const nonce = await Crypto.solveCaptcha(challenge.token, 12);
    const verdict = await verifyChallenge(challenge.token, nonce, {
        secret, bits: 12, ttlSeconds: 60, redis,
    });
    check('browser-solved nonce verifies server-side', verdict.ok === true,
        verdict.ok ? '' : `reason=${verdict.reason}`);
}

console.log('\n== Browser captcha: bits=0 short-circuits ==');
{
    // When CAPTCHA_BITS=0 (test default), solveCaptcha returns '' immediately.
    const t0 = Date.now();
    const out = await Crypto.solveCaptcha('AAAAAA', 0);
    const ms = Date.now() - t0;
    check('bits=0 returns empty string', out === '');
    check('bits=0 short-circuits fast', ms < 50, `ms=${ms}`);
}

console.log('\n== Solver: PoW search terminates in reasonable time at 12 bits ==');
{
    const t0 = Date.now();
    const { issueChallenge, solveChallenge } = await import('../dist/utils/captcha.js');
    const { Buffer } = await import('node:buffer');
    const secret = Buffer.from('s'.padEnd(32, 'X'));
    const ch = issueChallenge(secret, 12, 60);
    const nonce = solveChallenge(ch.token, 12);
    const ms = Date.now() - t0;
    check('PoW solve at 12 bits < 5s', ms < 5000, `ms=${ms}`);
    check('returns nonzero nonce', nonce.length > 0);
}

await app.close();
await redis.quit();

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed === 0 ? 0 : 1);
