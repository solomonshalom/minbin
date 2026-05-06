// Rate-limit + byte-budget + captcha integration tests. Runs as a separate
// process so Config can pick up RATE_LIMIT_*, DAILY_BYTE_BUDGET, and
// CAPTCHA_BITS env at module-load time. Verifies @fastify/rate-limit is
// wired correctly, the per-paste cross-IP cap fires, the per-IP daily byte
// budget rejects oversize cumulative uploads, and the PoW captcha is
// required when CAPTCHA_BITS > 0.
//
// Note on ioredis-mock: instances share global state by default. We
// `flushall()` between sub-tests so rate-limit counters start fresh and
// each block's setup is independent.
import RedisMock from 'ioredis-mock';

process.env.LOG_LEVEL = 'silent';
process.env.APP_DOMAIN = 'minb.in';
process.env.PASTE_EXPIRY = '60';
process.env.MAX_PASTE_SIZE = String(1024 * 1024 * 5);
process.env.NODE_ENV = 'test';

// Tight caps so the test runs fast.
process.env.RATE_LIMIT_ENABLED = 'true';
process.env.RATE_LIMIT_WINDOW_MS = '60000';
process.env.RATE_LIMIT_POST_MAX = '3';
process.env.RATE_LIMIT_GET_MAX = '100';
process.env.RATE_LIMIT_SRP_MAX = '3';
process.env.RATE_LIMIT_BURN_MAX = '3';
process.env.RATE_LIMIT_REPORT_MAX = '3';
process.env.RATE_LIMIT_CAPTCHA_MAX = '5';
process.env.RATE_LIMIT_ACCESS_MAX = '5';

// Per-IP byte budget (low so the test trips quickly).
process.env.DAILY_BYTE_BUDGET = '5000';

// Hashcash captcha at low difficulty so the test is fast but the path is
// still exercised end-to-end.
process.env.CAPTCHA_BITS = '8';
process.env.CAPTCHA_SECRET = 'fixed-test-secret-for-rl-suite';

const { createApp } = await import('../dist/app.js');
const { issueChallenge, solveChallenge } = await import('../dist/utils/captcha.js');
const { Buffer } = await import('node:buffer');
const { createHash } = await import('node:crypto');

const redis = new RedisMock();
const app = await createApp({ redis, logger: false });
await app.ready();

async function reset() {
    // Clears both paste-store and rate-limit-counter keys.
    await redis.flushall();
}

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

// Solve a captcha for the test secret without hitting /captcha (which is
// also rate-limited). Mirrors what a browser client would do.
function solvedCaptchaHeaders() {
    const secret = createHash('sha256').update('fixed-test-secret-for-rl-suite', 'utf8').digest();
    const ch = issueChallenge(secret, 8, 300);
    const nonce = solveChallenge(ch.token, 8);
    return {
        'x-captcha-token': ch.token,
        'x-captcha-nonce': nonce,
    };
}

console.log('\n== POST / cap (3 in window, 4th gets 429) ==');
{
    await reset();
    const results = [];
    for (let i = 0; i < 4; i++) {
        results.push(await app.inject({
            method: 'POST',
            url: '/?relative=true',
            headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
            payload: 'rl-' + i,
        }));
    }
    check('first 3 succeed (201)',
        results.slice(0, 3).every((r) => r.statusCode === 201),
        results.slice(0, 3).map((r) => r.statusCode).join('/'));
    check('4th rate-limited (429)',
        results[3].statusCode === 429,
        `got ${results[3].statusCode}`);
    check('retry-after header on 429',
        results[3].headers['retry-after'] !== undefined);
}

console.log('\n== GET /raw/<id> cap is generous (100/min) ==');
{
    await reset();
    const create = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: 'get-cap',
    });
    check('paste created', create.statusCode === 201,
        `status=${create.statusCode} body=${create.body}`);
    const id = create.body;
    let okCount = 0;
    for (let i = 0; i < 50; i++) {
        const r = await app.inject({ method: 'GET', url: '/raw/' + id });
        if (r.statusCode === 200) okCount++;
    }
    check('50 GET /raw within cap', okCount === 50, `ok=${okCount}`);
}

console.log('\n== SRP /srp/init cap (cross-IP per-paste defense) ==');
{
    await reset();

    // Build a v3 random-key record by hand (small, valid shape).
    const validRecord = {
        v: 3,
        enc: 'aes-256-gcm',
        mode: 'random',
        once: false,
        total: 1,
        chunks: [{ seq: 0, iv: 'AAAAAAAAAAAAAAAA', ct: 'A'.repeat(24) }],
        srp: {
            // 22 base64url chars decodes to exactly 16 bytes (the spec).
            group: '2048-sha256',
            salt: 'AAAAAAAAAAAAAAAAAAAAAA',
            verifier: 'Aw',
        },
    };
    const create = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'application/vnd.minbin.encrypted+json' },
        payload: JSON.stringify(validRecord),
    });
    check('paste created for SRP cap test', create.statusCode === 201,
        `status=${create.statusCode} body=${create.body}`);
    const id = create.body;

    // Vary the source IP per request so the per-(IP, paste) cap doesn't
    // trip; this exercises ONLY the cross-IP per-paste hook.
    const statuses = [];
    for (let i = 0; i < 5; i++) {
        const r = await app.inject({
            method: 'POST',
            url: '/' + id + '/srp/init',
            headers: {
                'content-type': 'application/json',
                'x-forwarded-for': '10.0.0.' + (i + 1),
            },
            payload: JSON.stringify({ A: 'AQ' }), // A=1, SRP will 400 (we expect 400 or 429)
        });
        statuses.push(r.statusCode);
    }
    const rateLimited = statuses.filter((s) => s === 429).length;
    check('cross-IP per-paste cap trips after 3 attempts',
        rateLimited >= 1, `statuses=${statuses.join(',')}`);
}

console.log('\n== /:id/burn cap (3/window) ==');
{
    await reset();
    const results = [];
    for (let i = 0; i < 4; i++) {
        results.push(await app.inject({
            method: 'POST',
            url: '/aaaaaaaa/burn',
        }));
    }
    check('first 3 burns succeed (204)',
        results.slice(0, 3).every((r) => r.statusCode === 204),
        results.slice(0, 3).map((r) => r.statusCode).join('/'));
    check('4th burn rate-limited (429)',
        results[3].statusCode === 429, `got ${results[3].statusCode}`);
}

console.log('\n== /report cap (3/window) ==');
{
    await reset();
    const results = [];
    for (let i = 0; i < 4; i++) {
        results.push(await app.inject({
            method: 'POST',
            url: '/report',
            headers: { 'content-type': 'application/json' },
            payload: JSON.stringify({
                paste_id: 'abcdabcd',
                reason: 'this is at least ten chars: r' + i,
            }),
        }));
    }
    check('first 3 reports accepted (201)',
        results.slice(0, 3).every((r) => r.statusCode === 201),
        results.slice(0, 3).map((r) => r.statusCode).join('/'));
    check('4th report rate-limited (429)',
        results[3].statusCode === 429, `got ${results[3].statusCode}`);
}

console.log('\n== Plaintext POST without captcha rejected when CAPTCHA_BITS>0 ==');
{
    await reset();
    const r = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain' },
        payload: 'no-captcha-token',
    });
    check('missing captcha 422', r.statusCode === 422, `got ${r.statusCode}`);
    const j = JSON.parse(r.body);
    check('detail mentions captcha', /captcha/i.test(j.detail || ''));
}

console.log('\n== Plaintext POST with bad captcha rejected ==');
{
    await reset();
    const r = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: {
            'content-type': 'text/plain',
            'x-captcha-token': 'AAAAAAAAAAAA',
            'x-captcha-nonce': 'AAAA',
        },
        payload: 'bad-captcha',
    });
    check('bad captcha 422', r.statusCode === 422, `got ${r.statusCode}`);
}

console.log('\n== Plaintext POST with valid captcha accepted ==');
{
    await reset();
    const r = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: 'valid-captcha',
    });
    check('valid captcha 201', r.statusCode === 201, `got ${r.statusCode} body=${r.body}`);
}

console.log('\n== Encrypted POST exempt from captcha ==');
{
    await reset();
    // Minimal valid v3 record (validation passes; we never decrypt).
    const record = {
        v: 3, enc: 'aes-256-gcm', mode: 'random', once: false,
        total: 1,
        chunks: [{ seq: 0, iv: 'AAAAAAAAAAAAAAAA', ct: 'A'.repeat(24) }],
        srp: { group: '2048-sha256', salt: 'AAAAAAAAAAAAAAAAAAAAAA', verifier: 'Aw' },
    };
    const r = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'application/vnd.minbin.encrypted+json' },
        payload: JSON.stringify(record),
    });
    check('encrypted POST 201 without captcha', r.statusCode === 201, r.body);
}

console.log('\n== Per-IP daily byte budget trips after cumulative 5kB ==');
{
    await reset();
    // First upload: 3kB (well under cap).
    const small1 = Buffer.alloc(3000, 'a');
    const r1 = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: small1,
    });
    check('first upload (3kB) 201', r1.statusCode === 201, r1.body);

    // Second upload: 3kB. Cumulative = 6kB, over the 5kB cap.
    const small2 = Buffer.alloc(3000, 'b');
    const r2 = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: small2,
    });
    check('second upload (6kB cum) rejected', r2.statusCode === 402, `got ${r2.statusCode}`);
    check('402 has retry-after', r2.headers['retry-after'] !== undefined);
    const j = JSON.parse(r2.body);
    check('402 detail mentions budget', /budget/i.test(j.detail || ''));
}

console.log('\n== Byte budget rolls back on rejection: small upload still works ==');
{
    await reset();
    // Push to just over the cap.
    const big = Buffer.alloc(4500, 'a');
    const r1 = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: big,
    });
    check('first 4.5kB 201', r1.statusCode === 201);
    // Try a too-big second upload: should reject AND roll back the counter.
    const tooBig = Buffer.alloc(2000, 'b');
    const r2 = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: tooBig,
    });
    check('second 2kB (would push over) rejected', r2.statusCode === 402);
    // Smaller upload that fits in remaining budget should still succeed.
    const tiny = Buffer.alloc(400, 'c');
    const r3 = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: tiny,
    });
    check('third 400B (fits) 201 (rollback worked)', r3.statusCode === 201, r3.body);
}

console.log('\n== Byte budget is NOT drained by failed-captcha attempts ==');
{
    await reset();
    // 2 unauthenticated POSTs of 4kB each (within RATE_LIMIT_POST_MAX=3).
    // Each should return 422 (captcha missing). Cumulative bytes attempted
    // = 8kB > our 5kB cap. If the captcha came AFTER the byte budget (the
    // bug we just fixed), the 4kB legit upload at the end would 402.
    for (let i = 0; i < 2; i++) {
        const r = await app.inject({
            method: 'POST',
            url: '/?relative=true',
            headers: { 'content-type': 'text/plain' },
            payload: Buffer.alloc(4000, 'x'),
        });
        check('attempt #' + i + ' rejected for missing captcha (not byte budget)',
            r.statusCode === 422, `got ${r.statusCode}`);
    }
    // Now a legitimate 4kB upload with the captcha solved should fit.
    const r = await app.inject({
        method: 'POST',
        url: '/?relative=true',
        headers: { 'content-type': 'text/plain', ...solvedCaptchaHeaders() },
        payload: Buffer.alloc(4000, 'y'),
    });
    check('legit 4kB upload 201 after 2x failed-captcha attempts (budget not drained)',
        r.statusCode === 201, `got ${r.statusCode} body=${r.body}`);
}

console.log('\n== /:id/access cap ==');
{
    await reset();
    const results = [];
    for (let i = 0; i < 6; i++) {
        results.push(await app.inject({
            method: 'POST',
            url: '/aaaaaaaaaaaaaaaa/access',
        }));
    }
    check('first 5 access bumps return 200',
        results.slice(0, 5).every((r) => r.statusCode === 200),
        results.slice(0, 5).map((r) => r.statusCode).join('/'));
    check('6th rate-limited (429)',
        results[5].statusCode === 429, `got ${results[5].statusCode}`);
}

await app.close();
await redis.quit();

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed === 0 ? 0 : 1);
