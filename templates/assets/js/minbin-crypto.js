/*
 * minbin-crypto.js
 *
 * End-to-end encryption for minbin pastes. Loaded as a plain <script>.
 * Skiff-aligned protocol with three modes:
 *
 *   1. random  — 256-bit link_key in URL fragment. HKDF splits it into
 *                an enc_key (AES-GCM) and an auth_key (SRP password). The
 *                server can only return ciphertext after a successful SRP-6a
 *                handshake using auth_key.
 *
 *   2. password — Argon2id(passphrase, kdfSalt) → master. HKDF splits master
 *                 into enc_key + auth_key. Server holds an SRP verifier so
 *                 the ciphertext+salt are not handed out for offline brute
 *                 force on a Redis dump (Skiff §3.2 / §6.5).
 *
 *   3. pubkey  — Encrypt to one or more recipients' published X25519 public
 *                keys. Two shapes (server accepts both):
 *                  - legacy single-recipient: ECDH(ephemeral, recipient.pub)
 *                    -> HKDF -> enc_key. encrypt body with enc_key directly.
 *                  - multi-recipient (Skiff §6.5): random per-paste content_key
 *                    encrypts the body. For each recipient, generate an
 *                    ephemeral keypair, ECDH+HKDF -> kek, then AES-GCM-wrap
 *                    content_key under kek. Each recipient unwraps using
 *                    their private key.
 *
 * Body is gzipped and split into authenticated chunks (Skiff §7). Each
 * chunk's AAD binds its sequence number, the total chunk count, and a
 * "final" flag, so the server cannot reorder, drop, or duplicate chunks
 * without breaking AES-GCM authentication.
 *
 * Loaded globals:
 *   hashwasm.argon2id  (templates/assets/vendor/argon2.umd.min.js)
 *   crypto.subtle      (WebCrypto, all evergreen browsers + Node 20)
 *
 * Vendoring policy: hash-wasm is vendored under templates/assets/vendor/
 * because a CDN compromise would otherwise leak every user's password.
 * Subresource Integrity (SRI sha512) is enforced on every <script>/<link>
 * tag pointing at /assets/vendor/, so a tampered git push cannot swap in a
 * different bundle either.
 */
(function () {
    'use strict';

    var ARGON2_PARAMS = Object.freeze({
        parallelism: 1,
        iterations: 3,
        memorySize: 65536, // 64 MiB
        hashLength: 32,
    });

    // Body is split into chunks of this size before encryption. Smaller
    // pastes still produce a single chunk; the chunking machinery is just
    // a tag-binding mechanism for those.
    var CHUNK_PLAINTEXT_BYTES = 64 * 1024;

    var INFO_ENC = 'minbin/v3/enc';
    var INFO_AUTH = 'minbin/v3/auth';
    var INFO_BOX = 'minbin/v3/box';
    var INFO_WRAP = 'minbin/v3/wrap';
    var CHUNK_AAD_PREFIX = 'minbin/v3/chunk';
    var WRAP_AAD = 'minbin/v3/wrap-aad';

    function getCrypto() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto;
        }
        throw new Error('WebCrypto unavailable in this environment');
    }

    function toBytes(input) {
        if (input instanceof Uint8Array) return input;
        if (input instanceof ArrayBuffer) return new Uint8Array(input);
        if (typeof input === 'string') return new TextEncoder().encode(input);
        throw new TypeError('expected Uint8Array | ArrayBuffer | string');
    }

    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        var diff = 0;
        for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    function concatBytes() {
        var total = 0;
        for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
        var out = new Uint8Array(total);
        var off = 0;
        for (var j = 0; j < arguments.length; j++) {
            out.set(arguments[j], off);
            off += arguments[j].length;
        }
        return out;
    }

    function be32(n) {
        if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
            throw new RangeError('be32: out of range');
        }
        var b = new Uint8Array(4);
        b[0] = (n >>> 24) & 0xff;
        b[1] = (n >>> 16) & 0xff;
        b[2] = (n >>> 8) & 0xff;
        b[3] = n & 0xff;
        return b;
    }

    function be64(n) {
        // n: BigInt
        var hex = n.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        if (hex.length > 16) throw new RangeError('be64: out of range');
        hex = hex.padStart(16, '0');
        var out = new Uint8Array(8);
        for (var i = 0; i < 8; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }

    // base64url (RFC 4648 §5) without padding.
    function b64uEncode(bytes) {
        var u8 = toBytes(bytes);
        var s = '';
        for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        var b64 = btoa(s);
        return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function b64uDecode(str) {
        if (typeof str !== 'string') throw new TypeError('b64uDecode: expected string');
        if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('b64uDecode: invalid characters');
        var b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        var pad = (4 - (b64.length % 4)) % 4;
        b64 += '='.repeat(pad);
        var bin = atob(b64);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function randomBytes(n) {
        // WebCrypto.getRandomValues has a 64 KiB cap per call (Web Crypto API
        // §10.7). Chunk for callers that need larger buffers (mostly tests).
        var out = new Uint8Array(n);
        var c = getCrypto();
        var off = 0;
        while (off < n) {
            var slice = out.subarray(off, Math.min(off + 65536, n));
            c.getRandomValues(slice);
            off += slice.length;
        }
        return out;
    }

    var PASSPHRASE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    function generatePassphrase() {
        var raw = randomBytes(24);
        var chars = '';
        for (var i = 0; i < 24; i++) {
            chars += PASSPHRASE_ALPHABET[raw[i] & 0x1F];
        }
        return chars.replace(/(.{4})(?=.)/g, '$1-');
    }

    function normalizePassphrase(s) {
        if (typeof s !== 'string') return '';
        var trimmed = s.trim();
        var compact = trimmed.replace(/-/g, '').toUpperCase();
        if (/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{24}$/.test(compact)) {
            return compact;
        }
        return trimmed;
    }

    async function gzip(bytes) {
        if (typeof CompressionStream === 'undefined') return bytes;
        var cs = new CompressionStream('gzip');
        var blob = new Blob([bytes]);
        var compressed = await new Response(blob.stream().pipeThrough(cs)).arrayBuffer();
        return new Uint8Array(compressed);
    }

    async function gunzip(bytes) {
        if (bytes.length < 2 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) return bytes;
        if (typeof DecompressionStream === 'undefined') {
            throw new Error('DecompressionStream unavailable');
        }
        var ds = new DecompressionStream('gzip');
        var blob = new Blob([bytes]);
        var out = await new Response(blob.stream().pipeThrough(ds)).arrayBuffer();
        return new Uint8Array(out);
    }

    async function importAesKey(rawKey) {
        if (rawKey.length !== 32) throw new Error('AES key must be 32 bytes');
        return getCrypto().subtle.importKey(
            'raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
        );
    }

    async function deriveKeyArgon2id(password, salt, params) {
        if (typeof password !== 'string' || password.length === 0) {
            throw new Error('password must be a non-empty string');
        }
        if (!(salt instanceof Uint8Array) || salt.length !== 16) {
            throw new Error('salt must be 16 bytes');
        }
        if (typeof globalThis.hashwasm === 'undefined' || !globalThis.hashwasm.argon2id) {
            throw new Error('Argon2id unavailable: hash-wasm not loaded');
        }
        var p = params || ARGON2_PARAMS;
        return globalThis.hashwasm.argon2id({
            password: password,
            salt: salt,
            parallelism: p.parallelism != null ? p.parallelism : ARGON2_PARAMS.parallelism,
            iterations: p.iterations != null ? p.iterations : ARGON2_PARAMS.iterations,
            memorySize: p.memorySize != null ? p.memorySize : ARGON2_PARAMS.memorySize,
            hashLength: p.hashLength != null ? p.hashLength : ARGON2_PARAMS.hashLength,
            outputType: 'binary',
        });
    }

    /**
     * HKDF-SHA256 expand into a 32-byte key keyed by `master`, with no
     * salt and a context-specific `info` label. We use HKDF here exactly
     * like Skiff §3.2: one Argon2id (or random) master, then HKDF expansions
     * for each downstream key (enc_key, auth_key, box session key).
     */
    async function hkdfExpand32(master, info) {
        var c = getCrypto();
        var key = await c.subtle.importKey(
            'raw', master, { name: 'HKDF' }, false, ['deriveBits'],
        );
        var bits = await c.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(0),
                info: typeof info === 'string' ? new TextEncoder().encode(info) : info,
            },
            key,
            256,
        );
        return new Uint8Array(bits);
    }

    /**
     * Build the AAD for chunk #seq of a `total`-chunk paste. AES-GCM tags
     * cover this so the server cannot reorder, drop, or alter chunk
     * boundaries without breaking decryption.
     */
    function chunkAAD(seq, total) {
        var prefix = new TextEncoder().encode(CHUNK_AAD_PREFIX);
        var finalByte = new Uint8Array([seq === total - 1 ? 1 : 0]);
        return concatBytes(prefix, be32(seq), be32(total), finalByte);
    }

    async function encryptChunks(plaintext, encKey) {
        var pt = toBytes(plaintext);
        var compressed = await gzip(pt);
        var total = Math.max(1, Math.ceil(compressed.length / CHUNK_PLAINTEXT_BYTES));
        var key = await importAesKey(encKey);
        var chunks = [];
        for (var i = 0; i < total; i++) {
            var start = i * CHUNK_PLAINTEXT_BYTES;
            var slice = compressed.slice(start, start + CHUNK_PLAINTEXT_BYTES);
            var iv = randomBytes(12);
            var aad = chunkAAD(i, total);
            var ct = new Uint8Array(
                await getCrypto().subtle.encrypt(
                    { name: 'AES-GCM', iv: iv, additionalData: aad },
                    key,
                    slice,
                ),
            );
            chunks.push({ seq: i, iv: b64uEncode(iv), ct: b64uEncode(ct) });
        }
        return { total: total, chunks: chunks };
    }

    async function decryptChunks(chunks, total, encKey) {
        if (!Array.isArray(chunks)) throw new Error('chunks not array');
        if (chunks.length !== total) throw new Error('chunk count mismatch');
        var key = await importAesKey(encKey);
        var pieces = [];
        for (var i = 0; i < total; i++) {
            var c = chunks[i];
            if (!c || c.seq !== i) throw new Error('chunk[' + i + '] out of order');
            var iv = b64uDecode(String(c.iv));
            var ct = b64uDecode(String(c.ct));
            if (iv.length !== 12) throw new Error('chunk iv wrong length');
            var aad = chunkAAD(i, total);
            // AES-GCM auth fails here if the server (or any MITM) reordered,
            // dropped, or altered any chunk: the AAD bound to (seq, total,
            // final) won't match.
            var pt = new Uint8Array(
                await getCrypto().subtle.decrypt(
                    { name: 'AES-GCM', iv: iv, additionalData: aad },
                    key,
                    ct,
                ),
            );
            pieces.push(pt);
        }
        var totalLen = 0;
        for (var j = 0; j < pieces.length; j++) totalLen += pieces[j].length;
        var combined = new Uint8Array(totalLen);
        var off = 0;
        for (var k = 0; k < pieces.length; k++) {
            combined.set(pieces[k], off);
            off += pieces[k].length;
        }
        return gunzip(combined);
    }

    // ============================================================
    // SRP-6a (RFC 5054 group 2048, SHA-256)
    // ============================================================
    // Mirror of src/utils/srp.ts. Constants are identical -- if you change
    // one, change the other. We use BigInt arithmetic in-browser since all
    // evergreen browsers have BigInt and modPow() runs in milliseconds for
    // 2048-bit operands.
    var SRP_N_HEX = (
        'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050' +
        'A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50' +
        'E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8' +
        '55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B' +
        'CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748' +
        '544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6' +
        'AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6' +
        '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'
    );
    var SRP_N = BigInt('0x' + SRP_N_HEX);
    var SRP_g = 2n;
    var SRP_N_BYTES = 256;

    function modPow(base, exp, mod) {
        var result = 1n;
        var b = ((base % mod) + mod) % mod;
        var e = exp;
        while (e > 0n) {
            if (e & 1n) result = (result * b) % mod;
            e >>= 1n;
            b = (b * b) % mod;
        }
        return result;
    }

    function bigIntToFixedBE(n, byteLen) {
        if (n < 0n) throw new RangeError('negative bigint');
        var hex = n.toString(16);
        if (hex.length > byteLen * 2) throw new RangeError('bigint too large');
        if (hex.length % 2) hex = '0' + hex;
        hex = hex.padStart(byteLen * 2, '0');
        var out = new Uint8Array(byteLen);
        for (var i = 0; i < byteLen; i++) {
            out[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return out;
    }

    function bigIntToMinBE(n) {
        if (n < 0n) throw new RangeError('negative bigint');
        if (n === 0n) return new Uint8Array([0]);
        var hex = n.toString(16);
        if (hex.length % 2) hex = '0' + hex;
        var out = new Uint8Array(hex.length / 2);
        for (var i = 0; i < out.length; i++) {
            out[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return out;
    }

    function bytesToBigInt(bytes) {
        if (bytes.length === 0) return 0n;
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, '0');
        }
        return BigInt('0x' + hex);
    }

    async function sha256(/* ...parts */) {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) parts.push(arguments[i]);
        var combined = concatBytes.apply(null, parts);
        var d = await getCrypto().subtle.digest('SHA-256', combined);
        return new Uint8Array(d);
    }

    /**
     * Client-side SRP. Caller provides `salt` (server-supplied) and `password`
     * (a Uint8Array — for paste flows this is the HKDF-derived auth_key, or
     * a 32-byte link_key for random-key mode).
     *
     * Returns:
     *   {
     *     A:  Uint8Array (big-endian, minimal-length),
     *     M1: (B: Uint8Array) -> Promise<Uint8Array>     // call after server replies with B
     *     verifyM2: (B, M1, M2) -> Promise<boolean>      // verify server's proof
     *   }
     */
    async function srpClientStart() {
        // 256 bits of entropy for `a`. RFC says >= 256 bits.
        var aBytes = randomBytes(32);
        var a = bytesToBigInt(aBytes);
        if (a === 0n) a = 1n; // astronomically unlikely
        var A = modPow(SRP_g, a, SRP_N);
        var padN = bigIntToFixedBE(SRP_N, SRP_N_BYTES);
        var padG = bigIntToFixedBE(SRP_g, SRP_N_BYTES);

        return {
            A_bigint: A,
            A_bytes: bigIntToMinBE(A),
            a: a,
            padN: padN,
            padG: padG,
        };
    }

    /**
     * Compute M1 given the server's B and the salt+password. Returns
     * { M1, K } so the caller can later check M2 = H(PAD(A) || M1 || K).
     */
    async function srpClientStep2(state, B_bytes, salt, password) {
        var B = bytesToBigInt(B_bytes);
        if (B % SRP_N === 0n) throw new Error('SRP abort: B mod N is zero');

        var padA = bigIntToFixedBE(state.A_bigint, SRP_N_BYTES);
        var padB = bigIntToFixedBE(B, SRP_N_BYTES);

        var u = bytesToBigInt(await sha256(padA, padB));
        if (u === 0n) throw new Error('SRP abort: u is zero');

        var k = bytesToBigInt(await sha256(state.padN, state.padG));
        var x = bytesToBigInt(await sha256(salt, password));

        var gx = modPow(SRP_g, x, SRP_N);
        var Bdiff = ((B - (k * gx) % SRP_N) % SRP_N + SRP_N) % SRP_N;
        var S = modPow(Bdiff, state.a + u * x, SRP_N);
        var padS = bigIntToFixedBE(S, SRP_N_BYTES);
        var K = await sha256(padS);

        var HN = await sha256(state.padN);
        var Hg = await sha256(state.padG);
        var HNxorHg = new Uint8Array(32);
        for (var i = 0; i < 32; i++) HNxorHg[i] = HN[i] ^ Hg[i];
        var HI = await sha256(new Uint8Array(0));

        var M1 = await sha256(HNxorHg, HI, salt, padA, padB, K);

        return { M1: M1, K: K, padA: padA };
    }

    async function srpClientVerifyM2(M2, padA, M1, K) {
        var expected = await sha256(padA, M1, K);
        return bytesEqual(expected, M2);
    }

    // ============================================================
    // Pubkey wrap / unwrap (X25519 ECDH + HKDF + AES-GCM)
    // ============================================================

    /**
     * Generate a content key + per-recipient wrapped-key entries. Each
     * recipient gets a fresh ephemeral keypair (forward secrecy per recipient).
     *
     * Returns:
     *   { contentKey: Uint8Array(32), recipients: [{pubkey, epk, wrappedKey, wrapIv}] }
     */
    async function buildWrappedRecipients(recipientPubkeys) {
        if (!Array.isArray(recipientPubkeys) || recipientPubkeys.length === 0) {
            throw new Error('recipientPubkeys must be a non-empty array');
        }
        var c = getCrypto();
        var contentKey = randomBytes(32);
        var contentKeyAesKey = await c.subtle.importKey(
            'raw', contentKey, { name: 'AES-GCM' }, false, ['encrypt'],
        );
        var wrapAad = new TextEncoder().encode(WRAP_AAD);
        var out = [];
        for (var i = 0; i < recipientPubkeys.length; i++) {
            var pubBytes = recipientPubkeys[i];
            if (!(pubBytes instanceof Uint8Array) || pubBytes.length !== 32) {
                throw new Error('recipientPubkeys[' + i + '] must be 32 bytes');
            }
            var ephemeral = await c.subtle.generateKey(
                { name: 'X25519' }, true, ['deriveBits'],
            );
            var recipientPub = await c.subtle.importKey(
                'raw', pubBytes, { name: 'X25519' }, false, [],
            );
            var sharedBits = await c.subtle.deriveBits(
                { name: 'X25519', public: recipientPub },
                ephemeral.privateKey,
                256,
            );
            var kek = await hkdfExpand32(new Uint8Array(sharedBits), INFO_WRAP);
            var kekKey = await c.subtle.importKey(
                'raw', kek, { name: 'AES-GCM' }, false, ['encrypt'],
            );
            var wrapIv = randomBytes(12);
            var wrapped = new Uint8Array(
                await c.subtle.encrypt(
                    { name: 'AES-GCM', iv: wrapIv, additionalData: wrapAad },
                    kekKey,
                    contentKey,
                ),
            );
            void contentKeyAesKey; // silence unused warning
            var epkRaw = new Uint8Array(
                await c.subtle.exportKey('raw', ephemeral.publicKey),
            );
            out.push({
                pubkey: b64uEncode(pubBytes),
                epk: b64uEncode(epkRaw),
                wrappedKey: b64uEncode(wrapped),
                wrapIv: b64uEncode(wrapIv),
            });
        }
        return { contentKey: contentKey, recipients: out };
    }

    /**
     * Find the wrapped-key entry for a given recipient pubkey and unwrap
     * the content key. Throws if the recipient is not in the list, or
     * if AES-GCM authentication fails.
     */
    async function unwrapRecipientKey(recipients, ownPubBytes, ownPrivKey) {
        var c = getCrypto();
        var ownPubB64 = b64uEncode(ownPubBytes);
        for (var i = 0; i < recipients.length; i++) {
            var entry = recipients[i];
            if (entry.pubkey !== ownPubB64) continue;
            var epk = b64uDecode(entry.epk);
            if (epk.length !== 32) throw new Error('epk malformed');
            var ephemeralPub = await c.subtle.importKey(
                'raw', epk, { name: 'X25519' }, false, [],
            );
            var sharedBits = await c.subtle.deriveBits(
                { name: 'X25519', public: ephemeralPub },
                ownPrivKey,
                256,
            );
            var kek = await hkdfExpand32(new Uint8Array(sharedBits), INFO_WRAP);
            var kekKey = await c.subtle.importKey(
                'raw', kek, { name: 'AES-GCM' }, false, ['decrypt'],
            );
            var wrapped = b64uDecode(entry.wrappedKey);
            var iv = b64uDecode(entry.wrapIv);
            if (iv.length !== 12) throw new Error('wrapIv malformed');
            var wrapAad = new TextEncoder().encode(WRAP_AAD);
            var contentKey = new Uint8Array(
                await c.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv, additionalData: wrapAad },
                    kekKey,
                    wrapped,
                ),
            );
            if (contentKey.length !== 32) throw new Error('content key wrong length');
            return contentKey;
        }
        throw new Error('your pubkey is not in the recipients list');
    }

    // ============================================================
    // High-level encrypt/decrypt API
    // ============================================================

    /**
     * Build an SRP verifier from a salt and a password (Uint8Array).
     * Used at upload time so the browser can hand the server only the
     * verifier and never the raw password material.
     */
    async function srpVerifier(salt, password) {
        var x = bytesToBigInt(await sha256(salt, password));
        return modPow(SRP_g, x, SRP_N);
    }

    /**
     * Encrypt plaintext into an encrypted record.
     *
     * opts:
     *   mode: 'random' | 'password' | 'pubkey'
     *   password?: string                    (mode='password')
     *   recipientPubkey?: Uint8Array(32)     (mode='pubkey', legacy single)
     *   recipientPubkeys?: Uint8Array(32)[]  (mode='pubkey', new multi)
     *   once?: boolean
     *   maxAccesses?: integer (1..1000)
     *
     * Returns:
     *   { record, link_key? (mode='random'), salt? (mode='password'),
     *     fingerprint? (mode='pubkey'), ephemeralKey? (legacy single only) }
     */
    async function encrypt(plaintext, opts) {
        opts = opts || {};
        var pt = toBytes(plaintext);
        if (pt.length === 0) throw new Error('plaintext is empty');

        var record = {
            v: 3,
            enc: 'aes-256-gcm',
            mode: opts.mode || 'random',
            once: !!opts.once,
        };

        // Optional max-access cap. Server enforces the upper bound; client
        // checks for sanity to fail fast on programming errors.
        if (opts.maxAccesses !== undefined && opts.maxAccesses !== null) {
            var ma = Number(opts.maxAccesses);
            if (!Number.isInteger(ma) || ma < 1 || ma > 1000) {
                throw new Error('maxAccesses must be an integer in [1, 1000]');
            }
            record.maxAccesses = ma;
        }

        var encKey;
        var out = { record: record };

        if (record.mode === 'random') {
            var linkKey = randomBytes(32);
            encKey = await hkdfExpand32(linkKey, INFO_ENC);
            var authKey = await hkdfExpand32(linkKey, INFO_AUTH);
            var srpSalt = randomBytes(16);
            record.srp = {
                group: '2048-sha256',
                salt: b64uEncode(srpSalt),
                verifier: b64uEncode(bigIntToMinBE(await srpVerifier(srpSalt, authKey))),
            };
            out.link_key = linkKey;
        } else if (record.mode === 'password') {
            if (typeof opts.password !== 'string' || opts.password.length === 0) {
                throw new Error('password required');
            }
            var kdfSalt = randomBytes(16);
            var master = await deriveKeyArgon2id(opts.password, kdfSalt);
            encKey = await hkdfExpand32(master, INFO_ENC);
            var authKey2 = await hkdfExpand32(master, INFO_AUTH);
            var srpSalt2 = randomBytes(16);
            record.kdf = 'argon2id';
            record.kdfSalt = b64uEncode(kdfSalt);
            record.argon2 = {
                m: ARGON2_PARAMS.memorySize,
                t: ARGON2_PARAMS.iterations,
                p: ARGON2_PARAMS.parallelism,
            };
            record.srp = {
                group: '2048-sha256',
                salt: b64uEncode(srpSalt2),
                verifier: b64uEncode(bigIntToMinBE(await srpVerifier(srpSalt2, authKey2))),
            };
            out.salt = kdfSalt;
        } else if (record.mode === 'pubkey') {
            // New shape: opts.recipientPubkeys (array). Fallback to legacy
            // single-recipient opts.recipientPubkey for callers that haven't
            // upgraded.
            var pubList = null;
            if (Array.isArray(opts.recipientPubkeys) && opts.recipientPubkeys.length > 0) {
                pubList = opts.recipientPubkeys;
            } else if (opts.recipientPubkey instanceof Uint8Array) {
                pubList = [opts.recipientPubkey];
            } else {
                throw new Error('recipientPubkey(s) required for pubkey mode');
            }
            if (pubList.length > 16) throw new Error('too many recipients (max 16)');
            // Reject duplicates client-side for a clearer error than the
            // server's "duplicate pubkey" rejection.
            var seenPubs = Object.create(null);
            for (var p = 0; p < pubList.length; p++) {
                var key = b64uEncode(pubList[p]);
                if (seenPubs[key]) throw new Error('duplicate recipient pubkey');
                seenPubs[key] = true;
            }
            var built = await buildWrappedRecipients(pubList);
            encKey = built.contentKey;
            record.recipients = built.recipients;
            // Best-effort fingerprint of the first recipient (UI convenience).
            out.fingerprints = [];
            for (var f = 0; f < pubList.length; f++) {
                out.fingerprints.push(await fingerprintPubkey(pubList[f]));
            }
            if (out.fingerprints.length > 0) out.fingerprint = out.fingerprints[0];
        } else {
            throw new Error('unknown mode');
        }

        var encrypted = await encryptChunks(pt, encKey);
        record.total = encrypted.total;
        record.chunks = encrypted.chunks;

        return out;
    }

    /**
     * Decrypt a record (after a successful SRP handshake or pubkey
     * decryption setup). Caller provides the `enc_key` directly.
     */
    async function decrypt(record, encKey) {
        if (!record || record.v !== 3 || record.enc !== 'aes-256-gcm') {
            throw new Error('unsupported record');
        }
        return decryptChunks(record.chunks, record.total, encKey);
    }

    /**
     * Derive the (enc_key, auth_key) pair for a password-mode header
     * fetched from /raw/:id. The header carries kdfSalt + argon2 params.
     */
    async function derivePasswordKeys(passphrase, header) {
        var normalized = normalizePassphrase(passphrase);
        if (!normalized) throw new Error('empty passphrase');
        var kdfSalt = b64uDecode(header.kdfSalt);
        if (kdfSalt.length !== 16) throw new Error('kdfSalt malformed');
        var p = header.argon2 || {};
        var master = await deriveKeyArgon2id(normalized, kdfSalt, {
            memorySize: p.m,
            iterations: p.t,
            parallelism: p.p,
            hashLength: 32,
        });
        var encKey = await hkdfExpand32(master, INFO_ENC);
        var authKey = await hkdfExpand32(master, INFO_AUTH);
        return { encKey: encKey, authKey: authKey };
    }

    function deriveRandomKeys(linkKey) {
        // hkdfExpand32 is async; wrap callers don't need a sync path here.
        return Promise.all([
            hkdfExpand32(linkKey, INFO_ENC),
            hkdfExpand32(linkKey, INFO_AUTH),
        ]).then(function (pair) {
            return { encKey: pair[0], authKey: pair[1] };
        });
    }

    /**
     * Derive the enc_key for a pubkey-mode record. Supports both the legacy
     * single-recipient shape and the new multi-recipient wrapped-key shape.
     *
     * `identity` is { pub: Uint8Array(32), priv: Uint8Array, keyPair: { privateKey: CryptoKey } }
     */
    async function derivePubkeyEnc(record, identity) {
        var c = getCrypto();
        if (Array.isArray(record.recipients)) {
            // Multi-recipient shape (new).
            return unwrapRecipientKey(
                record.recipients,
                identity.pub,
                identity.keyPair.privateKey,
            );
        }
        if (record.recipient && typeof record.recipient.epk === 'string') {
            // Legacy single-recipient shape: enc_key = HKDF(ECDH(my, epk), INFO_BOX).
            var epk = b64uDecode(record.recipient.epk);
            if (epk.length !== 32) throw new Error('epk malformed');
            var ephemeralPub = await c.subtle.importKey(
                'raw', epk, { name: 'X25519' }, false, [],
            );
            var shared = await c.subtle.deriveBits(
                { name: 'X25519', public: ephemeralPub },
                identity.keyPair.privateKey,
                256,
            );
            return hkdfExpand32(new Uint8Array(shared), INFO_BOX);
        }
        throw new Error('record has neither recipients[] nor recipient');
    }

    /**
     * Public-key fingerprint for out-of-band verification (Skiff §11). We
     * return the first 16 bytes of SHA-256(pubkey) formatted as 8 groups of
     * 4 hex chars. This is the same UX as Signal's safety numbers, just at
     * a smaller display size suitable for a paste-share link.
     */
    async function fingerprintPubkey(pubkey) {
        var d = await getCrypto().subtle.digest('SHA-256', toBytes(pubkey));
        var u8 = new Uint8Array(d).slice(0, 16);
        var hex = '';
        for (var i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, '0');
        return hex.toUpperCase().match(/.{1,4}/g).join(' ');
    }

    // ============================================================
    // Captcha (proof-of-work) solver
    // ============================================================

    /**
     * Solve a server-issued PoW token: find a 64-bit nonce such that
     * SHA-256(rand_part_of_token || nonce) has at least `bits` leading zero
     * bits. The "rand part" is the 16 bytes following the version byte +
     * timestamp inside the token; we don't need to parse the token's MAC
     * because the server re-extracts the same bytes server-side.
     *
     * Cooperative: yields control to the event loop every 4096 iterations
     * so a slow CPU + high `bits` doesn't freeze the page during paste.
     */
    async function solveCaptcha(token, bits) {
        if (!bits || bits <= 0) return '';
        var raw = b64uDecode(token);
        if (raw.length < 1 + 8 + 16 + 32) throw new Error('captcha token malformed');
        // version (1) + ts (8) + rand (16) + mac (32). We hash with rand only
        // (server contract).
        var rand = raw.subarray(1 + 8, 1 + 8 + 16);
        var c = getCrypto();
        var byteCount = bits >> 3;
        var bitRemainder = bits & 7;
        var mask = bitRemainder === 0 ? 0xff : (0xff << (8 - bitRemainder)) & 0xff;

        var counter = 0n;
        while (true) {
            var nonce = be64(counter);
            var h = new Uint8Array(await c.subtle.digest('SHA-256', concatBytes(rand, nonce)));
            var ok = true;
            for (var i = 0; i < byteCount; i++) {
                if (h[i] !== 0) { ok = false; break; }
            }
            if (ok && bitRemainder !== 0 && (h[byteCount] & mask) !== 0) ok = false;
            if (ok) return b64uEncode(nonce);
            counter += 1n;
            if ((counter & 0xfffn) === 0n) {
                // Yield so we don't lock the UI thread on slow phones at
                // ~20-bit difficulty (~1M iterations).
                await new Promise(function (r) { setTimeout(r, 0); });
            }
        }
    }

    /**
     * Fetch + solve a captcha challenge. Returns { token, nonce } or
     * { token: '', nonce: '' } when CAPTCHA_BITS=0 server-side.
     */
    async function solveCaptchaForUpload(progressCb) {
        var resp = await fetch('/captcha', {
            method: 'GET',
            headers: { Accept: 'application/json' },
            credentials: 'omit',
        });
        if (!resp.ok) throw new Error('captcha fetch failed (' + resp.status + ')');
        var body = await resp.json();
        if (!body || typeof body.token !== 'string') throw new Error('captcha response malformed');
        if (!body.bits || body.bits <= 0) return { token: '', nonce: '' };
        if (typeof progressCb === 'function') progressCb(body.bits);
        var nonce = await solveCaptcha(body.token, body.bits);
        return { token: body.token, nonce: nonce };
    }

    // ============================================================
    // Fragment helpers
    // ============================================================
    function parseFragment(frag) {
        var out = Object.create(null);
        if (!frag) return out;
        if (frag.charAt(0) === '#') frag = frag.slice(1);
        if (frag.length === 0) return out;
        var parts = frag.split('&');
        for (var i = 0; i < parts.length; i++) {
            var eq = parts[i].indexOf('=');
            var k, v;
            if (eq < 0) { k = parts[i]; v = ''; }
            else { k = parts[i].slice(0, eq); v = parts[i].slice(eq + 1); }
            try { k = decodeURIComponent(k); v = decodeURIComponent(v); } catch (_) {}
            out[k] = v;
        }
        return out;
    }

    function buildFragment(params) {
        var keys = Object.keys(params);
        var parts = [];
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            var v = params[k];
            if (v == null) continue;
            parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
        }
        return parts.join('&');
    }

    // ============================================================
    // Identity (pubkey mode): persistent X25519 keypair stored in localStorage.
    // ============================================================
    var IDENTITY_STORAGE_KEY = 'minbin.identity.v1';

    async function generateIdentity() {
        var c = getCrypto();
        var kp = await c.subtle.generateKey(
            { name: 'X25519' }, true, ['deriveBits'],
        );
        var pub = new Uint8Array(await c.subtle.exportKey('raw', kp.publicKey));
        var priv = new Uint8Array(await c.subtle.exportKey('pkcs8', kp.privateKey));
        return { pub: pub, priv: priv, keyPair: kp };
    }

    function saveIdentity(identity) {
        if (typeof localStorage === 'undefined') return;
        localStorage.setItem(
            IDENTITY_STORAGE_KEY,
            JSON.stringify({
                pub: b64uEncode(identity.pub),
                priv: b64uEncode(identity.priv),
                created: Date.now(),
            }),
        );
    }

    async function loadIdentity() {
        if (typeof localStorage === 'undefined') return null;
        var s = localStorage.getItem(IDENTITY_STORAGE_KEY);
        if (!s) return null;
        var obj;
        try { obj = JSON.parse(s); } catch (_) { return null; }
        if (!obj || !obj.pub || !obj.priv) return null;
        var pub = b64uDecode(obj.pub);
        var priv = b64uDecode(obj.priv);
        var c = getCrypto();
        try {
            var privKey = await c.subtle.importKey(
                'pkcs8', priv, { name: 'X25519' }, true, ['deriveBits'],
            );
            var pubKey = await c.subtle.importKey(
                'raw', pub, { name: 'X25519' }, true, [],
            );
            return { pub: pub, priv: priv, keyPair: { privateKey: privKey, publicKey: pubKey } };
        } catch (e) {
            return null;
        }
    }

    function clearIdentity() {
        if (typeof localStorage === 'undefined') return;
        localStorage.removeItem(IDENTITY_STORAGE_KEY);
    }

    var api = {
        // High-level
        encrypt: encrypt,
        decrypt: decrypt,
        derivePasswordKeys: derivePasswordKeys,
        deriveRandomKeys: deriveRandomKeys,
        derivePubkeyEnc: derivePubkeyEnc,
        fingerprintPubkey: fingerprintPubkey,

        // Low-level
        deriveKeyArgon2id: deriveKeyArgon2id,
        hkdfExpand32: hkdfExpand32,
        encryptChunks: encryptChunks,
        decryptChunks: decryptChunks,

        // Pubkey wrap helpers (exposed for tests)
        buildWrappedRecipients: buildWrappedRecipients,
        unwrapRecipientKey: unwrapRecipientKey,

        // SRP
        srpClientStart: srpClientStart,
        srpClientStep2: srpClientStep2,
        srpClientVerifyM2: srpClientVerifyM2,
        srpVerifier: srpVerifier,
        bigIntToMinBE: bigIntToMinBE,
        bytesToBigInt: bytesToBigInt,

        // Identity (pubkey mode)
        generateIdentity: generateIdentity,
        saveIdentity: saveIdentity,
        loadIdentity: loadIdentity,
        clearIdentity: clearIdentity,

        // Captcha
        solveCaptcha: solveCaptcha,
        solveCaptchaForUpload: solveCaptchaForUpload,

        // Utilities
        generatePassphrase: generatePassphrase,
        normalizePassphrase: normalizePassphrase,
        b64uEncode: b64uEncode,
        b64uDecode: b64uDecode,
        randomBytes: randomBytes,
        parseFragment: parseFragment,
        buildFragment: buildFragment,
        bytesEqual: bytesEqual,
        ARGON2_PARAMS: ARGON2_PARAMS,
        PASSPHRASE_ALPHABET: PASSPHRASE_ALPHABET,
        CHUNK_PLAINTEXT_BYTES: CHUNK_PLAINTEXT_BYTES,
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    } else {
        globalThis.MinbinCrypto = api;
    }
})();
