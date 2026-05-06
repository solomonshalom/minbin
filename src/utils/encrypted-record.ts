/**
 * src/utils/encrypted-record.ts
 *
 * Validation for encrypted paste records (Skiff-aligned wire format, v3).
 *
 * The server is zero-knowledge: it never sees plaintext or keys. But it does
 * need to validate the *shape* of submitted records so it can store them with
 * a TTL and serve them back, and so it can refuse obviously-malformed payloads
 * before they hit Redis.
 *
 *   {
 *     v: 3,
 *     enc: 'aes-256-gcm',
 *     mode: 'random' | 'password' | 'pubkey',
 *
 *     // password mode only:
 *     kdf:   'argon2id',
 *     kdfSalt: base64url(16B),
 *     argon2:  { m, t, p },
 *
 *     // SRP gate (random + password modes):
 *     srp: { group: '2048-sha256', salt: base64url(16B), verifier: base64url(<=256B) },
 *
 *     // pubkey mode (legacy, single recipient direct ECDH):
 *     recipient: { pubkey: b64u(32B), epk: b64u(32B) },
 *
 *     // pubkey mode (new, multi-recipient with wrapped content key — Skiff §6.5):
 *     recipients: [
 *       { pubkey: b64u(32B), epk: b64u(32B),
 *         wrappedKey: b64u(>=16B), wrapIv: b64u(12B) },
 *       ...
 *     ],
 *
 *     // chunked authenticated body:
 *     total: int,
 *     chunks: [ { seq, iv: b64u(12B), ct: b64u(...) }, ... ],
 *
 *     once: boolean,
 *     // optional max-access cap (1..MAX_ACCESS_COUNT). Counter is server-side;
 *     // the paste is deleted on the call that pushes the counter to >= cap.
 *     maxAccesses?: number
 *   }
 *
 * What we check (conservative):
 *   - JSON is a plain object with the expected shape.
 *   - Every base64url field decodes to the expected length.
 *   - Total ciphertext (sum across chunks) does not exceed MAX_PASTE_SIZE.
 *   - Mode-specific fields are present iff their mode demands them.
 *
 * What we do NOT check (cannot, by design): that any ciphertext decrypts to
 * anything sensible. AES-GCM authentication runs entirely client-side.
 */

const BASE64URL = /^[A-Za-z0-9_-]*$/;

export const ENCRYPTED_CONTENT_TYPE = 'application/vnd.minbin.encrypted+json';

export interface EncryptedChunk {
    seq: number;
    iv: string;
    ct: string;
}

export interface SrpGate {
    group: '2048-sha256';
    salt: string;
    verifier: string;
}

export interface Argon2Params {
    m: number; // memory in KiB
    t: number; // iterations
    p: number; // parallelism
}

export interface RecipientFields {
    pubkey: string;
    epk: string;
}

export interface WrappedRecipient {
    pubkey: string;
    epk: string;
    wrappedKey: string;
    wrapIv: string;
}

export interface EncryptedRecord {
    v: 3;
    enc: 'aes-256-gcm';
    mode: 'random' | 'password' | 'pubkey';
    kdf?: 'argon2id';
    kdfSalt?: string;
    argon2?: Argon2Params;
    srp?: SrpGate;
    recipient?: RecipientFields;
    recipients?: WrappedRecipient[];
    total: number;
    chunks: EncryptedChunk[];
    once: boolean;
    maxAccesses?: number;
}

function decodedLength(b64url: string): number {
    const n = b64url.length;
    if (n === 0) return 0;
    const tail = n % 4;
    if (tail === 1) return -1;
    const fullGroups = Math.floor(n / 4);
    if (tail === 0) return fullGroups * 3;
    if (tail === 2) return fullGroups * 3 + 1;
    return fullGroups * 3 + 2;
}

function isB64u(s: unknown): s is string {
    return typeof s === 'string' && BASE64URL.test(s);
}

function asObject(raw: unknown): Record<string, unknown> {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        throw new Error('record must be a JSON object');
    }
    return raw as Record<string, unknown>;
}

function parseSrpGate(raw: unknown): SrpGate {
    const r = asObject(raw);
    if (r.group !== '2048-sha256') throw new Error('unsupported srp group');
    if (!isB64u(r.salt)) throw new Error('invalid srp.salt');
    if (decodedLength(r.salt) !== 16) throw new Error('srp.salt must decode to 16 bytes');
    if (!isB64u(r.verifier)) throw new Error('invalid srp.verifier');
    const vBytes = decodedLength(r.verifier);
    // Verifier is a value mod N where N is 2048 bits = 256 bytes. We accept
    // anything from 1..256 bytes (clients may strip leading zeros). The full
    // range check (1 <= v < N) happens server-side at SRP init using the
    // BigInt parsed from the bytes.
    if (vBytes <= 0 || vBytes > 256) throw new Error('srp.verifier wrong length');
    return { group: '2048-sha256', salt: r.salt, verifier: r.verifier };
}

function parseArgon2(raw: unknown): Argon2Params {
    const r = asObject(raw);
    const m = r.m;
    const t = r.t;
    const p = r.p;
    if (typeof m !== 'number' || !Number.isInteger(m) || m < 8 || m > 1024 * 1024) {
        throw new Error('argon2.m out of range');
    }
    if (typeof t !== 'number' || !Number.isInteger(t) || t < 1 || t > 64) {
        throw new Error('argon2.t out of range');
    }
    if (typeof p !== 'number' || !Number.isInteger(p) || p < 1 || p > 16) {
        throw new Error('argon2.p out of range');
    }
    return { m, t, p };
}

function parseRecipient(raw: unknown): RecipientFields {
    const r = asObject(raw);
    if (!isB64u(r.pubkey)) throw new Error('invalid recipient.pubkey');
    if (decodedLength(r.pubkey) !== 32) throw new Error('recipient.pubkey must decode to 32 bytes');
    if (!isB64u(r.epk)) throw new Error('invalid recipient.epk');
    if (decodedLength(r.epk) !== 32) throw new Error('recipient.epk must decode to 32 bytes');
    return { pubkey: r.pubkey, epk: r.epk };
}

function parseWrappedRecipient(raw: unknown): WrappedRecipient {
    const r = asObject(raw);
    if (!isB64u(r.pubkey)) throw new Error('invalid recipients[].pubkey');
    if (decodedLength(r.pubkey) !== 32) throw new Error('recipients[].pubkey must decode to 32 bytes');
    if (!isB64u(r.epk)) throw new Error('invalid recipients[].epk');
    if (decodedLength(r.epk) !== 32) throw new Error('recipients[].epk must decode to 32 bytes');
    if (!isB64u(r.wrappedKey)) throw new Error('invalid recipients[].wrappedKey');
    // 32-byte content key + 16-byte AES-GCM tag = 48 bytes minimum, allow some
    // headroom since the client may vary AAD. Cap at 256 bytes to keep the
    // wire format predictable.
    const wkBytes = decodedLength(r.wrappedKey);
    if (wkBytes < 16 || wkBytes > 256) throw new Error('recipients[].wrappedKey wrong length');
    if (!isB64u(r.wrapIv)) throw new Error('invalid recipients[].wrapIv');
    if (decodedLength(r.wrapIv) !== 12) throw new Error('recipients[].wrapIv must decode to 12 bytes');
    return {
        pubkey: r.pubkey,
        epk: r.epk,
        wrappedKey: r.wrappedKey,
        wrapIv: r.wrapIv,
    };
}

function parseRecipients(raw: unknown, maxRecipients: number): WrappedRecipient[] {
    if (!Array.isArray(raw)) throw new Error('recipients must be an array');
    if (raw.length === 0) throw new Error('recipients must be non-empty');
    if (raw.length > maxRecipients) {
        throw new Error(`recipients length exceeds max (${maxRecipients})`);
    }
    const seen = new Set<string>();
    const out: WrappedRecipient[] = [];
    for (let i = 0; i < raw.length; i++) {
        const r = parseWrappedRecipient(raw[i]);
        // Recipient pubkey duplicates would be a misconfigured client; reject
        // so we don't silently drop wrapped keys on the read side.
        if (seen.has(r.pubkey)) {
            throw new Error(`recipients[${i}].pubkey duplicates an earlier entry`);
        }
        seen.add(r.pubkey);
        out.push(r);
    }
    return out;
}

function parseChunks(raw: unknown, expectedTotal: number, maxBytes: number): EncryptedChunk[] {
    if (!Array.isArray(raw)) throw new Error('chunks must be an array');
    if (raw.length === 0) throw new Error('chunks must be non-empty');
    if (raw.length !== expectedTotal) {
        throw new Error(`chunks.length (${raw.length}) does not match total (${expectedTotal})`);
    }
    let totalBytes = 0;
    const out: EncryptedChunk[] = [];
    for (let i = 0; i < raw.length; i++) {
        const c = asObject(raw[i]);
        if (c.seq !== i) {
            throw new Error(`chunk[${i}].seq must equal ${i}, got ${String(c.seq)}`);
        }
        if (!isB64u(c.iv)) throw new Error(`chunk[${i}].iv invalid`);
        if (decodedLength(c.iv) !== 12) {
            throw new Error(`chunk[${i}].iv must decode to 12 bytes`);
        }
        if (!isB64u(c.ct)) throw new Error(`chunk[${i}].ct invalid`);
        const ctBytes = decodedLength(c.ct);
        if (ctBytes < 16) throw new Error(`chunk[${i}].ct too short`);
        totalBytes += ctBytes;
        if (totalBytes > maxBytes) {
            throw new Error('total ciphertext across chunks exceeds maximum');
        }
        out.push({ seq: i, iv: c.iv, ct: c.ct });
    }
    return out;
}

export interface ParseOptions {
    /** Defaults to 16 to cover most team-sharing scenarios. */
    maxRecipients?: number;
    /** Defaults to 1000; a hard ceiling regardless of client choice. */
    maxAccessCount?: number;
}

export function parseEncryptedRecord(
    raw: unknown,
    maxCiphertextBytes: number,
    opts: ParseOptions = {},
): EncryptedRecord {
    const r = asObject(raw);
    if (r.v !== 3) throw new Error('unsupported version');
    if (r.enc !== 'aes-256-gcm') throw new Error('unsupported cipher');

    const mode = r.mode;
    if (mode !== 'random' && mode !== 'password' && mode !== 'pubkey') {
        throw new Error('unsupported mode');
    }
    if (typeof r.once !== 'boolean') throw new Error('once must be boolean');
    if (typeof r.total !== 'number' || !Number.isInteger(r.total) || r.total < 1 || r.total > 4096) {
        throw new Error('total must be an integer in [1, 4096]');
    }

    const maxAccessCap = opts.maxAccessCount ?? 1000;
    let maxAccesses: number | undefined;
    if (r.maxAccesses !== undefined) {
        if (
            typeof r.maxAccesses !== 'number' ||
            !Number.isInteger(r.maxAccesses) ||
            r.maxAccesses < 1 ||
            r.maxAccesses > maxAccessCap
        ) {
            throw new Error(`maxAccesses must be an integer in [1, ${maxAccessCap}]`);
        }
        maxAccesses = r.maxAccesses;
    }

    const out: EncryptedRecord = {
        v: 3,
        enc: 'aes-256-gcm',
        mode,
        total: r.total,
        chunks: parseChunks(r.chunks, r.total, maxCiphertextBytes),
        once: r.once,
    };
    if (maxAccesses !== undefined) out.maxAccesses = maxAccesses;

    if (mode === 'password') {
        if (r.kdf !== 'argon2id') throw new Error('password mode requires kdf=argon2id');
        if (!isB64u(r.kdfSalt)) throw new Error('invalid kdfSalt');
        if (decodedLength(r.kdfSalt) !== 16) throw new Error('kdfSalt must decode to 16 bytes');
        out.kdf = 'argon2id';
        out.kdfSalt = r.kdfSalt;
        out.argon2 = parseArgon2(r.argon2);
    } else {
        if (r.kdf !== undefined) throw new Error('kdf must be absent outside password mode');
        if (r.kdfSalt !== undefined) throw new Error('kdfSalt must be absent outside password mode');
        if (r.argon2 !== undefined) throw new Error('argon2 must be absent outside password mode');
    }

    if (mode === 'random' || mode === 'password') {
        if (r.srp === undefined) throw new Error(`${mode} mode requires srp gate`);
        out.srp = parseSrpGate(r.srp);
        if (r.recipient !== undefined) {
            throw new Error('recipient must be absent outside pubkey mode');
        }
        if (r.recipients !== undefined) {
            throw new Error('recipients must be absent outside pubkey mode');
        }
    } else {
        if (r.srp !== undefined) throw new Error('srp must be absent in pubkey mode');
        // Pubkey mode supports two shapes:
        //   - legacy single-recipient: `recipient: {pubkey, epk}` with the
        //     content key derived directly from ECDH(epk, recipient.pub).
        //   - new multi-recipient:    `recipients: [{pubkey, epk, wrappedKey,
        //     wrapIv}]` where each entry wraps the same content key with a
        //     per-recipient KEK derived from ECDH+HKDF.
        // Exactly one of the two must be present.
        const hasLegacy = r.recipient !== undefined;
        const hasMulti = r.recipients !== undefined;
        if (hasLegacy && hasMulti) {
            throw new Error('pubkey mode cannot set both recipient and recipients');
        }
        if (!hasLegacy && !hasMulti) {
            throw new Error('pubkey mode requires recipient or recipients');
        }
        if (hasLegacy) {
            out.recipient = parseRecipient(r.recipient);
        } else {
            out.recipients = parseRecipients(r.recipients, opts.maxRecipients ?? 16);
        }
    }

    return out;
}

export function isEncryptedRecord(raw: unknown): raw is EncryptedRecord {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return false;
    const r = raw as Record<string, unknown>;
    return r.v === 3 && r.enc === 'aes-256-gcm';
}

/**
 * Build the JSON body that GET /raw/:id should return.
 *
 * - random / password modes are SRP-gated. The client must complete SRP-6a
 *   before the server hands over the ciphertext. /raw/ returns ONLY the
 *   parameters the client needs to compute its SRP A and (for password
 *   mode) derive its keys -- not the chunks, not the verifier.
 *
 * - pubkey mode is gated by recipient X25519 private-key possession. There
 *   is no SRP layer; the ciphertext is opaque without the matching
 *   private key. /raw/ returns the full record so the recipient's browser
 *   can locate its wrapped key entry and decrypt.
 */
export function publicView(record: EncryptedRecord): unknown {
    if (record.mode === 'pubkey') {
        // Strip nothing; pubkey-mode pastes are opaque to the world.
        return record;
    }
    const out: Record<string, unknown> = {
        v: 3,
        enc: 'aes-256-gcm',
        mode: record.mode,
        total: record.total,
        once: record.once,
    };
    if (record.maxAccesses !== undefined) out.maxAccesses = record.maxAccesses;
    if (record.mode === 'password') {
        out.kdf = record.kdf;
        out.kdfSalt = record.kdfSalt;
        out.argon2 = record.argon2;
    }
    if (record.srp) {
        out.srpSalt = record.srp.salt;
    }
    return out;
}
