/**
 * src/utils/srp.ts
 *
 * Server-side SRP-6a (RFC 5054 / RFC 2945) using the 2048-bit group with
 * SHA-256 as the hash. No third-party dependencies -- BigInt + node:crypto.
 *
 * Why SRP at all on a pastebin?
 *
 * Skiff's whitepaper §6.5 ("Link sharing a document") uses SRP so that the
 * server only stores a salt+verifier per shareable link and the client must
 * prove knowledge of the link key via a zero-knowledge handshake before the
 * server returns the ciphertext.
 *
 * For minbin this gives two concrete improvements over the previous
 * "ciphertext is fetchable by anyone who guesses the 16-bit ID" model:
 *
 *   1. Casual ID-guessers (the keyspace is only 2^16) cannot exfiltrate the
 *      ciphertext + Argon2id salt, then offline-brute-force passwords. They
 *      have to interact with the server, which can rate-limit.
 *   2. A passive network observer of a successful SRP exchange cannot use
 *      the captured handshake to brute-force the password offline.
 *
 * SRP does NOT defeat an attacker who has compromised Redis directly: with
 * the verifier in hand they can still attempt offline password guessing.
 * The Argon2id step continues to be the cost barrier in that case.
 *
 * Constants are RFC 5054 Group 2048 ("Group 14") with g=2.
 *
 * Hash conventions:
 *   - H(x)        = SHA-256(x)
 *   - PAD(x, N)   = big-endian bytes of x, left-padded with zeros to byte_len(N)
 *   - k           = H(PAD(N) || PAD(g))                       (SRP-6a "k")
 *   - x           = H(salt || password)                       (we feed auth_key as password)
 *   - v           = g^x mod N                                 (verifier)
 *   - A           = g^a mod N                                 (client ephemeral)
 *   - B           = (k*v + g^b) mod N                         (server ephemeral)
 *   - u           = H(PAD(A) || PAD(B))
 *   - S (server)  = (A * v^u)^b mod N
 *   - K           = H(PAD(S))
 *   - M1          = H(H(N) XOR H(PAD(g)) || H('') || salt || PAD(A) || PAD(B) || K)
 *   - M2          = H(PAD(A) || M1 || K)
 *
 * We use H(I) = H('') because there is no user identity associated with a
 * paste -- each paste's verifier is independent.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// RFC 5054 Group 2048 prime, g = 2. 512 hex digits = 2048 bits.
const N_HEX = (
    'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050' +
    'A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50' +
    'E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8' +
    '55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B' +
    'CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748' +
    '544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6' +
    'AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6' +
    '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'
);

export const SRP_GROUP = '2048-sha256' as const;
export const N: bigint = BigInt('0x' + N_HEX);
export const g: bigint = 2n;
export const N_BYTE_LEN = 256;
export const HASH_BYTE_LEN = 32;

export function bigIntToFixedBE(n: bigint, byteLen: number): Buffer {
    if (n < 0n) throw new RangeError('negative bigint');
    let hex = n.toString(16);
    if (hex.length > byteLen * 2) {
        throw new RangeError(`bigint exceeds ${byteLen} bytes`);
    }
    if (hex.length % 2 === 1) hex = '0' + hex;
    const padded = hex.padStart(byteLen * 2, '0');
    return Buffer.from(padded, 'hex');
}

export function bigIntToMinBE(n: bigint): Buffer {
    if (n < 0n) throw new RangeError('negative bigint');
    if (n === 0n) return Buffer.from([0]);
    let hex = n.toString(16);
    if (hex.length % 2 === 1) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
}

export function bytesToBigInt(buf: Buffer | Uint8Array): bigint {
    if (buf.length === 0) return 0n;
    return BigInt('0x' + Buffer.from(buf).toString('hex'));
}

function H(...parts: (Buffer | Uint8Array)[]): Buffer {
    const h = createHash('sha256');
    for (const p of parts) h.update(p);
    return h.digest();
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    if (mod <= 0n) throw new RangeError('mod must be positive');
    let result = 1n;
    let b = ((base % mod) + mod) % mod;
    let e = exp;
    while (e > 0n) {
        if (e & 1n) result = (result * b) % mod;
        e >>= 1n;
        b = (b * b) % mod;
    }
    return result;
}

const PAD_N = bigIntToFixedBE(N, N_BYTE_LEN);
const PAD_g = bigIntToFixedBE(g, N_BYTE_LEN);
const HN = H(PAD_N);
const Hg = H(PAD_g);
const HN_XOR_Hg = (() => {
    const out = Buffer.alloc(HASH_BYTE_LEN);
    for (let i = 0; i < HASH_BYTE_LEN; i++) out[i] = HN[i] ^ Hg[i];
    return out;
})();
const k_BIG = bytesToBigInt(H(PAD_N, PAD_g));
const HI_EMPTY = H(Buffer.alloc(0));

/**
 * Compute the SRP "x" value from a salt and password (RFC 5054 §2.5.3).
 * For a paste, "password" is the 32-byte HKDF-derived auth_key (see
 * minbin-crypto.js). The SRP server only ever sees the verifier `v = g^x`.
 */
export function srpX(salt: Buffer, password: Buffer): bigint {
    return bytesToBigInt(H(salt, password));
}

/**
 * Given a salt + password, compute the verifier the server should store.
 * Used by the integration tests; live records always carry the verifier
 * already computed by the browser.
 */
export function srpVerifierFromPassword(salt: Buffer, password: Buffer): bigint {
    const x = srpX(salt, password);
    return modPow(g, x, N);
}

export interface SrpServerInit {
    b: bigint;
    B: bigint;
}

/**
 * Server-side step 1: pick a fresh `b`, compute `B = (k*v + g^b) mod N`.
 * Repeats until B != 0 (per RFC 5054 §2.5.3 -- B == 0 mod N is forbidden).
 *
 * `b` is sampled by full-width rejection: draw 256 random bytes (matching the
 * 2048-bit modulus), parse as BigInt, accept iff in [1, N-1]. This eliminates
 * the modulo bias of `randomBytes(32) % (N-1) + 1`. The acceptance rate is
 * ~80% per draw, so the expected number of redraws is < 2.
 */
export function srpServerInit(verifier: bigint): SrpServerInit {
    if (verifier <= 0n || verifier >= N) {
        throw new Error('invalid verifier');
    }
    for (let attempt = 0; attempt < 32; attempt++) {
        const b = bytesToBigInt(randomBytes(N_BYTE_LEN));
        if (b <= 0n || b >= N) continue;
        const B = (k_BIG * verifier + modPow(g, b, N)) % N;
        if (B !== 0n) return { b, B };
    }
    throw new Error('failed to pick valid b after 32 attempts'); // astronomically unlikely
}

/**
 * Server-side step 2: validate client's M1 and produce M2.
 *
 * Throws on any abort condition (A == 0 mod N, M1 mismatch, etc.). On
 * success returns the session key K and the server-side proof M2 to send
 * back to the client.
 */
export function srpServerVerify(args: {
    A: bigint;
    b: bigint;
    B: bigint;
    verifier: bigint;
    salt: Buffer;
    M1: Buffer;
}): { M2: Buffer; K: Buffer } {
    const { A, b, B, verifier, salt, M1 } = args;
    if (A % N === 0n) throw new Error('SRP abort: A is zero mod N');
    if (B % N === 0n) throw new Error('SRP abort: B is zero mod N');

    const padA = bigIntToFixedBE(A, N_BYTE_LEN);
    const padB = bigIntToFixedBE(B, N_BYTE_LEN);
    const u = bytesToBigInt(H(padA, padB));
    if (u === 0n) throw new Error('SRP abort: u is zero');

    // S = (A * v^u) ^ b mod N
    const Av = (A * modPow(verifier, u, N)) % N;
    const S = modPow(Av, b, N);

    const padS = bigIntToFixedBE(S, N_BYTE_LEN);
    const K = H(padS);

    const expectedM1 = H(HN_XOR_Hg, HI_EMPTY, salt, padA, padB, K);

    if (
        M1.length !== expectedM1.length ||
        !timingSafeEqual(M1, expectedM1)
    ) {
        throw new Error('SRP abort: client proof mismatch');
    }

    const M2 = H(padA, M1, K);
    return { M2, K };
}

/**
 * Validate that a base64url-decoded verifier is in range [1, N-1] before
 * accepting it for storage.
 */
export function isValidVerifier(verifier: bigint): boolean {
    return verifier > 0n && verifier < N;
}
