/**
 * src/utils/sri.ts
 *
 * Subresource Integrity (SRI) hash computation for vendored static assets.
 *
 * minbin vendors all third-party JS/CSS under templates/assets/vendor/. SRI
 * pins the *bytes* of those files inside every <script>/<link> tag so a
 * tampered git push, compromised CI, or (future) CDN-cached asset cannot
 * silently swap in a hostile bundle. Browsers compute the SHA-512 of the
 * fetched body and refuse to execute / apply the asset if it doesn't match.
 *
 * Hashes are computed once at server boot. The vendor directory is a small
 * fixed set of files (~5), so this is a single-digit milliseconds at startup
 * even on a cold Vercel function. We hash with SHA-512 (the strongest of the
 * three SRI-supported algorithms) and base64-encode the digest in the format
 * the spec mandates: `sha512-<base64>`.
 *
 * Bonus: every cache-busting query string in the templates (e.g.
 * `/assets/vendor/bootstrap.min.css?h=…`) is now redundant — SRI gives the
 * browser the same proof of freshness without the cache-key churn.
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export type SriMap = Readonly<Record<string, string>>;

/**
 * Recursively hash every regular file under `vendorDir`. Returns a map keyed
 * by the relative path inside `vendorDir` (e.g. 'argon2.umd.min.js' or
 * 'subdir/foo.js') with values like `sha512-<base64>`.
 */
export function computeSriMap(vendorDir: string): SriMap {
    const out: Record<string, string> = {};
    const walk = (dir: string, prefix: string): void => {
        let entries: string[];
        try {
            entries = readdirSync(dir);
        } catch {
            return; // directory missing -> empty SRI map (tests / weird setups)
        }
        for (const entry of entries) {
            const full = join(dir, entry);
            let stat;
            try {
                stat = statSync(full);
            } catch {
                continue;
            }
            if (stat.isDirectory()) {
                walk(full, prefix ? `${prefix}/${entry}` : entry);
            } else if (stat.isFile()) {
                const buf = readFileSync(full);
                const digest = createHash('sha512').update(buf).digest('base64');
                const key = prefix ? `${prefix}/${entry}` : entry;
                out[key] = `sha512-${digest}`;
            }
        }
    };
    walk(vendorDir, '');
    return Object.freeze(out);
}
