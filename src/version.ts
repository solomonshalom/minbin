/**
 * src/version.ts
 *
 * Reads the application version from package.json.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function getVersion(): string {
    try {
        const pkgPath = resolve(process.cwd(), 'package.json');
        const raw = readFileSync(pkgPath, 'utf-8');
        const pkg = JSON.parse(raw) as { version?: unknown };
        if (typeof pkg.version === 'string' && pkg.version.length > 0) {
            return pkg.version;
        }
    } catch {
        // fall through
    }
    return '0.0.0';
}
