import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
// @ts-expect-error: a plain .mjs script, no declarations.
import { apiSnapshot } from '../scripts/check-api.mjs';

/** A throwaway dist/ and src/ in a temp directory, with the given files. */
function tree(t: TestContext, files: Record<string, string>) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ultraton-api-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    for (const [name, text] of Object.entries(files)) {
        fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
        fs.writeFileSync(path.join(root, name), text);
    }
    return { dist: path.join(root, 'dist'), src: path.join(root, 'src') };
}

const INDEX = "export { Client } from './a.ts';\nexport type { Options } from './a.ts';\n";

describe('API snapshot (scripts/check-api.mjs)', () => {
    it('ignores TSDoc-only changes', (t) => {
        const a = tree(t, {
            'dist/index.d.ts': INDEX,
            'dist/a.d.ts': '/** One. */\nexport declare class Client {\n    /** Sends. */\n    get(url: string): Promise<void>;\n}\n/** Options. */\nexport interface Options {\n    readonly x?: number;\n}\n',
            'src/a.ts': '',
        });
        const b = tree(t, {
            'dist/index.d.ts': INDEX,
            'dist/a.d.ts': '/**\n * Another wording.\n */\nexport declare class Client {\n    /** Sends, reworded. */\n    get(url: string): Promise<void>;\n}\nexport interface Options {\n    /** Doc added. */\n    readonly x?: number;\n}\n',
            'src/a.ts': '',
        });
        assert.equal(apiSnapshot(a.dist, a.src), apiSnapshot(b.dist, b.src));
    });

    it('follows a type re-exported from another module', (t) => {
        const { dist, src } = tree(t, {
            'dist/index.d.ts': "export type { Policy } from './a.ts';\n",
            'dist/a.d.ts': "import type { Policy } from './b.ts';\nexport type { Policy };\n",
            'dist/b.d.ts': '/** A policy. */\nexport type Policy = boolean | readonly string[];\n',
            'src/a.ts': '',
        });
        assert.match(apiSnapshot(dist, src), /^export type Policy = boolean \| readonly string\[\];$/m);
    });

    it('shows a changed member', (t) => {
        const before = tree(t, { 'dist/index.d.ts': INDEX, 'dist/a.d.ts': 'export declare class Client {\n}\nexport interface Options {\n    readonly x?: number;\n}\n', 'src/a.ts': '' });
        const after = tree(t, { 'dist/index.d.ts': INDEX, 'dist/a.d.ts': 'export declare class Client {\n}\nexport interface Options {\n    readonly x?: number;\n    readonly y?: string;\n}\n', 'src/a.ts': '' });
        assert.notEqual(apiSnapshot(before.dist, before.src), apiSnapshot(after.dist, after.src));
        assert.match(apiSnapshot(after.dist, after.src), /readonly y\?: string;/);
    });

    it('lists every error code once, sorted', (t) => {
        const { dist, src } = tree(t, {
            'dist/index.d.ts': '',
            'src/a.ts': "throw new E('x', { code: 'ERR_ULTRATON_B' });\nconst c = 'ERR_ULTRATON_B';\n",
            'src/nested/b.ts': 'const d = "ERR_ULTRATON_A";\n',
        });
        const snapshot = apiSnapshot(dist, src);
        assert.match(snapshot, /^## error codes\nERR_ULTRATON_A\nERR_ULTRATON_B\n?$/m);
        assert.equal(snapshot.match(/ERR_ULTRATON_B/g)?.length, 1);
    });
});
