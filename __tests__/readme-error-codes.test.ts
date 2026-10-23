/**
 * Q11: the README's "Troubleshooting by error code" table lists every code UltraTon raises. The codes come from the
 * same scan the API gate uses (scripts/public-api.txt), so a code added to the source without a row fails here.
 */
import { it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

it('the troubleshooting table has a row for every error code in the API snapshot', () => {
    const snapshot = fs.readFileSync(path.join(root, 'scripts', 'public-api.txt'), 'utf8').replace(/\r\n/g, '\n');
    const codes = snapshot.slice(snapshot.indexOf('## error codes')).split('\n').slice(1).filter(Boolean);
    assert.ok(codes.length >= 10, 'the snapshot lists the codes');
    const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
    const table = readme.slice(readme.indexOf('### Troubleshooting by error code'), readme.indexOf('## Recipes'));
    for (const code of codes) assert.match(table, new RegExp(`^\\| \`${code}\``, 'm'), `${code} has a row`);
});
