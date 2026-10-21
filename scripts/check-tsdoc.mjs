// Fails if a public symbol has no TSDoc. Run with `npm run check:tsdoc` after `npm run build`.
// Public = what dist/index.d.ts exports, plus the members of those classes, interfaces and object types.
// Editors show these comments on hover, so they are the API reference.
// ponytail: a line-based scan of tsc's own .d.ts output (regular, 4-space indent); a real TS parser if that ever changes.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const missing = [];

const hasDoc = (lines, i) => {
  for (let j = i - 1; j >= 0; j--) {
    const l = lines[j].trim();
    if (l === '') continue;
    return l.endsWith('*/');
  }
  return false;
};

const toDts = (from, dir) => path.join(dir, from.replace(/\.ts$/, '.d.ts'));
let checked = 0;

function check(file, name) {
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  const rel = path.relative(dist, file).replaceAll('\\', '/');
  const decl = new RegExp(`^export (?:declare )?(?:abstract )?(?:class|function|const|interface|type) ${name}\\b`);
  const at = lines.findIndex((l) => decl.test(l));
  if (at === -1) {
    // Re-exported from another module (`import type { X } from '...'; export type { X };`): check it there.
    const from = lines.map((l) => new RegExp(`^import (?:type )?\\{[^}]*\\b${name}\\b[^}]*\\} from ["'](.+?)["']`).exec(l)).find(Boolean);
    if (from) return check(toDts(from[1], path.dirname(file)), name);
    missing.push(`${rel}: ${name} (declaration not found)`);
    return;
  }
  checked++;
  if (!hasDoc(lines, at)) missing.push(`${rel}: ${name}`);
  if (!lines[at].trimEnd().endsWith('{')) return;

  // Members: lines at 4-space indent until the closing brace at column 0.
  for (let i = at + 1; i < lines.length && !/^\}/.test(lines[i]); i++) {
    const m = /^ {4}(?!\*|\/|\}|private |protected |constructor|set |#)(?:(?:readonly|static|get|async) )*([\w$]+)/.exec(lines[i]);
    if (!m) continue;
    checked++;
    if (!hasDoc(lines, i)) missing.push(`${rel}: ${name}.${m[1]}`);
  }
}

const index = fs.readFileSync(path.join(dist, 'index.d.ts'), 'utf8');
for (const [, list, from] of index.matchAll(/export (?:type )?\{([^}]*)\} from '(.+?)'/g)) {
  for (const name of list.split(',').map((n) => n.trim()).filter(Boolean)) check(toDts(from, dist), name);
}

if (missing.length) {
  console.error(`Public symbols without TSDoc (${missing.length}):\n  ${missing.join('\n  ')}`);
  process.exit(1);
}
console.log(`All ${checked} public symbols and members have TSDoc.`);
