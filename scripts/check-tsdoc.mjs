// Fails if a public symbol has no TSDoc. Run with `npm run check:tsdoc` after `npm run build`.
// Public = what dist/index.d.ts exports, plus the members of those classes, interfaces and object types (see
// public-api.mjs). Editors show these comments on hover, so they are the API reference.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { publicDeclarations } from './public-api.mjs';

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

let checked = 0;
for (const { rel, name, lines, at, members } of publicDeclarations(dist)) {
  if (at === -1) {
    missing.push(`${rel}: ${name} (declaration not found)`);
    continue;
  }
  checked++;
  if (!hasDoc(lines, at)) missing.push(`${rel}: ${name}`);
  for (const member of members) {
    checked++;
    if (!hasDoc(lines, member.at)) missing.push(`${rel}: ${name}.${member.name}`);
  }
}

if (missing.length) {
  console.error(`Public symbols without TSDoc (${missing.length}):\n  ${missing.join('\n  ')}`);
  process.exit(1);
}
console.log(`All ${checked} public symbols and members have TSDoc.`);
