// Fails if the public API or the set of error codes differs from scripts/public-api.txt. Run with `npm run check:api`
// after `npm run build`; `node scripts/check-api.mjs --update` rewrites the snapshot after an intended change, so the
// change shows up in review as a diff of that file. TSDoc is left out: rewording a comment is not an API change.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { publicDeclarations } from './public-api.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const snapshotFile = path.join(root, 'scripts', 'public-api.txt');

/** The declaration lines with comments and blank lines removed, trailing spaces trimmed. */
function withoutComments(lines) {
  const kept = [];
  let inComment = false;
  for (const line of lines) {
    const text = line.trim();
    if (inComment) {
      if (text.includes('*/')) inComment = false;
      continue;
    }
    if (text.startsWith('/*')) {
      inComment = !text.includes('*/');
      continue;
    }
    if (text === '' || text.startsWith('//')) continue;
    kept.push(line.trimEnd());
  }
  return kept;
}

const sourceFiles = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
  const full = path.join(dir, entry.name);
  if (entry.isDirectory()) return sourceFiles(full);
  return entry.name.endsWith('.ts') ? [full] : [];
});

/** The snapshot: one section per public symbol (sorted by name), then every `ERR_ULTRATON_*` code an error is raised with in `src`. */
export function apiSnapshot(dist, src) {
  const sections = publicDeclarations(dist)
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(({ rel, name, lines, at, end }) => {
      const body = at === -1 ? ['(declaration not found)'] : withoutComments(lines.slice(at, end + 1));
      return [`## ${name} (${rel})`, ...body].join('\n');
    });
  const codes = new Set();
  for (const file of sourceFiles(src)) {
    // The codes errors are raised with (`code: '...'`): not ones a comment documents or a comparison checks, which
    // would keep listing a code nothing raises any more.
    for (const [, code] of fs.readFileSync(file, 'utf8').matchAll(/\bcode:\s*['"](ERR_ULTRATON_[A-Z0-9_]+)['"]/g)) codes.add(code);
  }
  sections.push(['## error codes', ...[...codes].sort()].join('\n'));
  return `${sections.join('\n\n')}\n`;
}

function main() {
  const current = apiSnapshot(path.join(root, 'dist'), path.join(root, 'src'));
  if (process.argv.includes('--update')) {
    fs.writeFileSync(snapshotFile, current);
    console.log(`Wrote ${path.relative(root, snapshotFile)}.`);
    return;
  }
  const expected = fs.existsSync(snapshotFile) ? fs.readFileSync(snapshotFile, 'utf8').replace(/\r\n/g, '\n') : '';
  if (current === expected) {
    console.log('The public API and the error codes match scripts/public-api.txt.');
    return;
  }
  // Only the first difference: after an added or removed line every later one shifts. The full diff is
  // `git diff scripts/public-api.txt` after --update.
  const a = expected.split('\n');
  const b = current.split('\n');
  let i = 0;
  while (a[i] === b[i]) i++;
  const section = b.slice(0, i + 1).reverse().find((line) => line.startsWith('## ')) ?? '(top)';
  console.error([
    'The public API or the error codes changed. If that is intended, run `node scripts/check-api.mjs --update`,',
    `review \`git diff scripts/public-api.txt\` and commit it. First difference, in ${section} (line ${i + 1}):`,
    `  snapshot: ${a[i] ?? '(end)'}`,
    `  now:      ${b[i] ?? '(end)'}`,
  ].join('\n'));
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
