// Smoke test against the PACKED tarball (what npm users actually get).
// Run with `npm run test:package`. Builds first, then: pack -> install into a
// temp consumer -> check ESM import, CJS require and TypeScript types.
// Only Node built-ins plus the repo's own `typescript` are used.
import { execFileSync, execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

const VALUES = [
  'SecureHttpError',
  'UltraTonClient',
  'UltraTonHTTP2',
  'UltraTonMemoryError',
  'UltraTonNetworkTimeoutError',
  'UltraTonParseError',
  'UltraTonRedirectError',
];
const TYPES = [
  'ReservedIpPolicy',
  'UltraTonOptionsHttp2',
  'UltraTonRequestOptions',
  'UltraTonRequestOptionsHttp2',
  'UltraTonResponse',
];

const q = (s) => `"${s}"`; // npm is launched through the shell (npm.cmd on Windows), so quote arguments
const npm = (args, cwd) =>
  execSync(['npm', ...args.map(q)].join(' '), { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ultraton-smoke-'));
let failed = false;

// Run one check; print a pass line or the reason it failed.
function check(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (err) {
    failed = true;
    const out = [err.message, err.stdout, err.stderr].filter(Boolean).join('\n').trim();
    console.error(`FAIL ${name}\n${out.replace(/^/gm, '    ')}`);
  }
}

// node -e in the consumer dir; prints the sorted exported keys as JSON, we compare.
function keysCheck(label, code, consumer) {
  const out = execFileSync(process.execPath, ['-e', code], { cwd: consumer, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const got = JSON.parse(out);
  if (JSON.stringify(got) !== JSON.stringify(VALUES)) {
    throw new Error(`${label}: expected exports ${JSON.stringify(VALUES)}\n  got ${JSON.stringify(got)}`);
  }
}

try {
  const packDir = path.join(root, 'pack');
  const consumer = path.join(root, 'consumer');
  fs.mkdirSync(packDir);
  fs.mkdirSync(consumer);

  // Until a prepack hook exists, make sure the tarball contains a fresh build.
  npm(['run', 'build'], repo);

  let tgz;
  check('npm pack', () => {
    const info = JSON.parse(npm(['pack', '--json', '--pack-destination', packDir], repo));
    tgz = path.join(packDir, info[0].filename);
    if (!fs.existsSync(tgz)) throw new Error(`tarball not found at ${tgz}`);
  });
  if (!tgz) throw new Error('cannot continue without a tarball');

  fs.writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({ name: 'consumer', private: true, type: 'module' }));
  check('npm install tarball', () => {
    npm(['install', tgz, '--no-audit', '--no-fund'], consumer);
  });

  check('ESM import() exposes exactly the 7 value exports', () =>
    keysCheck('import', "import('ultraton').then(m => console.log(JSON.stringify(Object.keys(m).sort())))", consumer));

  check('CJS require() exposes exactly the 7 value exports', () =>
    keysCheck('require', "console.log(JSON.stringify(Object.keys(require('ultraton')).sort()))", consumer));

  check('TypeScript (nodenext, strict) resolves values and types', () => {
    fs.writeFileSync(
      path.join(consumer, 'consumer.ts'),
      `import {
  ${VALUES.join(',\n  ')},
  type ${TYPES.join(',\n  type ')},
} from 'ultraton';

export const values = [${VALUES.join(', ')}];
export type Types = [${TYPES.map((t) => (t === 'UltraTonResponse' ? `${t}<unknown>` : t)).join(', ')}];

const opts: UltraTonRequestOptions = { method: 'GET' };
const policy: ReservedIpPolicy = false;
export { opts, policy };

export function classify(err: unknown): string {
  if (err instanceof UltraTonMemoryError) return 'memory';
  if (err instanceof SecureHttpError) return 'secure';
  return 'other';
}
`,
    );
    fs.writeFileSync(
      path.join(consumer, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          module: 'nodenext',
          moduleResolution: 'nodenext',
          target: 'ES2022',
          strict: true,
          noEmit: true,
          types: ['node'],
          typeRoots: [path.join(repo, 'node_modules', '@types')],
        },
        files: ['consumer.ts'],
      }),
    );
    const tsc = require.resolve('typescript/lib/tsc.js');
    execFileSync(process.execPath, [tsc, '-p', consumer], { cwd: consumer, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  });
} catch (err) {
  failed = true;
  console.error(`FAIL smoke script: ${err.message}`);
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

if (failed) {
  console.error('\nPackage smoke test FAILED');
  process.exit(1);
}
console.log('\nPackage smoke test passed');
