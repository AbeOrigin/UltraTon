// Smoke test against the PACKED tarball (what npm users actually get).
// Run with `npm run test:package`. Packs (the `prepack` hook does a clean build),
// then installs into a temp consumer -> check ESM import, CJS require and TypeScript types.
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
  'UltraTonMemoryError',
  'UltraTonNetworkError',
  'UltraTonNetworkTimeoutError',
  'UltraTonParseError',
  'UltraTonRedirectError',
  'createSecureAgents',
];
const TYPES = [
  'ReservedIpPolicy',
  'UltraTonClientOptions',
  'UltraTonRequestOptions',
  'UltraTonResponse',
  'UltraTonRetryOptions',
  'UltraTonRetryInfo',
  'UltraTonProxyOptions',
  'UltraTonSecureAgentOptions',
  'UltraTonSecureAgents',
  'UltraTonDiagnosticsRequest',
  'UltraTonDiagnosticsError',
  'UltraTonRequestStartMessage',
  'UltraTonRequestRetryMessage',
  'UltraTonRequestResponseMessage',
  'UltraTonRequestErrorMessage',
];
// Exports that existed before 2.0 and must stay gone.
const REMOVED = ['UltraTonHTTP2'];

const q = (s) => `"${s}"`; // npm is launched through the shell (npm.cmd on Windows), so quote arguments
// --dry-run=false: `npm publish --dry-run` exports npm_config_dry_run=true to lifecycle scripts,
// and nested pack/install would inherit it and write nothing. Force it off for every nested call.
// The `npm` token itself must stay unquoted: on Windows a quoted "npm" breaks npm.cmd's %~dp0.
const npm = (args, cwd) =>
  execSync(['npm', ...[...args, '--dry-run=false'].map(q)].join(' '), { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

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
  const leaked = REMOVED.filter((name) => got.includes(name));
  if (leaked.length) throw new Error(`${label}: removed exports are still present: ${JSON.stringify(leaked)}`);
  if (JSON.stringify(got) !== JSON.stringify(VALUES)) {
    throw new Error(`${label}: expected exports ${JSON.stringify(VALUES)}\n  got ${JSON.stringify(got)}`);
  }
}

try {
  const packDir = path.join(root, 'pack');
  const consumer = path.join(root, 'consumer');
  fs.mkdirSync(packDir);
  fs.mkdirSync(consumer);

  // `npm pack` runs the `prepack` hook (clean build), so the tarball never holds stale files.
  // --ignore-scripts=false forces the hook even if a .npmrc or env sets ignore-scripts=true.
  // --silent keeps the prepack build output off stdout so only the JSON is parsed.
  let tgz;
  check('npm pack', () => {
    const info = JSON.parse(npm(['pack', '--silent', '--ignore-scripts=false', '--json', '--pack-destination', packDir], repo));
    const packed = path.join(packDir, info[0].filename);
    if (!fs.existsSync(packed)) throw new Error(`tarball not found at ${packed}`);
    tgz = packed; // only set once the file exists, so a missing tarball stops the run
    // Only dist/ plus the four root files may ship, and the entry points must be there.
    const paths = info[0].files.map((f) => f.path);
    const allowed = new Set(['package.json', 'README.md', 'LICENSE', 'CHANGELOG.md']);
    const bad = paths.filter((p) => !allowed.has(p) && !p.startsWith('dist/'));
    const missing = ['dist/index.js', 'dist/index.d.ts'].filter((p) => !paths.includes(p));
    if (bad.length || missing.length) {
      throw new Error(`unexpected tarball contents
  not allowed: ${JSON.stringify(bad)}
  missing: ${JSON.stringify(missing)}`);
    }
  });
  if (!tgz) throw new Error('cannot continue without a tarball');

  fs.writeFileSync(path.join(consumer, 'package.json'), JSON.stringify({ name: 'consumer', private: true, type: 'module' }));
  check('npm install tarball', () => {
    npm(['install', tgz, '--no-audit', '--no-fund'], consumer);
  });

  check(`ESM import() exposes exactly the ${VALUES.length} value exports, without ${REMOVED.join(', ')}`, () =>
    keysCheck('import', "import('ultraton').then(m => console.log(JSON.stringify(Object.keys(m).sort())))", consumer));

  check(`CJS require() exposes exactly the ${VALUES.length} value exports, without ${REMOVED.join(', ')}`, () =>
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

const opts: UltraTonRequestOptions = { json: { a: 1 }, timeoutMs: 1000 };
const policy: ReservedIpPolicy = false;
export { opts, policy };

const clientOptions: UltraTonClientOptions = {
  baseUrl: 'https://api.example.com/v1',
  headers: { 'x-team': 'core' },
  timeoutMs: 5000,
  permitReservedIps: ['10.0.0.0/8'],
  http2: true,
  tls: { ca: '-----BEGIN CERTIFICATE-----', cert: [Buffer.from('pem')] },
  userAgent: 'consumer/1.0',
};
const client = new UltraTonClient(clientOptions);
export async function use(): Promise<number> {
  const res: UltraTonResponse<{ id: number }> = await client.get<{ id: number }>('users/1', { headers: { 'x-req': '1' } });
  await client.post('users', { json: { name: 'a' } });
  await client.close();
  return res.json().id + (res.ok ? res.statusCode : 0);
}

// @ts-expect-error certificate verification can never be turned off
export const noVerify: UltraTonClientOptions = { tls: { rejectUnauthorized: false } };
// @ts-expect-error per-request options do not take baseUrl
export const perRequestBase: UltraTonRequestOptions = { baseUrl: 'https://x.example' };

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
    // The package's own bin, not an internal path: TypeScript 7 no longer exports lib/tsc.js.
    const tsPackage = require.resolve('typescript/package.json');
    const tsc = path.join(path.dirname(tsPackage), require(tsPackage).bin.tsc);
    execFileSync(process.execPath, [tsc, '-p', consumer], { cwd: consumer, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  });
} catch (err) {
  failed = true;
  console.error(`FAIL smoke script: ${err.message}`);
} finally {
  // Windows can briefly hold files (EBUSY/EPERM), so retry the cleanup.
  fs.rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

if (failed) {
  console.error('\nPackage smoke test FAILED');
  process.exit(1);
}
console.log('\nPackage smoke test passed');
