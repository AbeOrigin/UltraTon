// The public API as tsc wrote it: what dist/index.d.ts exports, found in the .d.ts that declares it (following
// re-exports), with the members of classes, interfaces and object types. Shared by check-tsdoc.mjs and check-api.mjs.
// ponytail: a line-based scan of tsc's own .d.ts output (regular, 4-space indent); a real TS parser if that ever changes.
import fs from 'node:fs';
import path from 'node:path';

const toDts = (from, dir) => path.join(dir, from.replace(/\.ts$/, '.d.ts'));

/**
 * Every public declaration: `{ rel, name, lines, at, end, members }`, where `lines` are its file's lines, `at` the
 * declaration line and `end` its last line (both -1 when the declaration was not found), and `members` the
 * `{ name, at }` of each member line at 4-space indent.
 */
export function publicDeclarations(dist) {
  const found = [];

  function visit(file, name) {
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    const rel = path.relative(dist, file).replaceAll('\\', '/');
    const decl = new RegExp(`^export (?:declare )?(?:abstract )?(?:class|function|const|interface|type) ${name}\\b`);
    const at = lines.findIndex((l) => decl.test(l));
    if (at === -1) {
      // Re-exported from another module (`import type { X } from '...'; export type { X };`): look there.
      const from = lines.map((l) => new RegExp(`^import (?:type )?\\{[^}]*\\b${name}\\b[^}]*\\} from ["'](.+?)["']`).exec(l)).find(Boolean);
      if (from) return visit(toDts(from[1], path.dirname(file)), name);
      found.push({ rel, name, lines, at: -1, end: -1, members: [] });
      return;
    }
    let end = at;
    const members = [];
    if (lines[at].trimEnd().endsWith('{')) {
      // A body: up to the closing brace at column 0.
      while (end + 1 < lines.length && !/^\}/.test(lines[end + 1])) {
        end++;
        const m = /^ {4}(?!\*|\/|\}|private |protected |constructor|set |#)(?:(?:readonly|static|get|async) )*([\w$]+)/.exec(lines[end]);
        if (m) members.push({ name: m[1], at: end });
      }
      end++;
    } else {
      // One statement, possibly over several lines (a long union type).
      while (end < lines.length - 1 && !lines[end].trimEnd().endsWith(';')) end++;
    }
    found.push({ rel, name, lines, at, end, members });
  }

  const index = fs.readFileSync(path.join(dist, 'index.d.ts'), 'utf8');
  for (const [, list, from] of index.matchAll(/export (?:type )?\{([^}]*)\} from '(.+?)'/g)) {
    for (const name of list.split(',').map((n) => n.trim()).filter(Boolean)) visit(toDts(from, dist), name);
  }
  return found;
}
