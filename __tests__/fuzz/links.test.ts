/**
 * Property tests (no dependencies, see fuzz.ts) for the Link header parser behind paginate(): the result must be the
 * target of the first link whose first rel holds `next` and that has no anchor, computed from the structure the
 * header was built from, never by parsing it again. And no input, however broken, may make it throw.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { nextLink } from '../../src/helpers/link-header.ts';
import { forAll, type Rand } from './fuzz.ts';

const TARGETS = ['/p/2', 'https://a.example/x?b=1&c=2', '', '?page=3', '#f', '/a,b;c'];
/** A rel value as written, and the tokens it carries. */
const RELS: Array<[written: string, tokens: string[]]> = [
    ['next', ['next']], ['prev', ['prev']], ['"next"', ['next']], ['"prev next"', ['prev', 'next']],
    ['"NEXT"', ['next']], ['"nextpage"', ['nextpage']], ['"next\tlast"', ['next', 'last']], ['last', ['last']],
];
/** Parameters other than rel: none of them makes a link next, whatever they contain. */
const OTHERS = ['title="a, b; rel=next"', 'title="say \\"rel=next\\""', 'type="text/html"', 'hreflang=en'];

interface Link { target: string; params: string[]; firstRel?: string[]; anchored: boolean; trailingSemicolon: boolean }

const space = (r: Rand) => r.pick(['', '', ' ', '\t', '  ']);

function link(r: Rand): Link {
    const params: string[] = [];
    let firstRel: string[] | undefined;
    let anchored = false;
    for (let i = r.int(5); i > 0; i--) {
        const kind = r.int(4);
        if (kind <= 1) {
            const [written, tokens] = r.pick(RELS);
            params.push(`${r.pick(['rel', 'REL', 'Rel'])}${space(r)}=${space(r)}${written}`);
            firstRel ??= tokens;
        } else if (kind === 2) {
            params.push('anchor="#x"');
            anchored = true;
        } else {
            params.push(r.pick(OTHERS));
        }
    }
    return { target: r.pick(TARGETS), params, firstRel, anchored, trailingSemicolon: r.chance(0.15) };
}

const serialize = (r: Rand, l: Link) =>
    `<${l.target}>${l.params.map(p => `${space(r)};${space(r)}${p}`).join('')}${l.trailingSemicolon ? `${space(r)};` : ''}`;

/** The header, as one string or (sometimes) as the array Node gives for repeated headers, and the expected answer. */
function header(r: Rand): { value: string | string[]; parts: string[]; expected: string | undefined } {
    const links = r.array(1, 5, () => link(r));
    const parts = links.map(l => serialize(r, l));
    const join = (items: string[]) => items.join(`${space(r)},${space(r)}`);
    const split = parts.length > 1 && r.chance(0.3) ? 1 + r.int(parts.length - 1) : 0;
    const value = split ? [join(parts.slice(0, split)), join(parts.slice(split))] : join(parts);
    const next = links.find(l => !l.anchored && l.firstRel?.includes('next'));
    return { value, parts, expected: next?.target };
}

/** Broken links whose damage stays inside them: the scan skips to the next comma. */
const CONTAINED = ['</x>; title=Previous Page', '</x>; =v', '</x> rel=next'];
/** Broken links that may swallow what follows (an unclosed '<' or quote): only "never throws" holds. */
const SWALLOWING = ['</x', '</x>; rel="next', '<', '"'];

describe('fuzz: Link header (RFC 8288)', () => {
    it('nextLink finds exactly the first rel=next link without an anchor', async () => {
        await forAll(header, ({ value, expected }) => {
            assert.equal(nextLink(value), expected, JSON.stringify(value));
        });
    });

    it('a broken link never hides a well-formed next after it', async () => {
        await forAll(r => ({ broken: r.pick(CONTAINED), ...header(r) }), ({ broken, parts, expected }) => {
            const value = [broken, ...parts].join(', ');
            assert.equal(nextLink(value), expected, JSON.stringify(value));
        });
    });

    it('nextLink never throws, whatever the input', async () => {
        await forAll(r => r.array(1, 8, () => r.chance(0.5) ? r.pick(SWALLOWING) : r.pick([...CONTAINED, ...TARGETS.map(t => `<${t}>`), ';', ',', '=', 'rel', '"next"', ' ', '\\'])), pieces => {
            const value = pieces.join('');
            const result = nextLink(value);
            assert.ok(result === undefined || typeof result === 'string', JSON.stringify(value));
        });
    });
});
