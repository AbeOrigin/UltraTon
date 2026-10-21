// tchar of RFC 9110 5.6.2: what a parameter name or an unquoted value is made of.
const TOKEN_CHARS = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const isToken = (char: string | undefined): boolean => char !== undefined && TOKEN_CHARS.includes(char);

/**
 * The target of the first link whose `rel` holds `next` in a `Link` header (RFC 8288), as written (it may be relative),
 * or `undefined`. The header comes from the server, so it is read in one linear scan with no regex. A malformed link
 * is skipped up to the next ',' and the scan goes on, so it never hides a later `rel="next"`. A link with an `anchor`
 * is about another resource, not this page, and is ignored.
 */
export function nextLink(header: string | string[] | undefined): string | undefined {
    const value = Array.isArray(header) ? header.join(', ') : header;
    if (typeof value !== 'string') return undefined;
    let i = 0;
    const skipSpace = () => { while (value[i] === ' ' || value[i] === '\t') i++; };
    const readToken = () => { const start = i; while (isToken(value[i])) i++; return value.slice(start, i); };

    /** One link from `<`: its target when it is this page's next, `undefined` when it is not, `null` when malformed. */
    const readLink = (): string | undefined | null => {
        if (value[i] !== '<') return null;
        const end = value.indexOf('>', i + 1);
        if (end === -1) return null;
        const target = value.slice(i + 1, end).trim();
        i = end + 1;
        let rel: string | undefined;
        let anchored = false;
        for (;;) {
            skipSpace();
            if (i >= value.length || value[i] === ',') break;
            if (value[i] !== ';') return null;
            i++;
            skipSpace();
            // A trailing ';' with no parameter after it.
            if (i >= value.length || value[i] === ',') break;
            const name = readToken().toLowerCase();
            if (name === '') return null;
            skipSpace();
            let param = '';
            if (value[i] === '=') {
                i++;
                skipSpace();
                if (value[i] === '"') {
                    const parts: string[] = [];
                    for (i++; i < value.length && value[i] !== '"'; i++) {
                        if (value[i] === '\\') i++;
                        parts.push(value[i] ?? '');
                    }
                    if (i >= value.length) return null;
                    i++;
                    param = parts.join('');
                } else {
                    param = readToken();
                }
            }
            // RFC 8288 3.3: a second rel parameter is ignored.
            if (name === 'rel' && rel === undefined) rel = param;
            if (name === 'anchor') anchored = true;
        }
        const isNext = !anchored && rel !== undefined && rel.toLowerCase().replaceAll('\t', ' ').split(' ').includes('next');
        return isNext ? target : undefined;
    };

    /** Moves to the next ',' outside quotes and `<>`, past the rest of a malformed link. */
    const skipLink = () => {
        let quoted = false;
        let bracketed = false;
        for (; i < value.length; i++) {
            const char = value[i];
            if (quoted) {
                if (char === '\\') i++;
                else if (char === '"') quoted = false;
            } else if (bracketed) {
                if (char === '>') bracketed = false;
            } else if (char === '"') quoted = true;
            else if (char === '<') bracketed = true;
            else if (char === ',') return;
        }
    };

    while (i < value.length) {
        skipSpace();
        if (i >= value.length) break;
        if (value[i] === ',') { i++; continue; }
        const link = readLink();
        if (link === null) skipLink();
        else if (link !== undefined) return link;
    }
    return undefined;
}
