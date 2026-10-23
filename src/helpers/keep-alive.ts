import { atLeastFixed, type FixedReleases } from './node-release.ts';

/** The first release of each Node line that fixes CVE-2026-105481 (a keep-alive socket taking a response written before the request). */
const KEEP_ALIVE_FIXED: FixedReleases = { 22: [23, 4], 24: [22, 1], 26: [12, 1] };

/**
 * Whether this Node reuses keep-alive sockets safely. A server that writes a response on an idle pooled socket, before
 * the next request goes out, can have those bytes read as the response to that next request (CVE-2026-105481). Node's
 * fix destroys a pooled socket that received unsolicited bytes while idle and checks for a pending read before handing
 * one to a request; part of that check needs a native binding (`handle.hasPendingRead()`) added in the fixed releases,
 * which a library cannot reach, so on an earlier release UltraTon turns keep-alive off instead (see KEEP_ALIVE): a
 * socket serves one request and is then closed, so none ever sits idle in a pool to be poisoned. The pool is per
 * origin, so only the server you are talking to could do this, but closing the window needs no trust in the server.
 * Lines 23 and 25 are end-of-life and never got the fix; a prerelease may predate it. Upgrade Node to pool again.
 */
export function hasSafeKeepAlive(version: string = process.versions.node): boolean {
    return atLeastFixed(KEEP_ALIVE_FIXED, version);
}

/** The `keepAlive` every HTTP/1.1 agent is built with: off on a Node whose pooled-socket reuse is unsafe (see hasSafeKeepAlive). */
export const KEEP_ALIVE = hasSafeKeepAlive();
