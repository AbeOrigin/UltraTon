/**
 * Version gating for Node's own security fixes. A mitigation that turns a risky feature off until the runtime carries
 * the fix (Brotli, keep-alive reuse) asks the same question: is this Node at or past the first fixed release of its
 * line? Each mitigation keeps its own table of fixed releases (one per CVE, so they can diverge), and shares the
 * comparison here.
 */

/** The first fixed release of each Node major line: `{ 22: [minor, patch], 24: [...], ... }`. */
export type FixedReleases = Readonly<Record<number, readonly [minor: number, patch: number]>>;

/**
 * Node's October 2026 security releases: the first release of each line with the fixes for CVE-2026-111497 (Brotli)
 * and CVE-2026-105481 (keep-alive). One table because they shipped together; split it the day a line gets one fix
 * without the other, so that neither mitigation is lifted by the other's release.
 */
export const NODE_OCT_2026_FIXES: FixedReleases = { 22: [23, 4], 24: [22, 1], 26: [12, 1] };

/**
 * Whether `version` is at or past the fix for its own major line in `fixed`. A line newer than every one in the table
 * carries the fix; a line not in the table and no newer than the newest listed one does not. A prerelease
 * (`27.0.0-rc.1`, a nightly) may predate the fix even on a listed line, so it counts as unfixed, as does an
 * unparseable version.
 */
export function atLeastFixed(fixed: FixedReleases, version: string = process.versions.node): boolean {
    if (version.includes('-')) return false;
    const [major, minor, patch] = version.split('.').map(Number);
    const lines = Object.keys(fixed).map(Number);
    if (major > Math.max(...lines)) return true;
    const fix = fixed[major];
    if (fix === undefined) return false;
    return minor > fix[0] || (minor === fix[0] && patch >= fix[1]);
}
