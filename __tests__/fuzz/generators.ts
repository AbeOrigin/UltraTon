/** Generators shared by several property files (see fuzz.ts). */
import type { Rand } from './fuzz.ts';

/**
 * One of the many valid spellings of the IPv6 address with these 8 groups: hex of any width and case, sometimes the
 * last 32 bits as a dotted IPv4 tail, one run of zero groups compressed (any part of it), sometimes a zone id.
 */
export function spellIpv6(r: Rand, groups: readonly number[]): string {
    const hex = (n: number) => {
        const digits = n.toString(16).padStart(r.chance(0.3) ? 1 + r.int(4) : 1, '0');
        return r.chance(0.5) ? digits.toUpperCase() : digits;
    };
    // The last 32 bits as a dotted IPv4 tail (::ffff:1.2.3.4 and friends).
    const tail = r.chance(0.3);
    const written = tail ? groups.slice(0, 6).map(hex) : groups.map(hex);
    if (tail) written.push(`${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.${groups[7] & 255}`);
    // Compress one run of zero groups (any length >= 1 is valid input), never across the IPv4 tail.
    const last = tail ? 6 : 8;
    const zeroRuns: Array<[number, number]> = [];
    for (let i = 0; i < last; i++) {
        if (groups[i] !== 0) continue;
        let j = i;
        while (j < last && groups[j] === 0) j++;
        zeroRuns.push([i, j]);
        i = j;
    }
    let text: string;
    if (zeroRuns.length > 0 && r.chance(0.7)) {
        const [start, end] = r.pick(zeroRuns);
        const from = start + r.int(end - start);
        const to = from + 1 + r.int(end - from);
        text = `${written.slice(0, from).join(':')}::${written.slice(to).join(':')}`;
    } else {
        text = written.join(':');
    }
    if (r.chance(0.1)) text += '%eth0';
    return text;
}
