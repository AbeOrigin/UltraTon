# Support

## Getting help

- **A question or a bug:** open an [issue](https://github.com/AbeOrigin/UltraTon/issues/new/choose). Include the UltraTon and Node.js versions, the options you used, and a minimal reproduction (a local server is ideal).
- **A way past a protection** (reaching an address that should be blocked, a leaked credential, a hang or memory beyond the limits): do not open an issue. Report it privately as described in [SECURITY.md](SECURITY.md).

UltraTon has one maintainer, so answers can take a few days.

## Node.js versions

UltraTon supports every Node.js line from 22.12 on that is still maintained upstream: Current, Active LTS and Maintenance LTS (see Node's [release schedule](https://github.com/nodejs/release#release-schedule)).

- **CI:** every change is tested on Node 22.12.0 (the oldest supported version), the latest 22.x, 24.x and 26.x.
- **Security releases of Node:** supported does not mean safe. Run the latest release of your line; [SECURITY.md](SECURITY.md#nodejs-releases) lists the minimum releases with the fixes UltraTon depends on, and what UltraTon does on older ones.
- **Dropping a Node line:** only in a new UltraTon major, and only once that line has reached end-of-life upstream.
- **New Node lines:** added to CI when they are released. A bug that only shows on a new line is fixed in a patch or minor.

## UltraTon versions

| Version | Status |
|---|---|
| 2.x | Supported: features, bug fixes and security fixes. |
| 1.x | Not supported. It has known SSRF bypasses: upgrade to 2.x ([migration guide](README.md#migrating-from-1x)). |

When a new major ships, the previous one keeps getting **security fixes for 6 months**, then stops.

## Stability period: 2.8.0 to 2027-01-23

2.0.0 to 2.8.0 shipped in five days. Each release is documented and tested, but an API that moves that fast is not one you can build on, so from 2.8.0 (2026-10-23) and **for at least three months**:

- **Only patch releases (2.8.x).** Bug fixes, security fixes and documentation. No new options, methods, exports or error codes, and no change of behaviour that is not a fix.
- **The public API is frozen and CI enforces it.** `scripts/public-api.txt` is the snapshot of every exported type and signature, and of every error code; a change fails CI unless the snapshot is updated on purpose, and in this period it is not.
- **The one exception is a security fix that cannot be made without a new option.** It ships in a minor, the CHANGELOG says why under "Security", and nothing else comes with it.

What the period is for: feedback on the 2.7 and 2.8 additions (`explain()`, `extend()`, `assertOk()`, `redirectHeaders`, `maxConcurrency`, the `headers` function, the diagnostics timings) before anything is built on top of them, and a track record an adopter can check: the CHANGELOG and the API snapshot between two dates. Candidates for a later major are listed in the CHANGELOG as they come up (today: `redirectHeaders: 'safe'` as the default), and none of them ships before the period ends.

## What counts as a breaking change

UltraTon follows [semver](https://semver.org/). These need a new major:

- removing or renaming an export, a client method, an option, or an error class;
- changing an error `code` (`ERR_ULTRATON_*`) or which error class a failure rejects with;
- changing a default, in either direction, except to close a security hole (see below);
- dropping a Node.js line;
- a change to the TypeScript types that breaks code that compiled before, unless the old type did not match what the code actually did (that ships in a minor, with a note in the CHANGELOG).

These are **not** part of the API, and can change in any release:

- error messages (match on `code` and the error class instead);
- what `error.cause` holds;
- anything not exported from `ultraton` (the package has a single entry point, so `dist/` files are internal);
- benchmark numbers and the exact timing of retries (the documented bounds still hold).

**Security fixes are never held back for a major.** Closing a bypass ships in a patch or minor even if it blocks a request that used to get through, because that request was never meant to. The CHANGELOG says so under "Fixed" or "Security".
