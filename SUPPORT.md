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

## How the API changes

**There is no patches-only period today.** One was announced from 2.8.0 and restarted from 2.9.0 (2026-10-29) for at least three months. It ended early, with 2.10.0 (2026-11-04): the first application built on UltraTon needed what that release adds (Server-Sent Events, the headers of each redirect hop, reading a body without keeping it) and less CPU per request, and three months of workarounds in its first adopter would have cost more than the promise was worth. Two announced periods ended early in two weeks, so no new one is announced with a date: a date is only worth what keeping it is.

What holds instead, and what you can check:

- **Semver, as below.** A new option, method or error code ships in a minor; nothing you rely on changes outside a major.
- **Every addition is opt-in, and no default moves without a major**, except to close a security hole (see below). 2.9.0 and 2.10.0 kept to that: every change in both is opt-in or additive.
- **The public API is recorded and CI enforces it.** `scripts/public-api.txt` is the snapshot of every exported type and signature, and of every error code; a change fails CI unless the snapshot is updated on purpose, in the same commit, where the diff shows exactly what changed.
- **The CHANGELOG lists every change**, and candidates for a later major as they come up (today: `redirectHeaders: 'safe'` as the default).

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
