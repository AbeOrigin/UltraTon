# Contributing

Thanks for helping. UltraTon is a security library, so the bar is a bit higher than usual: every change comes with a test that proves it, and nothing gets weaker by accident.

**Found a way past a protection?** Do not open an issue or a pull request: report it privately as described in [SECURITY.md](SECURITY.md).

## Ground rules

- **Zero runtime dependencies.** UltraTon is built only on Node's own modules. A pull request that adds a `dependency` will not be merged. Development tools are kept to a minimum too; third-party clients for the compat tests live in [`compat/`](compat/README.md), installed with `--ignore-scripts`, and never ship.
- **Test first.** Write the failing test, then the fix. A bug fix includes the test that would have caught it. A new protection includes a test that tries to get past it.
- **Both engines.** HTTP/1.1 ([`src/engines/http1.ts`](src/engines/http1.ts)) and HTTP/2 ([`src/engines/http2.ts`](src/engines/http2.ts)) must behave the same: the same options, limits, errors and codes. Many test files run each case on both engines; do the same for anything a user can see.
- **Safe defaults stay safe.** A new option is off, or at its strictest, by default. Anything that loosens a check is opt-in and named so it reads as a decision (`permitReservedIps`, `allowPlainHttp`).
- **Errors never leak addresses.** Messages name neither the resolved IP nor the hostname of a blocked target. Use an `ERR_ULTRATON_*` code for anything callers need to tell apart.

## Setup

Node.js 22.12 or later:

```bash
npm ci
```

```bash
npm run build && npm test
```

Before opening a pull request, also run:

```bash
npm run build:strict
```

```bash
npm run check:tsdoc
```

```bash
npm run test:package
```

- **`build:strict`** type-checks with `--strict`.
- **`check:tsdoc`** fails if a public symbol or member has no TSDoc; editors show those comments on hover, so they are the API reference.
- **`test:package`** packs the tarball and imports it from ESM, CommonJS and TypeScript, as npm users would.

Before Node 22.18, `npm test` needs `NODE_OPTIONS=--experimental-strip-types`.

## Tests

- **Loopback only.** `npm test` preloads [`__tests__/fixtures/loopback-only.ts`](__tests__/fixtures/loopback-only.ts), which fails any socket to an address outside loopback. Tests that need a public-looking address mock DNS. No test may reach the internet.
- **Keep them light.** Tests run on contributors' own machines. Prove a limit with a small one (`maxBodySize: 1024`), never with a real zip bomb, a multi-gigabyte body or thousands of connections. Anything heavy belongs in CI.
- **Fuzzing.** [`__tests__/fuzz/`](__tests__/fuzz/) holds property tests for the parsers that face hostile input. `npm test` runs 200 cases per property with a fixed seed. `FUZZ_RUNS` and `FUZZ_SEED` change that, and a failure prints the seed and the shrunk input that reproduce it.
- **Benchmarks** run only in CI ([`compat/bench/`](compat/README.md#benchmarks)); `npm run bench` refuses to run elsewhere.

## Pull requests

- One topic per pull request, with a description of what changes for users and why.
- Add an entry to [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` for anything a user can notice.
- Update the README when an option, default or error changes, and [THREAT_MODEL.md](THREAT_MODEL.md) when a defense or a documented risk changes.
- See [SUPPORT.md](SUPPORT.md#what-counts-as-a-breaking-change) for what counts as a breaking change.
- CI runs the tests on every supported Node line, the compat and SSRF corpus tests, CodeQL and the package checks. All of them must pass.

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE).
