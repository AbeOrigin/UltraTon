# compat/: integration tests with third-party clients

**This folder is not part of `ultraton`.** It never ships in the npm package, and `ultraton` has zero runtime dependencies. Installing it installs exactly one package.

It exists to prove that [`createSecureAgents()`](../README.md#protect-the-client-you-already-use) works with the clients people already use, by testing the **packed tarball** (what npm users get) against real versions of them:

| Library | Pinned version |
|---|---|
| axios | 1.20.0 |
| got | 16.1.0 |
| node-fetch | 3.3.2 |

The tests also pin two axios behaviours that bypass any agent, which is why the README makes `proxy: false` mandatory and forbids `httpVersion: 2` with axios. If axios changes either behaviour, those "LIMIT" tests fail.

## Why the dependencies are safe here
- **Exact versions and a lockfile with integrity hashes:** `npm ci` refuses anything that does not match byte for byte.
- **No install scripts:** everything is installed with `--ignore-scripts`, so third-party code never runs at install time.
- **No secrets in the CI job:** it runs with a read-only token and no stored credentials.
- **Never on the publish path:** the publish workflow never installs this folder.

## Run it locally
From the repository root:

```bash
rm -f compat/ultraton-*.tgz && npm pack --pack-destination compat
```

Then in `compat/`:

```bash
npm ci --ignore-scripts && npm install --no-save --ignore-scripts ./ultraton-*.tgz && npm test
```

Everything runs on loopback, with DNS mocked; no request leaves the machine.
