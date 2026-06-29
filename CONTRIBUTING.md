# Contributing to the Lupid SDK

Thanks for your interest in improving the Lupid SDK. This guide covers how to build, test, and submit changes.

## Development

This is an npm-workspaces monorepo with two packages under `packages/`:

- `packages/sdk` — `@lupid/sdk`
- `packages/react` — `@lupid/react`

```bash
# from the repo root
npm install

# build / test / lint / typecheck (all workspaces)
npm run build
npm test
npm run lint
npm run typecheck
```

To work on a single package, use `-w`:

```bash
npm test -w @lupid/sdk
npm run build -w @lupid/react
```

### Conventions

- **No `any`** outside test files — use `unknown` and narrow.
- **Edge-safe:** files reachable from `index.ts` must not statically import Node
  builtins (`node:*`, `fs`, `path`, …) — use dynamic `await import(...)` inside
  the function that needs them. The SDK runs in Edge/Workers/browser surfaces.
- **Fail-closed by default.** Enforcement paths deny on transport/timeout/unknown
  shape unless a comment explicitly documents a fail-open exception.
- Add a test for every behavior change. HTTP is mocked with `nock`; no real network in tests.

## How this repo is maintained

The Lupid SDK is developed in a private monorepo and published here via a scrubbed,
one-directional export. Accepted contributions are back-ported into the canonical
source and flow out in the next release. This means:

- PRs are reviewed and merged here, then synced internally — there may be a short
  delay before a change appears in a published npm version.
- Large/architectural changes are best discussed in an issue first.

## Developer Certificate of Origin

We use the [DCO](https://developercertificate.org/) — there is **no CLA**. By
signing off your commits you certify that you wrote the patch (or have the right
to submit it) under the project's Apache-2.0 license.

Sign off every commit with `-s`:

```bash
git commit -s -m "fix: ..."
```

This appends a line to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

PRs whose commits are not signed off will be asked to amend before merge.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Ensure `npm run typecheck && npm run lint && npm test` pass.
- Do not commit secrets — CI runs a `gitleaks` scan on every PR.
- Be kind; see the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not file security issues as public PRs/issues — see [SECURITY.md](SECURITY.md).
