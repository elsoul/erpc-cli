# Releasing `@elsoul/erpc-cli`

Releases are approved by a maintainer and published from GitHub Actions. A push
to `main` never publishes a package.

## First public version

Before Trusted Publishing can be configured, a maintainer inspects and
publishes the first version:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm release:check
corepack pnpm pack:check
npm publish --access public
```

Use interactive npm authentication or a short-lived granular credential. Do
not add a long-lived npm token to this repository or its workflow secrets.

## Trusted Publishing

After the package exists, configure its npm Trusted Publisher:

| Setting | Value |
| --- | --- |
| Organization or user | `elsoul` |
| Repository | `erpc-cli` |
| Workflow filename | `release.yml` |
| Environment | `npm` |
| Allowed action | `npm publish` |

Create a protected GitHub Environment named `npm` with required human
reviewers and no `NPM_TOKEN` secret.

## Subsequent versions

1. Update `version` in `package.json` and synchronize the lockfile.
2. Run the complete release checks and merge the reviewed change.
3. Publish a GitHub Release tagged exactly `v<package-version>`.
4. Approve the `npm` environment deployment.
5. Verify the published package version and provenance on npm.

npm versions are immutable. Recover from a bad release with a new patch
version instead of reusing a published version.
