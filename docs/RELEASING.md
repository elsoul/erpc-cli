# Releasing ERPC CLI binaries

Releases are approved by a maintainer and published from GitHub Actions. A push
to `main` never uploads binaries or changes the public `latest` pointer.

## Release storage contract

The public custom domain maps to these R2 object keys:

```text
install
install.ps1
erpc/latest
erpc/v0.2.0/SHA256SUMS
erpc/v0.2.0/erpc-x86_64-unknown-linux-gnu.tar.gz
erpc/v0.2.0/erpc-aarch64-unknown-linux-gnu.tar.gz
erpc/v0.2.0/erpc-x86_64-apple-darwin.tar.gz
erpc/v0.2.0/erpc-aarch64-apple-darwin.tar.gz
erpc/v0.2.0/erpc-x86_64-pc-windows-msvc.zip
erpc/v0.2.0/erpc-aarch64-pc-windows-msvc.zip
```

Versioned objects are immutable. The workflow refuses to overwrite an existing
versioned key. It updates `erpc/latest`, `install`, and `install.ps1` only after
every binary and the checksum manifest have been uploaded successfully.

## GitHub environment

Create a protected GitHub Environment named `r2` with required human reviewers
and the following secrets:

| Secret                 | Purpose                                    |
| ---------------------- | ------------------------------------------ |
| `R2_ACCESS_KEY_ID`     | Release-bucket credential identifier       |
| `R2_SECRET_ACCESS_KEY` | Release-bucket credential secret           |
| `R2_ENDPOINT`          | Account-specific S3-compatible R2 endpoint |
| `R2_BUCKET`            | Bucket behind `storage.erpc.global`        |

Scope the credential to object reads and writes for the release bucket only.
Never put R2 credentials in this repository, release assets, logs, or the
installer.

## Release procedure

1. Before the first release or after credential rotation, manually run the
   `Test release storage` workflow. It uploads, verifies, and removes a unique
   probe object without changing `latest` or any release object.
2. Move the Unreleased changelog entries under the intended version.
3. Update `version` in `deno.json` and `CLI_VERSION` in `src/version.ts`
   together.
4. Run the complete checks:

   ```bash
   deno task release:check
   deno run --frozen-lockfile --allow-read scripts/verify-release.ts v0.2.0
   sh -n install
   ```

5. Merge the reviewed change to `main`.
6. Publish a non-prerelease GitHub Release tagged exactly `v<version>`.
7. Approve the protected `r2` environment deployment.
8. Verify all six public targets, `SHA256SUMS`, `erpc/latest`, and both
   installers through `https://storage.erpc.global`.

Release versions and versioned R2 objects are immutable. Recover from a bad
release with a new patch version instead of replacing an existing object.
