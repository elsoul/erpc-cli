<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Verifying an erpc release

> **Not yet in force.** No release has been published, and the signing key in
> `crates/erpc-release/pubkey.txt` is a placeholder. Verification against it
> will fail until the first signed release. This document describes the
> procedure that the release workflow implements, so that it can be reviewed
> before it is used.

Two paths are offered. The convenience path (`curl | bash`) trusts DNS, TLS,
the `install.erpc.global` worker and GitHub Releases at install time; `erpc`
then verifies every later update with the signatures below. Operators of
mainnet validators should use the high-assurance path.

## High-assurance path

1. Pick a tag, e.g. `v0.1.0`, and download from the GitHub Release
   (immutable) or the mirror `https://dl.erpc.global/v0.1.0/`:
   `release-manifest.json`, `release-manifest.json.minisig`, and the archive
   for your platform.
2. Verify the manifest signature with the project public key
   (`crates/erpc-release/pubkey.txt`, also embedded in every `erpc` binary):

   ```bash
   minisign -Vm release-manifest.json -P "$(grep -v '^untrusted' crates/erpc-release/pubkey.txt)"
   ```

3. Check that `tag` and `version` inside the manifest match the tag you chose,
   then compare the archive hash:

   ```bash
   sha256sum erpc-x86_64-unknown-linux-musl.tar.gz
   jq -r '.targets["x86_64-unknown-linux-musl"].sha256' release-manifest.json
   ```

4. Optionally verify GitHub build provenance:

   ```bash
   gh attestation verify erpc-x86_64-unknown-linux-musl.tar.gz --repo elsoul/erpc-cli
   ```

5. Extract and place the binary on your `PATH`.

## What the signature covers

`release-manifest.json` contains `version`, `tag`, `commit`, `build_time`, the
`sha256` and `size` of every archive, the SBOM hash and the URL of the signed
revocation list. `latest.json` (used by `erpc upgrade`) is signed separately
and carries an expiry so a stale copy cannot freeze you on an old version.

## Reproducible build check

Each release rebuilds the Linux musl targets on an independent runner with a
fixed `SOURCE_DATE_EPOCH` and compares the binary hashes before publishing.
macOS and Windows builds are not yet compared; the release notes say so.

## Key rotation

If the signing key is rotated, the new public key is announced in a release
signed by the old key and in the repository. Revoked versions are listed in
the signed revocation file referenced by the manifest.
