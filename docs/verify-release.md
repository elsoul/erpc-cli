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

Two paths are offered.

The convenience path (`curl | bash`) trusts DNS, TLS, the
`install.erpc.global` worker and GitHub Releases. That worker serves the
installer only from GitHub Releases, because it cannot verify a signature and
the script it returns is executed. It verifies nothing itself, and neither
does the installer script it serves. A self-updating command that would check
the signatures below does not exist yet, so nothing on this path is verified
at any point.

The high-assurance path below is therefore the only one that verifies
anything today. Operators of mainnet validators should use it.

## High-assurance path

1. Pick a tag, e.g. `v0.1.0`, and download from the GitHub Release:
   `release-manifest.json`, `release-manifest.json.minisig`, and the archive
   for your platform. There is no mirror; GitHub Releases is the only place
   release artifacts are published.

   Do not treat the download itself as trustworthy. A release asset can be
   replaced by anyone who can publish a release, and this page does not
   claim otherwise. What this procedure rests on is step 2: the signature is
   checked against a key you already hold, so it does not matter where the
   bytes came from. Step 4 adds the build provenance on top of that.
2. Verify the manifest signature with the project public key
   (`crates/erpc-release/pubkey.txt` in this repository, at the tag you are
   checking):

   ```bash
   minisign -Vm release-manifest.json -P "$(grep -v '^untrusted' crates/erpc-release/pubkey.txt)"
   ```

3. Check that `tag` and `version` inside the manifest match the tag you chose,
   then compare the archive hash:

   ```bash
   sha256sum erpc-x86_64-unknown-linux-musl.tar.xz
   jq -r '.targets["x86_64-unknown-linux-musl"].sha256' release-manifest.json
   ```

4. Optionally verify GitHub build provenance:

   ```bash
   gh attestation verify erpc-x86_64-unknown-linux-musl.tar.xz --repo elsoul/erpc-cli
   ```

5. Extract and place the binary on your `PATH`.

## What the signature covers

`release-manifest.json` contains `version`, `tag`, `commit`, `build_time`, and
the `sha256` and `size` of every archive, plus the SBOM hash. That is the
whole of it: there is no revocation list and no signed "latest version"
document, because nothing would read them. A self-update command that needs
either will add it then.

## Reproducible build check

Each release rebuilds the two Linux musl targets on an independent runner
with a fixed `SOURCE_DATE_EPOCH` and compares the binary hashes before
publishing. The macOS and Windows builds are **not** compared. Treat this
page, not the release notes, as the statement of what is checked.

## Key rotation

If the signing key is rotated, the new public key is announced in a release
signed by the old key and in the repository.
