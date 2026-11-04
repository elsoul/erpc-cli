<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Verifying an erpc release

> GitHub Releases, starting with `v0.1.0-rc.1`, are signed with the minisign
> key in `crates/erpc-release/pubkey.txt`, key ID `A84D7BB71B974545`.
> Version 0.0.1 exists only on crates.io, as a name reservation: for the
> first fifteen crates, published from a commit that still held a
> placeholder key; for a crate added since, an empty placeholder package
> (`scripts/reserve-crates.sh`). It has no GitHub Release, no binary and no
> signature.

Two paths are offered.

The convenience path (`curl | bash`) trusts DNS, TLS, the
`install.erpc.global` worker and GitHub Releases. That worker serves the
installer only from GitHub Releases, because it cannot verify a signature and
the script it returns is executed. The one thing it adds is a fixed tail, kept
in `installer/src/index.ts`, that runs the installed binary with
`erpc skills install` to write the assistant's skills to `~/.erpc/skills`. It
verifies nothing itself, and neither
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

   That holds only if the key really is one you already hold. Do **not** take
   it from `crates/erpc-release/pubkey.txt` at the tag you are checking: the
   people who can replace a release asset can also push a tag whose
   `pubkey.txt` is their own key, and a signature made with it would verify.
2. Verify the manifest signature with the project public key you saved the
   first time you installed erpc, and keep using that saved copy:

   ```bash
   # once, from a clone of this repository: save the key as it is on main
   git show origin/main:crates/erpc-release/pubkey.txt > ~/.erpc-release-pubkey.txt

   # every release: verify against the saved copy, not the copy at the tag
   minisign -Vm release-manifest.json -p ~/.erpc-release-pubkey.txt
   ```

   If `pubkey.txt` at the tag you are checking differs from your saved copy,
   stop: either the key was rotated (see Key rotation below) or someone is
   trying to make their own key look like the project's.

   This is trust on first use. The first copy is only as good as `main` was
   on the day you saved it; what the saved copy buys is that a later tag
   cannot quietly bring a different key with it.

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

5. Extract and place the binary on your `PATH`, then run
   `erpc skills install` to write the assistant's skills to `~/.erpc/skills`
   (add `--agent claude` for Claude Code's skills directory too).

## What the signature covers

`release-manifest.json` contains `version`, `tag`, `commit`, `build_time`, and
the `sha256` and `size` of every archive, plus the SBOM hash. That is the
whole of it: there is no revocation list and no signed "latest version"
document, because nothing would read them. A self-update command that needs
either will add it then.

Each erpc binary also carries the erpc worker agents (static musl, `x86_64`
and `aarch64` Linux) that `erpc worker deploy` installs on a server, built by
`scripts/build-worker-agents.sh` before the release build. They are part of the
binary, so the archive's digest covers them. `erpc version` prints their
SHA-256, and a deploy reports whether the server's agent changed.
`ERPC_WORKER_AGENT` makes a deploy install another agent instead (a build
of your own). When it differs from the embedded one, the deploy warns on
standard error, `--json` or not; its report names the agent installed either
way (`agent.sha256`,
`agent.source`: `embedded`, `ERPC_WORKER_AGENT` or `beside erpc`, and
`agent.changed`).

## Reproducible build check

Each release rebuilds the two Linux musl targets on a second runner of the
same image, with the same Rust toolchain and C compiler, and compares the
hash of the `erpc` binary with the one in the first runner's archive before
publishing. The rebuild makes the embedded worker agents again first, in the
same way (`scripts/build-worker-agents.sh`), so for those two builds the
comparison covers the agents too. A match shows that the build is deterministic and that the
`erpc` binary in that archive was not altered; it does not show that a
different machine would produce the same binary, and it does not cover the
other files in the archive. The agents inside the macOS and Windows builds,
where most operators run `erpc worker deploy`, are built the same way but are
not compared: `erpc version` prints their SHA-256, to set beside a Linux
build's. cargo-auditable is installed separately on each
side, so a new cargo-auditable release between the two installs makes the
hashes differ and stops the release. The macOS and Windows builds are
**not** compared. Treat this page, not the release notes, as the statement
of what is checked.

## Key rotation

If the signing key is rotated, the new public key is announced in a release
signed by the old key and in the repository.
