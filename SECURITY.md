<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

`erpc-cli` is developed and maintained by ELSOUL LABO B.V. (Netherlands), the
operator of the ERPC service.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/elsoul/erpc-cli/security/advisories/new).
Do not open a public issue for security problems.

Include the affected version (`erpc version --json`), the platform, steps to
reproduce, and the impact you observed. Encrypted reports are not required.

We acknowledge reports within 5 business days and aim to publish a fix or a
mitigation within 90 days of confirmation. We follow coordinated disclosure:
we will agree a publication date with you and credit you in the advisory
unless you prefer otherwise.

## Supported versions

Only the latest minor release line receives security fixes. No release has
been published yet, so nothing is currently supported or unsupported.

## Scope

In scope: the `erpc` binary and the crates in this repository, the installer
script served at `install.erpc.global`, the release artifacts and their
signatures.

Out of scope: the ERPC backend services (report those through the ERPC
dashboard support channel), third-party node clients that `erpc` installs on
your servers, and issues that require physical access to an operator machine.

## Verifying releases

Every release ships a signed `release-manifest.json` (minisign), a CycloneDX
SBOM and GitHub build provenance attestations. See `docs/verify-release.md`.

## Secret handling

`erpc` handles one kind of secret: the session for your ERPC account. It does
not read or store private keys.

- **Where a session is kept.** `erpc login` obtains an access token and a
  refresh token through the OAuth device authorization grant and keeps them
  in one store: the 1Password desktop app, a 1Password service account, the
  operating system's keychain, or a file. Without `--store`, the first of
  those that is usable on the machine is chosen, and `erpc doctor` says which
  one and why.
- **When a session is on disk in cleartext.** In two cases, both written with
  mode `0600` and both reported by `erpc doctor` for as long as they exist:
  - The file store. It is used when you ask for it, or when neither `op` nor a
    keychain is available, and `erpc login` warns when it is.
  - A parked session. When the issuer has rotated a refresh token and the
    store then refuses the new one, the new one is written to the erpc state
    directory instead of being lost. The next command files it into the
    store, as long as the store still holds the session it replaced.
- **Where a session is sent.** A token is attached only to the hosts listed
  for it in `crates/erpc-auth/src/allowlist.rs`. The HTTP client accepts
  `https` only and does not follow redirects. Request URLs are compile-time
  constants, not configuration.

Report any of the following as a vulnerability, through the channel above:

- a code path that writes secret material to disk other than in the two cases
  above;
- a code path that writes secret material to a log or an error message;
- a token sent to any host other than those listed for it.

Do not infer from this repository which protections are already in force. What
the code does today is what the code in this repository does today.
