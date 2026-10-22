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

`erpc` keeps one kind of secret: the session for your ERPC account, an access
token and a refresh token obtained through the OAuth device authorization
grant. It does not read or store private keys. When it uses a 1Password
service account, it reads `OP_SERVICE_ACCOUNT_TOKEN` from its environment and
passes it to the `op` process it starts. It does not write that token
anywhere.

### Where the session is kept

The session is kept in one store. Unless `--store` names one, the store is the
first of these that applies:

1. a 1Password service account, when `OP_SERVICE_ACCOUNT_TOKEN` is set;
2. the 1Password desktop app, when `op` is installed and `op account list`
   answers;
3. the operating system's keychain, when there is one;
4. a file in the erpc state directory.

`erpc doctor` reports which store is in use and why.

### When the session is on disk in cleartext

The erpc state directory is `$ERPC_HOME/state` or, without `ERPC_HOME`,
`.erpc/state` in your home directory. `erpc` will not use a state directory
that is not an absolute path.

`erpc` writes a session to that directory in the following cases, and
`erpc doctor` reports each file for as long as it exists:

- **The file store.** `erpc login` warns when the session is going there.
- **A parked session.** If the issuer has rotated a refresh token and the
  store then refuses the new one, the new token is written here so that it is
  not lost. `erpc whoami` moves it into the store if the store still holds the
  session it replaced. `erpc login` and `erpc logout` revoke it and remove it,
  and say so when they could not.
- **An interrupted write.** The two files above are written to a temporary
  file first and then renamed into place. A crash between the two steps
  leaves that temporary file behind.

On Unix these files are created with mode `0600`. On Windows `erpc` sets no
permissions of its own, so the files have the permissions of the directory
they are in.

### Where the session is sent

- The access token is sent as a bearer token only to the hosts listed for its
  audience in `crates/erpc-auth/src/allowlist.rs`.
- The refresh token is sent only to its issuer's token and revoke endpoints.
- Every request URL is a compile-time constant.
- The HTTP client is configured to accept `https` only and not to follow
  redirects. Neither setting is covered by a test; the reasons are given
  beside them in `crates/erpc-auth/src/http.rs`.

### What to report

Report any of the following as a vulnerability, through the channel above:

- secret material written to disk in any way not described above;
- secret material in a log, an error message, or other output;
- a token sent anywhere not described above.

Do not infer from this repository which protections are already in force. What
the code does today is what the code in this repository does today.
