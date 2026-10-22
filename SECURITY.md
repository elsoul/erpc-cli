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

Only the latest minor release line receives security fixes. Older releases
should upgrade with `erpc upgrade`.

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

`erpc` does not yet handle credentials: at this version it neither reads nor
stores private keys or session tokens. When it does, the rule will be that
secret material never rests on the operator machine in plaintext. Either way,
a code path that writes secret material to disk or to logs is a vulnerability;
report it through the channel above.

Do not infer from this repository which protections are already in force. What
the code does today is what the code in this repository does today.
