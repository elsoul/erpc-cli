<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Governance

## Roles

- **Maintainers** (ELSOUL LABO B.V. engineering) review and merge pull
  requests, triage issues and security reports, and own the roadmap in
  `docs/architecture.md`.
- **Release approvers** are the required reviewers of the GitHub environment
  `release`. A release is published only after an approver accepts the
  release checklist (CI green, dependency audit, SBOM diff review, changelog,
  reproducible-build comparison, secret scan).
- **Contributors** are anyone who opens a pull request under the terms of
  `CONTRIBUTING.md`.

## Decision making

Technical decisions are recorded in `docs/architecture.md` and in pull
request discussions. Maintainers decide by consensus; ELSOUL LABO B.V. holds
the final say as the responsible legal entity for the project and its
releases.

## Security and compliance

`SECURITY.md` defines the vulnerability process. Compliance evidence that can
be public (SBOM, provenance, signatures, verification procedures) lives in
this repository and its releases. Operational details, contacts and internal
assessments are kept by ELSOUL LABO B.V. and are not part of this repository.
