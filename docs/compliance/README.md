<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Compliance evidence index

This page lists the evidence this project publishes. It does **not** claim
conformity with the EU Cyber Resilience Act (Regulation (EU) 2024/2847), CE
marking, or any certification. Legal classification of the project and its
operator is handled by ELSOUL LABO B.V. outside this repository.

| Evidence | Where | Produced by |
|---|---|---|
| License and notices | `LICENSE`, `NOTICE`, `LICENSES/`, `REUSE.toml` | repository; `reuse lint` in CI |
| Third-party notices | `THIRD_PARTY_NOTICES.md` in each release | `cargo about` |
| Software bill of materials | `*.cdx.json` attached to each GitHub Release | `cargo cyclonedx` via cargo-dist |
| Build provenance | GitHub Attestations on every release artifact | `actions/attest` via cargo-dist |
| Release signatures | `release-manifest.json.minisig`, `latest.json.minisig` | release workflow; key custody by ELSOUL LABO B.V. |
| Dependency policy | `deny.toml`, `.cargo/audit.toml` | `cargo deny`, `cargo audit` in CI |
| Vulnerability handling | `SECURITY.md` | maintainers |
| Verification procedure | `docs/verify-release.md` | maintainers |
| Supported versions | `SECURITY.md` | maintainers |

## What is not here

Internal risk assessments, incident contacts, key custody procedures and
operator runbooks are maintained privately by ELSOUL LABO B.V. Requests from
market surveillance authorities should be addressed to the company, not to
this repository.
