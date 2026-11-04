<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Base release public key

`base.asc` is the public release verification key embedded in
[Base v1.5.1 baseup](https://github.com/base/base/blob/5476069f1eb74a56bccb56fdefd4b4bb0e3cda42/baseup/baseup),
read 2026-10-26. Its primary fingerprint is
`5EFE7BCFCD85682711F9FC30904841FFEBD38BAD`. It contains no private key material.
The backend requires this primary key's valid SHA-256-or-stronger signature plus
the reviewed archive SHA-256 before extracting a native binary. It does not run
baseup or honor its environment-variable trust-root overrides.
