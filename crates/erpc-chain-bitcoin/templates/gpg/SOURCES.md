<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Bitcoin Core release trust roots

These are public verification keys, not private signing material. Read on
2026-10-26 from Guix signatures commit
`a26ee14ac2594ed80040767fb53459d5d684c84a`:

- [Michael Ford / fanquake](https://github.com/bitcoin-core/guix.sigs/blob/a26ee14ac2594ed80040767fb53459d5d684c84a/builder-keys/fanquake.gpg), primary fingerprint `E777299FC265DD04793070EB944D35F9AC3DB76A`.
- [Ava Chow / achow101](https://github.com/bitcoin-core/guix.sigs/blob/a26ee14ac2594ed80040767fb53459d5d684c84a/builder-keys/achow101.gpg), primary fingerprint `152812300785C96444D3334D17565732E08E5E41`.

Both authenticated the official 31.1 SHA256SUMS manifest during implementation
research. Only the small manifest/signature/key files were downloaded; this is
not evidence that any release binary was downloaded or executed. The deployment
controller requires both distinct primary signatures via an isolated public keyring;
the host independently authenticates the manifest and hashes the archive before
installation. Offline fixture tests exercise these checks without a node binary.
