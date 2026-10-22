<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# If a secret reaches this repository

This is a public repository. Anything pushed to it, including to a pull
request branch, should be assumed to have been copied by someone else within
seconds. Work in this order.

## 1. Rotate first. Always.

**Rewriting git history does not undo exposure.** Rotate or revoke the
credential before you touch the history, and do it even if the exposure
lasted one minute:

| Leaked | Action |
|---|---|
| Blockchain private key or mnemonic | Move the funds to a new key immediately, then retire the old one. The key cannot be un-leaked. |
| Validator identity key | Treat the node as compromised. Generate a new identity and follow the chain's identity-change procedure. |
| ERPC API key | Revoke it in the ERPC dashboard and issue a new one. |
| 1Password service account token | Revoke the service account, issue a new token, review its vault access log. |
| Cloud token (Cloudflare, R2, AWS, GCP) | Delete the token or key, issue a replacement scoped as narrowly as the old one, review the provider's audit log for use you did not make. |
| crates.io token | Revoke it on crates.io. Prefer Trusted Publishing so there is no long-lived token to leak. |
| minisign signing key | Stop releasing. Generate a new key pair, publish the new public key in a release signed by the old key if that is still safe, and announce the rotation. |
| Signing certificate (Apple, Windows) | Revoke with the issuer and re-issue. |

If the credential belongs to someone else or to a customer, tell them. Do not
decide on their behalf that the exposure was harmless.

## 2. Work out what else was in the same commit

`git show <commit>` the whole commit, not only the file you noticed. Secrets
usually arrive in groups: a `.env` alongside a config, a keypair alongside an
inventory. Check whether the same material exists in other branches or in a
fork.

## 3. Remove it from the working branch

For a branch that is not merged yet, rebuild the history so the file never
existed, then force-push:

```bash
git branch backup/pre-rewrite HEAD          # keep a local reference
# rebuild each commit without the path, e.g. with git-filter-repo:
git filter-repo --force --invert-paths --path path/to/leaked.file
git push --force-with-lease origin <branch>
```

Verify before pushing:

```bash
for c in $(git rev-list main..HEAD); do
  git ls-tree -r "$c" --name-only | grep -q '^path/to/leaked.file$' && echo "$c still has it"
done
```

If the commit already reached `main`, do not rewrite `main` on your own.
Rotate, then raise it with the maintainers: rewriting a shared branch breaks
every clone and every open pull request.

## 4. Know what force-pushing does not do

After a force-push, the old commits remain reachable on GitHub by their SHA
for as long as GitHub keeps them, and anyone who saw the pull request has the
SHA. The pull request's event timeline also records the old head. Treat the
content as published. If you need the objects actually removed, open a request
with GitHub Support asking them to garbage-collect the unreachable objects in
the repository, and give them the SHAs. Do this after rotating, not instead of
it.

Caches outside GitHub, such as crates.io, docs.rs, forks, proxies and search
indexes, are not covered by any of this. If a published release artifact
contains the secret, yank the release as well.

## 5. Write it down

Record what leaked, when it was pushed, when it was rotated, and what you
checked in the provider's audit log. ELSOUL LABO B.V. keeps the escalation
path, the contact list and the incident record in its internal documentation;
if you are an outside contributor, report through the channel in
[`SECURITY.md`](../SECURITY.md) and we will take it from there.

## Prevention

- `lefthook install` wires the pre-commit hooks. Do not commit with
  `--no-verify`.
- `gitleaks` scans for credential values (`.gitleaks.toml`).
- `scripts/check-oss-hygiene.sh` blocks non-public hosts, infrastructure
  identifiers, key-shaped strings and internal documents.
- Both run again in CI, and GitHub secret scanning with push protection is
  enabled on the repository.
- Keep real credentials out of the checkout entirely: use 1Password
  references and the provider's environment, never a file in the tree.
