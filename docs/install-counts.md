<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Install counts

The `install.erpc.global` worker counts the installers it serves, so that
ELSOUL can see how many installs there are and where they come from. This
page says what one count holds.

## What is recorded

Every `GET` of an installer (`/`, `/ps1`, `/vX.Y.Z`, `/vX.Y.Z/ps1`) writes one
data point to Workers Analytics Engine after the response is ready, cache hits
and 502 responses included, with their status. `HEAD`, `/healthz`, other
methods and unknown paths write nothing.

Dataset: `erpc_installs` (binding `INSTALLS`, `installer/wrangler.toml`), in
the Cloudflare account the installer worker is deployed to.

| column      | field       | from |
|-------------|-------------|------|
| `index1`    | `script`    | `sh` or `ps1` |
| `blob1`     | `country`   | `request.cf.country` (ISO 3166-1 alpha-2, `T1` = Tor) |
| `blob2`     | `continent` | `request.cf.continent` (`AF AN AS EU NA OC SA`) |
| `blob3`     | `colo`      | `request.cf.colo` (Cloudflare data centre) |
| `blob4`     | `language`  | primary subtag of the first `Accept-Language` range (`ja-JP,…` is `ja`) |
| `blob5`     | `os`        | installer family: `unix` for `sh`, `windows` for `ps1` |
| `blob6`     | `arch`      | always `unknown`: the installer picks it on the machine |
| `blob7`     | `script`    | `sh` or `ps1` |
| `blob8`     | `requested` | `latest`; the tag in the path when that release was served; otherwise `unknown` |
| `blob9`     | `version`   | the tag served (`x-erpc-tag`), or `unknown` on an error |
| `double1`   | `status`    | HTTP status; an installer served is `200` |
| `timestamp` |             | Analytics Engine, UTC |

Any value that does not fit its pattern, and any tag longer than 64
characters, is `unknown`. The order is `INSTALL_BLOBS` in
`installer/src/index.ts`, and a test pins it. Columns are only ever appended;
the meaning of one is never changed.

## Privacy

Every value is either Cloudflare's own (country, continent, data centre),
one of a few constants, a language tag of two or three letters, or the name
of a release this worker served. A client cannot write text of its choosing
into the dataset: the tag in a pinned path is recorded only once a release by
that name has been served, and as `unknown` otherwise. No IP address, user
agent, city, coordinates or any other per-person value is read into the data
point. Recording cannot change or delay the response: `writeDataPoint` does
not wait on anything, and an error in it is dropped (`recordInstall`).

This is about the data point. The worker also has Cloudflare's Workers
observability turned on (`[observability]` in `installer/wrangler.toml`), as
it had before counts were added.

## Reading the numbers

- **A download is not an install.** A count is an installer served. CI
  pipelines that reinstall on every run, and anyone requesting the URL in a
  loop, count every time.
- **`language` is mostly `unknown`.** `curl` and PowerShell's
  `Invoke-RestMethod` send no `Accept-Language`, and those are how the
  installer is fetched. Country is the usable signal for which CLI languages
  to add. A real language signal would need the CLI itself to report its
  locale, which is a separate decision.
- **`os` and `arch` are coarse.** The request says only which installer was
  fetched.
- **Installs from crates.io (`cargo install`) and from a downloaded archive
  are not here.** crates.io and GitHub Releases keep their own download
  counts.

## Why Analytics Engine

The worker's trust model (top of `installer/src/index.ts`) is that it holds
no secrets. An Analytics Engine binding is not a credential, so the worker
stays that way. Writing anywhere else from the worker would need a
credential in it.
