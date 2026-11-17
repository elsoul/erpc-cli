<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Install counts

The `install.erpc.global` worker counts the installers it serves. A daily
export to BigQuery belongs to ELSOUL's internal KPI pipeline, which already
writes the company's other daily KPIs; this repository owns only the data
point below, and this page is the contract that export reads.

## What is recorded

Every `GET` of an installer (`/`, `/ps1`, `/vX.Y.Z`, `/vX.Y.Z/ps1`) writes one
data point to Workers Analytics Engine after the response is ready: cache hits
and failed serves included, with their status. `HEAD`, `/healthz`, other
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
| `blob8`     | `requested` | the tag in the path, or `latest` |
| `blob9`     | `version`   | the tag served (`x-erpc-tag`), or `unknown` on an error |
| `double1`   | `status`    | HTTP status; an installer served is `200` |
| `timestamp` |             | Analytics Engine, UTC |

The order is `INSTALL_BLOBS` in `installer/src/index.ts`, and a test pins
it. Columns are only ever appended; changing the meaning of one breaks the
export.

A day's installs, as the export reads them (Analytics Engine SQL API, with a
token that has *Account Analytics: Read*):

```sql
SELECT blob1 AS country, blob2 AS continent, blob4 AS language,
       blob5 AS os, blob6 AS arch, blob7 AS script, blob9 AS version,
       SUM(_sample_interval) AS count
FROM erpc_installs
WHERE timestamp >= toDateTime('2026-11-01 00:00:00')
  AND timestamp <  toDateTime('2026-11-02 00:00:00')
  AND double1 = 200
GROUP BY blob1, blob2, blob4, blob5, blob6, blob7, blob9
```

`SUM(_sample_interval)` is exact while Analytics Engine does not sample, and
the right estimate when it does. Analytics Engine keeps three months, which
bounds how far back a day can be written again.

## Privacy

Every value is checked against a short pattern in the worker and becomes
`unknown` otherwise, so a client cannot write a free-form value into the
dataset. No IP address, user agent, city, coordinates or any other
per-person value is read into the event. Recording cannot change or delay
the response: `writeDataPoint` does not wait on anything, and an error in it
is dropped (`recordInstall`).

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
stays that way; the credentials for reading the dataset and writing to
BigQuery live with the export. A queue or a direct BigQuery write from the
worker would need a Google credential in the worker.
