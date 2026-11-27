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
of a release this worker served. Beyond that language subtag, a client cannot
write text of its choosing into the dataset: the tag in a pinned path is recorded only once a release by
that name has been served, and as `unknown` otherwise. No IP address, user
agent, city, coordinates or any other per-person value is read into the data
point. Recording cannot change or delay the response: `writeDataPoint` does
not wait on anything, and an error in it is dropped (`recordInstall`).

This is about the data point. The worker also has Cloudflare's Workers
observability turned on (`[observability]` in `installer/wrangler.toml`), as
it had before counts were added.

## Error reports

When its `SENTRY_DSN` Worker secret is set, the worker reports its own
failures in answering a `GET` to Sentry: an exception, a fetch from GitHub
Releases that failed (with the release tag and the installer's flavour), or
a deployment that selected no release. The Sentry SDK does not report on
`HEAD` or `OPTIONS` requests. Each failed request is one report; there is no
sampling, so while GitHub is unreachable or a deployment has no release,
every request sends one.

Without the secret the worker reports nothing. It also reports nothing when a
`SENTRY_TUNNEL` variable is set, or when the DSN names anything but a Sentry
ingest host over https: `o<org id>.ingest.sentry.io`, or the same in Sentry's
`de` or `us` region. Those are among the hosts `WORKER_REPORT_HOST_PATTERNS`
in `crates/erpc-core/src/endpoints.rs` declares for this worker, and a test
checks that. It also refuses a DSN whose key is missing; whose key, or the
optional part after it, has characters other than letters, digits and `_`;
whose path is anything other than the project number; that has a `?` or `#`;
that names a port other than the default; or that has a space or line break
inside it. Some of these fail the Sentry SDK's own parser, which prints a DSN
it cannot parse, key included, to the logs; a port would send somewhere else;
and for the rest the worker accepts only the plain form. A refused value is
never used as the SDK's DSN, and an accepted one is given to the SDK rebuilt
from its checked parts, never as typed. Spaces and line breaks around the
value are trimmed. When the secret is set but not used for one of these
reasons, the worker logs one warning per Worker instance, in its Cloudflare
logs, saying which reason applies; the warning never contains the DSN or any
part of it. The DSN is never in this repository; a maintainer sets it with
`npx wrangler secret put SENTRY_DSN` in `installer/`. Whoever holds the DSN
can submit events to that Sentry project and cannot read them.

A report names what failed in the worker, and the request's method and URL
without its query string. The Sentry SDK would also attach the request's
headers (among them the user agent, `Accept-Language` and Cloudflare's
client IP and location headers), its query string, a user, the client's
timezone, any `sentry-*` baggage the request carries and the trace id its
`sentry-trace` header names;
`installer/src/sentry.ts` removes all of them before sending. Request bodies
are not read, and what the worker logs to the console is not attached.

Only error events are sent. Performance tracing is off, including when a
request carries a `sentry-trace` header asking for a sampled trace: the
worker samples no trace, drops any transaction before it is sent, and adds
no trace headers to its fetches from GitHub.

`installer/src/sentry.test.ts` runs the SDK with the worker's options and a
transport that keeps what would be sent. The network is a stub that presents
itself as the native `fetch`, so the SDK instruments it as it does in
Cloudflare's runtime. The tests cover a failed fetch from GitHub, a request
asking for a sampled trace, a deployment with no release selected and an
exception. Each checks that one error event is sent, no transaction, and
none of the request's IP address, user agent, language, cookie, timezone,
city or query. Where the worker fetched GitHub, they also check that the
fetch carried no trace headers. Further tests check that a refused DSN, or a
tunnel, sends nothing. The tests run under Node, not in Cloudflare's runtime.

Reports go from Cloudflare to Sentry, so Sentry sees Cloudflare's address,
not the address of the person installing.

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
no credential that could change what it serves. An Analytics Engine binding
is not a credential, so counts add none. Its one secret, the optional
Sentry DSN above, can only submit events to its Sentry project.
