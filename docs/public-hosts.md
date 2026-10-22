<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# Public hosts allowed in this repository

The machine-readable source of truth is `crates/erpc-core/src/endpoints.rs`.
This page explains it. The gates read the code, never this page. A unit test
fails if a host declared in the code is missing from this page, including the
documentation hosts below; the reverse direction is not checked, so treat the
code as authoritative if the two ever disagree.

- `scripts/check-endpoints.sh` applies **one rule**: every `http`, `https`,
  `ws` or `wss` URL in a tracked file must name a host declared in the code,
  and plaintext schemes are refused outside loopback. Hosts in
  `DOCUMENTATION_HOSTS` are accepted in prose files only. There is no
  heuristic about code blocks or command verbs; earlier versions had one and
  every review round found both a bypass and a false positive in it.
  A URL whose host is built from an expression is reported unless the literal
  text on both sides of the expression matches a declared `HOST_PATTERNS`
  pair, because an allowlisted prefix on its own says nothing about where the
  request goes. This holds wherever the expression sits: a host that *starts*
  with one still carries the registrable domain as a literal, and that is the
  part that decides the destination. Only a host that is entirely one
  balanced expression is skipped, there being nothing to check. The matcher
  looks at the authority only, so that one URL cannot absorb another on the
  same line and keep it out of the scan. That is a property the suite
  asserts case by case rather than something the design guarantees: each
  shape found so far has its own case, including five whose FIRST host is
  declared. Those matter because a declared first host produces no finding
  of its own, so the only thing that can name the second URL is the second
  URL being evaluated — and a comma, semicolon, closing paren or backtick
  between two URLs used to make the second one vanish from the scan
  completely, which every case in that block missed by putting an
  undeclared host first.
  Before matching, the line is normalised once, in `normalise()`, and the
  script's header is the full statement of what that does. In outline: ASCII
  tab and CR are deleted, except immediately before a scheme, where they
  become a space because there they separate two URLs rather than sit inside
  one; and any run of `/` after a scheme, **including no slash at all**,
  becomes `://`. These are not cosmetic. `ht<TAB>tps://host`,
  `https://declared<TAB>.other`, `https:host`, `https:/host` and
  `https:///host` are all live destinations to anything that fetches them --
  the URL Standard strips tab, CR and LF before parsing and skips any number
  of slashes after a special scheme -- and every one of them passed this gate
  without being looked at. A backslash is refused rather than resolved, since
  resolving it would name a host the source does not.

  **The list of shapes this gate does not see is not complete, and must not
  be read as if it were.** An earlier version of this page said "two shapes
  are not covered"; a later review found five more. The reason is structural:
  the matcher stops the authority at a fixed set of characters, and that set
  is narrower than the set a URL parser accepts, so a character at which the
  match ends early can always be looked for. The ones known today, all stated
  in the header:

  - a backtick expression containing a space ends the match at the space;
  - a colon not followed by digits ends it, so in `https://declared:x.other/`
    the host judged is the part before the colon. No URL parser accepts a
    non-numeric port, so that one is not a reachable destination;
  - a single or double quote inside the host ends it, and unlike the colon
    this one **is** reachable: `https://declared'other.example.net/` resolves
    to `declared'other.example.net`, which a wildcard record serves, so the
    DNS lookup reaches the other zone even though no public CA will issue for
    that label. It is left open rather than closed, which is a choice and
    not an impossibility: the tail test that closes the comma and backtick
    shapes could close this one too, but only if `check_url` could see the
    line beyond its match, which it cannot today. Admitting quotes to the
    authority instead would misread `["https://a","https://b"]` as the
    single host `a","https` and, worse, consume past the second URL so that
    it was never evaluated — trading a disclosed limit for a silent bypass;
  - a URL split across two lines by a multi-line string literal. The Standard
    deletes LF as it deletes tab and CR; this gate reads one line at a time.

  What follows from that: this gate raises the cost of adding a destination
  and makes one appearing in a diff visible. It is not a proof that none can
  be written. Treat a URL in a review as something to read, not as something
  the gate has already cleared.

  A guard over the colon shape was tried and removed. Its only unique catch
  was that unreachable shape, while it also reported
  `url.strip_prefix("https://")` and a declared host followed by ordinary
  punctuation in a comment.
  Some files are not scanned at all. That list is not copied here, because a
  copy drifts: run `scripts/check-endpoints.sh --print-exceptions`.
- `erpc_core::endpoints::ensure_service_url` is the runtime helper callers
  will use to check a destination. It has **no callers in this version**,
  which performs no network requests at all.
- `scripts/check-oss-hygiene.sh` additionally blocks cloud account
  identifiers, bare 1Password vault and item identifiers that appear beside
  the word `vault` or `item` on the same line, bearer-token and
  key-shaped strings, references to the organisation's other repositories,
  and internal documents. Credential *values* are caught by `gitleaks`
  (`.gitleaks.toml`). Read the script for what each rule actually matches.

What this buys: ERPC endpoints are compile-time constants and are never read
from configuration or environment variables, so a tampered configuration
cannot redirect ERPC traffic, and a new destination cannot enter the source
unreviewed. What it does not buy: this is not an egress sandbox, and it does
not constrain what a malicious dependency does at runtime.

Node endpoints the operator names themselves, such as `erpc check rpc --url`,
are not on this list: they are the user's own targets and are validated for
scheme and shape only.

| Host | Purpose | Credentials that may be sent |
|---|---|---|
| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke | none (public client `erpc-cli`) |
| `user-api.erpc.global` | ERPC account API | auth-api access token only |
| `mcp-user-api.erpc.global` | ERPC User MCP server | MCP access token only |
| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |
| `edge.erpc.global` | RPC endpoint, for the planned `check` command | RPC API key supplied by the operator |
| `dashboard.erpc.global` | opened in the browser for signup and payment setup | none |
| `erpc.global` | project home page, linked from package metadata | none |
| `solana-snapshot-*.erpc.global` | snapshot mirrors | none |
| `install.erpc.global` | installer script | none |
| `github.com`, `api.github.com` | releases, attestations | none |
| `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | release artifact downloads | none |
| `crates.io`, `index.crates.io`, `static.crates.io` | dependencies (cargo, build time) | none |
| `registry.npmjs.org` | installer worker dependencies (npm, build time) | none |
| `sh.rustup.rs` | toolchain installation in CI | none |
| `127.0.0.1`, `localhost`, `[::1]` | planned OAuth redirect listener and local MCP server; plaintext `http`/`ws` allowed here only | session token for the local MCP server |

Every row except the loopback one describes a destination a future version
will contact. This version contacts nothing.

## Documentation links

`DOCUMENTATION_HOSTS` in the same module lists hosts that may be linked from
prose (`.md`, `.txt`, `NOTICE`, `CHANGELOG`, `AUTHORS`) and nowhere else.
`erpc` never contacts them, and the gate refuses them in code. They exist so
one rule can cover the whole repository instead of guessing whether a link is
an instruction a reader will run.

| Host | Linked from |
|---|---|
| `www.contributor-covenant.org` | `CODE_OF_CONDUCT.md` |
| `keepachangelog.com` | `CHANGELOG.md` |
| `semver.org` | `CHANGELOG.md` |
| `elsoul.nl` | `NOTICE` |

Each row names a file that links the host today. Four hosts were removed from
this list, for two different reasons, neither of them "we might need it".
Two were linked only from files the gate never scans -- the licence texts and
generated third-party notices for one, the generated release workflow for the
other -- so the grant covered nothing it was asked to cover. The other two
had no URL anywhere in the repository at all.

This is a standing grant: once a host is here, a later change can turn a prose
link into an install command without the gate objecting. Keep the list short,
and treat an addition as a review question rather than a formality. The same
unit test that checks the table above also checks this one.
