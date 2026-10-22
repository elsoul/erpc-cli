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
  balanced expression is skipped, there being nothing to check.

  **How the scan works, because it was rewritten.** The gate used to match a
  whole URL with one regex and then trim that match into a host. Four
  consecutive review rounds each found a bypass of the same class in it, for
  a structural reason rather than a run of oversights: the regex's authority
  ran over a fixed character class, that class had to be *narrower* than the
  set a URL parser accepts, so there was always some character at which the
  match ended early and handed over a prefix of the real host. The attack
  surface was the complement of that class, and a complement never empties.
  Worse, `grep -o` emits non-overlapping matches, so a match that absorbed
  the letters of a following scheme consumed that URL too — it was never
  emitted and never evaluated, and nothing was reported.

  The scan is now driven from **scheme occurrences**, not from URLs. Every
  `http`, `https`, `ws` or `wss` followed by a colon at a word boundary is
  found separately, and the rest of the line from that point is evaluated on
  its own. Three things follow, and they are the whole reason for the
  rewrite:

  - No URL can be swallowed by another. The thing matched is a scheme word,
    and the scan continues from just past its colon, so every occurrence is
    evaluated whatever its neighbours are.
  - There is no "how far does the authority run" question answered by a
    character class. The authority ends where it cannot continue, trailing
    punctuation is stripped **from the end only**, and what is left must
    *equal* a declared host. Nothing is trimmed into shape.
  - The default is to **report**. A shape nobody has thought of fails closed
    instead of passing silently.

  The cost is the trade, and it is real: a default-report gate will report
  correct lines until its terminator and trailing-punctuation sets cover
  them. That cost is *bounded* — two enumerated lists, fourteen entries
  between them, and a miss is a loud failure on a correct line that someone
  fixes the same day. The old cost was *unbounded*: a character class that
  had to be complete, with no way to know when it was, and a miss was a
  silent pass that survived review rounds.

  Each of those fourteen entries has a case that fails when it is dropped —
  which is a claim worth stating only because it was false when first made.
  A review measured it and found at most six of eighteen entries covered,
  six live and uncovered, and four doing nothing at all. The uncovered ones
  were the real problem: a refactor could have dropped an entry and produced
  false positives that are loud to users and silent to CI. Eight cases were
  added and the four dead entries removed, after checking that dropping all
  four changed neither verdict nor message on eight probes.

  Two further reasons the sets cannot hide a destination, which is what
  makes them different in kind from the character class they replaced.
  Every terminator except `"` and `'` is a character the URL Standard
  forbids in a host, so it cannot cut a real host short; those two are the
  disclosed limit below. And no character in the trailing-punctuation set
  can form a DNS label, so stripping a run of them off the end cannot move
  the registrable domain.

  Before the scan, the line is normalised once, in `normalise()`. The script
  header is the full statement of what that does; this page does not
  paraphrase it, because a paraphrase drifts — an earlier version of this
  paragraph went on describing a slash-collapsing rule for a while after
  that rule was deleted. There are five rules, and all five are about tab,
  CR, or separating two adjacent URLs so that neither is read as part of the
  other.

  What matters here is why any normalisation exists at all: the URL Standard
  strips tab, CR and LF from its input *before* parsing, so
  `ht<TAB>tps://host` and `https://declared<TAB>.other` are live
  destinations to anything that fetches them, and a matcher looking at the
  line as written sees nothing in the first and stops at the tab in the
  second. A backslash is refused rather than resolved, since resolving it
  would name a host the source does not. Slash counts need no rule: the
  scanner starts from the scheme and strips the leading slashes itself,
  whatever their number including none, so `https:host`, `https:/host` and
  `https:///host` are all judged on their real host.

  **The list of shapes this gate does not see is still not complete, and
  must not be read as if it were.** The rewrite removed the mechanism that
  produced a new one every round; it did not turn a text gate into a parser.
  Two are known today, both stated in the header:

  - a single or double quote inside the host. This one **is** reachable:
    `https://declared'other.example.net/` resolves to the host
    `declared'other.example.net`, which a wildcard record serves, so the DNS
    query reaches the other zone even though no public CA will issue for a
    label containing a quote. A quote ends the authority because a quote is
    how source code delimits a URL: admitting quotes instead would read
    `["https://a","https://b"]` — a JSON array of two URLs — as the single
    host `a","https`, which is a false positive on a correct and common
    line. Left open by choice, not by impossibility.
  - a URL split across two lines by a multi-line string literal. The
    Standard deletes LF as it deletes tab and CR; this gate reads one line
    at a time.

  Three shapes this page used to list as limits are now **closed** rather
  than restated:

  - a colon followed by something that is not a port. It no longer ends the
    authority, so `https://declared:x.other/` is reported where it used to
    be judged as `declared`.
  - a backtick expression containing a space, as in
    ``https://`cat host`.other/``. The authority does end early there — the
    backtick is deliberately not paired across a space, because pairing it
    would swallow ``` `https://semver.org`. ``` and
    ``` `https://user-api.erpc.global`.trim() ``` to end of line, both
    correct lines. What changed is the answer: an authority that begins with
    punctuation has no literal part to judge, and is now reported instead of
    skipped. It was skipped *silently* until a review found it, and the same
    commit that introduced the rewrite had removed this entry from the list
    without closing it.
  - a `,`, `;`, `)` or backtick between a declared host and a second URL,
    which no longer hides that URL because the second scheme occurrence is
    scanned in its own right. This one was never on the list; it was found
    by a review two rounds before the rewrite.

  What follows from all of this: the gate raises the cost of adding a
  destination and makes one appearing in a diff visible. It is not a proof
  that none can be written. Treat a URL in a review as something to read,
  not as something the gate has already cleared.
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
