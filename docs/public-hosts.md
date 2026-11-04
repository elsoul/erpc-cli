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
  that rule was deleted. It turns a NUL byte into a space, and then applies
  five rules, all about tab, CR, or separating two adjacent URLs so that
  neither is read as part of the other.

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
  The ones known today are stated in the script header, and each is pinned
  by a `KNOWN LIMIT` case in the self-test, so closing one means changing a
  case rather than discovering it:

  - **Shell string concatenation next to a URL, in part.** In a shell word,
    quoted and unquoted parts and substitutions are joined, so a quote or
    backtick that ends the authority does not end the host the shell
    builds:

    ```text
    $ bash -c 'echo "https://erpc.global`echo .evil.example.net`/p"'
    https://erpc.global.evil.example.net/p
    ```

    The reason the terminator set is safe — none of its characters can
    appear in a real host — is about *literal* text, and runtime joining is
    exactly what breaks it. Closing the class completely needs a model of
    how the shell builds a word, which is a parser in a text matcher, so it
    is closed where the shape is unambiguous and open where it is not.

    **Closed** — reported:
    - a quote right after the scheme, followed by anything that can begin a
      host or an interpolation. `https://"evil.example.net"/x` is the URL
      `https://evil.example.net/x` and needs no declared host at all; it was
      allowed until a review found it, because the scan stops the authority
      at the quote and an empty authority returned before anything else was
      looked at.
    - a quote ending a host, followed at once by `$`, a backtick, `@`, `{`,
      a digit, `_`, or the same quote again. `@` replaces the host outright:
      `"https://erpc.global"@evil.example.net/x` resolves to
      `evil.example.net`.
    - a backtick inside a host followed by a letter or a digit, which is a
      command name.

    **Open** — *everything else in the class*. This is stated as the
    complement of the closed set rather than as a list of open shapes,
    because a list was written once and the next review found members of
    the class that were on neither side of it. Precisely:
    - a quote ending a host, followed by any character not listed as closed
      above. That includes `.`, which is a method call in Rust, TypeScript
      and Python (`"https://erpc.global".to_string()`), and a letter, which
      includes a quote *inside* the host as the URL Standard permits —
      `https://api.github.com'evil.example.net/x` resolves to that host,
      which a wildcard record serves — and which would also report a
      possessive in prose. It includes `,` `]` `}` `-` `!` `=` and the
      *other* quote, each of which begins a correct line somewhere: a JSON
      array, an index, a jq filter nested in a shell argument.
    - a backtick after a declared host followed by anything other than a
      letter or digit, *including* when it is the last character of the
      authority — a space, `/`, `(`, `{`, `.`, a quote or the end of the
      line. Under a shell that backtick may open a command substitution:
      ``https://erpc.global`/bin/echo .evil.example.net`/p`` resolves to
      `erpc.global.evil.example.net`. In Markdown and JavaScript the same
      backtick closes an inline code span or a template literal, and only a
      parser could tell which.

    Representative members of both are pinned as `KNOWN LIMIT` cases in the
    self-test. The two closes also report some correct lines, loudly: a
    regex end anchor written after a quoted URL, `'"https://erpc.global"$'`,
    and in Markdown a word run straight on from inline code,
    ``` `https://erpc.global`s docs ```.

    The design holds only while every construct that interpolates at
    runtime, in every file type tracked here, is either tracked as a
    balanced form or reported. That is a list, kept in the script, and a new
    file type with a new interpolation syntax needs an entry in it before it
    is safe.

  - **A URL split across two lines** by a multi-line string literal. The
    Standard deletes LF as it deletes tab and CR; this gate reads one line
    at a time.

  Shapes this page once listed as limits, and which are now **closed**
  rather than restated:

  - a colon followed by something that is not a port. It no longer ends the
    authority, so `https://declared:x.other/` is reported where it used to
    be judged as `declared`.
  - a backtick expression with **nothing before it**, as in
    ``https://`cat host`.other/``. An authority that begins with punctuation
    has no literal part to judge, and is reported instead of skipped. This
    page described the whole backtick-with-a-space shape as closed when only
    this part was; the part with a declared host in front is the first open
    item above.
  - a NUL byte, which hid the rest of its line from the scan and is now a
    space by the time the scan sees it.
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
- `erpc_core::endpoints::ensure_service_url` accepts a URL on any host
  declared in the code, of any kind: `https` or `wss` with no explicit
  port, or any of `http`, `https`, `ws` and `wss` with any port on loopback.
  - Every request URL `erpc` builds is a constant, and a test runs each one
    through it.
  - At runtime it is called before `erpc` opens a page in a browser. The only
    such page is the issuer's verification page, and `erpc-auth` has already
    required that to be an `https` URL on the issuer's own host, made of a
    narrow set of characters.
  - Where the access token and the refresh token may each be sent is
    narrower than this list, and is set out in `SECURITY.md`.
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
| `auth-api.erpc.global` | OAuth device flow: issue, refresh, revoke; its verification page is opened in the browser | the device code, and the refresh token to the token and revoke endpoints only; never the access token |
| `user-api.erpc.global` | ERPC account API | auth-api access token only |
| `mcp-user-api.erpc.global` | ERPC User MCP server, and the issuer of its own tokens | the device code, the MCP refresh token to the token and revoke endpoints, and the MCP access token; never the auth-api tokens |
| `x402.erpc.global` | x402 payments and credit top-up | x402 billing session token and payment headers only; never auth-api/MCP tokens, never ERPC API keys |
| `edge.erpc.global` | RPC endpoint, for the planned `check` command | RPC API key supplied by the operator |
| `dashboard.erpc.global` | opened in the browser for signup and payment setup | none |
| `erpc.global` | project home page, linked from package metadata | none |
| `solana-snapshot-*.erpc.global` | snapshot mirrors | none |
| `install.erpc.global` | installer script | none |
| `github.com`, `api.github.com` | releases, attestations, the pinned restic `erpc backup` installs | none |
| `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | release artifact downloads | none |
| `bitcoincore.org` | Bitcoin Core signed checksum manifests and official release archives | none |
| `chain.base.org` | Base public snapshot discovery and protocol documentation | none |
| `datadirs.optimism.io` | OP Mainnet storage-v2 snapshot catalog, checksums and archives | none |
| `mainnet-v2-snapshots.base.org`, `sepolia-v2-snapshots.base.org` | Base network-specific public manifests and snapshot components | none |
| `crates.io`, `index.crates.io`, `static.crates.io` | dependencies (cargo, build time) | none |
| `registry.npmjs.org` | installer worker dependencies (npm, build time) | none |
| `sh.rustup.rs` | toolchain installation in CI | none |
| `api.testnet.solana.com` | Solana testnet's public RPC, which the Solana CLI erpc runs on the operator's machine reads and sends transactions to | none |
| `docs.jito.wtf` | Jito's region table, read by the scheduled job that checks erpc's copy of it | none |
| `127.0.0.1`, `localhost`, `[::1]` | planned OAuth redirect listener and local MCP server; plaintext `http`/`ws` allowed here only | session token for the local MCP server |

This version of `erpc` contacts `auth-api.erpc.global` and
`user-api.erpc.global`, and opens the verification page on
`auth-api.erpc.global` in a browser during `erpc login`. The other rows are
contacted by a later version, by the release pipeline, or at build time, as
their purpose says.

The restic that `erpc backup` runs sends one more credential to
`user-api.erpc.global`: a storage access key, as Basic authentication, to
`/v3/storage/restic` only. It is not a session token, and erpc itself never
sends it.

## Address echo services

`ADDRESS_ECHO_HOSTS` lists services that answer a request with the address it
came from, and nothing else. `erpc ai` may run `curl` on one of them on the
operator's computer without asking first, to learn the operator's public
address; only the bare host is allowed, with no path or query. `erpc` itself
never contacts them, and nothing is sent but the request.

| Host | Purpose | Credentials that may be sent |
|---|---|---|
| `api.ipify.org`, `api64.ipify.org`, `checkip.amazonaws.com`, `icanhazip.com`, `ifconfig.co`, `ifconfig.me` | the operator's public address, as plain text | none |

## Hosts a node contacts

`NODE_HOSTS` lists hosts named in the playbooks and templates erpc carries for
a node (`crates/erpc-chain-solana/templates/`, `crates/erpc-chain-arc/templates/`,
`crates/erpc-chain-eth/templates/`, `crates/erpc-chain-sui/templates/`,
`crates/erpc-chain-tron/templates/`, `crates/erpc-chain-op/templates/`,
`crates/erpc-chain-nitro/templates/`), in the Jito region table (`crates/erpc-chain-solana/regions/`) and in the Arc
network tables (`crates/erpc-chain-arc/networks/`, `crates/erpc-chain-nitro/networks/`). The node reaches them once it runs the
scripts those templates write; `erpc` itself never contacts them, and the gate
accepts them in those trees and nowhere else. A plaintext URL is
accepted there when the node's client uses plaintext for that service.

| Host | Why the node reaches it |
|---|---|
| `raw.githubusercontent.com`, `cdn.robinhood.com` | Nitro's exact source-pinned Arbitrum chain information and official Robinhood chain/genesis metadata; byte digests are checked |
| `snapshot.arbitrum.foundation` | Nitro's official checksummed snapshot catalog and bootstrap archives |
| `docker.io`, `registry-1.docker.io`, `auth.docker.io` | Official Nitro container content, pulled by reviewed manifest digest; Docker registry authorization only, never ERPC or L1 provider credentials |
| `feed.mainnet.chain.robinhood.com`, `feed.testnet.chain.robinhood.com`, `delayed-feed.mainnet.chain.robinhood.com` | Official Robinhood sequencer feeds for their respective networks |
| `sequencer.mainnet.chain.robinhood.com`, `sequencer.testnet.chain.robinhood.com` | Official Robinhood transaction forwarding endpoints; no signing key or provider credential is sent |
| `metrics.solana.com` | the cluster's public metrics, which the validator service reports to |
| `ny.testnet.block-engine.jito.wtf` | the testnet startup script's Jito block engine when no region is set |
| `ny.testnet.bam.jito.wtf` | the testnet Jito startup script's BAM endpoint when none is set |
| `frankfurt.mainnet.block-engine.jito.wtf` | the mainnet startup script's Jito block engine when no region is set |
| `mainnet.block-engine.jito.wtf`, `testnet.block-engine.jito.wtf` | the region table's network-wide block engines |
| `amsterdam.mainnet.block-engine.jito.wtf`, `dublin.mainnet.block-engine.jito.wtf`, `london.mainnet.block-engine.jito.wtf`, `ny.mainnet.block-engine.jito.wtf`, `slc.mainnet.block-engine.jito.wtf`, `singapore.mainnet.block-engine.jito.wtf`, `tokyo.mainnet.block-engine.jito.wtf` | the region table's mainnet block engines; the host's nearest is written into its startup script |
| `dallas.testnet.block-engine.jito.wtf` | the region table's other testnet block engine |
| `dallas.testnet.relayer.jito.wtf`, `ny.testnet.relayer.jito.wtf` | the testnet relayers, one per region |
| `dallas.testnet.bam.jito.wtf` | the other testnet BAM endpoint |
| `files.old-faithful.net` | the Old Faithful archive a Solana Index RPC node's `faithful-cli` reads epoch indexes and blocks from |
| `api.mainnet-beta.solana.com` | Solana mainnet's public RPC: Old Faithful asks it for the current epoch and proxies to it what its archive cannot answer |
| `snapshots.reth.rs`, `snapshots-r2.reth.rs` | where an Ethereum RPC node's `reth download` lists Reth's official snapshot and fetches its archives |
| `hoodi.checkpoint.sigp.io` | Sigma Prime's Hoodi checkpoint server for a dedicated validator beacon node |
| `mainnet.checkpoint.sigp.io` | Sigma Prime's checkpoint server, which an Ethereum RPC node's Lighthouse starts from |
| `snapshots.avorio.network` | a public Solana snapshot mirror on Cloudflare R2, run by Avorio Network; a Solana RPC node may fetch its first snapshot from it when it is fresher or faster than the ERPC mirrors |
| `rpc.testnet.arc.io`, `rpc.mainnet.arc.io` | Arc's own relays: the consensus layer follows them, and the execution layer forwards transactions it is sent to them |
| `rpc.drpc.testnet.arc.io`, `rpc.blockdaemon.testnet.arc.io`, `rpc.drpc.mainnet.arc.io`, `rpc.blockdaemon.mainnet.arc.io`, `rpc.quicknode.mainnet.arc.io` | the other relays the Arc consensus layer follows, for redundancy |

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
| `docs.arc.io` | the Arc RPC skill (`crates/erpc-skills/skills/arc-rpc`) |
| `docs.anza.xyz` | the Solana skills: Agave's operator guide |
| `docs.firedancer.io` | the Solana validator skills: Firedancer's guide |
| `reth.rs` | the Ethereum skill: Reth's documentation |
| `lighthouse-book.sigmaprime.io` | the Ethereum skill: Lighthouse's book |
| `build.avax.network` | the Avalanche skill |
| `docs.sui.io` | the Sui skill |
| `solana.com` | Solana network, RPC and staking references in `docs/chains/solana.md` |
| `ethereum.org` | Ethereum networks, clients and validator rules in `docs/chains/ethereum.md` |
| `blog.ethereum.org` | Ethereum Foundation protocol upgrade announcements in `docs/chains/ethereum.md` |
| `docs.arbitrum.io` | Nitro node and validator documentation in `docs/chains/` |
| `docs.base.org` | Base node documentation in `docs/chains/` |
| `docs.optimism.io` | OP Mainnet and OP Stack node documentation in `docs/chains/` |
| `docs.robinhood.com` | Robinhood Chain node documentation in `docs/chains/` |
| `docs.soneium.org` | Soneium network documentation in `docs/chains/` |
| `snapshot-explorer.arbitrum.io` | Official Arbitrum and Robinhood snapshot catalog in `docs/chains/` |
| `docs.bnbchain.org` | BNB Smart Chain node and validator documentation in `docs/chains/` |
| `docs.kaia.io` | Kaia node documentation in `docs/chains/` |
| `docs.monad.xyz` | Monad node and validator documentation in `docs/chains/` |
| `docs.polygon.technology` | Polygon PoS node documentation in `docs/chains/` |
| `forum.polygon.technology` | Polygon official upgrade announcements in `docs/chains/` |
| `hyperliquid.gitbook.io` | Hyperliquid node and staking documentation in `docs/chains/` |
| `pkg.category.xyz` | Category Labs Monad package-signing public key in `docs/chains/` |
| `bitcoin.org` | Bitcoin full-node operator guide in `docs/chains/` |
| `developer.bitcoin.org` | Bitcoin Core RPC reference in `docs/chains/` |
| `developers.tron.network` | TRON node and Super Representative documentation in `docs/chains/` |
| `docs.near.org` | NEAR node and validator documentation in `docs/chains/` |
| `downloads.avax.network` | Avalanche release-signing public key in `docs/chains/` |
| `near.org` | NEAR validator requirements in `docs/chains/` |
| `snapshots.node.kaia.io` | Official Kaia snapshot manifests in `docs/chains/` |
| `tronprotocol.github.io` | Official TRON deployment reference in `docs/chains/` |

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

## Sui node bootstrap and peering

The Sui node templates use these public network destinations. The CLI does not
send credentials to them. Snapshot verification checks the genesis network and
committee commitments; release archives use pinned GitHub SHA-256 metadata.

| Host | Purpose |
|---|---|
| `fullnode.mainnet.sui.io` | Read-only Mainnet validator membership observations |
| `fullnode.testnet.sui.io` | Read-only Testnet validator membership observations |
| `formal-snapshot.mainnet.sui.io` | Mainnet formal snapshots |
| `formal-snapshot.testnet.sui.io` | Testnet formal snapshots |
| `checkpoints.mainnet.sui.io` | Mainnet snapshot epoch/checkpoint metadata |
| `checkpoints.testnet.sui.io` | Testnet snapshot epoch/checkpoint metadata |
| `mel-00.mainnet.sui.io` | Mainnet state-sync peer |
| `ewr-00.mainnet.sui.io` | Mainnet state-sync peer |
| `yto-tnt-ssfn-01.testnet.sui.io` | Testnet state-sync peer |
| `yto-tnt-ssfn-00.testnet.sui.io` | Testnet state-sync peer |

## TRON node observations and documentation

- `api.trongrid.io` and `nile.trongrid.io`: fixed official Mainnet and Nile
  read-only HTTP APIs used on the managed node to verify genesis, advancing
  heads, SR membership, current chain parameters and dedicated Witness-only
  permissions. These destinations are allowed only in node templates. Neither
  ERPC credentials nor witness keys/passwords are sent to them; no transaction
  construction, signing or broadcast endpoint is called.
- `nileex.io`: official Nile release/signing-key documentation, linked only.
- `www.freedesktop.org`: official systemd encrypted-credential semantics, linked only.
- `packages.ubuntu.com`: Ubuntu package documentation for the selected
  architecture-specific OpenJDK packages, linked only.

TRON Java release JARs, detached signatures and immutable network configuration
are fetched from the already declared GitHub distribution host. Bundled public
signing certificates and pinned SHA-256 digests authenticate the release.

## OP-family follower nodes

The carried follower templates select these node destinations. The controller
never sends ERPC account credentials to them. OP images are selected by immutable
platform digest; Base native archives require the pinned public signer and digest.

| Host | Purpose |
|---|---|
| `us-docker.pkg.dev` | Official OP Labs op-node/op-reth image distribution |
| `mainnet-sequencer.optimism.io`, `sepolia-sequencer.optimism.io` | OP transaction forwarding |
| `mainnet-sequencer.base.org`, `sepolia-sequencer.base.org` | Base transaction forwarding |
| `rpc.soneium.org`, `rpc.minato.soneium.org` | Sequencer endpoints selected by Soneium's pinned registry configurations |

Operator-selected Ethereum execution and beacon upstreams are a separate node
input. Their URLs and authentication headers live in a concealed 1Password field
and an encrypted systemd credential, not the public node record or Ansible bundle.
The shared loopback transport checks DNS/IP destinations, TLS, redirects and L1
identity, and excludes ERPC service hosts. This does not replace the fixed ERPC
account/payment endpoint lists. See the [transport contract](../crates/erpc-chain-rollup/README.md).
