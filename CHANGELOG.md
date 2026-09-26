# Changelog

## Unreleased

## 0.2.3 — 2026-09-26

- Add `erpc app init --template <name>@<tag>`: fetch a registered template's
  GitHub release asset, verify it against a pinned or explicitly supplied
  `--sha256`, validate its `erpc-template.json` manifest, collect answers from
  `--set`/`--domain`/`--email` or interactively, and generate a
  `cloudflare-worker` application. See
  [`docs/TEMPLATES.md`](./docs/TEMPLATES.md) for the manifest contract and
  [the README](./README.md#create-an-application-from-a-template) for usage.
- Register the OAuth client for a template with a `broker-register` prompt
  during `erpc app init --template`: the CLI checks the broker's discovery
  document, files a registration request, shows the broker's approval page and
  code, and waits for the approval, accepting the new client id only when the
  approved client name and redirect URIs match the request. The request's device
  code is never shown: a broker response that puts it in anything the CLI would
  print is refused without printing that value. See
  [the README](./README.md#registering-your-app-with-the-oidc-broker).
- Register the `stablecoin-manager` template (the `erpc-template.tar.gz` release
  asset of `elsoul/stablecoinmanager`) and pin its `v0.1.0` asset, so
  `erpc app init --template stablecoin-manager@v0.1.0` needs no `--sha256`.
- On Windows, open a URL in the browser only when it is an `http` or `https` URL
  whose parsed form consists of ASCII letters, digits, and the characters
  `-._~:/?#[]@$'()*+,;=`; any other URL is only printed. This covers both
  `erpc login` and the broker approval page.
- Add `erpc deploy --target cloudflare` for a `cloudflare-worker` application:
  authenticate and fix a Cloudflare account through project-local `wrangler`,
  reuse-or-create KV namespaces, generate or collect Worker secrets without ever
  overwriting an existing one, run a read-only preflight, deploy, and verify the
  result with `/health` and OAuth-authorize-redirect probes. `--target`,
  `--yes`, `--no-provision`, `--dry-run`, `--verify-only`, and
  `--ack-backup <KEY>` are new flags. Linux and macOS only in this release; see
  [the README](./README.md#deploy-to-cloudflare) for usage and the required
  Cloudflare API token permissions.

## 0.2.2 — 2026-08-29

- Make `erpc login` discover the authorization server's supported scopes and
  fall back to identity authentication while Cloud OAuth is disabled.

## 0.2.1 — 2026-08-28

- Rebuild the command interface with a typed declarative parser and generated,
  command-specific help.
- Print the colored ERPC welcome artwork after installation and with
  `erpc --print`.

## 0.2.0 — 2026-08-28

- Move the CLI runtime and development workflow from Node.js to Deno 2.9.
- Distribute standalone Linux, macOS, and Windows executables for x86-64 and
  ARM64 from R2 with checksum-verifying, non-root installers.
- Use the Linux Secret Service for refresh credential storage without a native
  npm dependency.
- Download and verify a pinned application-local Node.js runtime when a target
  node needs one.
- Add private `~/.erpc/config.toml` application and SSH node configuration.
- Create named applications under `~/.erpc/apps` and add `erpc app list`.
- Add `erpc deploy` with manifest discovery, Linux build gating, SSH upload,
  systemd activation, application-local Node runtime fallback, and rollback.

## 0.1.0 — 2026-08-28

- Add OAuth Device Authorization login with operating-system keychain storage.
- Add masked usage, capability catalog, credit snapshot, and credential-free
  resource inventory commands.
- Add interactive `erpc app init` scaffolding for Node.js with pnpm and Deno.
- Add runnable Node.js and Deno Hono examples.
- Publish the initial npm package.
