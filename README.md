# ERPC CLI

Build and deploy applications for ERPC Cloud from the terminal. The first
release provides secure Cloud login, read-only account commands, minimal Hono
application templates for Node.js with pnpm and Deno, and build-gated SSH
deployment to user-owned Linux nodes. The CLI itself is a standalone executable
compiled with Deno; Node.js, npm, pnpm, and Deno are not required to run it.

## Install

Linux and macOS on x86-64 and ARM64 are supported. The installer selects the
matching binary automatically:

```bash
curl -fsSL https://storage.erpc.global/install | sh
```

The installer downloads the platform archive, requires its entry in the
versioned `SHA256SUMS` file, verifies the embedded CLI version, and installs it
at `~/.erpc/bin/erpc`. After installation it prints the ERPC welcome screen. It
never uses `sudo` or edits shell startup files. Add the directory to `PATH` when
the installer asks:

```bash
export PATH="$HOME/.erpc/bin:$PATH"
```

Windows on x86-64 and ARM64 uses the native PowerShell installer:

```powershell
irm https://storage.erpc.global/install.ps1 | iex
```

It installs `erpc.exe` below `%USERPROFILE%\.erpc\bin` and prints a PATH
instruction when needed. It also prints the ERPC welcome screen after verifying
the installed executable. Preview binaries are not yet notarized or
Authenticode-signed; platform signing is tracked on the roadmap.

For a review-first installation, download and inspect the script before running
it:

```bash
curl -fsSL https://storage.erpc.global/install -o erpc-install.sh
less erpc-install.sh
sh erpc-install.sh
```

On Windows, use the corresponding review-first flow:

```powershell
iwr https://storage.erpc.global/install.ps1 -OutFile erpc-install.ps1
Get-Content ./erpc-install.ps1
& ./erpc-install.ps1
```

The npm `0.1.x` package remains available for existing installations, but new
CLI releases are distributed as Deno-compiled binaries.

Run the welcome screen again at any time:

```bash
erpc --print
```

## Create an application

Run the interactive initializer and choose Node.js or Deno. A bare application
name is created below `~/.erpc/apps`:

```bash
erpc app init my-api
# Creates ~/.erpc/apps/my-api
```

For scripts and CI, select the runtime explicitly:

```bash
erpc app init my-node-api --runtime node
erpc app init my-deno-api --runtime deno
```

Pass a relative or absolute path when the source should live elsewhere. The CLI
records that external manifest in `~/.erpc/config.toml`:

```bash
erpc app init ./services/my-api --runtime node
```

Use `--name` to set the application name independently of its directory. The
initializer refuses to overwrite a non-empty directory.

The Node.js template uses pnpm, TypeScript, Hono, and a Node HTTP server:

```bash
cd my-node-api
pnpm install
pnpm test
pnpm build
pnpm dev
```

The Deno template uses TypeScript and Hono through Deno's package resolver:

```bash
cd my-deno-api
deno task check
deno task test
deno task build
deno task dev
```

Runnable versions are kept in [`examples/node-hono`](./examples/node-hono) and
[`examples/deno-hono`](./examples/deno-hono).

## Create an application from a template

`erpc app init --template` fetches a registered template's GitHub release asset,
verifies it against a checksum, validates its `erpc-template.json` manifest,
collects answers, and generates a `cloudflare-worker` application:

```bash
erpc app init my-wallet --template stablecoin-manager@v0.1.0
```

**This release ships with an empty template registry.** The public template
repository's owner, repo, and asset name (`TEMPLATE_REGISTRY` in
`src/app/template-registry.ts`) were not decided when this release was cut, so
`--template <name>@<tag>` fails with "Unknown template" for every `<name>` until
a later release adds an entry shaped like:

```ts
export const TEMPLATE_REGISTRY: TemplateRegistry = {
  'stablecoin-manager': {
    source: { owner: 'elsoul', repo: '<repo>', asset: 'erpc-template.tar.gz' },
    pins: { 'v0.1.0': '<64 lowercase hex characters>' }, // omit to ship unpinned
  },
}
```

The `stablecoin-manager@v0.1.0` example above becomes valid once that entry
(with a `v0.1.0` pin) ships in a future release.

Once a template _name_ is registered, `--sha256` lets you use a _tag_ that
release doesn't have a bundled checksum for yet — it cannot register an unknown
name by itself:

```bash
erpc app init my-wallet --template stablecoin-manager@v0.2.0 \
  --sha256 <64 lowercase hex characters>
```

Answer template prompts non-interactively with `--set KEY=VALUE` (repeatable),
or with the `--domain`/`--email` shorthands for prompts that declare those
flags. `--yes` is required for every non-interactive run — including one with no
terminal attached: the CLI never infers non-interactive mode from a missing TTY
and silently falls back to defaults; without `--yes` it fails with an explicit
"Use --yes in non-interactive mode" error instead. With `--yes`, every prompt
needs a `--set`/shorthand value or a manifest default; a run with missing or
invalid answers fails once, listing every problem together. `--set` never
accepts a value for a secret prompt (`secret-generate`, `secret-pipe`,
`secret-input`) — those are generated during a later `erpc deploy`, never during
`init`.

**This CLI does not sandbox a template.** Once its checksum is verified, a
template's `[build].command`, Cloudflare preflight checks, and secret generation
scripts run with your permissions. A tag this CLI release does not already pin
prints a one-time warning before collecting any answer; only proceed with
`--sha256` for a template and tag you trust. `docs/TEMPLATES.md` documents the
manifest contract for template authors, including this trust boundary in full.

Templates that register an OAuth client (a `broker-register` prompt) are not yet
supported end-to-end in this release: pass
`--set APP_OIDC_CLIENT_ID=<client id>` for a template that declares one.

## `erpc.toml`

Every generated application includes its portable ERPC manifest:

```toml
schema_version = 1
name = "my-api"

[app]
runtime = "node" # or "deno"
entrypoint = "src/index.ts"

[build]
command = ["pnpm", "build"]
artifact = "dist/index.js"

[run]
command = ["node", "dist/index.js"]
host = "0.0.0.0"
port = 8080

[deploy]
target = "auto"

[health]
path = "/health"
timeout_seconds = 30
```

The runtime field is intentionally extensible. Rust templates are planned
without changing the Node.js and Deno manifest shape.

Build and run commands use argument arrays so local build execution does not
need a shell to interpret project-controlled strings. Both templates expose
unauthenticated `/health` and `/doc` routes, listen on `0.0.0.0:8080` by
default, and handle graceful shutdown signals. The Deno build produces a single
executable; the Node.js build bundles its runtime dependencies into one
JavaScript artifact.

The Deno deployment build targets 64-bit Linux by default. Change the
`build:linux` task explicitly when deploying to an ARM64 node.

## Local configuration and applications

The CLI creates `~/.erpc` with directory mode `0700` and writes
`~/.erpc/config.toml` with mode `0600`. It stores application locations and SSH
node references, never access tokens, refresh tokens, passwords, or private key
material.

```toml
schema_version = 1
apps_directory = "/home/alice/.erpc/apps"
apps = []

[nodes.primary]
host = "203.0.113.10"
user = "ubuntu"
port = 22
# identity_file = "/home/alice/.ssh/erpc"
```

`identity_file` is only a path reference. Prefer an unlocked key in a standard
SSH agent. OpenSSH host-key verification remains enabled and deployment uses
non-interactive authentication. Set `ERPC_HOME` only when an isolated config
directory is needed.

List managed and externally registered applications:

```bash
erpc app list
```

## Deploy to a Linux node

From an application directory or any child directory, run:

```bash
erpc deploy
```

The CLI searches the current directory and its parents for the nearest
`erpc.toml`. Select another manifest or node explicitly when needed:

```bash
erpc deploy --config /path/to/app/erpc.toml
erpc deploy --node primary
erpc deploy --config /path/to/app/erpc.toml --node primary
```

`[deploy].target` selects a node from `~/.erpc/config.toml`. The default
`target = "auto"` works when exactly one node is configured; otherwise pass
`--node` or set the node name in the manifest.

Deployment is ordered so a local failure cannot touch the node:

1. Run the manifest's argument-array build command without a shell.
2. Require a regular artifact inside the application root. Deno artifacts must
   be Linux ELF binaries with a supported architecture.
3. Check Linux, architecture, systemd, passwordless sudo, and required tools on
   the target without uploading anything.
4. Upload a versioned release through SSH and keep the current release active
   until upload completes.
5. Create or update `erpc-<app>.service`, run `systemctl daemon-reload`, enable
   and restart it, and require the service to become active.
6. Restore the previous release and unit automatically if activation fails.

Node applications deploy their bundled JavaScript. If Node.js 20 or newer is not
already available, the CLI downloads a pinned Linux Node.js runtime on the local
machine, verifies the official archive checksum, and uploads it as an
application-local runtime; no remote package manager or download script is used.
Deno applications deploy the locally compiled binary and require no Deno
installation on the node.

The node must be user-owned, reachable through OpenSSH, and use systemd. This
first transport does not expose ERPC infrastructure credentials or resolve
private node addresses through the Cloud API.

## Deploy to Cloudflare

An application created from a `cloudflare-worker` template (see
[Create an application from a template](#create-an-application-from-a-template))
deploys through project-local `wrangler` instead of SSH:

```bash
erpc deploy
```

`--target cloudflare` is implied for a `cloudflare-worker` application and does
not need to be spelled out; it is only rejected when it disagrees with the
manifest (for example passing it against a `node`/`deno` application).
Additional flags:

```bash
erpc deploy --config /path/to/app/erpc.toml
erpc deploy --yes                      # non-interactive; fail on any missing answer
erpc deploy --ack-backup WALLET_MNEMONIC # acknowledge a secret-pipe backup non-interactively
erpc deploy --no-provision             # skip Cloudflare KV/secret provisioning
erpc deploy --dry-run                  # `wrangler deploy --dry-run`; reports missing secrets instead of stopping
erpc deploy --verify-only              # re-run only the post-deploy verification probes
```

Each run authenticates with `wrangler whoami`, running `wrangler login`
interactively only when no session exists and `CLOUDFLARE_API_TOKEN` is not set
(a token present with no valid session stops rather than silently switching
identity). It then fixes a Cloudflare account id into the project's
`wrangler.toml`, reuses or creates any KV namespace the template declares,
generates or collects any Worker secret the template declares that does not
already exist, and finally deploys and probes the result. **An existing
Cloudflare Worker secret is never overwritten** by this command.

A secret value never touches a file, an argument list, or an error message: it
is generated in memory, piped to `wrangler secret put` on stdin, and the buffer
used to generate it is zeroed immediately afterward.

CI re-deploys of an already-provisioned application should use:

```bash
erpc deploy --no-provision --yes
```

which never generates a wallet or a new secret and never opens an interactive
prompt.

**Required Cloudflare API token permissions**: creating a new Worker needs
`Workers Scripts:Edit` (Workers Admin); binding a route or a custom domain
additionally needs `Zone:Workers Routes:Edit`.

**Trust boundary**: a template's `[build].command`, `cloudflare.preflight`
commands, a `secret-pipe` prompt's `command`, and `wrangler` itself (invoked as
`pnpm exec wrangler`) are template-authored scripts. This command does not
sandbox them: they run with your permissions. Pin verification (`--sha256` or a
CLI-bundled pin) is the only control on that content.

**Known limitation (Windows)**: `erpc deploy --target cloudflare` requires
resolving `pnpm.cmd` the same way the Node.js SSH deploy path does, and is not
supported on Windows in this release; use macOS or Linux.

## Cloud login and read-only commands

```bash
erpc login
```

The CLI opens the ERPC verification page. It requests read-only usage and
resource scopes when the authorization server advertises them; during rollout,
it uses the existing identity scopes so base account authentication remains
available. If the browser cannot be opened, follow the URL printed in the
terminal. The access credential stays in process memory and the refresh
credential is stored in the operating-system keychain. Linux login currently
requires `secret-tool` and an available Secret Service; on Debian and Ubuntu it
is provided by the `libsecret-tools` package. The macOS and Windows binaries
currently support local application and deployment commands, while native
keychain-backed login on those systems remains on the roadmap.

When the login grants Cloud scopes:

```bash
erpc usage monthly
erpc usage monthly 2026-08
erpc credit
erpc resources catalog
erpc resources list
erpc resources get <resource-id>
erpc resources status <resource-id>
erpc logout
```

The catalog is capability-only in the first release: it does not claim prices or
regional availability that the service cannot verify. `credit` returns a
read-only cents balance, current burn rate, estimated time to zero, alert level,
and the snapshot validity timestamps.

`logout` revokes the refresh credential at the authorization server before
deleting its keychain entry. Credentials are never written to `erpc.toml`,
project files, environment files, logs, or shell history by the CLI.

Cloud purchase, billing, and resource mutation commands remain unavailable until
their scoped authorization and confirmation contracts are enabled. The SSH
deployment transport operates only on a node explicitly configured by the user.
See the [roadmap](./ROADMAP.md).

## Development

```bash
deno task fmt:check
deno task lint
deno task check
deno task test
deno task build
```

The root CLI requires Deno 2.9.6. Node.js with pnpm is used only by the
generated Node application example. The release workflow publishes versioned
Linux, macOS, and Windows binaries and checksums to R2 only from a
human-approved GitHub Release. See the [release guide](./docs/RELEASING.md).

Release notes are maintained in the [changelog](./CHANGELOG.md).

## License

MIT
