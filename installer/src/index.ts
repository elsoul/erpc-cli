// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * install.erpc.global
 *
 *   GET /            -> shell installer for the latest release (stable preferred)
 *   GET /ps1         -> PowerShell installer for the latest release (stable preferred)
 *   GET /vX.Y.Z      -> shell installer pinned to that tag
 *   GET /vX.Y.Z/ps1  -> PowerShell installer pinned to that tag
 *   GET /healthz     -> 200
 *
 * Trust model (docs/verify-release.md). This worker holds no secrets and no
 * keys, and it verifies no signatures: WebCrypto has no BLAKE2b, so minisign
 * cannot be checked here.
 *
 * Because it cannot verify anything, **everything it serves comes from GitHub
 * Releases and nothing else** — both the tag it resolves and the installer
 * body it returns. There is deliberately no R2 fallback: the body is piped
 * straight into a shell, so serving it from a source this worker cannot
 * verify would hand arbitrary code execution to anyone able to write to that
 * bucket or interpose on it. When GitHub is unreachable, this worker fails.
 *
 * The convenience path therefore trusts DNS, TLS, this worker, and GitHub
 * Releases. Operators who need more follow the high-assurance path in
 * docs/verify-release.md, which does not involve this worker at all.
 *
 * One thing is added to the body: a fixed tail, `AFTER_INSTALL` below, that
 * runs the binary the installer just put in place with `skills install`, so
 * the assistant's skills are on the machine from the start. It is a constant
 * in this file, the same for every request; it adds no source of code, only
 * a call to the binary the GitHub installer installed.
 */

export interface Env {
  GITHUB_REPO: string; // "elsoul/erpc-cli"
}

const TAG_RE = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const CACHE_TTL = 300;
const UA = "erpc-installer-worker (+https://github.com/elsoul/erpc-cli)";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return text("method not allowed", 405);
    }
    if (url.pathname === "/healthz") return text("ok", 200);

    const parts = url.pathname.split("/").filter(Boolean);
    let tag: string | null = null;
    let flavor: "sh" | "ps1" = "sh";

    if (parts.length === 0) {
      // latest shell installer
    } else if (parts.length === 1 && parts[0] === "ps1") {
      flavor = "ps1";
    } else if (parts.length === 1 && TAG_RE.test(parts[0])) {
      tag = parts[0];
    } else if (parts.length === 2 && TAG_RE.test(parts[0]) && parts[1] === "ps1") {
      tag = parts[0];
      flavor = "ps1";
    } else {
      return text("not found", 404);
    }

    // Normalise the cache key to the path: a query string changes nothing in
    // the response, and keying on it would let `?x=1`, `?x=2`, … miss the
    // cache and amplify requests to api.github.com.
    const cache = caches.default;
    const cacheKey = new Request(new URL(url.pathname, url.origin).toString(), { method: "GET" });
    const cached = await cache.match(cacheKey);
    if (cached) return cached;

    let tagSource = "pinned";
    if (!tag) {
      const latest = await resolveLatest(env);
      if (!latest) {
        return text(
          "could not determine the latest release from GitHub; retry, or install a pinned version with https://install.erpc.global/vX.Y.Z",
          502,
        );
      }
      tag = latest.tag;
      tagSource = latest.source;
    }

    const file = flavor === "sh" ? "erpc-installer.sh" : "erpc-installer.ps1";
    const got = await fetchInstaller(env, tag, file, flavor);
    if (!got) {
      return text(
        `could not fetch the installer for ${tag} from GitHub Releases; there is no fallback source for an executable script`,
        502,
      );
    }

    const res = new Response(withAfterInstall(got.body, flavor), {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": `public, max-age=${CACHE_TTL}`,
        "x-erpc-tag": tag,
        "x-erpc-tag-source": tagSource,
        "x-erpc-source": got.source,
        "x-content-type-options": "nosniff",
      },
    });
    ctx.waitUntil(cache.put(cacheKey, res.clone()));
    return res;
  },
};

function text(msg: string, status: number): Response {
  return new Response(msg, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

/**
 * What runs after the installer: `erpc skills install`, with the binary the
 * installer put in place. cargo-dist's installers end by calling their main
 * function (`download_binary_and_run_installer "$@" || exit 1`, and
 * `Install-Binary` in a try/catch), so a tail runs after a successful
 * install and not after a failed one. The binary is looked for where the
 * generated installer puts it, in its order of precedence: with
 * `ERPC_INSTALL_DIR`, `CARGO_DIST_FORCE_INSTALL_DIR` or
 * `ERPC_UNMANAGED_INSTALL` set, in that directory itself (cargo-dist's
 * "flat" layout; under `bin/` only when the directory is Cargo's home), and
 * otherwise in `~/.erpc/bin` (dist-workspace.toml). An earlier tail looked
 * under `bin/` for the first two and so ran a binary from an earlier
 * install; `installer/scripts/verify-against-real-installers.mjs` now pins
 * the layout and the endings this tail depends on. A failure here never
 * fails the install: `erpc skills install` can be run again by hand.
 */
export const AFTER_INSTALL: Record<"sh" | "ps1", string> = {
  sh: `
# erpc: put the assistant's skills on this machine (~/.erpc/skills), with the
# binary the installer above put in place: in the forced directory itself
# (bin/ only when that directory is Cargo's home), else in ~/.erpc/bin.
for _erpc_dir in "\${ERPC_INSTALL_DIR:-}" "\${CARGO_DIST_FORCE_INSTALL_DIR:-}" \\
    "\${ERPC_UNMANAGED_INSTALL:-}" "$HOME/.erpc/bin"; do
  [ -n "$_erpc_dir" ] || continue
  for _erpc_bin in "$_erpc_dir/erpc" "$_erpc_dir/bin/erpc"; do
    if [ -x "$_erpc_bin" ]; then
      "$_erpc_bin" skills install || say "could not write the skills; run: erpc skills install"
      break 2
    fi
  done
done
`,
  ps1: `
# erpc: put the assistant's skills on this machine (~/.erpc/skills), with the
# binary the installer above put in place: in the forced directory itself
# (bin\\ only when that directory is Cargo's home), else in ~/.erpc/bin.
$erpcDirs = @()
foreach ($erpcForced in @($env:ERPC_INSTALL_DIR, $env:CARGO_DIST_FORCE_INSTALL_DIR, $env:ERPC_UNMANAGED_INSTALL)) {
  if ($erpcForced) { $erpcDirs += $erpcForced }
}
$erpcDirs += Join-Path $HOME ".erpc\\bin"
:erpcFound foreach ($erpcDir in $erpcDirs) {
  foreach ($erpcBin in @((Join-Path $erpcDir "erpc.exe"), (Join-Path $erpcDir "bin\\erpc.exe"))) {
    if (Test-Path -LiteralPath $erpcBin -PathType Leaf) {
      & $erpcBin skills install
      if ($LASTEXITCODE -ne 0) { Write-Information "could not write the skills; run: erpc skills install" }
      break erpcFound
    }
  }
}
`,
};

/**
 * The installer, with [`AFTER_INSTALL`] after it. `trimEnd`, not a `\s*$`
 * regex: on a body that is not ours a backtracking regex over runs of
 * whitespace is polynomial, and CodeQL says so.
 */
export function withAfterInstall(body: string, flavor: "sh" | "ps1"): string {
  return `${body.trimEnd()}\n${AFTER_INSTALL[flavor]}`;
}

/**
 * A sanity check, not a security control: it rejects markup and an empty
 * body, so a 404 page becomes a clear 502 rather than being piped into a
 * shell. A plain-text or markdown error body opening with `#` is accepted
 * for the PowerShell flavour, because the real installer opens that way too.
 *
 * The shapes are those of the installers cargo-dist actually generates, taken
 * from `dist build --artifacts=global` output rather than from the template:
 * the shell installer starts with `#!/bin/sh`, and the PowerShell one starts
 * with a run of `#` licence comments, reaching its `<#` block several lines
 * in. An earlier version of this function required `<#` at position 0 and
 * would have rejected every real PowerShell installer.
 */
export function looksLikeInstaller(body: string, flavor: "sh" | "ps1"): boolean {
  const head = body.slice(0, 512).trimStart();
  if (head.length === 0) return false;
  // Any markup is an error page, whatever it claims to be.
  if (/^<(!|html|\?xml)/i.test(head)) return false;
  if (flavor === "sh") return head.startsWith("#!");
  return head.startsWith("#") || head.startsWith("<#");
}

/**
 * Fetch an installer script from the GitHub Release for `tag`.
 *
 * GitHub only, by design: this body is executed by the caller and this worker
 * cannot verify a signature, so there is no second source to fall back to.
 */
async function fetchInstaller(
  env: Env,
  tag: string,
  file: string,
  flavor: "sh" | "ps1",
): Promise<{ body: string; source: string } | null> {
  const url = `https://github.com/${env.GITHUB_REPO}/releases/download/${tag}/${file}`;
  try {
    const r = await fetch(url, {
      redirect: "follow",
      headers: { "user-agent": UA },
      cf: { cacheTtl: CACHE_TTL },
    });
    if (r.ok) {
      const body = await r.text();
      if (looksLikeInstaller(body, flavor)) {
        return { body, source: "github" };
      }
    }
  } catch {
    // fall through to the error below
  }
  return null;
}

/**
 * Latest stable tag, or newest published prerelease while no stable release exists.
 *
 * GitHub is the only place release artifacts are published, so there is no
 * second source to consult. If GitHub is unreachable we serve an error
 * rather than a version we cannot vouch for.
 */
interface Release {
  tag_name: string;
  draft: boolean;
  prerelease: boolean;
  published_at: string;
}

function publishedRelease(value: unknown): value is Release {
  if (!value || typeof value !== "object") return false;
  const release = value as Partial<Release>;
  return typeof release.tag_name === "string" && TAG_RE.test(release.tag_name)
    && release.draft === false && typeof release.prerelease === "boolean"
    && typeof release.published_at === "string"
    && Number.isFinite(Date.parse(release.published_at));
}

async function resolveLatest(env: Env): Promise<{ tag: string; source: string } | null> {
  const headers = { "user-agent": UA, accept: "application/vnd.github+json" };
  const base = `https://api.github.com/repos/${env.GITHUB_REPO}/releases`;
  try {
    const stable = await fetch(`${base}/latest`, { headers, cf: { cacheTtl: CACHE_TTL } });
    if (stable.ok) {
      const release: unknown = await stable.json();
      return publishedRelease(release) && !release.prerelease
        ? { tag: release.tag_name, source: "github-latest" } : null;
    }
    // Only a missing stable release enables the prerelease fallback. Outages
    // and rate limits must not silently change the version selected.
    if (stable.status !== 404) return null;

    let newest: Release | null = null;
    for (let page = 1; ; page++) {
      const response = await fetch(`${base}?per_page=100&page=${page}`, {
        headers, cf: { cacheTtl: CACHE_TTL },
      });
      if (!response.ok) return null;
      const releases: unknown = await response.json();
      if (!Array.isArray(releases)) return null;
      for (const release of releases) {
        if (publishedRelease(release) && release.prerelease
          && (!newest || Date.parse(release.published_at) > Date.parse(newest.published_at))) {
          newest = release;
        }
      }
      if (releases.length < 100) break;
    }
    return newest ? { tag: newest.tag_name, source: "github-prerelease" } : null;
  } catch {
    return null;
  }
}
