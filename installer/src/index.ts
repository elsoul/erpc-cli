// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * install.erpc.global
 *
 *   GET /            -> shell installer for the latest stable release
 *   GET /ps1         -> PowerShell installer for the latest stable release
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
 * The R2 mirror still serves release *archives*, whose integrity is pinned by
 * the hashes in the signed manifest. That is a different trust question and
 * is handled by the client that checks those hashes, not here.
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

    const res = new Response(got.body, {
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
 * Fetch an installer script from the GitHub Release for `tag`.
 *
 * GitHub only, by design: this body is executed by the caller and this worker
 * cannot verify a signature, so there is no second source to fall back to.
 */
/**
 * A sanity check, not a security control: it turns a 404 page or an empty
 * body into a clear 502 instead of piping markup into a shell.
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
 * Latest stable tag, from GitHub only.
 *
 * There is deliberately no mirror fallback here: this worker cannot verify
 * the mirror's signed `latest.json`, so accepting it would let whoever can
 * write to the bucket choose which version every reader installs. If GitHub
 * is unreachable we serve an error rather than a version we cannot vouch for.
 */
async function resolveLatest(env: Env): Promise<{ tag: string; source: string } | null> {
  try {
    const r = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/releases/latest`, {
      headers: { "user-agent": UA, accept: "application/vnd.github+json" },
      cf: { cacheTtl: CACHE_TTL },
    });
    if (r.ok) {
      const j = (await r.json()) as { tag_name?: string };
      if (j.tag_name && TAG_RE.test(j.tag_name)) return { tag: j.tag_name, source: "github-latest" };
    }
  } catch {
    // fall through
  }
  return null;
}
