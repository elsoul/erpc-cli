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
 * Because of that, **the latest tag is resolved from GitHub only**. The R2
 * mirror is a fallback for downloading an installer whose tag is already
 * fixed, never for deciding which tag that is. Letting the mirror name the
 * tag would allow anyone able to write to the bucket, or to interpose on
 * dl.erpc.global, to pin every `curl … | bash` to an older release. The
 * response carries `x-erpc-source` saying which source answered.
 *
 * The convenience path therefore trusts DNS, TLS, this worker and GitHub
 * Releases. Operators who need more follow the high-assurance path in
 * docs/verify-release.md.
 */

export interface Env {
  GITHUB_REPO: string; // "elsoul/erpc-cli"
  MIRROR_BASE: string; // "https://dl.erpc.global"
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
    const got = await fetchInstaller(env, tag, file);
    if (!got) return text(`installer not found for ${tag}`, 502);

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

async function fetchInstaller(
  env: Env,
  tag: string,
  file: string,
): Promise<{ body: string; source: string } | null> {
  const candidates: Array<[string, string]> = [
    ["github", `https://github.com/${env.GITHUB_REPO}/releases/download/${tag}/${file}`],
    ["mirror", `${env.MIRROR_BASE}/${tag}/${file}`],
  ];
  for (const [source, u] of candidates) {
    try {
      const r = await fetch(u, {
        redirect: "follow",
        headers: { "user-agent": UA },
        cf: { cacheTtl: CACHE_TTL },
      });
      if (r.ok) {
        const body = await r.text();
        // cargo-dist installers start with a shebang or a PowerShell comment.
        if (body.startsWith("#!") || body.startsWith("#") || body.startsWith("<#")) {
          return { body, source };
        }
      }
    } catch {
      // try the next source
    }
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
