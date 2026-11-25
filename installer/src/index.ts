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
 * Trust model (docs/verify-release.md). This worker holds no signing keys
 * and no credential that could change what it serves, and it verifies no
 * signatures: WebCrypto has no BLAKE2b, so minisign cannot be checked here.
 * Its one secret is the optional Sentry DSN (src/sentry.ts). Whoever holds
 * it can submit events to that Sentry project and cannot read them.
 *
 * Because it cannot verify anything, **everything it serves comes from GitHub
 * Releases and nothing else**. GitHub Actions resolves the tag before deploying
 * the worker, and the worker fetches the installer body for that tag. There is deliberately no R2 fallback: the body is piped
 * straight into a shell, so serving it from a source this worker cannot
 * verify would hand arbitrary code execution to anyone able to write to that
 * bucket or interpose on it. When GitHub is unreachable, this worker fails.
 *
 * The convenience path therefore trusts DNS, TLS, this worker, and GitHub
 * Releases. Operators who need more follow the high-assurance path in
 * docs/verify-release.md, which does not involve this worker at all.
 *
 * One thing is added to the body: a fixed tail, `AFTER_INSTALL` in
 * src/body.ts, that runs the binary the installer just put in place with
 * `skills install`, so the assistant's skills are on the machine from the
 * start. It is a constant in that file, the same for every request; it adds no source of code, only
 * a call to the binary the GitHub installer installed.
 *
 * Install counts. Every GET of an installer writes one data point to Workers
 * Analytics Engine (`recordInstall` below): the country, continent and
 * Cloudflare data centre of the request, the primary language tag of
 * `Accept-Language`, the installer flavour, the version asked for and the
 * version served, and the status. No address, no user agent, nothing that
 * tells one person from another, and no text a client chose beyond a two- or
 * three-letter language subtag: a pinned tag is recorded only when it was
 * served, so it names a published release.
 * Recording cannot change or delay the response: `writeDataPoint` does not
 * wait on anything, and any error in it is dropped. The columns are in
 * docs/install-counts.md. The binding holds no secret.
 */

import { captureMessage, withSentry } from "@sentry/cloudflare";

import { TAG_RE } from "./releases.ts";
import { sentryOptions, type SentryEnv } from "./sentry.ts";
import { looksLikeInstaller, withAfterInstall } from "./body.ts";

// Re-exported for the tests; the body logic lives in ./body.ts.
export { AFTER_INSTALL, looksLikeInstaller, withAfterInstall } from "./body.ts";

export interface Env extends SentryEnv {
  GITHUB_REPO: string; // "elsoul/erpc-cli"
  LATEST_RELEASE?: string;
  LATEST_RELEASE_SOURCE?: string;
  /** Install counts (wrangler.toml); absent in tests and `wrangler dev` without it. */
  INSTALLS?: AnalyticsEngineDataset;
}

const CACHE_TTL = 300;
const UA = "erpc-installer-worker (+https://github.com/elsoul/erpc-cli)";

/**
 * A fresh handler, before `withSentry` wraps it. The SDK marks the `fetch`
 * function it wraps and reuses that wrapper (and its options) for any later
 * wrap of the same function, so a test that wraps this with its own options
 * needs a function production never wrapped.
 */
export function makeHandler() {
  return {
    fetch: (request: Request, env: Env, ctx: ExecutionContext) => handle(request, env, ctx),
  } satisfies ExportedHandler<Env>;
}

async function handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
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

    // Counted after serving, cache hits and failures included; HEAD, the
    // health check and unknown paths above are not installs.
    const res = await serveInstaller(url, tag, flavor, env, ctx);
    if (request.method === "GET") recordInstall(env, request, tag, flavor, res);
    return res;
}

// Errors go to Sentry when the SENTRY_DSN secret names a Sentry ingest host
// (src/sentry.ts).
export default withSentry((env: Env) => sentryOptions(env), makeHandler());

async function serveInstaller(
  url: URL,
  pinned: string | null,
  flavor: "sh" | "ps1",
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  let tag = pinned;
  let tagSource = "pinned";
  if (!tag) {
    if (!env.LATEST_RELEASE || !TAG_RE.test(env.LATEST_RELEASE)
      || !["github-latest", "github-prerelease"].includes(env.LATEST_RELEASE_SOURCE ?? "")) {
      captureMessage("no published release was selected during deployment", "warning");
      return text("no published release was selected during deployment; use a pinned version", 502);
    }
    tag = env.LATEST_RELEASE;
    tagSource = env.LATEST_RELEASE_SOURCE!;
  }

  // Ignore user queries, but separate releases so an approved selection
  // update takes effect even when the previous installer is still cached.
  const cache = caches.default;
  const cacheUrl = new URL(url.pathname, url.origin);
  cacheUrl.searchParams.set("release", tag);
  cacheUrl.searchParams.set("source", tagSource);
  const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  const file = flavor === "sh" ? "erpc-installer.sh" : "erpc-installer.ps1";
  const got = await fetchInstaller(env, tag, file, flavor);
  if (!got) {
    captureMessage("could not fetch the installer from GitHub Releases", {
      level: "error",
      tags: { release: tag, flavor },
    });
    return text(
      `could not fetch the installer for ${tag} from GitHub Releases; there is no fallback source for an executable script`,
      502,
    );
  }

  const body = withAfterInstall(got.body, flavor);
  const res = new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "content-length": byteLength(body),
      "cache-control": `public, max-age=${CACHE_TTL}`,
      "x-erpc-tag": tag,
      "x-erpc-tag-source": tagSource,
      "x-erpc-source": got.source,
      "x-content-type-options": "nosniff",
    },
  });
  ctx.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}

function text(msg: string, status: number): Response {
  return new Response(msg, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "content-length": byteLength(msg),
      "cache-control": "no-store",
    },
  });
}

/**
 * A text response's length, set on every response this worker builds. The
 * Sentry SDK treats `text/plain` without a length as a stream, and passes
 * such a body through a stream of its own to see where it ends.
 */
function byteLength(body: string): string {
  return String(new TextEncoder().encode(body).byteLength);
}

/**
 * One install, as a data point. The order of `blobs` is the column order in
 * docs/install-counts.md (`blob1` = country, …), which readers of the dataset
 * rely on: append, never reorder. `doubles` is `[status]`. The index is the flavour, which is
 * what Analytics Engine samples by.
 */
export const INSTALL_BLOBS = [
  "country",
  "continent",
  "colo",
  "language",
  "os",
  "arch",
  "script",
  "requested",
  "version",
] as const;

export type InstallEvent = Record<(typeof INSTALL_BLOBS)[number], string> & { status: number };

const UNKNOWN = "unknown";

/**
 * The install event for a request. Every field is checked against a short
 * pattern and becomes `unknown` otherwise, so nothing a client sends can add a
 * free-form value (or a person's identity) to the dataset. The tag in a pinned
 * path is the client's text until a release by that name is served, so it is
 * recorded only then (status 200 and that tag in `x-erpc-tag`), and as
 * `unknown` otherwise.
 *
 * `os` is the installer's platform family, because that is all the request
 * says: `sh` serves Linux and macOS, `ps1` serves Windows. `arch` is never in
 * the request; the installer picks it on the machine. Both columns exist so a
 * later source that does know them fills the same table.
 */
export function installEvent(
  request: Request,
  pinned: string | null,
  flavor: "sh" | "ps1",
  res: Response,
): InstallEvent {
  const cf = (request as { cf?: { country?: unknown; continent?: unknown; colo?: unknown } }).cf;
  return {
    country: pick(cf?.country, /^[A-Z0-9]{2}$/),
    continent: pick(cf?.continent, /^[A-Z0-9]{2}$/),
    colo: pick(cf?.colo, /^[A-Z]{3}$/),
    language: primaryLanguage(request.headers.get("accept-language")),
    os: flavor === "sh" ? "unix" : "windows",
    arch: UNKNOWN,
    script: flavor,
    requested: pinned === null ? "latest" : servedTag(pinned, res),
    version: tagOrUnknown(res.headers.get("x-erpc-tag")),
    status: res.status,
  };
}

function pick(v: unknown, re: RegExp): string {
  return typeof v === "string" && re.test(v) ? v : UNKNOWN;
}

/** `pinned`, when the response served that release; `unknown` otherwise. */
function servedTag(pinned: string, res: Response): string {
  return res.status === 200 && res.headers.get("x-erpc-tag") === pinned ? tagOrUnknown(pinned) : UNKNOWN;
}

/** A release tag of at most 64 characters, as recorded; anything else is `unknown`. */
function tagOrUnknown(v: string | null): string {
  return v !== null && v.length <= 64 && TAG_RE.test(v) ? v : UNKNOWN;
}

/**
 * The primary subtag of the first range in `Accept-Language`, lower-cased:
 * `ja-JP,ja;q=0.9,en;q=0.8` is `ja`. The first range is the one the client
 * prefers. `curl` and PowerShell send no such header, so most installs are
 * `unknown` here; country is the better signal for them.
 */
export function primaryLanguage(header: string | null): string {
  const first = (header ?? "").split(",")[0].split(";")[0].trim();
  const primary = first.split("-")[0].toLowerCase();
  return /^[a-z]{2,3}$/.test(primary) ? primary : UNKNOWN;
}

/** Write the install event. Never throws, never waits: counting must not cost an install. */
function recordInstall(
  env: Env,
  request: Request,
  pinned: string | null,
  flavor: "sh" | "ps1",
  res: Response,
): void {
  try {
    if (!env.INSTALLS) return;
    const e = installEvent(request, pinned, flavor, res);
    env.INSTALLS.writeDataPoint({
      indexes: [e.script],
      blobs: INSTALL_BLOBS.map((k) => e[k]),
      doubles: [e.status],
    });
  } catch {
    // dropped: a lost count is better than a lost install
  }
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
