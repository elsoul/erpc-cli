// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the installer worker's body check.
 *
 * The fixtures are the real first lines of the artifacts
 * `dist build --artifacts=global` produces with the cargo-dist version pinned
 * in `dist-workspace.toml`, not the shapes the upstream template suggests. An
 * earlier version of this predicate was written from the template, required
 * `<#` at position 0, and would have returned 502 for every PowerShell
 * install; only a fixture taken from a generated artifact catches that.
 *
 *   npm test        (node --test, no dependencies)
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { looksLikeInstaller } from "./index.ts";

// Verbatim from target/distrib/erpc-installer.sh
const REAL_SH = `#!/bin/sh
# shellcheck shell=dash
# shellcheck disable=SC2039  # local is non-POSIX
# shellcheck disable=SC2268  # no harm in supporting older shells
#
# Licensed under the MIT license
`;

// The first lines of target/distrib/erpc-installer.ps1. The licence URL on
// the second line is replaced with a placeholder: the shape under test is the
// leading run of `#` comments before the `<#` block, and a literal URL here
// would have to be declared in the endpoint allowlist for no reason.
const REAL_PS1 = `# Licensed under the MIT license
# <LICENSE-MIT or LICENCE-URL-REDACTED-FOR-THE-ENDPOINT-GATE>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

<#
.SYNOPSIS
`;

test("accepts the shell installer cargo-dist really generates", () => {
  assert.equal(looksLikeInstaller(REAL_SH, "sh"), true);
});

test("accepts the PowerShell installer cargo-dist really generates", () => {
  assert.equal(looksLikeInstaller(REAL_PS1, "ps1"), true);
});

test("accepts a PowerShell installer that opens with its block comment", () => {
  assert.equal(looksLikeInstaller("<#\n.SYNOPSIS\n#>\n", "ps1"), true);
});

test("rejects an HTML error page for either flavour", () => {
  const html = "<!DOCTYPE html>\n<html><body>Not Found</body></html>";
  assert.equal(looksLikeInstaller(html, "sh"), false);
  assert.equal(looksLikeInstaller(html, "ps1"), false);
  assert.equal(looksLikeInstaller("<html>x</html>", "ps1"), false);
  assert.equal(looksLikeInstaller('<?xml version="1.0"?><Error/>', "sh"), false);
});

test("rejects an empty or whitespace body", () => {
  assert.equal(looksLikeInstaller("", "sh"), false);
  assert.equal(looksLikeInstaller("   \n\n", "ps1"), false);
});

test("rejects a plain-text error body", () => {
  assert.equal(looksLikeInstaller("Not Found", "sh"), false);
  assert.equal(looksLikeInstaller("Not Found", "ps1"), false);
});

test("does not accept a PowerShell installer as a shell one", () => {
  assert.equal(looksLikeInstaller(REAL_PS1, "sh"), false);
});

test("the installer is served with the skills step after it", async () => {
  const { AFTER_INSTALL, withAfterInstall } = await import("./index.ts");
  const sh = withAfterInstall(`${REAL_SH}download_binary_and_run_installer "$@" || exit 1\n`, "sh");
  assert.ok(sh.startsWith("#!/bin/sh"), "still a shell script");
  assert.ok(sh.endsWith(AFTER_INSTALL.sh));
  assert.ok(sh.indexOf("|| exit 1") < sh.indexOf("skills install"), "after the install");
  // The forced directory itself, as the generated installer's "flat" layout
  // installs there; a `bin/` under it was an earlier tail's mistake, and it
  // ran a binary from an earlier install.
  assert.ok(sh.includes('"${ERPC_INSTALL_DIR:-}"'), "the forced directory, not a bin/ under it");
  assert.ok(!sh.includes("ERPC_INSTALL_DIR/bin"), "no bin/ under the forced directory");
  assert.ok(sh.includes('"$_erpc_dir/erpc" "$_erpc_dir/bin/erpc"'), "itself first, bin/ for Cargo's home");
  const ps1 = withAfterInstall(REAL_PS1, "ps1");
  assert.equal(looksLikeInstaller(ps1, "ps1"), true);
  assert.ok(ps1.includes('Join-Path $HOME ".erpc\\bin"'));
  assert.ok(ps1.includes('Join-Path $erpcDir "erpc.exe"'), "the forced directory itself");
  assert.ok(!ps1.includes('Join-Path $env:ERPC_INSTALL_DIR "bin"'), "no bin under the forced directory");
});

// Exercise the request handler, GitHub selection and executable-script fetch.
import worker from "./index.ts";
import { resolveLatest } from "./releases.ts";
import type { TestContext } from "node:test";

const REPO = "elsoul/erpc-cli";
const API = `https://api.github.com/repos/${REPO}/releases`;
const INSTALL = "https://install.erpc.global";

function release(tag: string, prerelease = true, date = "2026-11-10T10:00:00Z") {
  return { tag_name: tag, prerelease, draft: false, published_at: date };
}

function harness(t: TestContext, responses: Map<string, Response | Error>, selection?: { tag?: string; source?: string }) {
  const requests: string[] = [];
  const entries = new Map<string, Response>();
  const writes: Promise<unknown>[] = [];
  const previous = Object.getOwnPropertyDescriptor(globalThis, "caches");
  Object.defineProperty(globalThis, "caches", { configurable: true, value: {
    default: {
      async match(key: Request) { return entries.get(key.url)?.clone(); },
      async put(key: Request, value: Response) { entries.set(key.url, value); },
    },
  } });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "caches", previous);
    else Reflect.deleteProperty(globalThis, "caches");
  });
  t.mock.method(globalThis, "fetch", async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    requests.push(url);
    const response = responses.get(url);
    assert.ok(response, `unexpected fetch ${url}`);
    if (response instanceof Error) throw response;
    return response.clone();
  });
  const ctx = { waitUntil(p: Promise<unknown>) { writes.push(p); }, passThroughOnException() {}, props: {} };
  let selected: { tag?: string; source?: string } | null | undefined = selection;
  return {
    requests, entries,
    select(value: { tag?: string; source?: string }) { selected = value; },
    async get(path = "/") {
      // Selection happens once in the deploy workflow, before serving requests.
      if (selected === undefined && ["/", "/ps1"].includes(path.split("?")[0])) {
        selected = await resolveLatest(REPO);
      }
      const result = await worker.fetch(new Request(INSTALL + path), {
        GITHUB_REPO: REPO, LATEST_RELEASE: selected?.tag, LATEST_RELEASE_SOURCE: selected?.source,
      }, ctx as ExecutionContext);
      await Promise.all(writes);
      return result;
    },
  };
}

function installer(tag: string, flavor = "sh"): [string, Response] {
  return [`https://github.com/${REPO}/releases/download/${tag}/erpc-installer.${flavor}`,
    new Response(flavor === "sh" ? REAL_SH : REAL_PS1)];
}

test("root selects a stable release and caches the GitHub installer", async t => {
  const h = harness(t, new Map([
    [API + "/latest", Response.json(release("v0.1.0", false))], installer("v0.1.0"),
  ]));
  const result = await h.get();
  assert.equal(result.status, 200);
  assert.equal(result.headers.get("x-erpc-tag"), "v0.1.0");
  assert.equal(result.headers.get("x-erpc-tag-source"), "github-latest");
  assert.ok((await result.text()).startsWith(REAL_SH));
  assert.equal(result.headers.get("cache-control"), "public, max-age=300");
  assert.equal((await h.get("/?ignored=yes")).status, 200);
  assert.equal(h.requests.length, 2);
});

test("root and PowerShell select the most recently published public prerelease", async t => {
  const h = harness(t, new Map([
    [API + "/latest", new Response("missing", { status: 404 })],
    [API + "?per_page=100&page=1", Response.json([
      { ...release("v8.0.0-rc.1"), published_at: null },
      release("v7.0.0-rc.1", true, "invalid date"),
      release("v0.1.0-rc.2", true, "2026-11-05T10:00:00Z"),
      release("v6.0.0", false, "2026-11-11T10:00:00Z"),
      { ...release("v9.0.0-rc.1"), draft: true }, release("bad/tag"),
      release("v0.1.0-rc.3"),
    ])], installer("v0.1.0-rc.3"), installer("v0.1.0-rc.3", "ps1"),
  ]));
  for (const path of ["/", "/ps1"]) {
    const response = await h.get(path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-erpc-tag"), "v0.1.0-rc.3");
    assert.equal(response.headers.get("x-erpc-tag-source"), "github-prerelease");
    assert.ok((await response.text()).includes("skills install"));
  }
});

test("prerelease selection reads every page and compares publication times", async t => {
  const h = harness(t, new Map([
    [API + "/latest", new Response("missing", { status: 404 })],
    [API + "?per_page=100&page=1", Response.json(Array(100).fill(release("v0.1.0-rc.1", true, "2026-11-01T00:00:00Z")))],
    [API + "?per_page=100&page=2", Response.json([release("v0.1.0-rc.3")])],
    installer("v0.1.0-rc.3"),
  ]));
  assert.equal((await h.get()).headers.get("x-erpc-tag"), "v0.1.0-rc.3");
});

test("versioned URLs fetch exactly that tag without release discovery", async t => {
  const h = harness(t, new Map([installer("v0.1.0-rc.2"), installer("v0.1.0-rc.2", "ps1")]));
  for (const path of ["/v0.1.0-rc.2", "/v0.1.0-rc.2/ps1"]) {
    const response = await h.get(path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-erpc-tag-source"), "pinned");
  }
  assert.equal(h.requests.length, 2);
});

test("GitHub failures and malformed stable metadata never fall back to prereleases", async t => {
  for (const response of [new Response("limited", { status: 403 }), new Response("down", { status: 500 }),
    new Error("network"), new Response("bad JSON"), Response.json({ tag_name: "v0.1.0" }),
    Response.json(release("v0.1.0-rc.3"))]) {
    await t.test(String(response), async child => {
      const h = harness(child, new Map([[API + "/latest", response]]));
      const result = await h.get();
      assert.equal(result.status, 502);
      assert.equal(result.headers.get("cache-control"), "no-store");
      assert.equal(h.requests.length, 1);
      assert.equal(h.entries.size, 0);
    });
  }
});

test("empty releases, broken pagination, and unavailable installers fail closed", async t => {
  for (const listing of [Response.json([]), Response.json({ bad: true }), new Response("down", { status: 503 }),
    Response.json([release("v0.1.0-rc.3")])]) {
    await t.test(String(listing), async child => {
      const h = harness(child, new Map([
        [API + "/latest", new Response("missing", { status: 404 })],
        [API + "?per_page=100&page=1", listing],
        [`https://github.com/${REPO}/releases/download/v0.1.0-rc.3/erpc-installer.sh`, new Response("missing", { status: 404 })],
      ]));
      assert.equal((await h.get()).status, 502);
      assert.equal(h.entries.size, 0);
    });
  }
});


test("a deployed selection serves installers without any GitHub API request", async t => {
  const h = harness(t, new Map([installer("v0.1.0-rc.3"), installer("v0.1.0-rc.3", "ps1")]),
    { tag: "v0.1.0-rc.3", source: "github-prerelease" });
  for (const path of ["/", "/ps1"]) {
    const r = await h.get(path);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get("x-erpc-tag"), "v0.1.0-rc.3");
  }
  assert.ok(h.requests.every(url => url.startsWith("https://github.com/elsoul/erpc-cli/releases/download/")));
  assert.equal(h.requests.length, 2);
});

import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

test("the deployment selector authenticates metadata reads and fails before publishing outputs on errors", t => {
  const dir = mkdtempSync(join(tmpdir(), "erpc-selector-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const preload = join(dir, "fetch.mjs");
  const script = fileURLToPath(new URL("../scripts/select-release.mjs", import.meta.url).href);
  for (const available of [true, false]) {
    const output = join(dir, String(available));
    writeFileSync(preload, `import assert from 'node:assert/strict';
      globalThis.fetch=async (url,init)=>{
        assert.equal(new URL(url).hostname,'api.github.com');
        assert.equal(init.redirect,'error');
        assert.equal(init.headers.authorization,'Bearer fixture-token');
        return ${available ? "Response.json({tag_name:'v0.1.0',prerelease:false,draft:false,published_at:'2026-11-10T00:00:00Z'})" : "new Response('limited',{status:403})"};
      };
    `);
    const result = spawnSync(process.execPath, ["--import", preload, script], {
      encoding: "utf8", env: { ...process.env, GH_TOKEN: "fixture-token", GITHUB_OUTPUT: output },
    });
    assert.equal(result.status, available ? 0 : 1, result.stderr);
    assert.ok(!result.stdout.includes("fixture-token") && !result.stderr.includes("fixture-token"));
    if (available) assert.equal(readFileSync(output, "utf8"), "tag=v0.1.0\nsource=github-latest\n");
    else assert.equal(existsSync(output), false);
  }
});


test("invalid deployed selections fail before any asset fetch", async t => {
  for (const selection of [ {}, { tag: "bad/tag", source: "github-latest" },
    { tag: "v1.2.3\n", source: "github-latest" }, { tag: "v1.2.3", source: "unknown" },
    { tag: "v1.2.3" }]) {
    await t.test(JSON.stringify(selection), async child => {
      const h = harness(child, new Map(), selection);
      assert.equal((await h.get()).status, 502);
      assert.deepEqual(h.requests, []);
      assert.equal(h.entries.size, 0);
    });
  }
});

test("a newly deployed release does not reuse the previous release cache", async t => {
  const h = harness(t, new Map([installer("v0.1.0-rc.2"), installer("v0.1.0-rc.3")]),
    { tag: "v0.1.0-rc.2", source: "github-prerelease" });
  assert.equal((await h.get()).headers.get("x-erpc-tag"), "v0.1.0-rc.2");
  h.select({ tag: "v0.1.0-rc.3", source: "github-prerelease" });
  assert.equal((await h.get()).headers.get("x-erpc-tag"), "v0.1.0-rc.3");
  h.select({});
  assert.equal((await h.get()).status, 502);
  assert.equal(h.requests.length, 2);
});

// --- install counts ---------------------------------------------------------

import { installEvent, primaryLanguage, INSTALL_BLOBS } from "./index.ts";

/** A request as Workers hands it over, with the `cf` object Node lacks. */
function cfRequest(path: string, init: RequestInit = {}, cf: Record<string, unknown> = {}): Request {
  const req = new Request(INSTALL + path, init);
  Object.defineProperty(req, "cf", { value: cf });
  return req;
}

const TOKYO = { country: "JP", continent: "AS", colo: "NRT", city: "Tokyo", latitude: "35.6" };

/**
 * The worker with GitHub, the cache and the context stubbed: `v1.2.3` is the
 * only release, selected at deployment (or nothing, with `selected: false`). The cache keeps what is
 * put, so a second request is a cache hit.
 */
function counting(t: TestContext, installs?: AnalyticsEngineDataset, selected = true) {
  const entries = new Map<string, Response>();
  const previous = Object.getOwnPropertyDescriptor(globalThis, "caches");
  Object.defineProperty(globalThis, "caches", { configurable: true, value: {
    default: {
      async match(key: Request) { return entries.get(key.url)?.clone(); },
      async put(key: Request, value: Response) { entries.set(key.url, value); },
    },
  } });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "caches", previous);
    else Reflect.deleteProperty(globalThis, "caches");
  });
  const fetched: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    fetched.push(url);
    // Only v1.2.3 is published.
    if (!url.includes("/releases/download/v1.2.3/")) return new Response("not found", { status: 404 });
    return new Response(url.endsWith(".ps1") ? REAL_PS1 : REAL_SH);
  });
  const writes: Promise<unknown>[] = [];
  const ctx = { waitUntil(p: Promise<unknown>) { writes.push(p); }, passThroughOnException() {}, props: {} };
  const env = { GITHUB_REPO: REPO, INSTALLS: installs,
    LATEST_RELEASE: selected ? "v1.2.3" : undefined, LATEST_RELEASE_SOURCE: selected ? "github-latest" : undefined };
  return {
    fetched,
    async get(req: Request) {
      const res = await worker.fetch(req, env, ctx as ExecutionContext);
      await Promise.all(writes);
      return res;
    },
  };
}

function collector() {
  const points: AnalyticsEngineDataPoint[] = [];
  return { points, ds: { writeDataPoint: (p?: AnalyticsEngineDataPoint) => void points.push(p ?? {}) } };
}

const blob = (p: AnalyticsEngineDataPoint, name: (typeof INSTALL_BLOBS)[number]) => p.blobs?.[INSTALL_BLOBS.indexOf(name)];

test("the install event carries region, language and versions, and nothing else", () => {
  const req = cfRequest(
    "/",
    { headers: { "accept-language": "ja-JP,ja;q=0.9,en;q=0.8", "user-agent": "curl/8.7.1", "x-real-ip": "203.0.113.9" } },
    TOKYO,
  );
  const res = new Response("#!/bin/sh\n", { headers: { "x-erpc-tag": "v1.2.3" } });
  const e = installEvent(req, null, "sh", res);
  assert.deepEqual(e, {
    country: "JP",
    continent: "AS",
    colo: "NRT",
    language: "ja",
    os: "unix",
    arch: "unknown",
    script: "sh",
    requested: "latest",
    version: "v1.2.3",
    status: 200,
  });
  assert.deepEqual(Object.keys(e).filter((k) => k !== "status"), [...INSTALL_BLOBS]);
  const all = JSON.stringify(e);
  for (const leak of ["curl", "203.0.113.9", "Tokyo", "35.6"]) assert.ok(!all.includes(leak), `no ${leak}`);
});

test("a pinned PowerShell install is recorded as such", () => {
  const res = new Response("#\n", { headers: { "x-erpc-tag": "v0.9.0-rc.1" } });
  const req = cfRequest("/v0.9.0-rc.1/ps1", {}, { country: "DE", continent: "EU", colo: "FRA" });
  const e = installEvent(req, "v0.9.0-rc.1", "ps1", res);
  assert.equal(e.os, "windows");
  assert.equal(e.script, "ps1");
  assert.equal(e.requested, "v0.9.0-rc.1");
  assert.equal(e.version, "v0.9.0-rc.1");
});

test("values outside the expected shapes become unknown", () => {
  const req = cfRequest("/", { headers: { "accept-language": "<script>" } }, { country: "jp; drop", continent: 7, colo: "nrt-1" });
  const e = installEvent(req, `v1.0.0-${"a".repeat(80)}`, "sh", new Response("", { status: 502 }));
  assert.equal(e.country, "unknown");
  assert.equal(e.continent, "unknown");
  assert.equal(e.colo, "unknown");
  assert.equal(e.language, "unknown");
  assert.equal(e.requested, "unknown");
  assert.equal(e.version, "unknown");
  assert.equal(e.status, 502);
  // no cf object at all (wrangler dev, tests)
  assert.equal(installEvent(new Request(INSTALL + "/"), null, "sh", new Response("")).country, "unknown");
});

test("the primary language is the first range's primary subtag", () => {
  assert.equal(primaryLanguage("zh-Hant-TW,zh;q=0.8"), "zh");
  assert.equal(primaryLanguage(" RU-ru ; q=1"), "ru");
  assert.equal(primaryLanguage("fil"), "fil");
  assert.equal(primaryLanguage("*"), "unknown");
  assert.equal(primaryLanguage(""), "unknown");
  assert.equal(primaryLanguage(null), "unknown");
  assert.equal(primaryLanguage("x-klingon"), "unknown");
});

test("a served installer writes one data point in the export's column order", async t => {
  // The export reads blobN by position (docs/install-counts.md): append only.
  assert.deepEqual(
    [...INSTALL_BLOBS],
    ["country", "continent", "colo", "language", "os", "arch", "script", "requested", "version"],
  );
  const { points, ds } = collector();
  const w = counting(t, ds);
  const res = await w.get(cfRequest("/", { headers: { "accept-language": "ru" } }, TOKYO));
  assert.equal(res.status, 200);
  assert.equal(points.length, 1);
  const p = points[0];
  assert.deepEqual(p.indexes, ["sh"]);
  assert.deepEqual(p.doubles, [200]);
  assert.equal(p.blobs?.length, INSTALL_BLOBS.length);
  assert.equal(blob(p, "country"), "JP");
  assert.equal(blob(p, "language"), "ru");
  assert.equal(blob(p, "requested"), "latest");
  assert.equal(blob(p, "version"), "v1.2.3");
});

test("cache hits, PowerShell and failed serves are counted too", async t => {
  const { points, ds } = collector();
  const w = counting(t, ds);
  assert.equal((await w.get(cfRequest("/", {}, TOKYO))).status, 200);
  assert.equal((await w.get(cfRequest("/?again=1", {}, TOKYO))).status, 200);
  assert.equal((await w.get(cfRequest("/ps1", {}, TOKYO))).status, 200);
  assert.equal((await w.get(cfRequest("/v9.9.9", {}, TOKYO))).status, 502);
  // The second root request was served from the cache and still counted.
  assert.equal(w.fetched.filter((u) => u.endsWith("/v1.2.3/erpc-installer.sh")).length, 1);
  assert.deepEqual(points.map((p) => [blob(p, "script"), blob(p, "requested"), blob(p, "version"), p.doubles?.[0]]), [
    ["sh", "latest", "v1.2.3", 200],
    ["sh", "latest", "v1.2.3", 200],
    ["ps1", "latest", "v1.2.3", 200],
    ["sh", "unknown", "unknown", 502],
  ]);
  assert.deepEqual(points[2].indexes, ["ps1"]);
});

test("with no release selected the 502 is counted", async t => {
  const { points, ds } = collector();
  const w = counting(t, ds, false);
  assert.equal((await w.get(cfRequest("/", {}, TOKYO))).status, 502);
  assert.deepEqual(points.map((p) => [blob(p, "version"), p.doubles?.[0]]), [["unknown", 502]]);
  assert.deepEqual(w.fetched, []);
});

test("a failing Analytics Engine write still serves the install script", async t => {
  const throwing = {
    writeDataPoint() {
      throw new Error("analytics engine is down");
    },
  };
  const res = await counting(t, throwing).get(cfRequest("/", {}, TOKYO));
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.startsWith("#!/bin/sh"));
  assert.ok(body.includes("skills install"));
  assert.equal(res.headers.get("x-erpc-tag"), "v1.2.3");
});

test("no binding, HEAD, POST, health checks and unknown paths record nothing", async t => {
  await t.test("no binding", async c => {
    assert.equal((await counting(c).get(cfRequest("/", {}, TOKYO))).status, 200);
  });
  await t.test("not an installer GET", async c => {
    const { points, ds } = collector();
    const w = counting(c, ds);
    assert.equal((await w.get(cfRequest("/", { method: "HEAD" }, TOKYO))).status, 200);
    assert.equal((await w.get(cfRequest("/", { method: "POST" }, TOKYO))).status, 405);
    assert.equal((await w.get(cfRequest("/healthz", {}, TOKYO))).status, 200);
    assert.equal((await w.get(cfRequest("/wp-login.php", {}, TOKYO))).status, 404);
    assert.equal(points.length, 0);
  });
});

test("a pinned tag is recorded only once that release was served", async t => {
  const { points, ds } = collector();
  const w = counting(t, ds);
  // In range for the tag pattern and the length cap, but no such release.
  const chosen = "v0.0.0-alice.example.com-0123456789";
  assert.equal((await w.get(cfRequest(`/${chosen}`, {}, TOKYO))).status, 502);
  assert.equal((await w.get(cfRequest("/v1.2.3/ps1", {}, TOKYO))).status, 200);
  assert.deepEqual(points.map((p) => [blob(p, "requested"), blob(p, "version"), p.doubles?.[0]]), [
    ["unknown", "unknown", 502],
    ["v1.2.3", "v1.2.3", 200],
  ]);
  assert.ok(!JSON.stringify(points).includes("alice"));
  // A response for another tag does not vouch for the one in the path.
  const other = new Response("#!/bin/sh\n", { headers: { "x-erpc-tag": "v1.2.3" } });
  assert.equal(installEvent(cfRequest("/v1.2.4"), "v1.2.4", "sh", other).requested, "unknown");
});
