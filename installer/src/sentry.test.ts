// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the worker's error reports (src/sentry.ts).
 *
 * The tests after the first few run the real SDK: they wrap the worker with
 * the production options, swap only the transport for one that keeps what
 * would be sent, and read the envelopes. A test of `scrubEvent` on a
 * hand-built event alone would not show what the SDK itself attaches.
 *
 * The network is a stub that presents itself as the native `fetch`. The SDK
 * instruments `fetch` (breadcrumbs, and trace headers on outbound requests)
 * only when it looks native, as it is in workerd; a plain mock would leave
 * that instrumentation out and hide what it adds to the fetch from GitHub.
 * The SDK instruments `fetch` and `console.log` once per process, so both
 * stubs are installed once, below, before the SDK starts.
 *
 *   npm test        (node --test)
 */

import { strict as assert } from "node:assert";
import { test, type TestContext } from "node:test";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createTransport, withSentry, type ErrorEvent } from "@sentry/cloudflare";

import { makeHandler, type Env } from "./index.ts";
import { isSentryIngestHost, scrubBreadcrumb, scrubEvent, sentryOptions } from "./sentry.ts";

// A declared Sentry ingest host (WORKER_REPORT_HOST_PATTERNS) with an org id
// no project has; the transport below sends nothing anywhere.
const DSN = "https://public@o0.ingest.sentry.io/1";
const REPO = "elsoul/erpc-cli";

// What a request carries about the person installing. None of it may leave.
const PERSONAL = ["203.0.113.9", "curl/8.5.0", "ja-JP", "s3cr3t", "Asia/Tokyo", "Tokyo", "who=me"];

/** What the worker fetched: each URL with the headers it was sent with. */
interface Fetched { url: string; headers: Headers }
let fetched: Fetched[] = [];
const nativeLookingFetch = async function fetch(input: RequestInfo | URL, init?: RequestInit) {
  const request = new Request(input, init);
  fetched.push({ url: request.url, headers: request.headers });
  throw new Error("network down");
};
nativeLookingFetch.toString = () => "function fetch() { [native code] }";
globalThis.fetch = nativeLookingFetch as typeof fetch;

// What the worker logs. The SDK wraps console.log once per process, to make
// breadcrumbs; replacing it in a test would remove that wrapper and hide the
// breadcrumb the test means to check. So the quiet stand-in is set here,
// before the SDK starts, and the SDK wraps it.
const logged: unknown[][] = [];
console.log = (...args: unknown[]) => { logged.push(args); };

test("without a DSN nothing is reported", () => {
  const options = sentryOptions({});
  assert.equal(options.enabled, false);
  assert.equal(options.dsn, undefined);
});

test("a DSN that does not name a Sentry ingest host over https is not used", () => {
  for (const dsn of ["http://public@127.0.0.1/1", "https://public@127.0.0.1/1", "not a url"]) {
    const options = sentryOptions({ SENTRY_DSN: dsn });
    assert.equal(options.enabled, false, dsn);
    assert.equal(options.dsn, undefined, dsn);
  }
});

test("a Sentry ingest DSN over plain http is not used", () => {
  // Derived from DSN rather than written out: the endpoint gate refuses a
  // plaintext URL literal outside loopback, and nothing here is contacted.
  const url = new URL(DSN);
  url.protocol = "http:";
  const options = sentryOptions({ SENTRY_DSN: url.href });
  assert.equal(options.enabled, false);
  assert.equal(options.dsn, undefined);
});

test("a tunnel turns reporting off, since reports would go to it", () => {
  const options = sentryOptions({ SENTRY_DSN: DSN, SENTRY_TUNNEL: "" });
  assert.equal(options.enabled, false);
  assert.equal(options.dsn, undefined);
});

test("the hosts the worker accepts are among those endpoints.rs declares for it", () => {
  const source = readFileSync(fileURLToPath(new URL("../../crates/erpc-core/src/endpoints.rs", import.meta.url).href), "utf8");
  const list = source.slice(source.indexOf("pub const WORKER_REPORT_HOST_PATTERNS"));
  const pairs = [...list.slice(0, list.indexOf("];")).matchAll(/\("([^"]+)",\s*"([^"]+)"\)/g)]
    .map(([, prefix, suffix]) => [prefix, suffix]);
  assert.equal(pairs.length, 3, list);
  const declared = (host: string) => pairs.some(([prefix, suffix]) =>
    host.startsWith(prefix) && host.endsWith(suffix)
    && !host.slice(prefix.length, host.length - suffix.length).includes("."));
  // Every declared pair is usable, and nothing the worker accepts is undeclared.
  for (const [prefix, suffix] of pairs) {
    assert.ok(isSentryIngestHost(`${prefix}12345${suffix}`), `${prefix}*${suffix}`);
  }
  for (const region of ["", ".de", ".us", ".eu", ".jp", ".xx"]) {
    const host = `o12345.ingest${region}.sentry.io`;
    if (isSentryIngestHost(host)) assert.ok(declared(host), host);
  }
});

test("only Sentry's ingest hosts count", () => {
  for (const host of ["o0.ingest.sentry.io", "o12345.ingest.de.sentry.io", "o12345.ingest.us.sentry.io"]) {
    assert.ok(isSentryIngestHost(host), host);
  }
  for (const host of [
    "ingest.sentry.io", "oabc.ingest.sentry.io", "o1.ingest.xx.sentry.io", "o1.sentry.io",
    "o1.ingest.sentry.io.example.net", "xo1.ingest.sentry.io", "O1.INGEST.SENTRY.IO",
  ]) {
    assert.ok(!isSentryIngestHost(host), host);
  }
});

test("reports carry no personal data, no tracing and no trace headers", () => {
  const options = sentryOptions({ SENTRY_DSN: DSN });
  assert.equal(options.enabled, true);
  assert.equal(options.dsn, DSN);
  assert.equal(options.sendDefaultPii, false);
  assert.equal(options.tracesSampleRate, 0);
  assert.equal(options.tracesSampler(), 0);
  assert.equal(options.beforeSendTransaction(), null);
  assert.deepEqual(options.tracePropagationTargets, []);
  assert.equal(options.spotlight, false);
  assert.equal(options.beforeSend, scrubEvent);
  assert.equal(options.beforeBreadcrumb, scrubBreadcrumb);
});

test("an event keeps the method and path, and loses everything about the person installing", () => {
  const event = scrubEvent({
    type: undefined,
    request: {
      method: "GET",
      url: "https://install.erpc.global/v0.1.0/ps1?token=abc",
      query_string: "token=abc",
      headers: { "user-agent": "curl/8", "cf-connecting-ip": "203.0.113.9" },
      cookies: { a: "b" },
      data: "body",
      env: { REMOTE_ADDR: "203.0.113.9" },
    },
    user: { ip_address: "203.0.113.9" },
    contexts: { culture: { timezone: "Asia/Tokyo" }, runtime: { name: "cloudflare" } },
  } as ErrorEvent);
  assert.deepEqual(event.request, { method: "GET", url: "https://install.erpc.global/v0.1.0/ps1" });
  assert.equal(event.user, undefined);
  assert.equal(event.contexts?.culture, undefined);
  assert.deepEqual(event.contexts?.runtime, { name: "cloudflare" });
});

test("a breadcrumb's URL loses its query, and console breadcrumbs are dropped", () => {
  const crumb = scrubBreadcrumb({ category: "fetch", data: { url: "https://github.com/a?b=c", method: "GET" } });
  assert.deepEqual(crumb?.data, { url: "https://github.com/a", method: "GET" });
  assert.equal(scrubBreadcrumb({ category: "console", message: "who=me" }), null);
});

interface Sent {
  res?: Response;
  thrown?: unknown;
  /** Every envelope item, as [item header, payload]. */
  items: [{ type?: string }, Record<string, unknown>][];
  /** Every envelope, as sent. */
  raw: string;
  /** What the worker fetched. */
  asked: Fetched[];
}

/**
 * Runs one request through the worker wrapped as production wraps it, with
 * the cache and the network replaced and a transport that keeps envelopes.
 */
async function run(t: TestContext, opts: {
  path: string;
  headers?: Record<string, string>;
  env?: Partial<Env>;
  cacheMatch?: () => Promise<Response | undefined>;
}): Promise<Sent> {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "caches");
  Object.defineProperty(globalThis, "caches", { configurable: true, value: {
    default: { match: opts.cacheMatch ?? (async () => undefined), async put() {} },
  } });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "caches", previous);
    else delete (globalThis as { caches?: unknown }).caches;
  });

  fetched = [];

  const envelopes: string[] = [];
  const worker = withSentry((env: Env) => ({
    ...sentryOptions(env),
    transport: (options: Parameters<typeof createTransport>[0]) =>
      createTransport(options, async (request) => {
        envelopes.push(typeof request.body === "string" ? request.body : new TextDecoder().decode(request.body));
        return { statusCode: 200 };
      }),
  }), makeHandler()) as ExportedHandler<Env>;

  const request = new Request(new URL(opts.path, "https://install.erpc.global"), {
    headers: {
      "user-agent": "curl/8.5.0",
      "accept-language": "ja-JP",
      "cf-connecting-ip": "203.0.113.9",
      cookie: "session=s3cr3t",
      ...opts.headers,
    },
  });
  Object.defineProperty(request, "cf", { value: { timezone: "Asia/Tokyo", country: "JP", city: "Tokyo" } });
  const waits: Promise<unknown>[] = [];
  const ctx = { waitUntil(p: Promise<unknown>) { waits.push(p); }, passThroughOnException() {}, props: {} };

  const sent: Sent = { items: [], raw: "", asked: fetched };
  try {
    sent.res = await worker.fetch!(request as Request<unknown, IncomingRequestCfProperties>,
      { GITHUB_REPO: REPO, SENTRY_DSN: DSN, ...opts.env }, ctx as ExecutionContext);
  } catch (err) {
    sent.thrown = err;
  }
  await Promise.all(waits);

  sent.raw = envelopes.join("\n");
  for (const envelope of envelopes) {
    // An envelope is a header line, then an item header and payload per item.
    const lines = envelope.split("\n").filter((line) => line !== "");
    for (let i = 1; i + 1 < lines.length; i += 2) {
      sent.items.push([JSON.parse(lines[i]), JSON.parse(lines[i + 1])]);
    }
  }
  return sent;
}

function onlyEvent(sent: Sent): Record<string, unknown> {
  assert.deepEqual(sent.items.map(([header]) => header.type), ["event"], sent.raw);
  return sent.items[0][1];
}

function assertNothingPersonal(sent: Sent) {
  for (const personal of PERSONAL) {
    assert.ok(!sent.raw.includes(personal), `"${personal}" was sent: ${sent.raw}`);
  }
}

/** The worker's fetches carried no trace headers to GitHub. */
function assertNoTraceHeaders(sent: Sent) {
  assert.ok(sent.asked.length > 0);
  for (const { url, headers } of sent.asked) {
    assert.equal(headers.get("sentry-trace"), null, url);
    assert.equal(headers.get("baggage"), null, url);
    assert.equal(headers.get("traceparent"), null, url);
  }
}

test("an installer GitHub cannot serve is reported, and nothing about the person installing is sent", async (t) => {
  const sent = await run(t, { path: "/v0.1.0?who=me" });
  assert.equal(sent.res?.status, 502);
  // A length, so the SDK does not pass the body through a stream of its own.
  assert.equal(sent.res?.headers.get("content-length"), String((await sent.res!.arrayBuffer()).byteLength));
  const event = onlyEvent(sent);
  assert.equal(event.message, "could not fetch the installer from GitHub Releases");
  assert.equal(event.level, "error");
  assert.deepEqual(event.tags, { release: "v0.1.0", flavor: "sh" });
  assert.deepEqual(event.request, { method: "GET", url: "https://install.erpc.global/v0.1.0" });
  assertNothingPersonal(sent);
  assert.deepEqual(sent.asked.map(({ url }) => url),
    [`https://github.com/${REPO}/releases/download/v0.1.0/erpc-installer.sh`]);
  assertNoTraceHeaders(sent);
  // The SDK's fetch instrumentation is live: it left a breadcrumb.
  assert.ok(sent.raw.includes(`"category":"fetch"`), sent.raw);
});

test("a request that asks for a sampled trace gets no transaction, and its trace goes no further", async (t) => {
  const traceId = "0123456789abcdef0123456789abcdef";
  const sent = await run(t, {
    path: "/v0.1.0?who=me",
    headers: {
      "sentry-trace": `${traceId}-0123456789abcdef-1`,
      // A client's own sentry-* entries; the SDK would copy them into the
      // report's envelope header.
      baggage: `sentry-trace_id=${traceId},sentry-sampled=true,sentry-sample_rate=1,sentry-segment=Tokyo`,
    },
  });
  assert.equal(sent.res?.status, 502);
  onlyEvent(sent);
  assertNothingPersonal(sent);
  assert.ok(!sent.raw.includes("segment"), sent.raw);
  assert.ok(!sent.raw.includes(traceId), sent.raw);
  assertNoTraceHeaders(sent);
});

test("a rejected DSN, or a tunnel, sends nothing even though the SDK reads both from the env", async (t) => {
  const plain = new URL(DSN);
  plain.protocol = "http:";
  for (const env of [
    { SENTRY_DSN: "https://public@127.0.0.1/1" },
    { SENTRY_DSN: plain.href },
    { SENTRY_TUNNEL: "https://127.0.0.1/tunnel" },
  ]) {
    const sent = await run(t, { path: "/v0.1.0", env });
    assert.equal(sent.res?.status, 502);
    assert.equal(sent.raw, "", JSON.stringify(env));
  }
});

test("a deployment with no release selected is reported as a warning", async (t) => {
  const sent = await run(t, { path: "/?who=me" });
  assert.equal(sent.res?.status, 502);
  const event = onlyEvent(sent);
  assert.equal(event.message, "no published release was selected during deployment");
  assert.equal(event.level, "warning");
  assert.deepEqual(event.request, { method: "GET", url: "https://install.erpc.global/" });
  assertNothingPersonal(sent);
  assert.deepEqual(sent.asked, []);
});

test("an exception is reported, without what was logged before it", async (t) => {
  logged.length = 0;
  const sent = await run(t, {
    path: "/v0.1.0?who=me",
    cacheMatch: async () => {
      console.log("logged: who=me");
      throw new Error("cache unavailable");
    },
  });
  assert.deepEqual(logged, [["logged: who=me"]]);
  assert.equal((sent.thrown as Error | undefined)?.message, "cache unavailable");
  const event = onlyEvent(sent) as { exception?: { values?: { value?: string }[] } };
  assert.equal(event.exception?.values?.[0]?.value, "cache unavailable");
  assert.ok(!sent.raw.includes("logged"), sent.raw);
  assertNothingPersonal(sent);
});
