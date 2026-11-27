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
// The SDK's own DSN parser, from the package @sentry/cloudflare is built on
// (locked at the same version), to check every DSN the worker passes on.
import { makeDsn } from "@sentry/core";

import { makeHandler, type Env } from "./index.ts";
import { dsnRefusal, isSentryIngestHost, onceWarner, scrubBreadcrumb, scrubEvent, sentryOptions } from "./sentry.ts";

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

// The worker's own warning about a refused DSN, and anything the SDK prints
// as an error (it prints "Invalid Sentry Dsn: <the whole DSN>"), are kept
// here the same way, so tests can check what reached the logs.
const warned: string[] = [];
console.warn = (...args: unknown[]) => { warned.push(args.join(" ")); };
const errored: string[] = [];
console.error = (...args: unknown[]) => { errored.push(args.join(" ")); };

type SentryEnvForTest = Parameters<typeof sentryOptions>[0];

test("without a DSN nothing is reported", () => {
  const options = sentryOptions({});
  assert.equal(options.enabled, false);
  assert.equal(options.dsn, "");
});

test("a DSN that does not name a Sentry ingest host over https is not used", () => {
  for (const dsn of ["http://public@127.0.0.1/1", "https://public@127.0.0.1/1", "not a url"]) {
    const options = sentryOptions({ SENTRY_DSN: dsn }, () => {});
    assert.equal(options.enabled, false, dsn);
    assert.equal(options.dsn, "", dsn);
  }
});

test("a Sentry ingest DSN over plain http is not used", () => {
  // Derived from DSN rather than written out: the endpoint gate refuses a
  // plaintext URL literal outside loopback, and nothing here is contacted.
  const url = new URL(DSN);
  url.protocol = "http:";
  const options = sentryOptions({ SENTRY_DSN: url.href }, () => {});
  assert.equal(options.enabled, false);
  assert.equal(options.dsn, "");
});

test("a SENTRY_DSN that is not a string is treated as not set", () => {
  for (const value of [42, true, { dsn: DSN }]) {
    const reasons: string[] = [];
    const options = sentryOptions({ SENTRY_DSN: value as unknown as string }, (reason) => reasons.push(reason));
    assert.equal(options.enabled, false, JSON.stringify(value));
    assert.equal(options.dsn, "", JSON.stringify(value));
    assert.deepEqual(reasons, [], JSON.stringify(value));
  }
});

test("a tunnel turns reporting off, since reports would go to it", () => {
  const options = sentryOptions({ SENTRY_DSN: DSN, SENTRY_TUNNEL: "" }, () => {});
  assert.equal(options.enabled, false);
  assert.equal(options.dsn, "");
});

test("a refused DSN logs why, once, and never any part of the DSN", () => {
  const plain = new URL(DSN);
  plain.protocol = "http:";
  const refused: [SentryEnvForTest, string][] = [
    [{ SENTRY_DSN: "public@o9.example" }, "not a URL"],
    [{ SENTRY_DSN: "https://public@127.0.0.1/1" }, "not a Sentry ingest host"],
    [{ SENTRY_DSN: plain.href }, "not an https URL"],
    [{ SENTRY_DSN: DSN, SENTRY_TUNNEL: "" }, "SENTRY_TUNNEL is set"],
  ];
  for (const [env, why] of refused) {
    const reasons: string[] = [];
    sentryOptions(env, (reason) => reasons.push(reason));
    assert.equal(reasons.length, 1, JSON.stringify(env));
    assert.ok(reasons[0].includes(why), reasons[0]);
    assert.equal(dsnRefusal(env), reasons[0]);
    for (const part of [env.SENTRY_DSN!, "public", "127.0.0.1", "o0.ingest", "o9.example"]) {
      assert.ok(!reasons[0].includes(part), `"${part}" is in the reason: ${reasons[0]}`);
    }
  }
  for (const env of [{}, { SENTRY_DSN: DSN }, { SENTRY_DSN: "" }, { SENTRY_TUNNEL: "" }] as SentryEnvForTest[]) {
    const reasons: string[] = [];
    sentryOptions(env, (reason) => reasons.push(reason));
    assert.deepEqual(reasons, [], JSON.stringify(env));
    assert.equal(dsnRefusal(env), undefined, JSON.stringify(env));
  }
});

test("the refusal is logged once per Worker instance", () => {
  const lines: string[] = [];
  const warn = onceWarner((line) => lines.push(line));
  warn("first reason");
  warn("second reason");
  assert.equal(lines.length, 1, lines.join("\n"));
  assert.ok(lines[0].includes("SENTRY_DSN is set but not used") && lines[0].includes("first reason"), lines[0]);
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
  assert.equal(options.debug, false);
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

test("a rejected DSN, or a tunnel, sends nothing even though the SDK reads both from the env, and the worker says why once", async (t) => {
  const plain = new URL(DSN);
  plain.protocol = "http:";
  const warnedBefore = warned.length;
  // run() adds SENTRY_DSN: DSN unless the case sets its own, so the tunnel
  // case is a valid DSN together with a tunnel.
  for (const env of [
    { SENTRY_DSN: "https://public@127.0.0.1/1" },
    { SENTRY_DSN: plain.href },
    { SENTRY_DSN: DSN, SENTRY_TUNNEL: "https://127.0.0.1/tunnel" },
  ]) {
    const sent = await run(t, { path: "/v0.1.0", env });
    assert.equal(sent.res?.status, 502);
    assert.equal(sent.raw, "", JSON.stringify(env));
  }
  // Through the worker as production wraps it, with the default warner:
  // three requests with refused DSNs, one warning, and none of the DSN in it.
  const lines = warned.slice(warnedBefore).filter((line) => line.includes("SENTRY_DSN is set but not used"));
  assert.equal(lines.length, 1, warned.slice(warnedBefore).join("\n"));
  for (const part of ["public", "127.0.0.1", "o0.ingest", plain.href, DSN]) {
    assert.ok(!lines[0].includes(part), `"${part}" is in the warning: ${lines[0]}`);
  }
});

// Spellings the worker's URL parser accepts and normalises but the SDK's
// parser rejects: it prints the first four in full, key included, and drops
// HTTPS:// silently (its protocol check is case-sensitive). The worker hands
// the SDK a DSN rebuilt from the parsed parts, never this text, so each of
// these reports normally. Built from DSN at run time because the endpoint gate refuses
// a backslash or a non-ASCII host in a URL literal, as it should.
const NORMALISED = [
  DSN.replace("sentry.io/", "sentry.io:/"),
  DSN.replace("@o0.", "@\uff4f0."),
  DSN.replace("https://", "https:"),
  DSN.replace("//", "\\\\").replace("sentry.io/", "sentry.io\\"),
  DSN.replace("https://", "HTTPS://"),
];

test("through the real worker, a spelling the SDK cannot parse but the worker accepts is rebuilt, so the SDK never prints it", async (t) => {
  const errorsBefore = errored.length;
  for (const value of NORMALISED) {
    const sent = await run(t, { path: "/v0.1.0", env: { SENTRY_DSN: value } });
    assert.equal(sent.res?.status, 502);
    assert.ok(sent.raw.includes("could not fetch the installer"), JSON.stringify(value));
  }
  assert.deepEqual(errored.slice(errorsBefore).filter((line) => line.includes("Invalid Sentry Dsn")), []);
});

test("through the real worker, a DSN the SDK cannot parse is never handed to it, so it never prints one", async (t) => {
  // The SDK falls back to SENTRY_DSN from the env when the options give no
  // DSN, and prints "Invalid Sentry Dsn: " and the value when it cannot
  // parse it, even with reporting off. These values all fail its parser.
  const key = new URL(DSN).username;
  const errorsBefore = errored.length;
  for (const value of [
    DSN.replace(`//${key}@`, "//pub-lic@"),
    DSN.replace(`${key}@`, ""),
    DSN.replace("/1", "/x/1/y"),
    "   ",
  ]) {
    const sent = await run(t, { path: "/v0.1.0", env: { SENTRY_DSN: value } });
    assert.equal(sent.res?.status, 502);
    assert.equal(sent.raw, "", JSON.stringify(value));
  }
  assert.deepEqual(errored.slice(errorsBefore).filter((line) => line.includes("Invalid Sentry Dsn")), []);
});

test("every DSN the worker uses is one the SDK accepts, and the SDK never prints a DSN", () => {
  const key = new URL(DSN).username;
  const at = (rest: string) => DSN.replace(/@.*$/, "@" + rest);
  const used = [
    DSN,
    DSN + "\n",
    " " + DSN,
    "\t" + DSN + " ",
    at("o0.ingest.sentry.io:443/1"),
    at("O0.INGEST.SENTRY.IO/1"),
    DSN.replace(`//${key}@`, `//${key}:second_part@`),
    // The URL parser resolves the dots; the SDK is given the parsed URL.
    at("o0.ingest.sentry.io/1/../1"),
    ...NORMALISED,
  ];
  const refused: [string, string][] = [
    ["   ", "blank"],
    [DSN.replace(`${key}@`, ""), "its key"],
    [DSN.replace(`//${key}@`, "//@"), "its key"],
    [DSN.replace(`//${key}@`, "//pub-lic@"), "its key"],
    [DSN.replace(`//${key}@`, `//${key}:se-cret@`), "its key"],
    [at("o0.ingest.sentry.io/1/"), "project number"],
    [at("o0.ingest.sentry.io/abc"), "project number"],
    [at("o0.ingest.sentry.io/"), "project number"],
    [at("o0.ingest.sentry.io/1?x=y"), "project number"],
    [at("o0.ingest.sentry.io/1#f"), "project number"],
    [at("o0.ingest.sentry.io/1?"), "project number"],
    [at("o0.ingest.sentry.io/1#"), "project number"],
    [at("o0.ingest.sentry.io:8443/1"), "port"],
    [DSN.replace("/1", "/\n1"), "inside it"],
    [DSN.replace("@", " @"), "inside it"],
  ];
  const errorsBefore = errored.length;
  for (const value of used) {
    const reasons: string[] = [];
    const options = sentryOptions({ SENTRY_DSN: value }, (reason) => reasons.push(reason));
    assert.deepEqual(reasons, [], JSON.stringify(value));
    assert.equal(options.enabled, true, JSON.stringify(value));
    const parsed = makeDsn(options.dsn!);
    assert.ok(parsed && /^\d+$/.test(parsed.projectId) && parsed.publicKey === key, JSON.stringify(value));
    assert.equal(parsed.host, "o0.ingest.sentry.io", JSON.stringify(value));
    assert.equal(parsed.pass, value.includes(":second_part@") ? "second_part" : "", JSON.stringify(value));
  }
  for (const [value, why] of refused) {
    const reasons: string[] = [];
    const options = sentryOptions({ SENTRY_DSN: value }, (reason) => reasons.push(reason));
    assert.equal(options.enabled, false, JSON.stringify(value));
    assert.equal(options.dsn, "", JSON.stringify(value));
    assert.equal(reasons.length, 1, JSON.stringify(value));
    assert.ok(reasons[0].includes(why), `${JSON.stringify(value)}: ${reasons[0]}`);
    for (const part of [key, "pub-lic", "se-cret", "second_part", "o0.ingest"]) {
      assert.ok(!reasons[0].includes(part), `"${part}" is in the reason: ${reasons[0]}`);
    }
  }
  assert.deepEqual(errored.slice(errorsBefore).filter((line) => line.includes("Invalid Sentry Dsn")), []);
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
