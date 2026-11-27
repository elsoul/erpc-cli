// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * Error reports from this worker to Sentry, and what they may hold.
 *
 * Reporting is on only when the `SENTRY_DSN` Worker secret names a Sentry
 * ingest host over https and no `SENTRY_TUNNEL` variable is set; otherwise
 * (tests, `wrangler dev`, a deployment nobody configured) the SDK sends
 * nothing. A DSN the SDK's own parser would reject is refused, or, where the
 * URL parser normalises it, rebuilt; the SDK never sees the raw text, which
 * it would otherwise print in full. Spaces and line breaks around the value
 * are trimmed. When the DSN is set but refused, the worker logs why once per
 * Worker instance, without the DSN's value. The DSN is never in this
 * repository.
 *
 * Only error events are sent. Tracing is off however a request asks: the
 * SDK would otherwise continue a trace a client starts with a sampled
 * `sentry-trace` header, and send a transaction carrying that client's
 * request. `tracesSampler` refuses every trace, and any transaction that got
 * through would still be dropped by `beforeSendTransaction`.
 *
 * An error event says what failed in this worker: the error, the
 * installer's tag and flavour, the request's method and URL without its
 * query. The SDK would also attach the request's headers (user agent,
 * `Accept-Language`, Cloudflare's client IP and location headers), its query
 * string, a user, and a `culture` context holding the client's timezone;
 * `scrubEvent` removes all of them, the `sentry-*` baggage a request may
 * carry and the trace id it may name, and `sendDefaultPii` stays off. Request
 * bodies are never read. Console breadcrumbs are dropped. Sentry sees this
 * worker's connection, which comes from Cloudflare, not from the person
 * installing.
 */

import { httpServerIntegration, type Breadcrumb, type ErrorEvent } from "@sentry/cloudflare";

export interface SentryEnv {
  /** Worker secret; reporting is off without it. */
  SENTRY_DSN?: string;
  /** If set, reporting is off: reports would go to that host instead. */
  SENTRY_TUNNEL?: string;
}

/**
 * `o<org id>.ingest.sentry.io`, or the same in Sentry's `de` or `us` region:
 * the hosts `WORKER_REPORT_HOST_PATTERNS` in crates/erpc-core/src/endpoints.rs
 * declares for this worker, narrowed to a numeric org id.
 */
const INGEST_HOST = /^o[0-9]+\.ingest(\.(de|us))?\.sentry\.io$/;

export function isSentryIngestHost(host: string): boolean {
  return INGEST_HOST.test(host);
}

/**
 * Why a SENTRY_DSN that is set is not used, or undefined when it is used or
 * not set. The reason never quotes the DSN or any part of it.
 *
 * Besides the destination rules (https, a Sentry ingest host, no tunnel),
 * this refuses what the SDK's own parser would reject and the URL parser
 * cannot normalise. The SDK reports a DSN it cannot parse with
 * `console.error("Invalid Sentry Dsn: " + dsn)`, which would put the whole
 * value, key included, in the Worker's logs. Spellings the URL parser
 * normalises (HTTPS, a fullwidth letter in the host, an empty port,
 * backslashes) are accepted, because the SDK is given a DSN rebuilt from the
 * parsed parts (usableDsn), never the text. Spaces and line breaks around
 * the value are not a reason: they are trimmed.
 */
export function dsnRefusal(env: SentryEnv): string | undefined {
  return parseDsn(env).refusal;
}

/**
 * The DSN to give the SDK, rebuilt from the parts that were checked, so the
 * SDK sees exactly those.
 */
function usableDsn(env: SentryEnv): string | undefined {
  const url = parseDsn(env).url;
  if (!url) return undefined;
  const pass = url.password === "" ? "" : `:${url.password}`;
  return `https://${url.username}${pass}@${url.hostname}${url.pathname}`;
}

function parseDsn(env: SentryEnv): { url?: URL; refusal?: string } {
  // A secret is always a string; anything else is treated as not set.
  if (typeof env.SENTRY_DSN !== "string" || env.SENTRY_DSN === "") return {};
  if (env.SENTRY_TUNNEL !== undefined) {
    return { refusal: "SENTRY_TUNNEL is set, and reports would go there instead" };
  }
  const text = env.SENTRY_DSN.trim();
  if (text === "") return { refusal: "it is blank" };
  // The URL parser drops tabs and line breaks inside its input, so a value
  // with any inside it would be checked as a different string.
  if (/\s/.test(text)) return { refusal: "it has a space or line break inside it" };
  // Even an empty ? or # would stay in the URL's text.
  if (/[?#]/.test(text)) return { refusal: "its path is not a project number alone" };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { refusal: "it is not a URL" };
  }
  if (url.protocol !== "https:") return { refusal: "it is not an https URL" };
  if (!isSentryIngestHost(url.hostname)) {
    return {
      refusal: "its host is not a Sentry ingest host (o<digits>.ingest.sentry.io, or the same in the de or us region)",
    };
  }
  // The URL parser drops :443; any other port is not Sentry's ingest.
  if (url.port !== "") return { refusal: "it names a port" };
  // What the SDK's DSN pattern accepts: a key, and an optional second part,
  // of word characters only.
  if (!/^\w+$/.test(url.username) || (url.password !== "" && !/^\w+$/.test(url.password))) {
    return { refusal: "its key is missing or has characters other than letters, digits and _" };
  }
  if (!/^\/[0-9]+$/.test(url.pathname)) {
    return { refusal: "its path is not a project number alone" };
  }
  return { url };
}

/**
 * A function that logs a refused DSN's reason the first time it is called,
 * and does nothing after that. One is made per Worker instance (below), so a
 * misconfigured secret shows once in the Worker's logs, not on every request.
 */
export function onceWarner(log: (message: string) => void = (message) => console.warn(message)) {
  let warned = false;
  return (reason: string) => {
    if (warned) return;
    warned = true;
    log(`erpc-installer: SENTRY_DSN is set but not used, so error reports are off: ${reason}. `
      + "The DSN's value is not logged.");
  };
}

const warnOnce = onceWarner();

/**
 * Options for `withSentry`, read per request from the Worker's env. A DSN
 * that is set but refused is reported through `warn`.
 */
export function sentryOptions(env: SentryEnv, warn: (reason: string) => void = warnOnce) {
  const refusal = dsnRefusal(env);
  if (refusal !== undefined) warn(refusal);
  const dsn = usableDsn(env);
  return {
    // Never undefined: the SDK falls back to SENTRY_DSN from the env when
    // this is undefined (it uses ??), and parses that value even with
    // reporting off, printing "Invalid Sentry Dsn: " and the whole value
    // when it cannot. An empty string stops the fallback.
    dsn: dsn ?? "",
    // The guard that matters for sending: the SDK reads SENTRY_TUNNEL from
    // the env itself too, so reporting is turned off here whenever the DSN
    // is not used.
    enabled: dsn !== undefined,
    // Not from SENTRY_DEBUG in the env: debug logging is not wanted here.
    debug: false,
    sendDefaultPii: false,
    // Set, so the SDK does not read SENTRY_TRACES_SAMPLE_RATE from the env.
    tracesSampleRate: 0,
    // Wins over a sampling decision a request's sentry-trace header carries.
    tracesSampler: () => 0,
    beforeSendTransaction: () => null,
    // No outbound URL to add sentry-trace and baggage headers to; they would
    // name this DSN's public key and organisation.
    tracePropagationTargets: [],
    // Not from SENTRY_SPOTLIGHT in the env: a second destination.
    spotlight: false,
    // Request bodies are not read: a POST would wait for one before its 405.
    integrations: [httpServerIntegration({ maxRequestBodySize: "none" })],
    beforeSend: scrubEvent,
    beforeBreadcrumb: scrubBreadcrumb,
  };
}

/**
 * Keeps an event to what failed in this worker. The request is reduced to
 * its method and the URL without its query; headers, cookies, body, the
 * client's address and any user are dropped.
 */
export function scrubEvent(event: ErrorEvent): ErrorEvent {
  if (event.request) {
    const url = event.request.url ? withoutQuery(event.request.url) : undefined;
    event.request = { method: event.request.method, url };
  }
  delete event.user;
  // The envelope's trace header. When a request carries `sentry-*` baggage,
  // the SDK copies it here verbatim, so a client could write into a report.
  if (event.sdkProcessingMetadata) {
    delete event.sdkProcessingMetadata.dynamicSamplingContext;
  }
  if (event.contexts) {
    // The trace context: its trace id is the one a request's sentry-trace
    // header names, when it has one, so a client could choose it.
    delete event.contexts.trace;
    // The SDK sets a `culture` context from the request's `cf.timezone`:
    // the timezone of the person installing.
    delete event.contexts.culture;
  }
  return event;
}

/**
 * Console breadcrumbs are dropped: their text is whatever was logged. Other
 * breadcrumbs keep their URLs, without query strings.
 */
export function scrubBreadcrumb(breadcrumb: Breadcrumb): Breadcrumb | null {
  if (breadcrumb.category === "console") return null;
  const url = breadcrumb.data?.url;
  if (typeof url === "string") {
    breadcrumb.data = { ...breadcrumb.data, url: withoutQuery(url) };
  }
  return breadcrumb;
}

function withoutQuery(url: string): string {
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return "[unparsable url]";
  }
}
