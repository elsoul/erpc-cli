// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * Error reports from this worker to Sentry, and what they may hold.
 *
 * Reporting is on only when the `SENTRY_DSN` Worker secret names a Sentry
 * ingest host over https and no `SENTRY_TUNNEL` variable is set; otherwise
 * (tests, `wrangler dev`, a deployment nobody configured) the SDK sends
 * nothing. The DSN is never in this repository.
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

/** The DSN, when it names a Sentry ingest host over https. */
function ingestDsn(dsn: string | undefined): string | undefined {
  if (!dsn) return undefined;
  try {
    const url = new URL(dsn);
    return url.protocol === "https:" && isSentryIngestHost(url.hostname) ? dsn : undefined;
  } catch {
    return undefined;
  }
}

/** Options for `withSentry`, read per request from the Worker's env. */
export function sentryOptions(env: SentryEnv) {
  const dsn = env.SENTRY_TUNNEL === undefined ? ingestDsn(env.SENTRY_DSN) : undefined;
  return {
    dsn,
    // The guard that matters: the SDK reads SENTRY_DSN and SENTRY_TUNNEL from
    // the env itself when these options leave them unset, so a DSN refused
    // above would still be used if reporting were not turned off here.
    enabled: dsn !== undefined,
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
