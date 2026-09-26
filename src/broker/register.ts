// Registers an OAuth client with the template's OIDC broker.
//
// The flow follows the OAuth 2.0 Device Authorization Grant (RFC 8628) without
// issuing any token: the CLI files an unauthenticated registration request,
// the user reviews and approves it in the broker's own page, and the CLI polls
// until the broker hands back the new client_id exactly once. The
// `device_code` is the only thing that ties the poll to the request. The CLI
// sends it only to the poll endpoint and never puts it in output or an error
// itself. A value it would show from a broker response cannot carry it
// either: a registration response whose `user_code` or displayed verification
// page contains it, and a poll response whose error code, `client_id` or
// `approved_by_email` contains it, are refused without showing that value
// (see `parsePendingRegistration`, `acceptApprovedRegistration` and the poll
// loop). A device code with a character that printing would change is
// refused first, so these checks also hold for the printed form.

import type {
  OidcClientRegistrar,
  OidcClientRegistrationIo,
  OidcClientRegistrationRequest,
} from '../app/template-init.ts'
import {
  abortError,
  assertIssuerDiscovery,
  BrokerRegistrationError,
  brokerRequest,
  type BrokerRequestDeps,
  type BrokerResponse,
  BrokerUnavailableError,
  isAbortError,
  issuerUrl,
  parseIssuerOrigin,
  sanitizeForDisplay,
} from './discovery.ts'
import { isShellSafeUrl } from '../open-external.ts'

export interface BrokerRegistrarDeps {
  readonly fetch?: typeof globalThis.fetch
  readonly now?: () => number
  readonly requestTimeoutMs?: number
  readonly sleep?: (milliseconds: number, signal?: AbortSignal) => Promise<void>
}

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000
const SLOW_DOWN_INCREMENT_SECONDS = 5 // RFC 8628, section 3.5
// How long the broker keeps answering the device_code of a delivered
// registration with the same approved response.
const REDELIVERY_GRACE_MS = 60_000

const MAX_CLIENT_NAME_LENGTH = 64
const MAX_REDIRECT_URIS = 5
const MAX_REDIRECT_URI_LENGTH = 2048
const MAX_EXPIRES_IN_SECONDS = 1800
const MAX_INTERVAL_SECONDS = 60
const MAX_DEVICE_CODE_LENGTH = 1024
const MAX_EMAIL_LENGTH = 320

const USER_CODE_PATTERN = /^[A-Z]{4}-[A-Z]{4}$/
// Printing does not change these characters (the URL serializer does not
// percent-encode them and `sanitizeForDisplay` does not remove them), so a
// printed value that shows such a device code contains it exactly, and the
// `includes` checks find it.
const DEVICE_CODE_PATTERN = /^[A-Za-z0-9._~-]+$/
const CLIENT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/
const IPV4_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$/
const CONTROL_OR_FORMAT_CHARACTER = /[\p{Cc}\p{Cf}]/u

const defaultSleep = (
  milliseconds: number,
  signal?: AbortSignal,
): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    const complete = () => {
      signal?.removeEventListener('abort', abort)
      resolve()
    }
    const timeout = setTimeout(complete, milliseconds)
    const abort = () => {
      clearTimeout(timeout)
      signal?.removeEventListener('abort', abort)
      reject(abortError())
    }
    if (signal?.aborted) abort()
    else signal?.addEventListener('abort', abort, { once: true })
  })

const quoted = (value: string): string =>
  JSON.stringify(sanitizeForDisplay(value))

const redirectUriIssues = (
  uri: string,
  issuerHostname: string,
): string[] => {
  if (uri.length > MAX_REDIRECT_URI_LENGTH) {
    return [`longer than ${MAX_REDIRECT_URI_LENGTH} characters`]
  }
  if (CONTROL_OR_FORMAT_CHARACTER.test(uri)) {
    return ['contains a control or format character']
  }
  let url: URL
  try {
    url = new URL(uri)
  } catch {
    return ['is not a valid URL']
  }
  const issues: string[] = []
  if (url.href !== uri) issues.push(`is not in canonical form (${url.href})`)
  if (url.protocol !== 'https:') issues.push('must use https')
  if (url.username !== '' || url.password !== '') {
    issues.push('must not contain userinfo')
  }
  if (url.search !== '' || uri.includes('?')) {
    issues.push('must not contain a query')
  }
  if (url.hash !== '' || uri.includes('#')) {
    issues.push('must not contain a fragment')
  }
  if (uri.includes('*')) issues.push('must not contain a wildcard (*)')
  const hostname = url.hostname.toLowerCase()
  if (hostname.endsWith('.')) {
    issues.push('host must not end with a dot')
  } else if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    issues.push('host must not be localhost')
  } else if (IPV4_LITERAL.test(hostname) || hostname.startsWith('[')) {
    issues.push('host must not be an IP address')
  } else if (hostname === issuerHostname.toLowerCase()) {
    issues.push("host must not be the broker's own host")
  } else if (hostname === 'erpc.global' || hostname.endsWith('.erpc.global')) {
    issues.push('host must not be erpc.global or one of its subdomains')
  }
  return issues
}

/**
 * The broker's own `client_name` / `redirect_uris` rules, applied before
 * anything is sent so that a request the broker would reject never leaves the
 * machine. Returns every violation, not just the first.
 */
const registrationRequestIssues = (
  clientName: string,
  redirectUris: readonly string[],
  issuerHostname: string,
): string[] => {
  const issues: string[] = []
  if (clientName.length < 1 || clientName.length > MAX_CLIENT_NAME_LENGTH) {
    issues.push(
      `client_name must be 1 to ${MAX_CLIENT_NAME_LENGTH} characters (got ${clientName.length})`,
    )
  }
  if (CONTROL_OR_FORMAT_CHARACTER.test(clientName)) {
    issues.push('client_name must not contain control or format characters')
  }
  if (redirectUris.length < 1 || redirectUris.length > MAX_REDIRECT_URIS) {
    issues.push(
      `redirect_uris must contain 1 to ${MAX_REDIRECT_URIS} entries (got ${redirectUris.length})`,
    )
  }
  const seen = new Set<string>()
  redirectUris.forEach((uri, index) => {
    const label = `redirect_uris[${index}] ${quoted(uri)}`
    for (const issue of redirectUriIssues(uri, issuerHostname)) {
      issues.push(`${label} ${issue}`)
    }
    if (seen.has(uri)) issues.push(`${label} is listed more than once`)
    seen.add(uri)
  })
  return issues
}

interface PendingRegistration {
  readonly deviceCode: string
  readonly expiresIn: number
  readonly interval: number
  readonly userCode: string
  /** The approval page printed as `Open <page>`. */
  readonly verificationPage: string
  /** Whether `verificationPage` may be handed to the browser opener. */
  readonly openable: boolean
}

const isIntegerInRange = (
  value: unknown,
  min: number,
  max: number,
): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= min &&
  value <= max

/** Checks a 201 body; the verification pages must be on the issuer's origin. */
const parsePendingRegistration = (
  body: Record<string, unknown> | null,
  issuer: string,
): PendingRegistration => {
  const invalid = (field: string) =>
    new BrokerRegistrationError(
      'invalid_response',
      `The broker returned an invalid registration response (${field}).`,
    )
  if (body === null) throw invalid('body is not a JSON object')
  const deviceCode = body.device_code
  if (
    typeof deviceCode !== 'string' || deviceCode.length === 0 ||
    deviceCode.length > MAX_DEVICE_CODE_LENGTH ||
    !DEVICE_CODE_PATTERN.test(deviceCode)
  ) throw invalid('device_code')
  const userCode = body.user_code
  if (typeof userCode !== 'string' || !USER_CODE_PATTERN.test(userCode)) {
    throw invalid('user_code')
  }
  if (!isIntegerInRange(body.expires_in, 1, MAX_EXPIRES_IN_SECONDS)) {
    throw invalid('expires_in')
  }
  if (!isIntegerInRange(body.interval, 1, MAX_INTERVAL_SECONDS)) {
    throw invalid('interval')
  }
  const pages: URL[] = []
  for (const field of ['verification_uri', 'verification_uri_complete']) {
    const value = body[field]
    let url: URL
    try {
      if (typeof value !== 'string') throw new TypeError()
      url = new URL(value)
    } catch {
      throw invalid(field)
    }
    if (url.origin !== issuer) {
      // Do not show or open a page on another origin: the user would be
      // approving the request somewhere other than the issuer they trusted.
      throw new BrokerRegistrationError(
        'untrusted_verification_uri',
        `The broker's ${field} is not on ${issuer}; refusing to show or open it.`,
      )
    }
    pages.push(url)
  }
  if (userCode.includes(deviceCode)) throw invalid('user_code')
  // The opener on some platforms hands its argument to a shell, so only the
  // fixed form built from the checked issuer and user_code is ever opened,
  // and only when the issuer's host keeps it inside the characters a shell
  // reads as plain text. Anything else falls back to the verification page
  // without its query, which is printed next to the code and never opened.
  const fixedComplete = `${issuer}/register?user_code=${userCode}`
  const openable = pages[1]!.href === fixedComplete &&
    isShellSafeUrl(fixedComplete)
  // `href` is the URL serializer's output: printable ASCII only.
  const verificationPage = openable
    ? fixedComplete
    : `${pages[0]!.origin}${pages[0]!.pathname}`
  if (verificationPage.includes(deviceCode)) {
    throw invalid(openable ? 'verification_uri_complete' : 'verification_uri')
  }
  return {
    deviceCode,
    expiresIn: body.expires_in as number,
    interval: body.interval as number,
    userCode,
    verificationPage,
    openable,
  }
}

const sameRedirectUriSet = (
  returned: unknown,
  requested: readonly string[],
): boolean => {
  if (!Array.isArray(returned) || returned.length !== requested.length) {
    return false
  }
  if (!returned.every((value) => typeof value === 'string')) return false
  const requestedSet = new Set(requested)
  return new Set(returned).size === returned.length &&
    returned.every((value) => requestedSet.has(value))
}

const isValidApproverEmail = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 &&
  value.length <= MAX_EMAIL_LENGTH && value.includes('@') &&
  !CONTROL_OR_FORMAT_CHARACTER.test(value)

/**
 * Checks an approved registration against what was requested. Nothing from a
 * response that fails here is returned: the client_id is only shown so the
 * user can recognise the stray registration later, and a client_id or
 * approver email that contains the device_code is never shown.
 */
const acceptApprovedRegistration = (
  body: Record<string, unknown> | null,
  request: {
    readonly clientName: string
    readonly deviceCode: string
    readonly redirectUris: readonly string[]
  },
): { readonly approvedByEmail: string; readonly clientId: string } => {
  const invalid = (field: string) =>
    new BrokerRegistrationError(
      'invalid_response',
      `The broker returned an invalid approved registration (${field}). The registration was not used.`,
    )
  if (body === null) throw invalid('body is not a JSON object')
  const clientId = body.client_id
  if (
    typeof clientId !== 'string' || !CLIENT_ID_PATTERN.test(clientId) ||
    clientId.includes(request.deviceCode)
  ) throw invalid('client_id')
  const mismatched: string[] = []
  if (body.client_name !== request.clientName) mismatched.push('client_name')
  if (!sameRedirectUriSet(body.redirect_uris, request.redirectUris)) {
    mismatched.push('redirect_uris')
  }
  if (mismatched.length > 0) {
    throw new BrokerRegistrationError(
      'registration_mismatch',
      `The registration the broker returned does not match the request (${
        mismatched.join(', ')
      } differ; client_id: ${clientId}). The client_id was not used.`,
    )
  }
  const approvedByEmail = body.approved_by_email
  if (!isValidApproverEmail(approvedByEmail)) {
    throw new BrokerRegistrationError(
      'invalid_approver',
      `The broker did not say which account approved the registration (client_id: ${clientId}). The client_id was not used.`,
    )
  }
  if (approvedByEmail.includes(request.deviceCode)) {
    throw invalid('approved_by_email')
  }
  return { approvedByEmail, clientId }
}

/**
 * The broker registrar used by `erpc app init --template` for a
 * `broker-register` prompt. Every dependency is injectable so the whole flow
 * can run against a fake broker and a fake clock.
 */
export const createBrokerRegistrar = (
  deps: BrokerRegistrarDeps = {},
): OidcClientRegistrar => {
  const fetchImpl: typeof globalThis.fetch = deps.fetch ??
    ((input, init) => globalThis.fetch(input, init))
  const sleep = deps.sleep ?? defaultSleep
  const now = deps.now ?? Date.now
  const requestTimeoutMs = deps.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
  if (!Number.isFinite(requestTimeoutMs) || requestTimeoutMs <= 0) {
    throw new Error('requestTimeoutMs must be a positive finite number')
  }

  const register = async (
    request: OidcClientRegistrationRequest,
    io: OidcClientRegistrationIo,
  ): Promise<{ readonly clientId: string }> => {
    const { issuer, clientName } = request
    const redirectUris = [...request.redirectUris]
    const signal = io.signal
    if (signal?.aborted) throw abortError()

    const issuerOrigin = parseIssuerOrigin(issuer)
    if (issuerOrigin === null) {
      throw new BrokerRegistrationError(
        'invalid_issuer',
        `The broker issuer must be an https origin with no path or trailing slash: ${
          quoted(issuer)
        }`,
      )
    }
    const issues = registrationRequestIssues(
      clientName,
      redirectUris,
      issuerOrigin.hostname,
    )
    if (issues.length > 0) {
      throw new BrokerRegistrationError(
        'invalid_request',
        `Cannot send the broker registration request:\n${
          issues.map((issue) => `  - ${issue}`).join('\n')
        }`,
      )
    }

    const requestDeps: BrokerRequestDeps = {
      fetch: fetchImpl,
      requestTimeoutMs,
      ...(signal === undefined ? {} : { signal }),
    }
    await assertIssuerDiscovery(issuer, requestDeps)

    let created: BrokerResponse
    try {
      created = await brokerRequest(
        issuerUrl(issuer, '/clients/registration-requests'),
        {
          method: 'POST',
          json: { client_name: clientName, redirect_uris: redirectUris },
        },
        requestDeps,
      )
    } catch (error) {
      if (error instanceof BrokerUnavailableError) {
        throw new BrokerRegistrationError(
          'unreachable',
          `Unable to reach the broker at ${issuer} to request registration.`,
        )
      }
      throw error
    }
    if (created.status === 400) {
      const code = typeof created.json?.error === 'string'
        ? sanitizeForDisplay(created.json.error, 64)
        : 'invalid_request'
      const description = typeof created.json?.error_description === 'string'
        ? `: ${sanitizeForDisplay(created.json.error_description)}`
        : ''
      throw new BrokerRegistrationError(
        'rejected',
        `The broker rejected the registration request (${code})${description}`,
      )
    }
    if (created.status === 429) {
      throw new BrokerRegistrationError(
        'rate_limited',
        'The broker is receiving too many registration requests. Wait a while, then run the command again.',
      )
    }
    if (created.status !== 201) {
      throw new BrokerRegistrationError(
        'invalid_response',
        `The broker returned HTTP ${created.status} for the registration request.`,
      )
    }
    const pending = parsePendingRegistration(created.json, issuer)
    const expiresAt = now() + pending.expiresIn * 1000

    io.output(`Open ${pending.verificationPage}`)
    io.output(`Code: ${pending.userCode}`)
    io.output(
      [
        'Before approving, confirm that the broker page shows exactly these redirect URIs:',
        ...redirectUris.map((uri) => `  ${uri}`),
      ].join('\n'),
    )
    if (pending.openable) {
      try {
        io.openExternal?.(pending.verificationPage)
      } catch {
        // The URL is printed above, so opening a browser is best effort.
      }
    }

    const pollUrl = issuerUrl(issuer, '/clients/registration-requests/poll')
    // A poll that starts before `expiresAt` may be the one the broker answered
    // with the approval, and that answer may have been lost. The broker
    // re-sends it for REDELIVERY_GRACE_MS, so polling continues until that
    // long after the last such poll instead of reading a pending request as
    // expired at `expiresAt`.
    let lastPollBeforeExpiry: number | undefined
    const pollingEndsAt = (): number =>
      lastPollBeforeExpiry === undefined
        ? expiresAt
        : Math.max(expiresAt, lastPollBeforeExpiry + REDELIVERY_GRACE_MS)
    let intervalSeconds = pending.interval
    while (true) {
      const remaining = pollingEndsAt() - now()
      if (remaining <= 0) break
      await sleep(Math.min(intervalSeconds * 1000, remaining), signal)
      if (signal?.aborted) throw abortError()
      const startedAt = now()
      if (startedAt >= pollingEndsAt()) break
      if (startedAt < expiresAt) lastPollBeforeExpiry = startedAt

      let polled: BrokerResponse
      try {
        polled = await brokerRequest(
          pollUrl,
          { method: 'POST', json: { device_code: pending.deviceCode } },
          requestDeps,
        )
      } catch (error) {
        if (isAbortError(error)) throw error
        // A lost response is retried: an approved registration stays
        // available to the same device_code for a short grace period.
        if (error instanceof BrokerUnavailableError) continue
        throw error
      }

      if (polled.status === 200) {
        const approved = acceptApprovedRegistration(polled.json, {
          clientName,
          deviceCode: pending.deviceCode,
          redirectUris,
        })
        io.output(
          `Approved by: ${approved.approvedByEmail} — if this is not the Google account you used, stop and do not deploy.`,
        )
        return { clientId: approved.clientId }
      }
      if (polled.status === 429 || polled.status >= 500) continue
      if (polled.status === 400) {
        const code = polled.json?.error
        if (code === 'authorization_pending') continue
        if (code === 'slow_down') {
          intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS
          continue
        }
        if (code === 'access_denied') {
          if (polled.json?.error_description === 'quota_exceeded') {
            throw new BrokerRegistrationError(
              'quota_exceeded',
              'This Google account has reached the broker registration limit. The registration was not created.',
            )
          }
          throw new BrokerRegistrationError(
            'access_denied',
            'The registration request was denied in the browser.',
          )
        }
        if (code === 'expired_token') {
          throw new BrokerRegistrationError(
            'expired_token',
            "The broker reports that this registration request has expired or was already used. Run 'erpc app init' again to start a new request.",
          )
        }
        const shownCode = typeof code === 'string'
          ? sanitizeForDisplay(code, 64)
          : 'no error code'
        if (
          typeof code === 'string' &&
          (code.includes(pending.deviceCode) ||
            shownCode.includes(pending.deviceCode))
        ) {
          throw new BrokerRegistrationError(
            'invalid_response',
            'The broker returned an invalid registration poll response (error).',
          )
        }
        throw new BrokerRegistrationError(
          'invalid_response',
          `The broker rejected the registration poll (${shownCode}).`,
        )
      }
      throw new BrokerRegistrationError(
        'invalid_response',
        `The broker returned HTTP ${polled.status} while waiting for approval.`,
      )
    }
    throw new BrokerRegistrationError(
      'expired',
      "The registration request expired before it was approved. Run 'erpc app init' again to start a new request.",
    )
  }

  return { register }
}
