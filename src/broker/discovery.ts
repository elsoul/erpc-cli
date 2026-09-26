// Transport shared by the broker registration client, and the issuer check
// that runs before any registration request is sent.

/** Why a broker registration stopped. */
export type BrokerRegistrationFailure =
  | 'access_denied'
  | 'discovery_failed'
  | 'expired'
  | 'expired_token'
  | 'invalid_approver'
  | 'invalid_issuer'
  | 'invalid_request'
  | 'invalid_response'
  | 'quota_exceeded'
  | 'rate_limited'
  | 'registration_mismatch'
  | 'rejected'
  | 'unreachable'
  | 'untrusted_verification_uri'

export class BrokerRegistrationError extends Error {
  readonly reason: BrokerRegistrationFailure

  constructor(reason: BrokerRegistrationFailure, message: string) {
    super(message)
    this.name = 'BrokerRegistrationError'
    this.reason = reason
  }
}

/**
 * The request could not be completed: a network error, a timeout, or a body
 * that stopped arriving part-way. Callers decide whether that is retryable.
 */
export class BrokerUnavailableError extends Error {
  constructor() {
    super('The broker could not be reached')
    this.name = 'BrokerUnavailableError'
  }
}

export interface BrokerRequestDeps {
  readonly fetch: typeof globalThis.fetch
  readonly requestTimeoutMs: number
  readonly signal?: AbortSignal
}

export interface BrokerResponse {
  /** The body as a JSON object, or `null` when it is not one. */
  readonly json: Record<string, unknown> | null
  readonly status: number
}

const MAX_RESPONSE_BYTES = 64 * 1024
// Loopback origins are accepted over plain http for local testing only, the
// same set the template manifest accepts for `broker.issuer`.
const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', '[::1]', 'localhost'])

export const abortError = (): DOMException =>
  new DOMException('Aborted', 'AbortError')

export const isAbortError = (error: unknown): boolean =>
  error instanceof DOMException && error.name === 'AbortError'

const UNSAFE_DISPLAY_CHARACTERS = /[\p{Cc}\p{Cf}]/gu

/**
 * Makes a server-supplied string safe to print: control and format
 * characters (including bidi overrides) are removed and the result is cut to
 * `maxLength` characters.
 */
export const sanitizeForDisplay = (value: string, maxLength = 200): string => {
  const cleaned = value.replace(UNSAFE_DISPLAY_CHARACTERS, '')
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) : cleaned
}

/**
 * Returns the issuer's parsed URL when it is written exactly as an origin
 * (`https://host[:port]`, no path, no trailing slash), or `null` otherwise.
 */
export const parseIssuerOrigin = (issuer: string): URL | null => {
  let url: URL
  try {
    url = new URL(issuer)
  } catch {
    return null
  }
  if (url.origin !== issuer) return null
  if (url.protocol === 'https:') return url
  if (url.protocol === 'http:' && LOOPBACK_HOSTNAMES.has(url.hostname)) {
    return url
  }
  return null
}

/** `{issuer}{path}` for an issuer already checked by `parseIssuerOrigin`. */
export const issuerUrl = (issuer: string, path: string): URL =>
  new URL(`${issuer}${path}`)

const readBoundedText = async (response: Response): Promise<string | null> => {
  if (response.body === null) return ''
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {})
      return null
    }
    chunks.push(value)
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(bytes)
}

const parseJsonObject = (
  text: string | null,
): Record<string, unknown> | null => {
  if (text === null) return null
  try {
    const value: unknown = JSON.parse(text)
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null
  } catch {
    return null
  }
}

/**
 * One broker request: never follows redirects, never sends credentials,
 * always asks for JSON, and bounds both the wait (headers and body) and the
 * body size. Throws `BrokerUnavailableError` when no complete response
 * arrived, and an `AbortError` when the caller's signal aborted.
 */
export const brokerRequest = async (
  url: URL,
  request: { readonly method: 'GET' } | {
    readonly json: Readonly<Record<string, unknown>>
    readonly method: 'POST'
  },
  deps: BrokerRequestDeps,
): Promise<BrokerResponse> => {
  if (deps.signal?.aborted) throw abortError()
  const controller = new AbortController()
  const abort = () => controller.abort()
  const timeout = setTimeout(abort, deps.requestTimeoutMs)
  deps.signal?.addEventListener('abort', abort, { once: true })
  try {
    const init: RequestInit = request.method === 'POST'
      ? {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
        },
        body: JSON.stringify(request.json),
        redirect: 'manual',
        signal: controller.signal,
      }
      : {
        method: 'GET',
        headers: { accept: 'application/json' },
        redirect: 'manual',
        signal: controller.signal,
      }
    const response = await deps.fetch(url, init)
    const text = await readBoundedText(response)
    return { json: parseJsonObject(text), status: response.status }
  } catch {
    if (deps.signal?.aborted) throw abortError()
    throw new BrokerUnavailableError()
  } finally {
    clearTimeout(timeout)
    deps.signal?.removeEventListener('abort', abort)
  }
}

/**
 * Fetches `{issuer}/.well-known/openid-configuration` and requires a 200 JSON
 * document whose `issuer` is byte-for-byte the expected issuer (OpenID Connect
 * Discovery 1.0, section 4.3). Any redirect, other status, malformed body, or
 * different `issuer` - including one that differs only by a trailing slash -
 * is an error.
 */
export const assertIssuerDiscovery = async (
  issuer: string,
  deps: BrokerRequestDeps,
): Promise<void> => {
  if (parseIssuerOrigin(issuer) === null) {
    throw new BrokerRegistrationError(
      'invalid_issuer',
      `The broker issuer must be an https origin with no path or trailing slash: ${
        sanitizeForDisplay(issuer)
      }`,
    )
  }
  const failed = (detail: string) =>
    new BrokerRegistrationError(
      'discovery_failed',
      `Broker discovery failed for ${issuer}: ${detail}. No registration request was sent.`,
    )
  let response: BrokerResponse
  try {
    response = await brokerRequest(
      issuerUrl(issuer, '/.well-known/openid-configuration'),
      { method: 'GET' },
      deps,
    )
  } catch (error) {
    if (error instanceof BrokerUnavailableError) {
      throw failed('the broker could not be reached')
    }
    throw error
  }
  if (response.status !== 200) {
    throw failed(`expected HTTP 200, got ${response.status}`)
  }
  if (response.json === null) {
    throw failed('the discovery document is not a JSON object')
  }
  const advertised = response.json.issuer
  if (typeof advertised !== 'string') {
    throw failed('the discovery document has no issuer')
  }
  if (advertised !== issuer) {
    throw failed(
      `the discovery document names a different issuer (${
        JSON.stringify(sanitizeForDisplay(advertised))
      })`,
    )
  }
}
