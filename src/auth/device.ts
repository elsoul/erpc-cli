export const DEFAULT_AUTH_ENDPOINT = 'https://auth-api.erpc.global'
export const DEFAULT_CLIENT_ID = 'erpc-cli'

export const ERPC_CLOUD_SCOPES = [
  'usage:read',
  'resources:read',
  'resources:write',
  'billing:write',
  'deployments:write',
] as const

export type ErpcCloudScope = (typeof ERPC_CLOUD_SCOPES)[number]

export interface DeviceAuthorization {
  readonly deviceCode: string
  readonly expiresIn: number
  readonly interval: number
  readonly userCode: string
  readonly verificationUri: string
  readonly verificationUriComplete: string
}

export interface OAuthTokenSet {
  readonly accessToken: string
  readonly expiresIn: number
  readonly refreshToken: string
  readonly scope: readonly string[]
  readonly tokenType: 'Bearer'
}

export interface DeviceAuthClientConfig {
  readonly clientId?: string
  readonly endpoint?: string
  readonly fetch?: typeof globalThis.fetch
  readonly requestTimeoutMs?: number
}

export class OAuthProtocolError extends Error {
  readonly oauthCode: string

  constructor(oauthCode: string, message: string) {
    super(message)
    this.name = 'OAuthProtocolError'
    this.oauthCode = oauthCode
  }
}

const endpointUrl = (value?: string): URL => {
  const endpoint = new URL(value ?? DEFAULT_AUTH_ENDPOINT)
  const isLocalHttp = endpoint.protocol === 'http:' &&
    ['127.0.0.1', '::1', '[::1]', 'localhost'].includes(endpoint.hostname)
  if (endpoint.protocol !== 'https:' && !isLocalHttp) {
    throw new Error('OAuth endpoint must use HTTPS except on localhost')
  }
  endpoint.search = ''
  endpoint.hash = ''
  endpoint.pathname = endpoint.pathname.replace(/\/+$/, '') || '/'
  return endpoint
}

const withPath = (endpoint: URL, path: string): URL => {
  const url = new URL(endpoint)
  const base = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '')
  url.pathname = `${base}/${path.replace(/^\/+/, '')}`.replace(/\/{2,}/g, '/')
  return url
}

const objectValue = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null
    ? value as Record<string, unknown>
    : null

const requiredString = (
  value: Record<string, unknown>,
  key: string,
): string => {
  const result = value[key]
  if (typeof result !== 'string' || !result) {
    throw new OAuthProtocolError(
      'invalid_response',
      'The authorization server returned an invalid response',
    )
  }
  return result
}

const requiredNumber = (
  value: Record<string, unknown>,
  key: string,
): number => {
  const result = value[key]
  if (typeof result !== 'number' || !Number.isFinite(result)) {
    throw new OAuthProtocolError(
      'invalid_response',
      'The authorization server returned an invalid response',
    )
  }
  return result
}

const oauthError = (
  body: Record<string, unknown> | null,
): OAuthProtocolError => {
  const code = typeof body?.error === 'string' ? body.error : 'server_error'
  return new OAuthProtocolError(code, `OAuth request failed: ${code}`)
}

const parseTokenSet = (body: Record<string, unknown> | null): OAuthTokenSet => {
  if (!body) {
    throw new OAuthProtocolError(
      'invalid_response',
      'The authorization server returned an invalid response',
    )
  }
  const tokenType = requiredString(body, 'token_type')
  if (tokenType.toLowerCase() !== 'bearer') {
    throw new OAuthProtocolError(
      'invalid_response',
      'The authorization server returned an unsupported token type',
    )
  }
  return {
    accessToken: requiredString(body, 'access_token'),
    expiresIn: requiredNumber(body, 'expires_in'),
    refreshToken: requiredString(body, 'refresh_token'),
    scope: typeof body.scope === 'string'
      ? body.scope.split(/\s+/).filter(Boolean)
      : [],
    tokenType: 'Bearer',
  }
}

const parseJson = async (
  response: Response,
): Promise<Record<string, unknown> | null> => {
  try {
    return objectValue(await response.json())
  } catch {
    return null
  }
}

const sleep = async (milliseconds: number, signal?: AbortSignal) => {
  await new Promise<void>((resolve, reject) => {
    const complete = () => {
      signal?.removeEventListener('abort', abort)
      resolve()
    }
    const timeout = setTimeout(complete, milliseconds)
    const abort = () => {
      clearTimeout(timeout)
      signal?.removeEventListener('abort', abort)
      reject(new DOMException('Aborted', 'AbortError'))
    }
    if (signal?.aborted) abort()
    else signal?.addEventListener('abort', abort, { once: true })
  })
}

export class DeviceAuthClient {
  readonly #clientId: string
  readonly #endpoint: URL
  readonly #fetch: typeof globalThis.fetch
  readonly #requestTimeoutMs: number

  constructor(config: DeviceAuthClientConfig = {}) {
    this.#clientId = config.clientId ?? DEFAULT_CLIENT_ID
    this.#endpoint = endpointUrl(config.endpoint)
    this.#fetch = config.fetch ?? globalThis.fetch
    this.#requestTimeoutMs = config.requestTimeoutMs ?? 30_000
    if (typeof this.#fetch !== 'function') {
      throw new Error('A Fetch API implementation is required')
    }
    if (
      !Number.isFinite(this.#requestTimeoutMs) || this.#requestTimeoutMs <= 0
    ) {
      throw new Error('requestTimeoutMs must be a positive finite number')
    }
  }

  async start(scopes: readonly ErpcCloudScope[]): Promise<DeviceAuthorization> {
    const response = await this.#post('/oauth/device/authorization', {
      client_id: this.#clientId,
      scope: [...new Set(scopes)].join(' '),
    })
    const body = await parseJson(response)
    if (!response.ok) throw oauthError(body)
    if (!body) throw oauthError(body)
    return {
      deviceCode: requiredString(body, 'device_code'),
      expiresIn: requiredNumber(body, 'expires_in'),
      interval: requiredNumber(body, 'interval'),
      userCode: requiredString(body, 'user_code'),
      verificationUri: requiredString(body, 'verification_uri'),
      verificationUriComplete: requiredString(
        body,
        'verification_uri_complete',
      ),
    }
  }

  async poll(
    authorization: DeviceAuthorization,
    signal?: AbortSignal,
  ): Promise<OAuthTokenSet> {
    const expiresAt = Date.now() + authorization.expiresIn * 1000
    let intervalSeconds = authorization.interval

    while (Date.now() < expiresAt) {
      await sleep(intervalSeconds * 1000, signal)
      const response = await this.#post('/oauth/token', {
        client_id: this.#clientId,
        device_code: authorization.deviceCode,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      }, signal)
      const body = await parseJson(response)
      if (response.ok) return parseTokenSet(body)

      const error = oauthError(body)
      if (error.oauthCode === 'authorization_pending') continue
      if (error.oauthCode === 'slow_down') {
        intervalSeconds += 5
        continue
      }
      throw error
    }

    throw new OAuthProtocolError(
      'expired_token',
      'Device authorization expired',
    )
  }

  async refresh(
    refreshToken: string,
    signal?: AbortSignal,
  ): Promise<OAuthTokenSet> {
    const response = await this.#post('/oauth/token', {
      client_id: this.#clientId,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    }, signal)
    const body = await parseJson(response)
    if (!response.ok) throw oauthError(body)
    return parseTokenSet(body)
  }

  async revoke(refreshToken: string, signal?: AbortSignal): Promise<void> {
    const response = await this.#post('/oauth/revoke', {
      client_id: this.#clientId,
      token: refreshToken,
      token_type_hint: 'refresh_token',
    }, signal)
    if (!response.ok) throw oauthError(await parseJson(response))
  }

  async #post(
    path: string,
    fields: Readonly<Record<string, string>>,
    signal?: AbortSignal,
  ): Promise<Response> {
    const controller = new AbortController()
    const abort = () => controller.abort()
    const timeout = setTimeout(abort, this.#requestTimeoutMs)
    if (signal?.aborted) abort()
    else signal?.addEventListener('abort', abort, { once: true })
    try {
      return await this.#fetch(withPath(this.#endpoint, path), {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(fields),
        signal: controller.signal,
      })
    } catch {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      throw new OAuthProtocolError(
        'temporarily_unavailable',
        'Unable to reach ERPC authorization',
      )
    } finally {
      clearTimeout(timeout)
      signal?.removeEventListener('abort', abort)
    }
  }
}
