// D7: post-deploy verification. See design doc §3.3 Decision 9.
//
// `oauth-authorize-redirect` never renders the broker's consent screen and
// never reaches Google: a same-origin 302 chain worker -> issuer ->
// `<issuer>/oauth/consent...` is the positive signal (an unregistered client
// or a redirect_uri mismatch gets a 400 with no Location instead - contract
// D-2 3.), so the probe stops the instant it has observed that chain.

import { encodeBase64 } from '@std/encoding/base64'
import type { TemplateManifest } from '../app/template-manifest.ts'

const LOOPBACK_REDIRECT_URI = 'http://127.0.0.1:53682/callback'

const toBase64Url = (bytes: Uint8Array): string =>
  encodeBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(
    /=+$/,
    '',
  )

export interface PostDeployProbeOptions {
  readonly fetch: typeof globalThis.fetch
  readonly random: (bytes: Uint8Array<ArrayBuffer>) => void
  readonly timeoutSeconds: number
  readonly vars: Readonly<Record<string, string>>
}

type ProbeAttempt =
  | { readonly message: string; readonly ok: false }
  | { readonly ok: true }

const ok: ProbeAttempt = { ok: true }
const fail = (message: string): ProbeAttempt => ({ message, ok: false })

const originOf = (value: string): string | null => {
  try {
    return new URL(value).origin
  } catch {
    return null
  }
}

const attemptHttp = async (
  probe: Extract<
    NonNullable<TemplateManifest['postDeploy']>[number],
    { readonly kind: 'http' }
  >,
  options: PostDeployProbeOptions,
): Promise<ProbeAttempt> => {
  const base = options.vars[probe.baseUrlFromVar]
  if (!base) {
    return fail(`[vars].${probe.baseUrlFromVar} is not set in wrangler.toml`)
  }
  let response: Response
  try {
    response = await options.fetch(new URL(probe.path, base), {
      redirect: 'manual',
    })
  } catch (error) {
    return fail(
      `GET ${probe.path} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  if (response.status !== probe.expectStatus) {
    return fail(
      `GET ${probe.path} returned ${response.status}, expected ${probe.expectStatus}`,
    )
  }
  if (probe.expectJson) {
    let body: unknown
    try {
      body = await response.json()
    } catch {
      return fail(`GET ${probe.path} did not return valid JSON`)
    }
    for (const [key, expected] of Object.entries(probe.expectJson)) {
      const actual = body !== null && typeof body === 'object'
        ? (body as Record<string, unknown>)[key]
        : undefined
      if (actual !== expected) {
        return fail(
          `GET ${probe.path} JSON field "${key}" was ${
            JSON.stringify(actual)
          }, expected ${JSON.stringify(expected)}`,
        )
      }
    }
  }
  return ok
}

const attemptOauthAuthorizeRedirect = async (
  probe: Extract<
    NonNullable<TemplateManifest['postDeploy']>[number],
    { readonly kind: 'oauth-authorize-redirect' }
  >,
  options: PostDeployProbeOptions,
): Promise<ProbeAttempt> => {
  const base = options.vars[probe.baseUrlFromVar]
  const issuer = options.vars[probe.issuerFromVar]
  if (!base) {
    return fail(`[vars].${probe.baseUrlFromVar} is not set in wrangler.toml`)
  }
  if (!issuer) {
    return fail(`[vars].${probe.issuerFromVar} is not set in wrangler.toml`)
  }
  const issuerOrigin = originOf(issuer)
  if (!issuerOrigin) return fail(`[vars].${probe.issuerFromVar} is not a URL`)

  let registerResponse: Response
  try {
    registerResponse = await options.fetch(new URL('/oauth/register', base), {
      body: JSON.stringify({
        client_name: 'erpc-cli deploy probe',
        redirect_uris: [LOOPBACK_REDIRECT_URI],
        token_endpoint_auth_method: 'none',
      }),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
    })
  } catch (error) {
    return fail(
      `POST /oauth/register failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  if (!registerResponse.ok) {
    return fail(
      `POST /oauth/register returned ${registerResponse.status}`,
    )
  }
  let registered: unknown
  try {
    registered = await registerResponse.json()
  } catch {
    return fail('POST /oauth/register did not return valid JSON')
  }
  const clientId = registered !== null && typeof registered === 'object'
    ? (registered as Record<string, unknown>).client_id
    : undefined
  if (typeof clientId !== 'string' || !clientId) {
    return fail('POST /oauth/register response is missing client_id')
  }

  const verifierBytes = new Uint8Array(32)
  options.random(verifierBytes)
  const codeVerifier = toBase64Url(verifierBytes)
  const challengeBytes = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(codeVerifier),
    ),
  )
  const codeChallenge = toBase64Url(challengeBytes)
  const stateBytes = new Uint8Array(16)
  options.random(stateBytes)

  const authorizeUrl = new URL('/oauth/authorize', base)
  authorizeUrl.searchParams.set('response_type', 'code')
  authorizeUrl.searchParams.set('client_id', clientId)
  authorizeUrl.searchParams.set('redirect_uri', LOOPBACK_REDIRECT_URI)
  authorizeUrl.searchParams.set('state', toBase64Url(stateBytes))
  authorizeUrl.searchParams.set('code_challenge', codeChallenge)
  authorizeUrl.searchParams.set('code_challenge_method', 'S256')

  let authorizeResponse: Response
  try {
    authorizeResponse = await options.fetch(authorizeUrl, {
      redirect: 'manual',
    })
  } catch (error) {
    return fail(
      `GET /oauth/authorize failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  const firstLocation = authorizeResponse.headers.get('location')
  if (authorizeResponse.status !== 302 || !firstLocation) {
    return fail(
      `the worker's /oauth/authorize returned ${authorizeResponse.status}, expected a 302 with a Location`,
    )
  }
  let firstLocationUrl: URL
  try {
    firstLocationUrl = new URL(firstLocation, base)
  } catch {
    return fail(
      `the worker's /oauth/authorize Location header is not a URL: ${firstLocation}`,
    )
  }
  if (firstLocationUrl.origin !== issuerOrigin) {
    return fail(
      `the worker's /oauth/authorize redirected outside the issuer origin (${firstLocationUrl.origin})`,
    )
  }
  if (!probe.followIssuer) return ok

  let brokerResponse: Response
  try {
    brokerResponse = await options.fetch(firstLocationUrl, {
      redirect: 'manual',
    })
  } catch (error) {
    return fail(
      `GET the issuer's authorize redirect failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  const secondLocation = brokerResponse.headers.get('location')
  if (brokerResponse.status !== 302 || !secondLocation) {
    return fail(
      `the issuer returned ${brokerResponse.status}, expected a 302 with a Location (an unregistered client or redirect_uri mismatch responds 400 with no Location)`,
    )
  }
  let secondLocationUrl: URL
  try {
    secondLocationUrl = new URL(secondLocation, issuer)
  } catch {
    return fail(`the issuer's Location header is not a URL: ${secondLocation}`)
  }
  if (
    secondLocationUrl.origin !== issuerOrigin ||
    !secondLocationUrl.pathname.startsWith('/oauth/consent')
  ) {
    return fail(
      `the issuer redirected somewhere unexpected (${secondLocationUrl.origin}${secondLocationUrl.pathname}), expected ${issuerOrigin}/oauth/consent...`,
    )
  }
  return ok
}

const attemptProbe = (
  probe: NonNullable<TemplateManifest['postDeploy']>[number],
  options: PostDeployProbeOptions,
): Promise<ProbeAttempt> =>
  probe.kind === 'http'
    ? attemptHttp(probe, options)
    : attemptOauthAuthorizeRedirect(probe, options)

const sleep = (ms: number): Promise<void> =>
  new Promise((resolvePromise) => setTimeout(resolvePromise, ms))

const withBackoff = async (
  attempt: () => Promise<ProbeAttempt>,
  timeoutSeconds: number,
): Promise<ProbeAttempt> => {
  const deadline = Date.now() + timeoutSeconds * 1000
  let delayMs = 250
  while (true) {
    const result = await attempt()
    if (result.ok) return result
    const remaining = deadline - Date.now()
    if (remaining <= 0) return result
    await sleep(Math.min(delayMs, remaining))
    delayMs *= 2
  }
}

/**
 * Runs every `postDeploy[]` probe in order, retrying each with backoff up to
 * `timeoutSeconds`. Throws `${failurePrefix}: <reason>` for the first probe
 * that never succeeds (Decision 9).
 */
export const runPostDeployProbes = async (
  postDeploy: TemplateManifest['postDeploy'],
  options: PostDeployProbeOptions,
  failurePrefix: string,
): Promise<void> => {
  if (!postDeploy || postDeploy.length === 0) return
  for (const probe of postDeploy) {
    const result = await withBackoff(
      () => attemptProbe(probe, options),
      options.timeoutSeconds,
    )
    if (!result.ok) throw new Error(`${failurePrefix}: ${result.message}`)
  }
}
