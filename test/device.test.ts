import { describe, expect, it, vi } from './testing.ts'
import {
  DeviceAuthClient,
  type DeviceAuthorization,
  OAuthProtocolError,
} from '../src/index.ts'

const authorization: DeviceAuthorization = {
  deviceCode: 'device-secret',
  expiresIn: 60,
  interval: 0,
  userCode: 'ABCD-EFGH',
  verificationUri: 'https://auth.example/device',
  verificationUriComplete: 'https://auth.example/device?user_code=ABCD-EFGH',
}

describe('Device OAuth client', () => {
  it('rejects plaintext remote authorization endpoints', () => {
    expect(() =>
      new DeviceAuthClient({
        endpoint: 'http://auth.example',
      })
    ).toThrow('must use HTTPS except on localhost')
  })

  it('starts the fixed public client with explicit Cloud scopes', async () => {
    let capturedBody = ''
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch: async (_input, init) => {
        capturedBody = String(init?.body)
        return new Response(JSON.stringify({
          device_code: authorization.deviceCode,
          user_code: authorization.userCode,
          verification_uri: authorization.verificationUri,
          verification_uri_complete: authorization.verificationUriComplete,
          expires_in: authorization.expiresIn,
          interval: authorization.interval,
        }))
      },
    })

    await expect(auth.start(['usage:read', 'resources:read'])).resolves.toEqual(
      authorization,
    )
    const body = new URLSearchParams(capturedBody)
    expect(body.get('client_id')).toBe('erpc-cli')
    expect(body.get('scope')).toBe('usage:read resources:read')
  })

  it('uses identity scopes while Cloud OAuth is not advertised', async () => {
    let capturedBody = ''
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch: async (_input, init) => {
        if (init?.method !== 'POST') {
          return new Response(JSON.stringify({
            scopes_supported: ['identify', 'email', 'openid', 'profile'],
          }))
        }
        capturedBody = String(init.body)
        return new Response(JSON.stringify({
          device_code: authorization.deviceCode,
          user_code: authorization.userCode,
          verification_uri: authorization.verificationUri,
          verification_uri_complete: authorization.verificationUriComplete,
          expires_in: authorization.expiresIn,
          interval: authorization.interval,
        }))
      },
    })

    await expect(auth.startLogin()).resolves.toEqual(authorization)
    expect(new URLSearchParams(capturedBody).get('scope')).toBe(
      'openid profile email',
    )
  })

  it('uses read-only Cloud scopes as soon as they are advertised', async () => {
    let capturedBody = ''
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch: async (_input, init) => {
        if (init?.method !== 'POST') {
          return new Response(JSON.stringify({
            scopes_supported: [
              'openid',
              'profile',
              'email',
              'usage:read',
              'resources:read',
            ],
          }))
        }
        capturedBody = String(init.body)
        return new Response(JSON.stringify({
          device_code: authorization.deviceCode,
          user_code: authorization.userCode,
          verification_uri: authorization.verificationUri,
          verification_uri_complete: authorization.verificationUriComplete,
          expires_in: authorization.expiresIn,
          interval: authorization.interval,
        }))
      },
    })

    await expect(auth.startLogin()).resolves.toEqual(authorization)
    expect(new URLSearchParams(capturedBody).get('scope')).toBe(
      'usage:read resources:read',
    )
  })

  it('uses authorization-server defaults when metadata is unavailable', async () => {
    let capturedBody = ''
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch: async (_input, init) => {
        if (init?.method !== 'POST') return new Response(null, { status: 503 })
        capturedBody = String(init.body)
        return new Response(JSON.stringify({
          device_code: authorization.deviceCode,
          user_code: authorization.userCode,
          verification_uri: authorization.verificationUri,
          verification_uri_complete: authorization.verificationUriComplete,
          expires_in: authorization.expiresIn,
          interval: authorization.interval,
        }))
      },
    })

    await expect(auth.startLogin()).resolves.toEqual(authorization)
    expect(new URLSearchParams(capturedBody).get('scope')).toBe('')
  })

  it('polls through pending without exposing the device credential', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ error: 'authorization_pending' }),
          { status: 400 },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({
          access_token: 'access-secret',
          refresh_token: 'refresh-secret',
          token_type: 'Bearer',
          expires_in: 300,
          scope: 'usage:read',
        })),
      )
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch,
    })

    const tokens = await auth.poll(authorization)

    expect(tokens.accessToken).toBe('access-secret')
    expect(tokens.refreshToken).toBe('refresh-secret')
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('returns only the OAuth error code for rejected token requests', async () => {
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch: async () =>
        new Response(
          JSON.stringify({
            error: 'invalid_grant',
            error_description: 'refresh-secret must never be retained',
          }),
          { status: 400 },
        ),
    })

    const error = await auth.refresh('refresh-secret').catch((value) => value)

    expect(error).toBeInstanceOf(OAuthProtocolError)
    expect(String(error)).not.toContain('refresh-secret')
  })
})
