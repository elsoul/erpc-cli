import { describe, expect, it, vi } from './testing.ts'
import {
  DeviceAuthClient,
  type RefreshTokenStore,
  runCli,
} from '../src/index.ts'

class FailingStore implements RefreshTokenStore {
  async delete() {}
  async get() {
    return null
  }
  async set(_refreshToken: string) {
    throw new Error('keychain unavailable')
  }
}

describe('CLI login', () => {
  it('revokes a refresh credential when keychain storage fails', async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({
          device_code: 'device-secret',
          user_code: 'ABCD-EFGH',
          verification_uri: 'https://auth.example/device',
          verification_uri_complete:
            'https://auth.example/device?user_code=ABCD-EFGH',
          expires_in: 60,
          interval: 0,
        })),
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
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch,
    })

    await expect(runCli(['login', '--no-open'], {
      auth,
      output: () => undefined,
      store: new FailingStore(),
    })).rejects.toThrow('keychain unavailable')

    const revocation = new URLSearchParams(
      String(fetch.mock.calls[2]?.[1]?.body),
    )
    expect(revocation.get('token')).toBe('refresh-secret')
  })
})
