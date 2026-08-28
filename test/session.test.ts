import { describe, expect, it, vi } from 'vitest'
import {
  CliAuthSession,
  DeviceAuthClient,
  type RefreshTokenStore,
} from '../src'

class MemoryStore implements RefreshTokenStore {
  value: string | null = 'old-refresh'

  async delete() {
    this.value = null
  }

  async get() {
    return this.value
  }

  async set(refreshToken: string) {
    this.value = refreshToken
  }
}

describe('CLI auth session', () => {
  it('replaces the stored refresh token and returns access only in memory', async () => {
    const store = new MemoryStore()
    const auth = new DeviceAuthClient({
      endpoint: 'https://auth.example',
      fetch: async () => new Response(JSON.stringify({
        access_token: 'access-secret',
        refresh_token: 'new-refresh',
        token_type: 'Bearer',
        expires_in: 300,
        scope: 'usage:read',
      })),
    })
    const session = new CliAuthSession(auth, store)

    await expect(session.getAccessToken()).resolves.toBe('access-secret')
    expect(store.value).toBe('new-refresh')
  })

  it('revokes server-side before deleting the keychain entry', async () => {
    const store = new MemoryStore()
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response(null, { status: 200 }))
    const session = new CliAuthSession(
      new DeviceAuthClient({ endpoint: 'https://auth.example', fetch }),
      store,
    )

    await expect(session.logout()).resolves.toBe(true)
    expect(store.value).toBeNull()
    const body = new URLSearchParams(String(fetch.mock.calls[0]?.[1]?.body))
    expect(body.get('token')).toBe('old-refresh')
    expect(body.get('client_id')).toBe('erpc-cli')
  })
})
