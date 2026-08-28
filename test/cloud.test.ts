import { describe, expect, it } from 'vitest'
import { CloudApiClient } from '../src'

describe('Cloud API client', () => {
  it('rejects plaintext remote API endpoints', () => {
    expect(() => new CloudApiClient({
      accessToken: 'access-secret',
      endpoint: 'http://user.example',
    })).toThrow('must use HTTPS except on localhost')
  })

  it('returns masked monthly usage without retaining full API keys', async () => {
    const cloud = new CloudApiClient({
      accessToken: 'access-secret',
      endpoint: 'https://user.example',
      fetch: async () => new Response(JSON.stringify({
        success: true,
        message: {
          yearMonth: '2026-08',
          totalCount: 12,
          totalCredits: 3,
          updatedAt: null,
          keyCount: 1,
          hasStrandedUsage: false,
          chains: [],
          apiKeys: [{
            keyId: 7,
            apiKeyLast4: 'cdef',
            apiKeyLength: 32,
            count: 12,
            credits: 3,
            updatedAt: null,
            chains: [],
            apiKey: 'must-not-leave-the-client',
          }],
        },
      })),
    })

    const usage = await cloud.getMonthlyApiKeyUsage({ yearMonth: '2026-08' })

    expect(usage.apiKeys[0]?.apiKeyLast4).toBe('cdef')
    expect(usage.apiKeys[0]).not.toHaveProperty('apiKey')
  })

  it('lists only the safe resource projection', async () => {
    let authorization = ''
    const cloud = new CloudApiClient({
      accessToken: 'access-secret',
      endpoint: 'https://user.example',
      fetch: async (_input, init) => {
        authorization = new Headers(init?.headers).get('authorization') ?? ''
        return new Response(JSON.stringify({
          success: true,
          message: {
            resources: [{
              id: 'vps_123',
              kind: 'vps',
              status: 'active',
              region: 'frankfurt',
              billing: { status: 'active', hourlyCredits: 10 },
              username: 'must-not-leave-the-client',
              password: 'must-not-leave-the-client',
            }],
          },
        }))
      },
    })

    await expect(cloud.listResources()).resolves.toEqual([{
      id: 'vps_123',
      kind: 'vps',
      status: 'active',
      region: 'frankfurt',
    }])
    expect(authorization).toBe('Bearer access-secret')
  })

  it('encodes resource IDs and drops unexpected get-response fields', async () => {
    let capturedUrl = ''
    const cloud = new CloudApiClient({
      accessToken: 'access-secret',
      endpoint: 'https://user.example',
      fetch: async (input) => {
        capturedUrl = String(input)
        return new Response(JSON.stringify({
          success: true,
          message: {
            resource: {
              id: 'vps/example',
              kind: 'vps',
              status: 'active',
              host: 'must-not-leave-the-client',
            },
          },
        }))
      },
    })

    await expect(cloud.getResource(' vps/example ')).resolves.toEqual({
      id: 'vps/example',
      kind: 'vps',
      status: 'active',
    })
    expect(capturedUrl).toBe(
      'https://user.example/v4/cloud/resources/vps%2Fexample',
    )
  })

  it('projects the capability catalog without internal or pricing fields', async () => {
    const cloud = new CloudApiClient({
      accessToken: 'access-secret',
      endpoint: 'https://user.example',
      fetch: async () => new Response(JSON.stringify({
        success: true,
        message: {
          offerings: [{
            id: 'vps',
            kind: 'vps',
            mode: 'shared',
            name: 'Virtual server',
            description: 'General compute',
            regions: [],
            capabilities: ['node', 'deno'],
            compute: { tenancy: 'virtual-machine' },
            provider: 'must-not-leave-the-client',
            priceCents: 100,
          }],
        },
      })),
    })

    await expect(cloud.listCatalog()).resolves.toEqual([{
      id: 'vps',
      kind: 'vps',
      mode: 'shared',
      name: 'Virtual server',
      description: 'General compute',
      regions: [],
      capabilities: ['node', 'deno'],
      compute: { tenancy: 'virtual-machine' },
    }])
  })

  it('projects credit and resource status snapshots', async () => {
    const cloud = new CloudApiClient({
      accessToken: 'access-secret',
      endpoint: 'https://user.example',
      fetch: async (input) => {
        const path = new URL(String(input)).pathname
        if (path.endsWith('/status')) {
          return new Response(JSON.stringify({
            success: true,
            message: {
              id: 'vps_123',
              status: 'active',
              billing: {
                status: 'active',
                hourlyCredits: 10,
                nextChargeAt: '2026-08-28T15:00:00.000Z',
                password: 'must-not-leave-the-client',
              },
              host: 'must-not-leave-the-client',
            },
          }))
        }
        return new Response(JSON.stringify({
          success: true,
          message: {
            balanceCents: 5000,
            burnRateCentsPerHour: 100,
            timeToZeroHours: 50,
            alertLevel: 'normal',
            quoteTimestamp: '2026-08-28T14:00:00.000Z',
            quoteExpiresAt: '2026-08-28T14:05:00.000Z',
            internalLedgerId: 'must-not-leave-the-client',
          },
        }))
      },
    })

    await expect(cloud.getCredit()).resolves.toEqual({
      balanceCents: 5000,
      burnRateCentsPerHour: 100,
      timeToZeroHours: 50,
      alertLevel: 'normal',
      quoteTimestamp: '2026-08-28T14:00:00.000Z',
      quoteExpiresAt: '2026-08-28T14:05:00.000Z',
    })
    await expect(cloud.getResourceStatus('vps_123')).resolves.toEqual({
      id: 'vps_123',
      status: 'active',
      billing: {
        status: 'active',
        hourlyCredits: 10,
        nextChargeAt: '2026-08-28T15:00:00.000Z',
      },
    })
  })

  it('does not retain a credential-bearing network error', async () => {
    const cloud = new CloudApiClient({
      accessToken: 'access-secret',
      fetch: async (_input, init) => {
        throw new Error(String(new Headers(init?.headers).get('authorization')))
      },
    })

    const error = await cloud.listResources().catch((value) => value)
    expect(String(error)).not.toContain('access-secret')
  })
})
