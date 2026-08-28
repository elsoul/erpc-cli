import { describe, expect, it } from 'vitest'
import { app } from '../src/app.js'

describe('app', () => {
  it('reports health', async () => {
    const response = await app.request('/health')
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({ status: 'ok' })
  })

  it('publishes an OpenAPI document', async () => {
    const response = await app.request('/doc')
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({ openapi: '3.1.0' })
  })
})
