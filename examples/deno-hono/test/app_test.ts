import { app } from '../src/app.ts'

Deno.test('app reports health', async () => {
  const response = await app.request('/health')
  if (response.status !== 200) throw new Error('health request failed')
  const body = await response.json()
  if (body.status !== 'ok') throw new Error('health response was invalid')
})

Deno.test('app publishes an OpenAPI document', async () => {
  const response = await app.request('/doc')
  if (response.status !== 200) throw new Error('doc request failed')
  const body = await response.json()
  if (body.openapi !== '3.1.0') throw new Error('doc response was invalid')
})
