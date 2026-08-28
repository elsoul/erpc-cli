import { Hono } from 'hono'

export const app = new Hono()

app.get('/', (context) =>
  context.json({
    message: 'Hello from ERPC',
    success: true,
  }))

app.get('/health', (context) => context.json({ status: 'ok' }))

app.get('/doc', (context) =>
  context.json({
    info: { title: 'node-hono-example', version: '0.1.0' },
    openapi: '3.1.0',
    paths: {
      '/health': {
        get: {
          responses: { '200': { description: 'Application is healthy' } },
        },
      },
    },
  }))
