import { serve } from '@hono/node-server'
import { app } from './app.js'

const hostname = process.env.HOST ?? '0.0.0.0'
const port = Number.parseInt(process.env.PORT ?? '8080', 10)

const server = serve({ fetch: app.fetch, hostname, port }, (info) => {
  console.log(`Listening on http://${hostname}:${info.port}`)
})

let stopping = false
const shutdown = () => {
  if (stopping) return
  stopping = true
  server.close((error) => {
    if (error) {
      console.error('Graceful shutdown failed')
      process.exitCode = 1
    }
  })
}

process.once('SIGINT', shutdown)
process.once('SIGTERM', shutdown)
