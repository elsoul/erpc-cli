import { app } from './app.ts'

const hostname = Deno.env.get('HOST') ?? '0.0.0.0'
const port = Number.parseInt(Deno.env.get('PORT') ?? '8080', 10)
const controller = new AbortController()

console.log(`Listening on http://${hostname}:${port}`)
const server = Deno.serve({
  hostname,
  port,
  signal: controller.signal,
}, app.fetch)

const shutdown = () => controller.abort()
Deno.addSignalListener('SIGINT', shutdown)
Deno.addSignalListener('SIGTERM', shutdown)

await server.finished
