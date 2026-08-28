export const APP_RUNTIMES = ['node', 'deno'] as const
export type AppRuntime = (typeof APP_RUNTIMES)[number]

export interface AppTemplate {
  readonly files: Readonly<Record<string, string>>
  readonly installCommand: string
  readonly runtime: AppRuntime
  readonly startCommand: string
}

const erpcToml = (name: string, runtime: AppRuntime): string => {
  const isNode = runtime === 'node'
  return `schema_version = 1
name = "${name}"

[app]
runtime = "${runtime}"
entrypoint = "src/index.ts"

[build]
command = ["${isNode ? 'pnpm", "build' : 'deno", "task", "build:linux'}"]
artifact = "${isNode ? 'dist/index.js' : 'dist/erpc-app'}"

[run]
command = ["${isNode ? 'node", "dist/index.js' : './dist/erpc-app'}"]
host = "0.0.0.0"
port = 8080

[deploy]
target = "auto"

[health]
path = "/health"
timeout_seconds = 30
`
}

const nodeTemplate = (name: string): AppTemplate => ({
  runtime: 'node',
  installCommand: 'pnpm install',
  startCommand: 'pnpm dev',
  files: {
    '.gitignore': 'node_modules\ndist\n.env\n.env.*\n!.env.example\n',
    'erpc.toml': erpcToml(name, 'node'),
    'package.json': `${
      JSON.stringify(
        {
          name,
          version: '0.1.0',
          private: true,
          type: 'module',
          scripts: {
            build: 'tsup',
            check: 'tsc --noEmit',
            dev: 'tsx watch src/index.ts',
            start: 'node dist/index.js',
            test: 'vitest run',
          },
          dependencies: {
            '@hono/node-server': '^2.1.1',
            hono: '^4.13.5',
          },
          devDependencies: {
            '@types/node': '^26.4.0',
            tsup: '^8.5.1',
            tsx: '^4.23.12',
            typescript: '^7.0.2',
            vitest: '^4.1.11',
          },
          engines: { node: '>=20' },
          packageManager: 'pnpm@11.24.0',
        },
        null,
        2,
      )
    }\n`,
    'pnpm-workspace.yaml': `allowBuilds:
  esbuild: true
`,
    'src/app.ts': `import { Hono } from 'hono'

export const app = new Hono()

app.get('/', (context) =>
  context.json({
    message: 'Hello from ERPC',
    success: true,
  }))

app.get('/health', (context) => context.json({ status: 'ok' }))

app.get('/doc', (context) =>
  context.json({
    info: { title: '${name}', version: '0.1.0' },
    openapi: '3.1.0',
    paths: {
      '/health': {
        get: {
          responses: { '200': { description: 'Application is healthy' } },
        },
      },
    },
  }))
`,
    'src/index.ts': `import { serve } from '@hono/node-server'
import { app } from './app.js'

const hostname = process.env.HOST ?? '0.0.0.0'
const port = Number.parseInt(process.env.PORT ?? '8080', 10)

const server = serve({ fetch: app.fetch, hostname, port }, (info) => {
  console.log(\`Listening on http://\${hostname}:\${info.port}\`)
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
`,
    'test/app.test.ts': `import { describe, expect, it } from 'vitest'
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
`,
    'tsconfig.json': `${
      JSON.stringify(
        {
          compilerOptions: {
            target: 'ES2022',
            lib: ['ES2022'],
            module: 'NodeNext',
            moduleResolution: 'NodeNext',
            strict: true,
            noUncheckedIndexedAccess: true,
            exactOptionalPropertyTypes: true,
            noEmit: true,
            skipLibCheck: true,
            types: ['node'],
          },
          include: ['src', 'test', 'tsup.config.ts'],
        },
        null,
        2,
      )
    }\n`,
    'tsup.config.ts': `import { defineConfig } from 'tsup'

export default defineConfig({
  clean: true,
  entry: ['src/index.ts'],
  format: ['esm'],
  noExternal: ['@hono/node-server', 'hono'],
  outDir: 'dist',
  platform: 'node',
  sourcemap: true,
  target: 'node20',
})
`,
  },
})

const denoTemplate = (name: string): AppTemplate => ({
  runtime: 'deno',
  installCommand: 'deno task check',
  startCommand: 'deno task dev',
  files: {
    '.gitignore': 'dist\n.env\n.env.*\n!.env.example\n',
    'deno.json': `${
      JSON.stringify(
        {
          tasks: {
            build:
              'deno compile --allow-env=HOST,PORT --allow-net --output dist/erpc-app src/index.ts',
            'build:linux':
              'deno compile --target x86_64-unknown-linux-gnu --allow-env=HOST,PORT --allow-net --output dist/erpc-app src/index.ts',
            check: 'deno check src/index.ts test/app_test.ts',
            dev: 'deno run --allow-env --allow-net --watch src/index.ts',
            start: 'deno run --allow-env --allow-net src/index.ts',
            test: 'deno test --allow-env --allow-net',
          },
          imports: {
            hono: 'jsr:@hono/hono@^4.13.5',
          },
          compilerOptions: {
            strict: true,
            noUncheckedIndexedAccess: true,
            exactOptionalPropertyTypes: true,
          },
          fmt: {
            semiColons: false,
            singleQuote: true,
          },
        },
        null,
        2,
      )
    }\n`,
    'erpc.toml': erpcToml(name, 'deno'),
    'src/app.ts': `import { Hono } from 'hono'

export const app = new Hono()

app.get('/', (context) =>
  context.json({
    message: 'Hello from ERPC',
    success: true,
  }))

app.get('/health', (context) => context.json({ status: 'ok' }))

app.get('/doc', (context) =>
  context.json({
    info: { title: '${name}', version: '0.1.0' },
    openapi: '3.1.0',
    paths: {
      '/health': {
        get: {
          responses: { '200': { description: 'Application is healthy' } },
        },
      },
    },
  }))
`,
    'src/index.ts': `import { app } from './app.ts'

const hostname = Deno.env.get('HOST') ?? '0.0.0.0'
const port = Number.parseInt(Deno.env.get('PORT') ?? '8080', 10)
const controller = new AbortController()

console.log(\`Listening on http://\${hostname}:\${port}\`)
const server = Deno.serve({
  hostname,
  port,
  signal: controller.signal,
}, app.fetch)

const shutdown = () => controller.abort()
Deno.addSignalListener('SIGINT', shutdown)
Deno.addSignalListener('SIGTERM', shutdown)

await server.finished
`,
    'test/app_test.ts': `import { app } from '../src/app.ts'

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
`,
  },
})

export const createAppTemplate = (
  name: string,
  runtime: AppRuntime,
): AppTemplate => runtime === 'node' ? nodeTemplate(name) : denoTemplate(name)
