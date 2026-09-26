import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TarStream, type TarStreamInput } from '@std/tar'
import { parse as parseToml } from '@std/toml'
import { afterEach, describe, expect, it } from './testing.ts'
import {
  initializeTemplateApp,
  unsupportedOidcClientRegistrar,
} from '../src/app/template-init.ts'
import { sha256Hex } from '../src/app/template-fetch.ts'
import { tomlBasicString } from '../src/app/template-render.ts'
import { defaultOpenExternal, runCli } from '../src/cli.ts'
import type { PromptIO } from '../src/app/prompt-io.ts'
import type { TemplateRegistry } from '../src/app/template-registry.ts'
import type {
  OidcClientRegistrar,
  WriteFileFunction,
} from '../src/app/template-init.ts'

const textEncoder = new TextEncoder()

const directories: string[] = []
const temporaryDirectory = async (prefix: string): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), prefix))
  directories.push(directory)
  return directory
}
afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
})

const concatBytes = (chunks: readonly Uint8Array[]): Uint8Array => {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

const tarGzFromInputs = async (
  inputs: readonly TarStreamInput[],
): Promise<Uint8Array> => {
  const chunks: Uint8Array[] = []
  const stream = ReadableStream.from([...inputs])
    .pipeThrough(new TarStream())
    .pipeThrough(
      new CompressionStream('gzip') as unknown as ReadableWritablePair<
        Uint8Array,
        Uint8Array
      >,
    )
  for await (const chunk of stream) chunks.push(chunk)
  return concatBytes(chunks)
}

const fileInput = (path: string, content: string): TarStreamInput => ({
  type: 'file',
  path,
  size: textEncoder.encode(content).byteLength,
  readable: ReadableStream.from([textEncoder.encode(content)]),
})

const WRANGLER_TOML = `name = "{{app.name}}"
main = "src/index.ts"
compatibility_date = "2026-01-01"
label = "{{LABEL}}"

[[kv_namespaces]]
binding = "MCP_KV"
id = "{{erpc:kv-id:MCP_KV}}"

[[routes]]
pattern = "{{domain}}"
custom_domain = true

[secrets]
required = ["JWT_SECRET"]
`

const manifestJson = (
  options: { readonly withBroker?: boolean } = {},
): string =>
  JSON.stringify({
    schemaVersion: 1,
    name: 'fixture-template',
    runtime: 'cloudflare-worker',
    minCliVersion: '0.1.0',
    cloudflare: {
      config: 'wrangler.toml',
      wrangler: ['pnpm', 'exec', 'wrangler'],
      kv: [{ binding: 'MCP_KV', title: '{{app.name}}-mcp-kv' }],
    },
    build: { command: ['pnpm', 'install', '--frozen-lockfile'] },
    ...(options.withBroker
      ? { broker: { issuer: 'https://broker.example.com' } }
      : {}),
    render: [{ path: 'wrangler.toml', format: 'toml' }],
    prompts: [
      {
        key: 'domain',
        target: 'var',
        flag: 'domain',
        question: 'Custom domain',
        validate: { pattern: '[a-z0-9.-]+' },
      },
      { key: 'LABEL', target: 'var', question: 'A free-text label' },
      {
        key: 'MCP_SERVER_BASE_URL',
        target: 'derived',
        expr: 'https://{{domain}}',
      },
      ...(options.withBroker
        ? [{
          key: 'APP_OIDC_CLIENT_ID',
          target: 'broker-register',
          redirectUris: ['https://{{domain}}/oauth/callback'],
          clientName: '{{app.name}}',
          validate: { pattern: 'app_[A-Za-z0-9_-]{22}' },
        }]
        : []),
      {
        key: 'JWT_SECRET',
        target: 'secret-generate',
        bytes: 32,
        encoding: 'base64url',
      },
    ],
  })

const buildFixtureArchive = async (
  options: { readonly withBroker?: boolean } = {},
): Promise<Uint8Array> =>
  await tarGzFromInputs([
    fileInput('erpc-template.json', manifestJson(options)),
    fileInput('wrangler.toml', WRANGLER_TOML),
    fileInput(
      'src/index.ts',
      'export default { fetch: () => new Response("ok") }\n',
    ),
  ])

const registryWith = (
  sha256: string,
  options: { readonly pinned?: boolean } = {},
): TemplateRegistry => ({
  'fixture-template': {
    source: {
      owner: 'elsoul',
      repo: 'fixture-template-repo',
      asset: 'erpc-template.tar.gz',
    },
    pins: options.pinned === false ? {} : { 'v0.1.0': sha256 },
  },
})

const fetchStubFor = (
  bytes: Uint8Array,
): { readonly calls: number; readonly fetch: typeof fetch } => {
  const state = { calls: 0 }
  const stub = (async () => {
    state.calls++
    return new Response(bytes as unknown as BodyInit, { status: 200 })
  }) as typeof fetch
  return {
    get calls() {
      return state.calls
    },
    fetch: stub,
  }
}

const spyPromptIO = (
  interactive: boolean,
): PromptIO & {
  readonly callCount: number
  readonly informed: readonly string[]
} => {
  let calls = 0
  const informed: string[] = []
  const count =
    <T extends unknown[], R>(fn: (...args: T) => R) => (...args: T): R => {
      calls++
      return fn(...args)
    }
  return {
    get callCount() {
      return calls
    },
    get informed() {
      return informed
    },
    isInteractive: () => interactive,
    // Valid-looking defaults: existing tests never reach a successful prompt
    // (they assert callCount===0), and new interactive-path tests need a
    // value that satisfies typical validate patterns without per-test setup.
    text: count(async () => 'stub-value'),
    confirm: count(async () => true),
    select: count(async () => ''),
    secret: count(async () => ''),
    inform: count((message: string) => {
      informed.push(message)
    }),
  }
}

const cacheEntries = async (erpcHome: string): Promise<readonly string[]> => {
  try {
    return await readdir(join(erpcHome, 'cache', 'templates'))
  } catch {
    return []
  }
}

const directoryIsMissingOrEmpty = async (
  directory: string,
): Promise<boolean> => {
  try {
    return (await readdir(directory)).length === 0
  } catch {
    return true
  }
}

describe('initializeTemplateApp', () => {
  it('generates a cloudflare-worker app from a pinned template', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-a5-')
    const directory = join(parent, 'app')
    const erpcHome = join(parent, '.erpc')
    const output: string[] = []

    const result = await initializeTemplateApp({
      directory,
      erpcHome,
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map([
        ['domain', 'example.com'],
        ['LABEL', 'inject" and \\ backslash'],
      ]),
      yes: true,
      output: (message) => output.push(message),
      fetch: fetchStubFor(archive).fetch,
    })

    expect(result.name).toBe('app')
    const erpcToml = await readFile(join(directory, 'erpc.toml'), 'utf8')
    expect(erpcToml).toContain('runtime = "cloudflare-worker"')
    expect(erpcToml).toContain('[template]')
    expect(erpcToml).toContain('name = "fixture-template"')
    expect(erpcToml).toContain('ref = "v0.1.0"')
    expect(erpcToml).toContain(`sha256 = "${sha256}"`)

    const wranglerToml = await readFile(
      join(directory, 'wrangler.toml'),
      'utf8',
    )
    const withoutSentinel = wranglerToml.replace('{{erpc:kv-id:MCP_KV}}', '')
    expect(withoutSentinel).not.toContain('{{')
    expect(wranglerToml).toContain('id = "{{erpc:kv-id:MCP_KV}}"')

    // The TOML-injection value round-trips through a real TOML parser.
    const parsed = parseToml(wranglerToml) as Record<string, unknown>
    expect(parsed.label).toBe('inject" and \\ backslash')
    expect(parsed.name).toBe('app')
  })

  it('rejects a checksum mismatch without touching disk or the cache', async () => {
    const archive = await buildFixtureArchive()
    const wrongSha256 = '0'.repeat(64)
    const parent = await temporaryDirectory('erpc-template-init-a4-')
    const directory = join(parent, 'app')
    const erpcHome = join(parent, '.erpc')

    await expect(
      initializeTemplateApp({
        directory,
        erpcHome,
        templateName: 'fixture-template',
        templateRegistry: registryWith(wrongSha256, { pinned: false }),
        tag: 'v0.1.0',
        sha256: wrongSha256,
        setValues: new Map(),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('checksum')

    expect(await directoryIsMissingOrEmpty(directory)).toBe(true)
    expect(await cacheEntries(erpcHome)).toEqual([])
  })

  it('rejects a path-traversal archive and writes nothing', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJson()),
      fileInput('wrangler.toml', WRANGLER_TOML),
      fileInput('../evil.txt', 'evil'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-a6-')
    const directory = join(parent, 'app')

    await expect(
      initializeTemplateApp({
        directory,
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow()

    expect(await directoryIsMissingOrEmpty(directory)).toBe(true)
  })

  it('rejects an unresolved-placeholder manifest before prompting', async () => {
    const brokenWrangler = WRANGLER_TOML.replace(
      '{{app.name}}',
      '{{totally_unknown}}',
    )
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJson()),
      fileInput('wrangler.toml', brokenWrangler),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-a7-')
    const directory = join(parent, 'app')
    const promptIO = spyPromptIO(true)

    await expect(
      initializeTemplateApp({
        directory,
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map(),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        promptIO,
      }),
    ).rejects.toThrow('L4')

    expect(promptIO.callCount).toBe(0)
    expect(await directoryIsMissingOrEmpty(directory)).toBe(true)
  })

  it('lists every missing non-interactive answer in one error and never prompts', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-a8-')
    const promptIO = spyPromptIO(false)

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map(),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        promptIO,
      }),
    ).rejects.toThrow('domain')

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app2'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map(),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        promptIO,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).toContain('domain')
    expect(message).toContain('LABEL')
    expect(message).toContain('--set')
    // The `derived` key that depends on the missing `domain` fails to
    // interpolate too - it must add its own issue instead of resolving
    // silently.
    expect(message).toContain('MCP_SERVER_BASE_URL')
    expect(message).toContain('could not be derived')
    expect(promptIO.callCount).toBe(0)
  })

  it('rejects --set for a secret target key without prompting', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-a8-secret-')
    const promptIO = spyPromptIO(false)

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([
          ['domain', 'example.com'],
          ['LABEL', 'x'],
          ['JWT_SECRET', 'not-allowed'],
        ]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        promptIO,
      }),
    ).rejects.toThrow('JWT_SECRET')
    expect(promptIO.callCount).toBe(0)
  })

  it('requires --trust-issuer for an unpinned template with a broker-register prompt', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-a8-trust-')

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256, { pinned: false }),
        tag: 'v0.1.0',
        sha256,
        setValues: new Map([
          ['domain', 'example.com'],
          ['LABEL', 'x'],
          ['APP_OIDC_CLIENT_ID', 'app_1234567890123456789012'],
        ]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('not trusted')
  })

  it('rejects with the broker-register stub message and writes nothing', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-broker-stub-')
    const directory = join(parent, 'app')

    await expect(
      initializeTemplateApp({
        directory,
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: unsupportedOidcClientRegistrar,
      }),
    ).rejects.toThrow(
      'Broker registration is not available in this CLI version',
    )

    expect(await directoryIsMissingOrEmpty(directory)).toBe(true)
  })

  it('uses --set APP_OIDC_CLIENT_ID without calling the registrar', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-broker-set-')
    const directory = join(parent, 'app')
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'should-not-be-used' })
      },
    }

    const result = await initializeTemplateApp({
      directory,
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map([
        ['domain', 'example.com'],
        ['LABEL', 'x'],
        ['APP_OIDC_CLIENT_ID', 'app_1234567890123456789012'],
      ]),
      yes: true,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
      oidcRegistrar: registrar,
    })

    expect(registrarCalls).toBe(0)
    const erpcToml = await readFile(join(directory, 'erpc.toml'), 'utf8')
    expect(erpcToml).toContain('[oidc]')
    expect(erpcToml).toContain('client_id = "app_1234567890123456789012"')
    expect(result.name).toBe('app')
  })

  it('prints the unpinned-template warning exactly once', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-n11-unpinned-')
    const output: string[] = []

    await initializeTemplateApp({
      directory: join(parent, 'app'),
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256, { pinned: false }),
      tag: 'v0.1.0',
      sha256,
      setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
      yes: true,
      output: (message) => output.push(message),
      fetch: fetchStubFor(archive).fetch,
    })

    const warnings = output.filter((message) =>
      message.includes('with your permissions')
    )
    expect(warnings).toHaveLength(1)
  })

  it('does not print the warning for a pinned template', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-n11-pinned-')
    const output: string[] = []

    await initializeTemplateApp({
      directory: join(parent, 'app'),
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
      yes: true,
      output: (message) => output.push(message),
      fetch: fetchStubFor(archive).fetch,
    })

    const warnings = output.filter((message) =>
      message.includes('with your permissions')
    )
    expect(warnings).toHaveLength(0)
  })

  it('never overwrites a non-empty target directory', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-nonempty-')
    const directory = join(parent, 'app')
    await Deno.mkdir(directory, { recursive: true })
    await Deno.writeTextFile(join(directory, 'keep.txt'), 'keep me')

    await expect(
      initializeTemplateApp({
        directory,
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('non-empty directory')
    expect(await readFile(join(directory, 'keep.txt'), 'utf8')).toBe('keep me')
  })

  it('shows the client_id if writing fails after broker registration already succeeded', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b1-')
    const directory = join(parent, 'app')
    const output: string[] = []
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }
    // An injected write failure rather than a chmod'd read-only directory:
    // running as root (which ignores permission bits) would otherwise make
    // this test flaky.
    const failingWriteFile: WriteFileFunction = () => {
      throw new Error('injected write failure')
    }

    await expect(
      initializeTemplateApp({
        directory,
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256), // pinned: trust is automatic
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: (message) => output.push(message),
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
        writeFile: failingWriteFile,
      }),
    ).rejects.toThrow('injected write failure')

    expect(registrarCalls).toBe(1)
    const clientIdMessages = output.filter((message) =>
      message.includes('app_1234567890123456789012')
    )
    expect(clientIdMessages).toHaveLength(1)
    expect(clientIdMessages[0]).toContain('--set APP_OIDC_CLIENT_ID=')
  })

  it('names the actual broker-register key (not a hardcoded one) in the recovery guidance', async () => {
    // A manifest is free to name its broker-register prompt anything that
    // matches the key pattern (L1); the recovery guidance after a later
    // write failure must use that same name, not assume it is always
    // "APP_OIDC_CLIENT_ID".
    const manifestJsonText = JSON.stringify({
      schemaVersion: 1,
      name: 'fixture-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: {
        config: 'wrangler.toml',
        wrangler: ['pnpm', 'exec', 'wrangler'],
      },
      broker: { issuer: 'https://broker.example.com' },
      render: [{ path: 'wrangler.toml', format: 'text' }],
      prompts: [{
        key: 'OIDC_ID',
        target: 'broker-register',
        redirectUris: ['https://example.com/callback'],
        clientName: '{{app.name}}',
      }],
    })
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJsonText),
      fileInput('wrangler.toml', 'name = "{{app.name}}"\n'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-recovery-key-',
    )
    const output: string[] = []
    const registrar: OidcClientRegistrar = {
      register: () =>
        Promise.resolve({ clientId: 'app_1234567890123456789012' }),
    }
    const failingWriteFile: WriteFileFunction = () => {
      throw new Error('injected write failure')
    }

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map(),
        yes: true,
        output: (message) => output.push(message),
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
        writeFile: failingWriteFile,
      }),
    ).rejects.toThrow('injected write failure')

    const clientIdMessages = output.filter((message) =>
      message.includes('app_1234567890123456789012')
    )
    expect(clientIdMessages).toHaveLength(1)
    expect(clientIdMessages[0]).toContain('--set OIDC_ID=')
    expect(clientIdMessages[0]).not.toContain('APP_OIDC_CLIENT_ID')
  })

  it('shows the client_id if *rendering* fails after broker registration already succeeded', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b3-render-')
    const output: string[] = []
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: (message) => output.push(message),
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
        renderTemplateFiles: () => {
          throw new Error('injected render failure')
        },
      }),
    ).rejects.toThrow('injected render failure')

    expect(registrarCalls).toBe(1)
    const clientIdMessages = output.filter((message) =>
      message.includes('app_1234567890123456789012')
    )
    expect(clientIdMessages).toHaveLength(1)
  })

  it('does not call the registrar when a var declared after broker-register is missing', async () => {
    const manifestJsonText = JSON.stringify({
      schemaVersion: 1,
      name: 'fixture-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: {
        config: 'wrangler.toml',
        wrangler: ['pnpm', 'exec', 'wrangler'],
      },
      broker: { issuer: 'https://broker.example.com' },
      render: [{ path: 'wrangler.toml', format: 'text' }],
      prompts: [
        {
          key: 'APP_OIDC_CLIENT_ID',
          target: 'broker-register',
          redirectUris: ['https://example.com/callback'],
          clientName: '{{app.name}}',
        },
        // Declared AFTER broker-register: with the registration call
        // deferred to a single pass over the whole manifest, this missing
        // answer must still prevent the registrar from ever being called.
        { key: 'LATER_REQUIRED', target: 'var', question: 'A later value' },
      ],
    })
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJsonText),
      fileInput('wrangler.toml', 'name = "{{app.name}}"\n'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b3-later-')
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256), // pinned: trust is automatic
        tag: 'v0.1.0',
        setValues: new Map(), // LATER_REQUIRED missing
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).toContain('LATER_REQUIRED')
    expect(registrarCalls).toBe(0)
  })

  it('lists only the missing var, not a raw interpolation error, when a valid --set redirectUris-dependent var is missing', async () => {
    // A minimal manifest (no `derived` prompt) so the only possible issue is
    // the missing `domain` var itself: `redirectUris` depends on `{{domain}}`,
    // but `--set` never needs `redirectUris` to resolve, so a valid --set
    // value must not surface `Cannot resolve {{domain}}` as a second, raw
    // error alongside the clean "missing value" one.
    const manifestJsonText = JSON.stringify({
      schemaVersion: 1,
      name: 'fixture-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: {
        config: 'wrangler.toml',
        wrangler: ['pnpm', 'exec', 'wrangler'],
      },
      broker: { issuer: 'https://broker.example.com' },
      render: [{ path: 'wrangler.toml', format: 'text' }],
      prompts: [
        {
          key: 'domain',
          target: 'var',
          flag: 'domain',
          question: 'Custom domain',
        },
        {
          key: 'APP_OIDC_CLIENT_ID',
          target: 'broker-register',
          redirectUris: ['https://{{domain}}/oauth/callback'],
          clientName: '{{app.name}}',
          validate: { pattern: 'app_[A-Za-z0-9_-]{22}' },
        },
      ],
    })
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJsonText),
      fileInput('wrangler.toml', 'name = "{{app.name}}"\n'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-mx9-')
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256), // pinned: trust is automatic
        tag: 'v0.1.0',
        setValues: new Map([[
          'APP_OIDC_CLIENT_ID',
          'app_1234567890123456789012',
        ]]), // domain missing; --set is correctly formatted
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).toContain('domain: missing value')
    expect(message).not.toContain('Cannot resolve')
    expect(registrarCalls).toBe(0)
  })

  it('lists a missing var alongside an untrusted broker issuer in the same error', async () => {
    // A broker-register prompt whose redirectUris/clientName do not depend on
    // the missing var, so it reaches the trust check regardless of that
    // var's status.
    const manifestJsonText = JSON.stringify({
      schemaVersion: 1,
      name: 'fixture-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: {
        config: 'wrangler.toml',
        wrangler: ['pnpm', 'exec', 'wrangler'],
      },
      broker: { issuer: 'https://broker.example.com' },
      render: [{ path: 'wrangler.toml', format: 'text' }],
      prompts: [
        { key: 'REQUIRED_LABEL', target: 'var', question: 'A label' },
        {
          key: 'APP_OIDC_CLIENT_ID',
          target: 'broker-register',
          redirectUris: ['https://example.com/callback'],
          clientName: '{{app.name}}',
        },
      ],
    })
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJsonText),
      fileInput('wrangler.toml', 'name = "{{app.name}}"\n'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b4-')

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256, { pinned: false }),
        tag: 'v0.1.0',
        sha256,
        setValues: new Map(), // REQUIRED_LABEL missing; no --trust-issuer
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).toContain('REQUIRED_LABEL')
    expect(message).toContain('not trusted')
  })

  it('shows the registrar-returned value when it does not match the required pattern, with an upstream-creation note', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-registrar-invalid-',
    )
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'not-app-format' })
      },
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256), // pinned: trust is automatic
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    // The registrar *was* called - show the value it returned rather than
    // only saying "invalid", and distinguish this
    // wording from the --set path's own message.
    expect(registrarCalls).toBe(1)
    expect(message).toContain('"not-app-format"')
    expect(message).toContain("registrar's response")
    expect(message).toContain('does not match the required pattern')
    expect(message).toContain('--set APP_OIDC_CLIENT_ID=')
    // A client may already exist upstream even though this response is
    // unusable, and retrying with the same value via --set will not help.
    expect(message).toContain('already have been created upstream')
    expect(message).toContain('will not help')
  })

  it('shows a shape-violation wording, not a pattern-mismatch wording, for a too-long registrar response', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-registrar-shape-',
    )
    const tooLong = 'a'.repeat(600)
    const registrar: OidcClientRegistrar = {
      register: () => Promise.resolve({ clientId: tooLong }),
    }

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      }),
    ).rejects.toThrow('exceeds 512 characters')
  })

  it('escapes a control character in a registrar-returned value instead of showing it raw or fully hiding it', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-registrar-escape-',
    )
    const badValue = 'app_bad\x01value1234567890'
    const registrar: OidcClientRegistrar = {
      register: () => Promise.resolve({ clientId: badValue }),
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    // No longer redacted wholesale: the readable part stays visible and only
    // the control character itself is escaped.
    expect(message).not.toContain(badValue)
    expect(message).not.toContain('redacted')
    expect(message).toContain('app_bad')
    expect(message).toContain('value1234567890')
    expect(message).toContain('\\u0001')
  })

  it('escapes a C1 control character and a bidi override in a registrar-returned value', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-registrar-c1bidi-',
    )
    // U+009B (a C1 control) and U+202E (right-to-left override): neither is
    // matched by the answer-side `CONTROL_CHARACTER_PATTERN` (C0 + DEL
    // only), so a plain `JSON.stringify` would print both of these raw.
    const badValue = `app_\u009b‮value1234567890`
    const registrar: OidcClientRegistrar = {
      register: () => Promise.resolve({ clientId: badValue }),
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).not.toContain(badValue)
    expect(message).not.toContain('\u009b')
    expect(message).not.toContain('‮')
    expect(message).toContain('\\u009b')
    expect(message).toContain('\\u202e')
  })

  it('trims a trailing newline from a registrar-returned value before displaying it', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-registrar-trailing-newline-',
    )
    // Otherwise a valid-looking id, plus wire noise many APIs/CLIs emit.
    const withTrailingNewline = 'app_1234567890123456789012\n'
    const registrar: OidcClientRegistrar = {
      register: () => Promise.resolve({ clientId: withTrailingNewline }),
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    // The trailing newline is what made this a control-character shape
    // issue in the first place; once trimmed for display, the id itself
    // reads cleanly with no `\n` escape cluttering it.
    expect(message).toContain('"app_1234567890123456789012"')
    expect(message).not.toContain('\\n')
  })

  it('truncates a very long registrar-returned value in the error message', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-registrar-truncate-',
    )
    const veryLong = 'a'.repeat(2000)
    const registrar: OidcClientRegistrar = {
      register: () => Promise.resolve({ clientId: veryLong }),
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        oidcRegistrar: registrar,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    // A 2000-character value must not appear in full: this is the shape
    // path (exceeds 512 characters), so the display cap matters for the
    // "registrar response: ..." fragment specifically, not the whole error.
    expect(message).toContain('exceeds 512 characters')
    expect(message.length < 2000).toBe(true)
  })

  it('shows an interactive summary of derived values and deploy-time secrets', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b5-')
    const promptIO = spyPromptIO(true)

    await initializeTemplateApp({
      directory: join(parent, 'app'),
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map(),
      yes: false,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
      promptIO,
    })

    expect(promptIO.informed).toHaveLength(1)
    expect(promptIO.informed[0]).toContain('MCP_SERVER_BASE_URL')
    expect(promptIO.informed[0]).toContain('JWT_SECRET')
  })

  it('distinguishes a secret-input prompt from a generated secret in the interactive summary', async () => {
    // `buildFixtureArchive` has no `secret-input` prompt (only
    // `secret-generate`), so its summary never exercises the "prompted for"
    // branch of `summaryText` - a bespoke manifest is needed to reach it.
    const manifestJsonText = JSON.stringify({
      schemaVersion: 1,
      name: 'fixture-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: {
        config: 'wrangler.toml',
        wrangler: ['pnpm', 'exec', 'wrangler'],
      },
      render: [{ path: 'wrangler.toml', format: 'text' }],
      prompts: [
        {
          key: 'JWT_SECRET',
          target: 'secret-generate',
          bytes: 32,
          encoding: 'base64url',
        },
        {
          key: 'THIRD_PARTY_API_KEY',
          target: 'secret-input',
          question: 'Third-party API key',
        },
      ],
    })
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJsonText),
      fileInput('wrangler.toml', 'name = "{{app.name}}"\n'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b5-input-')
    const promptIO = spyPromptIO(true)

    await initializeTemplateApp({
      directory: join(parent, 'app'),
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map(),
      yes: false,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
      promptIO,
    })

    expect(promptIO.informed).toHaveLength(1)
    const summary = promptIO.informed[0]!
    expect(summary).toContain("Secrets generated during 'erpc deploy'")
    expect(summary).toContain('JWT_SECRET')
    expect(summary).toContain("Secrets prompted for during 'erpc deploy'")
    expect(summary).toContain('THIRD_PARTY_API_KEY')
    // Each key must appear only under its own heading, not both.
    const generatedLine = summary.split('\n').find((line) =>
      line.includes("generated during 'erpc deploy'")
    )!
    const promptedLine = summary.split('\n').find((line) =>
      line.includes("prompted for during 'erpc deploy'")
    )!
    expect(generatedLine).not.toContain('THIRD_PARTY_API_KEY')
    expect(promptedLine).not.toContain('JWT_SECRET')
  })

  it('shows the interactive summary before calling the registrar, not after', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-order-')
    const events: string[] = []
    const promptIO: PromptIO = {
      isInteractive: () => true,
      text: () => Promise.resolve('stub-value'),
      confirm: () => Promise.resolve(true),
      select: () => Promise.resolve(''),
      secret: () => Promise.resolve(''),
      inform: () => {
        events.push('summary')
      },
    }
    const registrar: OidcClientRegistrar = {
      register: () => {
        events.push('registrar')
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    await initializeTemplateApp({
      directory: join(parent, 'app'),
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map(),
      yes: false,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
      promptIO,
      oidcRegistrar: registrar,
    })

    // A mutant that moves `onAnswersReady` to after the broker-register
    // block (or drops the "single pass after every var/derived" ordering)
    // would flip this to ['registrar', 'summary'].
    expect(events).toEqual(['summary', 'registrar'])
  })

  it('does not show the summary non-interactively', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-init-b5-noninteractive-',
    )
    const promptIO = spyPromptIO(false)

    await initializeTemplateApp({
      directory: join(parent, 'app'),
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
      yes: true,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
      promptIO,
    })

    expect(promptIO.informed).toHaveLength(0)
  })

  it('lists a missing domain alongside an untrusted broker issuer when redirectUris depends on {{domain}}', async () => {
    // Unlike the "lists a missing var alongside an untrusted broker issuer"
    // fixture above, this uses the real shape (redirectUris:
    // ["https://{{domain}}/oauth/callback"]) so the trust check must run
    // even though interpolating redirectUris would otherwise fail for the
    // same reason domain is missing.
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b2-1-')

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256, { pinned: false }),
        tag: 'v0.1.0',
        sha256,
        setValues: new Map([['LABEL', 'x']]), // domain missing; no --trust-issuer
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).toContain('domain')
    expect(message).toContain('not trusted')
  })

  it('lists an invalid --set client_id alongside a missing key in the same error', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b2-2-')

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256), // pinned: trust is automatic
        tag: 'v0.1.0',
        setValues: new Map([
          ['domain', 'example.com'],
          // LABEL intentionally omitted -> missing.
          ['APP_OIDC_CLIENT_ID', 'not-a-valid-client-id'],
        ]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    expect(message).toContain('LABEL')
    expect(message).toContain('APP_OIDC_CLIENT_ID')
  })

  it('lists an untrusted issuer alongside an invalid --set client_id in the same error', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-x1b-')

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        // Unpinned and no --trust-issuer: the issuer is not trusted.
        templateRegistry: registryWith(sha256, { pinned: false }),
        tag: 'v0.1.0',
        sha256,
        setValues: new Map([
          ['domain', 'example.com'],
          ['LABEL', 'x'],
          ['APP_OIDC_CLIENT_ID', 'not-a-valid-client-id'],
        ]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    // Both issues must land in the same aggregated error: an untrusted
    // issuer must not suppress the independent --set format check, and vice
    // versa.
    expect(message).toContain('not trusted')
    expect(message).toContain('--set APP_OIDC_CLIENT_ID=')
    expect(message).toContain('does not match the required pattern')
  })

  it('does not prompt for issuer trust interactively when --set is already invalid', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-x1k-')
    let confirmCalls = 0
    const promptIO: PromptIO = {
      isInteractive: () => true,
      text: () => {
        throw new Error('text should not be called: every var is set')
      },
      confirm: () => {
        confirmCalls++
        return Promise.resolve(true)
      },
      select: () => Promise.resolve(''),
      secret: () => Promise.resolve(''),
      inform: () => {},
    }

    let observed: unknown
    try {
      await initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        // Unpinned and no --trust-issuer: this would otherwise prompt
        // interactively for issuer trust.
        templateRegistry: registryWith(sha256, { pinned: false }),
        tag: 'v0.1.0',
        sha256,
        setValues: new Map([
          ['domain', 'example.com'],
          ['LABEL', 'x'],
          ['APP_OIDC_CLIENT_ID', 'not-a-valid-client-id'],
        ]),
        yes: false,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
        promptIO,
      })
    } catch (error) {
      observed = error
    }
    const message = observed instanceof Error
      ? observed.message
      : String(observed)
    // The run is doomed by the invalid --set regardless of the trust
    // answer, so the (interactive) trust confirm must never fire.
    expect(confirmCalls).toBe(0)
    expect(message).toContain('does not match the required pattern')
  })

  it('does not claim registration "already succeeded" when the client_id came from --set', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-p8-')
    const output: string[] = []
    const failingWriteFile: WriteFileFunction = () => {
      throw new Error('injected write failure')
    }

    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([
          ['domain', 'example.com'],
          ['LABEL', 'x'],
          ['APP_OIDC_CLIENT_ID', 'app_1234567890123456789012'],
        ]),
        yes: true,
        output: (message) => output.push(message),
        fetch: fetchStubFor(archive).fetch,
        writeFile: failingWriteFile,
      }),
    ).rejects.toThrow('injected write failure')

    expect(output.some((message) => message.includes('already succeeded')))
      .toBe(
        false,
      )
  })

  it('rejects an answer containing a line feed', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-lf-')
    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'a\nb']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('control character')
  })

  it('rejects an answer containing a carriage return', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-cr-')
    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'a\rb']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('control character')
  })

  it('rejects an answer containing a tab', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-tab-')
    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'a\tb']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('control character')
  })

  it('rejects an answer containing DEL (U+007F)', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-del-')
    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([['domain', 'example.com'], ['LABEL', 'a\u007fb']]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('control character')
  })

  it('rejects an answer containing "{{"', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-brace-')
    await expect(
      initializeTemplateApp({
        directory: join(parent, 'app'),
        erpcHome: join(parent, '.erpc'),
        templateName: 'fixture-template',
        templateRegistry: registryWith(sha256),
        tag: 'v0.1.0',
        setValues: new Map([
          ['domain', 'example.com'],
          ['LABEL', 'a {{erpc:kv-id:MCP_KV}} b'],
        ]),
        yes: true,
        output: () => {},
        fetch: fetchStubFor(archive).fetch,
      }),
    ).rejects.toThrow('{{')
  })

  it('does not misinterpret a literal ".." at the start of a filename as a path escape', async () => {
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJson()),
      fileInput('wrangler.toml', WRANGLER_TOML),
      fileInput('..hidden', 'not a traversal, just an odd filename\n'),
    ])
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-dotdot-name-')
    const directory = join(parent, 'app')

    const result = await initializeTemplateApp({
      directory,
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registryWith(sha256),
      tag: 'v0.1.0',
      setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
      yes: true,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
    })

    expect(result.files).toContain('..hidden')
    expect(await readFile(join(directory, '..hidden'), 'utf8')).toBe(
      'not a traversal, just an odd filename\n',
    )
  })

  it('escapes DEL (U+007F) in erpc.toml through tomlBasicString, not JSON.stringify', async () => {
    const archive = await buildFixtureArchive()
    // A registry-controlled field (not user input) carrying a byte
    // JSON.stringify would leave unescaped, to prove erpc.toml's [template]
    // fields go through tomlBasicString rather than JSON.stringify.
    const oddAsset = 'erpc-template\u007f.tar.gz'
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-del-asset-')
    const directory = join(parent, 'app')
    const registry: TemplateRegistry = {
      'fixture-template': {
        source: {
          owner: 'elsoul',
          repo: 'fixture-template-repo',
          asset: oddAsset,
        },
        pins: { 'v0.1.0': sha256 },
      },
    }

    await initializeTemplateApp({
      directory,
      erpcHome: join(parent, '.erpc'),
      templateName: 'fixture-template',
      templateRegistry: registry,
      tag: 'v0.1.0',
      setValues: new Map([['domain', 'example.com'], ['LABEL', 'x']]),
      yes: true,
      output: () => {},
      fetch: fetchStubFor(archive).fetch,
    })

    const erpcToml = await readFile(join(directory, 'erpc.toml'), 'utf8')
    expect(erpcToml).toContain('asset = "erpc-template\\u007f.tar.gz"')
    expect(erpcToml.includes('\u007f')).toBe(false) // the raw byte must not appear unescaped
  })
})

describe('tomlBasicString', () => {
  it('escapes DEL (U+007F) and a newline', () => {
    expect(tomlBasicString('a\u007fb\nc')).toBe('a\\u007fb\\nc')
  })
})

describe('CLI wiring', () => {
  it('forwards --template through cliffy to initializeTemplateApp', async () => {
    const archive = await buildFixtureArchive()
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-cli-wiring-')
    const directory = join(parent, 'app')
    const output: string[] = []

    await expect(
      runCli(
        [
          'app',
          'init',
          directory,
          '--template',
          'fixture-template@v0.1.0',
          '--set',
          'domain=example.com',
          '--set',
          'LABEL=x',
          '--yes',
        ],
        {
          erpcHome: join(parent, '.erpc'),
          templateRegistry: registryWith(sha256),
          fetch: fetchStubFor(archive).fetch,
          output: (message) => output.push(message),
        },
      ),
    ).resolves.toBe(0)

    expect(await readFile(join(directory, 'erpc.toml'), 'utf8')).toContain(
      'runtime = "cloudflare-worker"',
    )
  })

  it('wires an injected openExternal through to the registrar', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-cli-openexternal-')
    const directory = join(parent, 'app')
    const opened: string[] = []
    const registrar: OidcClientRegistrar = {
      register: (_request, io) => {
        io.openExternal?.('https://broker.example.com/verify')
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    await expect(
      runCli(
        [
          'app',
          'init',
          directory,
          '--template',
          'fixture-template@v0.1.0',
          '--set',
          'domain=example.com',
          '--set',
          'LABEL=x',
          '--yes',
        ],
        {
          erpcHome: join(parent, '.erpc'),
          templateRegistry: registryWith(sha256),
          fetch: fetchStubFor(archive).fetch,
          output: () => {},
          oidcRegistrar: registrar,
          openExternal: (url) => opened.push(url),
        },
      ),
    ).resolves.toBe(0)

    expect(opened).toEqual(['https://broker.example.com/verify'])
  })

  it('wires a default openExternal through to the registrar when none is injected', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory(
      'erpc-template-cli-openexternal-default-',
    )
    const directory = join(parent, 'app')
    let capturedOpenExternal: ((url: string) => void) | undefined
    const registrar: OidcClientRegistrar = {
      register: (_request, io) => {
        capturedOpenExternal = io.openExternal
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    await expect(
      runCli(
        [
          'app',
          'init',
          directory,
          '--template',
          'fixture-template@v0.1.0',
          '--set',
          'domain=example.com',
          '--set',
          'LABEL=x',
          '--yes',
        ],
        {
          erpcHome: join(parent, '.erpc'),
          templateRegistry: registryWith(sha256),
          fetch: fetchStubFor(archive).fetch,
          output: () => {},
          oidcRegistrar: registrar,
          // openExternal intentionally not injected: cli.ts must fall back
          // to its own real-launcher default instead of leaving this
          // undefined (a production run would then never actually open the
          // broker's verification URL in a browser).
        },
      ),
    ).resolves.toBe(0)

    expect(capturedOpenExternal).toBe(defaultOpenExternal)
  })

  it('forwards an injected signal through to the registrar', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-cli-signal-')
    const directory = join(parent, 'app')
    const controller = new AbortController()
    let capturedSignal: AbortSignal | undefined
    const registrar: OidcClientRegistrar = {
      register: (_request, io) => {
        capturedSignal = io.signal
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    await expect(
      runCli(
        [
          'app',
          'init',
          directory,
          '--template',
          'fixture-template@v0.1.0',
          '--set',
          'domain=example.com',
          '--set',
          'LABEL=x',
          '--yes',
        ],
        {
          erpcHome: join(parent, '.erpc'),
          templateRegistry: registryWith(sha256),
          fetch: fetchStubFor(archive).fetch,
          output: () => {},
          oidcRegistrar: registrar,
          signal: controller.signal,
        },
      ),
    ).resolves.toBe(0)

    expect(capturedSignal).toBe(controller.signal)
  })
})
