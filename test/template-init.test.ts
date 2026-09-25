import { chmod, mkdir, mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TarStream, type TarStreamInput } from '@std/tar'
import { parse as parseToml } from '@std/toml'
import { afterEach, describe, expect, it } from './testing.ts'
import { initializeTemplateApp } from '../src/app/template-init.ts'
import { sha256Hex } from '../src/app/template-fetch.ts'
import { tomlBasicString } from '../src/app/template-render.ts'
import { runCli } from '../src/cli.ts'
import type { PromptIO } from '../src/app/prompt-io.ts'
import type { TemplateRegistry } from '../src/app/template-registry.ts'
import type { OidcClientRegistrar } from '../src/app/template-init.ts'

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
  it('A5: generates a cloudflare-worker app from a pinned template', async () => {
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

  it('A4: rejects a checksum mismatch without touching disk or the cache', async () => {
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

  it('A6: rejects a path-traversal archive and writes nothing', async () => {
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

  it('A7: rejects an unresolved-placeholder manifest before prompting', async () => {
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

  it('A8: lists every missing non-interactive answer in one error and never prompts', async () => {
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
    expect(promptIO.callCount).toBe(0)
  })

  it('A8: rejects --set for a secret target key without prompting', async () => {
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

  it('A8: requires --trust-issuer for an unpinned template with a broker-register prompt', async () => {
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

  it('N11: prints the unpinned-template warning exactly once', async () => {
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

  it('N11: does not print the warning for a pinned template', async () => {
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

  it('B1: shows the client_id if writing fails after broker registration already succeeded', async () => {
    const archive = await buildFixtureArchive({ withBroker: true })
    const sha256 = await sha256Hex(archive)
    const parent = await temporaryDirectory('erpc-template-init-b1-')
    const unwritable = join(parent, 'unwritable')
    await mkdir(unwritable, { recursive: true })
    const directory = join(unwritable, 'app')
    const output: string[] = []
    let registrarCalls = 0
    const registrar: OidcClientRegistrar = {
      register: () => {
        registrarCalls++
        return Promise.resolve({ clientId: 'app_1234567890123456789012' })
      },
    }

    await chmod(unwritable, 0o500) // read + execute only: mkdir(directory) will fail with EACCES
    try {
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
        }),
      ).rejects.toThrow()
    } finally {
      await chmod(unwritable, 0o700) // let afterEach's rm clean up
    }

    expect(registrarCalls).toBe(1)
    const clientIdMessages = output.filter((message) =>
      message.includes('app_1234567890123456789012')
    )
    expect(clientIdMessages).toHaveLength(1)
    expect(clientIdMessages[0]).toContain('--set APP_OIDC_CLIENT_ID=')
  })

  it('B4: lists a missing var alongside an untrusted broker issuer in the same error', async () => {
    // A broker-register prompt whose redirectUris/clientName do not depend on
    // the missing var, so it reaches the trust check regardless of that
    // var's status (Decision 6 / Acceptance A8; steiner r1 B4, cyan r1 B3).
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
      render: [],
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

  it('B5: shows an interactive summary of derived values and deploy-time secrets', async () => {
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
})

describe('tomlBasicString', () => {
  it('escapes DEL (U+007F) and a newline (steiner r1 N3/M5)', () => {
    expect(tomlBasicString('a\u007fb\nc')).toBe('a\\u007fb\\nc')
  })
})

describe('CLI wiring', () => {
  it('forwards --template through cliffy to initializeTemplateApp (cyan r1 N13)', async () => {
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
})
