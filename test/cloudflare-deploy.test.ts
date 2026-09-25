// `erpc deploy --target cloudflare`. See Task Brief
// `2026-09-25-packet-erpc-cli-pr-b.md` Acceptance A9/A10/A12 and the
// "追加" bullets, plus N11/N12. A11 (sentinel leak) lives in
// `secrets-leak.test.ts`.
//
// wrangler is never real here: every scenario runs against a fake
// `ProcessRunner` (`command === 'fake-wrangler'`) that records every call and
// answers exactly the way wrangler 4.104.0 does for the subcommands this
// deploy path uses (design doc R1/R2/R6/R7).

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TarStream, type TarStreamInput } from '@std/tar'
import { afterEach, describe, expect, it } from './testing.ts'
import {
  type CloudflareWorkerManifest,
  deployToCloudflare,
  initializeApp,
  loadAnyErpcManifest,
  type ProcessRequest,
  type ProcessRunner,
  type PromptIO,
  runCli,
  sha256Hex,
  type TemplateRegistry,
} from '../src/index.ts'

const WORKER_BASE = 'https://test-app.example.workers.dev'
const ISSUER = 'https://issuer.example.test'
const TEMPLATE_OWNER = 'elsoul'
const TEMPLATE_REPO = 'fixture-template-repo'
const TEMPLATE_ASSET = 'erpc-template.tar.gz'
const TEMPLATE_TAG = 'v0.1.0'
const TEMPLATE_NAME = 'fixture-template'

const textEncoder = new TextEncoder()

const directories: string[] = []
const envToRestore = new Map<string, string | undefined>()

const temporaryDirectory = async (prefix: string): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), prefix))
  directories.push(directory)
  return directory
}

const setEnv = (name: string, value: string | undefined): void => {
  if (!envToRestore.has(name)) envToRestore.set(name, Deno.env.get(name))
  if (value === undefined) Deno.env.delete(name)
  else Deno.env.set(name, value)
}

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
  for (const [name, value] of envToRestore) {
    if (value === undefined) Deno.env.delete(name)
    else Deno.env.set(name, value)
  }
  envToRestore.clear()
})

// ---- tar fixture builder (mirrors test/template-init.test.ts's pattern) ----

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

// ---- fixture text builders ----

interface TemplateManifestOptions {
  readonly includeKv?: boolean
  readonly includePostDeploy?: boolean
  readonly includePreflight?: boolean
  readonly minWranglerVersion?: string
  readonly secretPrompts?: readonly Record<string, unknown>[]
}

const templateManifestJson = (options: TemplateManifestOptions = {}): string =>
  JSON.stringify({
    schemaVersion: 1,
    name: TEMPLATE_NAME,
    runtime: 'cloudflare-worker',
    minCliVersion: '0.1.0',
    cloudflare: {
      config: 'wrangler.toml',
      wrangler: ['fake-wrangler'],
      minWranglerVersion: options.minWranglerVersion ?? '4.0.0',
      ...(options.includeKv === false
        ? {}
        : { kv: [{ binding: 'MCP_KV', title: '{{app.name}}-mcp-kv' }] }),
      ...(options.includePreflight === false
        ? {}
        : { preflight: [['fake-preflight']] }),
    },
    render: [{ path: 'wrangler.toml', format: 'toml' }],
    prompts: options.secretPrompts ?? [
      {
        key: 'JWT_SECRET',
        target: 'secret-generate',
        bytes: 32,
        encoding: 'hex',
      },
    ],
    ...(options.includePostDeploy === false ? {} : {
      postDeploy: [
        {
          kind: 'http',
          baseUrlFromVar: 'MCP_SERVER_BASE_URL',
          path: '/health',
          expectStatus: 200,
        },
        {
          kind: 'oauth-authorize-redirect',
          baseUrlFromVar: 'MCP_SERVER_BASE_URL',
          issuerFromVar: 'APP_OIDC_ISSUER',
          followIssuer: true,
        },
      ],
    }),
  })

interface WranglerTomlOptions {
  readonly accountId?: string
  readonly includeKv?: boolean
  readonly requiredSecrets?: readonly string[]
}

const wranglerTomlText = (options: WranglerTomlOptions = {}): string => {
  const accountLine = `account_id = "${
    options.accountId ?? '{{erpc:cloudflare-account-id}}'
  }"`
  const kvBlock = options.includeKv === false
    ? ''
    : '\n[[kv_namespaces]]\nbinding = "MCP_KV"\nid = "{{erpc:kv-id:MCP_KV}}"\n'
  const required = options.requiredSecrets ?? ['JWT_SECRET']
  const requiredLine = required.map((name) => `"${name}"`).join(', ')
  return `name = "test-app"
main = "src/index.ts"
compatibility_date = "2026-01-01"
${accountLine}
${kvBlock}
[vars]
MCP_SERVER_BASE_URL = "${WORKER_BASE}"
APP_OIDC_ISSUER = "${ISSUER}"

[secrets]
required = [${requiredLine}]
`
}

const erpcTomlText = (sha256: string): string =>
  `schema_version = 1
name = "test-app"

[app]
runtime = "cloudflare-worker"
entrypoint = "src/index.ts"

[deploy]
target = "cloudflare"

[cloudflare]
config = "wrangler.toml"
wrangler = ["fake-wrangler"]

[template]
name = "${TEMPLATE_NAME}"
source = "github:${TEMPLATE_OWNER}/${TEMPLATE_REPO}"
ref = "${TEMPLATE_TAG}"
asset = "${TEMPLATE_ASSET}"
sha256 = "${sha256}"

[health]
timeout_seconds = 1
`

interface Project {
  readonly archive: Uint8Array
  readonly configPath: string
  readonly erpcHome: string
  readonly root: string
  readonly sha256: string
}

const setupProject = async (
  options: TemplateManifestOptions & WranglerTomlOptions = {},
): Promise<Project> => {
  const parent = await temporaryDirectory('erpc-cf-deploy-')
  const root = join(parent, 'app')
  const erpcHome = join(parent, '.erpc')
  await mkdir(root, { recursive: true })
  const wranglerToml = wranglerTomlText({
    accountId: options.accountId,
    includeKv: options.includeKv,
    requiredSecrets: options.requiredSecrets,
  })
  await writeFile(join(root, 'wrangler.toml'), wranglerToml, 'utf8')
  const archive = await tarGzFromInputs([
    fileInput('erpc-template.json', templateManifestJson(options)),
    fileInput('wrangler.toml', wranglerToml),
    fileInput(
      'src/index.ts',
      'export default { fetch: () => new Response("ok") }\n',
    ),
  ])
  const sha256 = await sha256Hex(archive)
  await writeFile(join(root, 'erpc.toml'), erpcTomlText(sha256), 'utf8')
  return {
    archive,
    configPath: join(root, 'erpc.toml'),
    erpcHome,
    root,
    sha256,
  }
}

const loadManifest = async (
  project: Project,
): Promise<CloudflareWorkerManifest> => {
  const manifest = await loadAnyErpcManifest(project.configPath)
  if (manifest.app.runtime !== 'cloudflare-worker') {
    throw new Error('fixture manifest was not a cloudflare-worker manifest')
  }
  return manifest as CloudflareWorkerManifest
}

// ---- fake wrangler ----

interface FakeWranglerOptions {
  readonly accounts?: readonly { readonly id: string; readonly name: string }[]
  readonly existingSecrets?: readonly string[]
  readonly whoamiOk?: boolean
  readonly workerExists?: boolean
}

const createFakeWrangler = (options: FakeWranglerOptions = {}) => {
  const calls: ProcessRequest[] = []
  const kvNamespaces: { id: string; title: string }[] = []
  const secrets = new Set(options.existingSecrets ?? [])
  const accounts = options.accounts ?? [{ id: 'acct-1', name: 'Test Account' }]
  let whoamiOk = options.whoamiOk ?? true
  let workerExists = options.workerExists ?? secrets.size > 0
  let nextKvId = 1

  const run: ProcessRunner = async (request) => {
    calls.push(request)
    if (request.command !== 'fake-wrangler') {
      return { code: 0, stderr: '', stdout: '' }
    }
    const [sub1, sub2, sub3, sub4] = request.args
    if (sub1 === '--version') {
      return { code: 0, stderr: '', stdout: '4.104.0\n' }
    }
    if (sub1 === 'whoami') {
      if (!whoamiOk) return { code: 1, stderr: 'not authenticated', stdout: '' }
      return {
        code: 0,
        stderr: '',
        stdout: JSON.stringify({ loggedIn: true, accounts }),
      }
    }
    if (sub1 === 'login') {
      whoamiOk = true
      return { code: 0, stderr: '', stdout: '' }
    }
    if (sub1 === 'kv' && sub2 === 'namespace' && sub3 === 'list') {
      return { code: 0, stderr: '', stdout: JSON.stringify(kvNamespaces) }
    }
    if (sub1 === 'kv' && sub2 === 'namespace' && sub3 === 'create') {
      const title = sub4 ?? ''
      const id = `kv-id-${nextKvId++}`
      kvNamespaces.push({ id, title })
      return {
        code: 0,
        stderr: '',
        stdout: `[[kv_namespaces]]\nbinding = "MCP_KV"\nid = "${id}"\n`,
      }
    }
    if (sub1 === 'secret' && sub2 === 'list') {
      if (!workerExists) {
        return {
          code: 1,
          stderr: '',
          stdout:
            'Worker "test-app" not found.\n\nIf this is a new Worker, run `wrangler deploy` first to create it.',
        }
      }
      return {
        code: 0,
        stderr: '',
        stdout: JSON.stringify(
          [...secrets].map((name) => ({ name, type: 'secret_text' })),
        ),
      }
    }
    if (sub1 === 'secret' && sub2 === 'put') {
      const name = sub3 ?? ''
      secrets.add(name)
      workerExists = true
      return { code: 0, stderr: '', stdout: `Success! Uploaded secret ${name}` }
    }
    if (sub1 === 'deploy') {
      return { code: 0, stderr: '', stdout: '' }
    }
    return {
      code: 1,
      stderr: `unhandled fake-wrangler args: ${request.args.join(' ')}`,
      stdout: '',
    }
  }

  return {
    run,
    calls,
    kvNamespaces,
    secrets,
    get workerExists() {
      return workerExists
    },
  }
}

const commandNames = (calls: readonly ProcessRequest[]): readonly string[] =>
  calls.map((call) =>
    call.command === 'fake-wrangler' ? call.args[0]! : call.command
  )

// ---- fetch stubs ----

const buildFetchStub = (
  archiveBytes: Uint8Array,
  probeFetch: typeof fetch,
): typeof fetch =>
  (async (input, init) => {
    const url = new URL(
      input instanceof Request ? input.url : String(input),
    )
    if (url.hostname === 'github.com') {
      return new Response(archiveBytes as unknown as BodyInit, { status: 200 })
    }
    return await probeFetch(input, init)
  }) as typeof fetch

const successProbeFetch: typeof fetch = (async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input))
  const method = init?.method ??
    (input instanceof Request ? input.method : 'GET')
  if (url.origin === WORKER_BASE && url.pathname === '/health') {
    return new Response(JSON.stringify({ ok: true }), { status: 200 })
  }
  if (url.origin === WORKER_BASE && url.pathname === '/oauth/register') {
    if (method !== 'POST') throw new Error('expected a POST to /oauth/register')
    return new Response(JSON.stringify({ client_id: 'client-abc' }), {
      status: 200,
    })
  }
  if (url.origin === WORKER_BASE && url.pathname === '/oauth/authorize') {
    return new Response(null, {
      status: 302,
      headers: { location: `${ISSUER}/oauth/authorize?forwarded=1` },
    })
  }
  if (url.origin === ISSUER && url.pathname === '/oauth/authorize') {
    return new Response(null, {
      status: 302,
      headers: { location: `${ISSUER}/oauth/consent?txn=abc123` },
    })
  }
  throw new Error(`unexpected probe fetch: ${method} ${url}`)
}) as typeof fetch

const brokerBadRedirectProbeFetch = (location: string): typeof fetch =>
  (async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input))
    if (url.origin === ISSUER && url.pathname === '/oauth/authorize') {
      return new Response(null, { status: 302, headers: { location } })
    }
    return await successProbeFetch(input, init)
  }) as typeof fetch

const brokerRejectsProbeFetch: typeof fetch = (async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input))
  if (url.origin === ISSUER && url.pathname === '/oauth/authorize') {
    return new Response('bad request', { status: 400 })
  }
  return await successProbeFetch(input, init)
}) as typeof fetch

// ---- promptIO / random doubles ----

const nonInteractivePromptIO = (): PromptIO => ({
  isInteractive: () => false,
  confirm: () => {
    throw new Error('confirm() should not be called in a non-interactive test')
  },
  text: () => {
    throw new Error('text() should not be called in a non-interactive test')
  },
  secret: () => {
    throw new Error('secret() should not be called in a non-interactive test')
  },
  select: () => {
    throw new Error('select() should not be called in a non-interactive test')
  },
})

const fixedRandom =
  (byte: number) => (bytes: Uint8Array<ArrayBuffer>): void => {
    bytes.fill(byte)
  }

const emptyRegistry: TemplateRegistry = {}
const pinnedRegistryFor = (sha256: string): TemplateRegistry => ({
  [TEMPLATE_NAME]: {
    source: {
      owner: TEMPLATE_OWNER,
      repo: TEMPLATE_REPO,
      asset: TEMPLATE_ASSET,
    },
    pins: { [TEMPLATE_TAG]: sha256 },
  },
})

// ---- tests ----

describe('erpc deploy --target cloudflare', () => {
  it('A9: --no-provision stops on a missing required secret without ever deploying', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      noProvision: true,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: emptyRegistry,
    })).rejects.toThrow('JWT_SECRET')

    expect(commandNames(fake.calls)).toEqual(['--version', 'whoami', 'secret'])
    expect(fake.calls.some((call) => call.args.includes('deploy'))).toBe(false)
    expect(fake.calls.some((call) => call.args[1] === 'put')).toBe(false)
    // N11: the fixture template is unpinned in `emptyRegistry`.
    expect(
      output.filter((line) => line.includes('will run with your permissions'))
        .length,
    ).toBe(1)
  })

  it('N11: a pinned template prints no trust warning', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      noProvision: true,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('JWT_SECRET')

    expect(
      output.filter((line) => line.includes('will run with your permissions'))
        .length,
    ).toBe(0)
  })

  it('A10: full provision -> deploy -> probe in order, then a second run is a no-op for KV/secret', async () => {
    const project = await setupProject()
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const probeCalls: string[] = []
    const probeFetch: typeof fetch = (async (input, init) => {
      probeCalls.push(
        `${init?.method ?? 'GET'} ${new URL(
          input instanceof Request ? input.url : String(input),
        )}`,
      )
      return await successProbeFetch(input, init)
    }) as typeof fetch
    const output: string[] = []

    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(7),
      run: fake.run,
      fetch: buildFetchStub(project.archive, probeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

    expect(commandNames(fake.calls)).toEqual([
      '--version',
      'whoami',
      'kv',
      'kv',
      'secret',
      'secret',
      'secret',
      'fake-preflight',
      'deploy',
    ])
    // whoami -> kv list -> kv create -> secret list -> secret put -> secret list (recheck)
    const secretCalls = fake.calls.filter((call) =>
      call.command === 'fake-wrangler' && call.args[0] === 'secret'
    )
    expect(secretCalls[1]?.args).toEqual(['secret', 'put', 'JWT_SECRET'])
    expect(secretCalls[1]?.input).toBeDefined()
    expect(secretCalls[1]?.display).toBe(false)
    // Probe never fetches consent or Google.
    expect(probeCalls.some((call) => call.includes('/oauth/consent'))).toBe(
      false,
    )
    expect(probeCalls.some((call) => call.includes('accounts.google.com')))
      .toBe(false)
    // /health (http probe) + /oauth/register + worker /oauth/authorize +
    // issuer /oauth/authorize (oauth-authorize-redirect probe).
    expect(probeCalls).toHaveLength(4)

    // A second run against the same fixture files: the account_id and KV
    // sentinels are already resolved on disk, and the secret already exists.
    fake.calls.splice(0, fake.calls.length)
    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(7),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })
    expect(commandNames(fake.calls)).toEqual([
      '--version',
      'whoami',
      'secret',
      'secret',
      'fake-preflight',
      'deploy',
    ])
    expect(fake.calls.some((call) => call.args[0] === 'kv')).toBe(false)
    expect(fake.calls.some((call) => call.args[1] === 'put')).toBe(false)
  })

  it('A12: a non-interactive secret-pipe backup with no --ack-backup runs nothing', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      requiredSecrets: [],
      secretPrompts: [
        {
          key: 'WALLET_MNEMONIC',
          target: 'secret-pipe',
          command: ['fake-pipe'],
          backup: { message: 'back this up', confirm: 'I HAVE BACKED IT UP' },
        },
      ],
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('--ack-backup')

    expect(fake.calls.some((call) => call.command === 'fake-pipe')).toBe(false)
    expect(fake.calls.some((call) => call.args[1] === 'put')).toBe(false)

    // With the ack, the same fixture proceeds (pipe runs, put runs).
    const fake2 = createFakeWrangler()
    await deployToCloudflare(manifest, {
      ackBackup: ['WALLET_MNEMONIC'],
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake2.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })
    expect(fake2.calls.some((call) => call.command === 'fake-pipe')).toBe(true)
    expect(
      fake2.calls.some((call) =>
        call.args[0] === 'secret' && call.args[1] === 'put' &&
        call.args[2] === 'WALLET_MNEMONIC'
      ),
    ).toBe(true)
  })

  it('secret-input: non-interactive, no env, required:false skips and continues', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      requiredSecrets: [],
      secretPrompts: [
        { key: 'OPTIONAL_TOKEN', target: 'secret-input', required: false },
      ],
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []

    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

    expect(fake.calls.some((call) => call.args[1] === 'put')).toBe(false)
    expect(output.some((line) => line.includes('OPTIONAL_TOKEN'))).toBe(true)
  })

  it('D3: CLOUDFLARE_API_TOKEN set + wrangler not authenticated stops without logging in', async () => {
    setEnv('CLOUDFLARE_API_TOKEN', 'token-value')
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler({ whoamiOk: false })

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('CLOUDFLARE_API_TOKEN')

    expect(fake.calls.some((call) => call.args[0] === 'login')).toBe(false)
  })

  it('D3: non-interactive with no token and no session stops without logging in', async () => {
    setEnv('CLOUDFLARE_API_TOKEN', undefined)
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler({ whoamiOk: false })

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('wrangler login')

    expect(fake.calls.some((call) => call.args[0] === 'login')).toBe(false)
  })

  it('D3: CLOUDFLARE_ACCOUNT_ID disagreeing with an already-resolved wrangler.toml stops', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      accountId: 'account-already-fixed',
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    setEnv('CLOUDFLARE_ACCOUNT_ID', 'a-different-account')

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      noProvision: true,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('does not match')
  })

  it('rejects --target cloudflare on a node/deno erpc.toml, and --node on a cloudflare-worker one', async () => {
    const parent = await temporaryDirectory('erpc-cf-deploy-mismatch-')
    const nodeApp = join(parent, 'node-app')
    await initializeApp({
      directory: nodeApp,
      runtime: 'node',
      name: 'node-app',
    })

    await expect(runCli(
      [
        'deploy',
        '--config',
        join(nodeApp, 'erpc.toml'),
        '--target',
        'cloudflare',
      ],
      { erpcHome: join(parent, '.erpc'), output: () => undefined },
    )).rejects.toThrow('--target')

    const cfProject = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    await expect(runCli(
      ['deploy', '--config', cfProject.configPath, '--node', 'primary'],
      { erpcHome: cfProject.erpcHome, output: () => undefined },
    )).rejects.toThrow('--node')
  })

  it('N12: WRANGLER_LOG_SANITIZE is forced true on every wrangler call even when the parent env disagrees', async () => {
    setEnv('WRANGLER_LOG_SANITIZE', 'false')
    const project = await setupProject()
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()

    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

    const wranglerCalls = fake.calls.filter((call) =>
      call.command === 'fake-wrangler'
    )
    expect(wranglerCalls.length > 0).toBe(true)
    for (const call of wranglerCalls) {
      expect(call.env?.WRANGLER_LOG_SANITIZE).toBe('true')
    }
    const putCall = wranglerCalls.find((call) => call.args[1] === 'put')
    expect(putCall?.env?.WRANGLER_LOG_SANITIZE).toBe('true')
  })

  it('D7: a worker 302 followed by the issuer 302ing to /oauth/consent passes', async () => {
    // Covered end-to-end by the A10 test above; this asserts the exact
    // Location shape once more in isolation via --verify-only.
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)
    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      verifyOnly: true,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })
  })

  it('D7: the issuer responding 400 (no Location) fails verification', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      verifyOnly: true,
      fetch: buildFetchStub(project.archive, brokerRejectsProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('verification failed')
  })

  it('D7: the issuer redirecting to Google fails verification', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      verifyOnly: true,
      fetch: buildFetchStub(
        project.archive,
        brokerBadRedirectProbeFetch(
          'https://accounts.google.com/o/oauth2/v2/auth',
        ),
      ),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('verification failed')
  })

  it('D7: the issuer redirecting to an unexpected path on its own origin fails verification', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      verifyOnly: true,
      fetch: buildFetchStub(
        project.archive,
        brokerBadRedirectProbeFetch(`${ISSUER}/other`),
      ),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('verification failed')
  })

  it('--dry-run reports a missing secret instead of stopping, skips provisioning, and runs `wrangler deploy --dry-run`', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []

    await deployToCloudflare(manifest, {
      dryRun: true,
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

    expect(commandNames(fake.calls)).toEqual([
      '--version',
      'whoami',
      'secret',
      'deploy',
    ])
    expect(fake.calls.at(-1)?.args).toEqual(['deploy', '--dry-run'])
    expect(output.some((line) => line.includes('Missing required'))).toBe(true)
  })
})
