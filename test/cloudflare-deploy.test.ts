// `erpc deploy --target cloudflare`. The secret-value leak checks live in
// `secrets-leak.test.ts`.
//
// wrangler is never real here: every scenario runs against a fake
// `ProcessRunner` (`command === 'fake-wrangler'`) that records every call and
// answers the way wrangler 4.104.0 does for the subcommands this deploy path
// uses.

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TarStream, type TarStreamInput } from '@std/tar'
import { parse as parseToml } from '@std/toml'
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
  readonly kvTitle?: string
  readonly minWranglerVersion?: string
  readonly postDeploy?: readonly Record<string, unknown>[]
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
      ...(options.includeKv === false ? {} : {
        kv: [{
          binding: 'MCP_KV',
          title: options.kvTitle ?? '{{app.name}}-mcp-kv',
        }],
      }),
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
      postDeploy: options.postDeploy ?? [
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

const erpcTomlText = (
  sha256: string,
  options: { readonly build?: readonly string[] } = {},
): string =>
  `schema_version = 1
name = "test-app"

[app]
runtime = "cloudflare-worker"
entrypoint = "src/index.ts"
${
    options.build
      ? `\n[build]\ncommand = [${
        options.build.map((value) => `"${value}"`).join(', ')
      }]\n`
      : ''
  }
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
  options:
    & TemplateManifestOptions
    & WranglerTomlOptions
    & { readonly build?: readonly string[] } = {},
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
  await writeFile(
    join(root, 'erpc.toml'),
    erpcTomlText(sha256, { build: options.build }),
    'utf8',
  )
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

/** Every wrangler call carries a leading `--config <path>`; strip it before reading the subcommand. */
const withoutConfigFlag = (args: readonly string[]): readonly string[] =>
  args[0] === '--config' ? args.slice(2) : args

const createFakeWrangler = (options: FakeWranglerOptions = {}) => {
  const calls: ProcessRequest[] = []
  const kvNamespaces: { id: string; title: string }[] = []
  const secrets = new Set(options.existingSecrets ?? [])
  const accounts = options.accounts ??
    [{ id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', name: 'Test Account' }]
  let whoamiOk = options.whoamiOk ?? true
  let workerExists = options.workerExists ?? secrets.size > 0
  let nextKvId = 1

  const run: ProcessRunner = async (request) => {
    calls.push(request)
    if (request.command !== 'fake-wrangler') {
      return { code: 0, stderr: '', stdout: '' }
    }
    const [sub1, sub2, sub3, sub4] = withoutConfigFlag(request.args)
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
      const id = (nextKvId++).toString(16).padStart(32, '0')
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
    call.command === 'fake-wrangler'
      ? withoutConfigFlag(call.args)[0]!
      : call.command
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

/**
 * A TTY is present but every prompt is a hard failure - used only to prove a
 * negative (e.g. that the CLOUDFLARE_API_TOKEN check stops the run *before*
 * any prompt or `wrangler login` would otherwise happen for an interactive
 * session). `isInteractive` must be `true` here: a `false` value would make
 * the CLOUDFLARE_API_TOKEN-specific stop indistinguishable from the separate
 * "no terminal" stop, since both produce a rejection and 0 `login` calls.
 */
const interactivePromptIOThatMustNotBeUsed = (): PromptIO => ({
  isInteractive: () => true,
  confirm: () => {
    throw new Error('confirm() should not have been called')
  },
  text: () => {
    throw new Error('text() should not have been called')
  },
  secret: () => {
    throw new Error('secret() should not have been called')
  },
  select: () => {
    throw new Error('select() should not have been called')
  },
})

/**
 * An interactive `PromptIO` that records every `secret`/`select` question
 * and answers `secret` from `secretAnswers` in order. `select` answers with
 * `selectAnswer` when one is given and throws otherwise; `confirm`/`text`
 * always throw.
 */
const interactivePromptSpy = (
  options: {
    readonly secretAnswers?: readonly string[]
    readonly selectAnswer?: string
  } = {},
) => {
  const secretQuestions: string[] = []
  const selectQuestions: string[] = []
  const secretAnswers = [...(options.secretAnswers ?? [])]
  const io: PromptIO = {
    isInteractive: () => true,
    confirm: () => {
      throw new Error('confirm() should not have been called')
    },
    text: () => {
      throw new Error('text() should not have been called')
    },
    secret: (question) => {
      secretQuestions.push(question)
      const answer = secretAnswers.shift()
      if (answer === undefined) {
        throw new Error(`no scripted answer for secret(): ${question}`)
      }
      return Promise.resolve(answer)
    },
    select: (question) => {
      selectQuestions.push(question)
      if (options.selectAnswer === undefined) {
        throw new Error('select() should not have been called')
      }
      return Promise.resolve(options.selectAnswer)
    },
  }
  return { io, secretQuestions, selectQuestions }
}

/** The secret names passed to `wrangler secret put`, in call order. */
const putSecretNames = (calls: readonly ProcessRequest[]): readonly string[] =>
  calls
    .filter((call) =>
      call.command === 'fake-wrangler' &&
      withoutConfigFlag(call.args)[0] === 'secret' &&
      withoutConfigFlag(call.args)[1] === 'put'
    )
    .map((call) => withoutConfigFlag(call.args)[2] ?? '')

/**
 * Rejects if `promise` has not settled within `ms`, so a regression that
 * makes a deploy hang fails the test instead of hanging the whole run.
 */
const settlesWithin = async <T>(
  promise: Promise<T>,
  ms: number,
): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined
  const guard = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`did not settle within ${ms}ms`)),
      ms,
    )
  })
  try {
    return await Promise.race([promise, guard])
  } finally {
    clearTimeout(timer)
  }
}

/** A fetch that never answers, but rejects as soon as its signal aborts. */
const hangUntilAborted = (init?: RequestInit): Promise<Response> =>
  new Promise((_, reject) => {
    const signal = init?.signal
    if (!signal) return
    if (signal.aborted) {
      reject(signal.reason)
      return
    }
    signal.addEventListener('abort', () => reject(signal.reason), {
      once: true,
    })
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
  it('--no-provision stops on a missing required secret without ever deploying', async () => {
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
    expect(
      fake.calls.some((call) =>
        withoutConfigFlag(call.args).includes('deploy')
      ),
    ).toBe(false)
    expect(fake.calls.some((call) => withoutConfigFlag(call.args)[1] === 'put'))
      .toBe(false)
    // The fixture template is unpinned in `emptyRegistry`.
    expect(
      output.filter((line) => line.includes('will run with your permissions'))
        .length,
    ).toBe(1)
  })

  it('a pinned template prints no trust warning', async () => {
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

  it('full provision -> deploy -> probe in order, then a second run is a no-op for KV/secret', async () => {
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
      call.command === 'fake-wrangler' &&
      withoutConfigFlag(call.args)[0] === 'secret'
    )
    expect(withoutConfigFlag(secretCalls[1]?.args ?? [])).toEqual([
      'secret',
      'put',
      'JWT_SECRET',
    ])
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
    expect(fake.calls.some((call) => withoutConfigFlag(call.args)[0] === 'kv'))
      .toBe(false)
    expect(fake.calls.some((call) => withoutConfigFlag(call.args)[1] === 'put'))
      .toBe(false)
  })

  it('a non-interactive secret-pipe backup with no --ack-backup runs nothing', async () => {
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
    expect(fake.calls.some((call) => withoutConfigFlag(call.args)[1] === 'put'))
      .toBe(false)

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
        withoutConfigFlag(call.args)[0] === 'secret' &&
        withoutConfigFlag(call.args)[1] === 'put' &&
        withoutConfigFlag(call.args)[2] === 'WALLET_MNEMONIC'
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

    expect(fake.calls.some((call) => withoutConfigFlag(call.args)[1] === 'put'))
      .toBe(false)
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

    // Interactive on purpose (see interactivePromptIOThatMustNotBeUsed): if
    // the CLOUDFLARE_API_TOKEN check were removed, execution would fall
    // through to the interactive branch and call `wrangler login` - only an
    // interactive session makes "0 login calls" a real discriminator here.
    // The assertion also pins a phrase ("CLOUDFLARE_API_TOKEN is set") that
    // is unique to this branch, not the shared "no terminal" message, which
    // also happens to mention CLOUDFLARE_API_TOKEN as a remedy.
    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: interactivePromptIOThatMustNotBeUsed(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('CLOUDFLARE_API_TOKEN is set')

    expect(
      fake.calls.some((call) => withoutConfigFlag(call.args)[0] === 'login'),
    ).toBe(false)
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

    expect(
      fake.calls.some((call) => withoutConfigFlag(call.args)[0] === 'login'),
    ).toBe(false)
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

  it('every cloudflare-only deploy option is rejected on a node/deno app before any subprocess runs', async () => {
    const parent = await temporaryDirectory('erpc-cf-deploy-b1-')
    const nodeApp = join(parent, 'node-app')
    await initializeApp({
      directory: nodeApp,
      runtime: 'node',
      name: 'node-app',
    })
    const erpcHome = join(parent, '.erpc')

    for (
      const args of [
        ['--dry-run'],
        ['--verify-only'],
        ['--no-provision'],
        ['--yes'],
        ['--ack-backup', 'SOME_KEY'],
      ]
    ) {
      const calls: ProcessRequest[] = []
      const run: ProcessRunner = async (request) => {
        calls.push(request)
        return { code: 0, stderr: '', stdout: '' }
      }
      await expect(runCli(
        ['deploy', '--config', join(nodeApp, 'erpc.toml'), ...args],
        { erpcHome, output: () => undefined, runProcess: run },
      )).rejects.toThrow('only supported for the cloudflare-worker runtime')
      expect(calls).toHaveLength(0)
    }
  })

  it('WRANGLER_LOG_SANITIZE is forced true on every wrangler call even when the parent env disagrees', async () => {
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
    const putCall = wranglerCalls.find((call) =>
      withoutConfigFlag(call.args)[1] === 'put'
    )
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
    expect(withoutConfigFlag(fake.calls.at(-1)?.args ?? [])).toEqual([
      'deploy',
      '--dry-run',
    ])
    expect(output.some((line) => line.includes('Missing required'))).toBe(true)
  })

  it('a failing [build].command stops before any Cloudflare command runs', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      build: ['fake-build'],
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []
    const run: ProcessRunner = async (request) => {
      if (request.command === 'fake-build') {
        return { code: 1, stderr: 'build blew up', stdout: '' }
      }
      return await fake.run(request)
    }

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('Build failed')

    expect(fake.calls).toHaveLength(0)
    expect(output.some((line) => line.includes('build blew up'))).toBe(true)
  })

  it('a failing preflight command stops before deploy', async () => {
    const project = await setupProject({
      includeKv: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []
    const run: ProcessRunner = async (request) => {
      if (request.command === 'fake-preflight') {
        return { code: 1, stderr: 'preflight failed loudly', stdout: '' }
      }
      return await fake.run(request)
    }

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('Preflight command failed')

    expect(commandNames(fake.calls).includes('deploy')).toBe(false)
    expect(output.some((line) => line.includes('preflight failed loudly')))
      .toBe(true)
  })

  it('an old wrangler stops before any Cloudflare command runs', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      minWranglerVersion: '4.104.0',
    })
    const manifest = await loadManifest(project)
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      if (withoutConfigFlag(request.args)[0] === '--version') {
        return { code: 0, stderr: '', stdout: '4.0.0\n' }
      }
      return { code: 1, stderr: '', stdout: '' }
    }

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('4.104.0 or newer is required')

    expect(calls).toHaveLength(1)
  })

  it('an existing KV namespace with a matching title is reused, not recreated', async () => {
    const project = await setupProject({
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    fake.kvNamespaces.push({
      id: 'cccccccccccccccccccccccccccccccc',
      title: 'test-app-mcp-kv',
    })

    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

    expect(commandNames(fake.calls).includes('kv')).toBe(true)
    expect(
      fake.calls.some((call) =>
        withoutConfigFlag(call.args)[0] === 'kv' &&
        withoutConfigFlag(call.args)[2] === 'create'
      ),
    ).toBe(false)
    const wranglerTomlAfter = await Deno.readTextFile(
      join(project.root, 'wrangler.toml'),
    )
    expect(wranglerTomlAfter).toContain('cccccccccccccccccccccccccccccccc')
  })
})

describe('erpc deploy --target cloudflare: secret-input values', () => {
  const OPTIONAL_ENV = 'ERPC_CLI_TEST_OPTIONAL_INPUT'
  const REQUIRED_ENV = 'ERPC_CLI_TEST_REQUIRED_INPUT'

  const generatedJwtSecret = {
    key: 'JWT_SECRET',
    target: 'secret-generate',
    bytes: 32,
    encoding: 'hex',
  }

  const deployWith = async (
    project: Project,
    fake: ReturnType<typeof createFakeWrangler>,
    promptIO: PromptIO,
    output: string[],
  ): Promise<void> =>
    await deployToCloudflare(await loadManifest(project), {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO,
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

  const setupSecretInputProject = async (
    input: Record<string, unknown>,
  ): Promise<Project> =>
    await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      requiredSecrets: input.required === true
        ? ['JWT_SECRET', String(input.key)]
        : ['JWT_SECRET'],
      secretPrompts: [generatedJwtSecret, input],
    })

  it('an empty interactive answer to an optional prompt leaves the secret unset and still deploys', async () => {
    const project = await setupSecretInputProject({
      key: 'OPTIONAL_API_KEY',
      target: 'secret-input',
      required: false,
      question: 'API key (optional)',
    })
    const fake = createFakeWrangler()
    const spy = interactivePromptSpy({ secretAnswers: [''] })
    const output: string[] = []

    await deployWith(project, fake, spy.io, output)

    expect(spy.secretQuestions).toEqual(['API key (optional)'])
    expect(putSecretNames(fake.calls)).toEqual(['JWT_SECRET'])
    expect(commandNames(fake.calls)).toContain('deploy')
    expect(
      output.some((line) => line.includes('OPTIONAL_API_KEY was left unset')),
    ).toBe(true)
  })

  it('an empty environment variable for an optional prompt leaves the secret unset and still deploys', async () => {
    setEnv(OPTIONAL_ENV, '')
    const project = await setupSecretInputProject({
      key: 'OPTIONAL_API_KEY',
      target: 'secret-input',
      required: false,
      env: OPTIONAL_ENV,
    })
    const fake = createFakeWrangler()
    const output: string[] = []

    await deployWith(project, fake, nonInteractivePromptIO(), output)

    expect(putSecretNames(fake.calls)).toEqual(['JWT_SECRET'])
    expect(commandNames(fake.calls)).toContain('deploy')
    expect(
      output.some((line) => line.includes('OPTIONAL_API_KEY was left unset')),
    ).toBe(true)
  })

  it('an empty environment variable for a required prompt stops before any secret is put', async () => {
    setEnv(REQUIRED_ENV, '')
    const project = await setupSecretInputProject({
      key: 'REQUIRED_API_KEY',
      target: 'secret-input',
      required: true,
      env: REQUIRED_ENV,
    })
    const fake = createFakeWrangler()

    await expect(
      deployWith(project, fake, nonInteractivePromptIO(), []),
    ).rejects.toThrow(
      `REQUIRED_API_KEY is required; set the ${REQUIRED_ENV} environment variable`,
    )

    expect(putSecretNames(fake.calls)).toEqual([])
    expect(commandNames(fake.calls)).not.toContain('deploy')
  })

  it('an empty interactive answer to a required prompt stops without putting that secret', async () => {
    const project = await setupSecretInputProject({
      key: 'REQUIRED_API_KEY',
      target: 'secret-input',
      required: true,
    })
    const fake = createFakeWrangler()
    const spy = interactivePromptSpy({ secretAnswers: [''] })

    await expect(deployWith(project, fake, spy.io, [])).rejects.toThrow(
      'REQUIRED_API_KEY is required',
    )

    expect(putSecretNames(fake.calls)).not.toContain('REQUIRED_API_KEY')
    expect(commandNames(fake.calls)).not.toContain('deploy')
  })

  it('an interactive answer that does not match validate.pattern stops without putting that secret', async () => {
    const project = await setupSecretInputProject({
      key: 'OPTIONAL_API_KEY',
      target: 'secret-input',
      required: false,
      validate: { pattern: '[a-z]{8}' },
    })
    const fake = createFakeWrangler()
    const spy = interactivePromptSpy({ secretAnswers: ['NOT-VALID-VALUE'] })

    let caught: unknown
    try {
      await deployWith(project, fake, spy.io, [])
    } catch (error) {
      caught = error
    }

    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error).message).toContain(
      'The value entered for secret OPTIONAL_API_KEY does not match its validate.pattern',
    )
    expect((caught as Error).message).not.toContain('NOT-VALID-VALUE')
    expect(putSecretNames(fake.calls)).not.toContain('OPTIONAL_API_KEY')
    expect(commandNames(fake.calls)).not.toContain('deploy')
  })

  it('an environment value that does not match validate.pattern stops before any secret is put', async () => {
    setEnv(OPTIONAL_ENV, 'NOT-VALID-VALUE')
    const project = await setupSecretInputProject({
      key: 'OPTIONAL_API_KEY',
      target: 'secret-input',
      required: false,
      env: OPTIONAL_ENV,
      validate: { pattern: '[a-z]{8}' },
    })
    const fake = createFakeWrangler()

    let caught: unknown
    try {
      await deployWith(project, fake, nonInteractivePromptIO(), [])
    } catch (error) {
      caught = error
    }

    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error).message).toContain(
      `OPTIONAL_API_KEY: the value provided in ${OPTIONAL_ENV} does not match its validate.pattern`,
    )
    expect((caught as Error).message).not.toContain('NOT-VALID-VALUE')
    expect(putSecretNames(fake.calls)).toEqual([])
    expect(commandNames(fake.calls)).not.toContain('deploy')
  })

  it('a non-empty environment value that matches validate.pattern is put through stdin', async () => {
    setEnv(OPTIONAL_ENV, 'abcdefgh')
    const project = await setupSecretInputProject({
      key: 'OPTIONAL_API_KEY',
      target: 'secret-input',
      required: false,
      env: OPTIONAL_ENV,
      validate: { pattern: '[a-z]{8}' },
    })
    const fake = createFakeWrangler()

    await deployWith(project, fake, nonInteractivePromptIO(), [])

    expect(putSecretNames(fake.calls)).toEqual([
      'JWT_SECRET',
      'OPTIONAL_API_KEY',
    ])
    const put = fake.calls.find((call) =>
      withoutConfigFlag(call.args)[2] === 'OPTIONAL_API_KEY'
    )
    expect(put?.input).toBe('abcdefgh')
    expect(put?.args.includes('abcdefgh')).toBe(false)
  })
})

describe('erpc deploy --target cloudflare: --yes, probe timeouts, and redirect origins', () => {
  const TWO_ACCOUNTS = [
    { id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', name: 'First Account' },
    { id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', name: 'Second Account' },
  ] as const

  it('--yes with a terminal attached never asks which account to use', async () => {
    setEnv('CLOUDFLARE_ACCOUNT_ID', undefined)
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler({ accounts: TWO_ACCOUNTS })
    const spy = interactivePromptSpy({ selectAnswer: TWO_ACCOUNTS[0].id })

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      noProvision: true,
      output: () => undefined,
      promptIO: spy.io,
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
      yes: true,
    })).rejects.toThrow('Multiple Cloudflare accounts are available')

    expect(spy.selectQuestions).toEqual([])
  })

  it('without --yes, the same terminal session asks which account to use', async () => {
    setEnv('CLOUDFLARE_ACCOUNT_ID', undefined)
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler({ accounts: TWO_ACCOUNTS })
    const spy = interactivePromptSpy({ selectAnswer: TWO_ACCOUNTS[1].id })

    // --no-provision then stops at the missing required JWT_SECRET, after
    // the account choice has already been made and written.
    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      noProvision: true,
      output: () => undefined,
      promptIO: spy.io,
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('JWT_SECRET')

    expect(spy.selectQuestions).toHaveLength(1)
    expect(await Deno.readTextFile(join(project.root, 'wrangler.toml')))
      .toContain(`account_id = "${TWO_ACCOUNTS[1].id}"`)
  })

  it('--yes with a terminal attached and no wrangler session stops without running wrangler login', async () => {
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
      noProvision: true,
      output: () => undefined,
      promptIO: interactivePromptIOThatMustNotBeUsed(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
      yes: true,
    })).rejects.toThrow('--yes turns off interactive prompts')

    expect(
      fake.calls.some((call) => withoutConfigFlag(call.args)[0] === 'login'),
    ).toBe(false)
  })

  it('an http probe whose request never answers fails once [health].timeout_seconds has passed', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)
    const probeFetch: typeof fetch = (async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.origin === WORKER_BASE && url.pathname === '/health') {
        return await hangUntilAborted(init)
      }
      return await successProbeFetch(input, init)
    }) as typeof fetch

    const startedAt = Date.now()
    await expect(settlesWithin(
      deployToCloudflare(manifest, {
        erpcHome: project.erpcHome,
        output: () => undefined,
        promptIO: nonInteractivePromptIO(),
        random: fixedRandom(1),
        verifyOnly: true,
        fetch: buildFetchStub(project.archive, probeFetch),
        templateRegistry: pinnedRegistryFor(project.sha256),
      }),
      5000,
    )).rejects.toThrow('GET /health failed')
    expect(Date.now() - startedAt < 4000).toBe(true)
  })

  it('an OAuth client registration request that never answers fails once [health].timeout_seconds has passed', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)
    let registerCalls = 0
    const probeFetch: typeof fetch = (async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.origin === WORKER_BASE && url.pathname === '/oauth/register') {
        registerCalls++
        return await hangUntilAborted(init)
      }
      return await successProbeFetch(input, init)
    }) as typeof fetch

    const startedAt = Date.now()
    await expect(settlesWithin(
      deployToCloudflare(manifest, {
        erpcHome: project.erpcHome,
        output: () => undefined,
        promptIO: nonInteractivePromptIO(),
        random: fixedRandom(1),
        verifyOnly: true,
        fetch: buildFetchStub(project.archive, probeFetch),
        templateRegistry: pinnedRegistryFor(project.sha256),
      }),
      5000,
    )).rejects.toThrow('POST /oauth/register failed')
    expect(Date.now() - startedAt < 4000).toBe(true)
    expect(registerCalls).toBe(1)
  })

  it('a response body that stops arriving is reported as a timeout, not as invalid JSON', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      postDeploy: [
        {
          kind: 'http',
          baseUrlFromVar: 'MCP_SERVER_BASE_URL',
          path: '/health',
          expectStatus: 200,
          expectJson: { ok: true },
        },
      ],
    })
    const manifest = await loadManifest(project)
    const probeFetch: typeof fetch = (async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.origin === WORKER_BASE && url.pathname === '/health') {
        const signal = init?.signal
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(textEncoder.encode('{"ok":'))
            signal?.addEventListener(
              'abort',
              () => controller.error(signal.reason),
              { once: true },
            )
          },
        })
        return new Response(body, { status: 200 })
      }
      return await successProbeFetch(input, init)
    }) as typeof fetch

    await expect(settlesWithin(
      deployToCloudflare(manifest, {
        erpcHome: project.erpcHome,
        output: () => undefined,
        promptIO: nonInteractivePromptIO(),
        random: fixedRandom(1),
        verifyOnly: true,
        fetch: buildFetchStub(project.archive, probeFetch),
        templateRegistry: pinnedRegistryFor(project.sha256),
      }),
      5000,
    )).rejects.toThrow('GET /health timed out while reading the response body')
  })

  it('the issuer redirecting to /oauth/consent on a different origin fails verification', async () => {
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
          'https://not-the-issuer.example.test/oauth/consent?txn=abc123',
        ),
      ),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('the issuer redirected somewhere unexpected')
  })

  it('the worker redirecting outside the issuer origin fails verification without requesting that origin', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const manifest = await loadManifest(project)
    const OTHER_ORIGIN = 'https://not-the-issuer.example.test'
    const otherOriginRequests: string[] = []
    const probeFetch: typeof fetch = (async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.origin === WORKER_BASE && url.pathname === '/oauth/authorize') {
        return new Response(null, {
          status: 302,
          headers: { location: `${OTHER_ORIGIN}/oauth/authorize` },
        })
      }
      if (url.origin === OTHER_ORIGIN) {
        // If it were ever requested, this host would bounce straight to the
        // issuer's consent page, so only the worker-side origin check can
        // catch the redirect.
        otherOriginRequests.push(url.toString())
        return new Response(null, {
          status: 302,
          headers: { location: `${ISSUER}/oauth/consent?txn=abc123` },
        })
      }
      return await successProbeFetch(input, init)
    }) as typeof fetch

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      verifyOnly: true,
      fetch: buildFetchStub(project.archive, probeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('redirected outside the issuer origin')

    expect(otherOriginRequests).toEqual([])
  })
})

describe('erpc deploy --target cloudflare: wrangler.toml edits', () => {
  it('a KV namespace id that is not 32 hex characters is never written into wrangler.toml', async () => {
    const project = await setupProject({
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    fake.kvNamespaces.push({
      id: 'not-a-kv-id"\n[vars]\nINJECTED = "1',
      title: 'test-app-mcp-kv',
    })
    const wranglerTomlPath = join(project.root, 'wrangler.toml')

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('does not look like a KV namespace id')

    const after = await Deno.readTextFile(wranglerTomlPath)
    expect(after).toContain('{{erpc:kv-id:MCP_KV}}')
    expect(after).not.toContain('INJECTED')
    expect(putSecretNames(fake.calls)).toEqual([])
    expect(commandNames(fake.calls)).not.toContain('deploy')
  })

  it('an account_id that would land inside a multi-line string stops before wrangler.toml is written', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const manifest = await loadManifest(project)
    const wranglerTomlPath = join(project.root, 'wrangler.toml')
    const original = `name = "test-app"
main = "src/index.ts"
compatibility_date = "2026-01-01"
notes = """
[this line is inside a string, not a table header]
"""

[vars]
MCP_SERVER_BASE_URL = "${WORKER_BASE}"
APP_OIDC_ISSUER = "${ISSUER}"

[secrets]
required = ["JWT_SECRET"]
`
    await writeFile(wranglerTomlPath, original, 'utf8')
    const fake = createFakeWrangler()

    await expect(deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })).rejects.toThrow('Unable to add account_id')

    expect(await Deno.readTextFile(wranglerTomlPath)).toBe(original)
    expect(commandNames(fake.calls)).toEqual(['--version', 'whoami'])
  })
})

describe('erpc deploy --target cloudflare: OAuth client registration retries', () => {
  const countingProbeFetch = (
    options: {
      readonly failFirstAuthorize?: boolean
      readonly failFirstRegister?: boolean
    },
  ) => {
    const counts = { authorize: 0, register: 0 }
    const probeFetch: typeof fetch = (async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.origin === WORKER_BASE && url.pathname === '/oauth/register') {
        counts.register++
        if (options.failFirstRegister && counts.register === 1) {
          return new Response('unavailable', { status: 503 })
        }
      }
      if (url.origin === WORKER_BASE && url.pathname === '/oauth/authorize') {
        counts.authorize++
        if (options.failFirstAuthorize && counts.authorize === 1) {
          return new Response('error', { status: 500 })
        }
      }
      return await successProbeFetch(input, init)
    }) as typeof fetch
    return { counts, probeFetch }
  }

  const verify = async (project: Project, probeFetch: typeof fetch) =>
    await deployToCloudflare(await loadManifest(project), {
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      verifyOnly: true,
      fetch: buildFetchStub(project.archive, probeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

  it('a successful registration is reused when the authorize step is retried', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const { counts, probeFetch } = countingProbeFetch({
      failFirstAuthorize: true,
    })

    await verify(project, probeFetch)

    expect(counts.authorize).toBe(2)
    expect(counts.register).toBe(1)
  })

  it('a failed registration is retried on the next attempt', async () => {
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
    })
    const { counts, probeFetch } = countingProbeFetch({
      failFirstRegister: true,
    })

    await verify(project, probeFetch)

    expect(counts.register).toBe(2)
    expect(counts.authorize).toBe(1)
  })
})

describe('erpc deploy --target cloudflare: account and config handling', () => {
  const deployOnce = async (
    project: Project,
    fake: ReturnType<typeof createFakeWrangler>,
    extra: { readonly dryRun?: boolean; readonly noProvision?: boolean } = {},
  ): Promise<void> =>
    await deployToCloudflare(await loadManifest(project), {
      ...extra,
      erpcHome: project.erpcHome,
      output: () => undefined,
      promptIO: nonInteractivePromptIO(),
      random: fixedRandom(1),
      run: fake.run,
      fetch: buildFetchStub(project.archive, successProbeFetch),
      templateRegistry: pinnedRegistryFor(project.sha256),
    })

  it('--dry-run leaves wrangler.toml byte-for-byte unchanged', async () => {
    const project = await setupProject({
      includePreflight: false,
      includePostDeploy: false,
    })
    const wranglerTomlPath = join(project.root, 'wrangler.toml')
    const before = await Deno.readTextFile(wranglerTomlPath)
    const fake = createFakeWrangler()

    await deployOnce(project, fake, { dryRun: true })

    expect(await Deno.readTextFile(wranglerTomlPath)).toBe(before)
  })

  it('every wrangler call names the project config explicitly with --config', async () => {
    const project = await setupProject({ includePostDeploy: false })
    const fake = createFakeWrangler()

    await deployOnce(project, fake)

    const wranglerCalls = fake.calls.filter((call) =>
      call.command === 'fake-wrangler'
    )
    expect(wranglerCalls.length > 0).toBe(true)
    for (const call of wranglerCalls) {
      expect(call.args.slice(0, 2)).toEqual([
        '--config',
        join(project.root, 'wrangler.toml'),
      ])
    }
  })

  it('an account_id already in wrangler.toml that this login cannot see stops right after whoami', async () => {
    setEnv('CLOUDFLARE_ACCOUNT_ID', undefined)
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
      accountId: 'dddddddddddddddddddddddddddddddd',
    })
    const fake = createFakeWrangler()

    await expect(deployOnce(project, fake)).rejects.toThrow(
      'is not one of the accounts this wrangler login can see',
    )
    expect(commandNames(fake.calls)).toEqual(['--version', 'whoami'])
  })

  it('a CLOUDFLARE_ACCOUNT_ID that is not an account id is never written into wrangler.toml', async () => {
    setEnv('CLOUDFLARE_ACCOUNT_ID', 'abc"\n[vars]\nINJECTED = "1')
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const wranglerTomlPath = join(project.root, 'wrangler.toml')
    const before = await Deno.readTextFile(wranglerTomlPath)
    const fake = createFakeWrangler()

    await expect(deployOnce(project, fake)).rejects.toThrow(
      'does not look like an account id',
    )
    expect(await Deno.readTextFile(wranglerTomlPath)).toBe(before)
  })

  it('account_id is inserted above an indented first table header', async () => {
    setEnv('CLOUDFLARE_ACCOUNT_ID', undefined)
    const project = await setupProject({
      includeKv: false,
      includePreflight: false,
      includePostDeploy: false,
    })
    const wranglerTomlPath = join(project.root, 'wrangler.toml')
    await writeFile(
      wranglerTomlPath,
      `name = "test-app"
main = "src/index.ts"
compatibility_date = "2026-01-01"

  [vars]
  MCP_SERVER_BASE_URL = "${WORKER_BASE}"
  APP_OIDC_ISSUER = "${ISSUER}"

[secrets]
required = ["JWT_SECRET"]
`,
      'utf8',
    )
    const fake = createFakeWrangler()

    await deployOnce(project, fake)

    const after = parseToml(await Deno.readTextFile(wranglerTomlPath))
    expect(after.account_id).toBe('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    expect(after.vars).toEqual({
      MCP_SERVER_BASE_URL: WORKER_BASE,
      APP_OIDC_ISSUER: ISSUER,
    })
  })

  it('a kv title written as {{ app.name }} (with spaces) is interpolated like {{app.name}}', async () => {
    const project = await setupProject({
      includePreflight: false,
      includePostDeploy: false,
      kvTitle: '{{ app.name }}-mcp-kv',
    })
    const fake = createFakeWrangler()

    await deployOnce(project, fake)

    expect(fake.kvNamespaces.map((namespace) => namespace.title)).toEqual([
      'test-app-mcp-kv',
    ])
  })
})
