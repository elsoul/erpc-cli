// A11 (sentinel leak). See Task Brief `2026-09-25-packet-erpc-cli-pr-b.md`
// Decision 10 / Acceptance A11: a secret value must never appear in
// `output`, in a thrown error message, in any file under the project
// directory or `ERPC_HOME`, or in any subprocess call's `args`/`env` - the
// only place it may legitimately appear is the recorded `secret put` call's
// `input` (what actually goes to wrangler's stdin).
//
// Two canaries exercise the two value-producing secret targets this PR
// implements: `secret-generate` (`SENTINEL` - 6 raw bytes injected via
// `CliDependencies.random`, base64url-encoded) and `secret-pipe`
// (`SENTINEL-PIPE-VALUE`, the fake generator script's own stdout). The pipe
// generator also emits the value on stderr, exercising the `[REDACTED]`
// substitution (Decision 6).

import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TarStream, type TarStreamInput } from '@std/tar'
import { afterEach, describe, expect, it } from './testing.ts'
import {
  type CloudflareWorkerManifest,
  deployToCloudflare,
  loadAnyErpcManifest,
  type ProcessRequest,
  type ProcessRunner,
  type PromptIO,
  sha256Hex,
} from '../src/index.ts'

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

// The two canary secrets this test tracks end-to-end. `GENERATED_CANARY` is
// only the leading substring of the actual `secret-generate` value: base64
// encodes 3 raw bytes per 4 characters, so seeding the first 6 (of the
// required minimum 32) random bytes with `Uint8Array.fromBase64('SENTINEL')`
// makes the base64url-encoded secret start with the literal text
// "SENTINEL" - `toContain`, not `toBe`, is the correct check below.
const GENERATED_CANARY = 'SENTINEL'
const PIPE_CANARY = 'SENTINEL-PIPE-VALUE'
const sentinelRandomBytes = Uint8Array.fromBase64(GENERATED_CANARY)

const wranglerTomlText = (): string =>
  `name = "test-app"
main = "src/index.ts"
compatibility_date = "2026-01-01"
account_id = "{{erpc:cloudflare-account-id}}"

[secrets]
required = ["JWT_SECRET", "WALLET_MNEMONIC"]
`

const templateManifestJson = (): string =>
  JSON.stringify({
    schemaVersion: 1,
    name: 'fixture-template',
    runtime: 'cloudflare-worker',
    minCliVersion: '0.1.0',
    cloudflare: {
      config: 'wrangler.toml',
      wrangler: ['fake-wrangler'],
      minWranglerVersion: '4.0.0',
    },
    render: [{ path: 'wrangler.toml', format: 'toml' }],
    prompts: [
      {
        key: 'JWT_SECRET',
        target: 'secret-generate',
        bytes: 32,
        encoding: 'base64url',
      },
      {
        key: 'WALLET_MNEMONIC',
        target: 'secret-pipe',
        command: ['fake-pipe'],
      },
    ],
  })

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
name = "fixture-template"
source = "github:elsoul/fixture-template-repo"
ref = "v0.1.0"
asset = "erpc-template.tar.gz"
sha256 = "${sha256}"

[health]
timeout_seconds = 1
`

interface Project {
  readonly archive: Uint8Array
  readonly configPath: string
  readonly erpcHome: string
  readonly root: string
}

const setupProject = async (): Promise<Project> => {
  const parent = await temporaryDirectory('erpc-secrets-leak-')
  const root = join(parent, 'app')
  const erpcHome = join(parent, '.erpc')
  await mkdir(root, { recursive: true })
  const wranglerToml = wranglerTomlText()
  await writeFile(join(root, 'wrangler.toml'), wranglerToml, 'utf8')
  const archive = await tarGzFromInputs([
    fileInput('erpc-template.json', templateManifestJson()),
    fileInput('wrangler.toml', wranglerToml),
    fileInput(
      'src/index.ts',
      'export default { fetch: () => new Response("ok") }\n',
    ),
  ])
  const sha256 = await sha256Hex(archive)
  await writeFile(join(root, 'erpc.toml'), erpcTomlText(sha256), 'utf8')
  return { archive, configPath: join(root, 'erpc.toml'), erpcHome, root }
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

const createFakeWrangler = () => {
  const calls: ProcessRequest[] = []
  const secrets = new Set<string>()
  let workerExists = false

  const run: ProcessRunner = async (request) => {
    calls.push(request)
    if (request.command === 'fake-pipe') {
      // The generator script's own stdout is the secret; its stderr echoes
      // the same value back (a realistic "here's what I just generated"
      // debug line) so the redaction path is exercised too.
      return {
        code: 0,
        stderr: `debug: generated ${PIPE_CANARY} ok\n`,
        stdout: `${PIPE_CANARY}\n`,
      }
    }
    if (request.command !== 'fake-wrangler') {
      return { code: 0, stderr: '', stdout: '' }
    }
    const [sub1, sub2] = request.args
    if (sub1 === '--version') {
      return { code: 0, stderr: '', stdout: '4.104.0\n' }
    }
    if (sub1 === 'whoami') {
      return {
        code: 0,
        stderr: '',
        stdout: JSON.stringify({
          loggedIn: true,
          accounts: [{ id: 'acct-1', name: 'Test Account' }],
        }),
      }
    }
    if (sub1 === 'secret' && sub2 === 'list') {
      if (!workerExists) {
        return { code: 1, stderr: '', stdout: 'Worker "test-app" not found.' }
      }
      return {
        code: 0,
        stderr: '',
        stdout: JSON.stringify([...secrets].map((name) => ({ name }))),
      }
    }
    if (sub1 === 'secret' && sub2 === 'put') {
      secrets.add(request.args[2] ?? '')
      workerExists = true
      return { code: 0, stderr: '', stdout: 'Success!' }
    }
    if (sub1 === 'deploy') return { code: 0, stderr: '', stdout: '' }
    return {
      code: 1,
      stderr: `unhandled fake-wrangler args: ${request.args.join(' ')}`,
      stdout: '',
    }
  }

  return { run, calls }
}

const nonInteractivePromptIO = (): PromptIO => ({
  isInteractive: () => false,
  confirm: () => {
    throw new Error('confirm() should not be called in this test')
  },
  text: () => {
    throw new Error('text() should not be called in this test')
  },
  secret: () => {
    throw new Error('secret() should not be called in this test')
  },
  select: () => {
    throw new Error('select() should not be called in this test')
  },
})

const walkFiles = async function* (
  directory: string,
): AsyncGenerator<string> {
  let entries
  try {
    entries = await readdir(directory, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const full = join(directory, entry.name)
    if (entry.isDirectory()) {
      yield* walkFiles(full)
    } else if (entry.isFile()) {
      yield full
    }
  }
}

const filesContaining = async (
  root: string,
  needle: string,
): Promise<readonly string[]> => {
  const hits: string[] = []
  for await (const path of walkFiles(root)) {
    const content = await readFile(path, 'utf8').catch(() => '')
    if (content.includes(needle)) hits.push(path)
  }
  return hits
}

describe('A11: secret values never leak outside the recorded `secret put` stdin', () => {
  it('the generated secret and the piped secret reach stdin only, never args/env/output/files', async () => {
    const project = await setupProject()
    const manifest = await loadManifest(project)
    const fake = createFakeWrangler()
    const output: string[] = []
    const fetchStub: typeof fetch = (async (input) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.hostname === 'github.com') {
        return new Response(project.archive as unknown as BodyInit, {
          status: 200,
        })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }) as typeof fetch

    await deployToCloudflare(manifest, {
      erpcHome: project.erpcHome,
      output: (message) => output.push(message),
      promptIO: nonInteractivePromptIO(),
      random: (bytes) => {
        bytes.set(sentinelRandomBytes.subarray(0, bytes.length))
      },
      run: fake.run,
      fetch: fetchStub,
      templateRegistry: {},
    })

    // Both secrets were actually generated and put.
    const putCalls = fake.calls.filter((call) =>
      call.command === 'fake-wrangler' && call.args[0] === 'secret' &&
      call.args[1] === 'put'
    )
    expect(putCalls).toHaveLength(2)
    const putByName = new Map(
      putCalls.map((call) => [call.args[2], call.input]),
    )
    expect(putByName.get('JWT_SECRET')).toContain(GENERATED_CANARY)
    expect(putByName.get('WALLET_MNEMONIC')).toBe(PIPE_CANARY)

    for (const canary of [GENERATED_CANARY, PIPE_CANARY]) {
      // 1) `output` never carries the raw value.
      for (const line of output) {
        expect(line).not.toContain(canary)
      }

      // 2) No subprocess call's `args` or `env` carries the raw value -
      // the only sanctioned home for a secret value is `input`.
      for (const call of fake.calls) {
        for (const argument of call.args) {
          expect(argument).not.toContain(canary)
        }
        for (const value of Object.values(call.env ?? {})) {
          expect(value).not.toContain(canary)
        }
      }

      // 3) Nothing under the project dir or ERPC_HOME ever has the value on
      // disk (erpc.toml/wrangler.toml/cache never see a secret).
      expect(await filesContaining(project.root, canary)).toEqual([])
      expect(await filesContaining(project.erpcHome, canary)).toEqual([])
    }

    // 4) Every call's `input` is either undefined or exactly one of the two
    // secret puts above - no other call carries a secret-shaped payload.
    for (const call of fake.calls) {
      if (call.input === undefined) continue
      const isKnownPut = call.command === 'fake-wrangler' &&
        call.args[0] === 'secret' && call.args[1] === 'put' &&
        (call.input.includes(GENERATED_CANARY) ||
          call.input === PIPE_CANARY)
      expect(isKnownPut).toBe(true)
    }

    // 5) The pipe generator's stderr, which echoed the raw value, was
    // redacted before reaching `output` (Decision 6).
    const stderrLine = output.find((line) =>
      line.includes('WALLET_MNEMONIC generator stderr')
    )
    expect(stderrLine).toBeDefined()
    expect(stderrLine).not.toContain(PIPE_CANARY)
    expect(stderrLine).toContain('[REDACTED]')
  })

  it('a thrown error never carries a secret value (missing --ack-backup path)', async () => {
    const parent = await temporaryDirectory('erpc-secrets-leak-ack-')
    const root = join(parent, 'app')
    const erpcHome = join(parent, '.erpc')
    await mkdir(root, { recursive: true })
    const wranglerToml = `name = "test-app"
main = "src/index.ts"
compatibility_date = "2026-01-01"
account_id = "{{erpc:cloudflare-account-id}}"
`
    await writeFile(join(root, 'wrangler.toml'), wranglerToml, 'utf8')
    const manifestJson = JSON.stringify({
      schemaVersion: 1,
      name: 'fixture-template',
      runtime: 'cloudflare-worker',
      minCliVersion: '0.1.0',
      cloudflare: {
        config: 'wrangler.toml',
        wrangler: ['fake-wrangler'],
        minWranglerVersion: '4.0.0',
      },
      render: [{ path: 'wrangler.toml', format: 'toml' }],
      prompts: [
        {
          key: 'WALLET_MNEMONIC',
          target: 'secret-pipe',
          command: ['fake-pipe'],
          backup: { message: 'back it up', confirm: 'YES' },
        },
      ],
    })
    const archive = await tarGzFromInputs([
      fileInput('erpc-template.json', manifestJson),
      fileInput('wrangler.toml', wranglerToml),
      fileInput(
        'src/index.ts',
        'export default { fetch: () => new Response("ok") }\n',
      ),
    ])
    const sha256 = await sha256Hex(archive)
    await writeFile(join(root, 'erpc.toml'), erpcTomlText(sha256), 'utf8')

    const manifest = await loadManifest({
      archive,
      configPath: join(root, 'erpc.toml'),
      erpcHome,
      root,
    })
    const fake = createFakeWrangler()
    const fetchStub: typeof fetch = (async (input) => {
      const url = new URL(input instanceof Request ? input.url : String(input))
      if (url.hostname === 'github.com') {
        return new Response(archive as unknown as BodyInit, { status: 200 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }) as typeof fetch

    let caught: unknown
    try {
      await deployToCloudflare(manifest, {
        erpcHome,
        output: () => undefined,
        promptIO: nonInteractivePromptIO(),
        random: (bytes) => {
          bytes.set(sentinelRandomBytes.subarray(0, bytes.length))
        },
        run: fake.run,
        fetch: fetchStub,
        templateRegistry: {},
      })
    } catch (error) {
      caught = error
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error).message).not.toContain(PIPE_CANARY)
    expect(fake.calls.some((call) => call.command === 'fake-pipe')).toBe(false)
  })
})
