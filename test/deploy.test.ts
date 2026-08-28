import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from './testing.ts'
import {
  buildForDeployment,
  createAppTemplate,
  deployOverSsh,
  findErpcManifest,
  initializeApp,
  loadErpcManifest,
  type ProcessRequest,
  type ProcessResult,
  type ProcessRunner,
  runCli,
} from '../src/index.ts'

const directories: string[] = []

const temporaryDirectory = async () => {
  const directory = await mkdtemp(join(tmpdir(), 'erpc-deploy-'))
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

const result = (
  code = 0,
  stdout = '',
  stderr = '',
): ProcessResult => ({ code, stderr, stdout })

const writeNodeConfig = async (erpcHome: string) => {
  await mkdir(join(erpcHome, 'apps'), { recursive: true })
  await writeFile(
    join(erpcHome, 'config.toml'),
    `schema_version = 1
apps_directory = "${join(erpcHome, 'apps')}"

[nodes.primary]
host = "node.example.test"
user = "ubuntu"
port = 22
`,
    { mode: 0o600 },
  )
}

describe('deployment manifest and local build gate', () => {
  it('finds the nearest erpc.toml or accepts an explicit config directory', async () => {
    const parent = await temporaryDirectory()
    const app = join(parent, 'app')
    await initializeApp({ directory: app, runtime: 'node' })
    const nested = join(app, 'src', 'nested')
    await mkdir(nested, { recursive: true })

    await expect(findErpcManifest(nested)).resolves.toBe(join(app, 'erpc.toml'))
    await expect(findErpcManifest(parent, app)).resolves.toBe(
      join(app, 'erpc.toml'),
    )
  })

  it('validates a locally produced Linux Deno binary', async () => {
    const parent = await temporaryDirectory()
    const app = join(parent, 'deno-api')
    await initializeApp({ directory: app, runtime: 'deno' })
    const manifest = await loadErpcManifest(join(app, 'erpc.toml'))
    const run: ProcessRunner = async () => {
      await mkdir(join(app, 'dist'), { recursive: true })
      const header = new Uint8Array(20)
      header.set([0x7f, 0x45, 0x4c, 0x46])
      header[5] = 1
      new DataView(header.buffer).setUint16(18, 62, true)
      await writeFile(join(app, 'dist', 'erpc-app'), header)
      return result()
    }

    await expect(buildForDeployment(manifest, { run })).resolves.toMatchObject({
      architecture: 'x64',
      runtime: 'deno',
    })
  })

  it('never opens SSH when the local build fails', async () => {
    const parent = await temporaryDirectory()
    const erpcHome = join(parent, '.erpc')
    const app = join(parent, 'app')
    await initializeApp({ directory: app, runtime: 'node' })
    await writeNodeConfig(erpcHome)
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      return result(1, '', 'type error')
    }

    await expect(runCli(
      ['deploy', '--config', join(app, 'erpc.toml')],
      { erpcHome, output: () => undefined, runProcess: run },
    )).rejects.toThrow(
      'Local build failed; no deployment connection was attempted',
    )
    expect(calls.map((call) => call.command)).toEqual(['pnpm'])
  })

  it('builds first, uploads once, and activates a systemd service', async () => {
    const parent = await temporaryDirectory()
    const erpcHome = join(parent, '.erpc')
    const app = join(parent, 'app')
    await initializeApp({ directory: app, runtime: 'node' })
    await writeNodeConfig(erpcHome)
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      if (request.command === 'pnpm') {
        await mkdir(join(app, 'dist'), { recursive: true })
        await writeFile(join(app, 'dist', 'index.js'), 'console.log("ok")\n')
        return result()
      }
      if (
        request.command === 'ssh' && request.args.at(-1)?.includes('uname -m')
      ) {
        return result(0, 'x86_64\n')
      }
      if (
        request.command === 'ssh' && request.args.at(-1)?.includes('node_path')
      ) {
        return result(0, '/usr/bin/node\n22\n')
      }
      return result()
    }
    const output: string[] = []

    await expect(runCli(
      ['deploy', '--config', join(app, 'erpc.toml')],
      {
        erpcHome,
        output: (message) => output.push(message),
        runProcess: run,
      },
    )).resolves.toBe(0)

    expect(calls.map((call) => call.command)).toEqual([
      'pnpm',
      'ssh',
      'ssh',
      'scp',
      'ssh',
    ])
    const activation = calls.at(-1)
    expect(activation?.input).toContain('systemctl daemon-reload')
    expect(activation?.input).toContain('systemctl restart erpc-app.service')
    expect(output.at(-1)).toContain('Deployed app as erpc-app.service')
  })

  it('uploads an application-local Node runtime when the node has no Node.js 20+', async () => {
    const parent = await temporaryDirectory()
    const app = join(parent, 'app')
    await initializeApp({ directory: app, runtime: 'node' })
    const manifest = await loadErpcManifest(join(app, 'erpc.toml'))
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      if (
        request.command === 'ssh' && request.args.at(-1)?.includes('uname -m')
      ) {
        return result(
          0,
          `${Deno.build.arch === 'aarch64' ? 'aarch64' : 'x86_64'}\n`,
        )
      }
      if (
        request.command === 'ssh' && request.args.at(-1)?.includes('node_path')
      ) {
        return result()
      }
      return result()
    }

    await expect(deployOverSsh(
      manifest,
      { path: join(app, 'dist', 'index.js'), runtime: 'node' },
      'primary',
      { host: 'node.example.test', port: 22, user: 'ubuntu' },
      {
        resolveNodeRuntime: async () => Deno.execPath(),
        run,
      },
    )).resolves.toMatchObject({ node: 'primary', service: 'erpc-app' })

    expect(calls.map((call) => call.command)).toEqual([
      'ssh',
      'ssh',
      'scp',
      'scp',
      'ssh',
    ])
    const encodedUnit = calls.at(-1)?.input?.match(/printf '%s' '([^']+)'/)?.[1]
    expect(encodedUnit).toBeDefined()
    expect(
      new TextDecoder().decode(Uint8Array.fromBase64(encodedUnit ?? '')),
    ).toContain(
      'ExecStart=/opt/erpc/apps/app/current/node /opt/erpc/apps/app/current/app.js',
    )
  })

  it('rejects manifest values that could inject systemd unit lines', async () => {
    const parent = await temporaryDirectory()
    const app = join(parent, 'unsafe')
    const template = createAppTemplate('unsafe', 'node')
    await mkdir(app)
    await writeFile(
      join(app, 'erpc.toml'),
      (template.files['erpc.toml'] ?? '').replace(
        'host = "0.0.0.0"',
        'host = "0.0.0.0\\nExecStart=/bin/false"',
      ),
    )

    await expect(loadErpcManifest(join(app, 'erpc.toml'))).rejects.toThrow(
      'Invalid ERPC manifest contract',
    )
  })

  it('rejects a binary architecture mismatch before upload', async () => {
    const parent = await temporaryDirectory()
    const app = join(parent, 'deno-api')
    const template = createAppTemplate('deno-api', 'deno')
    await mkdir(app)
    await writeFile(join(app, 'erpc.toml'), template.files['erpc.toml'] ?? '')
    const manifest = await loadErpcManifest(join(app, 'erpc.toml'))
    const calls: ProcessRequest[] = []
    const run: ProcessRunner = async (request) => {
      calls.push(request)
      return result(0, 'x86_64\n')
    }

    await expect(deployOverSsh(
      manifest,
      { architecture: 'arm64', path: '/tmp/app', runtime: 'deno' },
      'primary',
      { host: 'node.example.test', port: 22, user: 'ubuntu' },
      { run },
    )).rejects.toThrow('architecture does not match')
    expect(calls.map((call) => call.command)).toEqual(['ssh'])
  })
})
