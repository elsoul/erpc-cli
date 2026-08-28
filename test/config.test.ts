import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from './testing.ts'
import { readErpcConfig, runCli } from '../src/index.ts'

const directories: string[] = []

const temporaryDirectory = async () => {
  const directory = await mkdtemp(join(tmpdir(), 'erpc-config-'))
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

describe('local ERPC application registry', () => {
  it('creates a private config without storing credentials', async () => {
    const erpcHome = join(await temporaryDirectory(), '.erpc')
    const config = await readErpcConfig({ erpcHome })
    const source = await readFile(config.configPath, 'utf8')

    expect((await stat(erpcHome)).mode & 0o777).toBe(0o700)
    expect((await stat(config.configPath)).mode & 0o777).toBe(0o600)
    expect(source).not.toMatch(
      /access.?token|refresh.?token|password|private.?key/i,
    )
    expect(config.appsDirectory).toBe(join(erpcHome, 'apps'))
  })

  it('creates named applications below ~/.erpc/apps and lists them', async () => {
    const parent = await temporaryDirectory()
    const erpcHome = join(parent, '.erpc')
    const output: string[] = []

    await expect(runCli(
      ['app', 'init', 'managed-api', '--runtime', 'node'],
      {
        cwd: parent,
        erpcHome,
        output: (message) => output.push(message),
      },
    )).resolves.toBe(0)

    await expect(readFile(
      join(erpcHome, 'apps', 'managed-api', 'erpc.toml'),
      'utf8',
    )).resolves.toContain('name = "managed-api"')

    output.length = 0
    await expect(runCli(
      ['app', 'list'],
      { erpcHome, output: (message) => output.push(message) },
    )).resolves.toBe(0)
    expect(output).toHaveLength(1)
    expect(output[0]).toContain('managed-api\tnode\tauto')
  })

  it('registers an explicitly located application in config.toml', async () => {
    const parent = await temporaryDirectory()
    const erpcHome = join(parent, '.erpc')
    const external = join(parent, 'workspace', 'external-api')

    await expect(runCli(
      ['app', 'init', external, '--runtime', 'deno'],
      { erpcHome, output: () => undefined },
    )).resolves.toBe(0)

    const config = await readErpcConfig({ erpcHome })
    expect(config.apps).toEqual([{
      config: join(external, 'erpc.toml'),
      name: 'external-api',
    }])
  })
})
