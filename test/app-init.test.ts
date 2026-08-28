import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from './testing.ts'
import { createAppTemplate, initializeApp, runCli } from '../src/index.ts'

const directories: string[] = []

const temporaryDirectory = async () => {
  const directory = await mkdtemp(join(tmpdir(), 'erpc-app-init-'))
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

describe('app init', () => {
  it.each(
    [
      ['node', 'node-hono-example', 'node-hono'],
      ['deno', 'deno-hono-example', 'deno-hono'],
    ] as const,
  )(
    'keeps the %s example synchronized with the generated template',
    async (runtime, name, exampleDirectory) => {
      const template = createAppTemplate(name, runtime)
      for (const [relativePath, contents] of Object.entries(template.files)) {
        const file = new URL(
          `../examples/${exampleDirectory}/${relativePath}`,
          import.meta.url,
        )
        await expect(readFile(file, 'utf8')).resolves.toBe(contents)
      }
    },
  )

  it('creates a Node Hono app and records the runtime in erpc.toml', async () => {
    const parent = await temporaryDirectory()
    const directory = join(parent, 'node-service')

    const result = await initializeApp({ directory, runtime: 'node' })

    expect(result.runtime).toBe('node')
    expect(result.files).toContain('package.json')
    expect(await readFile(join(directory, 'erpc.toml'), 'utf8')).toContain(
      'runtime = "node"',
    )
    expect(await readFile(join(directory, 'src/app.ts'), 'utf8')).toContain(
      "from 'hono'",
    )
  })

  it('creates a Deno Hono app through the non-interactive CLI flag', async () => {
    const parent = await temporaryDirectory()
    const directory = join(parent, 'deno-service')
    const output: string[] = []

    await expect(runCli([
      'app',
      'init',
      directory,
      '--runtime',
      'deno',
    ], {
      erpcHome: join(parent, '.erpc'),
      output: (message) => output.push(message),
    })).resolves.toBe(0)

    expect(await readFile(join(directory, 'erpc.toml'), 'utf8')).toContain(
      'runtime = "deno"',
    )
    expect(await readFile(join(directory, 'deno.json'), 'utf8')).toContain(
      'jsr:@hono/hono',
    )
    expect(output[0]).toContain('deno runtime')
  })

  it('never overwrites a non-empty target directory', async () => {
    const parent = await temporaryDirectory()
    const directory = join(parent, 'existing-service')
    await mkdir(directory)
    await writeFile(join(directory, 'important.txt'), 'keep me')

    await expect(
      initializeApp({ directory, runtime: 'node' }),
    ).rejects.toThrow('Refusing to overwrite non-empty directory')
    await expect(readFile(join(directory, 'important.txt'), 'utf8')).resolves
      .toBe('keep me')
  })

  it('shows app-specific help without prompting for a runtime', async () => {
    const output: string[] = []
    await expect(runCli(
      ['app', 'init', '--help'],
      { output: (message) => output.push(message) },
    )).resolves.toBe(0)
    expect(output.join('\n')).toContain('erpc app init')
  })

  it('rejects ambiguous initializer arguments', async () => {
    await expect(runCli([
      'app',
      'init',
      'first',
      'second',
      '--runtime',
      'node',
    ])).rejects.toThrow('only one directory')
    await expect(runCli([
      'app',
      'init',
      '--runtime',
    ])).rejects.toThrow('--runtime requires a value')
    await expect(runCli([
      'app',
      'init',
      '--unknown',
    ])).rejects.toThrow('Unknown option')
  })
})

describe('CLI metadata', () => {
  it('keeps Cloud billing and resource write commands explicitly unavailable', async () => {
    const output: string[] = []
    await expect(runCli(
      ['--help'],
      { output: (message) => output.push(message) },
    )).resolves.toBe(0)
    expect(output.join('\n')).toContain(
      'Cloud billing and resource write commands are unavailable',
    )
  })

  it('prints its package version', async () => {
    const output: string[] = []
    await expect(runCli(
      ['--version'],
      { output: (message) => output.push(message) },
    )).resolves.toBe(0)
    expect(output).toEqual(['0.2.0'])
  })
})
