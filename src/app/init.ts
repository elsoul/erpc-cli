import { mkdir, readdir, writeFile } from 'node:fs/promises'
import { basename, dirname, resolve } from 'node:path'
import { type AppRuntime, createAppTemplate } from './templates.ts'

export interface InitializeAppOptions {
  readonly directory: string
  readonly name?: string
  readonly runtime: AppRuntime
}

export interface InitializedApp {
  readonly directory: string
  readonly files: readonly string[]
  readonly installCommand: string
  readonly name: string
  readonly runtime: AppRuntime
  readonly startCommand: string
}

const APP_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/

export const initializeApp = async (
  options: InitializeAppOptions,
): Promise<InitializedApp> => {
  const directory = resolve(options.directory)
  const name = options.name ?? basename(directory)
  if (!APP_NAME.test(name)) {
    throw new Error(
      'App name must contain lowercase letters, numbers, and single hyphens',
    )
  }

  await mkdir(directory, { recursive: true })
  const existing = await readdir(directory)
  if (existing.length > 0) {
    throw new Error(`Refusing to overwrite non-empty directory: ${directory}`)
  }

  const template = createAppTemplate(name, options.runtime)
  const files = Object.entries(template.files).sort(([left], [right]) =>
    left.localeCompare(right)
  )
  for (const [relativePath, contents] of files) {
    const destination = resolve(directory, relativePath)
    if (!destination.startsWith(`${directory}/`)) {
      throw new Error('Template path escaped the application directory')
    }
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, contents, { encoding: 'utf8', flag: 'wx' })
  }

  return {
    directory,
    files: files.map(([path]) => path),
    installCommand: template.installCommand,
    name,
    runtime: template.runtime,
    startCommand: template.startCommand,
  }
}
