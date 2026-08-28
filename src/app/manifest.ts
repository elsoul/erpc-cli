import { readFile, stat } from 'node:fs/promises'
import {
  dirname,
  isAbsolute,
  join,
  parse as parsePath,
  relative,
  resolve,
} from 'node:path'
import { parse } from '@std/toml'
import type { AppRuntime } from './templates.ts'

const APP_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
const LISTEN_HOST = /^[A-Za-z0-9._:[\]%-]+$/

export interface ErpcManifest {
  readonly app: {
    readonly entrypoint: string
    readonly runtime: AppRuntime
  }
  readonly build: {
    readonly artifact: string
    readonly command: readonly string[]
  }
  readonly configPath: string
  readonly deploy: {
    readonly target: string
  }
  readonly health: {
    readonly path: string
    readonly timeoutSeconds: number
  }
  readonly name: string
  readonly projectRoot: string
  readonly run: {
    readonly command: readonly string[]
    readonly host: string
    readonly port: number
  }
  readonly schemaVersion: 1
}

const objectValue = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null

const relativeProjectPath = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || !value || isAbsolute(value)) {
    throw new Error(`${field} must be a non-empty relative path`)
  }
  const normalized = relative('.', value)
  if (
    normalized === '..' ||
    normalized.startsWith(`..${Deno.build.os === 'windows' ? '\\' : '/'}`)
  ) {
    throw new Error(`${field} must stay inside the application root`)
  }
  return value
}

const command = (value: unknown, field: string): readonly string[] => {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((item) =>
      typeof item === 'string' && item.length > 0 && !item.includes('\0')
    )
  ) throw new Error(`${field} must be a non-empty argument array`)
  return value as readonly string[]
}

export const loadErpcManifest = async (
  configPath: string,
): Promise<ErpcManifest> => {
  const absoluteConfig = resolve(configPath)
  let document: Record<string, unknown>
  try {
    document = parse(await readFile(absoluteConfig, 'utf8')) as Record<
      string,
      unknown
    >
  } catch {
    throw new Error(`Unable to parse ERPC manifest: ${absoluteConfig}`)
  }
  const app = objectValue(document.app)
  const build = objectValue(document.build)
  const run = objectValue(document.run)
  const deploy = objectValue(document.deploy)
  const health = objectValue(document.health)
  if (
    document.schema_version !== 1 ||
    typeof document.name !== 'string' ||
    !APP_NAME.test(document.name) ||
    !app ||
    (app.runtime !== 'node' && app.runtime !== 'deno') ||
    !build ||
    !run ||
    !deploy ||
    !health ||
    typeof run.host !== 'string' ||
    !LISTEN_HOST.test(run.host) ||
    typeof run.port !== 'number' ||
    !Number.isInteger(run.port) ||
    run.port < 1 ||
    run.port > 65_535 ||
    typeof deploy.target !== 'string' ||
    !deploy.target ||
    typeof health.path !== 'string' ||
    !health.path.startsWith('/') ||
    typeof health.timeout_seconds !== 'number' ||
    !Number.isInteger(health.timeout_seconds) ||
    health.timeout_seconds < 1
  ) throw new Error(`Invalid ERPC manifest contract: ${absoluteConfig}`)

  return {
    app: {
      entrypoint: relativeProjectPath(app.entrypoint, 'app.entrypoint'),
      runtime: app.runtime,
    },
    build: {
      artifact: relativeProjectPath(build.artifact, 'build.artifact'),
      command: command(build.command, 'build.command'),
    },
    configPath: absoluteConfig,
    deploy: { target: deploy.target },
    health: {
      path: health.path,
      timeoutSeconds: health.timeout_seconds,
    },
    name: document.name,
    projectRoot: dirname(absoluteConfig),
    run: {
      command: command(run.command, 'run.command'),
      host: run.host,
      port: run.port,
    },
    schemaVersion: 1,
  }
}

const isDirectory = async (path: string): Promise<boolean> => {
  try {
    return (await stat(path)).isDirectory()
  } catch {
    return false
  }
}

export const findErpcManifest = async (
  cwd: string,
  explicit?: string,
): Promise<string> => {
  if (explicit !== undefined) {
    const selected = resolve(cwd, explicit)
    return await isDirectory(selected) ? join(selected, 'erpc.toml') : selected
  }
  let directory = resolve(cwd)
  while (true) {
    const candidate = join(directory, 'erpc.toml')
    try {
      if ((await stat(candidate)).isFile()) return candidate
    } catch {
      // Continue toward the filesystem root.
    }
    const parent = parsePath(directory).root === directory
      ? directory
      : dirname(directory)
    if (parent === directory) break
    directory = parent
  }
  throw new Error('No erpc.toml found in the current directory or its parents')
}
