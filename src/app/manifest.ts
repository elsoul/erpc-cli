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

const SHA256_HEX = /^[0-9a-f]{64}$/

/**
 * The `erpc.toml` contract `erpc app init --template` produces.
 * `run`/`build.artifact` do not apply: `erpc deploy --target cloudflare`
 * never runs a local build artifact the way the node/deno SSH deploy path
 * does.
 */
export interface CloudflareWorkerManifest {
  readonly app: {
    readonly entrypoint: string
    readonly runtime: 'cloudflare-worker'
  }
  readonly build?: {
    readonly command: readonly string[]
  }
  readonly cloudflare: {
    readonly config: string
    readonly wrangler: readonly string[]
  }
  readonly configPath: string
  readonly deploy: {
    readonly target: string
  }
  readonly health: {
    readonly timeoutSeconds: number
  }
  readonly name: string
  readonly oidc?: {
    readonly clientId: string
    readonly issuer: string
    readonly redirectUris: readonly string[]
  }
  readonly projectRoot: string
  readonly schemaVersion: 1
  readonly template: {
    readonly asset: string
    readonly name: string
    readonly ref: string
    readonly sha256: string
    readonly source: string
  }
}

const stringArray = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.length > 0 &&
  value.every((item) => typeof item === 'string' && item.length > 0)

const parseCloudflareWorkerManifest = (
  document: Record<string, unknown>,
  absoluteConfig: string,
): CloudflareWorkerManifest => {
  const app = objectValue(document.app)
  const cloudflare = objectValue(document.cloudflare)
  const deploy = objectValue(document.deploy)
  const health = objectValue(document.health)
  const template = objectValue(document.template)
  const build = document.build === undefined
    ? undefined
    : objectValue(document.build)
  const oidc = document.oidc === undefined
    ? undefined
    : objectValue(document.oidc)
  const invalid = new Error(`Invalid ERPC manifest contract: ${absoluteConfig}`)

  if (
    document.schema_version !== 1 ||
    typeof document.name !== 'string' || !APP_NAME.test(document.name) ||
    !app || app.runtime !== 'cloudflare-worker' ||
    typeof app.entrypoint !== 'string' || !app.entrypoint ||
    !cloudflare ||
    typeof cloudflare.config !== 'string' || !cloudflare.config ||
    !stringArray(cloudflare.wrangler) ||
    !deploy || typeof deploy.target !== 'string' || !deploy.target ||
    !health || typeof health.timeout_seconds !== 'number' ||
    !Number.isInteger(health.timeout_seconds) || health.timeout_seconds < 1 ||
    !template ||
    typeof template.name !== 'string' || !template.name ||
    typeof template.source !== 'string' || !template.source ||
    typeof template.ref !== 'string' || !template.ref ||
    typeof template.asset !== 'string' || !template.asset ||
    typeof template.sha256 !== 'string' || !SHA256_HEX.test(template.sha256) ||
    (document.build !== undefined && (!build || !stringArray(build.command))) ||
    (document.oidc !== undefined && (
      !oidc ||
      typeof oidc.issuer !== 'string' || !oidc.issuer ||
      typeof oidc.client_id !== 'string' || !oidc.client_id ||
      !stringArray(oidc.redirect_uris)
    ))
  ) throw invalid

  return {
    app: { entrypoint: app.entrypoint, runtime: 'cloudflare-worker' },
    ...(build
      ? { build: { command: build.command as readonly string[] } }
      : {}),
    cloudflare: {
      config: cloudflare.config,
      wrangler: cloudflare.wrangler as readonly string[],
    },
    configPath: absoluteConfig,
    deploy: { target: deploy.target },
    health: { timeoutSeconds: health.timeout_seconds },
    name: document.name,
    ...(oidc
      ? {
        oidc: {
          clientId: oidc.client_id as string,
          issuer: oidc.issuer as string,
          redirectUris: oidc.redirect_uris as readonly string[],
        },
      }
      : {}),
    projectRoot: dirname(absoluteConfig),
    schemaVersion: 1,
    template: {
      asset: template.asset,
      name: template.name,
      ref: template.ref,
      sha256: template.sha256,
      source: template.source,
    },
  }
}

/**
 * Loads an `erpc.toml` whose `[app].runtime` may be `node`, `deno`, or
 * `cloudflare-worker`. `node`/`deno` manifests keep the exact
 * `loadErpcManifest` contract unchanged; this only adds the
 * `cloudflare-worker` branch on top.
 */
export const loadAnyErpcManifest = async (
  configPath: string,
): Promise<ErpcManifest | CloudflareWorkerManifest> => {
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
  if (app?.runtime === 'cloudflare-worker') {
    return parseCloudflareWorkerManifest(document, absoluteConfig)
  }
  return await loadErpcManifest(configPath)
}
