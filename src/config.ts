import {
  chmod,
  mkdir,
  readFile,
  rename,
  writeFile,
} from 'node:fs/promises'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { parse, stringify } from 'smol-toml'

const NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
const SSH_HOST = /^[A-Za-z0-9._:[\]%-]+$/
const SSH_USER = /^[A-Za-z_][A-Za-z0-9._-]{0,63}$/

export interface ErpcNodeConfig {
  readonly host: string
  readonly identityFile?: string
  readonly port: number
  readonly user: string
}

export interface ErpcAppRegistration {
  readonly config: string
  readonly name: string
}

export interface ErpcLocalConfig {
  readonly apps: readonly ErpcAppRegistration[]
  readonly appsDirectory: string
  readonly configPath: string
  readonly erpcHome: string
  readonly nodes: Readonly<Record<string, ErpcNodeConfig>>
  readonly schemaVersion: 1
}

export interface ErpcConfigOptions {
  readonly erpcHome?: string
}

const objectValue = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null

const expandHome = (value: string): string => value === '~'
  ? homedir()
  : value.startsWith('~/')
    ? join(homedir(), value.slice(2))
    : value

export const resolveErpcHome = (options: ErpcConfigOptions = {}): string =>
  resolve(
    options.erpcHome ?? process.env.ERPC_HOME ?? join(homedir(), '.erpc'),
  )

const initialConfig = (appsDirectory: string): string =>
  `schema_version = 1\napps_directory = ${JSON.stringify(appsDirectory)}\n`

export const ensureErpcConfig = async (
  options: ErpcConfigOptions = {},
): Promise<string> => {
  const erpcHome = resolveErpcHome(options)
  const appsDirectory = join(erpcHome, 'apps')
  const configPath = join(erpcHome, 'config.toml')
  await mkdir(appsDirectory, { mode: 0o700, recursive: true })
  try {
    await writeFile(configPath, initialConfig(appsDirectory), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) {
      throw error
    }
  }
  await chmod(erpcHome, 0o700)
  await chmod(configPath, 0o600)
  return configPath
}

const parseNode = (name: string, value: unknown): ErpcNodeConfig => {
  if (!NAME.test(name)) throw new Error(`Invalid node name in config.toml: ${name}`)
  const node = objectValue(value)
  if (!node) throw new Error(`Node ${name} must be a TOML table`)
  const { host, identity_file: identityFile, port = 22, user } = node
  if (
    typeof host !== 'string' ||
    !SSH_HOST.test(host) ||
    typeof user !== 'string' ||
    !SSH_USER.test(user) ||
    typeof port !== 'number' ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    (identityFile !== undefined && typeof identityFile !== 'string')
  ) {
    throw new Error(`Node ${name} has invalid SSH settings`)
  }
  return {
    host,
    port,
    user,
    ...(typeof identityFile === 'string'
      ? { identityFile: resolve(expandHome(identityFile)) }
      : {}),
  }
}

const parseApp = (value: unknown): ErpcAppRegistration => {
  const app = objectValue(value)
  if (
    !app ||
    typeof app.name !== 'string' ||
    !NAME.test(app.name) ||
    typeof app.config !== 'string'
  ) throw new Error('config.toml contains an invalid app registration')
  const expanded = expandHome(app.config)
  if (!isAbsolute(expanded)) throw new Error('Registered app config must be absolute')
  const config = resolve(expanded)
  return { config, name: app.name }
}

export const readErpcConfig = async (
  options: ErpcConfigOptions = {},
): Promise<ErpcLocalConfig> => {
  const configPath = await ensureErpcConfig(options)
  let document: Record<string, unknown>
  try {
    document = parse(await readFile(configPath, 'utf8')) as Record<string, unknown>
  } catch {
    throw new Error(`Unable to parse ERPC config: ${configPath}`)
  }
  if (document.schema_version !== 1) {
    throw new Error('Unsupported ERPC config schema_version')
  }
  const erpcHome = resolveErpcHome(options)
  const configuredAppsDirectory = document.apps_directory
  if (typeof configuredAppsDirectory !== 'string') {
    throw new Error('config.toml apps_directory must be a path')
  }
  const appsDirectory = resolve(expandHome(configuredAppsDirectory))
  const rawNodes = document.nodes === undefined
    ? {}
    : objectValue(document.nodes)
  if (!rawNodes) throw new Error('config.toml nodes must be a TOML table')
  const nodes = Object.fromEntries(
    Object.entries(rawNodes).map(([name, value]) => [name, parseNode(name, value)]),
  )
  const rawApps = document.apps === undefined ? [] : document.apps
  if (!Array.isArray(rawApps)) throw new Error('config.toml apps must be an array')
  const apps = rawApps.map(parseApp)
  return {
    apps,
    appsDirectory,
    configPath,
    erpcHome,
    nodes,
    schemaVersion: 1,
  }
}

const serializableConfig = (config: ErpcLocalConfig) => ({
  schema_version: 1,
  apps_directory: config.appsDirectory,
  nodes: Object.fromEntries(
    Object.entries(config.nodes).map(([name, node]) => [name, {
      host: node.host,
      user: node.user,
      port: node.port,
      ...(node.identityFile === undefined
        ? {}
        : { identity_file: node.identityFile }),
    }]),
  ),
  apps: config.apps.map((app) => ({ name: app.name, config: app.config })),
})

export const writeErpcConfig = async (config: ErpcLocalConfig): Promise<void> => {
  const temporary = `${config.configPath}.tmp-${process.pid}-${Date.now()}`
  await writeFile(temporary, stringify(serializableConfig(config)), {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  })
  await rename(temporary, config.configPath)
  await chmod(config.configPath, 0o600)
}

export const registerErpcApplication = async (
  registration: ErpcAppRegistration,
  options: ErpcConfigOptions = {},
): Promise<void> => {
  const config = await readErpcConfig(options)
  const normalized = { ...registration, config: resolve(registration.config) }
  const apps = [
    ...config.apps.filter((app) => app.config !== normalized.config),
    normalized,
  ].sort((left, right) => left.name.localeCompare(right.name))
  await writeErpcConfig({ ...config, apps })
}
