import { Command, EnumType } from '@cliffy/command'
import { basename, isAbsolute, join, relative, resolve } from 'node:path'
import { CLI_VERSION } from './version.ts'
import { CloudApiClient } from './cloud.ts'
import {
  DeviceAuthClient,
  ERPC_CLOUD_SCOPES,
  type ErpcCloudScope,
} from './auth/device.ts'
import { CliAuthSession } from './auth/session.ts'
import {
  KeyringRefreshTokenStore,
  type RefreshTokenStore,
} from './auth/token-store.ts'
import { initializeApp } from './app/init.ts'
import {
  type CloudflareWorkerManifest,
  type ErpcManifest,
  findErpcManifest,
  loadAnyErpcManifest,
} from './app/manifest.ts'
import { promptForRuntime, promptForTemplateOrRuntime } from './app/prompt.ts'
import { defaultPromptIO, type PromptIO } from './app/prompt-io.ts'
import { listErpcApplications } from './app/registry.ts'
import { APP_RUNTIMES, type AppRuntime } from './app/templates.ts'
import {
  isValidSha256Hex,
  isValidTemplateTag,
  parseTemplateRef,
  TEMPLATE_TAG_PATTERN,
} from './app/template-ref.ts'
import {
  defaultOidcClientRegistrar,
  initializeTemplateApp,
  type OidcClientRegistrar,
} from './app/template-init.ts'
import {
  TEMPLATE_REGISTRY,
  type TemplateRegistry,
} from './app/template-registry.ts'
import { readErpcConfig, registerErpcApplication } from './config.ts'
import { buildForDeployment } from './deploy/build.ts'
import { deployOverSsh } from './deploy/ssh.ts'
import { resolveVerifiedNodeRuntime } from './deploy/node-runtime.ts'
import { deployToCloudflare } from './deploy/cloudflare.ts'
import type { ProcessRunner } from './process.ts'
import { erpcAA, erpcWelcomeMessage } from './ui/welcome.ts'

export interface CliDependencies {
  readonly auth?: DeviceAuthClient
  readonly cwd?: string
  readonly erpcHome?: string
  readonly fetch?: typeof globalThis.fetch
  readonly oidcRegistrar?: OidcClientRegistrar
  readonly openExternal?: (url: string) => void
  readonly output?: (message: string) => void
  readonly promptIO?: PromptIO
  /**
   * `crypto.getRandomValues`'s signature. Forwarded into
   * `erpc deploy --target cloudflare`'s secret generation and post-deploy
   * PKCE probe so a test can inject deterministic bytes instead of real
   * entropy (packet Decision 10, Acceptance A11).
   */
  readonly random?: (bytes: Uint8Array<ArrayBuffer>) => void
  readonly runProcess?: ProcessRunner
  /**
   * Forwarded into `initializeTemplateApp`'s broker-register call so a
   * caller wiring its own cancellation (for example an `AbortController`
   * tied to `SIGINT`) can cut short the device-flow poll instead of it
   * running to its own timeout (packet Decision 8).
   */
  readonly signal?: AbortSignal
  readonly store?: RefreshTokenStore
  readonly templateRegistry?: TemplateRegistry
}

const help = `ERPC CLI

Usage:
  erpc --version
  erpc login [--no-open] [--scope <scope>]
  erpc logout
  erpc usage monthly [YYYY-MM]
  erpc credit
  erpc resources catalog
  erpc resources list
  erpc resources get <resource-id>
  erpc resources status <resource-id>
  erpc app init [directory] [--runtime node|deno] [--name app-name]
  erpc app init [directory] --template <name>@<tag> [--sha256 <hex>] [--set KEY=VALUE]...
  erpc app list
  erpc deploy [--config path/to/erpc.toml] [--node node-name]
  erpc deploy [--config path/to/erpc.toml] [--target cloudflare] [--yes]
    [--ack-backup <KEY>]... [--no-provision] [--dry-run] [--verify-only]

Cloud billing and resource write commands are unavailable until their authorization and confirmation contracts are enabled.`

const appInitHelp = `Create a minimal ERPC application

Usage:
  erpc app init [directory] [--runtime node|deno] [--name app-name]
  erpc app init [directory] --template <name>@<tag> [--sha256 <hex64>]
    [--set KEY=VALUE]... [--domain <value>] [--email <value>]
    [--trust-issuer <origin>] [--yes]

Bare names are created below ~/.erpc/apps. Paths are created where specified.
When neither --runtime nor --template is given in a terminal, the CLI asks
you to choose. --runtime and --template are mutually exclusive.

--template fetches a registered template's GitHub release asset, verifies it
against a pinned or explicitly supplied --sha256, and answers its prompts
from --set/--domain/--email or interactively. Non-interactive runs require
--yes and fail with every missing or invalid answer listed together.`

export const defaultOpenExternal = (url: string): void => {
  const platform = Deno.build.os
  const [command, args] = platform === 'darwin'
    ? ['open', [url]]
    : platform === 'windows'
    ? ['cmd', ['/c', 'start', '', url]]
    : ['xdg-open', [url]]
  try {
    const child = new Deno.Command(command, {
      args,
      stdin: 'null',
      stdout: 'null',
      stderr: 'null',
    }).spawn()
    child.unref()
  } catch {
    // The verification URL is always printed, so browser launch is best effort.
  }
}

const parseScopes = (args: readonly string[]): readonly ErpcCloudScope[] => {
  const requested: ErpcCloudScope[] = []
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--no-open') continue
    if (args[index] !== '--scope') {
      throw new Error(`Unknown login option: ${args[index]}`)
    }
    const value = args[index + 1]
    if (!value || !ERPC_CLOUD_SCOPES.includes(value as ErpcCloudScope)) {
      throw new Error(`Unsupported Cloud scope: ${value ?? '(missing)'}`)
    }
    requested.push(value as ErpcCloudScope)
    index++
  }
  return requested
}

const parseRuntime = (value: string | undefined): AppRuntime | undefined => {
  if (value === undefined) return undefined
  if (APP_RUNTIMES.includes(value as AppRuntime)) return value as AppRuntime
  throw new Error('Runtime must be node or deno')
}

/** Parses the leading `vMAJOR.MINOR.PATCH` for ordering tags; unparsable tags sort first. */
const semverSortKey = (value: string): readonly [number, number, number] => {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(value)
  if (!match) return [-1, -1, -1]
  return [Number(match[1]), Number(match[2]), Number(match[3])]
}

const compareSemver = (a: string, b: string): number => {
  const [aMajor, aMinor, aPatch] = semverSortKey(a)
  const [bMajor, bMinor, bPatch] = semverSortKey(b)
  return (aMajor - bMajor) || (aMinor - bMinor) || (aPatch - bPatch)
}

/** Interactively asks for a tag (and, when unpinned, a sha256) after the user picks a template by name. */
const promptForTemplateTagAndSha256 = async (
  promptIO: PromptIO,
  registry: TemplateRegistry,
  name: string,
): Promise<{ readonly sha256?: string; readonly tag: string }> => {
  // `Object.hasOwn` (not bracket access) so a template named e.g.
  // "constructor" can't resolve through the prototype chain.
  const entry = Object.hasOwn(registry, name) ? registry[name] : undefined
  const pinnedTags = entry ? Object.keys(entry.pins).sort(compareSemver) : []
  const suggestion = pinnedTags.at(-1) // highest semver, not lexicographically last
  const tag = await promptIO.text(
    pinnedTags.length > 0
      ? `Tag for ${name} (pinned: ${pinnedTags.join(', ')})`
      : `Tag for ${name} (for example v0.1.0)`,
    {
      ...(suggestion === undefined ? {} : { default: suggestion }),
      validate: (value) =>
        isValidTemplateTag(value) ||
        `Must match ${TEMPLATE_TAG_PATTERN} (for example v0.1.0)`,
    },
  )
  const pinnedSha256 = entry && Object.hasOwn(entry.pins, tag)
    ? entry.pins[tag]
    : undefined
  if (pinnedSha256 !== undefined) return { tag }
  const sha256 = await promptIO.text(
    `sha256 for ${name}@${tag} (this tag is not pinned by this CLI; 64 hex characters)`,
    {
      validate: (value) =>
        isValidSha256Hex(value) || 'Must be 64 lowercase hex characters',
    },
  )
  return { sha256, tag }
}

interface AppInitArguments {
  readonly directory?: string
  readonly domainValue?: string
  readonly emailValue?: string
  readonly name?: string
  readonly runtime?: AppRuntime
  readonly setValues: ReadonlyMap<string, string>
  readonly sha256?: string
  readonly template?: string
  readonly trustIssuer?: string
  readonly yes: boolean
}

const VALUED_APP_INIT_OPTIONS = [
  '--runtime',
  '--name',
  '--template',
  '--sha256',
  '--set',
  '--domain',
  '--email',
  '--trust-issuer',
] as const

const parseAppInitArguments = (
  args: readonly string[],
): AppInitArguments => {
  let directory: string | undefined
  let name: string | undefined
  let runtime: AppRuntime | undefined
  let template: string | undefined
  let sha256: string | undefined
  let domainValue: string | undefined
  let emailValue: string | undefined
  let trustIssuer: string | undefined
  let yes = false
  const setValues = new Map<string, string>()

  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (value === '--yes') {
      yes = true
      continue
    }
    if ((VALUED_APP_INIT_OPTIONS as readonly string[]).includes(value ?? '')) {
      const optionValue = args[index + 1]
      if (!optionValue || optionValue.startsWith('-')) {
        throw new Error(`${value} requires a value`)
      }
      switch (value) {
        case '--runtime':
          if (runtime !== undefined) {
            throw new Error('--runtime may be used once')
          }
          runtime = parseRuntime(optionValue)
          break
        case '--name':
          if (name !== undefined) throw new Error('--name may be used once')
          name = optionValue
          break
        case '--template':
          if (template !== undefined) {
            throw new Error('--template may be used once')
          }
          template = optionValue
          break
        case '--sha256':
          if (sha256 !== undefined) throw new Error('--sha256 may be used once')
          if (!isValidSha256Hex(optionValue)) {
            throw new Error('--sha256 must be 64 lowercase hex characters')
          }
          sha256 = optionValue
          break
        case '--domain':
          if (domainValue !== undefined) {
            throw new Error('--domain may be used once')
          }
          domainValue = optionValue
          break
        case '--email':
          if (emailValue !== undefined) {
            throw new Error('--email may be used once')
          }
          emailValue = optionValue
          break
        case '--trust-issuer':
          if (trustIssuer !== undefined) {
            throw new Error('--trust-issuer may be used once')
          }
          trustIssuer = optionValue
          break
        case '--set': {
          const equalsIndex = optionValue.indexOf('=')
          if (equalsIndex <= 0) {
            throw new Error('--set requires KEY=VALUE')
          }
          setValues.set(
            optionValue.slice(0, equalsIndex),
            optionValue.slice(equalsIndex + 1),
          )
          break
        }
      }
      index++
      continue
    }
    if (value?.startsWith('-')) throw new Error(`Unknown option: ${value}`)
    if (value === undefined) continue
    if (directory !== undefined) {
      throw new Error('app init accepts only one directory')
    }
    directory = value
  }

  if (runtime !== undefined && template !== undefined) {
    throw new Error('--runtime and --template are mutually exclusive')
  }

  return {
    ...(directory === undefined ? {} : { directory }),
    ...(domainValue === undefined ? {} : { domainValue }),
    ...(emailValue === undefined ? {} : { emailValue }),
    ...(name === undefined ? {} : { name }),
    ...(runtime === undefined ? {} : { runtime }),
    setValues,
    ...(sha256 === undefined ? {} : { sha256 }),
    ...(template === undefined ? {} : { template }),
    ...(trustIssuer === undefined ? {} : { trustIssuer }),
    yes,
  }
}

interface DeployArguments {
  readonly ackBackup: readonly string[]
  readonly config?: string
  readonly dryRun: boolean
  readonly node?: string
  readonly noProvision: boolean
  readonly target?: string
  readonly verifyOnly: boolean
  readonly yes: boolean
}

const DEPLOY_VALUED_OPTIONS = [
  '--config',
  '--node',
  '--target',
  '--ack-backup',
] as const

const parseDeployArguments = (args: readonly string[]): DeployArguments => {
  let config: string | undefined
  let node: string | undefined
  let target: string | undefined
  let dryRun = false
  let noProvision = false
  let verifyOnly = false
  let yes = false
  const ackBackup: string[] = []
  for (let index = 0; index < args.length; index++) {
    const option = args[index]
    if (option === '--yes') {
      yes = true
      continue
    }
    if (option === '--no-provision') {
      noProvision = true
      continue
    }
    if (option === '--dry-run') {
      dryRun = true
      continue
    }
    if (option === '--verify-only') {
      verifyOnly = true
      continue
    }
    if (!(DEPLOY_VALUED_OPTIONS as readonly string[]).includes(option ?? '')) {
      throw new Error(`Unknown deploy option: ${option}`)
    }
    const value = args[index + 1]
    if (!value || value.startsWith('-')) {
      throw new Error(`${option} requires a value`)
    }
    if (option === '--config') {
      if (config !== undefined) throw new Error('--config may be used once')
      config = value
    } else if (option === '--node') {
      if (node !== undefined) throw new Error('--node may be used once')
      node = value
    } else if (option === '--target') {
      if (target !== undefined) throw new Error('--target may be used once')
      target = value
    } else {
      ackBackup.push(value)
    }
    index++
  }
  return {
    ackBackup,
    ...(config === undefined ? {} : { config }),
    dryRun,
    ...(node === undefined ? {} : { node }),
    noProvision,
    ...(target === undefined ? {} : { target }),
    verifyOnly,
    yes,
  }
}

const pathLike = (value: string): boolean =>
  isAbsolute(value) ||
  value.startsWith('.') ||
  value.includes('/') ||
  value.includes('\\')

const insideDirectory = (parent: string, child: string): boolean => {
  const path = relative(parent, child)
  return path === '' || (!path.startsWith('..') && !isAbsolute(path))
}

/**
 * `loadAnyErpcManifest`'s union discriminates on `app.runtime`, which sits
 * one property below the union's root - some TypeScript versions do not
 * narrow through that automatically, so this predicate makes the narrowing
 * explicit at both call sites below.
 */
const isCloudflareWorkerManifest = (
  manifest: ErpcManifest | CloudflareWorkerManifest,
): manifest is CloudflareWorkerManifest =>
  manifest.app.runtime === 'cloudflare-worker'

const executeCliCommand = async (
  args: readonly string[],
  dependencies: CliDependencies = {},
): Promise<number> => {
  const output = dependencies.output ?? console.log
  const [command, subcommand] = args
  const cwd = resolve(dependencies.cwd ?? Deno.cwd())
  const configOptions = dependencies.erpcHome === undefined
    ? {}
    : { erpcHome: dependencies.erpcHome }

  const createAuth = () => {
    const authEndpoint = Deno.env.get('ERPC_AUTH_ENDPOINT')
    return dependencies.auth ?? new DeviceAuthClient({
      ...(authEndpoint === undefined ? {} : { endpoint: authEndpoint }),
    })
  }
  const createStore = () => dependencies.store ?? new KeyringRefreshTokenStore()

  if (
    !command || command === 'help' || command === '--help' || command === '-h'
  ) {
    output(help)
    return 0
  }

  if (command === '--version' || command === '-v' || command === 'version') {
    output(CLI_VERSION)
    return 0
  }

  if (command === 'login') {
    const auth = createAuth()
    const store = createStore()
    const authorization = await auth.startLogin(parseScopes(args.slice(1)))
    output(`Open ${authorization.verificationUriComplete}`)
    output(`Device code: ${authorization.userCode}`)
    if (!args.includes('--no-open')) {
      ;(dependencies.openExternal ?? defaultOpenExternal)(
        authorization.verificationUriComplete,
      )
    }
    const tokens = await auth.poll(authorization)
    try {
      await store.set(tokens.refreshToken)
    } catch (error) {
      await auth.revoke(tokens.refreshToken).catch(() => undefined)
      throw error
    }
    output(
      'Logged in to ERPC. The refresh credential is stored in the OS keychain.',
    )
    return 0
  }

  if (command === 'logout') {
    if (args.length !== 1) throw new Error('logout does not accept arguments')
    const session = new CliAuthSession(createAuth(), createStore())
    const revoked = await session.logout()
    output(revoked ? 'Logged out of ERPC.' : 'No ERPC login was stored.')
    return 0
  }

  if (command === 'usage' && subcommand === 'monthly') {
    if (args.length > 3) {
      throw new Error('usage monthly accepts only an optional YYYY-MM value')
    }
    const session = new CliAuthSession(createAuth(), createStore())
    const yearMonth = args[2]
    const accessToken = await session.getAccessToken()
    const userEndpoint = Deno.env.get('ERPC_USER_ENDPOINT')
    const cloud = new CloudApiClient({
      accessToken,
      ...(userEndpoint === undefined ? {} : { endpoint: userEndpoint }),
    })
    const usage = await cloud.getMonthlyApiKeyUsage(
      yearMonth ? { yearMonth } : {},
    )
    output(JSON.stringify(usage, null, 2))
    return 0
  }

  if (command === 'resources' && subcommand === 'list') {
    if (args.length !== 2) {
      throw new Error('resources list does not accept arguments')
    }
    const session = new CliAuthSession(createAuth(), createStore())
    const accessToken = await session.getAccessToken()
    const userEndpoint = Deno.env.get('ERPC_USER_ENDPOINT')
    const cloud = new CloudApiClient({
      accessToken,
      ...(userEndpoint === undefined ? {} : { endpoint: userEndpoint }),
    })
    output(JSON.stringify(await cloud.listResources(), null, 2))
    return 0
  }

  if (command === 'resources' && subcommand === 'catalog') {
    if (args.length !== 2) {
      throw new Error('resources catalog does not accept arguments')
    }
    const session = new CliAuthSession(createAuth(), createStore())
    const accessToken = await session.getAccessToken()
    const userEndpoint = Deno.env.get('ERPC_USER_ENDPOINT')
    const cloud = new CloudApiClient({
      accessToken,
      ...(userEndpoint === undefined ? {} : { endpoint: userEndpoint }),
    })
    output(JSON.stringify(await cloud.listCatalog(), null, 2))
    return 0
  }

  if (command === 'resources' && subcommand === 'get') {
    if (args.length !== 3) {
      throw new Error('resources get requires one resource-id')
    }
    const resourceId = args[2]
    if (!resourceId) throw new Error('resource-id is required')
    const session = new CliAuthSession(createAuth(), createStore())
    const accessToken = await session.getAccessToken()
    const userEndpoint = Deno.env.get('ERPC_USER_ENDPOINT')
    const cloud = new CloudApiClient({
      accessToken,
      ...(userEndpoint === undefined ? {} : { endpoint: userEndpoint }),
    })
    output(JSON.stringify(await cloud.getResource(resourceId), null, 2))
    return 0
  }

  if (command === 'resources' && subcommand === 'status') {
    if (args.length !== 3) {
      throw new Error('resources status requires one resource-id')
    }
    const resourceId = args[2]
    if (!resourceId) throw new Error('resource-id is required')
    const session = new CliAuthSession(createAuth(), createStore())
    const accessToken = await session.getAccessToken()
    const userEndpoint = Deno.env.get('ERPC_USER_ENDPOINT')
    const cloud = new CloudApiClient({
      accessToken,
      ...(userEndpoint === undefined ? {} : { endpoint: userEndpoint }),
    })
    output(JSON.stringify(await cloud.getResourceStatus(resourceId), null, 2))
    return 0
  }

  if (command === 'credit') {
    if (args.length !== 1) throw new Error('credit does not accept arguments')
    const session = new CliAuthSession(createAuth(), createStore())
    const accessToken = await session.getAccessToken()
    const userEndpoint = Deno.env.get('ERPC_USER_ENDPOINT')
    const cloud = new CloudApiClient({
      accessToken,
      ...(userEndpoint === undefined ? {} : { endpoint: userEndpoint }),
    })
    output(JSON.stringify(await cloud.getCredit(), null, 2))
    return 0
  }

  if (command === 'app' && subcommand === 'init') {
    const appArgs = args.slice(2)
    if (appArgs.includes('--help') || appArgs.includes('-h')) {
      output(appInitHelp)
      return 0
    }
    const parsed = parseAppInitArguments(appArgs)
    const templateRegistry = dependencies.templateRegistry ?? TEMPLATE_REGISTRY
    const promptIO = dependencies.promptIO ?? defaultPromptIO

    let runtime = parsed.runtime
    let templateRef = parsed.template === undefined
      ? undefined
      : parseTemplateRef(parsed.template)
    let interactiveSha256: string | undefined

    if (runtime === undefined && templateRef === undefined) {
      const choice = await promptForTemplateOrRuntime(templateRegistry)
      if (choice.kind === 'runtime') {
        runtime = choice.runtime
      } else {
        const tagAndSha256 = await promptForTemplateTagAndSha256(
          promptIO,
          templateRegistry,
          choice.name,
        )
        templateRef = { name: choice.name, tag: tagAndSha256.tag }
        interactiveSha256 = tagAndSha256.sha256
      }
    }

    const localConfig = await readErpcConfig(configOptions)
    const requested = parsed.directory
    const applicationName = parsed.name ?? (
      requested === undefined
        ? 'erpc-app'
        : pathLike(requested)
        ? basename(resolve(cwd, requested))
        : requested
    )
    const directory = requested !== undefined && pathLike(requested)
      ? resolve(cwd, requested)
      : join(localConfig.appsDirectory, requested ?? applicationName)

    if (templateRef !== undefined) {
      const initialized = await initializeTemplateApp({
        directory,
        ...(parsed.domainValue === undefined
          ? {}
          : { domainValue: parsed.domainValue }),
        ...(parsed.emailValue === undefined
          ? {}
          : { emailValue: parsed.emailValue }),
        erpcHome: localConfig.erpcHome,
        ...(dependencies.fetch === undefined
          ? {}
          : { fetch: dependencies.fetch }),
        ...(parsed.name === undefined ? {} : { name: parsed.name }),
        oidcRegistrar: dependencies.oidcRegistrar ?? defaultOidcClientRegistrar,
        // Falls back to the real `xdg-open`/`open`/`start` launcher outside
        // tests, the same way `oidcRegistrar` falls back above (packet
        // Decision 8).
        openExternal: dependencies.openExternal ?? defaultOpenExternal,
        output,
        promptIO,
        setValues: parsed.setValues,
        ...(dependencies.signal === undefined
          ? {}
          : { signal: dependencies.signal }),
        ...(parsed.sha256 ?? interactiveSha256) === undefined
          ? {}
          : { sha256: (parsed.sha256 ?? interactiveSha256)! },
        tag: templateRef.tag,
        templateName: templateRef.name,
        templateRegistry,
        ...(parsed.trustIssuer === undefined
          ? {}
          : { trustIssuer: parsed.trustIssuer }),
        yes: parsed.yes,
      })
      if (!insideDirectory(localConfig.appsDirectory, initialized.directory)) {
        await registerErpcApplication({
          config: join(initialized.directory, 'erpc.toml'),
          name: initialized.name,
        }, configOptions)
      }
      output(
        `Created ${initialized.name} from template ${templateRef.name}@${templateRef.tag}.`,
      )
      output(`Next: cd ${initialized.directory}`)
      return 0
    }

    const resolvedRuntime = runtime ?? await promptForRuntime()
    const initialized = await initializeApp({
      directory,
      runtime: resolvedRuntime,
      name: applicationName,
    })
    if (!insideDirectory(localConfig.appsDirectory, initialized.directory)) {
      await registerErpcApplication({
        config: join(initialized.directory, 'erpc.toml'),
        name: initialized.name,
      }, configOptions)
    }
    output(
      `Created ${initialized.name} with the ${initialized.runtime} runtime.`,
    )
    output(`Next: cd ${initialized.directory}`)
    output(`      ${initialized.installCommand}`)
    output(`      ${initialized.startCommand}`)
    return 0
  }

  if (command === 'app' && subcommand === 'list') {
    if (args.length !== 2) throw new Error('app list does not accept arguments')
    const applications = await listErpcApplications(configOptions)
    if (applications.length === 0) {
      output('No ERPC applications found.')
      return 0
    }
    for (const application of applications) {
      output([
        application.name,
        application.runtime,
        application.target,
        application.root,
      ].join('\t'))
    }
    return 0
  }

  if (command === 'deploy') {
    const parsed = parseDeployArguments(args.slice(1))
    const configPath = await findErpcManifest(cwd, parsed.config)
    const manifest = await loadAnyErpcManifest(configPath)

    if (isCloudflareWorkerManifest(manifest)) {
      if (parsed.node !== undefined) {
        throw new Error(
          '--node is not supported for the cloudflare-worker runtime; use --config to select the application',
        )
      }
      if (parsed.target !== undefined && parsed.target !== 'cloudflare') {
        throw new Error(
          '--target must be "cloudflare" for the cloudflare-worker runtime',
        )
      }
      const localConfig = await readErpcConfig(configOptions)
      await deployToCloudflare(manifest, {
        ackBackup: parsed.ackBackup,
        dryRun: parsed.dryRun,
        erpcHome: localConfig.erpcHome,
        noProvision: parsed.noProvision,
        output,
        verifyOnly: parsed.verifyOnly,
        yes: parsed.yes,
        ...(dependencies.fetch === undefined
          ? {}
          : { fetch: dependencies.fetch }),
        promptIO: dependencies.promptIO ?? defaultPromptIO,
        ...(dependencies.random === undefined
          ? {}
          : { random: dependencies.random }),
        ...(dependencies.runProcess === undefined
          ? {}
          : { run: dependencies.runProcess }),
        ...(dependencies.templateRegistry === undefined
          ? {}
          : { templateRegistry: dependencies.templateRegistry }),
      })
      return 0
    }

    if (parsed.target !== undefined) {
      throw new Error(
        '--target is only supported for the cloudflare-worker runtime',
      )
    }
    const localConfig = await readErpcConfig(configOptions)
    const nodeNames = Object.keys(localConfig.nodes).sort()
    const nodeName = parsed.node ?? (
      manifest.deploy.target !== 'auto'
        ? manifest.deploy.target
        : nodeNames.length === 1
        ? nodeNames[0]
        : undefined
    )
    if (!nodeName) {
      throw new Error(
        nodeNames.length === 0
          ? 'No deployment node is configured in ~/.erpc/config.toml'
          : 'Multiple deployment nodes are configured; use --node or set deploy.target',
      )
    }
    const node = localConfig.nodes[nodeName]
    if (!node) throw new Error(`Unknown deployment node: ${nodeName}`)

    output(`Building ${manifest.name} for Linux...`)
    const artifact = await buildForDeployment(manifest, {
      ...(dependencies.runProcess === undefined
        ? {}
        : { run: dependencies.runProcess }),
    })
    output(`Deploying ${manifest.name} to ${nodeName}...`)
    const deployed = await deployOverSsh(
      manifest,
      artifact,
      nodeName,
      node,
      {
        ...(dependencies.runProcess === undefined
          ? {}
          : { run: dependencies.runProcess }),
        resolveNodeRuntime: async (architecture) =>
          await resolveVerifiedNodeRuntime(
            architecture,
            localConfig.erpcHome,
            {
              ...(dependencies.runProcess === undefined
                ? {}
                : { run: dependencies.runProcess }),
            },
          ),
      },
    )
    output(
      `Deployed ${manifest.name} as ${deployed.service}.service on ${deployed.node}.`,
    )
    return 0
  }

  throw new Error(`Unknown command.\n\n${help}`)
}

const appendCommandOptions = (
  args: string[],
  options: ReadonlyArray<readonly [string, string | boolean | undefined]>,
): string[] => {
  for (const [flag, value] of options) {
    if (value === undefined || value === false) continue
    args.push(flag)
    if (typeof value === 'string') args.push(value)
  }
  return args
}

const commandArguments = (
  command: string,
  options: ReadonlyArray<readonly [string, string | boolean | undefined]>,
): string[] => appendCommandOptions([command], options)

export const createProgram = (
  dependencies: CliDependencies = {},
) => {
  const output = dependencies.output ?? console.log
  const execute = async (args: readonly string[]): Promise<void> => {
    await executeCliCommand(args, dependencies)
  }
  const showHelp = function (this: Command): void {
    output(this.getHelp())
  }

  const program = new Command()
    .name('erpc')
    .version(CLI_VERSION)
    .versionOption(
      '-v, --version',
      'Show the installed ERPC CLI version.',
      () => output(CLI_VERSION),
    )
    .helpOption(
      '-h, --help',
      'Show help for ERPC or a command.',
      showHelp,
    )
    .description(
      'Build, deploy, and operate applications on ERPC.\n\n' +
        'Cloud billing and resource write commands are unavailable.\n' +
        'They will be enabled after their authorization and confirmation contracts are ready.',
    )
    .option('-P, --print', 'Print the ERPC welcome message.')
    .action(({ print }) => {
      if (print) {
        erpcAA(output)
        erpcWelcomeMessage(output)
        return
      }
      output('Use `erpc --help` to see available commands.')
    })
    .noExit()

  const loginCommand = new Command()
    .description('Sign in with the ERPC device authorization flow.')
    .type('scope', new EnumType([...ERPC_CLOUD_SCOPES]))
    .option('--no-open', 'Do not open the verification URL in a browser.')
    .option('--scope <scope:scope>', 'Request an ERPC Cloud scope.', {
      collect: true,
    })
    .action(async ({ open, scope }) => {
      const scopes = scope === undefined
        ? []
        : Array.isArray(scope)
        ? scope
        : [scope]
      const args = commandArguments('login', [['--no-open', !open]])
      for (const value of scopes) args.push('--scope', value)
      await execute(args)
    })

  const logoutCommand = new Command()
    .description('Sign out and remove the stored refresh credential.')
    .action(async () => await execute(['logout']))

  const monthlyUsageCommand = new Command()
    .description('Show API key usage for a calendar month.')
    .arguments('[year-month:string]')
    .action(async (_options, yearMonth?: string) => {
      await execute([
        'usage',
        'monthly',
        ...(yearMonth === undefined ? [] : [yearMonth]),
      ])
    })
  const usageCommand = new Command()
    .description('Inspect ERPC usage.')
    .action(showHelp)
    .command('monthly', monthlyUsageCommand)

  const resourcesCommand = new Command()
    .description('Inspect ERPC resource offerings and allocations.')
    .action(showHelp)
    .command(
      'catalog',
      new Command()
        .description('List available resource offerings.')
        .action(async () => await execute(['resources', 'catalog'])),
    )
    .command(
      'list',
      new Command()
        .description('List allocated resources.')
        .action(async () => await execute(['resources', 'list'])),
    )
    .command(
      'get',
      new Command()
        .description('Show a resource.')
        .arguments('<resource-id:string>')
        .action(async (_options, resourceId: string) =>
          await execute(['resources', 'get', resourceId])
        ),
    )
    .command(
      'status',
      new Command()
        .description('Show resource status and billing state.')
        .arguments('<resource-id:string>')
        .action(async (_options, resourceId: string) =>
          await execute(['resources', 'status', resourceId])
        ),
    )

  const appInitCommand = new Command()
    .description('Create a minimal ERPC application.')
    .arguments('[directory:string]')
    .type('runtime', new EnumType([...APP_RUNTIMES]))
    .option('--runtime <runtime:runtime>', 'Application runtime.')
    .option('--name <name:string>', 'Application name.')
    .option(
      '--template <ref:string>',
      'Create from a registered template: <name>@<tag>. Mutually exclusive with --runtime.',
    )
    .option(
      '--sha256 <hex:string>',
      'Expected sha256 of the template release asset (required for an unpinned tag).',
    )
    .option(
      '--set <keyValue:string>',
      'Answer a template prompt: KEY=VALUE. May be repeated.',
      { collect: true },
    )
    .option(
      '--domain <value:string>',
      'Shorthand for a template prompt flagged "domain".',
    )
    .option(
      '--email <value:string>',
      'Shorthand for a template prompt flagged "email".',
    )
    .option(
      '--trust-issuer <origin:string>',
      'Trust an unpinned template broker issuer non-interactively.',
    )
    .option(
      '--yes',
      'Do not prompt; use defaults and fail if an answer is missing.',
    )
    .action(
      async (
        {
          domain,
          email,
          name,
          runtime,
          set,
          sha256,
          template,
          trustIssuer,
          yes,
        },
        directory?: string,
      ) => {
        const args = appendCommandOptions([
          'app',
          'init',
          ...(directory === undefined ? [] : [directory]),
        ], [
          ['--runtime', runtime],
          ['--name', name],
          ['--template', template],
          ['--sha256', sha256],
          ['--domain', domain],
          ['--email', email],
          ['--trust-issuer', trustIssuer],
          ['--yes', yes],
        ])
        const setValues = set === undefined
          ? []
          : Array.isArray(set)
          ? set
          : [set]
        for (const value of setValues) args.push('--set', value)
        await execute(args)
      },
    )
  const appCommand = new Command()
    .description('Create and inspect local ERPC applications.')
    .action(showHelp)
    .command('init', appInitCommand)
    .command(
      'list',
      new Command()
        .description('List discovered ERPC applications.')
        .action(async () => await execute(['app', 'list'])),
    )

  const deployCommand = new Command()
    .description(
      'Build for Linux and deploy an application over SSH, or deploy a ' +
        'cloudflare-worker application with `--target cloudflare`.',
    )
    .option('--config <path:string>', 'Path to an erpc.toml file.')
    .option('--node <name:string>', 'Configured deployment node name.')
    .option(
      '--target <target:string>',
      'Deployment target for the cloudflare-worker runtime (only "cloudflare" is supported).',
    )
    .option(
      '--yes',
      'Do not prompt during a cloudflare-worker deploy; fail on a missing non-interactive answer.',
    )
    .option(
      '--ack-backup <key:string>',
      'Acknowledge a secret-pipe backup warning non-interactively. May be repeated.',
      { collect: true },
    )
    .option(
      '--no-provision',
      'Skip Cloudflare KV/secret provisioning (cloudflare-worker only).',
    )
    .option(
      '--dry-run',
      'Run `wrangler deploy --dry-run` instead of a real deploy (cloudflare-worker only).',
    )
    .option(
      '--verify-only',
      'Only re-run the post-deploy verification probes (cloudflare-worker only).',
    )
    .action(
      async (
        { ackBackup, config, dryRun, node, provision, target, verifyOnly, yes },
      ) => {
        const args = commandArguments('deploy', [
          ['--config', config],
          ['--node', node],
          ['--target', target],
          ['--yes', yes],
          ['--no-provision', !provision],
          ['--dry-run', dryRun],
          ['--verify-only', verifyOnly],
        ])
        const ackBackupValues = ackBackup === undefined
          ? []
          : Array.isArray(ackBackup)
          ? ackBackup
          : [ackBackup]
        for (const value of ackBackupValues) args.push('--ack-backup', value)
        await execute(args)
      },
    )

  program
    .command('login', loginCommand)
    .command('logout', logoutCommand)
    .command('usage', usageCommand)
    .command(
      'credit',
      new Command()
        .description('Show the current ERPC credit balance.')
        .action(async () => await execute(['credit'])),
    )
    .command('resources', resourcesCommand)
    .command('app', appCommand)
    .command('deploy', deployCommand)
    .command(
      'version',
      new Command().hidden().action(() => output(CLI_VERSION)),
    )
    .command(
      'help',
      new Command().hidden().action(() => output(program.getHelp())),
    )

  return program
}

export const runCli = async (
  args: readonly string[],
  dependencies: CliDependencies = {},
): Promise<number> => {
  await createProgram(dependencies).parse([...args])
  return 0
}
