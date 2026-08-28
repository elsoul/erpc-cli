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
import { findErpcManifest, loadErpcManifest } from './app/manifest.ts'
import { promptForRuntime } from './app/prompt.ts'
import { listErpcApplications } from './app/registry.ts'
import { APP_RUNTIMES, type AppRuntime } from './app/templates.ts'
import { readErpcConfig, registerErpcApplication } from './config.ts'
import { buildForDeployment } from './deploy/build.ts'
import { deployOverSsh } from './deploy/ssh.ts'
import { resolveVerifiedNodeRuntime } from './deploy/node-runtime.ts'
import type { ProcessRunner } from './process.ts'
import { erpcAA, erpcWelcomeMessage } from './ui/welcome.ts'

export interface CliDependencies {
  readonly auth?: DeviceAuthClient
  readonly cwd?: string
  readonly erpcHome?: string
  readonly openExternal?: (url: string) => void
  readonly output?: (message: string) => void
  readonly runProcess?: ProcessRunner
  readonly store?: RefreshTokenStore
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
  erpc app list
  erpc deploy [--config path/to/erpc.toml] [--node node-name]

Cloud billing and resource write commands are unavailable until their authorization and confirmation contracts are enabled.`

const appInitHelp = `Create a minimal ERPC application

Usage:
  erpc app init [directory] [--runtime node|deno] [--name app-name]

Bare names are created below ~/.erpc/apps. Paths are created where specified.
When --runtime is omitted in a terminal, the CLI asks you to choose.`

const defaultOpenExternal = (url: string): void => {
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
  return requested.length > 0 ? requested : ['usage:read', 'resources:read']
}

const parseRuntime = (value: string | undefined): AppRuntime | undefined => {
  if (value === undefined) return undefined
  if (APP_RUNTIMES.includes(value as AppRuntime)) return value as AppRuntime
  throw new Error('Runtime must be node or deno')
}

interface AppInitArguments {
  readonly directory?: string
  readonly name?: string
  readonly runtime?: AppRuntime
}

const parseAppInitArguments = (
  args: readonly string[],
): AppInitArguments => {
  let directory: string | undefined
  let name: string | undefined
  let runtime: AppRuntime | undefined

  for (let index = 0; index < args.length; index++) {
    const value = args[index]
    if (value === '--runtime' || value === '--name') {
      const optionValue = args[index + 1]
      if (!optionValue || optionValue.startsWith('-')) {
        throw new Error(`${value} requires a value`)
      }
      if (value === '--runtime') {
        if (runtime !== undefined) throw new Error('--runtime may be used once')
        runtime = parseRuntime(optionValue)
      } else {
        if (name !== undefined) throw new Error('--name may be used once')
        name = optionValue
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

  return {
    ...(directory === undefined ? {} : { directory }),
    ...(name === undefined ? {} : { name }),
    ...(runtime === undefined ? {} : { runtime }),
  }
}

interface DeployArguments {
  readonly config?: string
  readonly node?: string
}

const parseDeployArguments = (args: readonly string[]): DeployArguments => {
  let config: string | undefined
  let node: string | undefined
  for (let index = 0; index < args.length; index++) {
    const option = args[index]
    if (option !== '--config' && option !== '--node') {
      throw new Error(`Unknown deploy option: ${option}`)
    }
    const value = args[index + 1]
    if (!value || value.startsWith('-')) {
      throw new Error(`${option} requires a value`)
    }
    if (option === '--config') {
      if (config !== undefined) throw new Error('--config may be used once')
      config = value
    } else {
      if (node !== undefined) throw new Error('--node may be used once')
      node = value
    }
    index++
  }
  return {
    ...(config === undefined ? {} : { config }),
    ...(node === undefined ? {} : { node }),
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
    const authorization = await auth.start(parseScopes(args.slice(1)))
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
    const runtime = parsed.runtime ?? await promptForRuntime()
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
    const initialized = await initializeApp({
      directory,
      runtime,
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
    const manifest = await loadErpcManifest(configPath)
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
    .action(async ({ name, runtime }, directory?: string) => {
      await execute(
        appendCommandOptions([
          'app',
          'init',
          ...(directory === undefined ? [] : [directory]),
        ], [
          ['--runtime', runtime],
          ['--name', name],
        ]),
      )
    })
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
    .description('Build for Linux and deploy an application over SSH.')
    .option('--config <path:string>', 'Path to an erpc.toml file.')
    .option('--node <name:string>', 'Configured deployment node name.')
    .action(async ({ config, node }) => {
      await execute(commandArguments('deploy', [
        ['--config', config],
        ['--node', node],
      ]))
    })

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
