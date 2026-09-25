// Orchestrates `erpc app init --template <name>@<tag>`.
// See design doc §1/§2.6 and Task Brief Decisions 1-16.

import { mkdir, readdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import {
  type CollectedBrokerRegistration,
  collectTemplateAnswers,
} from './template-answers.ts'
import {
  type ExtractedTemplateFile,
  extractTemplateArchive,
} from './template-archive.ts'
import {
  obtainVerifiedTemplateArchive,
  templateAssetUrl,
} from './template-fetch.ts'
import {
  isSecretPromptTarget,
  lintTemplateFiles,
  parseTemplateManifest,
  type TemplateManifest,
} from './template-manifest.ts'
import type { PromptIO } from './prompt-io.ts'
import { defaultPromptIO } from './prompt-io.ts'
import { renderTemplateFiles } from './template-render.ts'
import {
  resolveExpectedSha256,
  resolveTemplateRegistryEntry,
  type TemplateRegistry,
} from './template-registry.ts'

const APP_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
const MAX_CLOUDFLARE_WORKER_APP_NAME_LENGTH = 63

export interface OidcClientRegistrationRequest {
  readonly clientName: string
  readonly issuer: string
  readonly redirectUris: readonly string[]
}

export interface OidcClientRegistrationIo {
  readonly openExternal?: (url: string) => void
  output(message: string): void
  readonly signal?: AbortSignal
}

export interface OidcClientRegistrar {
  register(
    request: OidcClientRegistrationRequest,
    io: OidcClientRegistrationIo,
  ): Promise<{ readonly clientId: string }>
}

/**
 * The stub broker-register target for this release (Decision 8 / packet
 * scope: broker registration ships in PR-C). `--set APP_OIDC_CLIENT_ID=<id>`
 * bypasses this entirely; see `collectTemplateAnswers`.
 */
export const unsupportedOidcClientRegistrar: OidcClientRegistrar = {
  register(): Promise<{ clientId: string }> {
    throw new Error(
      'Broker registration is not available in this CLI version. ' +
        'Pass --set APP_OIDC_CLIENT_ID=<client id>.',
    )
  },
}

export const defaultOidcClientRegistrar: OidcClientRegistrar =
  unsupportedOidcClientRegistrar

const UNPINNED_TEMPLATE_WARNING = (
  owner: string,
  repo: string,
  tag: string,
): string =>
  `This template is not pinned by this CLI. Its scripts (install, preflight, secret generation, wrangler) will run with your permissions. Continue only if you trust ${owner}/${repo}@${tag}.`

const originsMatch = (a: string, b: string): boolean => {
  try {
    return new URL(a).origin === new URL(b).origin
  } catch {
    return a === b
  }
}

export interface InitializeTemplateAppOptions {
  readonly directory: string
  readonly domainValue?: string
  readonly emailValue?: string
  readonly erpcHome: string
  readonly fetch?: typeof globalThis.fetch
  readonly name?: string
  readonly oidcRegistrar?: OidcClientRegistrar
  readonly output: (message: string) => void
  readonly promptIO?: PromptIO
  readonly setValues: ReadonlyMap<string, string>
  readonly sha256?: string
  readonly tag: string
  readonly templateName: string
  readonly templateRegistry: TemplateRegistry
  readonly trustIssuer?: string
  readonly yes: boolean
}

export interface InitializedTemplateApp {
  readonly directory: string
  readonly files: readonly string[]
  readonly name: string
}

const findManifestFile = (
  files: readonly ExtractedTemplateFile[],
): ExtractedTemplateFile => {
  const manifestFile = files.find((file) => file.path === 'erpc-template.json')
  if (!manifestFile) {
    // extractTemplateArchive already enforces this; kept as a defensive check.
    throw new Error('Template archive is missing erpc-template.json')
  }
  return manifestFile
}

const renderErpcToml = (options: {
  readonly appName: string
  readonly build?: TemplateManifest['build']
  readonly cloudflare: TemplateManifest['cloudflare']
  readonly entrypoint: string
  readonly oidc?: {
    readonly clientId: string
    readonly issuer: string
    readonly redirectUris: readonly string[]
  }
  readonly sha256: string
  readonly source: {
    readonly asset: string
    readonly owner: string
    readonly repo: string
  }
  readonly tag: string
  readonly templateName: string
}): string => {
  const lines: string[] = [
    'schema_version = 1',
    `name = ${JSON.stringify(options.appName)}`,
    '',
    '[app]',
    'runtime = "cloudflare-worker"',
    `entrypoint = ${JSON.stringify(options.entrypoint)}`,
  ]
  if (options.build) {
    lines.push(
      '',
      '[build]',
      `command = ${JSON.stringify(options.build.command)}`,
    )
  }
  lines.push(
    '',
    '[deploy]',
    'target = "cloudflare"',
    '',
    '[cloudflare]',
    `config = ${JSON.stringify(options.cloudflare.config)}`,
    `wrangler = ${JSON.stringify(options.cloudflare.wrangler)}`,
    '',
    '[template]',
    `name = ${JSON.stringify(options.templateName)}`,
    `source = ${
      JSON.stringify(`github:${options.source.owner}/${options.source.repo}`)
    }`,
    `ref = ${JSON.stringify(options.tag)}`,
    `asset = ${JSON.stringify(options.source.asset)}`,
    `sha256 = ${JSON.stringify(options.sha256)}`,
  )
  if (options.oidc) {
    lines.push(
      '',
      '[oidc]',
      `issuer = ${JSON.stringify(options.oidc.issuer)}`,
      `client_id = ${JSON.stringify(options.oidc.clientId)}`,
      `redirect_uris = ${JSON.stringify(options.oidc.redirectUris)}`,
    )
  }
  lines.push('', '[health]', 'timeout_seconds = 120', '')
  return lines.join('\n')
}

/** Reads `main = "..."` from a rendered wrangler.toml, defaulting to `src/index.ts`. */
const detectEntrypoint = (
  files: readonly { path: string; content: Uint8Array }[],
): string => {
  const wrangler = files.find((file) => file.path === 'wrangler.toml')
  if (wrangler) {
    const match = /(?:^|\n)\s*main\s*=\s*"([^"]+)"/.exec(
      new TextDecoder().decode(wrangler.content),
    )
    if (match?.[1]) return match[1]
  }
  return 'src/index.ts'
}

export const initializeTemplateApp = async (
  options: InitializeTemplateAppOptions,
): Promise<InitializedTemplateApp> => {
  const promptIO = options.promptIO ?? defaultPromptIO
  const directory = resolve(options.directory)
  const appName = options.name ??
    directory.split(/[\\/]/).filter(Boolean).pop() ?? 'erpc-app'
  if (!APP_NAME.test(appName)) {
    throw new Error(
      'App name must contain lowercase letters, numbers, and single hyphens',
    )
  }
  if (appName.length > MAX_CLOUDFLARE_WORKER_APP_NAME_LENGTH) {
    throw new Error(
      `App name must be at most ${MAX_CLOUDFLARE_WORKER_APP_NAME_LENGTH} characters for the cloudflare-worker runtime`,
    )
  }

  // ① Target directory must not already contain files. Checked before any
  // network access (design §2.6 step 1).
  await mkdir(directory, { recursive: true })
  const existing = await readdir(directory)
  if (existing.length > 0) {
    throw new Error(`Refusing to overwrite non-empty directory: ${directory}`)
  }

  // ② Registry resolution.
  const entry = resolveTemplateRegistryEntry(
    options.templateRegistry,
    options.templateName,
  )
  const { pinned, sha256: expectedSha256 } = resolveExpectedSha256(
    entry,
    options.tag,
    options.sha256,
  )

  // ③ Fetch + verify checksum before anything else touches the target dir or cache.
  const url = templateAssetUrl(entry.source, options.tag)
  const archiveBytes = await obtainVerifiedTemplateArchive(
    url,
    options.erpcHome,
    expectedSha256,
    { ...(options.fetch === undefined ? {} : { fetch: options.fetch }) },
  )

  // Decision 16: the trust-boundary warning, exactly once, immediately after
  // fetch+checksum succeed and before any prompting.
  if (!pinned) {
    options.output(
      UNPINNED_TEMPLATE_WARNING(
        entry.source.owner,
        entry.source.repo,
        options.tag,
      ),
    )
  }

  // ④ Expansion policy.
  const { files } = await extractTemplateArchive(archiveBytes)

  // ⑤ Schema + semantic lint, entirely before any prompt is shown.
  const manifestFile = findManifestFile(files)
  let manifestJson: unknown
  try {
    manifestJson = JSON.parse(new TextDecoder().decode(manifestFile.content))
  } catch {
    throw new Error('erpc-template.json is not valid JSON')
  }
  const manifest = parseTemplateManifest(manifestJson)
  const filesByPath = new Map(files.map((file) => [file.path, file.content]))
  lintTemplateFiles(manifest, filesByPath)

  // Decision 6: `--set` may never provide a secret target's value; those are
  // generated during `erpc deploy` (PR-B), never during `init`.
  const secretPromptKeys = new Set(
    manifest.prompts
      .filter((prompt) => isSecretPromptTarget(prompt.target))
      .map((prompt) => prompt.key),
  )
  const rejectedSetKeys = [...options.setValues.keys()].filter((key) =>
    secretPromptKeys.has(key)
  )
  if (rejectedSetKeys.length > 0) {
    throw new Error(
      `--set cannot provide a value for a secret target (generated during 'erpc deploy', not 'erpc app init'): ${
        rejectedSetKeys.join(', ')
      }`,
    )
  }

  // Interactive vs non-interactive gate (mirrors promptForRuntime's contract).
  const ttyInteractive = promptIO.isInteractive()
  if (!ttyInteractive && !options.yes) {
    throw new Error(
      'Use --yes in non-interactive mode (no TTY is available to prompt for answers)',
    )
  }
  const interactive = ttyInteractive && !options.yes

  const brokerIssuer = manifest.broker?.issuer
  const confirmIssuerTrust = async (issuer: string): Promise<boolean> => {
    if (pinned) return true
    if (options.trustIssuer !== undefined) {
      return originsMatch(options.trustIssuer, issuer)
    }
    if (interactive) {
      return await promptIO.confirm(
        `This template is not pinned. It will register an OAuth client with ${issuer}. Do you trust this issuer?`,
        { default: false },
      )
    }
    return false
  }

  const oidcRegistrar = options.oidcRegistrar ?? defaultOidcClientRegistrar
  const resolveBrokerRegister = async (
    prompt: {
      readonly key: string
      readonly validate?: { readonly pattern: string }
    },
    redirectUris: readonly string[],
    clientName: string,
  ): Promise<string> => {
    const setValue = options.setValues.get(prompt.key)
    if (setValue !== undefined) {
      if (
        prompt.validate &&
        !new RegExp(`^(?:${prompt.validate.pattern})$`).test(setValue)
      ) {
        throw new Error(
          `${prompt.key}: value does not match the required pattern`,
        )
      }
      return setValue
    }
    const result = await oidcRegistrar.register(
      { issuer: brokerIssuer ?? '', clientName, redirectUris },
      { output: options.output },
    )
    return result.clientId
  }

  // ⑥/⑦ Collect var + derived + broker-register answers.
  const { values, brokerRegistration } = await collectTemplateAnswers(
    manifest,
    {
      builtIns: {
        appName,
        ...(brokerIssuer === undefined ? {} : { brokerIssuer }),
      },
      confirmIssuerTrust,
      ...(options.domainValue === undefined
        ? {}
        : { domainValue: options.domainValue }),
      ...(options.emailValue === undefined
        ? {}
        : { emailValue: options.emailValue }),
      interactive,
      promptIO,
      resolveBrokerRegister,
      setValues: options.setValues,
    },
  )

  // ⑧ Render declared files.
  const rendered = renderTemplateFiles(manifest, files, values, {
    appName,
    ...(brokerIssuer === undefined ? {} : { brokerIssuer }),
  })

  const entrypoint = detectEntrypoint(rendered)
  const oidc: {
    readonly clientId: string
    readonly issuer: string
    readonly redirectUris: readonly string[]
  } | undefined = brokerRegistration && brokerIssuer !== undefined
    ? {
      clientId: brokerRegistration.clientId,
      issuer: brokerIssuer,
      redirectUris: brokerRegistration.redirectUris,
    }
    : undefined
  const erpcToml = renderErpcToml({
    appName,
    ...(manifest.build ? { build: manifest.build } : {}),
    cloudflare: manifest.cloudflare,
    entrypoint,
    ...(oidc ? { oidc } : {}),
    sha256: expectedSha256,
    source: entry.source,
    tag: options.tag,
    templateName: options.templateName,
  })

  // ⑨ Write every file, then erpc.toml. `wx` refuses to clobber (defense in
  // depth on top of the earlier empty-directory check).
  for (const file of rendered) {
    const destination = resolve(directory, file.path)
    if (!destination.startsWith(`${directory}/`)) {
      throw new Error('Template path escaped the application directory')
    }
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, file.content, {
      flag: 'wx',
      mode: file.executable ? 0o755 : 0o644,
    })
  }
  await writeFile(resolve(directory, 'erpc.toml'), erpcToml, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o644,
  })

  return {
    directory,
    files: [...rendered.map((file) => file.path), 'erpc.toml'].sort(),
    name: appName,
  }
}

export type { CollectedBrokerRegistration }
