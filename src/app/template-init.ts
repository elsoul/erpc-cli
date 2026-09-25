// Orchestrates `erpc app init --template <name>@<tag>`.
// See design doc §1/§2.6 and Task Brief Decisions 1-16.

import { mkdir, readdir, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
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
import {
  renderTemplateFiles as defaultRenderTemplateFiles,
  tomlBasicString,
} from './template-render.ts'
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

/**
 * The Decision 16 trust-boundary warning text, exported so PR-B/PR-C can
 * reuse the exact wording instead of duplicating it.
 */
export const unpinnedTemplateWarning = (
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

/**
 * Platform-safe "is `child` inside (or equal to) `parent`" check. Compares
 * the relative path's first segment to `..` exactly, rather than a string
 * prefix - `..startsWith` would misfire on a legitimately named entry such
 * as `..hidden`.
 */
const isInsideDirectory = (parent: string, child: string): boolean => {
  const relativePath = relative(parent, child)
  if (relativePath === '') return true
  if (isAbsolute(relativePath)) return false
  const [firstSegment] = relativePath.split(/[\\/]/)
  return firstSegment !== '..'
}

const tomlString = (value: string): string => `"${tomlBasicString(value)}"`
const tomlStringArray = (values: readonly string[]): string =>
  `[${values.map((value) => tomlString(value)).join(', ')}]`

export interface InitializeTemplateAppOptions {
  readonly directory: string
  readonly domainValue?: string
  readonly emailValue?: string
  readonly erpcHome: string
  readonly fetch?: typeof globalThis.fetch
  readonly name?: string
  readonly oidcRegistrar?: OidcClientRegistrar
  /** Forwarded to the OIDC registrar's io; PR-A never sets this itself. */
  readonly openExternal?: (url: string) => void
  readonly output: (message: string) => void
  readonly promptIO?: PromptIO
  /** Overrides step ⑧'s renderer. Defaults to the real `renderTemplateFiles`; tests use this to force a deterministic render failure. */
  readonly renderTemplateFiles?: typeof defaultRenderTemplateFiles
  readonly setValues: ReadonlyMap<string, string>
  readonly sha256?: string
  /** Forwarded to the OIDC registrar's io; PR-A never creates one itself. */
  readonly signal?: AbortSignal
  readonly tag: string
  readonly templateName: string
  readonly templateRegistry: TemplateRegistry
  readonly trustIssuer?: string
  /**
   * Overrides the primitive used for every file write in step ⑨ (and the
   * `erpc.toml` write). Defaults to `node:fs/promises`'s `writeFile`; tests
   * use this to force a deterministic, root-safe write failure instead of
   * relying on filesystem permissions.
   */
  readonly writeFile?: WriteFileFunction
  readonly yes: boolean
}

export type WriteFileFunction = (
  path: string,
  data: Uint8Array | string,
  options: {
    readonly encoding?: 'utf8'
    readonly flag: 'wx'
    readonly mode: number
  },
) => Promise<void>

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
    `name = ${tomlString(options.appName)}`,
    '',
    '[app]',
    'runtime = "cloudflare-worker"',
    `entrypoint = ${tomlString(options.entrypoint)}`,
  ]
  if (options.build) {
    lines.push(
      '',
      '[build]',
      `command = ${tomlStringArray(options.build.command)}`,
    )
  }
  lines.push(
    '',
    '[deploy]',
    'target = "cloudflare"',
    '',
    '[cloudflare]',
    `config = ${tomlString(options.cloudflare.config)}`,
    `wrangler = ${tomlStringArray(options.cloudflare.wrangler)}`,
    '',
    '[template]',
    `name = ${tomlString(options.templateName)}`,
    `source = ${
      tomlString(`github:${options.source.owner}/${options.source.repo}`)
    }`,
    `ref = ${tomlString(options.tag)}`,
    `asset = ${tomlString(options.source.asset)}`,
    `sha256 = ${tomlString(options.sha256)}`,
  )
  if (options.oidc) {
    lines.push(
      '',
      '[oidc]',
      `issuer = ${tomlString(options.oidc.issuer)}`,
      `client_id = ${tomlString(options.oidc.clientId)}`,
      `redirect_uris = ${tomlStringArray(options.oidc.redirectUris)}`,
    )
  }
  lines.push('', '[health]', 'timeout_seconds = 120', '')
  return lines.join('\n')
}

/** Reads `main = "..."` from the rendered `cloudflare.config` file, defaulting to `src/index.ts`. */
const detectEntrypoint = (
  files: readonly { path: string; content: Uint8Array }[],
  configPath: string,
): string => {
  const config = files.find((file) => file.path === configPath)
  if (config) {
    const match = /(?:^|\n)\s*main\s*=\s*"([^"]+)"/.exec(
      new TextDecoder().decode(config.content),
    )
    if (match?.[1]) return match[1]
  }
  return 'src/index.ts'
}

const summaryText = (
  manifest: TemplateManifest,
  values: ReadonlyMap<string, string>,
): string => {
  const derivedLines = manifest.prompts
    .filter((prompt) => prompt.target === 'derived')
    .map((prompt) =>
      `  ${prompt.key} = ${values.get(prompt.key) ?? '(unresolved)'}`
    )
  // `secret-generate`/`secret-pipe` produce a value with no user input;
  // `secret-input` asks the user for one (or reads an env var) - list them
  // separately so the summary doesn't call a prompt "generated" when it will
  // actually ask.
  const generatedSecretKeys = manifest.prompts
    .filter((prompt) =>
      prompt.target === 'secret-generate' || prompt.target === 'secret-pipe'
    )
    .map((prompt) => prompt.key)
  const promptedSecretKeys = manifest.prompts
    .filter((prompt) => prompt.target === 'secret-input')
    .map((prompt) => prompt.key)
  const lines = ['Summary:']
  if (derivedLines.length > 0) lines.push(...derivedLines)
  if (generatedSecretKeys.length > 0) {
    lines.push(
      `  Secrets generated during 'erpc deploy': ${
        generatedSecretKeys.join(', ')
      }`,
    )
  }
  if (promptedSecretKeys.length > 0) {
    lines.push(
      `  Secrets prompted for during 'erpc deploy': ${
        promptedSecretKeys.join(', ')
      }`,
    )
  }
  if (generatedSecretKeys.length === 0 && promptedSecretKeys.length === 0) {
    lines.push(
      "  No secrets are generated or prompted for during 'erpc deploy' for this template.",
    )
  }
  return lines.join('\n')
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
  // network access (design §2.6 step 1) and without creating the directory
  // a later failure must not leave an empty directory.
  const existing = await readdir(directory).catch((error) => {
    if (
      error && typeof error === 'object' && 'code' in error &&
      (error as { code?: unknown }).code === 'ENOENT'
    ) {
      return [] as string[]
    }
    throw error
  })
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
      unpinnedTemplateWarning(
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
    // A `--set`-provided value is returned as-is: `collectTemplateAnswers`
    // checks it against `prompt.validate` right after this call returns, the
    // same way it checks a value the registrar itself returned, so a bad
    // `--set` value joins the same aggregated error instead of throwing here
    // on its own.
    const setValue = options.setValues.get(prompt.key)
    if (setValue !== undefined) return setValue
    const result = await oidcRegistrar.register(
      { issuer: brokerIssuer ?? '', clientName, redirectUris },
      {
        output: options.output,
        ...(options.openExternal === undefined
          ? {}
          : { openExternal: options.openExternal }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    )
    return result.clientId
  }

  // ⑥/⑦ Collect var + derived answers, show the interactive summary once
  // every one of them is ready, then - only after that - resolve broker
  // registration (design §2.5 order: var → summary → registrar).
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
      onAnswersReady: (resolvedValues) => {
        if (interactive) {
          promptIO.inform?.(summaryText(manifest, resolvedValues))
        }
      },
      promptIO,
      resolveBrokerRegister,
      setValues: options.setValues,
    },
  )

  // ⑧ Render declared files.
  const write = options.writeFile ?? writeFile
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

  // Steps ⑧ (render) and ⑨ (write) below share one try/catch: a real,
  // newly registered OAuth client (never one supplied via `--set` - see
  // `registered` on `CollectedBrokerRegistration`) is public information the
  // user needs in order to avoid registering a second client on retry, and a
  // render failure is exactly as much "after registration already
  // succeeded" as a write failure is. This mirrors design §2.6's ordering
  // (registration resolves, then rendering, then writing) and its "⑦〜⑨ 間の
  // 失敗は client_id を表示し --set APP_OIDC_CLIENT_ID=<id> で再実行" contract,
  // even though registration itself now runs inside the combined answer-
  // collection call above rather than as its own separately numbered step
  // here (packet Decision 6).
  try {
    const render = options.renderTemplateFiles ?? defaultRenderTemplateFiles
    const rendered = render(manifest, files, values, {
      appName,
      ...(brokerIssuer === undefined ? {} : { brokerIssuer }),
    })
    const entrypoint = detectEntrypoint(rendered, manifest.cloudflare.config)
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

    await mkdir(directory, { recursive: true })
    for (const file of rendered) {
      const destination = resolve(directory, file.path)
      if (!isInsideDirectory(directory, destination)) {
        throw new Error('Template path escaped the application directory')
      }
      await mkdir(dirname(destination), { recursive: true })
      await write(destination, file.content, {
        flag: 'wx',
        mode: file.executable ? 0o755 : 0o644,
      })
    }
    await write(resolve(directory, 'erpc.toml'), erpcToml, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o644,
    })

    return {
      directory,
      files: [...rendered.map((file) => file.path), 'erpc.toml'].sort(),
      name: appName,
    }
  } catch (error) {
    if (brokerRegistration?.registered) {
      options.output(
        `Broker registration already succeeded (client_id: ${brokerRegistration.clientId}) before this failure. ` +
          `Re-run with --set APP_OIDC_CLIENT_ID=${brokerRegistration.clientId} instead of registering a new client.`,
      )
    }
    throw error
  }
}

export type { CollectedBrokerRegistration }
