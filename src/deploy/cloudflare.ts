// `erpc deploy --target cloudflare`. See design doc §3/§4 and Task Brief
// Decision 1-12 (`2026-09-25-packet-erpc-cli-pr-b.md`).
//
// D0 read -> D1 toolchain -> D2 build -> D3 auth+account -> D4 provision
// (KV, secrets) -> D5 preflight -> D6 `wrangler deploy` -> D7 post-deploy
// probe. `--no-provision` skips D4; `--dry-run` skips D4 and the real D6
// (running `wrangler deploy --dry-run` instead) and returns before D7;
// `--verify-only` runs only D0 and D7.

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { defaultPromptIO, type PromptIO } from '../app/prompt-io.ts'
import { extractTemplateArchive } from '../app/template-archive.ts'
import {
  obtainVerifiedTemplateArchive,
  templateAssetUrl,
} from '../app/template-fetch.ts'
import {
  lintTemplateFiles,
  parseTemplateManifest,
  requiredSecretKeys,
  type TemplateManifest,
} from '../app/template-manifest.ts'
import type { CloudflareWorkerManifest } from '../app/manifest.ts'
import {
  TEMPLATE_REGISTRY,
  type TemplateRegistry,
  type TemplateSource,
} from '../app/template-registry.ts'
import { unpinnedTemplateWarning } from '../app/template-init.ts'
import { runProcess } from '../process.ts'
import type { ProcessRunner } from '../process.ts'
import {
  blockingSecretIssues,
  resolveSecretValue,
  secretPromptsOf,
} from './secrets.ts'
import { runPostDeployProbes } from './probes.ts'
import {
  applyAccountIdSentinel,
  applyKvIdSentinel,
  atomicWriteWranglerConfig,
  hasUnresolvedPlaceholders,
  kvIdSentinel,
  parseWranglerConfig,
  readWranglerConfigText,
  readWranglerRequiredSecrets,
  readWranglerVars,
  resolvedAccountId,
} from './wrangler-config.ts'
import {
  checkWranglerToolchain,
  DEFAULT_MIN_WRANGLER_VERSION,
  wranglerDeploy,
  wranglerKvNamespaceCreate,
  wranglerKvNamespaceList,
  wranglerLogin,
  wranglerSecretList,
  wranglerSecretPut,
  wranglerWhoami,
} from './wrangler.ts'

export interface CloudflareDeployOptions {
  readonly ackBackup?: readonly string[]
  readonly dryRun?: boolean
  readonly erpcHome: string
  readonly fetch?: typeof globalThis.fetch
  readonly noProvision?: boolean
  readonly output: (message: string) => void
  readonly promptIO?: PromptIO
  /** `crypto.getRandomValues`'s signature - tests inject a deterministic double (Acceptance A11). */
  readonly random?: (bytes: Uint8Array<ArrayBuffer>) => void
  readonly run?: ProcessRunner
  readonly templateRegistry?: TemplateRegistry
  readonly verifyOnly?: boolean
  readonly yes?: boolean
}

const defaultRandom = (bytes: Uint8Array<ArrayBuffer>): void => {
  crypto.getRandomValues(bytes)
}

const GITHUB_SOURCE_PATTERN = /^github:([^/]+)\/(.+)$/

const parseTemplateSource = (source: string, asset: string): TemplateSource => {
  const match = GITHUB_SOURCE_PATTERN.exec(source)
  if (!match) throw new Error(`Unsupported template source: ${source}`)
  return { asset, owner: match[1]!, repo: match[2]! }
}

/**
 * D0: re-obtains (from the erpcHome cache, or re-fetching against the sha256
 * already pinned in erpc.toml) and re-verifies `erpc-template.json` exactly
 * the way `erpc app init --template` did (Decision 3), since only
 * `app.name`/`cloudflare.{config,wrangler}` from `erpc.toml` are persisted -
 * `cloudflare.kv`/`preflight`/`minWranglerVersion` and `postDeploy` live in
 * the template manifest, not in `erpc.toml`.
 */
const loadDeployTemplateManifest = async (
  manifest: CloudflareWorkerManifest,
  options: {
    readonly erpcHome: string
    readonly fetch: typeof globalThis.fetch
    readonly templateRegistry: TemplateRegistry
  },
): Promise<
  { readonly pinned: boolean; readonly templateManifest: TemplateManifest }
> => {
  const source = parseTemplateSource(
    manifest.template.source,
    manifest.template.asset,
  )
  const url = templateAssetUrl(source, manifest.template.ref)
  const archiveBytes = await obtainVerifiedTemplateArchive(
    url,
    options.erpcHome,
    manifest.template.sha256,
    { fetch: options.fetch },
  )
  const { files } = await extractTemplateArchive(archiveBytes)
  const manifestFile = files.find((file) => file.path === 'erpc-template.json')
  if (!manifestFile) {
    throw new Error(
      'erpc-template.json is missing from the re-fetched template archive',
    )
  }
  let json: unknown
  try {
    json = JSON.parse(new TextDecoder().decode(manifestFile.content))
  } catch {
    throw new Error('erpc-template.json is not valid JSON')
  }
  const templateManifest = parseTemplateManifest(json)
  const filesByPath = new Map(files.map((file) => [file.path, file.content]))
  lintTemplateFiles(templateManifest, filesByPath)

  const entry = Object.hasOwn(options.templateRegistry, manifest.template.name)
    ? options.templateRegistry[manifest.template.name]
    : undefined
  const pinnedSha256 = entry && Object.hasOwn(entry.pins, manifest.template.ref)
    ? entry.pins[manifest.template.ref]
    : undefined
  const pinned = pinnedSha256 !== undefined &&
    pinnedSha256 === manifest.template.sha256

  return { pinned, templateManifest }
}

interface AccountResolution {
  readonly accountEnv: Readonly<Record<string, string>>
  readonly accountId: string
}

/**
 * D3: authenticate, then fix an account_id, writing it into wrangler.toml
 * (Decision 4). Under `--dry-run` the account is still resolved (D5(b)'s
 * report needs the right `CLOUDFLARE_ACCOUNT_ID`) but never written back
 * (packet review N5) - a dry run must not mutate the project.
 */
const resolveCloudflareAccount = async (params: {
  readonly dryRun: boolean
  readonly isInteractive: boolean
  readonly promptIO: PromptIO
  readonly root: string
  readonly run: ProcessRunner
  readonly wrangler: readonly string[]
  readonly wranglerConfigPath: string
}): Promise<AccountResolution> => {
  const cloudflareApiToken = Deno.env.get('CLOUDFLARE_API_TOKEN')
  let whoami = await wranglerWhoami(
    params.run,
    params.wrangler,
    params.root,
    params.wranglerConfigPath,
  )
  if (!whoami) {
    if (cloudflareApiToken !== undefined) {
      throw new Error(
        'wrangler is not authenticated and CLOUDFLARE_API_TOKEN is set; ' +
          'refusing to run `wrangler login` under a different identity. Fix or unset CLOUDFLARE_API_TOKEN, then retry.',
      )
    }
    if (!params.isInteractive) {
      throw new Error(
        'wrangler is not authenticated and no terminal is available for `wrangler login`. ' +
          'Set CLOUDFLARE_API_TOKEN, or run `wrangler login` first.',
      )
    }
    await wranglerLogin(
      params.run,
      params.wrangler,
      params.root,
      params.wranglerConfigPath,
    )
    whoami = await wranglerWhoami(
      params.run,
      params.wrangler,
      params.root,
      params.wranglerConfigPath,
    )
    if (!whoami) {
      throw new Error(
        '`wrangler login` did not result in an authenticated session',
      )
    }
  }

  const text = await readWranglerConfigText(params.wranglerConfigPath)
  const parsed = parseWranglerConfig(text)
  const configAccountId = resolvedAccountId(parsed)
  const envAccountId = Deno.env.get('CLOUDFLARE_ACCOUNT_ID')

  // Decision 4's rank order (env -> wrangler.toml's already-resolved value ->
  // the single account -> a TTY choice -> stop) means a *resolved*
  // wrangler.toml value wins over re-deriving from whoami's account list -
  // the only remaining conflict to catch is env disagreeing with a value a
  // previous run already fixed.
  let accountId: string
  if (configAccountId !== undefined) {
    if (envAccountId !== undefined && envAccountId !== configAccountId) {
      throw new Error(
        `CLOUDFLARE_ACCOUNT_ID (${envAccountId}) does not match the Cloudflare account already resolved in wrangler.toml (${configAccountId})`,
      )
    }
    // packet review N11: a pinned account that this login can no longer see
    // (revoked membership, wrong login) must stop here, not surface as a
    // confusing 403 several steps later.
    if (!whoami.accounts.some((account) => account.id === configAccountId)) {
      throw new Error(
        `wrangler.toml account_id (${configAccountId}) is not one of the accounts this wrangler login can see`,
      )
    }
    accountId = configAccountId
  } else if (envAccountId !== undefined) {
    accountId = envAccountId
  } else if (whoami.accounts.length === 1) {
    accountId = whoami.accounts[0]!.id
  } else if (whoami.accounts.length > 1 && params.isInteractive) {
    accountId = await params.promptIO.select(
      'Select a Cloudflare account',
      whoami.accounts.map((account) => ({
        name: `${account.name} (${account.id})`,
        value: account.id,
      })),
    )
  } else {
    throw new Error(
      whoami.accounts.length === 0
        ? 'No Cloudflare accounts are available for this login'
        : 'Multiple Cloudflare accounts are available; set CLOUDFLARE_ACCOUNT_ID or wrangler.toml account_id',
    )
  }

  if (!params.dryRun) {
    const updated = applyAccountIdSentinel(text, accountId)
    if (updated !== text) {
      await atomicWriteWranglerConfig(params.wranglerConfigPath, updated)
      // packet review N3: confirm the write actually landed before trusting
      // it for the rest of the run.
      const readBack = await readWranglerConfigText(params.wranglerConfigPath)
      if (resolvedAccountId(parseWranglerConfig(readBack)) !== accountId) {
        throw new Error(
          `${params.wranglerConfigPath} does not show account_id ${accountId} after writing it`,
        )
      }
    }
  }

  return { accountEnv: { CLOUDFLARE_ACCOUNT_ID: accountId }, accountId }
}

/**
 * `cloudflare.kv[].title` is only ever interpolated with `{{app.name}}` -
 * `erpc-template.json`'s own lint (`template-manifest.ts` L2) rejects any
 * other placeholder in a kv title precisely because nothing else is
 * resolvable at this point (packet Decision 5(iii)), so an unresolved `{{`
 * remaining here means the archive re-fetched in D0 disagrees with what
 * passed lint at init time. The lint trims whitespace inside `{{ }}` when it
 * compares names (`extractPlaceholderNames`), so `{{ app.name }}` passes
 * lint too - this matches that with the same tolerance instead of only
 * accepting the exact byte sequence `{{app.name}}` (cyan r1 N5).
 */
const APP_NAME_PLACEHOLDER = /\{\{\s*app\.name\s*\}\}/g

const interpolateKvTitle = (title: string, appName: string): string => {
  const resolved = title.replace(APP_NAME_PLACEHOLDER, appName)
  if (resolved.includes('{{')) {
    throw new Error(
      `Unable to resolve the Cloudflare KV namespace title "${title}" at deploy time`,
    )
  }
  return resolved
}

/** D4a: reuse-or-create every KV namespace whose sentinel is still present. */
const provisionKvNamespaces = async (params: {
  readonly accountEnv: Readonly<Record<string, string>>
  readonly appName: string
  readonly kv: TemplateManifest['cloudflare']['kv']
  readonly root: string
  readonly run: ProcessRunner
  readonly wrangler: readonly string[]
  readonly wranglerConfigPath: string
}): Promise<void> => {
  const entries = params.kv ?? []
  if (entries.length === 0) return
  let text = await readWranglerConfigText(params.wranglerConfigPath)
  let listCache:
    | readonly { readonly id: string; readonly title: string }[]
    | undefined
  let changed = false
  for (const entry of entries) {
    const sentinel = kvIdSentinel(entry.binding)
    if (!text.includes(sentinel)) continue // already resolved by a previous run
    const title = interpolateKvTitle(entry.title, params.appName)
    if (!listCache) {
      listCache = await wranglerKvNamespaceList(
        params.run,
        params.wrangler,
        params.root,
        params.wranglerConfigPath,
        params.accountEnv,
      )
    }
    const existing = listCache.find((namespace) => namespace.title === title)
    const id = existing ? existing.id : await wranglerKvNamespaceCreate(
      params.run,
      params.wrangler,
      params.root,
      params.wranglerConfigPath,
      params.accountEnv,
      title,
    )
    text = applyKvIdSentinel(text, entry.binding, id)
    changed = true
  }
  if (changed) await atomicWriteWranglerConfig(params.wranglerConfigPath, text)
}

/** D4b: put every required secret this Worker does not already have (Decision 6). */
const provisionSecrets = async (params: {
  readonly ackBackup: ReadonlySet<string>
  readonly accountEnv: Readonly<Record<string, string>>
  readonly isInteractive: boolean
  readonly output: (message: string) => void
  readonly promptIO: PromptIO
  readonly random: (bytes: Uint8Array<ArrayBuffer>) => void
  readonly root: string
  readonly run: ProcessRunner
  readonly templateManifest: TemplateManifest
  readonly wrangler: readonly string[]
  readonly wranglerConfigPath: string
}): Promise<void> => {
  const secretPrompts = secretPromptsOf(params.templateManifest.prompts)
  if (secretPrompts.length === 0) return
  const existing = await wranglerSecretList(
    params.run,
    params.wrangler,
    params.root,
    params.wranglerConfigPath,
    params.accountEnv,
  )
  const toProcess = secretPrompts.filter((prompt) => !existing.has(prompt.key))
  if (toProcess.length === 0) return

  const issues = blockingSecretIssues(toProcess, params)
  if (issues.length > 0) {
    throw new Error(
      `Cannot provision Cloudflare Worker secrets:\n${
        issues.map((issue) => `  - ${issue}`).join('\n')
      }`,
    )
  }

  for (const prompt of toProcess) {
    const resolution = await resolveSecretValue(prompt, params)
    if (resolution.kind === 'skip') continue
    await wranglerSecretPut(
      params.run,
      params.wrangler,
      params.root,
      params.wranglerConfigPath,
      params.accountEnv,
      prompt.key,
      resolution.value,
    )
  }
}

/** D5: read-only preflight, always run (even under `--no-provision`). */
const runPreflight = async (params: {
  readonly accountEnv: Readonly<Record<string, string>>
  readonly output: (message: string) => void
  readonly reportMissingOnly: boolean
  readonly root: string
  readonly run: ProcessRunner
  readonly templateManifest: TemplateManifest
  readonly wrangler: readonly string[]
  readonly wranglerConfigPath: string
}): Promise<void> => {
  const text = await readWranglerConfigText(params.wranglerConfigPath)
  if (hasUnresolvedPlaceholders(text)) {
    // D5(a): under `--dry-run`, D4 never ran, so a fresh project's KV/account
    // sentinels are still there - report instead of stopping, the same
    // relaxation `--dry-run` already gets for D5(b) (packet review N5).
    const message =
      `${params.wranglerConfigPath} still has an unresolved {{...}} placeholder`
    if (params.reportMissingOnly) {
      params.output(message)
    } else {
      throw new Error(message)
    }
  }
  const parsed = parseWranglerConfig(text)
  const required = new Set([
    ...requiredSecretKeys(params.templateManifest),
    ...readWranglerRequiredSecrets(parsed),
  ])
  if (required.size > 0) {
    const existing = await wranglerSecretList(
      params.run,
      params.wrangler,
      params.root,
      params.wranglerConfigPath,
      params.accountEnv,
    )
    const missing = [...required].filter((name) => !existing.has(name)).sort()
    if (missing.length > 0) {
      const message =
        `Missing required Cloudflare Worker secret(s) before deploy: ${
          missing.join(', ')
        }`
      if (params.reportMissingOnly) {
        params.output(message)
      } else {
        throw new Error(message)
      }
    }
  }
  for (const command of params.templateManifest.cloudflare.preflight ?? []) {
    const [head, ...rest] = command
    const result = await params.run({
      args: rest,
      command: head!,
      cwd: params.root,
    })
    if (result.code !== 0) {
      // packet review N10: surface stderr (a preflight command is
      // template-authored, not a secret-value source like secret-pipe).
      if (result.stderr) params.output(result.stderr)
      throw new Error(`Preflight command failed: ${command.join(' ')}`)
    }
  }
}

export const deployToCloudflare = async (
  manifest: CloudflareWorkerManifest,
  options: CloudflareDeployOptions,
): Promise<void> => {
  const run = options.run ?? runProcess
  const output = options.output
  const promptIO = options.promptIO ?? defaultPromptIO
  const random = options.random ?? defaultRandom
  const fetcher = options.fetch ?? globalThis.fetch
  const templateRegistry = options.templateRegistry ?? TEMPLATE_REGISTRY
  // `--yes` forces the non-interactive path even with a TTY attached - the
  // same contract `initializeTemplateApp` uses for `erpc app init --template`
  // (Decision Q2/6; packet review B2/cyan B2).
  const isInteractive = !(options.yes ?? false) && promptIO.isInteractive()
  const root = manifest.projectRoot
  const wrangler = manifest.cloudflare.wrangler
  const wranglerConfigPath = resolve(root, manifest.cloudflare.config)
  const ackBackup = new Set(options.ackBackup ?? [])

  // D0
  const { pinned, templateManifest } = await loadDeployTemplateManifest(
    manifest,
    { erpcHome: options.erpcHome, fetch: fetcher, templateRegistry },
  )
  if (!pinned) {
    const source = parseTemplateSource(
      manifest.template.source,
      manifest.template.asset,
    )
    output(
      unpinnedTemplateWarning(source.owner, source.repo, manifest.template.ref),
    )
  }

  if (options.verifyOnly) {
    const text = await readFile(wranglerConfigPath, 'utf8')
    const vars = readWranglerVars(parseWranglerConfig(text))
    await runPostDeployProbes(
      templateManifest.postDeploy,
      {
        fetch: fetcher,
        random,
        timeoutSeconds: manifest.health.timeoutSeconds,
        vars,
      },
      'Post-deploy verification failed',
    )
    return
  }

  // D2 before D1 (packet review N7): a freshly-initialized project has not
  // run its own install yet, so `[build].command` (typically
  // `pnpm install --frozen-lockfile`) must run before `wrangler --version`
  // has any chance of finding wrangler at all.
  if (manifest.build) {
    const [command, ...rest] = manifest.build.command
    const result = await run({ args: rest, command: command!, cwd: root })
    if (result.code !== 0) {
      // packet review N10: a build command is template-authored, not a
      // secret-value source, so its stderr is safe to show.
      if (result.stderr) output(result.stderr)
      throw new Error('Build failed; no Cloudflare command was run')
    }
  }

  // D1
  const minVersion = templateManifest.cloudflare.minWranglerVersion ??
    DEFAULT_MIN_WRANGLER_VERSION
  await checkWranglerToolchain(
    run,
    wrangler,
    root,
    wranglerConfigPath,
    minVersion,
  )

  // D3
  const { accountEnv } = await resolveCloudflareAccount({
    dryRun: options.dryRun ?? false,
    isInteractive,
    promptIO,
    root,
    run,
    wrangler,
    wranglerConfigPath,
  })

  if (!options.dryRun && !options.noProvision) {
    // D4a
    await provisionKvNamespaces({
      accountEnv,
      appName: manifest.name,
      kv: templateManifest.cloudflare.kv,
      root,
      run,
      wrangler,
      wranglerConfigPath,
    })
    // D4b
    await provisionSecrets({
      ackBackup,
      accountEnv,
      isInteractive,
      output,
      promptIO,
      random,
      root,
      run,
      templateManifest,
      wrangler,
      wranglerConfigPath,
    })
  }

  // D5
  await runPreflight({
    accountEnv,
    output,
    reportMissingOnly: options.dryRun ?? false,
    root,
    run,
    templateManifest,
    wrangler,
    wranglerConfigPath,
  })

  // D6
  const deployResult = await wranglerDeploy(
    run,
    wrangler,
    root,
    wranglerConfigPath,
    accountEnv,
    { dryRun: options.dryRun },
  )
  if (deployResult.code !== 0) {
    throw new Error(
      options.dryRun
        ? 'wrangler deploy --dry-run failed'
        : 'wrangler deploy failed',
    )
  }
  if (options.dryRun) return

  // D7
  const text = await readFile(wranglerConfigPath, 'utf8')
  const vars = readWranglerVars(parseWranglerConfig(text))
  await runPostDeployProbes(
    templateManifest.postDeploy,
    {
      fetch: fetcher,
      random,
      timeoutSeconds: manifest.health.timeoutSeconds,
      vars,
    },
    'Deployed, but post-deploy verification failed',
  )
}
