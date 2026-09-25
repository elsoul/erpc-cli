// Thin wrapper around `[cloudflare].wrangler` subprocess calls.
// See design doc §3.1/§3.3/§3.4 and Task Brief Decision 2/4/5/7/8/10.

import type {
  ProcessRequest,
  ProcessResult,
  ProcessRunner,
} from '../process.ts'

/**
 * Forced on every wrangler child process (Decision 10/N12): wrangler
 * 4.104.0 only writes unsanitized request bodies (which can contain a
 * secret value) to its debug log when this is `false` and debug logging is
 * on. This always wins over whatever the parent environment set, because it
 * is layered on last in `runWrangler`.
 */
const WRANGLER_LOG_SANITIZE_ENV = { WRANGLER_LOG_SANITIZE: 'true' } as const

export const DEFAULT_MIN_WRANGLER_VERSION = '4.104.0'

export interface WranglerCallOptions {
  readonly cwd: string
  readonly display?: boolean
  readonly env?: Readonly<Record<string, string>>
  readonly input?: string
  readonly stdio?: 'inherit' | 'piped'
}

/** Runs `[...wrangler, ...args]` through `run`, always forcing `WRANGLER_LOG_SANITIZE=true`. */
export const runWrangler = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  args: readonly string[],
  options: WranglerCallOptions,
): Promise<ProcessResult> => {
  const [command, ...prefixArgs] = wrangler
  if (!command) throw new Error('cloudflare.wrangler must not be empty')
  const request: ProcessRequest = {
    args: [...prefixArgs, ...args],
    command,
    cwd: options.cwd,
    env: { ...options.env, ...WRANGLER_LOG_SANITIZE_ENV },
    ...(options.display === undefined ? {} : { display: options.display }),
    ...(options.input === undefined ? {} : { input: options.input }),
    ...(options.stdio === undefined ? {} : { stdio: options.stdio }),
  }
  return await run(request)
}

const VERSION_PATTERN = /(\d+)\.(\d+)\.(\d+)/

export type SemverTriple = readonly [number, number, number]

export const parseWranglerVersion = (output: string): SemverTriple | null => {
  const match = VERSION_PATTERN.exec(output)
  if (!match) return null
  return [Number(match[1]), Number(match[2]), Number(match[3])]
}

export const meetsMinimumVersion = (
  current: SemverTriple,
  minimum: SemverTriple,
): boolean => {
  for (let index = 0; index < 3; index++) {
    if (current[index]! > minimum[index]!) return true
    if (current[index]! < minimum[index]!) return false
  }
  return true
}

/** D1: `wrangler --version` must run and meet `minVersion`, or deploy stops before touching Cloudflare (Decision 2). */
export const checkWranglerToolchain = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
  minVersion: string,
): Promise<void> => {
  const cannotRun = new Error(
    'Unable to run wrangler; run `pnpm install` in the project directory first',
  )
  let result: ProcessResult
  try {
    result = await runWrangler(run, wrangler, ['--version'], { cwd })
  } catch {
    throw cannotRun
  }
  const current = result.code === 0 ? parseWranglerVersion(result.stdout) : null
  if (!current) throw cannotRun
  const minimum = parseWranglerVersion(minVersion)
  if (!minimum || !meetsMinimumVersion(current, minimum)) {
    throw new Error(
      `wrangler ${minVersion} or newer is required (found ${
        current.join('.')
      }); run \`pnpm install\``,
    )
  }
}

export interface WranglerAccount {
  readonly id: string
  readonly name: string
}

export interface WranglerWhoami {
  readonly accounts: readonly WranglerAccount[]
  readonly loggedIn: true
}

/** D3: `wrangler whoami --json` (R6). Returns `null` on any non-authenticated/non-zero outcome - the caller decides what to do next. */
export const wranglerWhoami = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
): Promise<WranglerWhoami | null> => {
  const result = await runWrangler(run, wrangler, ['whoami', '--json'], { cwd })
  if (result.code !== 0) return null
  try {
    const parsed = JSON.parse(result.stdout) as {
      readonly accounts?: readonly WranglerAccount[]
      readonly loggedIn?: boolean
    }
    if (parsed.loggedIn !== true) return null
    return { accounts: parsed.accounts ?? [], loggedIn: true }
  } catch {
    return null
  }
}

/** D3: interactive-only `wrangler login`, run with the terminal shared directly (Decision 4). */
export const wranglerLogin = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
): Promise<void> => {
  const result = await runWrangler(run, wrangler, ['login'], {
    cwd,
    stdio: 'inherit',
  })
  if (result.code !== 0) throw new Error('`wrangler login` did not succeed')
}

export interface WranglerKvNamespace {
  readonly id: string
  readonly title: string
}

/** D4a: `wrangler kv namespace list` always prints a JSON array (R7). */
export const wranglerKvNamespaceList = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
  env: Readonly<Record<string, string>>,
): Promise<readonly WranglerKvNamespace[]> => {
  const result = await runWrangler(run, wrangler, ['kv', 'namespace', 'list'], {
    cwd,
    env,
  })
  if (result.code !== 0) {
    throw new Error(
      `Unable to list Cloudflare KV namespaces: ${
        result.stderr || result.stdout
      }`,
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(result.stdout)
  } catch {
    throw new Error('Unable to parse `wrangler kv namespace list` output')
  }
  if (!Array.isArray(parsed)) {
    throw new Error('`wrangler kv namespace list` did not return an array')
  }
  return parsed.filter((entry): entry is WranglerKvNamespace =>
    typeof entry === 'object' && entry !== null &&
    typeof (entry as { id?: unknown }).id === 'string' &&
    typeof (entry as { title?: unknown }).title === 'string'
  )
}

const KV_ID_LINE = /\bid\s*=\s*"([^"]+)"/

/** D4a: `wrangler kv namespace create <title>` prints the new id in a config snippet (Decision 5). */
export const wranglerKvNamespaceCreate = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
  env: Readonly<Record<string, string>>,
  title: string,
): Promise<string> => {
  const result = await runWrangler(
    run,
    wrangler,
    ['kv', 'namespace', 'create', title],
    { cwd, env },
  )
  if (result.code !== 0) {
    throw new Error(
      `Unable to create the Cloudflare KV namespace "${title}": ${
        result.stderr || result.stdout
      }`,
    )
  }
  const match = KV_ID_LINE.exec(result.stdout)
  if (!match?.[1]) {
    throw new Error(
      `Unable to read the id of the newly created KV namespace "${title}"`,
    )
  }
  return match[1]
}

const WORKER_NOT_FOUND = /Worker "[^"]*" not found\./

/** D4b/D5: `wrangler secret list` - a "Worker not found" failure means an empty secret set (R2), any other failure stops the deploy. */
export const wranglerSecretList = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
  env: Readonly<Record<string, string>>,
): Promise<ReadonlySet<string>> => {
  const result = await runWrangler(
    run,
    wrangler,
    ['secret', 'list', '--format', 'json'],
    { cwd, env },
  )
  if (result.code !== 0) {
    if (WORKER_NOT_FOUND.test(`${result.stdout}\n${result.stderr}`)) {
      return new Set()
    }
    throw new Error(
      `Unable to list Cloudflare Worker secrets: ${
        result.stderr || result.stdout
      }`,
    )
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(result.stdout)
  } catch {
    throw new Error('Unable to parse `wrangler secret list` output')
  }
  if (!Array.isArray(parsed)) {
    throw new Error('`wrangler secret list` did not return an array')
  }
  return new Set(
    parsed
      .filter((entry): entry is { name: string } =>
        typeof entry === 'object' && entry !== null &&
        typeof (entry as { name?: unknown }).name === 'string'
      )
      .map((entry) => entry.name),
  )
}

/** D4b: `wrangler secret put <NAME>` - the value travels only through stdin, never argv (Decision 10). */
export const wranglerSecretPut = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
  env: Readonly<Record<string, string>>,
  name: string,
  value: string,
): Promise<void> => {
  const result = await runWrangler(run, wrangler, ['secret', 'put', name], {
    cwd,
    display: false,
    env,
    input: value,
  })
  if (result.code !== 0) {
    throw new Error(`Unable to set the Cloudflare Worker secret ${name}`)
  }
}

/** D6: `wrangler deploy` (or `--dry-run`), streamed straight to the terminal (Decision 8). */
export const wranglerDeploy = async (
  run: ProcessRunner,
  wrangler: readonly string[],
  cwd: string,
  env: Readonly<Record<string, string>>,
  options: { readonly dryRun?: boolean } = {},
): Promise<ProcessResult> =>
  await runWrangler(
    run,
    wrangler,
    options.dryRun ? ['deploy', '--dry-run'] : ['deploy'],
    { cwd, env, stdio: 'inherit' },
  )
