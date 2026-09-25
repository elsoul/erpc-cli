// Reads and surgically patches the project's `wrangler.toml` (or whatever
// `[cloudflare].config` points at). Sentinel replacement rewrites only the
// placeholder substring in place (tmp + rename) so every other byte -
// comments, key order, formatting - survives (design doc §3.3 Decision 4/5).

import { readFile, rename, writeFile } from 'node:fs/promises'
import { parse as parseToml } from '@std/toml'
import { tomlBasicString } from '../app/template-render.ts'

export const WRANGLER_ACCOUNT_ID_SENTINEL = '{{erpc:cloudflare-account-id}}'

export const kvIdSentinel = (binding: string): string =>
  `{{erpc:kv-id:${binding}}}`

export const readWranglerConfigText = async (path: string): Promise<string> =>
  await readFile(path, 'utf8')

export const parseWranglerConfig = (
  text: string,
): Record<string, unknown> => {
  try {
    return parseToml(text) as Record<string, unknown>
  } catch (error) {
    throw new Error(
      `Unable to parse the Cloudflare Worker config as TOML: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

/** Atomic tmp + rename write, matching the pattern already used by `config.ts`. */
export const atomicWriteWranglerConfig = async (
  path: string,
  text: string,
): Promise<void> => {
  const temporary = `${path}.tmp-${Deno.pid}-${Date.now()}`
  await writeFile(temporary, text, { encoding: 'utf8', mode: 0o644 })
  await rename(temporary, path)
}

/** D5(a): no `{{...}}` placeholder may remain once provisioning has run. */
export const hasUnresolvedPlaceholders = (text: string): boolean =>
  text.includes('{{')

/**
 * D3: fills in `account_id`. Replaces the sentinel in place if present;
 * otherwise inserts a fresh top-level `account_id = "..."` line before the
 * first table header (or appends one, for a file with no tables at all).
 * A file that already carries a resolved (non-sentinel) `account_id` is
 * returned unchanged - the caller is responsible for stopping when that
 * value disagrees with the newly resolved account (Decision 4).
 */
export const applyAccountIdSentinel = (
  text: string,
  accountId: string,
): string => {
  if (text.includes(WRANGLER_ACCOUNT_ID_SENTINEL)) {
    return text.replaceAll(WRANGLER_ACCOUNT_ID_SENTINEL, accountId)
  }
  const parsed = parseWranglerConfig(text)
  if (typeof parsed.account_id === 'string') return text
  const line = `account_id = "${tomlBasicString(accountId)}"\n`
  const match = /^\[/m.exec(text)
  if (!match) {
    if (text.length === 0) return line
    return text.endsWith('\n') ? `${text}${line}` : `${text}\n${line}`
  }
  return `${text.slice(0, match.index)}${line}${text.slice(match.index)}`
}

/** D4a: replaces a single `{{erpc:kv-id:<BINDING>}}` sentinel with the resolved namespace id. No-op if the sentinel is already gone (a prior run resolved it). */
export const applyKvIdSentinel = (
  text: string,
  binding: string,
  id: string,
): string => {
  const sentinel = kvIdSentinel(binding)
  return text.includes(sentinel) ? text.replaceAll(sentinel, id) : text
}

/** The already-resolved (non-sentinel) `account_id`, if any. */
export const resolvedAccountId = (
  parsed: Record<string, unknown>,
): string | undefined =>
  typeof parsed.account_id === 'string' && !parsed.account_id.includes('{{')
    ? parsed.account_id
    : undefined

/** D7: `[vars]`, used to resolve `postDeploy[].baseUrlFromVar`/`issuerFromVar`. */
export const readWranglerVars = (
  parsed: Record<string, unknown>,
): Readonly<Record<string, string>> => {
  const vars = parsed.vars
  if (typeof vars !== 'object' || vars === null || Array.isArray(vars)) {
    return {}
  }
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(vars as Record<string, unknown>)) {
    if (typeof value === 'string') out[key] = value
  }
  return out
}

/** D5(b): `[secrets] required`, unioned with the template manifest's own required secret keys. */
export const readWranglerRequiredSecrets = (
  parsed: Record<string, unknown>,
): readonly string[] => {
  const secrets = parsed.secrets
  if (
    typeof secrets !== 'object' || secrets === null || Array.isArray(secrets)
  ) {
    return []
  }
  const required = (secrets as Record<string, unknown>).required
  return Array.isArray(required)
    ? required.filter((value): value is string => typeof value === 'string')
    : []
}
