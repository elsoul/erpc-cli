// Reads and surgically patches the project's `wrangler.toml` (or whatever
// `[cloudflare].config` points at). Sentinel replacement rewrites only the
// placeholder substring in place (tmp + rename) so every other byte -
// comments, key order, formatting - survives.

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

/** A Cloudflare account id is 32 lowercase hex characters. */
const ACCOUNT_ID_PATTERN = /^[0-9a-f]{32}$/

/**
 * D3: fills in `account_id`. Replaces the sentinel in place if present;
 * otherwise inserts a fresh top-level `account_id = "..."` line before the
 * first table header (an indented one included - `/^\s*\[/m`) or appends
 * one, for a file with no tables at all. A file that already carries a
 * resolved (non-sentinel) `account_id` is returned unchanged - the caller is
 * responsible for stopping when that value disagrees with the newly
 * resolved account.
 *
 * `accountId` must already look like a Cloudflare account id: this value
 * came from `wrangler whoami --json` or the
 * `CLOUDFLARE_ACCOUNT_ID` environment variable, and writing an unvalidated
 * string into TOML text (even one built with `tomlBasicString`) is not a
 * risk worth taking for a value this shape-constrained.
 */
export const applyAccountIdSentinel = (
  text: string,
  accountId: string,
): string => {
  if (!ACCOUNT_ID_PATTERN.test(accountId)) {
    throw new Error(
      `Resolved Cloudflare account id does not look like an account id: ${accountId}`,
    )
  }
  if (text.includes(WRANGLER_ACCOUNT_ID_SENTINEL)) {
    return text.replaceAll(WRANGLER_ACCOUNT_ID_SENTINEL, accountId)
  }
  const parsed = parseWranglerConfig(text)
  if (typeof parsed.account_id === 'string') return text
  const line = `account_id = "${tomlBasicString(accountId)}"\n`
  const match = /^\s*\[/m.exec(text)
  if (!match) {
    if (text.length === 0) return line
    return text.endsWith('\n') ? `${text}${line}` : `${text}\n${line}`
  }
  return `${text.slice(0, match.index)}${line}${text.slice(match.index)}`
}

/**
 * A Cloudflare KV namespace id is 32 lowercase hex characters (Cloudflare's
 * KV binding docs use `06779da6940b431db6e566b4846d64db` as the example).
 */
const KV_NAMESPACE_ID_PATTERN = /^[0-9a-f]{32}$/

/**
 * D4a: replaces a single `{{erpc:kv-id:<BINDING>}}` sentinel with the
 * resolved namespace id. No-op if the sentinel is already gone (a prior run
 * resolved it). The id comes from parsing wrangler's own output (`kv
 * namespace list` JSON or the `kv namespace create` config snippet), so it is
 * checked against the namespace-id shape before it is written into TOML
 * text: a quote or a newline in it would otherwise change the file's
 * structure.
 */
export const applyKvIdSentinel = (
  text: string,
  binding: string,
  id: string,
): string => {
  if (!KV_NAMESPACE_ID_PATTERN.test(id)) {
    throw new Error(
      `The KV namespace id wrangler reported for ${binding} does not look like a KV namespace id: ${
        JSON.stringify(id)
      }`,
    )
  }
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
